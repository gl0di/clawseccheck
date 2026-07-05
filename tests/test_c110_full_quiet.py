"""C-110 — `--full --quiet` collapses the appended self-test + vet-mcp sections.

`--full` runs audit + self-test material + vet-mcp in one command; the appended sections
are what push it to hundreds of lines, heavy for CI logs / scroll. `--quiet` (only
meaningful with `--full`) collapses those two sections to one honest summary line each,
while the concise report above is unchanged and the ledger-refresh / --exit-code
behaviour is identical to the verbose path. Offline, read-only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.cli import main

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"
VULN = str(FIXTURES / "home_vuln")
MCP = str(FIXTURES / "clean_c047_mcp_localhost")  # has ≥1 configured MCP server
BASE = ["--no-native", "--no-history"]


def _run(capsys, extra: list[str], home: str = VULN) -> tuple[int, str]:
    code = main(["--home", home] + BASE + extra)
    return code, capsys.readouterr().out


# ---------------------------------------------------------------------------
# Volume + collapse
# ---------------------------------------------------------------------------

def test_quiet_is_substantially_shorter(capsys):
    _, full = _run(capsys, ["--full"])
    _, quiet = _run(capsys, ["--full", "--quiet"])
    assert len(quiet.splitlines()) < len(full.splitlines()) // 2, (
        f"--full={len(full.splitlines())} lines, "
        f"--full --quiet={len(quiet.splitlines())} — expected >50% collapse"
    )


def test_quiet_has_summary_lines(capsys):
    _, quiet = _run(capsys, ["--full", "--quiet"])
    assert "SELF-TEST: 1 canary +" in quiet
    assert "Full harness: --self-test." in quiet
    assert "VET-MCP:" in quiet


def test_quiet_omits_verbose_banners(capsys):
    # The heavy verbose sections (banner rules + per-scenario prompt text) must be gone.
    _, quiet = _run(capsys, ["--full", "--quiet"])
    assert "CLAWSECCHECK SELF-TEST" not in quiet
    assert "CLAWSECCHECK VET-MCP" not in quiet
    assert "VULNERABLE" not in quiet  # per-scenario red-team prompt text


def test_verbose_still_has_banners(capsys):
    _, full = _run(capsys, ["--full"])
    assert "CLAWSECCHECK SELF-TEST" in full
    assert "CLAWSECCHECK VET-MCP" in full


def test_report_body_unchanged_by_quiet(capsys):
    # The concise report + card + next-actions are emitted identically before the
    # appended sections in both paths, so the quiet output up to its SELF-TEST summary
    # line must be a byte-for-byte prefix of the verbose output.
    _, full = _run(capsys, ["--full"])
    _, quiet = _run(capsys, ["--full", "--quiet"])
    quiet_head = quiet.split("\nSELF-TEST:")[0]
    assert full.startswith(quiet_head), "report body diverged between --full and --full --quiet"


# ---------------------------------------------------------------------------
# Vet-mcp summary counts
# ---------------------------------------------------------------------------

def test_quiet_vetmcp_counts_when_servers_present(capsys):
    _, quiet = _run(capsys, ["--full", "--quiet"], home=MCP)
    assert "server-check(s)" in quiet
    assert "FAIL," in quiet and "WARN," in quiet and "PASS" in quiet


def test_quiet_vetmcp_unknown_when_no_servers(capsys):
    # home_vuln configures no MCP server → the single-UNKNOWN summary path.
    _, quiet = _run(capsys, ["--full", "--quiet"])
    assert "VET-MCP: No MCP servers configured" in quiet


# ---------------------------------------------------------------------------
# Coherence + parity
# ---------------------------------------------------------------------------

def test_quiet_without_full_notes_no_effect(capsys):
    main(["--home", VULN] + BASE + ["--quiet"])
    err = capsys.readouterr().err
    assert "--quiet has no effect without --full" in err


def test_exit_code_parity_full_vs_quiet(capsys):
    # --quiet must not change the audit verdict — only the rendering.
    code_full, _ = _run(capsys, ["--full", "--exit-code"])
    code_quiet, _ = _run(capsys, ["--full", "--quiet", "--exit-code"])
    assert code_full == code_quiet
