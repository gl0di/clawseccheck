"""B-350 — the vet-mcp "single UNKNOWN" detail is sanitized on BOTH ``--full`` paths.

``--full`` renders the embedded vet-mcp section twice over, once per branch: the verbose
banner section and the one-line ``--full --quiet`` summary. When ``vet_mcp`` comes back
with exactly one UNKNOWN finding (the "no MCP servers configured" shape), both branches
print that finding's ``.detail`` — but only the quiet one routed it through
``report._sanitize``. The loud one printed it raw.

That is not a live vulnerability: the detail on this branch is engine-authored today, so
there is no attacker string in it. It is a latent terminal-injection surface, and the
asymmetry is the actual defect — a sanitizer that is applied on one of two twinned paths
is a sanitizer that gets bypassed later, by a change to the *producer*, without anyone
touching the sanitizer or noticing the gap.

So the property pinned here is deliberately the SYMMETRY, not just the fix: both paths
must neutralise the same hostile detail. A future edit that re-raws either branch fails
this file, whichever branch it was.

Offline, read-only, writes nothing outside ``tmp_path``.
"""
from __future__ import annotations

from pathlib import Path

import clawseccheck.cli as cli
from clawseccheck.catalog import Finding
from clawseccheck.cli import main

# A real terminal-spoofing primitive, same shape tests/test_b164_terminal_injection.py
# uses: OSC-0 window-title set (ESC ] 0 ; ... BEL), then CSI erase-line / cursor-up /
# erase-line to blank and overwrite whatever the audit just printed above it.
_ESC = "\x1b"
_BEL = "\x07"
_EVIL_DETAIL = (
    "No MCP servers configured"
    + _ESC + "]0;PWNED" + _BEL
    + _ESC + "[2K" + _ESC + "[1A"
    + "GRADE: A - nothing to see here"
)

BASE = ["--no-native", "--no-host", "--no-history", "--ascii", "--seed", "b350"]


def _home(tmp_path: Path) -> str:
    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    return str(tmp_path)


def _hostile_unknown() -> list:
    """Exactly the shape both branches special-case: ONE finding, status UNKNOWN."""
    return [Finding(
        id="VET-MCP",
        title="MCP servers",
        severity="INFO",
        status="UNKNOWN",
        detail=_EVIL_DETAIL,
        fix="Configure an MCP server to vet.",
        framework="n/a",
    )]


def _run(monkeypatch, capsys, tmp_path, extra: list[str]) -> str:
    monkeypatch.setattr(cli, "vet_mcp", lambda **kw: _hostile_unknown())
    rc = main(["--home", _home(tmp_path)] + BASE + ["--full"] + extra)
    assert rc == 0
    return capsys.readouterr().out


def _assert_neutralised(out: str) -> None:
    assert _ESC not in out, "raw ESC sequence reached stdout"
    assert _BEL not in out, "raw BEL reached stdout"
    # The visible text still survives — sanitizing must neutralise, not censor.
    assert "No MCP servers configured" in out


# ---------------------------------------------------------------------------
# Both branches, same property
# ---------------------------------------------------------------------------

def test_verbose_full_sanitizes_single_unknown_vetmcp_detail(monkeypatch, capsys, tmp_path):
    """The loud path — this is the one that was raw before B-350."""
    _assert_neutralised(_run(monkeypatch, capsys, tmp_path, []))


def test_quiet_full_sanitizes_single_unknown_vetmcp_detail(monkeypatch, capsys, tmp_path):
    """The quiet twin — already correct; pinned so it cannot regress to match the loud
    path instead of the other way round."""
    _assert_neutralised(_run(monkeypatch, capsys, tmp_path, ["--quiet"]))


def test_both_full_paths_neutralise_identically(monkeypatch, capsys, tmp_path):
    """The symmetry itself: neither branch may carry a control byte the other strips.

    Asserted as a property of the pair rather than of each branch alone, because the
    defect this file exists for is precisely a divergence between two renderings of one
    value — a per-branch test can stay green while the two drift apart in what they let
    through.
    """
    verbose = _run(monkeypatch, capsys, tmp_path, [])
    quiet = _run(monkeypatch, capsys, tmp_path, ["--quiet"])
    controls = {c for c in (_ESC, _BEL)}
    assert {c for c in controls if c in verbose} == {c for c in controls if c in quiet} == set()
