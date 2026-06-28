"""Tests for --full flag (audit + self-test + vet-mcp in one invocation).

The --full flag is a CI-convenience composite: it runs the standard audit
(human output), then emits the self-test material (canary + red-team + dryrun),
then the vet-mcp output — all in a single invocation, exit 0.

Self-test emits deterministic test material; it does NOT autonomously attack.
"""
from __future__ import annotations

import re
from pathlib import Path

from clawseccheck.cli import main

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE = str(FIXTURES / "home_safe")
VULN = str(FIXTURES / "home_vuln")
BASE = ["--no-native", "--no-history", "--ascii"]


# ---------------------------------------------------------------------------
# Core behaviour: --full emits all three sections
# ---------------------------------------------------------------------------

def test_full_exits_zero(capsys):
    rc = main(["--home", SAFE] + BASE + ["--full"])
    assert rc == 0


def test_full_output_contains_audit(capsys):
    main(["--home", SAFE] + BASE + ["--full"])
    out = capsys.readouterr().out
    assert "ClawSecCheck - OpenClaw Security Audit" in out


def test_full_output_contains_canary(capsys):
    main(["--home", SAFE] + BASE + ["--full"])
    out = capsys.readouterr().out
    assert "CLAWSECCHECK-CANARY-" in out


def test_full_output_contains_redteam(capsys):
    main(["--home", SAFE] + BASE + ["--full"])
    out = capsys.readouterr().out
    assert "CLAWSECCHECK-RT-" in out


def test_full_output_contains_dryrun(capsys):
    main(["--home", SAFE] + BASE + ["--full"])
    out = capsys.readouterr().out
    assert "CLAWSECCHECK-DR-" in out


def test_full_output_self_test_section_header(capsys):
    main(["--home", SAFE] + BASE + ["--full"])
    out = capsys.readouterr().out
    assert "CLAWSECCHECK SELF-TEST" in out


def test_full_output_vet_mcp_section_header(capsys):
    main(["--home", SAFE] + BASE + ["--full"])
    out = capsys.readouterr().out
    assert "CLAWSECCHECK VET-MCP" in out


def test_full_output_vet_mcp_no_servers(capsys):
    """home_safe has no MCP servers -> vet-mcp section reports UNKNOWN."""
    main(["--home", SAFE] + BASE + ["--full"])
    out = capsys.readouterr().out
    assert "No MCP servers configured" in out


def test_full_audit_before_self_test(capsys):
    """Audit section must appear before self-test section in the output."""
    main(["--home", SAFE] + BASE + ["--full"])
    out = capsys.readouterr().out
    audit_pos = out.find("ClawSecCheck - OpenClaw Security Audit")
    selftest_pos = out.find("CLAWSECCHECK SELF-TEST")
    assert audit_pos >= 0 and selftest_pos >= 0
    assert audit_pos < selftest_pos


def test_full_self_test_before_vet_mcp(capsys):
    """Self-test section must appear before vet-mcp section in the output."""
    main(["--home", SAFE] + BASE + ["--full"])
    out = capsys.readouterr().out
    selftest_pos = out.find("CLAWSECCHECK SELF-TEST")
    vetmcp_pos = out.find("CLAWSECCHECK VET-MCP")
    assert selftest_pos >= 0 and vetmcp_pos >= 0
    assert selftest_pos < vetmcp_pos


# ---------------------------------------------------------------------------
# --no-history is honoured under --full
# ---------------------------------------------------------------------------

def test_full_no_history_honored(tmp_path, capsys):
    hist = tmp_path / "history.jsonl"
    rc = main([
        "--home", SAFE, "--no-native", "--no-history", "--ascii",
        "--full", "--history", str(hist),
    ])
    assert rc == 0
    assert not hist.exists()


# ---------------------------------------------------------------------------
# --full + --seed produces stable self-test tokens
# ---------------------------------------------------------------------------

def test_full_seeded_stable(capsys):
    seed = "ci-stable"
    main(["--home", SAFE] + BASE + ["--full", "--seed", seed])
    out1 = capsys.readouterr().out
    rt1 = re.findall(r"CLAWSECCHECK-RT-[0-9A-F]+", out1)

    main(["--home", SAFE] + BASE + ["--full", "--seed", seed])
    out2 = capsys.readouterr().out
    rt2 = re.findall(r"CLAWSECCHECK-RT-[0-9A-F]+", out2)

    assert rt1 == rt2
    assert len(rt1) > 0


# ---------------------------------------------------------------------------
# --full + --json: extra sections are skipped (human-path only)
# ---------------------------------------------------------------------------

def test_full_json_skips_extra_sections(capsys):
    import json as _json
    rc = main(["--home", SAFE, "--no-native", "--no-history", "--full", "--json"])
    assert rc == 0
    out = capsys.readouterr().out
    # Must be valid JSON with no extra human text appended.
    doc = _json.loads(out)
    assert "grade" in doc
    # Self-test tokens must NOT appear in the JSON-mode output.
    assert "CLAWSECCHECK-CANARY-" not in out
    assert "CLAWSECCHECK SELF-TEST" not in out
    assert "CLAWSECCHECK VET-MCP" not in out


# ---------------------------------------------------------------------------
# vuln fixture: --full still exits 0 (no --exit-code / --fail-under)
# ---------------------------------------------------------------------------

def test_full_vuln_fixture_exits_zero(capsys):
    rc = main(["--home", VULN] + BASE + ["--full"])
    assert rc == 0


# ---------------------------------------------------------------------------
# Back-compat: existing modes are unchanged by the new flag
# ---------------------------------------------------------------------------

def test_self_test_standalone_unchanged(capsys):
    rc = main(["--self-test", "--ascii"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "CLAWSECCHECK-CANARY-" in out
    assert "CLAWSECCHECK-RT-" in out
    assert "CLAWSECCHECK-DR-" in out
    # Must NOT contain the audit report
    assert "ClawSecCheck - OpenClaw Security Audit" not in out


def test_default_audit_does_not_include_self_test(capsys):
    rc = main(["--home", SAFE] + BASE)
    assert rc == 0
    out = capsys.readouterr().out
    # Without --full, default audit must not emit self-test tokens.
    assert "CLAWSECCHECK-CANARY-" not in out
    assert "CLAWSECCHECK SELF-TEST" not in out
    assert "CLAWSECCHECK VET-MCP" not in out
