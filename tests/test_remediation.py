"""Paste-ready remediation: REMEDIATION map, render_fix, --json/SARIF surfacing, --fix CLI.

ClawSecCheck only PRINTS remediation — it never applies it (read-only by default).
"""
import json
from pathlib import Path

from clawseccheck import audit, render_fix, render_json
from clawseccheck.catalog import BY_ID, REMEDIATION, remediation_for
from clawseccheck.cli import main
from clawseccheck.sarif import render_sarif

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

# Allowlisted command verbs — nothing destructive or network-touching may appear.
_ALLOWED_VERBS = ("chmod", "openclaw")
_FORBIDDEN = ("rm ", "rm\t", "mv ", "curl", "wget", "dd ", "sudo", "> ", ">>", "|", "&&",
              ";", "`", "$(", ":(){", "eval", "python", "sh ", "bash")


# ---- mapping integrity ----
def test_every_remediated_id_is_a_real_check():
    for cid in REMEDIATION:
        assert cid in BY_ID, f"REMEDIATION references unknown check id {cid!r}"


def test_remediation_structure_is_valid():
    for cid in REMEDIATION:
        rem = remediation_for(cid)
        assert isinstance(rem["commands"], list)
        assert isinstance(rem["config"], list)
        for cmd in rem["commands"]:
            assert isinstance(cmd, str) and cmd.strip()
        for c in rem["config"]:
            assert isinstance(c["path"], str) and c["path"].strip()
            assert "." in c["path"], f"{cid} config path should be dotted: {c['path']!r}"
            assert "set" in c  # explicit (None means descriptive)


def test_remediation_for_unmapped_is_empty():
    assert remediation_for("B16") == {"commands": [], "config": []}
    assert remediation_for("ZZ99") == {"commands": [], "config": []}


# ---- safety guard (§5): commands must be safe, never destructive or network ----
def test_commands_use_only_allowlisted_safe_verbs():
    for cid in REMEDIATION:
        for cmd in remediation_for(cid)["commands"]:
            first = cmd.strip().split()[0]
            assert first in _ALLOWED_VERBS, f"{cid}: non-allowlisted command verb {first!r}"
            for bad in _FORBIDDEN:
                assert bad not in cmd, f"{cid}: forbidden token {bad!r} in command {cmd!r}"


# ---- render_fix ----
def _ctx_findings(home):
    _, findings, score = audit(home, include_native=False, include_host=False)
    return findings, score


def test_render_fix_shows_commands_and_does_not_apply_banner():
    findings, _ = _ctx_findings(FIXTURES / "home_vuln")
    out = render_fix(findings)
    assert "does NOT apply" in out
    assert "commands:" in out
    assert "chmod 600 ~/.openclaw/openclaw.json" in out      # B1 command
    assert "diff:" in out
    assert "--- a/" in out and "+++ b/" in out and "@@" in out


def test_render_fix_empty_when_no_actionable():
    # A clean finding set (no FAIL/WARN with remediation) -> "nothing" message.
    out = render_fix([])
    assert "Nothing to paste-apply" in out


def test_render_fix_config_guidance_form_not_a_json_blob():
    findings, _ = _ctx_findings(FIXTURES / "home_vuln")
    out = render_fix(findings)
    # guidance points at the dotted path; it must not dump a full JSON object to paste over
    assert "agents.defaults.sandbox.mode" in out
    assert '{\n' not in out  # no multi-line JSON blob


# ---- --json / SARIF surfacing ----
def test_json_includes_remediation():
    findings, score = _ctx_findings(FIXTURES / "home_vuln")
    data = json.loads(render_json(findings, score))
    by_id = {f["id"]: f for f in data["findings"]}
    assert by_id["B1"]["remediation"]["commands"][0].startswith("openclaw secrets")
    assert by_id["B8"]["remediation"]["config"][0]["path"] == "tools.exec.mode"
    # an unmapped check still carries the normalized empty shape
    assert by_id["B16"]["remediation"] == {"commands": [], "config": []}


def test_sarif_includes_fixes():
    findings, score = _ctx_findings(FIXTURES / "home_vuln")
    sar = json.loads(render_sarif(findings, score, tool_version="1.7.0"))
    results = {r["ruleId"]: r for r in sar["runs"][0]["results"]}
    assert "fixes" in results["B1"]
    assert results["B1"]["fixes"][0]["description"]["text"].startswith("openclaw secrets")


# ---- --fix CLI ----
def test_cli_fix_returns_zero_and_prints_block(capsys):
    rc = main(["--home", str(FIXTURES / "home_vuln"), "--no-native", "--no-host",
               "--no-history", "--fix"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Remediation" in out and "does NOT apply" in out

