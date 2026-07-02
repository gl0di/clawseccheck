"""Remediation DATA: REMEDIATION map integrity + --json/SARIF surfacing.

Reports-only (F-074): ClawSecCheck renders NO remediation for humans — --fix/--prompts
and the fix: lines were removed. The structured remediation map stays as machine DATA
in --json/SARIF (frozen public contract) for external tooling; these tests pin that
boundary: data present in machine formats, absent from human renders, CLI flags gone.
"""
import json
from pathlib import Path

from clawseccheck import audit, render_json
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


# ---- human renders carry no remediation (F-074) ----
def _ctx_findings(home):
    _, findings, score = audit(home, include_native=False, include_host=False)
    return findings, score


def test_render_fix_and_prompts_are_gone():
    import clawseccheck
    import clawseccheck.report as report
    for name in ("render_fix", "render_prompts"):
        assert not hasattr(clawseccheck, name)
        assert not hasattr(report, name)


def test_human_report_has_no_fix_lines():
    from clawseccheck.report import render_dashboard, render_report
    findings, score = _ctx_findings(FIXTURES / "home_vuln")
    for out in (render_report(findings, score), render_dashboard(findings, score)):
        assert "    fix:" not in out
        assert "FIX FIRST" not in out


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


# ---- CLI flags removed ----
def test_cli_fix_flag_is_gone(capsys):
    import pytest
    with pytest.raises(SystemExit) as exc:
        main(["--home", str(FIXTURES / "home_vuln"), "--fix"])
    assert exc.value.code == 2  # argparse: unrecognized argument
    assert "unrecognized arguments" in capsys.readouterr().err


def test_cli_prompts_flag_is_gone(capsys):
    import pytest
    with pytest.raises(SystemExit) as exc:
        main(["--home", str(FIXTURES / "home_vuln"), "--prompts"])
    assert exc.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err
