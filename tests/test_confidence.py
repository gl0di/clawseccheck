"""Per-finding confidence (HIGH = config-fact, MEDIUM = heuristic match)."""
from __future__ import annotations

import json

from clawseccheck import audit, render_json, render_sarif
from clawseccheck.catalog import BY_ID, FAIL, Finding
from clawseccheck.checks import _finding, vet_skill
from clawseccheck.report import render_report
from clawseccheck.scoring import compute


def test_checkmeta_confidence_defaults_high():
    assert BY_ID["B2"].confidence == "HIGH"


def test_heuristic_checks_are_medium():
    for cid in ("B6", "B13", "B21", "B23", "B42", "C5"):
        assert BY_ID[cid].confidence == "MEDIUM", cid


def test_config_fact_checks_are_high():
    for cid in ("B1", "B2", "B3", "B26", "B41", "B50"):
        assert BY_ID[cid].confidence == "HIGH", cid


def test_finding_inherits_confidence():
    assert _finding("B6", FAIL, "d", "f").confidence == "MEDIUM"
    assert _finding("B2", FAIL, "d", "f").confidence == "HIGH"


def test_vet_skill_finding_is_medium(tmp_path):
    d = tmp_path / "evil"
    d.mkdir()
    (d / "SKILL.md").write_text("# x\n")
    (d / "t.py").write_text('import base64\nexec(base64.b64decode("eA=="))\n')
    assert vet_skill(d).confidence == "MEDIUM"


def test_json_includes_confidence(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}")
    _, findings, score = audit(tmp_path)
    data = json.loads(render_json(findings, score))
    assert data["findings"]
    assert all("confidence" in f for f in data["findings"])
    assert {f["confidence"] for f in data["findings"]} <= {"HIGH", "MEDIUM", "LOW", "ATTESTED"}


def test_sarif_includes_confidence():
    f = Finding("B6", "t", "HIGH", FAIL, "d", "fx", "fw", confidence="MEDIUM")
    data = json.loads(render_sarif([f], compute([f]), "0.0.0"))
    res = data["runs"][0]["results"]
    assert res and res[0]["properties"]["confidence"] == "MEDIUM"


def test_text_report_shows_medium_marker():
    f = Finding("B6", "Bootstrap injection", "HIGH", FAIL, "d", "fx", "fw", confidence="MEDIUM")
    assert "confidence: medium" in render_report([f], compute([f]))


def test_text_report_no_marker_for_high_confidence():
    f = Finding("B2", "Gateway", "CRITICAL", FAIL, "d", "fx", "fw", confidence="HIGH")
    assert "confidence:" not in render_report([f], compute([f]))


def test_text_report_no_marker_for_passing_medium():
    # a MEDIUM-confidence PASS should not carry the verify marker (only FAIL/WARN)
    from clawseccheck.catalog import PASS
    f = Finding("B6", "Bootstrap injection", "HIGH", PASS, "d", "fx", "fw", confidence="MEDIUM")
    assert "confidence:" not in render_report([f], compute([f]))
