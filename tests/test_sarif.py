"""Tests for clawseccheck.sarif.render_sarif.

Parses the returned JSON string and asserts structural correctness per SARIF 2.1.0.
No file I/O is performed by render_sarif; all assertions are in-memory.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from clawseccheck import audit
from clawseccheck.catalog import (
    CRITICAL, FAIL, HIGH, PASS, UNKNOWN, WARN, Finding,
)
from clawseccheck.sarif import render_sarif
from clawseccheck.scoring import compute

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(id_: str, status: str, severity: str = HIGH,
             detail: str = "detail text", suppressed: bool = False) -> Finding:
    return Finding(
        id=id_,
        title=f"Title for {id_}",
        severity=severity,
        status=status,
        detail=detail,
        fix="fix text",
        framework="Test",
        scored=True,
        evidence=[],
        suppressed=suppressed,
    )


def _parse(findings, score=None, version="1.2.3"):
    if score is None:
        score = compute(findings)
    text = render_sarif(findings, score, tool_version=version)
    return json.loads(text), text


# ---------------------------------------------------------------------------
# Top-level structure
# ---------------------------------------------------------------------------

def test_version_is_2_1_0():
    doc, _ = _parse([_finding("B2", PASS)])
    assert doc["version"] == "2.1.0"


def test_schema_field_is_string_literal():
    doc, _ = _parse([_finding("B2", PASS)])
    schema = doc["$schema"]
    assert isinstance(schema, str)
    assert "sarif" in schema.lower()
    assert "2.1.0" in schema


def test_single_run():
    doc, _ = _parse([_finding("B2", PASS)])
    assert len(doc["runs"]) == 1


# ---------------------------------------------------------------------------
# tool.driver
# ---------------------------------------------------------------------------

def test_tool_driver_name_is_clawseccheck():
    doc, _ = _parse([_finding("B2", PASS)])
    assert doc["runs"][0]["tool"]["driver"]["name"] == "ClawSecCheck"


def test_tool_driver_version_propagated():
    doc, _ = _parse([_finding("B2", PASS)], version="0.9.5")
    assert doc["runs"][0]["tool"]["driver"]["version"] == "0.9.5"


def test_tool_driver_information_uri():
    doc, _ = _parse([_finding("B2", PASS)])
    uri = doc["runs"][0]["tool"]["driver"]["informationUri"]
    assert "clawseccheck" in uri.lower()


# ---------------------------------------------------------------------------
# rules — built from CATALOG
# ---------------------------------------------------------------------------

def test_rules_array_is_non_empty():
    doc, _ = _parse([_finding("B2", PASS)])
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) > 0


def test_rules_cover_known_id_b2():
    doc, _ = _parse([_finding("B2", PASS)])
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    ids = {r["id"] for r in rules}
    assert "B2" in ids


def test_rules_cover_catalog_ids():
    from clawseccheck.catalog import CATALOG
    doc, _ = _parse([_finding("B2", PASS)])
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = {r["id"] for r in rules}
    catalog_ids = {m.id for m in CATALOG}
    assert catalog_ids == rule_ids


def test_rule_has_required_fields():
    doc, _ = _parse([_finding("B2", PASS)])
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    b2 = next(r for r in rules if r["id"] == "B2")
    assert "name" in b2
    assert "shortDescription" in b2
    assert "text" in b2["shortDescription"]
    assert "defaultConfiguration" in b2
    assert "level" in b2["defaultConfiguration"]


def test_critical_rule_level_is_error():
    doc, _ = _parse([_finding("B1", PASS)])
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    # B1 is CRITICAL
    b1 = next(r for r in rules if r["id"] == "B1")
    assert b1["defaultConfiguration"]["level"] == "error"


def test_high_rule_level_is_error():
    doc, _ = _parse([_finding("B2", PASS)])
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    b2 = next(r for r in rules if r["id"] == "B2")
    assert b2["defaultConfiguration"]["level"] == "error"


def test_medium_rule_level_is_warning():
    # B9 was MEDIUM but is now LOW (B-128: absent redactSensitive is secure-by-default,
    # not an active exposure) — B10 is a stable MEDIUM example for this assertion.
    doc, _ = _parse([_finding("B10", PASS)])  # B10 is MEDIUM
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    b10 = next(r for r in rules if r["id"] == "B10")
    assert b10["defaultConfiguration"]["level"] == "warning"


def test_low_rule_level_is_note():
    doc, _ = _parse([_finding("B12", PASS)])  # B12 is LOW
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    b12 = next(r for r in rules if r["id"] == "B12")
    assert b12["defaultConfiguration"]["level"] == "note"


# ---------------------------------------------------------------------------
# results — only FAIL / WARN, not suppressed
# ---------------------------------------------------------------------------

def test_fail_finding_produces_error_result():
    f = _finding("B2", FAIL, severity=HIGH, detail="gateway wide open")
    doc, _ = _parse([f])
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    r = results[0]
    assert r["ruleId"] == "B2"
    assert r["level"] == "error"
    assert r["message"]["text"] == "gateway wide open"


def test_warn_finding_produces_warning_result():
    f = _finding("B3", WARN, severity=HIGH, detail="privilege likely elevated")
    doc, _ = _parse([f])
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    r = results[0]
    assert r["ruleId"] == "B3"
    assert r["level"] == "warning"


def test_pass_finding_produces_no_result():
    f = _finding("B2", PASS)
    doc, _ = _parse([f])
    results = doc["runs"][0]["results"]
    assert results == []


def test_unknown_finding_produces_no_result():
    f = _finding("B2", UNKNOWN)
    doc, _ = _parse([f])
    results = doc["runs"][0]["results"]
    assert results == []


def test_suppressed_fail_produces_no_result():
    f = _finding("B2", FAIL, suppressed=True)
    doc, _ = _parse([f])
    results = doc["runs"][0]["results"]
    assert results == []


def test_suppressed_warn_produces_no_result():
    f = _finding("B3", WARN, suppressed=True)
    doc, _ = _parse([f])
    results = doc["runs"][0]["results"]
    assert results == []


def test_mixed_findings_only_actionable_in_results():
    findings = [
        _finding("B1", FAIL, severity=CRITICAL),
        _finding("B2", WARN, severity=HIGH),
        _finding("B3", PASS),
        _finding("B4", UNKNOWN),
        _finding("B5", FAIL, suppressed=True),
    ]
    doc, _ = _parse(findings)
    results = doc["runs"][0]["results"]
    # Only B1 (FAIL) and B2 (WARN) should appear
    assert len(results) == 2
    rule_ids = {r["ruleId"] for r in results}
    assert rule_ids == {"B1", "B2"}


def test_result_message_falls_back_to_title_when_detail_empty():
    f = Finding(
        id="B2",
        title="Gateway title",
        severity=HIGH,
        status=FAIL,
        detail="",
        fix="fix",
        framework="fw",
    )
    doc, _ = _parse([f])
    results = doc["runs"][0]["results"]
    assert results[0]["message"]["text"] == "Gateway title"


# ---------------------------------------------------------------------------
# Output format
# ---------------------------------------------------------------------------

def test_output_is_valid_json_string():
    text = render_sarif([_finding("B2", FAIL)], compute([_finding("B2", FAIL)]))
    assert isinstance(text, str)
    parsed = json.loads(text)
    assert isinstance(parsed, dict)


def test_output_is_ascii_safe():
    text = render_sarif([_finding("B2", FAIL)], compute([_finding("B2", FAIL)]))
    text.encode("ascii")  # must not raise


def test_output_is_indented():
    text = render_sarif([_finding("B2", FAIL)], compute([_finding("B2", FAIL)]))
    # indent=2 means lines after the first are indented
    lines = text.splitlines()
    assert any(line.startswith("  ") for line in lines)


def test_deterministic_output():
    findings = [_finding("B1", FAIL), _finding("B2", WARN), _finding("B3", PASS)]
    score = compute(findings)
    assert render_sarif(findings, score) == render_sarif(findings, score)


# ---------------------------------------------------------------------------
# Integration: use audit() on real fixtures
# ---------------------------------------------------------------------------

def test_vuln_fixture_has_error_results():
    _, findings, score = audit(FIXTURES / "home_vuln")
    doc, _ = _parse(findings, score)
    results = doc["runs"][0]["results"]
    levels = {r["level"] for r in results}
    assert "error" in levels


def test_safe_fixture_has_no_error_results():
    _, findings, score = audit(FIXTURES / "home_safe")
    doc, _ = _parse(findings, score)
    results = doc["runs"][0]["results"]
    error_results = [r for r in results if r["level"] == "error"]
    assert error_results == []


def test_default_tool_version():
    text = render_sarif([], compute([]))
    doc = json.loads(text)
    assert doc["runs"][0]["tool"]["driver"]["version"] == "0.0.0"


# ---------------------------------------------------------------------------
# analysis_completeness tests
# ---------------------------------------------------------------------------

def test_analysis_completeness_omitted_without_ctx():
    # analysisCompleteness is always added, so properties is always present.
    # The ctx-dependent snake_case key (analysis_completeness) must be absent.
    doc = json.loads(render_sarif([], ctx=None))
    run = doc["runs"][0]
    assert "properties" in run
    assert "analysisCompleteness" in run["properties"]
    assert "analysis_completeness" not in run["properties"]


def test_analysis_completeness_metablock_always_present():
    """analysisCompleteness is in run.properties regardless of ctx."""
    findings = [
        _finding("B1", FAIL, severity=CRITICAL),
        _finding("B2", WARN),
        _finding("B3", PASS),
        _finding("B4", UNKNOWN),
        _finding("B5", FAIL, suppressed=True),
    ]
    doc = json.loads(render_sarif(findings, ctx=None))
    props = doc["runs"][0]["properties"]
    ac = props["analysisCompleteness"]
    # All required keys present
    for key in ("checksRun", "checksTotal", "unknownCount", "warnCount", "failCount"):
        assert key in ac, f"missing key: {key}"
        assert isinstance(ac[key], int) and ac[key] >= 0, f"{key} must be int >= 0"
    # Counts match the findings list
    assert ac["failCount"] == 2   # B1 + B5 (suppressed still counted by status)
    assert ac["warnCount"] == 1
    assert ac["unknownCount"] == 1
    assert ac["passCount"] == 1
    assert ac["suppressedCount"] == 1


def test_analysis_completeness_populated_with_ctx():
    from clawseccheck.collector import Context
    ctx = Context(home=Path("/tmp"))
    ctx.total_files_inspected = 42
    ctx.excluded_binary_files_count = 3
    ctx.archives_unpacked = 2
    ctx.limit_hits = ["limit_hit_1"]
    ctx.path_traversal_violations = ["violation_1"]
    ctx.file_manifest = {"file1.py": "scanned"}
    ctx.installed_skill_py = {
        "my_skill": [
            ("file1.py", "print('hello')")
        ]
    }
    
    doc = json.loads(render_sarif([], ctx=ctx))
    props = doc["runs"][0]["properties"]
    assert "analysis_completeness" in props
    
    completeness = props["analysis_completeness"]
    assert completeness["total_files_inspected"] == 42
    assert completeness["excluded_binary_files_count"] == 3
    assert completeness["archives_unpacked"] == 2
    assert completeness["limit_hits"] == ["limit_hit_1"]
    assert completeness["path_traversal_violations"] == ["violation_1"]
    assert completeness["file_manifest"] == {"file1.py": "scanned"}
    assert isinstance(completeness["simulated_effects"], list)


@patch("clawseccheck.skillast.simulate_effects")
def test_analysis_completeness_simulated_effects(mock_simulate):
    from clawseccheck.collector import Context
    mock_simulate.return_value = [{"test_effect": "val"}]
    
    ctx = Context(home=Path("/tmp"))
    ctx.installed_skill_py = {
        "test_skill": [
            ("test_file.py", "dummy code")
        ]
    }
    
    doc = json.loads(render_sarif([], ctx=ctx))
    completeness = doc["runs"][0]["properties"]["analysis_completeness"]
    effects = completeness["simulated_effects"]
    assert len(effects) == 1
    assert effects[0]["test_effect"] == "val"
    assert effects[0]["skill"] == "test_skill"
    assert effects[0]["file"] == "test_file.py"
    
    mock_simulate.assert_called_once_with("dummy code", "test_file.py")


@patch("clawseccheck.skillast.simulate_effects")
def test_analysis_completeness_simulate_effects_crashes(mock_simulate):
    from clawseccheck.collector import Context
    mock_simulate.side_effect = Exception("ast error")
    
    ctx = Context(home=Path("/tmp"))
    ctx.installed_skill_py = {
        "test_skill": [
            ("test_file.py", "dummy code")
        ]
    }
    
    # This should not raise an exception
    doc = json.loads(render_sarif([], ctx=ctx))
    completeness = doc["runs"][0]["properties"]["analysis_completeness"]
    assert completeness["simulated_effects"] == []
