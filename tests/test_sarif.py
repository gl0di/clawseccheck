"""Tests for clawcheck.sarif.render_sarif.

Parses the returned JSON string and asserts structural correctness per SARIF 2.1.0.
No file I/O is performed by render_sarif; all assertions are in-memory.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawcheck import audit
from clawcheck.catalog import (
    CRITICAL, FAIL, HIGH, PASS, UNKNOWN, WARN, Finding,
)
from clawcheck.sarif import render_sarif
from clawcheck.scoring import compute

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

def test_tool_driver_name_is_clawcheck():
    doc, _ = _parse([_finding("B2", PASS)])
    assert doc["runs"][0]["tool"]["driver"]["name"] == "ClawCheck"


def test_tool_driver_version_propagated():
    doc, _ = _parse([_finding("B2", PASS)], version="0.9.5")
    assert doc["runs"][0]["tool"]["driver"]["version"] == "0.9.5"


def test_tool_driver_information_uri():
    doc, _ = _parse([_finding("B2", PASS)])
    uri = doc["runs"][0]["tool"]["driver"]["informationUri"]
    assert "clawcheck" in uri.lower()


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
    from clawcheck.catalog import CATALOG
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
    doc, _ = _parse([_finding("B9", PASS)])  # B9 is MEDIUM
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    b9 = next(r for r in rules if r["id"] == "B9")
    assert b9["defaultConfiguration"]["level"] == "warning"


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
