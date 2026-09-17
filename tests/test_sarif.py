"""Tests for clawseccheck.sarif.render_sarif.

Parses the returned JSON string and asserts structural correctness per SARIF 2.1.0.
No file I/O is performed by render_sarif; all assertions are in-memory.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from unittest.mock import patch

from clawseccheck import audit
from clawseccheck.catalog import (
    CRITICAL, FAIL, HIGH, PASS, UNKNOWN, WARN, Finding,
)
from clawseccheck.checks import _shared
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


def test_suppressed_noncapping_fail_produces_no_result():
    # An ordinary suppressed FAIL (not score-capping, not a sensitive id) stays omitted.
    f = _finding("B7", FAIL, severity="MEDIUM", suppressed=True)
    doc, _ = _parse([f])
    results = doc["runs"][0]["results"]
    assert results == []


def test_suppressed_capping_fail_surfaced_with_suppressions():
    # B-163: a score-capping suppressed CRITICAL/HIGH FAIL stays visible in `results`
    # but carries a SARIF `suppressions` array, so it can't be hidden from a reviewer.
    f = _finding("B2", FAIL, severity=CRITICAL, suppressed=True)
    doc, _ = _parse([f])
    results = doc["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == ["B2"]
    assert results[0]["suppressions"][0]["kind"] == "external"


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
        # An ordinary (non-capping) suppressed FAIL stays omitted from results.
        _finding("B5", FAIL, severity="MEDIUM", suppressed=True),
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

# ---------------------------------------------------------------------------
# B-651: the two tests below used to just run audit() over home_vuln/home_safe
# and assert on the `level` set alone — a property that would pass identically
# whether or not B-620's redaction fix (sarif._sarif_text / report._redact_home_paths)
# existed at all, since nothing in either shipped fixture happens to produce a finding
# that embeds an absolute home-directory path. A test that cannot fail for the defect
# it appears to cover is worse than no test — it reads as coverage.
#
# Replaced with a real, hermetic C5 (native binary PATH safety) scenario, using the
# exact live-leak-construction technique tests/test_b757_no_username_leak.py already
# proved reliable: a genuinely writable (WARN scenario) or tight (PASS scenario)
# install directory built under a monkeypatched $HOME, driven through the REAL
# check_path_safety via a REAL audit() — not a synthetic Finding — so the "does a real
# WARN reach SARIF as an error-level result" property the old tests nominally covered
# is now driven by an ACTUAL condition that can flip (a real writable vs. tight
# directory), rather than "whatever home_vuln happens to already trip".
#
# B-757 (checks/_shared._username_safe_path) already collapses this exact scenario's
# leak to '~' at the CHECK layer, before SARIF ever sees it — confirmed by mutation, not
# assumed: reverting sarif._sarif_text to skip report._redact_home_paths leaves both
# tests below green, because there is nothing left in Finding.detail/evidence for that
# fold to catch once B-757 has already run. So this pair is a real, non-vacuous
# CHECK-TO-RENDERER integration guard (mutating _username_safe_path itself does fail
# them) plus the genuine "does a real WARN reach SARIF as an error-level result"
# property — not independent proof of sarif._sarif_text's own fold, which is what
# tests/test_b620_sarif_results_path_redaction.py exists to give in isolation, using a
# directly-constructed Finding that bypasses the check layer (and therefore B-757)
# entirely — the one shape a real check can no longer produce.
#
# Also close to test_b757_no_username_leak.py::
# test_no_renderer_leaks_the_home_prefix_over_a_real_audit (same live C5 leak, swept
# across all five renderers) — this pair is the SARIF-specific slice of that property,
# living in the file a reader of "SARIF fixture tests" actually opens, with a condition
# (a real WARN vs. a real PASS) that can actually move the assertion, unlike the two
# tests it replaces.
# ---------------------------------------------------------------------------

def _c5_leak_scenario(monkeypatch, tmp_path, *, writable: bool):
    """Builds a real openclaw-install directory tree under a monkeypatched $HOME and
    points `shutil.which` at it, so `check_path_safety` reports a genuine WARN
    (`writable=True`, a world-writable bin dir) or PASS (`writable=False`, every
    ancestor tightened) when driven for real inside `audit()`. Returns the sandbox
    home `Path` so callers can assert redaction against it."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))

    bin_dir = home / ".npm-global" / "lib" / "node_modules" / "openclaw" / "bin"
    bin_dir.mkdir(parents=True)
    fake_exe = bin_dir / "openclaw"
    fake_exe.write_text("#!/bin/sh\necho openclaw")
    fake_exe.chmod(0o755)
    if writable:
        bin_dir.chmod(0o777)  # world-writable -> WARN
    else:
        # mkdir(parents=True) leaves intermediates group-writable under a permissive
        # umask -- tighten every ancestor _walk_ancestors will visit so this is
        # genuinely a PASS, not an accidental WARN from mkdir's own default mode.
        for d in (bin_dir, bin_dir.parent, bin_dir.parent.parent,
                  bin_dir.parent.parent.parent, home / ".npm-global", home):
            d.chmod(0o755)

    monkeypatch.setattr(_shared, "_is_posix", lambda: True)
    monkeypatch.setattr(shutil, "which", lambda name: str(fake_exe))
    monkeypatch.setenv("PATH", str(bin_dir))
    return home


def test_vuln_fixture_has_error_results(monkeypatch, tmp_path):
    home = _c5_leak_scenario(monkeypatch, tmp_path, writable=True)
    openclaw_home = home / ".openclaw"
    shutil.copytree(FIXTURES / "home_vuln", openclaw_home)

    ctx, findings, score = audit(openclaw_home, include_host=True)
    c5 = next((f for f in findings if f.id == "C5"), None)
    assert c5 is not None and c5.status == "WARN", "precondition: C5 must actually fire"
    # Non-vacuity control: the pre-render finding really did inspect (and flag) the
    # sandbox's own writable directory -- the collapsed '~/...' form, not merely the
    # ABSENCE of the raw path, which could just as easily mean the scenario never fired
    # at all. B-757 already folds this at the check layer (Finding.detail never carries
    # the raw path here); this proves that, rather than assuming it.
    assert str(home) not in c5.detail, c5.detail
    assert "~/.npm-global/lib/node_modules/openclaw/bin" in c5.detail, c5.detail

    doc, text = _parse(findings, score)
    results = doc["runs"][0]["results"]
    levels = {r["level"] for r in results}
    assert "error" in levels

    assert str(home) not in text, text
    c5_result = next(r for r in results if r["ruleId"] == "C5")
    assert str(home) not in c5_result["message"]["text"], c5_result["message"]["text"]
    assert "~/.npm-global/lib/node_modules/openclaw/bin" in c5_result["message"]["text"]


def test_safe_fixture_has_no_error_results(monkeypatch, tmp_path):
    home = _c5_leak_scenario(monkeypatch, tmp_path, writable=False)
    openclaw_home = home / ".openclaw"
    shutil.copytree(FIXTURES / "home_safe", openclaw_home)

    ctx, findings, score = audit(openclaw_home, include_host=True)
    c5 = next((f for f in findings if f.id == "C5"), None)
    assert c5 is not None and c5.status == "PASS", "precondition: C5 must resolve clean"

    doc, _text = _parse(findings, score)
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


def test_engine_degraded_count_distinct_from_ordinary_unknown():
    """B-767: a check that crashed/timed out must be countable separately from an
    ordinary UNKNOWN (e.g. "no gateway config present") — a CI consumer gating on
    unknownCount alone cannot tell "not applicable to my setup" from "failed to run"."""
    findings = [
        _finding("B1", UNKNOWN),  # ordinary undetermined — no surface
        Finding(
            id="ERR:check_something", title="Check 'check_something' could not run",
            severity="MEDIUM", status=UNKNOWN, detail="crashed", fix="re-run with --debug",
            framework="Engine robustness", scored=False, evidence=[],
            engine_degraded=True,
        ),
    ]
    doc = json.loads(render_sarif(findings, ctx=None))
    ac = doc["runs"][0]["properties"]["analysisCompleteness"]
    assert ac["unknownCount"] == 2
    assert ac["engineDegradedCount"] == 1
    assert any("crashed or timed out" in line for line in ac["limitations"])


def test_engine_degraded_count_zero_and_no_limitation_on_a_clean_run():
    findings = [_finding("B1", PASS), _finding("B2", WARN)]
    doc = json.loads(render_sarif(findings, ctx=None))
    ac = doc["runs"][0]["properties"]["analysisCompleteness"]
    assert ac["engineDegradedCount"] == 0
    assert not any("crashed or timed out" in line for line in ac["limitations"])


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
