"""Tests for the Tamper Score sub-grade (clawseccheck.tamperscore).

Presentation-layer only: these tests assert the sub-grade's own arithmetic and caps;
they never touch scoring.compute() or the main A-F grade. All tests are offline and
deterministic — no network calls, no file writes.
"""
from __future__ import annotations

from clawseccheck.catalog import FAIL, HIGH, LOW, MEDIUM, PASS, WARN, Finding
from clawseccheck.tamperscore import tamper_subgrade


def _f(id_: str, status: str, severity: str) -> Finding:
    return Finding(
        id=id_,
        title=f"Check {id_}",
        severity=severity,
        status=status,
        detail=f"detail for {id_}",
        fix=f"fix for {id_}",
        framework="Test",
    )


def _all_pass() -> list[Finding]:
    return [
        _f("B20", PASS, MEDIUM),
        _f("B22", PASS, HIGH),
        _f("B42", PASS, MEDIUM),
        _f("B78", PASS, HIGH),
        _f("B85", PASS, MEDIUM),
        _f("B86", PASS, MEDIUM),
        _f("C5", PASS, LOW),
    ]


class TestAllPassGradeA:
    def test_all_pass_plus_monitor_present_is_grade_a(self):
        r = tamper_subgrade(_all_pass(), monitor_state_present=True)
        assert r.assessable is True
        assert r.capped is False
        assert r.score == 100
        assert r.grade == "A"


class TestB22FailCapsAtF:
    def test_b22_fail_caps_at_49(self):
        findings = _all_pass()
        findings[1] = _f("B22", FAIL, HIGH)  # replace B22 PASS with FAIL
        r = tamper_subgrade(findings, monitor_state_present=True)
        assert r.capped is True
        assert r.score <= 49
        assert r.grade == "F"
        assert r.cap_severity == "B22-FAIL"

    def test_b78_fail_also_caps_at_49(self):
        findings = _all_pass()
        findings[3] = _f("B78", FAIL, HIGH)  # replace B78 PASS with FAIL
        r = tamper_subgrade(findings, monitor_state_present=True)
        assert r.capped is True
        assert r.score <= 49
        assert r.grade == "F"
        assert r.cap_severity == "B78-FAIL"


class TestNoMonitorCapsAtC:
    def test_monitor_absent_everything_else_pass_caps_at_79(self):
        r = tamper_subgrade(_all_pass(), monitor_state_present=False)
        assert r.capped is True
        assert r.score <= 79
        assert r.grade == "C"
        assert r.cap_severity == "no-monitor"


class TestSingleWarnCapsAtB:
    def test_one_warn_rest_pass_caps_at_89(self):
        findings = _all_pass()
        findings[0] = _f("B20", WARN, MEDIUM)  # replace B20 PASS with WARN
        r = tamper_subgrade(findings, monitor_state_present=True)
        assert r.capped is True
        assert r.score <= 89
        assert r.grade == "B"
        assert r.cap_severity == "WARN"


class TestOtherIngredientFailCapsAtC:
    def test_b20_fail_caps_at_79(self):
        findings = _all_pass()
        findings[0] = _f("B20", FAIL, MEDIUM)
        r = tamper_subgrade(findings, monitor_state_present=True)
        assert r.capped is True
        assert r.score <= 79
        assert r.grade == "C"
        assert r.cap_severity == "B20-FAIL"


class TestMissingIngredientsExcluded:
    def test_missing_check_id_excluded_not_fabricated_pass(self):
        """A check ID absent from findings is excluded from the denominator, not
        treated as a fabricated PASS."""
        # Only B22 present (PASS) + monitor present -> should be a clean 100/A,
        # exactly as if the missing checks never existed.
        r = tamper_subgrade([_f("B22", PASS, HIGH)], monitor_state_present=True)
        assert r.assessable is True
        assert r.score == 100
        assert r.grade == "A"


class TestNotAssessable:
    def test_empty_findings_is_not_assessable_not_a_fabricated_f(self):
        r = tamper_subgrade([], monitor_state_present=False)
        assert r.assessable is False
        assert r.grade == "N/A"
        assert r.score == 0
        assert r.capped is False

    def test_empty_findings_not_assessable_regardless_of_monitor_flag(self):
        r = tamper_subgrade([], monitor_state_present=True)
        assert r.assessable is False
        assert r.grade == "N/A"


class TestScoringNeverMutatesMainGrade:
    def test_tamper_subgrade_does_not_import_or_call_compute(self):
        """Guard the presentation-layer-only contract: tamperscore must not reach
        into scoring.compute() (the main A-F grade path)."""
        import clawseccheck.tamperscore as mod
        assert "compute" not in mod.__dict__
