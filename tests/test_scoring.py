from clawcheck.catalog import (
    CRITICAL, FAIL, HIGH, LOW, MEDIUM, PASS, UNKNOWN, WARN, Finding,
)
from clawcheck.scoring import compute, grade_for


def _f(severity, status, scored=True):
    return Finding("X", "t", severity, status, "d", "fix", "fw", scored)


def test_grade_boundaries():
    assert grade_for(90) == "A"
    assert grade_for(89) == "B"
    assert grade_for(70) == "C"
    assert grade_for(49) == "F"
    assert grade_for(50) == "D"


def test_all_pass_is_100():
    r = compute([_f(CRITICAL, PASS), _f(HIGH, PASS), _f(LOW, PASS)])
    assert r.score == 100
    assert r.grade == "A"
    assert r.capped is False


def test_failed_critical_caps_at_49():
    # one tiny critical fail among many passes would otherwise score high
    findings = [_f(CRITICAL, FAIL)] + [_f(LOW, PASS) for _ in range(20)]
    r = compute(findings)
    assert r.score <= 49
    assert r.capped is True
    assert r.failed_critical == 1


def test_failed_high_caps_at_79():
    findings = [_f(HIGH, FAIL)] + [_f(LOW, PASS) for _ in range(20)]
    r = compute(findings)
    assert r.score <= 79
    assert r.failed_high == 1


def test_unknown_excluded_from_denominator():
    # an UNKNOWN must not drag the score down
    only_pass = compute([_f(HIGH, PASS)])
    with_unknown = compute([_f(HIGH, PASS), _f(CRITICAL, UNKNOWN)])
    assert only_pass.score == with_unknown.score == 100


def test_warn_is_half_weight():
    r = compute([_f(MEDIUM, WARN)])  # half of full -> 50
    assert r.score == 50


def test_advisory_not_scored():
    r = compute([_f(HIGH, PASS), _f(CRITICAL, FAIL, scored=False)])
    # the non-scored fail must not cap or count
    assert r.score == 100
    assert r.capped is False
