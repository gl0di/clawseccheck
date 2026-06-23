from clawseccheck.catalog import (
    CRITICAL, FAIL, HIGH, LOW, MEDIUM, PASS, UNKNOWN, WARN, Finding,
)
from clawseccheck.scoring import compute, grade_for


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


# ---------------------------------------------------------------------------
# B-011: MEDIUM/LOW FAILs are capped too, so a FAIL always costs a grade
# ---------------------------------------------------------------------------

def test_medium_fail_caps_at_89():
    # was: [MEDIUM FAIL] + 200x[LOW PASS] -> raw ~99 -> "A". Now capped to <=89.
    findings = [_f(MEDIUM, FAIL)] + [_f(LOW, PASS) for _ in range(200)]
    r = compute(findings)
    assert r.score <= 89
    assert r.capped is True
    assert r.failed_medium == 1
    assert r.cap_severity == MEDIUM


def test_low_fail_caps_at_94():
    findings = [_f(LOW, FAIL)] + [_f(LOW, PASS) for _ in range(200)]
    r = compute(findings)
    assert r.score <= 94
    assert r.failed_low == 1
    assert r.cap_severity == LOW


def test_most_severe_cap_wins():
    findings = [_f(CRITICAL, FAIL), _f(MEDIUM, FAIL)] + [_f(LOW, PASS) for _ in range(50)]
    r = compute(findings)
    assert r.score <= 49
    assert r.cap_severity == CRITICAL


def test_failing_a_check_never_raises_the_grade():
    """Monotonicity: flipping any single PASS to FAIL must not increase the score."""
    base = [_f(CRITICAL, PASS), _f(HIGH, PASS), _f(MEDIUM, PASS),
            _f(LOW, PASS), _f(MEDIUM, PASS), _f(HIGH, PASS)]
    base_score = compute(base).score
    for i in range(len(base)):
        flipped = list(base)
        flipped[i] = _f(base[i].severity, FAIL)
        assert compute(flipped).score <= base_score, (
            f"flipping check {i} ({base[i].severity}) PASS->FAIL raised the score"
        )


# ---------------------------------------------------------------------------
# B-014: empty / all-UNKNOWN / all-advisory -> "not assessable", not a fake F
# ---------------------------------------------------------------------------

def test_empty_is_not_assessable_not_f():
    r = compute([])
    assert r.assessable is False
    assert r.grade == "N/A"
    assert r.score == 0


def test_all_unknown_is_not_assessable():
    r = compute([_f(CRITICAL, UNKNOWN), _f(HIGH, UNKNOWN)])
    assert r.assessable is False
    assert r.grade == "N/A"


def test_all_advisory_is_not_assessable():
    r = compute([_f(CRITICAL, FAIL, scored=False), _f(HIGH, PASS, scored=False)])
    assert r.assessable is False


def test_real_failure_is_assessable():
    r = compute([_f(CRITICAL, FAIL), _f(HIGH, PASS)])
    assert r.assessable is True
    assert r.grade == "F"
