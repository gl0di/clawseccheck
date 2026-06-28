"""Tests for the what-if projection feature (scoring.project).

Covers:
- projected score >= current score (fixing only helps)
- cap-lift case: Critical FAIL holds the grade cap; fixing it tops any non-cap fix
- all-PASS / no-FAIL → top1 is None, cumulative delta 0
- determinism: same input → identical output on repeated calls
- scored-FAIL example where top1 delta > 0 and grade improves
- suppressed / unscored FAILs excluded from candidates
- input findings not mutated
- cumulative flips only CRITICAL + HIGH FAILs, leaving MEDIUM/LOW intact
"""
from dataclasses import replace as dc_replace

from clawseccheck.catalog import CRITICAL, FAIL, HIGH, LOW, MEDIUM, PASS, Finding
from clawseccheck.scoring import compute, project


# ── helper ───────────────────────────────────────────────────────────────────

def _f(fid: str, severity: str, status: str,
       scored: bool = True, suppressed: bool = False) -> Finding:
    return Finding(
        fid, "title", severity, status, "detail", "fix", "framework",
        scored=scored, suppressed=suppressed,
    )


# ── 1. projected score never decreases ───────────────────────────────────────

def test_top1_projected_score_gte_current():
    findings = [
        _f("c1", CRITICAL, FAIL),
        _f("h1", HIGH, PASS),
        _f("m1", MEDIUM, PASS),
    ]
    result = project(findings)
    assert result["top1"]["projected_score"] >= result["current"]["score"]


def test_cumulative_projected_score_gte_current():
    findings = [
        _f("c1", CRITICAL, FAIL),
        _f("h1", HIGH, FAIL),
        _f("m1", MEDIUM, PASS),
    ]
    result = project(findings)
    assert result["cumulative"]["projected_score"] >= result["current"]["score"]


# ── 2. cap-lift case ──────────────────────────────────────────────────────────

def test_cap_lift_finding_selected_as_top1():
    """A Critical FAIL caps the score at <=49 (F). Fixing it must be top1 over
    a Low FAIL whose fix cannot lift the critical cap (grade stays F)."""
    findings = [
        _f("crit1", CRITICAL, FAIL),   # caps entire result at 49
        _f("low1", LOW, FAIL),          # low cap 94 is irrelevant while CRITICAL holds
        _f("h1", HIGH, PASS),
        _f("h2", HIGH, PASS),
        _f("h3", HIGH, PASS),
    ]
    result = project(findings)
    assert result["current"]["grade"] == "F"
    assert result["top1"]["finding_id"] == "crit1"
    assert result["top1"]["projected_grade"] != "F"


def test_cap_lift_delta_beats_non_cap_fix_delta():
    """top1 delta (cap-lifting fix) must be >= the delta of fixing the LOW FAIL
    that cannot escape the CRITICAL cap."""
    findings = [
        _f("crit1", CRITICAL, FAIL),
        _f("low1", LOW, FAIL),
        _f("h1", HIGH, PASS),
        _f("h2", HIGH, PASS),
        _f("h3", HIGH, PASS),
    ]
    result = project(findings)

    # independently compute what fixing only the LOW FAIL would yield
    low_fixed = [dc_replace(f, status=PASS) if f.id == "low1" else f for f in findings]
    low_delta = compute(low_fixed).score - result["current"]["score"]

    assert result["top1"]["delta"] >= low_delta


# ── 3. all-PASS / no-FAIL ────────────────────────────────────────────────────

def test_all_pass_top1_is_none():
    findings = [_f("h1", HIGH, PASS), _f("m1", MEDIUM, PASS), _f("l1", LOW, PASS)]
    result = project(findings)
    assert result["top1"] is None


def test_all_pass_cumulative_delta_zero():
    findings = [_f("h1", HIGH, PASS), _f("m1", MEDIUM, PASS)]
    result = project(findings)
    assert result["cumulative"]["delta"] == 0
    assert result["cumulative"]["projected_score"] == result["current"]["score"]


def test_empty_findings_top1_none_and_cumulative_zero():
    result = project([])
    assert result["top1"] is None
    assert result["cumulative"]["delta"] == 0


# ── 4. determinism ───────────────────────────────────────────────────────────

def test_deterministic_on_repeated_calls():
    findings = [
        _f("c1", CRITICAL, FAIL),
        _f("h1", HIGH, FAIL),
        _f("m1", MEDIUM, PASS),
        _f("l1", LOW, PASS),
        _f("h2", HIGH, PASS),
    ]
    r1 = project(findings)
    r2 = project(findings)
    assert r1 == r2


def test_deterministic_with_multiple_same_severity_fails():
    """Multiple FAILs at the same severity must resolve to the same top1 each time."""
    findings = [
        _f("h1", HIGH, FAIL),
        _f("h2", HIGH, FAIL),
        _f("h3", HIGH, FAIL),
        _f("m1", MEDIUM, PASS),
    ]
    r1 = project(findings)
    r2 = project(findings)
    assert r1["top1"]["finding_id"] == r2["top1"]["finding_id"]


# ── 5. scored-FAIL where top1 improves grade ─────────────────────────────────

def test_top1_delta_positive_and_grade_improves():
    """One HIGH FAIL alongside one HIGH PASS gives grade D.
    Fixing the FAIL projects to grade A with a positive delta."""
    findings = [
        _f("hf", HIGH, FAIL),
        _f("hp", HIGH, PASS),
    ]
    result = project(findings)
    assert result["current"]["grade"] == "D"
    assert result["top1"] is not None
    assert result["top1"]["delta"] > 0
    assert result["top1"]["projected_grade"] != "D"


def test_single_critical_fail_projects_to_full_score():
    """A single Critical FAIL with no other findings: fixing it should project
    to a perfect score (no remaining scored findings → assessable=False, score 0)
    or an improved grade depending on remaining findings."""
    findings = [_f("c1", CRITICAL, FAIL), _f("h1", HIGH, PASS), _f("h2", HIGH, PASS)]
    result = project(findings)
    assert result["top1"]["projected_score"] > result["current"]["score"]


# ── 6. suppressed / unscored FAILs excluded ──────────────────────────────────

def test_suppressed_fail_excluded_from_top1():
    findings = [
        _f("hs", HIGH, FAIL, suppressed=True),
        _f("hp", HIGH, PASS),
    ]
    result = project(findings)
    assert result["top1"] is None


def test_unscored_fail_excluded_from_top1():
    findings = [
        _f("hu", HIGH, FAIL, scored=False),
        _f("hp", HIGH, PASS),
    ]
    result = project(findings)
    assert result["top1"] is None


def test_suppressed_fail_excluded_from_cumulative():
    """Suppressed FAILs must not appear in the cumulative fix set."""
    findings = [
        _f("cs", CRITICAL, FAIL, suppressed=True),  # suppressed — excluded
        _f("hp", HIGH, PASS),
    ]
    result = project(findings)
    # No fixable FAILs → cumulative equals current
    assert result["cumulative"]["delta"] == 0


# ── 7. input not mutated ─────────────────────────────────────────────────────

def test_input_findings_not_mutated():
    findings = [_f("c1", CRITICAL, FAIL), _f("h1", HIGH, PASS)]
    original = [(f.id, f.status) for f in findings]
    project(findings)
    assert [(f.id, f.status) for f in findings] == original


# ── 8. cumulative fixes only CRITICAL + HIGH ──────────────────────────────────

def test_cumulative_leaves_medium_fail_in_place():
    """cumulative fixes CRITICAL+HIGH FAILs; a MEDIUM FAIL remains, so the
    resulting score is still capped below 90 (by the MEDIUM cap at 89)."""
    findings = [
        _f("c1", CRITICAL, FAIL),
        _f("h1", HIGH, FAIL),
        _f("m1", MEDIUM, FAIL),  # NOT fixed by cumulative
        _f("l1", LOW, PASS),
    ]
    result = project(findings)
    # cumulative fixed CRITICAL+HIGH → score improves
    assert result["cumulative"]["projected_score"] > result["current"]["score"]
    # but MEDIUM FAIL still caps at 89, so grade cannot reach "A"
    assert result["cumulative"]["projected_score"] <= 89


def test_cumulative_delta_positive_when_crit_high_fails_exist():
    findings = [
        _f("c1", CRITICAL, FAIL),
        _f("h1", HIGH, PASS),
        _f("m1", MEDIUM, PASS),
    ]
    result = project(findings)
    assert result["cumulative"]["delta"] > 0


def test_cumulative_delta_zero_when_only_medium_low_fail():
    """If only MEDIUM/LOW FAILs exist, cumulative must not change the score
    (it only flips CRITICAL+HIGH)."""
    findings = [
        _f("m1", MEDIUM, FAIL),
        _f("l1", LOW, FAIL),
        _f("h1", HIGH, PASS),
    ]
    result = project(findings)
    assert result["cumulative"]["delta"] == 0
    assert result["cumulative"]["projected_score"] == result["current"]["score"]


# ── 9. return-shape sanity ────────────────────────────────────────────────────

def test_return_shape_with_fails():
    findings = [_f("h1", HIGH, FAIL), _f("m1", MEDIUM, PASS)]
    result = project(findings)
    assert set(result.keys()) == {"current", "top1", "cumulative"}
    assert set(result["current"].keys()) == {"score", "grade"}
    assert set(result["top1"].keys()) == {"finding_id", "projected_score", "projected_grade", "delta"}
    assert set(result["cumulative"].keys()) == {"projected_score", "projected_grade", "delta"}


def test_return_shape_no_fails():
    findings = [_f("h1", HIGH, PASS)]
    result = project(findings)
    assert result["top1"] is None
    assert set(result["cumulative"].keys()) == {"projected_score", "projected_grade", "delta"}
