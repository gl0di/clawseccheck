"""F-140 step 5a — ``scoring.assessment_coverage`` gains ``not_applicable`` and
``applicable_total`` as a PURE ADDITION.

The whole value of this change is what it does NOT move. ``unknown`` deliberately stays
the FULL UNKNOWN count rather than being narrowed to exclude not-applicable findings, so
``assessable``, ``unknown``, ``assessable_frac``, ``unknown_frac`` and the
``assessable + unknown == scored_total`` invariant keep exactly the values they had
before ``Finding.not_applicable`` existed. That is what lets the flag roll out across the
check catalog without silently relaxing report.py's LOW_COVERAGE_FRAC /
DRIFT_UNKNOWN_FRAC bands in the same change -- rebasing those onto ``applicable_total``
is a separate, deliberate task.

So the load-bearing tests here are the NEGATIVE ones: flipping the flag on real findings
must leave every pre-existing key byte-identical. ``tests/test_assurance_coverage.py``
pins the invariant itself and must stay green unchanged.

Offline, read-only.
"""
from __future__ import annotations

import dataclasses

import pytest

from clawseccheck import scoring
from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN, Finding

_PRE_EXISTING_KEYS = (
    "scored_total",
    "assessable",
    "unknown",
    "assessable_frac",
    "unknown_frac",
)


def _f(fid: str, status: str, *, not_applicable: bool = False, scored: bool = True) -> Finding:
    return Finding(
        fid,
        f"{fid} title",
        "MEDIUM",
        status,
        "detail",
        "fix",
        "framework",
        scored,
        [],
        not_applicable=not_applicable,
    )


def _corpus() -> list[Finding]:
    """Two of each status, with two of the UNKNOWNs flagged not-applicable."""
    return [
        _f("A1", PASS),
        _f("A2", FAIL),
        _f("A3", WARN),
        _f("A4", UNKNOWN),
        _f("A5", UNKNOWN, not_applicable=True),
        _f("A6", UNKNOWN, not_applicable=True),
    ]


# ---------------------------------------------------------------------------
# The two new keys.
# ---------------------------------------------------------------------------

def test_new_keys_are_present():
    cov = scoring.assessment_coverage(_corpus())
    assert cov["not_applicable"] == 2
    assert cov["applicable_total"] == 4  # scored_total(6) - not_applicable(2)


def test_new_keys_present_on_the_empty_corpus():
    cov = scoring.assessment_coverage([])
    assert cov["scored_total"] == 0
    assert cov["not_applicable"] == 0
    assert cov["applicable_total"] == 0


def test_applicable_total_is_scored_total_minus_not_applicable():
    cov = scoring.assessment_coverage(_corpus())
    assert cov["applicable_total"] == cov["scored_total"] - cov["not_applicable"]


def test_not_applicable_never_exceeds_unknown():
    """``__post_init__`` forbids the flag at a non-UNKNOWN status, and the counter tests
    the status anyway -- together that keeps ``applicable_total >= assessable`` safe to
    rely on."""
    cov = scoring.assessment_coverage(_corpus())
    assert cov["not_applicable"] <= cov["unknown"]
    assert cov["applicable_total"] >= cov["assessable"]


def test_flag_at_non_unknown_status_is_not_counted():
    """A caller that constructs a PASS finding with the flag set gets it normalized away
    by ``Finding.__post_init__``; the counter's own status test is the second line of
    defence, so neither can drift into counting it."""
    f = _f("A1", PASS, not_applicable=True)
    assert f.not_applicable is False, "precondition: __post_init__ normalizes"
    assert scoring.assessment_coverage([f])["not_applicable"] == 0


# ---------------------------------------------------------------------------
# The restraint: every PRE-EXISTING key is blind to the flag.
# ---------------------------------------------------------------------------

def test_pre_existing_keys_are_unchanged_by_the_flag():
    """The core guarantee. Same findings, flag cleared vs set -- the five pre-existing
    keys must be identical, so no consumer reading them can observe the migration."""
    findings = _corpus()
    cleared = [dataclasses.replace(f, not_applicable=False) for f in findings]

    with_flag = scoring.assessment_coverage(findings)
    without = scoring.assessment_coverage(cleared)

    assert with_flag["not_applicable"] == 2 and without["not_applicable"] == 0, (
        "precondition: the two runs must actually differ in the flag, or this test is vacuous"
    )
    for key in _PRE_EXISTING_KEYS:
        assert with_flag[key] == without[key], (
            f"{key} moved when only not_applicable changed -- assessment_coverage's "
            "pre-existing keys must stay blind to the flag (F-140 step 5a is additive; "
            "narrowing 'unknown' is explicitly out of scope)"
        )


def test_unknown_is_not_narrowed():
    """Stated as its own test because it is the single most tempting 'improvement': the
    full UNKNOWN count includes not-applicable findings, and must keep doing so."""
    cov = scoring.assessment_coverage(_corpus())
    assert cov["unknown"] == 3, "unknown must count ALL UNKNOWN findings, flagged or not"
    assert cov["assessable"] == 3


def test_invariant_still_holds():
    cov = scoring.assessment_coverage(_corpus())
    assert cov["assessable"] + cov["unknown"] == cov["scored_total"]


def test_fractions_still_divide_by_scored_total():
    """Not by ``applicable_total`` -- that is exactly the band-relaxing change reserved
    for a separate task."""
    cov = scoring.assessment_coverage(_corpus())
    assert cov["assessable_frac"] == pytest.approx(cov["assessable"] / cov["scored_total"])
    assert cov["unknown_frac"] == pytest.approx(cov["unknown"] / cov["scored_total"])


# ---------------------------------------------------------------------------
# End-to-end on a real audit, so the guarantee is not just an artefact of hand-built
# findings.
# ---------------------------------------------------------------------------

def test_real_audit_pre_existing_keys_blind_to_the_flag(tmp_path):
    from clawseccheck import audit

    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    _ctx, findings, _ = audit(tmp_path)

    cov = scoring.assessment_coverage(findings)
    cleared = scoring.assessment_coverage(
        [dataclasses.replace(f, not_applicable=False) for f in findings]
    )

    assert cov["not_applicable"] > 0, (
        "a fully-read empty config should produce some not-applicable findings after the "
        "F-140 migration -- if this is 0 the comparison below is vacuous"
    )
    for key in _PRE_EXISTING_KEYS:
        assert cov[key] == cleared[key], f"{key} moved on a real audit"
    assert cov["applicable_total"] == cov["scored_total"] - cov["not_applicable"]
