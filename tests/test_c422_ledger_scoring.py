"""CLAWSECCHECK-C-422 — `scoring.compute(ledger=)` / `graded` / `not_checked` /
`missing_layers`, and the projection path (`scoring.project(ledger=)`).

Teaches `scoring.py` about the five-layer ledger already defined in `layers.py`
(layers.py itself is out of scope here — see `tests/test_c421_layers.py`).

The single most important property under test: **`ledger=None` means graded**. Every
existing call site (including `clawseccheck.__init__.audit()`) omits `ledger` and must
see byte-identical behaviour to before this argument existed — that is what keeps the
rest of the suite green.

B-547 REVISION: the original version of this module additionally asserted that a
COMPLETE ledger (every layer `"ran"`) was fully indistinguishable from no ledger at
all. That was itself the defect: a `ScoreResult` that cannot tell "every layer proved
it ran" from "nothing was ever tracked" cannot let a renderer state coverage from
evidence (see `ScoreResult.ledger_present`'s own docstring, and
`tests/test_b547_ledger_present.py` for the dedicated three-state coverage). `score`/
`grade`/`graded`/`not_checked`/`missing_layers` — every field that feeds a verdict —
still agree exactly between the two; only `ledger_present` differs. That is
deliberate, not a regression of the "byte-identical for every existing call site"
promise above: no existing call site ever read `ledger_present` (it did not exist),
so every one of them still sees byte-identical behaviour.

Stdlib-only, offline, no network, nothing written outside pytest's own machinery.
"""
from __future__ import annotations

import inspect

from clawseccheck.catalog import CRITICAL, FAIL, HIGH, LOW, MEDIUM, PASS, UNKNOWN, Finding
from clawseccheck.layers import (
    COVERAGE_PARTIAL,
    COVERAGE_UNKNOWN,
    LAYER_INSTALLED_SWEEP,
    LAYER_LIVE_BEHAVIOUR,
    LAYER_LOGS_TRAJECTORIES,
    LAYER_ORDER,
    LAYER_SELF_REPORT,
    LAYER_STATIC,
    STATUS_ERROR,
    STATUS_NOT_REACHED,
    STATUS_RAN,
    STATUS_REFUSED,
    STATUS_SKIPPED,
    STATUS_UNAVAILABLE,
    LayerLedger,
    LayerState,
)
from clawseccheck import scoring
from clawseccheck.scoring import ScoreResult, compute, project

import pytest


# ── helpers ──────────────────────────────────────────────────────────────────

def _f(severity: str, status: str, fid: str = "X", scored: bool = True) -> Finding:
    return Finding(fid, "t", severity, status, "d", "fix", "fw", scored)


def _all_ran_ledger() -> LayerLedger:
    return LayerLedger(states={layer: LayerState(status=STATUS_RAN) for layer in LAYER_ORDER})


def _ledger_with(layer: str, status: str, not_reached: tuple = ()) -> LayerLedger:
    states = {lyr: LayerState(status=STATUS_RAN) for lyr in LAYER_ORDER}
    states[layer] = LayerState(status=status, not_reached=not_reached)
    return LayerLedger(states=states)


# A handful of representative finding-set "scenarios" (the house idiom in
# test_scoring.py/test_projection.py builds synthetic Finding lists rather than
# loading real fixtures/ homes through the collector — matched here) standing in
# for "several fixture homes": empty, all-clean, a capped run, and an
# all-UNKNOWN/not-assessable run.
_SCENARIOS: dict = {
    "empty": [],
    "all_pass": [_f(CRITICAL, PASS, "c1"), _f(HIGH, PASS, "h1"), _f(LOW, PASS, "l1")],
    "critical_fail_capped": [_f(CRITICAL, FAIL, "c1")] + [
        _f(LOW, PASS, f"l{i}") for i in range(5)
    ],
    "all_unknown": [_f(CRITICAL, UNKNOWN, "c1"), _f(HIGH, UNKNOWN, "h1")],
}


# ── 1. regression: ledger=None means graded, and a complete ledger changes nothing ──

@pytest.mark.parametrize("name", sorted(_SCENARIOS))
def test_no_ledger_is_graded_with_no_missing_layers(name: str) -> None:
    findings = _SCENARIOS[name]
    r = compute(findings)
    assert r.graded is True
    assert r.not_checked == ()
    assert r.missing_layers == ()
    # B-547: the "absent" state — no evidence a ledger was ever tracked.
    assert r.ledger_present is False


@pytest.mark.parametrize("name", sorted(_SCENARIOS))
def test_complete_ledger_agrees_with_no_ledger_on_every_scoring_field(name: str) -> None:
    """B-547 REVISION of the old `test_complete_ledger_equals_no_ledger`: a complete
    ledger and no ledger must still agree on every field that feeds a verdict (score,
    grade, graded, not_checked, missing_layers, every cap) — that half of the original
    C-422 guarantee stands. They must NOT agree on `ledger_present`: that was the
    defect (B-547) — a complete ledger is now provably distinguishable from no ledger
    at all, which `test_no_ledger_and_complete_ledger_are_distinguishable` below pins
    directly."""
    import dataclasses

    findings = _SCENARIOS[name]
    without = compute(findings)
    with_complete = compute(findings, ledger=_all_ran_ledger())
    without_fields = dataclasses.asdict(without)
    complete_fields = dataclasses.asdict(with_complete)
    del without_fields["ledger_present"]
    del complete_fields["ledger_present"]
    assert without_fields == complete_fields


def test_no_ledger_and_complete_ledger_are_distinguishable() -> None:
    """The B-547 fix, pinned directly: `ledger=None` ("absent") and a complete ledger
    ("complete") must no longer be `==` as whole `ScoreResult`s — a consumer holding
    only a `ScoreResult` must be able to tell them apart. Non-vacuity: both branches
    are asserted, so a broken `__eq__`/an always-True comparison cannot pass this."""
    findings = _SCENARIOS["all_pass"]
    without = compute(findings)
    with_complete = compute(findings, ledger=_all_ran_ledger())
    assert without.ledger_present is False
    assert with_complete.ledger_present is True
    assert without != with_complete


# ── 2. each incomplete status on one layer -> graded False, and it shows up in
#      missing_layers paired with its own status ────────────────────────────────

@pytest.mark.parametrize(
    "status",
    [STATUS_SKIPPED, STATUS_REFUSED, STATUS_UNAVAILABLE, STATUS_ERROR, STATUS_NOT_REACHED],
)
def test_each_incomplete_status_ungrades_and_is_named_in_missing_layers(status: str) -> None:
    ledger = _ledger_with(LAYER_SELF_REPORT, status)
    r = compute([_f(HIGH, PASS)], ledger=ledger)
    assert r.graded is False
    assert r.missing_layers == ((LAYER_SELF_REPORT, status),)
    # B-547: "partial" — a ledger was supplied, it just proves incompleteness.
    assert r.ledger_present is True


# ── 3. central subtlety: all five ran, some carry not_reached -> graded True AND
#      not_checked non-empty ────────────────────────────────────────────────────

def test_all_ran_with_not_reached_is_graded_but_not_fully_checked() -> None:
    states = {layer: LayerState(status=STATUS_RAN) for layer in LAYER_ORDER}
    states[LAYER_STATIC] = LayerState(status=STATUS_RAN, not_reached=("dup", "static-only"))
    states[LAYER_INSTALLED_SWEEP] = LayerState(status=STATUS_RAN, not_reached=("dup", "sweep-only"))
    ledger = LayerLedger(states=states)

    r = compute([_f(HIGH, PASS)], ledger=ledger)
    assert r.graded is True  # "ran" means started and named its limits, not exhausted
    assert r.missing_layers == ()
    # not_checked is passed through faithfully (order/dedupe is LayerLedger's job,
    # already pinned by test_c421_layers.py's own union test).
    assert r.not_checked == ("dup", "static-only", "sweep-only")


# ── 4. graded vs assessable are independent ─────────────────────────────────────

def test_assessable_true_graded_false_is_reachable() -> None:
    ledger = _ledger_with(LAYER_LIVE_BEHAVIOUR, STATUS_REFUSED)
    r = compute([_f(HIGH, PASS), _f(MEDIUM, PASS)], ledger=ledger)
    assert r.assessable is True
    assert r.graded is False


def test_assessable_false_graded_true_is_reachable() -> None:
    r = compute([], ledger=_all_ran_ledger())
    assert r.assessable is False
    assert r.graded is True


# ── 5. total == 0 early-return path with an incomplete ledger -> graded False ───

def test_total_zero_path_with_incomplete_ledger_is_ungraded() -> None:
    ledger = _ledger_with(LAYER_LOGS_TRAJECTORIES, STATUS_ERROR)
    r = compute([], ledger=ledger)
    assert r.assessable is False  # unchanged: still nothing scorable
    assert r.graded is False
    assert r.missing_layers == ((LAYER_LOGS_TRAJECTORIES, STATUS_ERROR),)


def test_total_zero_path_with_complete_ledger_stays_graded() -> None:
    r = compute([], ledger=_all_ran_ledger())
    assert r.assessable is False
    assert r.graded is True


# ── 6. positional construction still works (tail-append discipline) ─────────────

def test_positional_score_result_construction_defaults_graded_true() -> None:
    r = ScoreResult(0, "N/A", False, 0, 0, 0, assessable=False)
    assert r.graded is True
    assert r.not_checked == ()
    assert r.missing_layers == ()
    # B-547: a caller predating this field (or the many positional-construction call
    # sites this test exists to protect) gets the "absent" reading, tail-appended
    # exactly like `graded`/`not_checked`/`missing_layers` above.
    assert r.ledger_present is False


# ── 7. the generalisation: project()'s _cap_kwargs carries every keyword-only
#      argument compute() accepts, derived from the signature, never hardcoded ──

def test_project_forwards_every_compute_kwonly_argument(monkeypatch) -> None:
    real_compute = scoring.compute
    seen_kwarg_sets: list[frozenset] = []

    def spy(*args, **kwargs):
        seen_kwarg_sets.append(frozenset(kwargs))
        return real_compute(*args, **kwargs)

    monkeypatch.setattr(scoring, "compute", spy)

    findings = [
        _f(CRITICAL, FAIL, "c1"),
        _f(HIGH, FAIL, "h1"),
        _f(HIGH, PASS, "h2"),
    ]
    scoring.project(findings)

    compute_kwonly = {
        name
        for name, param in inspect.signature(real_compute).parameters.items()
        if param.kind is inspect.Parameter.KEYWORD_ONLY
    }
    assert seen_kwarg_sets, "project() never called compute()"
    # every compute() call inside project() (current / per-candidate / cumulative)
    # must be given the exact same keyword-only argument set compute() accepts —
    # a future cap-only signal added to compute() cannot silently miss this path.
    for kwargs in seen_kwarg_sets:
        assert kwargs == compute_kwonly


# B-512: `known_ungraded` is project()'s alone and deliberately has no compute()
# counterpart. Every other keyword here is an INPUT to scoring — a cap signal, or the
# ledger — and the guard below exists so a new one cannot be added to compute() and
# forgotten on this path. `known_ungraded` is not an input to scoring at all: it lets a
# caller that already holds the answer ("the ScoreResult I am rendering says ungraded")
# suppress the projection's figures without re-deriving them, and it is one-directional
# — it can only withhold, never grant. Adding it to compute() would be meaningless,
# since compute() is where `graded` is decided in the first place.
_PROJECT_ONLY_KWONLY = {"known_ungraded"}


def test_project_signature_still_matches_compute_kwonly_set() -> None:
    """project()'s own optional keyword-only surface mirrors compute()'s (minus
    `ctx`, which project() takes positionally, same as compute() does, and minus the
    documented project-only names above)."""
    compute_kwonly = {
        name
        for name, param in inspect.signature(compute).parameters.items()
        if param.kind is inspect.Parameter.KEYWORD_ONLY
    }
    project_kwonly = {
        name
        for name, param in inspect.signature(project).parameters.items()
        if param.kind is inspect.Parameter.KEYWORD_ONLY
    }
    assert project_kwonly - _PROJECT_ONLY_KWONLY == compute_kwonly
    # The exemption must stay honest: every name in it has to really be on project().
    assert _PROJECT_ONLY_KWONLY <= project_kwonly
    assert "ledger" in compute_kwonly  # sanity: would be vacuous if C-422 regressed


# ── 8. project(): ungraded suppresses every letter; graded is unchanged ─────────

def test_project_ungraded_suppresses_every_grade_value() -> None:
    findings = [_f(CRITICAL, FAIL, "c1"), _f(HIGH, PASS, "h1")]
    ledger = _ledger_with(LAYER_LIVE_BEHAVIOUR, STATUS_REFUSED)

    result = project(findings, ledger=ledger)

    assert result["graded"] is False
    assert result["current"]["grade"] is None
    assert result["top1"] is not None
    assert result["top1"]["projected_grade"] is None
    assert result["cumulative"]["projected_grade"] is None
    # C-423/C-425: the numbers are withheld too, not just the letters. Keeping them was
    # the original call ("internal data, the renderer decides") and it leaked: --full
    # --json published `"score": null` at the top level while
    # `projection.current.score` still carried 49, so the withheld number was one key
    # away. Caught by test_full_json_projection_current_matches_top_level_score.
    assert result["current"]["score"] is None
    assert result["top1"]["projected_score"] is None
    assert result["cumulative"]["projected_score"] is None
    # `delta` stays real either way: a difference between two withheld numbers reveals
    # no verdict, and "fixing this one is the biggest win" is the actionable part.
    assert isinstance(result["top1"]["delta"], int)


def test_project_graded_run_unchanged_from_today() -> None:
    findings = [_f(CRITICAL, FAIL, "c1"), _f(HIGH, PASS, "h1")]

    without_ledger = project(findings)
    with_complete_ledger = project(findings, ledger=_all_ran_ledger())

    for result in (without_ledger, with_complete_ledger):
        assert result["graded"] is True
        assert result["current"]["grade"] is not None
        assert result["top1"]["projected_grade"] is not None
        assert result["cumulative"]["projected_grade"] is not None

    # ledger=None and a complete ledger must project identically, mirroring
    # compute()'s own "ledger=None means graded" equality rule.
    assert with_complete_ledger == without_ledger


def test_project_ungraded_top1_none_case_still_suppresses_current_and_cumulative() -> None:
    """No fixable FAILs -> top1 is None, but current/cumulative grades must still be
    suppressed when the run itself is ungraded."""
    findings = [_f(HIGH, PASS, "h1"), _f(MEDIUM, PASS, "m1")]
    ledger = _ledger_with(LAYER_SELF_REPORT, STATUS_UNAVAILABLE)

    result = project(findings, ledger=ledger)

    assert result["graded"] is False
    assert result["top1"] is None
    assert result["current"]["grade"] is None
    assert result["cumulative"]["projected_grade"] is None


# ── B-558 guard: `coverage` must never reach the grade ──────────────────────────
#
# The whole point of adding a THIRD axis to LayerState (layers.py's `coverage`) is
# that it must stay purely descriptive — `LayerLedger.complete`/`.missing`/
# `.not_checked` and `scoring.compute` all read `.status`/`.not_reached` only (see
# each's own source). If `coverage` ever changed whether/how a grade is issued, that
# would be a WIDER decision than the one this slice was authorised to make.


def _all_ran_ledger_with_coverage(coverage: str) -> LayerLedger:
    return LayerLedger(states={
        layer: LayerState(status=STATUS_RAN, coverage=coverage) for layer in LAYER_ORDER
    })


def test_all_partial_coverage_still_reads_complete_and_graded() -> None:
    """All five layers `ran` but every one PARTIAL — `LayerLedger.complete` only
    reads `.status`, so it must still be True, and the run must still be graded."""
    findings = _SCENARIOS["all_pass"]
    ledger = _all_ran_ledger_with_coverage(COVERAGE_PARTIAL)

    assert ledger.complete is True
    assert ledger.missing == ()

    score = compute(findings, ledger=ledger)
    assert score.graded is True
    assert score.grade is not None
    assert score.missing_layers == ()


def test_coverage_value_never_changes_a_scoring_field() -> None:
    """The tight form of the guard: two ledgers identical in every `status`/
    `not_reached`, differing ONLY in `coverage` (UNKNOWN vs PARTIAL, on all five
    layers), must produce `ScoreResult`s that are fully `==` — `coverage` is not
    read anywhere in the scoring path. Non-vacuity: `coverage` itself really does
    differ between the two ledgers built here, so this cannot pass by comparing a
    ledger to an identical copy of itself."""
    findings = _SCENARIOS["all_pass"]
    unknown_ledger = _all_ran_ledger_with_coverage(COVERAGE_UNKNOWN)
    partial_ledger = _all_ran_ledger_with_coverage(COVERAGE_PARTIAL)
    assert (
        unknown_ledger.states[LAYER_STATIC].coverage
        != partial_ledger.states[LAYER_STATIC].coverage
    )

    with_unknown = compute(findings, ledger=unknown_ledger)
    with_partial = compute(findings, ledger=partial_ledger)
    assert with_unknown == with_partial


def test_all_partial_coverage_ledger_scores_same_as_no_ledger() -> None:
    """As `test_complete_ledger_agrees_with_no_ledger_on_every_scoring_field` above,
    but for the new PARTIAL-everywhere shape: every scoring field must still agree
    with `ledger=None` except `ledger_present`, which the B-547 fix deliberately
    keeps distinguishable regardless of coverage."""
    import dataclasses

    findings = _SCENARIOS["all_pass"]
    without = compute(findings)
    with_partial = compute(findings, ledger=_all_ran_ledger_with_coverage(COVERAGE_PARTIAL))

    without_fields = dataclasses.asdict(without)
    partial_fields = dataclasses.asdict(with_partial)
    del without_fields["ledger_present"]
    del partial_fields["ledger_present"]
    assert without_fields == partial_fields
