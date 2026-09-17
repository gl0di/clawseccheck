"""CLAWSECCHECK-C-469 — the pass-rate backstop's own rounding floor.

`raw_score` is `round(earned / total * 100)`. On a real machine `total` is ~407 weight
units, so one integer of the reported figure is about four weight units, and a
`WARN -> FAIL` on a LOW check costs half of one — small enough to leave the rounded figure
standing still while a real regression happened underneath it. `ScoreResult` already
carries the exact `earned`/`total` pair (B-505); this closes the gap by recording and
comparing them directly, through the one shared predicate (`monitordims._shared.
raw_backstop`) both the monitor and `--trend` already route through since B-691.

That closure is not free. An independent adversarial pass on this task's FIRST attempt
(comparing exact `earned` whenever `total` matched, over the pre-existing id-only scope
hash) found a real soundness hole: two scored checks whose SEVERITIES move in offsetting
directions between two runs — one PASSing check's weight shrinks, one FAILing check's
weight grows by exactly the same amount — hold `total` pinned equal with NEITHER check's
own status ever changing, while `earned` genuinely falls. Severity is data-dependent for
some checks (e.g. B171: CRITICAL vs HIGH depending on which `commands.*` surface is
enabled), so this is reachable within a single build, not only across a version bump.

The fix isn't "compare earned less eagerly" — it's making the SCOPE HASH itself see the
retune: `_raw_score_scope` (monitordims/_score.py) now hashes `id:weight` pairs, not bare
ids, so a lone severity change on an unchanged id set moves the hash and the comparison
correctly stands down as RAW_SCOPE_MOVED. Once scope equality PROVES per-check weight
equality, comparing `earned` directly is sound: a fall behind pinned weights can only come
from a check's own status moving.

Offline, stdlib only, writes nothing outside tmp_path.
"""
from __future__ import annotations

from clawseccheck.catalog import Finding, WEIGHT
from clawseccheck.history import load, record, render_trend
from clawseccheck.monitordims._score import _diff_score, _raw_score_scope
from clawseccheck.monitordims._shared import RAW_DEGRADED, RAW_SCOPE_MOVED, raw_backstop
from clawseccheck.scoring import compute

_SCOPE = "same-scope-hash"


def _f(id_, severity, status, scored=True):
    return Finding(id=id_, title="t", severity=severity, status=status,
                   detail="d", fix="f", framework="x", scored=scored)


def _arm(prev_extra: dict, curr_extra: dict):
    """`_diff_score`, driven directly like test_b694 — everything but the fields under
    test held equal."""
    alerts: list = []
    notes: list = []
    _diff_score(
        True, True, alerts,
        {"score": 90, "grade": "B", "raw_score_scope": _SCOPE, **curr_extra}, False,
        lambda category, sentence: notes.append((category, sentence)),
        {"score": 90, "grade": "B", "raw_score_scope": _SCOPE, **prev_extra}, False,
    )
    return alerts, notes


# --------------------------------------------------------------- the resolution gain

def test_a_subrounding_fall_is_caught_only_once_earned_and_total_are_recorded():
    """Test-plan item 1: a WARN -> FAIL on one LOW check, in a big enough denominator that
    the ROUNDED raw_score does not move. Both directions asserted, so this shows the gain
    rather than assuming it.

    total=200: a LOW (weight 1) going WARN (0.5 earned) -> FAIL (0 earned) drops earned by
    0.5 on a base of ~150. round(150.5/200*100) == round(150/200*100) == 75 — the rounded
    figure is silent both ways.
    """
    prev_extra = {"raw_score": 75, "raw_score_earned": 150.5, "raw_score_total": 200.0}
    curr_extra = {"raw_score": 75, "raw_score_earned": 150.0, "raw_score_total": 200.0}

    # WITH earned/total: the sub-integer fall is caught.
    alerts, notes = _arm(prev_extra, curr_extra)
    assert len(alerts) == 1, (alerts, notes)
    level, text = alerts[0]
    assert level == "HIGH" and "degraded" in text.lower(), text

    # WITHOUT them (a baseline predating this fix, or a duck-typed score with no
    # .earned/.total): the exact same pair of runs, minus the two new keys, produces
    # nothing — the documented resolution limit this task closes.
    bare_prev = {k: v for k, v in prev_extra.items() if k == "raw_score"}
    bare_curr = {k: v for k, v in curr_extra.items() if k == "raw_score"}
    old_alerts, old_notes = _arm(bare_prev, bare_curr)
    assert old_alerts == [] and old_notes == [], (old_alerts, old_notes)


def test_rounding_boundary_earned_moves_round_does_not():
    """Test-plan item 2, isolated from any particular check shape: earned moves, the
    rounded percentage it feeds does not."""
    prev_extra = {"raw_score": 75, "raw_score_earned": 301.0, "raw_score_total": 400.0}
    curr_extra = {"raw_score": 75, "raw_score_earned": 300.0, "raw_score_total": 400.0}
    assert round(301.0 / 400 * 100) == round(300.0 / 400 * 100) == 75  # the premise

    alerts, _notes = _arm(prev_extra, curr_extra)
    assert len(alerts) == 1, alerts


def test_a_real_fall_in_the_rounded_figure_still_alerts_the_old_way():
    """Positive control on the OLD path: the refinement is additive, and a rounded fall
    that already crosses an integer must keep firing with no earned/total present at all."""
    alerts, _notes = _arm({"raw_score": 75}, {"raw_score": 60})
    assert len(alerts) == 1, alerts


def test_a_rise_in_earned_is_not_an_alert():
    """The refinement is one-sided, same as the rounded comparison it extends: RAW_HELD
    is not "unchanged", but a RISE must never read as a fall either way."""
    prev_extra = {"raw_score": 75, "raw_score_earned": 300.0, "raw_score_total": 400.0}
    curr_extra = {"raw_score": 75, "raw_score_earned": 301.0, "raw_score_total": 400.0}
    alerts, notes = _arm(prev_extra, curr_extra)
    assert alerts == [] and notes == [], (alerts, notes)


def test_an_unchanged_earned_is_not_an_alert():
    prev_extra = {"raw_score": 75, "raw_score_earned": 300.0, "raw_score_total": 400.0}
    curr_extra = {"raw_score": 75, "raw_score_earned": 300.0, "raw_score_total": 400.0}
    alerts, notes = _arm(prev_extra, curr_extra)
    assert alerts == [] and notes == [], (alerts, notes)


def test_a_total_mismatch_skips_the_refinement_rather_than_comparing_across_it():
    """The redundant `p_total == c_total` witness: even with the weight-aware scope hash
    already guaranteeing this in practice, a record whose stored `total` genuinely
    disagrees must not be compared as a ratio — same self-healing skip as everything else
    here, not a crash and not a fabricated verdict."""
    prev_extra = {"raw_score": 75, "raw_score_earned": 300.0, "raw_score_total": 400.0}
    curr_extra = {"raw_score": 75, "raw_score_earned": 100.0, "raw_score_total": 133.0}
    alerts, notes = _arm(prev_extra, curr_extra)
    assert alerts == [] and notes == [], (alerts, notes)


def test_a_zero_total_never_divides():
    prev_extra = {"raw_score": 0, "raw_score_earned": 0.0, "raw_score_total": 0.0}
    curr_extra = {"raw_score": 0, "raw_score_earned": 0.0, "raw_score_total": 0.0}
    alerts, notes = _arm(prev_extra, curr_extra)
    assert alerts == [] and notes == [], (alerts, notes)


# ----------------------------------------------------- the adversarial-pass regression

def test_offsetting_severity_retune_moves_the_scope_hash_not_a_false_degraded():
    """The exact repro an independent C-135 pass found against this task's first attempt.

    B9 MEDIUM(3)->LOW(1), status PASS in both runs. B12 LOW(1)->MEDIUM(3), status FAIL in
    both runs. `total` is pinned at 3+1 == 1+3 == 4 in both runs, and `earned` genuinely
    falls (3 -> 1) with ZERO status transition on either check — a retune, not a
    regression. An id-only scope hash cannot see it (the id SET is identical); the
    id:weight hash must.
    """
    prev = [_f("B9", "MEDIUM", "PASS"), _f("B12", "LOW", "FAIL")]
    curr = [_f("B9", "LOW", "PASS"), _f("B12", "MEDIUM", "FAIL")]

    prev_ids = sorted(f.id for f in prev)
    curr_ids = sorted(f.id for f in curr)
    assert prev_ids == curr_ids, "the premise: identical id set"

    prev_total = sum(WEIGHT[f.severity] for f in prev)
    curr_total = sum(WEIGHT[f.severity] for f in curr)
    assert prev_total == curr_total == 4, "the premise: identical total"

    prev_earned = sum(WEIGHT[f.severity] for f in prev if f.status == "PASS")
    curr_earned = sum(WEIGHT[f.severity] for f in curr if f.status == "PASS")
    assert prev_earned == 3 and curr_earned == 1, "the premise: earned genuinely fell"

    prev_scope = _raw_score_scope(prev)
    curr_scope = _raw_score_scope(curr)
    assert prev_scope != curr_scope, (
        "the fix: an id:weight hash must move on a lone severity retune even though "
        "the id set and the total are both unchanged")

    verdict, _p, _c = raw_backstop(
        {"raw_score_scope": prev_scope, "raw_score": 75,
         "raw_score_earned": prev_earned, "raw_score_total": prev_total},
        {"raw_score_scope": curr_scope, "raw_score": 25,
         "raw_score_earned": curr_earned, "raw_score_total": curr_total},
        "raw_score_scope", "raw_score", "raw_score_earned", "raw_score_total",
    )
    assert verdict == RAW_SCOPE_MOVED, verdict

    # And through the full monitor arm, not just the leaf predicate: no HIGH alert, only
    # the "cannot compare" note.
    alerts, notes = _arm(
        {"raw_score": 75, "raw_score_earned": prev_earned, "raw_score_total": prev_total,
         "raw_score_scope": prev_scope},
        {"raw_score": 25, "raw_score_earned": curr_earned, "raw_score_total": curr_total,
         "raw_score_scope": curr_scope},
    )
    assert alerts == [], alerts
    assert notes, "a scope-moved run must still say it could not compare"


def test_a_real_regression_coinciding_with_an_unrelated_retune_reads_scope_moved():
    """C-135 (independent, post-commit): a documented, ACCEPTED consequence of the fix
    above, not a new defect — pinned so it is never mistaken for one.

    Check A goes MEDIUM(3)->LOW(1), status PASS in both runs (an unrelated, legitimate
    retune). Check B genuinely regresses PASS->FAIL, weight fixed at LOW(1) (a real
    posture fall). `total` moves 4->2 and the ROUNDED raw_score genuinely falls
    100->50 -- a real regression by any measure. But because A's weight changed, the
    id:weight scope hash differs, and `raw_backstop` returns RAW_SCOPE_MOVED before it
    ever compares `score_key` -- the real fall goes unreported this run, not merely
    reported at reduced confidence.

    This is not new: RAW_SCOPE_MOVED already meant 'the denominator moved for reasons
    unrelated to any single check's status, so the comparison cannot be trusted' for
    every check-SET change before C-469 (see the RAW_* docstring in
    monitordims/_shared.py). C-469 widened what counts as 'the denominator moved' to
    include a per-check WEIGHT change too -- trading a known false-DEGRADED bug for a
    known blind spot in this compound case, the same fail-toward-silence direction the
    function already took. Comparing `score_key` anyway would reopen the exact
    false-DEGRADED bug C-469 fixed, since a raw_score fall that partly traces to a
    legitimate retune cannot be told apart from one that doesn't without re-deriving
    which portion of the delta each cause explains."""
    prev = [_f("A", "MEDIUM", "PASS"), _f("B", "LOW", "PASS")]
    curr = [_f("A", "LOW", "PASS"), _f("B", "LOW", "FAIL")]

    prev_total = sum(WEIGHT[f.severity] for f in prev)
    curr_total = sum(WEIGHT[f.severity] for f in curr)
    assert (prev_total, curr_total) == (4, 2), "the premise: total itself moves"

    prev_earned = sum(WEIGHT[f.severity] for f in prev if f.status == "PASS")
    curr_earned = sum(WEIGHT[f.severity] for f in curr if f.status == "PASS")
    prev_raw = round(100 * prev_earned / prev_total)
    curr_raw = round(100 * curr_earned / curr_total)
    assert (prev_raw, curr_raw) == (100, 50), "the premise: raw_score genuinely falls"

    prev_scope = _raw_score_scope(prev)
    curr_scope = _raw_score_scope(curr)
    assert prev_scope != curr_scope, "the premise: the id:weight hash moves"

    verdict, _p, _c = raw_backstop(
        {"raw_score_scope": prev_scope, "raw_score": prev_raw,
         "raw_score_earned": prev_earned, "raw_score_total": prev_total},
        {"raw_score_scope": curr_scope, "raw_score": curr_raw,
         "raw_score_earned": curr_earned, "raw_score_total": curr_total},
        "raw_score_scope", "raw_score", "raw_score_earned", "raw_score_total",
    )
    assert verdict == RAW_SCOPE_MOVED, (
        "documented, accepted trade-off: a real regression coinciding with an "
        f"unrelated weight retune reads as 'cannot compare', not DEGRADED — got {verdict}")


def test_an_unchanged_severity_set_still_catches_a_real_regression():
    """The mirror of the case above, and the reason the fix must not simply widen the
    scope hash into silence: identical severities, a genuine WARN -> FAIL, must still be
    caught through the real `_raw_score_scope` (not a hand-built scope string)."""
    prev = [_f("B9", "MEDIUM", "PASS"), _f("B12", "LOW", "WARN")]
    curr = [_f("B9", "MEDIUM", "PASS"), _f("B12", "LOW", "FAIL")]

    prev_scope = _raw_score_scope(prev)
    curr_scope = _raw_score_scope(curr)
    assert prev_scope == curr_scope, "no severity moved, so the scope must hold"

    prev_total = sum(WEIGHT[f.severity] for f in prev)
    curr_total = sum(WEIGHT[f.severity] for f in curr)
    prev_earned = 3 + 0.5   # B9 PASS full weight, B12 WARN half weight
    curr_earned = 3 + 0.0   # B12 now FAIL

    verdict, _p, _c = raw_backstop(
        {"raw_score_scope": prev_scope, "raw_score": round(prev_earned / prev_total * 100),
         "raw_score_earned": prev_earned, "raw_score_total": prev_total},
        {"raw_score_scope": curr_scope, "raw_score": round(curr_earned / curr_total * 100),
         "raw_score_earned": curr_earned, "raw_score_total": curr_total},
        "raw_score_scope", "raw_score", "raw_score_earned", "raw_score_total",
    )
    assert verdict == RAW_DEGRADED, verdict


# ------------------------------------------------------------- scope volatility stands down

def test_an_unknown_appearing_stands_down_regardless_of_earned():
    """Test-plan item 3. `_raw_score_scope` excludes UNKNOWN findings from the denominator
    (same as `scoring.compute()`), so a check going UNKNOWN moves the scope and the
    comparison must stand down — never compare `earned` across a denominator that shrank
    for coverage reasons."""
    prev = [_f("B9", "MEDIUM", "PASS"), _f("B12", "LOW", "PASS")]
    curr = [_f("B9", "MEDIUM", "PASS"), _f("B12", "LOW", "UNKNOWN")]

    prev_scope = _raw_score_scope(prev)
    curr_scope = _raw_score_scope(curr)
    assert prev_scope != curr_scope

    verdict, _p, _c = raw_backstop(
        {"raw_score_scope": prev_scope, "raw_score": 100,
         "raw_score_earned": 4.0, "raw_score_total": 4.0},
        {"raw_score_scope": curr_scope, "raw_score": 100,
         "raw_score_earned": 3.0, "raw_score_total": 3.0},
        "raw_score_scope", "raw_score", "raw_score_earned", "raw_score_total",
    )
    assert verdict == RAW_SCOPE_MOVED, verdict


# --------------------------------------------------------------------- one predicate

def test_monitor_and_history_share_one_predicate():
    """DoD: 'One predicate still serves both stores, guarded.' Both modules import the
    SAME function object from the one leaf — never a second implementation that could
    drift from it the way B-689/B-692/B-693 each did before B-691 unified them."""
    import clawseccheck.history as history_mod
    import clawseccheck.monitor as monitor_mod
    import clawseccheck.monitordims._score as score_mod
    from clawseccheck.monitordims._shared import raw_backstop as shared_raw_backstop

    assert history_mod.raw_backstop is shared_raw_backstop
    assert monitor_mod.raw_backstop is shared_raw_backstop
    assert score_mod.raw_backstop is shared_raw_backstop


# ------------------------------------------------------------- end-to-end through history

def test_end_to_end_through_real_scoring_and_the_history_store(tmp_path):
    """Not just the leaf predicate: a real `scoring.compute()` ScoreResult, recorded
    through `history.record()`, loaded back, and rendered by `render_trend()` — the
    sub-rounding fall reaches the screen through the real store, not only a hand-built
    dict."""
    # 199 low-weight PASS findings pad the denominator to 200, so one LOW WARN->FAIL
    # (0.5 of one weight unit) cannot move the rounded percentage: round(199.5/200*100)
    # == round(199/200*100) == 100 (verified directly, not assumed, in the assertion
    # right below).
    padding = [_f(f"PAD{i}", "LOW", "PASS") for i in range(199)]
    prev_findings = [*padding, _f("B12", "LOW", "WARN")]      # total 200
    curr_findings = [*padding, _f("B12", "LOW", "FAIL")]      # total 200

    prev_score = compute(prev_findings)
    curr_score = compute(curr_findings)
    assert prev_score.total == curr_score.total == 200
    assert prev_score.raw_score == curr_score.raw_score, (
        "the premise: the rounded figure must not move")
    assert prev_score.earned > curr_score.earned, (
        "the premise: the exact figure must move")

    path = str(tmp_path / "history.jsonl")
    record(prev_score, path=path, when="2026-09-01T09:00:00", source="audit",
          findings=prev_findings, version="4.1.0", home="~/.openclaw")
    record(curr_score, path=path, when="2026-09-02T09:00:00", source="audit",
          findings=curr_findings, version="4.1.0", home="~/.openclaw")

    rows = load(path)
    assert rows[0]["raw_earned"] == prev_score.earned
    assert rows[0]["raw_total"] == prev_score.total
    assert rows[1]["raw_earned"] == curr_score.earned

    out = render_trend(rows, ascii_only=True)
    assert "pass-rate fell" in out, out
