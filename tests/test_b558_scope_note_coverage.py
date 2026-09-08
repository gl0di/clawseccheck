"""CLAWSECCHECK-B-558 step 4 — the scope note READS `LayerState.coverage`.

Steps 1-3 built the signal (`layers.LayerState.coverage`, `pipeline.to_ledger`'s rule,
`scoring.ScoreResult.layer_coverage`). This module pins the consumer: what the reader
actually sees for each of the three coverage states, and what happens in the two shapes
that must not produce a claim at all.

Why this matters, from the task's own owner decision (Dave, 2026-09-03): the advice
should be DERIVED from what the run did, not from a hand-maintained list of strings. On
a real `--full` run the line "Run `--behavioral` ..." printed 624 lines above the
BEHAVIOURAL REPLAY section it was describing. The COMPLETE branch is what stops that —
and the PARTIAL branch is what keeps it from over-correcting into silence.

The tests build ledgers directly rather than running a pipeline: this module is about
the RENDERER's branch, and `tests/test_b558_ledger_coverage_single_producer.py` already
drives the same states through the real `to_ledger` -> `compute` -> render chain with a
real `behavioral.analyze()` result. Both are needed — that one proves the states are
reachable, this one proves each renders correctly and distinctly.

Offline, stdlib only, writes nothing.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from clawseccheck import report  # noqa: E402
from clawseccheck.catalog import HIGH, PASS, Finding  # noqa: E402
from clawseccheck.layers import (  # noqa: E402
    COVERAGE_COMPLETE,
    COVERAGE_PARTIAL,
    COVERAGE_UNKNOWN,
    LAYER_INSTALLED_SWEEP,
    LAYER_LOGS_TRAJECTORIES,
    LAYER_ORDER,
    STATUS_RAN,
    LayerLedger,
    LayerState,
)
from clawseccheck.scoring import compute  # noqa: E402

LOGS_SUBJECT = next(c.subject for c in report._SCOPE_CLAUSES
                    if c.layer == LAYER_LOGS_TRAJECTORIES)
SWEEP_SUBJECT = next(c.subject for c in report._SCOPE_CLAUSES
                     if c.layer == LAYER_INSTALLED_SWEEP)


def _findings() -> list:
    return [Finding("X1", "t", HIGH, PASS, "d", "fix", "fw", True)]


def _ledger(coverage_by_layer: dict) -> LayerLedger:
    """Every layer RAN — so nothing lands on the `missing` branch — with the coverage
    each named layer is given and UNKNOWN (the field's own default) for the rest."""
    return LayerLedger(states={
        layer: LayerState(status=STATUS_RAN,
                          coverage=coverage_by_layer.get(layer, COVERAGE_UNKNOWN))
        for layer in LAYER_ORDER
    })


def _clause(coverage_by_layer: dict, subject: str = LOGS_SUBJECT) -> str:
    score = compute(_findings(), ledger=_ledger(coverage_by_layer))
    lines, _live = report._scope_note_lines(score, _findings())
    matches = [ln for ln in lines if subject in ln]
    assert len(matches) == 1, matches
    return matches[0]


# ── the three states, each rendering distinctly ───────────────────────────────

def test_unknown_coverage_renders_todays_wording_byte_for_byte():
    """The default state, and the overwhelmingly common one: four of five layers are
    pinned UNKNOWN by `to_ledger`. Its text may not move — a coverage field nobody has
    answered must read exactly as it did before the field existed."""
    clause = _clause({LAYER_LOGS_TRAJECTORIES: COVERAGE_UNKNOWN})
    assert " · ran, coverage not accounted for — " in clause, clause
    assert "this audit's own log/transcript scan ran" in clause, clause
    assert "Run `--behavioral`" in clause, clause


def test_complete_coverage_stops_advising_the_mode_the_run_already_ran():
    """The point of the whole change. `COVERAGE_COMPLETE` on this layer means the
    replay phase ran and left nothing unread, so `Run --behavioral` is an instruction
    to redo what the same report prints further down."""
    clause = _clause({LAYER_LOGS_TRAJECTORIES: COVERAGE_COMPLETE})
    assert " · ran and covered — " in clause, clause
    assert "Run `--behavioral`" not in clause, clause


def test_complete_coverage_keeps_the_advice_the_signal_does_not_cover():
    """Over-suppression is the failure mode this file has already retracted once (for
    the sweep layer, B-547). `behavioral_ran` speaks for `--behavioral` only:
    `--analyze-trajectory` is a separate CLI branch `--full` never invokes, so no
    coverage signal in this ledger vouches for it and its recommendation must survive.

    A withheld recommendation is invisible to both release FP gates (`fleet_fp_gate`
    compares FAIL sets; `monitor_fp_gate` diffs two snapshots of an unchanged home), so
    this assertion is the only thing standing between that half and a silent loss."""
    clause = _clause({LAYER_LOGS_TRAJECTORIES: COVERAGE_COMPLETE})
    assert "`--analyze-trajectory`" in clause, clause


def test_partial_coverage_attributes_the_hole_and_keeps_the_full_advice():
    """PARTIAL must not collapse into UNKNOWN. `ScoreResult.not_checked` prints the
    hole's own words elsewhere, but as a flat union across all five layers — this
    clause is the only place a reader learns WHICH layer it belongs to. And unlike the
    COMPLETE branch, re-running the mode is exactly what a partly-covered layer needs,
    so the advice stays whole."""
    clause = _clause({LAYER_LOGS_TRAJECTORIES: COVERAGE_PARTIAL})
    assert " · ran, partly covered — " in clause, clause
    assert "Run `--behavioral`" in clause, clause


def test_the_three_states_render_three_different_lines():
    """Non-vacuity for all of the above: a renderer that ignored `coverage` entirely
    would satisfy several assertions above individually (they share substrings) but
    cannot satisfy this one."""
    seen = {
        cov: _clause({LAYER_LOGS_TRAJECTORIES: cov})
        for cov in (COVERAGE_UNKNOWN, COVERAGE_COMPLETE, COVERAGE_PARTIAL)
    }
    assert len(set(seen.values())) == 3, seen


# ── the two shapes that must produce no claim ──────────────────────────────────

def test_a_complete_layer_with_no_wording_under_claims_instead_of_inventing_one():
    """`_SCOPE_CLAUSES` carries a `covered_note` for exactly one layer, because exactly
    one layer can be proven complete today. Should a future producer start answering
    COMPLETE for another (B-723 would do this for the sweep), the renderer must fall
    back to the UNKNOWN wording — under-claiming, the safe direction — rather than
    raising inside a user's report or fabricating a sentence nobody wrote.

    This is a tripwire, not a permanent contract: when that producer lands, the fix is
    to write the sweep's `covered_note`, and this test is where the omission surfaces.
    """
    assert next(c.covered_note for c in report._SCOPE_CLAUSES
                if c.layer == LAYER_INSTALLED_SWEEP) is None, "premise no longer holds"
    clause = _clause({LAYER_INSTALLED_SWEEP: COVERAGE_COMPLETE}, subject=SWEEP_SUBJECT)
    assert " · ran, coverage not accounted for — " in clause, clause
    assert "covered" not in clause.split("—")[0], clause


def test_a_score_from_before_the_field_existed_renders_as_unknown():
    """~17 positional `ScoreResult(...)` sites and any pickled/hand-built one predate
    `layer_coverage`. The renderer reads it through `getattr` with an empty default for
    that reason; this pins that such a score renders identically to an explicit
    UNKNOWN, so the new branch cannot change a caller that never opted in."""
    import dataclasses

    score = compute(_findings(), ledger=_ledger({LAYER_LOGS_TRAJECTORIES: COVERAGE_COMPLETE}))
    stripped = dataclasses.replace(score, layer_coverage=())
    lines, _live = report._scope_note_lines(stripped, _findings())
    clause = next(ln for ln in lines if LOGS_SUBJECT in ln)
    assert clause == _clause({LAYER_LOGS_TRAJECTORIES: COVERAGE_UNKNOWN}), clause
