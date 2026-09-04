"""B-719: a skill sweep the BUDGET killed was reported as one the operator skipped.

Three phases in `run_pipeline` are gated on the same wall-clock budget — P6 (installed
skills), P7 (installed plugins), P8 (behavioural replay). Two of them disclose that
cause; the third did not.

P7 and P8 each carry an `elif budget_exceeded(deadline): _not_reached(...)` branch. P6
had no such branch, so a run whose budget was already spent fell through to
`record_skill_sweep(None)`, which returns `_skipped(PHASE_SKILL_SWEEP, "not run.")`.
Measured on a blown budget before the fix::

    skill_sweep     status=skipped      detail="not run."
    plugin_sweep    status=not_reached  detail="not run — the 30s pipeline budget ..."
    behavioral      status=not_reached  detail="not run — the 30s pipeline budget ..."

One cause, three phases, and only one of them tells the truth about it.

**What this is and is not.** `STATUS_SKIPPED` means, in layers.py's own words, "the
operator narrowed the run (e.g. --fast)" and renders as "skipped by this run's flags".
So the ledger told a user who asked for a full sweep that they had asked for less. It is
a DISCLOSURE defect, not a scoring one: `LayerLedger.complete` requires every layer to be
`ran`, and both `skipped` and `not_reached` fail that equally, so no grade moved. Stated
plainly rather than inflated.

**The task's premise was wider than the defect.** B-719 described a budget-truncated
sweep as reporting `not_reached=()`, "bit-for-bit identical to a fully-completed sweep".
Measured, that is not so: a sweep truncated MID-fleet already names every target it never
reached, because `sweep_installed_skills` appends a `SKIPPED` row for each remaining
target before breaking, and `not_scanned()` returns exactly those rows. That path was
working; the tests below keep it that way. What was broken is the sweep that never
started at all.

Offline, writes nothing outside tmp_path, stdlib only, no sleeping — the deadline is
injected.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from clawseccheck import pipeline as P
from clawseccheck.collector import Context
from clawseccheck.layers import LAYER_INSTALLED_SWEEP

BLOWN = -1.0      # seconds relative to now; negative == the budget is already spent
LIVE = 3600.0


def _ctx() -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    return c


def _run(*, skill_sweep=None, offset_s: float = BLOWN, fast: bool = False):
    return P.run_pipeline(
        _ctx(), [], home_dir="/nonexistent", skill_sweep=skill_sweep,
        deadline=time.monotonic() + offset_s, budget_s=30.0, fast=fast,
    )


def _phase(result, name):
    ph = result.by_name(name)
    assert ph is not None, f"phase {name} missing entirely from {result.phases!r}"
    return ph


class _Sweep:
    """Duck-typed to record_skill_sweep's published surface (it never imports the real
    SkillSweep — that would be a Layer 3 -> Layer 4 import cycle, see its docstring)."""

    def __init__(self, total: int, skipped: int):
        self.no_roots = False
        self.no_targets = False
        self.has_fail = False
        self._total, self._skipped = total, skipped
        self.complete = skipped == 0

    def counts(self):
        return {"total": self._total, "fails": 0, "warns": 0,
                "safe": self._total - self._skipped, "truncated": 0,
                "skipped": self._skipped}

    def not_scanned(self):
        return [f"skill{i}" for i in range(self._skipped)]


# ---------------------------------------------------------------------------
# The defect
# ---------------------------------------------------------------------------

def test_a_budget_killed_sweep_is_not_blamed_on_the_operators_flags():
    ph = _phase(_run(), P.PHASE_SKILL_SWEEP)
    assert ph.status == P.STATUS_NOT_REACHED, (
        "a skill sweep the pipeline budget killed reported "
        f"{ph.status!r} — which layers.py renders as 'skipped by this run's flags', "
        "telling a user who asked for a full sweep that they asked for less"
    )
    assert "budget" in ph.detail.lower(), (
        f"the phase does not say what stopped it: {ph.detail!r}"
    )


def test_the_three_budget_gated_phases_give_the_same_answer():
    """P6/P7/P8 share one cause here, so they must share one verdict. This is the
    invariant the fix restores; asserting the three together is what makes a future
    divergence in ANY of them fail, not only in the one repaired today."""
    result = _run()
    statuses = {
        name: _phase(result, name).status
        for name in (P.PHASE_SKILL_SWEEP, P.PHASE_PLUGIN_SWEEP, P.PHASE_BEHAVIORAL)
    }
    assert set(statuses.values()) == {P.STATUS_NOT_REACHED}, (
        "phases gated on the same budget disagree about why they did not run: "
        f"{statuses}"
    )


def test_the_layer_status_masks_this_defect_and_cannot_be_the_guard():
    """Documents WHY the assertions above are at phase level, not layer level.

    This test passed before the fix as well as after it, which is the point. The
    installed-sweep layer folds P6 and P7 through `_worse_status`, and P7 was already
    reporting `not_reached` correctly — so the layer came out `not_reached` no matter
    what P6 said. A layer-level assertion here looks like a guard and is not one: it
    would have gone green over the bug for as long as the two phases share a deadline,
    which they always do.

    The user-visible harm was always per-phase — each phase renders its own status and
    detail — so that is where this is pinned. Written down rather than deleted, so the
    next person does not "strengthen" the suite by adding the layer assertion back and
    believe they have covered it."""
    masked = P.PipelineResult(phases=[
        P.PhaseResult(name=P.PHASE_SKILL_SWEEP, status=P.STATUS_SKIPPED,
                      complete=False, detail="not run."),          # the bug
        P.PhaseResult(name=P.PHASE_PLUGIN_SWEEP, status=P.STATUS_NOT_REACHED,
                      complete=False, detail="budget spent"),
    ])
    state = masked.to_ledger(findings=[], degraded_count=0).states[LAYER_INSTALLED_SWEEP]
    assert state.status == P.STATUS_NOT_REACHED, (
        "if this ever fails, _worse_status changed and a layer-level assertion may now "
        "be able to see a divergence between P6 and P7 — revisit the note above"
    )

    # And the fixed pipeline agrees at the layer too, for whatever that is worth here.
    live = _run().to_ledger(findings=[], degraded_count=0).states[LAYER_INSTALLED_SWEEP]
    assert live.status == P.STATUS_NOT_REACHED


# ---------------------------------------------------------------------------
# The properties the fix must NOT break
# ---------------------------------------------------------------------------

def test_a_sweep_that_really_ran_survives_a_budget_blown_afterwards():
    """The load-bearing safety property.

    P6 differs from P7/P8: its sweep is executed by the CALLER and handed in, so by the
    time the pipeline looks at the budget the work may already be done. Gating on the
    clock alone — the way P7 and P8 do — would throw away a completed sweep's real
    result and replace it with "not reached", inventing a coverage hole out of a run
    that actually happened."""
    ph = _phase(_run(skill_sweep=_Sweep(10, 0)), P.PHASE_SKILL_SWEEP)
    assert ph.status == P.STATUS_RAN, (
        "a completed sweep was discarded because the budget expired after it finished"
    )
    assert ph.complete is True
    assert list(ph.not_scanned) == []


def test_fast_still_names_the_flags_because_that_is_true_there():
    """Negative control. Under --fast the operator DID narrow the run, so
    'skipped by this run's flags' is the correct claim and must not be replaced."""
    ph = _phase(_run(offset_s=LIVE, fast=True), P.PHASE_SKILL_SWEEP)
    assert ph.status == P.STATUS_SKIPPED
    assert "--fast" in ph.detail


def test_a_missing_sweep_on_a_live_budget_still_reads_as_skipped():
    """Second negative control: the fix must key on the BUDGET, not merely on the sweep
    being absent. A caller that passed nothing while time remained did not run out of
    budget, and must not be described as though it had."""
    ph = _phase(_run(offset_s=LIVE), P.PHASE_SKILL_SWEEP)
    assert ph.status == P.STATUS_SKIPPED
    assert "budget" not in ph.detail.lower()


# ---------------------------------------------------------------------------
# The mid-sweep truncation path the task believed was broken — it is not.
# These pin it so a fix aimed at the never-started case cannot damage it.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("skipped,expected", [(0, 0), (4, 4)])
def test_a_truncated_sweep_names_every_target_it_missed(skipped, expected):
    result = _run(skill_sweep=_Sweep(10, skipped), offset_s=LIVE)
    state = result.to_ledger(findings=[], degraded_count=0).states[LAYER_INSTALLED_SWEEP]
    assert len(state.not_reached) == expected
    assert _phase(result, P.PHASE_SKILL_SWEEP).status == P.STATUS_RAN


def test_a_complete_and_a_truncated_sweep_are_distinguishable():
    """The comparison B-719 asked for, on the path where it applies."""
    def layer(sweep):
        return _run(skill_sweep=sweep, offset_s=LIVE).to_ledger(
            findings=[], degraded_count=0).states[LAYER_INSTALLED_SWEEP]

    whole, part = layer(_Sweep(10, 0)), layer(_Sweep(10, 4))
    assert whole.not_reached == ()
    assert part.not_reached != ()
    assert (whole.status, whole.not_reached) != (part.status, part.not_reached)
