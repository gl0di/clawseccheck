"""CLAWSECCHECK-B-547 — `ScoreResult.ledger_present`: making ledger completeness
representable at the scoring boundary.

The defect (see `scoring.ScoreResult.ledger_present`'s own docstring for the full
account): C-422 deliberately made a COMPLETE `layers.LayerLedger` (every layer
`"ran"`) produce a `ScoreResult` bit-for-bit equal to `ledger=None` ("no ledger was
ever tracked"). That collapse meant no consumer holding only a `ScoreResult` could
tell "this run's own ledger proves every layer ran" from "this run never tracked a
ledger at all" — `report._scope_note_lines`'s `have_ledger` proxy read both as
False, which is how a Grade-A `--full` run with a fully complete ledger got told to
go run the modes it had just finished.

Three real states, and this module pins each as a DISTINCT, non-vacuous fact:

    absent    ledger=None                 -> ledger_present=False, graded=True
    complete  every layer STATUS_RAN      -> ledger_present=True,  graded=True
    partial   >=1 layer status != RAN     -> ledger_present=True,  graded=False

"Partial" must not collapse into either neighbour: it shares `ledger_present=True`
with "complete" (both are evidence) and shares nothing with "absent" — and it must
NOT share `graded` with "complete" (that boundary is `graded`'s job, already pinned
by `tests/test_c422_ledger_scoring.py`; this module does not re-pin it, only checks
`ledger_present` stays True there too, since a partial ledger is still evidence).

Every positive assertion here carries a non-vacuity control (an assertion that the
SAME predicate reads False/differently on a deliberately different input) so this
suite cannot pass by asserting something true of any object, or of an
under-constructed `LayerLedger`.

Stdlib-only, offline, no network, nothing written outside pytest's own machinery.
"""
from __future__ import annotations

from clawseccheck.catalog import HIGH, PASS, Finding
from clawseccheck.layers import (
    LAYER_ORDER,
    LAYER_SELF_REPORT,
    STATUS_RAN,
    STATUS_REFUSED,
    LayerLedger,
    LayerState,
)
from clawseccheck.scoring import ScoreResult, compute


def _f() -> Finding:
    return Finding("X", "t", HIGH, PASS, "d", "fix", "fw")


def _complete_ledger() -> LayerLedger:
    return LayerLedger(states={layer: LayerState(status=STATUS_RAN) for layer in LAYER_ORDER})


def _partial_ledger() -> LayerLedger:
    states = {layer: LayerState(status=STATUS_RAN) for layer in LAYER_ORDER}
    states[LAYER_SELF_REPORT] = LayerState(status=STATUS_REFUSED)
    return LayerLedger(states=states)


# ── 1. the three states, each a distinct (ledger_present, graded) pair ──────────

def test_absent_state_is_ledger_present_false_and_graded_true():
    r = compute([_f()])
    assert r.ledger_present is False
    assert r.graded is True
    # non-vacuity: the complete state below flips ledger_present, proving this read
    # is not a hardcoded True/False that ignores the input.
    assert compute([_f()], ledger=_complete_ledger()).ledger_present is not r.ledger_present


def test_complete_state_is_ledger_present_true_and_graded_true():
    r = compute([_f()], ledger=_complete_ledger())
    assert r.ledger_present is True
    assert r.graded is True
    # non-vacuity: the absent state above reads False for the identical findings.
    assert compute([_f()]).ledger_present is not r.ledger_present


def test_partial_state_is_ledger_present_true_and_graded_false():
    r = compute([_f()], ledger=_partial_ledger())
    assert r.ledger_present is True
    assert r.graded is False
    # non-vacuity: the complete state shares ledger_present=True but NOT graded —
    # proves `graded` is doing real work here, not mirroring ledger_present.
    complete = compute([_f()], ledger=_complete_ledger())
    assert complete.ledger_present == r.ledger_present
    assert complete.graded is not r.graded


# ── 2. partial does not collapse into either neighbour ──────────────────────────

def test_partial_is_not_absent():
    """Partial must not be mistaken for "no evidence" — it is evidence of a gap."""
    absent = compute([_f()])
    partial = compute([_f()], ledger=_partial_ledger())
    assert partial.ledger_present != absent.ledger_present  # True vs False
    assert partial != absent


def test_partial_is_not_complete():
    """Partial must not be mistaken for "fully covered" — `graded` is the
    discriminator C-422 already owns; this pins that B-547's new field does not
    quietly erase it (a bug where `ledger_present` alone gated a "confirmed complete"
    render would misfire here)."""
    complete = compute([_f()], ledger=_complete_ledger())
    partial = compute([_f()], ledger=_partial_ledger())
    assert complete != partial
    assert complete.graded != partial.graded
    assert complete.missing_layers != partial.missing_layers


# ── 3. all three, side by side, all mutually distinct ────────────────────────────

def test_all_three_states_are_pairwise_distinct():
    findings = [_f()]
    absent = compute(findings)
    complete = compute(findings, ledger=_complete_ledger())
    partial = compute(findings, ledger=_partial_ledger())
    results = {"absent": absent, "complete": complete, "partial": partial}
    for name_a, a in results.items():
        for name_b, b in results.items():
            if name_a == name_b:
                continue
            assert a != b, f"{name_a} must be distinguishable from {name_b}"
    # Non-vacuity: confirm the trio is not all-equal-by-construction by checking the
    # (ledger_present, graded) signature is unique per state.
    signatures = {name: (r.ledger_present, r.graded) for name, r in results.items()}
    assert signatures == {
        "absent": (False, True),
        "complete": (True, True),
        "partial": (True, False),
    }
    assert len(set(signatures.values())) == 3  # all three genuinely distinct pairs


# ── 4. default construction (positional/legacy callers) reads as "absent" ────────

def test_default_construction_is_the_absent_state_not_the_reassuring_one():
    """A caller (or an old test, or a stand-in object) that never heard of this field
    must land on "absent" (no evidence tracked), matching `ledger=None`'s own
    pre-existing default — never silently read as "complete", which would be the
    reassuring misreading this field exists to prevent."""
    r = ScoreResult(0, "N/A", False, 0, 0, 0, assessable=False)
    assert r.ledger_present is False
    # non-vacuity: an explicit complete ledger through the real producer reads True,
    # so False above is not just the field's only reachable value.
    assert compute([_f()], ledger=_complete_ledger()).ledger_present is True


# ── 5. ledger_present is orthogonal to graded — not derivable from it alone ──────

def test_ledger_present_is_not_a_restatement_of_graded():
    """If `ledger_present` were merely `graded` under another name, the absent and
    complete states (both graded=True) would be forced equal on this field too —
    which is precisely the B-547 defect. Assert the two GRADED states disagree on
    `ledger_present` while agreeing on `graded`, proving the new field carries
    information `graded` alone does not."""
    absent = compute([_f()])
    complete = compute([_f()], ledger=_complete_ledger())
    assert absent.graded == complete.graded == True  # noqa: E712 — explicit for clarity
    assert absent.ledger_present != complete.ledger_present


# ── 6. total==0 early-return path carries ledger_present too (all three states) ──

def test_ledger_present_set_on_the_assessable_false_path_too():
    absent = compute([])
    complete = compute([], ledger=_complete_ledger())
    partial = compute([], ledger=_partial_ledger())
    assert absent.assessable is False and absent.ledger_present is False
    assert complete.assessable is False and complete.ledger_present is True
    assert partial.assessable is False and partial.ledger_present is True
    assert partial.graded is False
