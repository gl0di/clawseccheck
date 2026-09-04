"""B-723 — the layer ledger is projected from phases that RAN, never from a promise.

`_build_layer_ledger` used to record `PHASE_SKILL_SWEEP` and `PHASE_PLUGIN_SWEEP` as
`STATUS_RAN` before either had run, on the strength of the caller intending to run them
later in the same invocation. Its own detail string said "scheduled this invocation" —
an intention written down as an outcome.

That is not a disclosure defect. `LayerLedger.complete` requires `STATUS_RAN` on all five
layers and is the gate deciding whether a letter grade is issued at all, so the fabricated
status OPENED the grade for a run whose sweep might never have finished. Fail-open: a
clean verdict over ground nobody had looked at yet.

The fix has two halves, and BOTH are load-bearing — either alone is worse than the bug:

* the promise is gone (`cli._build_layer_ledger` adds no sweep phases), so nothing
  claims `ran` before the work happens; and
* every `--full` surface RE-PROJECTS the ledger from the real phases once they have run,
  so a run that genuinely did the work still earns its letter.

Without the second half the tool could never grade again, which is why the "still grades
when the sweeps complete" cases below are not niceties — they are the control that stops a
fail-open being traded for a dead feature.

Wiring, not helper. Every case drives the real CLI and forces a REAL degraded sweep by
shrinking the pipeline budget the call site itself reads; none monkeypatches a ledger, a
status, or `to_ledger`. Offline, writes nothing outside `tmp_path`, no sleeping — an
already-spent deadline is deterministic without one.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawseccheck import cli
from clawseccheck.layers import (
    LAYER_INSTALLED_SWEEP,
    STATUS_NOT_REACHED,
    STATUS_RAN,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE_HOME = FIXTURES / "home_safe"

#: Positive, so `start_deadline` returns a real deadline rather than disabling the cap
#: (`audit_deadline` treats 0 as "no limit"), and small enough that it is already spent by
#: the time any phase consults it. Deterministic without sleeping.
SPENT = 1e-9


def _json_run(tmp_path, monkeypatch, capsys, *, budget_s=None, extra=()):
    """`--json` writes the document to stdout; there is no file flag for it."""
    if budget_s is not None:
        monkeypatch.setattr(cli, "DEFAULT_FULL_BUDGET_S", budget_s)
    cli.main(["--home", str(SAFE_HOME), "--full", "--json", "--no-history", "--no-native",
              "--data-dir", str(tmp_path / "dd"), *extra])
    return json.loads(capsys.readouterr().out)


def _layer_status(payload, layer=LAYER_INSTALLED_SWEEP):
    """The status `--json` reports for one layer.

    The document lists only the layers that did NOT run (`missing_layers`), so a layer's
    absence from that list IS its `ran` status — read through this helper rather than
    asserted as an absence, because "not in the list" and "the list is missing" look the
    same at a call site and only one of them is a pass.
    """
    missing = payload.get("missing_layers")
    assert isinstance(missing, list), (
        f"--json carries no missing_layers array (got {missing!r}) — the ledger is not "
        "reaching the document at all, so nothing below would mean anything")
    for entry in missing:
        if entry.get("layer") == layer:
            return entry.get("status")
    return STATUS_RAN


# ── the defect ───────────────────────────────────────────────────────────────────────

def test_a_budget_killed_sweep_is_not_reported_as_a_layer_that_ran(tmp_path, monkeypatch,
                                                                   capsys):
    """THE fail-open. A `--full` run whose sweep never got a turn must not claim it did."""
    payload = _json_run(tmp_path, monkeypatch, capsys, budget_s=SPENT)
    assert _layer_status(payload) != STATUS_RAN, (
        "the installed-sweep layer reports 'ran' on a run whose budget was spent before "
        "the sweep started — this is the promise B-723 removed, reappearing")
    assert payload.get("grade") in (None, "", "no grade yet"), (
        f"a letter was issued over a sweep that never ran: {payload.get('grade')!r}")
    assert payload.get("graded") is not True


def test_the_prelim_ledger_never_claims_the_sweep_ran(tmp_path, monkeypatch):
    """The other half: even before any pipeline runs, the promise must not be recorded.

    Distinct from the case above — that one proves the FINAL ledger is honest, this one
    proves the INTERMEDIATE one is, which is what any future caller inherits.
    """
    from clawseccheck import audit
    from clawseccheck.cli import _build_layer_ledger

    class _Args:
        fast = False
        full = True

    _, findings, _ = audit(SAFE_HOME)
    ledger = _build_layer_ledger(_Args(), findings, commit_full_phases=True,
                                 behavioral_ran=True)
    assert ledger.status(LAYER_INSTALLED_SWEEP) != STATUS_RAN
    assert ledger.complete is False


# ── the control: the fix must not cost the grade ─────────────────────────────────────

def test_a_completed_sweep_still_reports_the_layer_as_run(tmp_path, monkeypatch, capsys):
    """MANDATORY control, and the reason the re-projection exists.

    Removing the promise alone would leave `installed_sweep` permanently un-run on every
    surface, so no run could ever be graded again — a fail-open traded for a dead product.
    This asserts the opposite direction: work actually done is still credited.
    """
    payload = _json_run(tmp_path, monkeypatch, capsys)
    assert _layer_status(payload) == STATUS_RAN, (
        "a --full run that completed both sweeps does not credit the installed-sweep "
        "layer — the ledger is no longer being re-projected from the real phases")


def test_the_two_directions_disagree(tmp_path, monkeypatch, capsys):
    """A negative needs a positive control, and both need to be the SAME assertion.

    Asserting only "degraded is not ran" passes trivially if the layer is never `ran`;
    asserting only "complete is ran" passes trivially if it is always `ran`. Running both
    through one comparison is what makes either mean anything.
    """
    degraded = _layer_status(_json_run(tmp_path / "a", monkeypatch, capsys, budget_s=SPENT))
    # `monkeypatch` unwinds at TEARDOWN, not between calls — without this the second run
    # inherits the spent budget and both sides report `not_reached`, which the assertion
    # below then reads as "the ledger ignores the phases". Caught by writing the test:
    # the harness has to be right before the thing it is checking can be.
    monkeypatch.undo()
    completed = _layer_status(_json_run(tmp_path / "b", monkeypatch, capsys))
    assert degraded != completed, (
        f"a budget-killed sweep and a completed one report the same layer status "
        f"({degraded!r}) — the ledger is not reading the phases at all")
    assert completed == STATUS_RAN


# ── the dashboard surface, which builds its phases inline ────────────────────────────

def _dashboard_run(tmp_path, monkeypatch, capsys, *, budget_s=None):
    if budget_s is not None:
        monkeypatch.setattr(cli, "DEFAULT_FULL_BUDGET_S", budget_s)
    cli.main(["--home", str(SAFE_HOME), "--dashboard", "--full", "--no-history",
              "--no-native", "--ascii", "--data-dir", str(tmp_path / "dd")])
    return capsys.readouterr().out


def test_the_dashboard_credits_a_sweep_it_actually_ran(tmp_path, monkeypatch, capsys):
    """`--dashboard --full` runs its phases INLINE, not through `run_pipeline`, so it
    needs its own projection — and it is the surface the product's headline mode uses."""
    out = _dashboard_run(tmp_path, monkeypatch, capsys)
    assert "installed skills and plugins (not reached)" not in out, (
        "the dashboard ran both sweeps and still reports the layer as not reached — its "
        "inline phases are not reaching the ledger")


def test_the_dashboard_does_not_credit_a_sweep_the_budget_killed(tmp_path, monkeypatch,
                                                                 capsys):
    out = _dashboard_run(tmp_path, monkeypatch, capsys, budget_s=SPENT)
    assert "installed skills and plugins (not reached)" in out, (
        "the dashboard's budget-killed sweep is not disclosed in the layer ledger")


@pytest.mark.parametrize("layer_line", [
    "agent self-report (not submitted)",
    "live behaviour test (not submitted)",
])
def test_the_other_missing_layers_are_unchanged(tmp_path, monkeypatch, capsys, layer_line):
    """Guard against over-reach: this change is about the installed sweep only. The two
    layers that need `--attest` / `--judged-bundle` must still read exactly as before."""
    assert layer_line in _dashboard_run(tmp_path, monkeypatch, capsys)


# ── the structural guard: the promise cannot come back ───────────────────────────────

def test_the_early_ledger_can_never_be_complete_whatever_it_is_given():
    """The invariant that makes the fabrication impossible to reintroduce by accident.

    Every test above is BEHAVIOURAL: it drives a surface and checks what came out. All of
    them would still pass if someone re-added a `STATUS_RAN` sweep phase to
    `_build_layer_ledger` AND left the re-projection in place — the re-projection would
    simply overwrite the fabrication on the three surfaces that have one, and a fourth
    surface added later would silently inherit the lie.

    So this asserts the property directly: a ledger built BEFORE any pipeline has run can
    never be `complete`, no matter how generous its other inputs are. `complete` is the
    gate that allows a letter, so this is the same statement as "the early ledger can
    never authorise a grade".

    Everything else here is maximally favourable on purpose — a real attestation, a valid
    live-test bucket, a behavioural replay that ran. Four of the five layers can therefore
    reach `ran`; the sweep is the one that cannot, because it has not happened.
    """
    from clawseccheck import audit
    from clawseccheck.cli import _build_layer_ledger

    class _Args:
        fast = False
        full = True

    _, findings, _ = audit(SAFE_HOME)
    ledger = _build_layer_ledger(
        _Args(), findings,
        attestation={"tools": ["read", "write"]},
        live_test_bucket={"verdicts": [
            {"tool": "canary", "id": "canary", "verdict": "RESISTANT"}]},
        behavioral_ran=True, behavioral_analysis={},
        commit_full_phases=True,
    )
    assert ledger.complete is False, (
        "the pre-pipeline ledger reports a COMPLETE check, so it would authorise a letter "
        "for work that has not happened — this is B-723 reintroduced")
    assert ledger.status(LAYER_INSTALLED_SWEEP) != STATUS_RAN

    # The positive control: with those same generous inputs, the ONLY thing missing is the
    # sweep. Without this the assertion above would also pass if some unrelated layer had
    # quietly regressed to un-run, and the test would be guarding the wrong thing.
    assert tuple(ledger.missing) == (LAYER_INSTALLED_SWEEP,), (
        f"more than the sweep is outstanding on a maximally-supplied early ledger "
        f"({ledger.missing}) — this test is no longer measuring what it claims to")
    assert ledger.status(LAYER_INSTALLED_SWEEP) == STATUS_NOT_REACHED
