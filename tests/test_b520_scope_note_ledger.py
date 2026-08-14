"""B-520 — the scope note must describe THIS run, not a static assumption.

The paragraph under the score asserted, unconditionally, three things the run "does
not" do. Measured on the maintainer's own `--full` run, all three were false at the
moment they were printed:

    line   9: ... It does not test live prompt-injection resistance or do a deep MCP
              supply-chain vet — run `--canary` / `--redteam` / `--dryrun` ... It also
              doesn't mine what your agent has already logged — run `--behavioral` ...
    line 459: CLAWSECCHECK SELF-TEST        (canary + red-team + dry-run + multi-turn)
    line 915: CLAWSECCHECK VET-MCP
    line 920: CLAWSECCHECK SKILL SWEEP
    line 948: CLAWSECCHECK PLUGIN SWEEP
    line 954: CLAWSECCHECK BEHAVIORAL REPLAY

Five of the six modes it told the reader to go run had already run, in that same
process, and printed their results a few hundred lines below the advice.

The fix reads the run's own five-layer ledger (`layers.py`, carried on
`ScoreResult.missing_layers`) instead of assuming. So the load-bearing tests here are
BOTH directions, on the rendered report:

  * a layer the ledger says ran must stop being advertised as missing, and
  * a layer that did NOT run must still be recommended.

The second direction is the one this project keeps losing: three fixes in this family
traded a false positive for a false negative, and both FP gates are structurally blind
to that (`fleet_fp_gate.py` compares FAIL sets; `monitor_fp_gate.py` diffs two
snapshots of an unchanged home — neither can see a lost signal). The log/trajectory
clause is where that trap actually lives: `pipeline.py` marks that layer as having run
on EVERY audit, because B164 scans log sinks in the base run, so treating that as proof
the replay modes ran would silently stop telling a plain-run user to run them.

Stdlib-only, offline, writes nothing.
"""
from __future__ import annotations

from types import MappingProxyType

import pytest

from clawseccheck.catalog import FAIL, HIGH, Finding
from clawseccheck.collector import Context
from clawseccheck.layers import (
    LAYER_INSTALLED_SWEEP,
    LAYER_LIVE_BEHAVIOUR,
    LAYER_LOGS_TRAJECTORIES,
    LAYER_ORDER,
    LAYER_SELF_REPORT,
    LAYER_STATIC,
    STATUS_NOT_REACHED,
    STATUS_RAN,
    STATUS_SKIPPED,
    STATUS_UNAVAILABLE,
    LayerLedger,
    LayerState,
)
from clawseccheck.report import render_report
from clawseccheck.scoring import compute

# The three coverage clauses, each identified by the flag a reader would type. Kept as
# literal flag strings rather than imported from the clause table: a test that reads the
# same constant as the code cannot notice the constant changing.
CANARY = "`--canary`"
VET_MCP = "`--vet-mcp`"
BEHAVIORAL = "`--behavioral`"

SUBJECT_OF_LAYER = {
    LAYER_LIVE_BEHAVIOUR: "live prompt-injection resistance",
    LAYER_INSTALLED_SWEEP: "a deep vet of the skills, plugins and MCP servers sitting on disk",
    LAYER_LOGS_TRAJECTORIES: "what your agent has already logged",
}


def _ledger(**overrides) -> LayerLedger:
    """A ledger where every layer ran unless overridden."""
    states = {layer: LayerState(status=overrides.get(layer, STATUS_RAN))
              for layer in LAYER_ORDER}
    return LayerLedger(states=MappingProxyType(states))


def _findings() -> list[Finding]:
    return [Finding("B1", "seeded", HIGH, FAIL, "detail", "fix", "framework")]


def _render(ledger) -> str:
    findings = _findings()
    score = compute(findings, ledger=ledger)
    return render_report(findings, score, ctx=Context(home=None))


def _scope_block(text: str) -> str:
    """The scope note only — from its header to the paragraph after it — so an
    assertion about a flag cannot be satisfied by some unrelated line elsewhere in a
    thousand-line report."""
    head = "Coverage of the layers beyond the static audit"
    assert text.count(head) == 1, f"expected exactly one scope note, got {text.count(head)}"
    after = text.split(head, 1)[1]
    return head + after.split("Static audit —", 1)[0]


# ── direction 1: a layer that RAN is no longer advertised as missing ──────────

def test_full_run_does_not_tell_the_reader_to_run_what_it_just_ran():
    """The exact `--full` shape that produced the bug: the sweeps and the MCP vet ran,
    only self-report and live behaviour did not."""
    text = _render(_ledger(**{LAYER_SELF_REPORT: STATUS_UNAVAILABLE,
                              LAYER_LIVE_BEHAVIOUR: STATUS_UNAVAILABLE}))
    block = _scope_block(text)
    assert VET_MCP not in block, (
        "the installed-surface sweep ran this run and the report still tells the reader "
        f"to go run it:\n{block}")
    assert "covered by this run — " + SUBJECT_OF_LAYER[LAYER_INSTALLED_SWEEP] in block, block


def test_a_live_tested_run_stops_recommending_the_live_harnesses():
    text = _render(_ledger(**{LAYER_SELF_REPORT: STATUS_UNAVAILABLE}))
    block = _scope_block(text)
    assert CANARY not in block, block
    assert "covered by this run — " + SUBJECT_OF_LAYER[LAYER_LIVE_BEHAVIOUR] in block, block


def test_the_static_audit_tail_does_not_dangle_when_the_live_tests_already_ran():
    """Sibling defect, same paragraph: "Use the live tests above" is a back-reference to
    flags the scope note no longer names once the ledger says that layer ran."""
    ran = _render(_ledger(**{LAYER_SELF_REPORT: STATUS_UNAVAILABLE}))
    not_ran = _render(_ledger(**{LAYER_SELF_REPORT: STATUS_UNAVAILABLE,
                                 LAYER_LIVE_BEHAVIOUR: STATUS_UNAVAILABLE}))
    assert "Use the live tests above" not in ran
    assert "The live-behaviour result above is what speaks to that." in ran
    assert "Use the live tests above" in not_ran


def test_a_layer_that_ran_is_never_listed_as_not_covered():
    """The invariant, stated once: positive `ran` evidence and a "not covered" line for
    the same subject may not both appear."""
    for layer in (LAYER_LIVE_BEHAVIOUR, LAYER_INSTALLED_SWEEP):
        # Something must be missing, or there is no ledger evidence at all to read.
        text = _render(_ledger(**{LAYER_SELF_REPORT: STATUS_UNAVAILABLE, layer: STATUS_RAN}))
        assert f"not covered — {SUBJECT_OF_LAYER[layer]}" not in _scope_block(text), layer


def test_the_log_layer_is_not_reported_as_unmined_when_it_ran():
    """The original false claim, in its own right: "It also doesn't mine what your agent
    has already logged" printed 941 lines above BEHAVIORAL REPLAY."""
    text = _render(_ledger(**{LAYER_SELF_REPORT: STATUS_UNAVAILABLE}))
    block = _scope_block(text)
    assert f"not covered — {SUBJECT_OF_LAYER[LAYER_LOGS_TRAJECTORIES]}" not in block, block
    assert "partly covered — " + SUBJECT_OF_LAYER[LAYER_LOGS_TRAJECTORIES] in block, block


# ── direction 2: a layer that did NOT run must still be recommended ───────────
#
# This is the half a "remove the false positive" fix silently drops.

@pytest.mark.parametrize("status", [STATUS_UNAVAILABLE, STATUS_SKIPPED, STATUS_NOT_REACHED])
@pytest.mark.parametrize(
    "layer,flag",
    [(LAYER_LIVE_BEHAVIOUR, CANARY),
     (LAYER_INSTALLED_SWEEP, VET_MCP),
     (LAYER_LOGS_TRAJECTORIES, BEHAVIORAL)],
)
def test_a_layer_that_did_not_run_is_still_recommended(layer, flag, status):
    block = _scope_block(_render(_ledger(**{layer: status})))
    assert flag in block, (
        f"{layer} did not run ({status}) and the report no longer tells the reader how "
        f"to run it:\n{block}")
    assert f"not covered — {SUBJECT_OF_LAYER[layer]}" in block, block


def test_the_replay_modes_survive_the_layer_being_marked_as_having_run():
    """The trap, pinned. `pipeline.py` marks the log/trajectory layer as having run on
    EVERY audit (B164 scans log sinks in the base run), so `ran` there is NOT evidence
    that `--behavioral` / `--analyze-trajectory` ran. A plain audit must still be told
    to run them — suppressing that on this evidence would invent a clean, which neither
    FP gate can see."""
    plain_run = _ledger(**{LAYER_INSTALLED_SWEEP: STATUS_NOT_REACHED,
                           LAYER_SELF_REPORT: STATUS_UNAVAILABLE,
                           LAYER_LIVE_BEHAVIOUR: STATUS_UNAVAILABLE})
    assert plain_run.status(LAYER_LOGS_TRAJECTORIES) == STATUS_RAN, "fixture is wrong"
    block = _scope_block(_render(plain_run))
    assert BEHAVIORAL in block, block
    assert "`--analyze-trajectory`" in block, block


def test_no_ledger_keeps_every_clause():
    """`missing_layers` is empty both when no ledger was supplied and when a complete
    one was — `graded` stays True in both, so the two are indistinguishable here. With
    no evidence the note under-claims coverage rather than inventing it: an unnecessary
    "run it" costs one command, a suppressed one costs the check."""
    findings = _findings()
    text = render_report(findings, compute(findings), ctx=Context(home=None))
    block = _scope_block(text)
    for flag in (CANARY, VET_MCP, BEHAVIORAL):
        assert flag in block, (flag, block)
    assert "from this run's own ledger" not in block, (
        "no ledger reached this render; the note must not claim one did")


def test_the_reason_a_layer_did_not_run_comes_from_the_shared_wording_table():
    """`layers.describe_layer` is the single wording site for layer/status phrasing —
    the reason must be quoted from it, never re-phrased here (tests/test_c423_* fails
    the build on a competing table in report.py)."""
    from clawseccheck.layers import describe_layer

    text = _render(_ledger(**{LAYER_INSTALLED_SWEEP: STATUS_NOT_REACHED}))
    assert describe_layer(LAYER_INSTALLED_SWEEP, STATUS_NOT_REACHED) in _scope_block(text)


def test_static_layer_is_not_in_the_scope_note():
    """The note is about the layers BEYOND the static audit — the static layer is the
    report itself, and advertising it would be circular."""
    block = _scope_block(_render(_ledger(**{LAYER_STATIC: STATUS_RAN,
                                            LAYER_SELF_REPORT: STATUS_UNAVAILABLE})))
    assert "static config audit" not in block, block
