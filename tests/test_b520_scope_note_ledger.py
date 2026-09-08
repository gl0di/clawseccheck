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

B-537 — the same paragraph, inverted, and the reason this file grew a third section.
The fix above was right that an absence must be proven; it then read "not listed as
missing" as proof of COVERAGE, which the ledger cannot support:

  * a COMPLETE ledger is indistinguishable from no ledger (C-422 pins the two
    `ScoreResult`s equal), so the flagship graded run — five layers `ran`, Grade A —
    fell into the no-evidence branch and told the reader to run all three modes;
  * `status == "ran"` is not "covered its subject" — `pipeline.to_ledger` reads the
    sweep phases' STATUS and never their `PhaseResult.complete`, so a run printing
    `Not fully covered: third-party-skill-0 … -5` also printed
    `· covered by this run — a deep vet of the skills … on disk.`;
  * at default budgets a TRUNCATED-but-WARN target leaves `not_scanned` empty, so the
    over-claim printed with no "Not fully covered" line to contradict it.

None of the three had a test, and the first is why: no test in the tree exercised a
complete ledger. The tests below now do, and the invariant that replaces the coverage
claim is mechanical — every clause, in every ledger shape, still carries SOME
actionable advice (`test_no_ledger_shape_ever_drops_the_advice`). That is what keeps
this repair from being the fourth fix in the family to trade an FP for an FN.

B-547 narrowed what "carries advice" means on exactly one branch. A layer whose `ran`
status IS the advised mode having just run — LAYER_INSTALLED_SWEEP (`ran` iff both
sweep phases ran) and LAYER_LIVE_BEHAVIOUR (`ran` iff a `--judged-bundle` live-test
entry arrived) — used to keep naming that same mode on `ran`, i.e. telling the operator
to go run what this very invocation just finished; that was the filed defect, not a
feature the old test protected. LAYER_LOGS_TRAJECTORIES is the one layer where the old
invariant still holds exactly: its `ran` starts True on every base audit (B164 scans
log sinks unconditionally) and proves nothing about whether `--behavioral` ran, so
suppressing its advice there would recreate the false-negative trap this file's second
section exists to guard against
(`test_the_replay_modes_survive_the_layer_being_marked_as_having_run`).

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

#: The clause prefix B-537 put in place of `· covered by this run — `. Spelled out
#: rather than imported for the same reason as the flags above.
RAN = " · ran, coverage not accounted for — "

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


def _ledger_with_unreached(layer: str, items, **overrides) -> LayerLedger:
    """As `_ledger`, but *layer* ran while leaving *items* of its subject unread —
    the shape `pipeline.to_ledger` produces from a sweep phase's `not_scanned`."""
    states = {name: LayerState(status=overrides.get(name, STATUS_RAN))
              for name in LAYER_ORDER}
    states[layer] = LayerState(status=overrides.get(layer, STATUS_RAN),
                               not_reached=tuple(items))
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
    head = "What this run reached beyond the static audit"
    assert text.count(head) == 1, f"expected exactly one scope note, got {text.count(head)}"
    after = text.split(head, 1)[1]
    return head + after.split("Static audit —", 1)[0]


# ── direction 1: a layer that RAN is no longer advertised as missing ──────────

def test_full_run_no_longer_claims_the_sweep_did_not_happen():
    """The exact `--full` shape that produced the bug: the sweeps and the MCP vet ran,
    only self-report and live behaviour did not.

    B-537 narrowed what this asserts, deliberately. The defect was the false CLAIM
    ("it does not do a deep vet"), and that is what must not come back. The advice
    beside it is NOT part of the defect and is now unconditional — see
    `test_no_ledger_shape_ever_drops_the_advice` for why suppressing it on `ran`
    evidence is unsound.
    """
    text = _render(_ledger(**{LAYER_SELF_REPORT: STATUS_UNAVAILABLE,
                              LAYER_LIVE_BEHAVIOUR: STATUS_UNAVAILABLE}))
    block = _scope_block(text)
    assert f"not covered — {SUBJECT_OF_LAYER[LAYER_INSTALLED_SWEEP]}" not in block, (
        "the installed-surface sweep ran this run and the report still says it did not:"
        f"\n{block}")
    assert f"not covered by the static audit — {SUBJECT_OF_LAYER[LAYER_INSTALLED_SWEEP]}" \
        not in block, block
    assert RAN + SUBJECT_OF_LAYER[LAYER_INSTALLED_SWEEP] in block, block


def test_a_live_tested_run_no_longer_claims_the_live_layer_is_absent():
    text = _render(_ledger(**{LAYER_SELF_REPORT: STATUS_UNAVAILABLE}))
    block = _scope_block(text)
    assert f"not covered — {SUBJECT_OF_LAYER[LAYER_LIVE_BEHAVIOUR]}" not in block, block
    assert RAN + SUBJECT_OF_LAYER[LAYER_LIVE_BEHAVIOUR] in block, block


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
    assert RAN + SUBJECT_OF_LAYER[LAYER_LOGS_TRAJECTORIES] in block, block
    # ... and it still says which half of the layer that `ran` accounts for. B-537
    # dropped "covered it" here for the same reason it dropped it everywhere: B164's
    # own disclosure is "N log/transcript sink(s) not scanned", so the base scan
    # running is not the base scan finishing.
    assert "this audit's own log/transcript scan ran" in block
    assert "covered it" not in block, block
    # B-558: this line used to pin the note's second clause, "; the replay analyses did
    # not". That clause was false on any run that DID run them — a `--full` report
    # printed T1/T2/T3/B191 verdicts a few hundred lines below it — and `ran` proves the
    # replay was skipped no more than it proves it happened. So the assertion above was
    # shortened rather than the note being "fixed" to satisfy it: this test had pinned
    # the successor of the very claim its own docstring exists to guard against.
    assert "did not" not in block.split("already logged")[1].split("Run `--behavioral`")[0]


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
    """With no ledger-derived evidence at all, the only provable scope is the static
    audit's own, and every clause keeps its advice: an unnecessary "run it" costs one
    command, a suppressed one costs the check."""
    findings = _findings()
    text = render_report(findings, compute(findings), ctx=Context(home=None))
    block = _scope_block(text)
    for flag in (CANARY, VET_MCP, BEHAVIORAL):
        assert flag in block, (flag, block)
    assert "from its own ledger" not in block, (
        "no ledger reached this render; the note must not claim one did")
    assert block.count("not covered by the static audit — ") == 3, block


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


# ── B-537: the note may only say what the ledger can prove ────────────────────
#
# Three shapes, none of which had a test before this. The first is the flagship case
# and its absence is the whole story: `test_no_ledger_keeps_every_clause` above pinned
# the ambiguity of an empty `missing_layers` as a *documented* limitation, and nothing
# ever rendered the other side of it.

def _complete_ledger() -> LayerLedger:
    """A ledger in the shape `pipeline.to_ledger` builds when all five layers ran:
    an attestation was supplied (so `self_report` is `ran`, and ALWAYS carries the
    freshness `not_reached` disclosure — that branch is unconditional in to_ledger)
    and a structurally-valid live-test entry arrived with `--judged-bundle`."""
    return _ledger_with_unreached(
        LAYER_SELF_REPORT,
        ["attestation freshness not verified — the schema carries no timestamp, so "
         "this can only mean one was supplied, never that it is recent"],
    )


def test_a_complete_ledger_is_rendered_at_all():
    """The case that shipped the bug: five layers `ran`, `ledger.complete` True,
    Grade A — and the note said "not covered by the static audit … run it" for all
    three subjects, because `missing_layers` is empty on a complete ledger exactly as
    it is on no ledger (C-422 pins the two ScoreResults equal)."""
    ledger = _complete_ledger()
    assert ledger.complete, "fixture is wrong — this must be a COMPLETE ledger"
    score = compute(_findings(), ledger=ledger)
    assert score.graded is True and score.missing_layers == (), (
        "fixture is wrong — a complete ledger must look graded with nothing missing")
    block = _scope_block(_render(ledger))
    assert "not covered by the static audit" not in block, (
        "every layer ran and the note still tells the reader to go run them:\n" + block)
    assert "from its own ledger" in block, block
    for layer in SUBJECT_OF_LAYER:
        assert RAN + SUBJECT_OF_LAYER[layer] in block, (layer, block)


def test_a_complete_ledger_never_claims_coverage_it_cannot_prove():
    """The other half: having noticed the ledger, the note must not swing to asserting
    that each layer covered its subject. `ran` is a status, not a completeness."""
    block = _scope_block(_render(_complete_ledger()))
    assert "covered by this run" not in block, block
    assert "partly covered" not in block, block


def test_a_ran_sweep_that_skipped_skills_does_not_vouch_for_them():
    """Defect 2, verbatim: a real sweep whose phases ran but whose `not_scanned` list
    named six skills printed `Not fully covered: third-party-skill-0 … -5` and, seven
    lines later, `· covered by this run — a deep vet of the skills … on disk.`"""
    unscanned = [f"third-party-skill-{i}" for i in range(6)]
    ledger = _ledger_with_unreached(
        LAYER_INSTALLED_SWEEP, unscanned,
        **{LAYER_SELF_REPORT: STATUS_UNAVAILABLE, LAYER_LIVE_BEHAVIOUR: STATUS_UNAVAILABLE})
    assert ledger.status(LAYER_INSTALLED_SWEEP) == STATUS_RAN, "fixture is wrong"
    text = _render(ledger)
    # The contradiction was between these two lines of the SAME report, so assert on both.
    assert "Not fully covered: " + "; ".join(unscanned) in text, text[:800]
    block = _scope_block(text)
    assert "covered by this run" not in block, (
        "the report lists six skills it never opened and still vouches for the sweep:"
        f"\n{block}")
    assert RAN + SUBJECT_OF_LAYER[LAYER_INSTALLED_SWEEP] in block, block
    assert VET_MCP in block, "the way to cover the six is no longer named: " + block


def test_a_truncated_but_warn_sweep_is_not_vouched_for_either():
    """Defect 3 — the same over-claim, silent. At default budgets a TRUNCATED-but-WARN
    target leaves `not_scanned` empty while the sweep is incomplete, so the ledger is
    byte-identical to a sweep that finished and no "Not fully covered" line prints to
    contradict the vouch. Keying the note on `not_checked` being non-empty would
    therefore suppress the advice in EXACTLY the case that has no other disclosure —
    which is why the clause wording, not the advice, is what B-537 changed."""
    ledger = _ledger(**{LAYER_SELF_REPORT: STATUS_UNAVAILABLE,
                        LAYER_LIVE_BEHAVIOUR: STATUS_UNAVAILABLE})
    text = _render(ledger)
    assert "Not fully covered" not in text, (
        "fixture is wrong — this shape must have NO partial-coverage disclosure")
    block = _scope_block(text)
    assert "covered by this run" not in block, block
    assert RAN + SUBJECT_OF_LAYER[LAYER_INSTALLED_SWEEP] in block, block
    assert VET_MCP in block, block


def test_the_header_does_not_promise_an_accounting_the_clauses_refuse_to_give():
    """A heading is a claim too. "Coverage of the layers …" over three lines that
    deliberately decline to state coverage is the same defect one level up."""
    for ledger in (_complete_ledger(), _ledger(**{LAYER_LIVE_BEHAVIOUR: STATUS_SKIPPED})):
        block = _scope_block(_render(ledger))
        assert "Coverage of the layers" not in block, block


@pytest.mark.parametrize("status", [STATUS_RAN, STATUS_UNAVAILABLE, STATUS_SKIPPED,
                                    STATUS_NOT_REACHED])
@pytest.mark.parametrize("subject_layer", list(SUBJECT_OF_LAYER))
def test_no_ledger_shape_ever_drops_the_advice(subject_layer, status):
    """The invariant that replaces the coverage claim: every clause carries SOME
    actionable advice, in every ledger shape — but B-547 bounds what that advice may
    say on `ran`, for exactly ONE layer.

    LAYER_LIVE_BEHAVIOUR's `ran` status IS the advised mode having just run (a
    structurally-valid `--judged-bundle` entry arrived — see `report._SCOPE_CLAUSES`),
    AND `pipeline.to_ledger` never attaches `not_reached` to this layer at all, so
    `ran` is the complete signal this renderer will ever have for it: there is no
    hidden-gap case to protect advice for. So on `ran` this one clause must NOT keep
    naming the mode — that was the filed defect: a graded run telling the operator to
    go run what this same invocation just finished. This is the one place this test
    asserts the flag's ABSENCE rather than presence, and it is a narrow, evidenced
    carve-out, not a general loosening — see the mirror check below that the subject is
    still named and the "ran, coverage not accounted for" clause still fires, so
    nothing about the layer having run goes unmentioned, only the already-run mode's
    name.

    LAYER_INSTALLED_SWEEP looks like the same shape — its `ran` also derives from the
    advised mode (`--full`/`--vet-all`/`--vet-mcp`) having run — but is deliberately
    EXCLUDED from the carve-out: unlike live-behaviour, a sweep's `ran` CAN coexist
    with a real, undisclosed gap (a phase can finish `ran` while truncated/capped
    without tripping "Not fully covered"), and `ScoreResult.not_checked` cannot
    attribute a gap back to one layer even when it IS disclosed. Suppressing the mode
    name there was tried and retracted as over-suppression — see
    `test_a_ran_sweep_that_skipped_skills_does_not_vouch_for_them` (a disclosed gap
    that still needs `--vet-mcp`) and `test_a_truncated_but_warn_sweep_is_not_vouched_for_either`
    (the same gap, undisclosed, indistinguishable at this renderer's inputs from a
    truly complete sweep). Both keep the flag on `ran`, same as before this task.

    LAYER_LOGS_TRAJECTORIES is excluded from the carve-out for a different, sharper
    reason: its `ran` starts True on every base audit (B164 scans log sinks
    unconditionally) and proves nothing about `--behavioral` having run at all, so its
    advice stays unconditional even on `ran` — see
    `test_the_replay_modes_survive_the_layer_being_marked_as_having_run` for why
    suppressing it there would be the false negative C-135 forbids.

    Every non-`ran` status keeps the original, deliberately mechanical invariant: both
    release FP gates are structurally blind to a lost signal (`fleet_fp_gate.py`
    compares FAIL sets on an unchanged config; `monitor_fp_gate.py` diffs two snapshots
    of an unchanged home), so an advice line that quietly stops printing on some ledger
    shape would ship green — which is how three earlier fixes in this family each
    traded an FP for an FN.
    """
    flags = {LAYER_LIVE_BEHAVIOUR: CANARY,
             LAYER_INSTALLED_SWEEP: VET_MCP,
             LAYER_LOGS_TRAJECTORIES: BEHAVIORAL}
    ledger = _ledger(**{subject_layer: status})
    block = _scope_block(_render(ledger))
    for layer, flag in flags.items():
        assert SUBJECT_OF_LAYER[layer] in block, (layer, block)
        if ledger.status(layer) == STATUS_RAN and layer == LAYER_LIVE_BEHAVIOUR:
            # B-547: this is the ONE layer whose `ran` status IS the advised mode
            # having just run WITH no possible hidden gap — naming it again is the
            # filed defect, not the invariant this test exists to protect.
            assert flag not in block, (
                f"{layer} ran this pass and the report still tells the operator to "
                f"(re)run {flag}, the mode that produced that `ran` status:\n{block}")
            assert RAN + SUBJECT_OF_LAYER[layer] in block, (
                f"{layer} ran but its own 'ran' clause is missing — the layer having "
                f"run must still be stated, just not with the already-run mode's name:"
                f"\n{block}")
        else:
            assert flag in block, (
                f"{layer}'s advice vanished when its status was "
                f"{ledger.status(layer)}:\n{block}")
