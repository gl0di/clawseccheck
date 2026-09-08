"""B-558 (verification pass): a `--full` run must not print a detector's verdict and
then, on a different surface of the same output, report that detector as unscanned.

This is a distinct file from tests/test_b558_behavioral_coverage_accounting.py (which
already pins the fix at the unit level: the phase carries `evaluated_findings`,
`coverage.build_coverage_page` merges them, and the ledger note wording). This file
adds three things that file does not:

1. A SINGLE reader-level helper (`_assert_no_contradiction`) applied identically to the
   text render, the JSON render, and a real ledger-derived scope note built through
   `pipeline.to_ledger` + `scoring.compute` + `report._scope_note_lines` — the actual
   call chain a user's report goes through, not the static `_SCOPE_CLAUSES` tuple read
   directly.
2. A non-vacuity control (`test_the_helper_itself_can_fail`): proves the helper is not
   tautological by feeding it a hand-built reproduction of the ORIGINAL bug shape and
   asserting it raises. Without this, "assert no contradiction" could pass by finding
   nothing to check.
3. A `--full --json` parity check: `coveragePage` in the JSON payload is asserted to be
   the literal same dict `pipeline.render_sections` renders from (one producer), not a
   second computation that happens to agree today.

Grounded in a real fixture (fixtures/traj_behavioral_trifecta) whose trajectory sidecar
gives T1 a WARN and T2 a PASS — i.e. real, non-uniform conclusive verdicts, not an
all-PASS run that could hide a status-specific regression.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck import pipeline as pl
from clawseccheck import report
from clawseccheck import scoring
from clawseccheck.behavioral import BEHAVIORAL_CHECK_IDS
from clawseccheck.checks import run_all
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
TRAJ_HOME = FIXTURES / "traj_behavioral_trifecta"


def _printed_verdicts(rendered_lines: list) -> dict:
    """id -> glyph ('[ok]'/'[!]'/'[?]') for every BEHAVIORAL_CHECK_IDS verdict a
    rendered report actually prints. Reads the glyph the renderer itself emits, not a
    status field, so this matches what a human reader sees."""
    out: dict = {}
    for line in rendered_lines:
        stripped = line.strip()
        if not stripped.startswith(("[ok]", "[!]", "[?]")):
            continue
        for cid in BEHAVIORAL_CHECK_IDS:
            if f"{cid} -" in stripped or f"{cid} —" in stripped:
                out[cid] = stripped.split(None, 1)[0]
    return out


def _assert_no_contradiction(printed: dict, not_scanned) -> None:
    """The single invariant both surfaces must satisfy: a detector printed with a
    CONCLUSIVE glyph may not also appear in `not_scanned`. UNKNOWN ([?]) is exempt by
    design — it is not a verdict anywhere else on this page either."""
    not_scanned = set(not_scanned)
    for cid, glyph in printed.items():
        if glyph == "[?]":
            continue
        assert cid not in not_scanned, (
            f"{cid} was printed with verdict {glyph} and reported as not scanned "
            f"(not_scanned={sorted(not_scanned)})")


# --------------------------------------------------------- the helper is not vacuous


def test_the_helper_itself_can_fail():
    """Non-vacuity control. Hand-built reproduction of the ORIGINAL bug shape (a
    conclusive glyph printed for T1 while the coverage page still lists T1 as
    unscanned) — proves `_assert_no_contradiction` can actually fail, so the real-run
    tests below are not passing merely because nothing was checked."""
    with pytest.raises(AssertionError, match="reported as not scanned"):
        _assert_no_contradiction({"T1": "[ok]"}, {"T1", "B191"})
    # The ledger-side half of the same family is covered by
    # `test_full_run_ledger_note_does_not_contradict_the_printed_verdicts` below, which
    # drives the real call chain. It is deliberately NOT asserted here against a literal
    # of this test's own making: "a string I just wrote contains the substring I put in
    # it" is true by construction and would be exactly the vacuous assertion this
    # non-vacuity control exists to rule out.


# ------------------------------------------------------------------- the real run


def test_full_run_text_and_coverage_page_agree():
    """The reproduction, end to end, over a real trajectory fixture with mixed
    verdicts (T1 WARN, T2 PASS — not an all-PASS run)."""
    ctx = collect(TRAJ_HOME)
    findings = run_all(ctx)
    result = pl.run_pipeline(ctx, findings, home_dir=ctx.home, ascii_only=True)
    rendered = pl.render_sections(result, ascii_only=True)

    printed = _printed_verdicts(rendered)
    assert printed, "non-vacuity: the behavioural section printed no detector verdict"
    conclusive = {cid for cid, g in printed.items() if g != "[?]"}
    assert conclusive, "non-vacuity: no CONCLUSIVE verdict was printed to check against"
    assert {"T1", "T2"} <= conclusive, sorted(conclusive)  # this fixture's known shape

    not_scanned = result.coverage_page["logs"]["not_scanned"]
    _assert_no_contradiction(printed, not_scanned)

    # The UNKNOWN pair stays correctly unscanned — the fix must not have overcorrected
    # into hiding a real gap.
    assert {"T3", "B191"} & set(not_scanned)


def test_full_run_json_coverage_page_is_the_same_object_as_the_text_render():
    """`--full --json`'s `coveragePage` must be one producer with the text render, not
    a second computation that happens to agree today."""
    ctx = collect(TRAJ_HOME)
    findings = run_all(ctx)
    result = pl.run_pipeline(ctx, findings, home_dir=ctx.home, ascii_only=True)
    rendered = pl.render_sections(result, ascii_only=True)
    doc = result.to_json()

    assert doc["coveragePage"]["logs"] == result.coverage_page["logs"]
    printed = _printed_verdicts(rendered)
    assert printed, "non-vacuity"
    _assert_no_contradiction(printed, doc["coveragePage"]["logs"]["not_scanned"])


def led_coverage(result, findings) -> str:
    """The logs layer's coverage off the real producer — so the assertion above cannot
    silently become vacuous if the fixture stops proving the COMPLETE branch."""
    return result.to_ledger(findings).coverage("logs_trajectories")


def test_full_run_ledger_note_does_not_contradict_the_printed_verdicts():
    """The SAME chain a real report renders through: PipelineResult.to_ledger ->
    scoring.compute -> report._scope_note_lines. Not the static _SCOPE_CLAUSES tuple
    read directly — that only proves the source table is worded safely, not that the
    text a user actually sees stays that way through the real call chain."""
    ctx = collect(TRAJ_HOME)
    findings = run_all(ctx)
    result = pl.run_pipeline(ctx, findings, home_dir=ctx.home, ascii_only=True)
    rendered = pl.render_sections(result, ascii_only=True)
    assert _printed_verdicts(rendered), "non-vacuity"

    ledger = result.to_ledger(findings)
    score = scoring.compute(findings, ctx, ledger=ledger)
    scope_lines, _live_tested = report._scope_note_lines(score, findings)
    # Anchored on the layer's SUBJECT, not on one wording. The previous anchor was the
    # `ran_note`'s own text, so B-558 step 4 — which moves this fixture onto the
    # `covered_note` form — broke it for a reason that has nothing to do with the
    # property under test. The subject string is the one part of the clause that is
    # stable across all five evidence forms.
    subject = next(c.subject for c in report._SCOPE_CLAUSES
                   if c.layer == "logs_trajectories")
    logs_clause = next((ln for ln in scope_lines if subject in ln), None)
    assert logs_clause is not None, scope_lines
    # The property, stated directly rather than by banning a noun: the clause may not
    # DENY what the report just printed. ("replay analyses" itself is no longer a
    # forbidden phrase — the covered form says the replay analyses RAN, which is the
    # opposite of the claim the ban was written to block.)
    assert "did not" not in logs_clause, logs_clause
    assert "not run" not in logs_clause.split("`--analyze-trajectory`")[0], logs_clause

    # B-558 step 4 / Dave's 2026-09-03 call: this fixture's replay provably exhausted
    # its subject (verified: no incompleteness reason, B164 leaves nothing unscanned),
    # so the clause must stop telling the reader to run the mode this run just ran.
    assert led_coverage(result, findings) == "complete", "fixture no longer proves the branch"
    assert "Run `--behavioral`" not in logs_clause, logs_clause
    # ...without dropping the half that genuinely has not run: `--analyze-trajectory`
    # is a separate CLI branch `--full` never invokes, so no signal here speaks for it.
    assert "`--analyze-trajectory`" in logs_clause, logs_clause


# ------------------------------------------------------------- the opposite direction


def test_fast_run_prints_no_verdict_and_reports_them_all_unscanned():
    """`--fast` drops the behavioural phase entirely. No conclusive glyph is printed
    for any BEHAVIORAL_CHECK_IDS id, and the coverage page is right to list them all as
    unscanned — the fix must not make that claim unconditional."""
    ctx = collect(TRAJ_HOME)
    findings = run_all(ctx)
    result = pl.run_pipeline(ctx, findings, home_dir=ctx.home, ascii_only=True, fast=True)
    rendered = pl.render_sections(result, ascii_only=True)

    printed = _printed_verdicts(rendered)
    conclusive = {cid for cid, g in printed.items() if g != "[?]"}
    assert not conclusive, conclusive

    not_scanned = set(result.coverage_page["logs"]["not_scanned"])
    assert set(BEHAVIORAL_CHECK_IDS) <= not_scanned, sorted(not_scanned)


# ------------------------------------------------------- B-558 steps 1-3: coverage
#
# The three tests below exercise the real `to_ledger` chain with a REAL
# `behavioral.analyze(ctx)` result — the only tests in the tree that do; the unit
# tests in test_c425_full_ledger.py hand-build `PhaseResult`s and never pass
# `behavioral_analysis` at all (so they exercise the guarded "phase ran but no
# analysis handed in" branch, not the coverage rule itself).


def test_ledger_coverage_complete_with_real_conclusive_analysis():
    """TRAJ_HOME gives T1/T2 conclusive verdicts and a clean B164 scan — the real
    `behavioral.analyze(ctx)` result should read COMPLETE, not just RAN."""
    from clawseccheck import behavioral
    from clawseccheck.layers import COVERAGE_COMPLETE

    ctx = collect(TRAJ_HOME)
    findings = run_all(ctx)
    result = pl.run_pipeline(ctx, findings, home_dir=ctx.home, ascii_only=True)
    analysis = behavioral.analyze(ctx)

    ledger = result.to_ledger(findings, behavioral_analysis=analysis)
    state = ledger.states["logs_trajectories"]
    assert state.status == "ran"
    assert state.coverage == COVERAGE_COMPLETE


def test_ledger_coverage_partial_when_real_analysis_is_incomplete():
    """A fixture whose `behavioral.analyze(ctx)` genuinely can't reach a clean
    verdict (every observed verb is outside the classifier's vocabulary) must read
    PARTIAL, with `behavioral.analysis_incompleteness`'s own reason folded into
    `not_reached` — not a fresh re-derivation of it."""
    from clawseccheck import behavioral
    from clawseccheck.layers import COVERAGE_PARTIAL

    home = FIXTURES / "traj_b299_bootstrap_uncorrelated"
    ctx = collect(str(home))
    findings = run_all(ctx)
    result = pl.run_pipeline(ctx, findings, home_dir=ctx.home, ascii_only=True)
    analysis = behavioral.analyze(ctx)
    reason = behavioral.analysis_incompleteness(analysis)
    assert reason is not None, "non-vacuity: this fixture must exercise the PARTIAL branch"

    ledger = result.to_ledger(findings, behavioral_analysis=analysis)
    state = ledger.states["logs_trajectories"]
    assert state.status == "ran"
    assert state.coverage == COVERAGE_PARTIAL
    assert reason in state.not_reached


def test_ledger_coverage_unknown_when_behavioral_did_not_run():
    """`--fast` drops the behavioural phase — `logs_trajectories` still reads
    `skipped` (unchanged), but its coverage must stay UNKNOWN, never COMPLETE:
    B164 alone proves nothing about whether the replay modes ran."""
    from clawseccheck.layers import COVERAGE_UNKNOWN

    ctx = collect(TRAJ_HOME)
    findings = run_all(ctx)
    result = pl.run_pipeline(ctx, findings, home_dir=ctx.home, ascii_only=True, fast=True)

    ledger = result.to_ledger(findings)
    state = ledger.states["logs_trajectories"]
    assert state.coverage == COVERAGE_UNKNOWN
