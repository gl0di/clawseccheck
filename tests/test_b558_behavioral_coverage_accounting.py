"""B-558: a detector whose verdict a run PRINTS may not be reported as unscanned.

A `--full` run used to say all three of these about the same four detectors:

    CLAWSECCHECK BEHAVIORAL REPLAY
      ✓ T1 — ...   ✓ T2 — ...   ? T3 — ...   ✓ B191 — 520 row(s) ...

    · ran, coverage not accounted for — what your agent has already logged: this
      audit's own log/transcript scan ran; the replay analyses did not.

    Logs & trajectories: 2 of 7 scanned
      not scanned: B180, B191, T1, T2, T3

Two false statements about the run's own coverage, on two surfaces, twenty lines apart.

## Why it happened

`behavioral.py` is deliberately outside `CHECKS` (F-154 routes a fired detector to the
grade as a cap-only signal instead), but `BEHAVIORAL_CHECK_IDS` ARE in `CATALOG` and
routed to the `logs` subject. So they counted in the coverage page's denominator and
could never reach its numerator, whatever the run did. The ledger note was the same gap
on the other surface: it asserted the negative "the replay analyses did not", which the
layer's `ran` status no more proves than it proves the opposite.

## What is asserted here

The invariant is derived from the run's own output, never from a hard-coded id list, so a
detector added to `BEHAVIORAL_CHECK_IDS` later is covered without editing this file.

Note what is deliberately NOT changed: an UNKNOWN detector stays in `not_scanned`. That is
`_CHECKED_STATUSES` applying to these ids exactly as to every other check on the page — an
UNKNOWN is not a verdict anywhere else either, and special-casing it here would trade one
inconsistency for another.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from clawseccheck import behavioral
from clawseccheck import coverage as cov
from clawseccheck import pipeline as pl
from clawseccheck.behavioral import BEHAVIORAL_CHECK_IDS
from clawseccheck.catalog import Finding
from clawseccheck.checks import run_all
from clawseccheck.collector import collect
from clawseccheck.report import _SCOPE_CLAUSES

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
# A home whose agent has actually produced a trajectory sidecar, so the detectors have
# something to reach a verdict about.
TRAJ_HOME = FIXTURES / "traj_present_not_acted"


def _finding(id_: str, status: str) -> Finding:
    return Finding(id=id_, title="synthetic", severity="LOW", status=status,
                   detail="synthetic detail", fix="synthetic fix", framework="Test")


# --------------------------------------------------------------- the phase carries them


def test_the_behavioural_phase_reports_the_findings_it_evaluated():
    ctx = collect(TRAJ_HOME)
    phase = pl.run_behavioral(ctx)
    assert phase.status == pl.STATUS_RAN, phase.detail
    ids = {f.id for f in phase.evaluated_findings}
    assert ids, "the phase rendered verdicts but reported no evaluated findings"
    assert ids <= set(BEHAVIORAL_CHECK_IDS), ids


def test_evaluated_findings_stay_out_of_the_phase_json():
    """They are coverage input, not a payload. Findings carry evidence text, and this
    dict is what `--full --json` publishes."""
    ctx = collect(TRAJ_HOME)
    doc = pl.run_behavioral(ctx).to_json()
    assert "evaluated_findings" not in doc
    assert "evaluatedFindings" not in doc


# ------------------------------------------------------------------- the coverage page


def test_an_off_check_verdict_reaches_the_coverage_numerator():
    ctx = collect(TRAJ_HOME)
    findings = run_all(ctx)
    before = cov.build_coverage_page(ctx, findings)["logs"]
    after = cov.build_coverage_page(
        ctx, findings, extra_findings=[_finding("T1", "PASS")])["logs"]
    assert "T1" in before["not_scanned"]
    assert "T1" not in after["not_scanned"]
    assert after["scanned"] == before["scanned"] + 1
    assert after["total"] == before["total"], "the denominator must not move"


def test_an_unknown_detector_stays_unscanned_like_every_other_unknown():
    ctx = collect(TRAJ_HOME)
    findings = run_all(ctx)
    page = cov.build_coverage_page(
        ctx, findings, extra_findings=[_finding("T3", "UNKNOWN")])["logs"]
    assert "T3" in page["not_scanned"]


def test_a_real_check_id_is_not_displaced_by_an_off_check_twin():
    """`subject_coverage` keeps the LAST finding per id, so the extras must be merged
    FIRST for a registered check to win a collision.

    This test was written the other way round first — asserting the id landed in
    `not_scanned`, under a message saying that outcome was the bug. It passed, because
    the merge order was the reverse of what its own comment claimed. Nothing collides
    today (no `BEHAVIORAL_CHECK_IDS` member is in `CHECKS`), which is exactly why the
    ordering needs a test rather than a comment: the parameter is generic over any
    future phase and a collision would be silent.
    """
    ctx = collect(TRAJ_HOME)
    findings = run_all(ctx) + [_finding("B164", "WARN")]
    page = cov.build_coverage_page(
        ctx, findings, extra_findings=[_finding("B164", "UNKNOWN")])["logs"]
    assert "B164" not in page["not_scanned"], (
        "an off-check UNKNOWN overrode a registered check's conclusive WARN")


# ------------------------------------------------- a vacuous PASS is not coverage


def _home_with_trajectory(tmp_path: Path, *lines: str) -> Path:
    """A copy of the trajectory fixture whose sidecars carry exactly *lines*."""
    home = tmp_path / "home"
    shutil.copytree(TRAJ_HOME, home)
    for sidecar in home.rglob("*.trajectory.jsonl"):
        sidecar.write_text("".join(f"{ln}\n" for ln in lines), encoding="utf-8")
    return home


def test_a_pass_over_an_empty_event_set_is_not_counted_as_scanned(tmp_path):
    """The break an independent review found in this fix's first version.

    T1/T2 gate only on `meta["present"]`, so they return PASS with zero events parsed —
    "no thread shows an ingress -> sensitive -> egress sequence" is trivially true when
    there are no threads. That is fine as a rendered line, and it is not a basis for
    counting the subject scanned. No check in `CHECKS` behaves this way: one that cannot
    determine state returns UNKNOWN, so its PASS is always a verdict.
    """
    ctx = collect(_home_with_trajectory(tmp_path, '{"schemaVersion": 99, "type": "note"}'))
    analysis = behavioral.analyze(ctx)
    assert analysis["event_count"] == 0, analysis
    assert {f.id: f.status for f in analysis["findings"]}["T1"] == "PASS", (
        "fixture no longer produces the vacuous PASS this test exists for")

    result = pl.run_pipeline(ctx, run_all(ctx), home_dir=ctx.home)
    not_scanned = set(result.coverage_page["logs"]["not_scanned"])
    assert {"T1", "T2"} <= not_scanned, sorted(not_scanned)


def test_the_conclusiveness_gate_names_every_incompleteness_analyze_reports(tmp_path):
    """Each flag alone must withhold the verdicts, so a host that is merely capped — the
    common real case, 60 of 78 sidecars — cannot claim coverage it does not have."""
    ctx = collect(_home_with_trajectory(tmp_path, '{"schemaVersion": 99, "type": "note"}'))
    base = dict(behavioral.analyze(ctx))
    base.update(present=True, event_count=5, truncated=False,
                files_capped=False, unknown_version=False)
    assert behavioral.analysis_is_conclusive(base)
    for flag in ("truncated", "files_capped", "unknown_version"):
        assert not behavioral.analysis_is_conclusive({**base, flag: True}), flag
    for absent in ("present", "event_count"):
        assert not behavioral.analysis_is_conclusive({**base, absent: 0}), absent


# -------------------------------------------------------------------- end to end, full


def test_no_printed_verdict_is_reported_as_unscanned():
    """The invariant as a READER meets it: both halves come from the run's own rendered
    output, so this would have caught the bug with no knowledge of the internals that fix
    it — and it keeps catching a regression reintroduced by any other route.

    Conclusiveness is read from the glyph the renderer itself prints (`[ok]`/`[!]` for a
    verdict, `[?]` for UNKNOWN, in `--ascii` form so the assertion does not hinge on
    terminal encoding), not from a status field, and the detector ids come from
    `BEHAVIORAL_CHECK_IDS` rather than a literal list, so a detector added later is
    covered without editing this test.
    """
    ctx = collect(TRAJ_HOME)
    findings = run_all(ctx)
    result = pl.run_pipeline(ctx, findings, home_dir=ctx.home, ascii_only=True)
    rendered = pl.render_sections(result, ascii_only=True)
    not_scanned = set(result.coverage_page["logs"]["not_scanned"])

    verdicts: dict[str, str] = {}
    for line in rendered:
        stripped = line.strip()
        for cid in BEHAVIORAL_CHECK_IDS:
            for marker in (f"{cid} -", f"{cid} —"):
                if marker in stripped and stripped.startswith(("[ok]", "[!]", "[?]")):
                    verdicts[cid] = stripped.split(None, 1)[0]

    assert verdicts, "the behavioural section printed no detector verdict to check against"
    for cid, glyph in verdicts.items():
        if glyph == "[?]":
            continue  # UNKNOWN is not a verdict here, same as anywhere else on the page
        assert cid not in not_scanned, (
            f"{cid} was printed with verdict {glyph} and then reported as not scanned")


def test_a_run_without_the_behavioural_phase_still_reports_them_unscanned():
    """The other direction. `--fast` drops P8, and then the page is right to say these
    were never looked at — the fix must not make the claim unconditional."""
    ctx = collect(TRAJ_HOME)
    findings = run_all(ctx)
    result = pl.run_pipeline(ctx, findings, home_dir=ctx.home, fast=True)
    not_scanned = set(result.coverage_page["logs"]["not_scanned"])
    assert set(BEHAVIORAL_CHECK_IDS) <= not_scanned, sorted(not_scanned)


# ------------------------------------------------------------------------- the ledger


def test_the_logs_layer_note_asserts_nothing_about_the_replay():
    """It used to say "the replay analyses did not", which is false on any run that ran
    them. `ran` for this layer proves the log/transcript scan happened and nothing more,
    in either direction."""
    note = next(n for layer, _subject, _advice, n in _SCOPE_CLAUSES
                if layer == "logs_trajectories")
    assert "did not" not in note, note
    assert "replay" not in note, note


def test_the_logs_layer_still_tells_the_reader_how_to_run_the_replay():
    """The actionable half must survive the wording fix — it is what the reader does
    next, and it is unconditional by design (see _SCOPE_CLAUSES' own comment)."""
    advice = next(a for layer, _subject, a, _n in _SCOPE_CLAUSES
                  if layer == "logs_trajectories")
    assert "--behavioral" in advice
