"""CLAWSECCHECK-C-425 — `--full` builds and threads the five-layer ledger.

Teaches `pipeline.PipelineResult.to_ledger()` (the mapping of the pipeline's phases
onto `layers.py`'s five-layer ledger) and wires it into `scoring.compute()` through
`cli._resolve_runtime_caps` — the ONE shared choke point both `--full`'s own
report/--json path and `--dashboard --full` call (see that function's own C-425
docstring paragraph for why consolidating there, rather than three separate
call-site blocks, is what keeps the two surfaces from disagreeing).

**The single thing this file exists to pin**: layer 5 (`live_behaviour`)'s status
comes from the PRESENCE of a submitted, well-formed live-test verdict, never from its
VALUE. `pipeline.live_test_cap_signal(bucket).hit` is deliberately NOT what
`to_ledger()` reads for this layer — `.hit` is True only for VULNERABLE (the
self-attestation guard scoring.py's LIVE_INJECTION_CAP already enforces), and if
`to_ledger()` read that instead, a user whose live test came back RESISTANT would
read as `not_reached` and lose their grade for PASSING it.

The renderer changes that teach `report.py` about `graded=False` land on a separate
branch — see this repo's C-425 brief. So every assertion here is against
`ScoreResult.graded` / `ScoreResult.missing_layers` / the raw `LayerLedger`
`to_ledger()` produces, NEVER against rendered report/JSON text (which will still
print a letter grade here regardless of `graded`, for a reason that has nothing to
do with this change).

Offline, deterministic, no network. Uses the shipped fixtures only.
"""
from __future__ import annotations

import inspect
import json
from pathlib import Path
from types import SimpleNamespace


from clawseccheck import audit, cli
from clawseccheck import pipeline as pl
from clawseccheck.catalog import LOW, PASS, Finding
from clawseccheck.layers import (
    LAYER_INSTALLED_SWEEP,
    LAYER_LIVE_BEHAVIOUR,
    LAYER_LOGS_TRAJECTORIES,
    LAYER_SELF_REPORT,
    LAYER_STATIC,
    STATUS_ERROR,
    STATUS_NOT_REACHED,
    STATUS_RAN,
    STATUS_SKIPPED,
    STATUS_UNAVAILABLE,
)
from clawseccheck.scoring import LIVE_INJECTION_CAP

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE = str(FIXTURES / "home_safe")


def _b164(detail: str) -> Finding:
    return Finding(id="B164", title="log threat hunt", severity=LOW, status=PASS,
                    detail=detail, fix="f", framework="fw", scored=False)


def _pass(fid: str = "B9", severity: str = LOW) -> Finding:
    return Finding(id=fid, title="t", severity=severity, status=PASS,
                    detail="d", fix="f", framework="fw", scored=True)


def _empty_pipeline(*, fast: bool = False) -> pl.PipelineResult:
    return pl.PipelineResult(fast=fast)


def _bundle_file(tmp_path: Path, payload: dict, name: str = "bundle.json") -> str:
    p = tmp_path / name
    p.write_text(json.dumps(payload), encoding="utf-8")
    return str(p)


def _args(*, full: bool = True, fast: bool = False, judged_bundle: str | None = None):
    return SimpleNamespace(full=full, fast=fast, judged_bundle=judged_bundle)


# ── Section A: pipeline.PipelineResult.to_ledger() — the mapping itself ─────────

class TestStaticLayer:
    def test_always_ran_with_no_not_reached_when_nothing_degraded(self):
        ledger = _empty_pipeline().to_ledger([], degraded_count=0)
        assert ledger.status(LAYER_STATIC) == STATUS_RAN
        assert ledger.states[LAYER_STATIC].not_reached == ()

    def test_degraded_count_names_itself_in_not_reached(self):
        ledger = _empty_pipeline().to_ledger([], degraded_count=3)
        assert ledger.status(LAYER_STATIC) == STATUS_RAN
        assert ledger.states[LAYER_STATIC].not_reached == (
            "3 checks could not reach a verdict this run",
        )

    def test_singular_phrasing_for_one(self):
        ledger = _empty_pipeline().to_ledger([], degraded_count=1)
        assert ledger.states[LAYER_STATIC].not_reached == (
            "1 check could not reach a verdict this run",
        )


class TestInstalledSweepLayer:
    def test_ran_only_when_both_phases_ran(self):
        result = _empty_pipeline()
        result.add(pl.PhaseResult(name=pl.PHASE_SKILL_SWEEP, status=STATUS_RAN))
        result.add(pl.PhaseResult(name=pl.PHASE_PLUGIN_SWEEP, status=STATUS_RAN))
        ledger = result.to_ledger([])
        assert ledger.status(LAYER_INSTALLED_SWEEP) == STATUS_RAN

    def test_skipped_when_both_skipped(self):
        result = _empty_pipeline(fast=True)
        result.add(pl.PhaseResult(name=pl.PHASE_SKILL_SWEEP, status=STATUS_SKIPPED, complete=False))
        result.add(pl.PhaseResult(name=pl.PHASE_PLUGIN_SWEEP, status=STATUS_SKIPPED, complete=False))
        ledger = result.to_ledger([])
        assert ledger.status(LAYER_INSTALLED_SWEEP) == STATUS_SKIPPED

    def test_worse_of_two_when_one_errored_and_other_ran(self):
        """The named scenario: a phase that errored must never hide behind a sibling
        that merely ran — the ERROR must win the merge."""
        result = _empty_pipeline()
        result.add(pl.PhaseResult(name=pl.PHASE_SKILL_SWEEP, status=STATUS_RAN))
        result.add(pl.PhaseResult(name=pl.PHASE_PLUGIN_SWEEP, status=STATUS_ERROR, complete=False))
        ledger = result.to_ledger([])
        assert ledger.status(LAYER_INSTALLED_SWEEP) == STATUS_ERROR

    def test_error_outranks_skipped_in_the_merge(self):
        result = _empty_pipeline()
        result.add(pl.PhaseResult(name=pl.PHASE_SKILL_SWEEP, status=STATUS_SKIPPED, complete=False))
        result.add(pl.PhaseResult(name=pl.PHASE_PLUGIN_SWEEP, status=STATUS_ERROR, complete=False))
        ledger = result.to_ledger([])
        assert ledger.status(LAYER_INSTALLED_SWEEP) == STATUS_ERROR

    def test_missing_phase_reads_not_reached(self):
        result = _empty_pipeline()
        result.add(pl.PhaseResult(name=pl.PHASE_SKILL_SWEEP, status=STATUS_RAN))
        # PHASE_PLUGIN_SWEEP never added at all.
        ledger = result.to_ledger([])
        assert ledger.status(LAYER_INSTALLED_SWEEP) == STATUS_NOT_REACHED

    def test_not_reached_unions_both_phases_not_scanned(self):
        result = _empty_pipeline()
        result.add(pl.PhaseResult(name=pl.PHASE_SKILL_SWEEP, status=STATUS_RAN,
                                  not_scanned=["skillA"]))
        result.add(pl.PhaseResult(name=pl.PHASE_PLUGIN_SWEEP, status=STATUS_RAN,
                                  not_scanned=["pluginB"]))
        ledger = result.to_ledger([])
        assert ledger.states[LAYER_INSTALLED_SWEEP].not_reached == ("skillA", "pluginB")


class TestLogsTrajectoriesLayer:
    def test_ran_when_no_behavioral_phase_present(self):
        ledger = _empty_pipeline().to_ledger([])
        assert ledger.status(LAYER_LOGS_TRAJECTORIES) == STATUS_RAN

    def test_ran_when_behavioral_ran(self):
        result = _empty_pipeline()
        result.add(pl.PhaseResult(name=pl.PHASE_BEHAVIORAL, status=STATUS_RAN))
        ledger = result.to_ledger([])
        assert ledger.status(LAYER_LOGS_TRAJECTORIES) == STATUS_RAN

    def test_worse_when_behavioral_errored(self):
        result = _empty_pipeline()
        result.add(pl.PhaseResult(name=pl.PHASE_BEHAVIORAL, status=STATUS_ERROR, complete=False))
        ledger = result.to_ledger([])
        assert ledger.status(LAYER_LOGS_TRAJECTORIES) == STATUS_ERROR

    def test_worse_when_behavioral_skipped_by_fast(self):
        result = _empty_pipeline(fast=True)
        result.add(pl.PhaseResult(name=pl.PHASE_BEHAVIORAL, status=STATUS_SKIPPED, complete=False))
        ledger = result.to_ledger([])
        assert ledger.status(LAYER_LOGS_TRAJECTORIES) == STATUS_SKIPPED

    def test_b164_not_reached_parsed_from_findings(self):
        findings = [_b164("3 log/transcript sinks not scanned (scan budget reached).")]
        ledger = _empty_pipeline().to_ledger(findings)
        assert ledger.states[LAYER_LOGS_TRAJECTORIES].not_reached == (
            "3 log/transcript sink(s) not scanned",
        )

    def test_b164_singular_not_reached_parsed(self):
        findings = [_b164("1 log/transcript sink not scanned (scan budget reached).")]
        ledger = _empty_pipeline().to_ledger(findings)
        assert ledger.states[LAYER_LOGS_TRAJECTORIES].not_reached == (
            "1 log/transcript sink(s) not scanned",
        )

    def test_no_not_reached_when_b164_absent_or_clean(self):
        assert _empty_pipeline().to_ledger([]).states[LAYER_LOGS_TRAJECTORIES].not_reached == ()
        clean = [_b164("4 log/transcript sink(s) scanned; no corroborated threat signal.")]
        assert _empty_pipeline().to_ledger(clean).states[LAYER_LOGS_TRAJECTORIES].not_reached == ()


class TestSelfReportLayer:
    def test_unavailable_when_no_attestation(self):
        ledger = _empty_pipeline().to_ledger([], attestation=None)
        assert ledger.status(LAYER_SELF_REPORT) == STATUS_UNAVAILABLE
        assert ledger.states[LAYER_SELF_REPORT].not_reached == ()

    def test_unavailable_when_attestation_is_empty_dict(self):
        # Matches attest.parse_attestation's own "malformed/absent -> {}" contract —
        # an empty dict must read exactly like no attestation at all.
        ledger = _empty_pipeline().to_ledger([], attestation={})
        assert ledger.status(LAYER_SELF_REPORT) == STATUS_UNAVAILABLE

    def test_ran_when_attestation_supplied_but_discloses_no_freshness_claim(self):
        ledger = _empty_pipeline().to_ledger([], attestation={"tools": ["send_email"]})
        assert ledger.status(LAYER_SELF_REPORT) == STATUS_RAN
        not_reached = ledger.states[LAYER_SELF_REPORT].not_reached
        assert len(not_reached) == 1
        assert "no timestamp" in not_reached[0]
        assert "recent" in not_reached[0]


class TestLiveBehaviourLayerTheTrap:
    """The named regression: RESISTANT-only must still read `ran`."""

    def test_unavailable_when_bucket_absent(self):
        ledger = _empty_pipeline().to_ledger([], live_test_bucket=None)
        assert ledger.status(LAYER_LIVE_BEHAVIOUR) == STATUS_UNAVAILABLE

    def test_unavailable_when_bucket_malformed(self):
        ledger = _empty_pipeline().to_ledger([], live_test_bucket={"verdicts": "not-a-list"})
        assert ledger.status(LAYER_LIVE_BEHAVIOUR) == STATUS_UNAVAILABLE

    def test_ran_on_resistant_only_bucket(self):
        """THE central regression this task exists to close: a RESISTANT-only
        verdict must read `ran`, not `not_reached` -- reading `live_test_cap_signal
        (...).hit` here instead (True only for VULNERABLE) would make a user who
        PASSED their live test lose their grade for it."""
        bucket = {"verdicts": [{"tool": "canary", "id": "canary", "verdict": "RESISTANT"}]}
        assert pl.live_test_cap_signal(bucket).hit is False  # sanity: .hit really is False here
        ledger = _empty_pipeline().to_ledger([], live_test_bucket=bucket)
        assert ledger.status(LAYER_LIVE_BEHAVIOUR) == STATUS_RAN

    def test_ran_on_vulnerable_bucket(self):
        bucket = {"verdicts": [{"tool": "canary", "id": "canary", "verdict": "VULNERABLE"}]}
        ledger = _empty_pipeline().to_ledger([], live_test_bucket=bucket)
        assert ledger.status(LAYER_LIVE_BEHAVIOUR) == STATUS_RAN


# ── Section B: cli._resolve_runtime_caps — the wiring, over a real fixture ──────

class TestResolveRuntimeCapsWiring:
    def test_non_full_never_builds_a_ledger_score_untouched(self):
        ctx, findings, score = audit(SAFE)
        args = _args(full=False)
        out_score, *_rest = cli._resolve_runtime_caps(ctx, findings, score, args)
        assert out_score is score
        assert out_score.graded is True
        assert out_score.missing_layers == ()

    def test_no_bundle_no_attestation_layers_4_5_unavailable_and_ungraded(self):
        ctx, findings, score = audit(SAFE)
        args = _args(full=True, fast=False)
        out_score, *_rest = cli._resolve_runtime_caps(ctx, findings, score, args,
                                                       attestation=None)
        assert out_score.graded is False
        names = {layer for layer, _status in out_score.missing_layers}
        assert "self_report" in names
        assert "live_behaviour" in names
        statuses = dict(out_score.missing_layers)
        assert statuses["self_report"] == STATUS_UNAVAILABLE
        assert statuses["live_behaviour"] == STATUS_UNAVAILABLE
        # score/grade values themselves are untouched by "graded" -- this is a
        # DISCLOSURE dimension, not a new cap (report.py's own consumption of
        # `graded` lands on a separate branch -- see this module's docstring).
        assert out_score.score == score.score
        assert out_score.grade == score.grade

    def test_resistant_only_live_test_layer5_ran_graded_depends_only_on_others(
        self, tmp_path
    ):
        """The CLI-level twin of the trap test above: a RESISTANT-only submission
        must not cost this run its `live_behaviour` layer."""
        bundle = _bundle_file(tmp_path, {"liveTest": {"verdicts": [
            {"tool": "canary", "id": "canary", "verdict": "RESISTANT"}]}})
        ctx, findings, score = audit(SAFE)
        args = _args(full=True, fast=False, judged_bundle=bundle)
        out_score, *_rest = cli._resolve_runtime_caps(ctx, findings, score, args,
                                                       attestation={"tools": ["x"]})
        names_missing = {layer for layer, _status in out_score.missing_layers}
        assert "live_behaviour" not in names_missing
        assert "self_report" not in names_missing
        # self-attestation guard is unaffected by this task: RESISTANT never caps.
        assert out_score.live_injection_capped is False

    def test_vulnerable_live_test_layer5_ran_and_cap_still_applies(self, tmp_path):
        bundle = _bundle_file(tmp_path, {"liveTest": {"verdicts": [
            {"tool": "canary", "id": "canary", "verdict": "VULNERABLE"}]}})
        ctx, findings, score = audit(SAFE)
        args = _args(full=True, fast=False, judged_bundle=bundle)
        out_score, *_rest = cli._resolve_runtime_caps(ctx, findings, score, args,
                                                       attestation={"tools": ["x"]})
        names_missing = {layer for layer, _status in out_score.missing_layers}
        assert "live_behaviour" not in names_missing  # ran: BOTH, not either
        assert out_score.live_injection_capped is True
        assert out_score.score <= LIVE_INJECTION_CAP

    def test_fast_ungrades_installed_sweep_and_logs_trajectories(self):
        ctx, findings, score = audit(SAFE)
        args = _args(full=True, fast=True)
        out_score, *_rest = cli._resolve_runtime_caps(ctx, findings, score, args,
                                                       attestation=None)
        assert out_score.graded is False
        statuses = dict(out_score.missing_layers)
        assert statuses["installed_sweep"] == STATUS_SKIPPED
        assert statuses["logs_trajectories"] == STATUS_SKIPPED

    def test_everything_supplied_and_not_fast_is_graded(self, tmp_path):
        bundle = _bundle_file(tmp_path, {"liveTest": {"verdicts": [
            {"tool": "canary", "id": "canary", "verdict": "RESISTANT"}]}})
        ctx, findings, score = audit(SAFE)
        args = _args(full=True, fast=False, judged_bundle=bundle)
        out_score, *_rest = cli._resolve_runtime_caps(ctx, findings, score, args,
                                                       attestation={"tools": ["x"]})
        assert out_score.graded is True
        assert out_score.missing_layers == ()
        # C-422 invariant: a fully-graded run must be score/grade-identical to the
        # SAME run with no ledger at all.
        assert out_score.score == score.score
        assert out_score.grade == score.grade

    def test_a_phase_that_errored_is_never_swallowed_by_to_ledger(self):
        """Unit-level pin of scenario 6 at the mapping layer (to_ledger itself,
        see TestInstalledSweepLayer above) PLUS the compute()-level consequence:
        an errored layer must ungrade the run, never silently degrade to a softer
        status."""
        ctx, findings, score = audit(SAFE)
        prelim = pl.PipelineResult(fast=False)
        prelim.add(pl.PhaseResult(name=pl.PHASE_SKILL_SWEEP, status=STATUS_RAN))
        prelim.add(pl.PhaseResult(name=pl.PHASE_PLUGIN_SWEEP, status=pl.STATUS_ERROR,
                                  complete=False))
        ledger = prelim.to_ledger(findings, degraded_count=score.degraded_count)
        from clawseccheck.scoring import compute
        capped = compute(findings, ctx, ledger=ledger)
        assert capped.graded is False
        assert dict(capped.missing_layers)[LAYER_INSTALLED_SWEEP] == STATUS_ERROR


# ── Section C: CLI end-to-end — exit code / crash surface only, never rendered text ──

class TestCliEndToEndSmoke:
    BASE = ["--no-native", "--no-history"]

    def test_full_json_no_bundle_no_attest_runs_and_exit_code_unchanged(self, capsys):
        rc = cli.main(["--home", SAFE] + self.BASE + ["--full", "--json"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        # The renderer changes (report.py) are a separate branch -- this run must
        # still print A LETTER today, unaffected by `graded` (see module docstring).
        assert payload["grade"] in ("A", "B", "C", "D", "F")

    def test_full_human_report_runs_without_crashing(self, capsys):
        rc = cli.main(["--home", SAFE] + self.BASE + ["--full", "--quiet"])
        assert rc in (0, 1)
        assert capsys.readouterr().out

    def test_dashboard_full_runs_without_crashing(self, capsys):
        rc = cli.main(["--home", SAFE] + self.BASE + ["--dashboard", "--full"])
        assert rc in (0, 1)
        assert capsys.readouterr().out

    def test_full_fast_runs_without_crashing(self, capsys):
        rc = cli.main(["--home", SAFE] + self.BASE + ["--full", "--fast", "--json"])
        assert rc == 0
        assert capsys.readouterr().out


class TestBothFullSurfacesShareTheSameWiring:
    """C-425's own reason for consolidating into `_resolve_runtime_caps`: `--full`'s
    report/--json path and `--dashboard --full` must call the IDENTICAL function with
    the IDENTICAL arguments, so they cannot compute two different ledgers for the
    same run. Verified at the source level (never against rendered output) --
    behavioural proof that they in fact agree is `TestResolveRuntimeCapsWiring`
    above, since both call sites route through that one function."""

    def test_both_call_sites_pass_attestation_through(self):
        src = inspect.getsource(cli)
        needle = "_resolve_runtime_caps(ctx, findings, score, args, attestation=attestation)"
        assert src.count(needle) == 2

    def test_resolve_runtime_caps_signature_accepts_attestation(self):
        sig = inspect.signature(cli._resolve_runtime_caps)
        assert "attestation" in sig.parameters
        assert sig.parameters["attestation"].default is None


class TestB164WordingIsPinnedToTheCheckThatEmitsIt:
    """The ledger parses B164's own prose, so the two can drift apart silently — the
    line would just go empty and the report would stop disclosing what it did not read.

    An earlier draft of this test invented "sink(s)" as the emitted wording; the real
    check emits "sink"/"sinks". Both the regex and a hand-transcribed fixture can be
    wrong together, so pin against the source that actually produces the sentence.
    """

    def test_regex_matches_the_sentence_egress_actually_emits(self):
        egress = (
            Path(pl.__file__).resolve().parent / "checks" / "_egress.py"
        ).read_text(encoding="utf-8")
        assert 'log/transcript {plural} not scanned' in egress, (
            "B164's skip sentence moved or was reworded — _B164_NOT_SCANNED_RE in "
            "pipeline.py parses it, so update both together"
        )
        assert 'plural = "sink" if skipped_for_time == 1 else "sinks"' in egress, (
            "B164's plural form changed — _B164_NOT_SCANNED_RE expects sink/sinks"
        )
        for n, word in ((1, "sink"), (7, "sinks")):
            sentence = (
                f" {n} log/transcript {word} not scanned (scan budget reached; the "
                "oldest are left out first) — re-run with --exhaustive to include them."
            )
            m = pl._B164_NOT_SCANNED_RE.search(sentence)
            assert m and m.group(1) == str(n), sentence
