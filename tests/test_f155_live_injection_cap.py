"""F-155 — live injection-test verdicts (canary/dryrun/redteam/multiturn) reach the
grade as a NEW, dedicated fourth cap-only tier (Dave's 2026-07-30 ruling, distinct from
RUNTIME_SIGNAL_CAP/CONFIG_BLIND_CAP/DEGRADED_CHECK_CAP).

Covers, per the task's own test plan:
  - VULNERABLE verdict submitted -> ceiling binds, reason surfaced in the report.
  - RESISTANT submitted -> score byte-identical to submitting nothing (self-attestation
    guard: the verdict comes from the agent UNDER TEST, so only VULNERABLE ever moves
    anything).
  - Nothing submitted -> today's behaviour byte-identical (regression on the existing
    --full/--judged-bundle contract).
  - A random-token (unseeded) run is never recorded into history.jsonl/trend/baseline; a
    seeded (reproducible) run is.
  - Forged/malformed/replayed verdict payload -> rejected without moving the grade.

Offline, deterministic, no network. Uses the shipped fixtures only.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import CRITICAL, FAIL, LOW, PASS, Finding
from clawseccheck.cli import main
from clawseccheck.history import load as history_load
from clawseccheck.monitor import load_state
from clawseccheck.report import render_html, render_json, render_report
from clawseccheck.scoring import LIVE_INJECTION_CAP, ScoreResult, compute

from clawseccheck import pipeline as pl

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
VULN = str(FIXTURES / "home_vuln")
SAFE = str(FIXTURES / "home_safe")
BASE = ["--no-native", "--no-history"]


def _pass_finding(fid: str = "B9", severity: str = LOW) -> Finding:
    return Finding(id=fid, title="t", severity=severity, status=PASS,
                    detail="d", fix="f", framework="fw", scored=True)


def _fail_finding(fid: str = "B1", severity: str = CRITICAL) -> Finding:
    return Finding(id=fid, title="t", severity=severity, status=FAIL,
                    detail="d", fix="f", framework="fw", scored=True)


def _drop_elapsed(payload: dict) -> dict:
    """Strip the ONE deliberately non-deterministic value in a --full --json payload
    (each phases[] entry's wall-clock elapsed_s — see pipeline.PhaseResult.to_json's own
    docstring) before a byte-identical comparison, so two real runs a few ms apart don't
    spuriously fail a same-content assertion.
    """
    out = dict(payload)
    if "phases" in out:
        out["phases"] = [
            {k: v for k, v in p.items() if k != "elapsed_s"} for p in out["phases"]
        ]
    return out


def _bundle_file(tmp_path: Path, payload, name: str = "bundle.json") -> str:
    p = tmp_path / name
    if isinstance(payload, str):
        p.write_text(payload, encoding="utf-8")
    else:
        p.write_text(json.dumps(payload), encoding="utf-8")
    return str(p)


# ── scoring.py: compute() unit tests ─────────────────────────────────────────

class TestLiveInjectionCapScoring:
    def test_vulnerable_caps_an_otherwise_perfect_score(self):
        findings = [_pass_finding()]
        clean = compute(findings)
        capped = compute(findings, live_test_vulnerable=True, live_test_reason="redteam:PI-01")
        assert clean.live_injection_capped is False
        assert clean.live_injection_cap_reason is None
        assert capped.live_injection_capped is True
        assert capped.live_injection_cap_reason == "redteam:PI-01"
        assert capped.score <= LIVE_INJECTION_CAP
        assert capped.grade in ("D", "F")
        assert capped.score < clean.score

    def test_resistant_or_absent_has_zero_effect(self):
        # Self-attestation guard: _live_injection_cap_signal only ever reacts to
        # live_test_vulnerable=True. A "RESISTANT" or absent submission is modeled as
        # False -- the only value that reaches the "nothing happened" branch.
        findings = [_pass_finding()]
        baseline = compute(findings)
        resistant = compute(findings, live_test_vulnerable=False,
                            live_test_reason="redteam:PI-01")
        assert resistant == baseline

    def test_nothing_submitted_byte_identical_to_default_compute(self):
        findings = [_pass_finding(), _fail_finding(fid="B2", severity=LOW)]
        assert compute(findings) == compute(findings, ctx=None)
        assert compute(findings) == compute(
            findings, live_test_vulnerable=False, live_test_reason=None)

    def test_live_injection_capped_false_when_tighter_cap_already_applied(self):
        # A genuine CRITICAL FAIL already caps at the SAME ceiling -- the live-test
        # signal is real but not independently BINDING (mirrors DEGRADED_CHECK_CAP's
        # own "tighter cap already applied" test).
        findings = [_fail_finding(), _pass_finding()]
        result = compute(findings, live_test_vulnerable=True, live_test_reason="canary:canary")
        assert result.score <= LIVE_INJECTION_CAP
        assert result.live_injection_capped is False

    def test_total_zero_with_only_live_test_signal_forces_f_not_na(self):
        result = compute([], live_test_vulnerable=True, live_test_reason="canary:canary")
        assert result.assessable is True
        assert result.grade == "F"
        assert result.live_injection_capped is True
        assert result.live_injection_cap_reason == "canary:canary"

    def test_total_zero_with_nothing_at_all_stays_na(self):
        result = compute([])
        assert result.assessable is False
        assert result.grade == "N/A"
        assert result.live_injection_capped is False

    def test_never_earns_or_costs_an_ordinary_scored_point(self):
        findings = [_pass_finding()]
        clean = compute(findings)
        capped = compute(findings, live_test_vulnerable=True, live_test_reason="x")
        assert clean.raw_score == capped.raw_score == 100


# ── report.py rendering ───────────────────────────────────────────────────────

def _score(**kw) -> ScoreResult:
    defaults = dict(
        score=79, grade="C", capped=False, raw_score=79,
        failed_critical=0, failed_high=0, failed_medium=0, failed_low=0,
        assessable=True, cap_severity=None,
        runtime_capped=False, runtime_cap_reason=None,
        config_blind_capped=False, degraded_capped=False, degraded_count=0,
        live_injection_capped=False, live_injection_cap_reason=None,
    )
    defaults.update(kw)
    return ScoreResult(**defaults)


class TestReportRendering:
    def test_nothing_submitted_no_new_text_in_text_report(self):
        out = render_report([], _score(), ascii_only=True)
        assert "Live-test exception" not in out
        assert "live injection-test" not in out.lower()

    def test_capped_explanation_present_when_binding(self):
        out = render_report([], _score(score=49, raw_score=79, grade="F",
                                       live_injection_capped=True,
                                       live_injection_cap_reason="redteam:PI-01"),
                            ascii_only=True)
        assert (
            "(capped from 79 - a live injection-test scenario reported VULNERABLE "
            "(redteam:PI-01))"
        ) in out
        assert "Live-test exception (F-155): this run's grade WAS capped" in out
        assert "redteam:PI-01" in out

    def test_html_no_new_text_when_not_capped(self):
        html = render_html([], _score())
        assert "live injection-test" not in html.lower()

    def test_html_shows_cap_when_binding(self):
        html = render_html([], _score(score=49, raw_score=79, grade="F",
                                      live_injection_capped=True,
                                      live_injection_cap_reason="canary:canary"))
        assert "live injection-test scenario reported VULNERABLE" in html
        assert "canary:canary" in html

    def test_json_carries_live_injection_fields_when_capped(self):
        payload = json.loads(render_json([], _score(live_injection_capped=True,
                                                     live_injection_cap_reason="dryrun:DR-01")))
        assert payload["live_injection_capped"] is True
        assert payload["live_injection_cap_reason"] == "dryrun:DR-01"

    def test_json_default_fields_absent_signal(self):
        payload = json.loads(render_json([], _score()))
        assert payload["live_injection_capped"] is False
        assert payload["live_injection_cap_reason"] is None


# ── pipeline.py: liveTest bucket parsing ──────────────────────────────────────

class TestLiveTestCapSignal:
    def test_absent_bucket_is_inert(self):
        sig = pl.live_test_cap_signal(None)
        assert sig.hit is False
        assert sig.reason is None
        assert sig.reproducible is False

    def test_vulnerable_entry_hits_and_is_reproducible_when_seeded(self):
        bucket = {"seed": "abc123",
                 "verdicts": [{"tool": "redteam", "id": "PI-01", "verdict": "VULNERABLE"}]}
        sig = pl.live_test_cap_signal(bucket)
        assert sig.hit is True
        assert sig.reason == "redteam:PI-01"
        assert sig.reproducible is True

    def test_resistant_only_does_not_hit(self):
        bucket = {"verdicts": [{"tool": "canary", "id": "canary", "verdict": "RESISTANT"}]}
        sig = pl.live_test_cap_signal(bucket)
        assert sig.hit is False
        assert sig.reason is None

    def test_mixed_entries_any_vulnerable_hits(self):
        bucket = {"verdicts": [
            {"tool": "canary", "id": "canary", "verdict": "RESISTANT"},
            {"tool": "redteam", "id": "JB-01", "verdict": "VULNERABLE"},
        ]}
        sig = pl.live_test_cap_signal(bucket)
        assert sig.hit is True
        assert sig.reason == "redteam:JB-01"

    def test_unseeded_hit_still_caps_but_is_not_reproducible(self):
        bucket = {"verdicts": [{"tool": "canary", "id": "canary", "verdict": "VULNERABLE"}]}
        sig = pl.live_test_cap_signal(bucket)
        assert sig.hit is True
        assert sig.reproducible is False

    def test_many_vulnerable_entries_reason_is_capped(self):
        entries = [{"tool": "redteam", "id": f"PI-{i:02d}", "verdict": "VULNERABLE"}
                  for i in range(10)]
        sig = pl.live_test_cap_signal({"verdicts": entries})
        assert sig.hit is True
        assert "(+4 more)" in sig.reason

    # ── forged / malformed rejection ────────────────────────────────────────
    def test_bucket_not_a_dict(self):
        assert pl.live_test_cap_signal("not-a-dict").hit is False
        assert pl.live_test_cap_signal(["a", "list"]).hit is False
        assert pl.live_test_cap_signal(12345).hit is False

    def test_verdicts_not_a_list(self):
        assert pl.live_test_cap_signal({"verdicts": "not-a-list"}).hit is False

    def test_entries_not_dicts_are_dropped_not_crashed(self):
        bucket = {"verdicts": ["garbage", 42, None, {"tool": "canary"}]}
        assert pl.live_test_cap_signal(bucket).hit is False

    def test_unknown_tool_dropped(self):
        bucket = {"verdicts": [{"tool": "totally-unknown-tool", "id": "X", "verdict": "VULNERABLE"}]}
        assert pl.live_test_cap_signal(bucket).hit is False

    def test_malformed_id_dropped(self):
        bucket = {"verdicts": [
            {"tool": "canary", "id": "'; DROP TABLE --", "verdict": "VULNERABLE"}]}
        assert pl.live_test_cap_signal(bucket).hit is False

    def test_oversized_id_dropped(self):
        bucket = {"verdicts": [{"tool": "canary", "id": "A" * 200, "verdict": "VULNERABLE"}]}
        assert pl.live_test_cap_signal(bucket).hit is False

    def test_unrecognized_verdict_dropped(self):
        bucket = {"verdicts": [{"tool": "canary", "id": "canary", "verdict": "MAYBE"}]}
        assert pl.live_test_cap_signal(bucket).hit is False

    def test_seed_wrong_type_not_reproducible(self):
        bucket = {"seed": 12345,
                 "verdicts": [{"tool": "canary", "id": "canary", "verdict": "VULNERABLE"}]}
        sig = pl.live_test_cap_signal(bucket)
        assert sig.hit is True
        assert sig.reproducible is False

    def test_seed_oversized_not_reproducible(self):
        bucket = {"seed": "x" * 500,
                 "verdicts": [{"tool": "canary", "id": "canary", "verdict": "VULNERABLE"}]}
        assert pl.live_test_cap_signal(bucket).reproducible is False

    def test_seed_empty_string_not_reproducible(self):
        bucket = {"seed": "",
                 "verdicts": [{"tool": "canary", "id": "canary", "verdict": "VULNERABLE"}]}
        assert pl.live_test_cap_signal(bucket).reproducible is False


class TestSplitJudgedBundleLiveTest:
    def test_live_test_bucket_round_trips(self):
        raw = json.dumps({"liveTest": {"seed": "x", "verdicts": []}})
        out = pl.split_judged_bundle(raw)
        assert out["liveTest"] == {"seed": "x", "verdicts": []}

    def test_live_test_wrong_type_dropped(self):
        raw = json.dumps({"liveTest": "not-a-dict"})
        out = pl.split_judged_bundle(raw)
        assert out["liveTest"] is None

    def test_live_test_absent_key_defaults_none(self):
        raw = json.dumps({"judged": {}})
        out = pl.split_judged_bundle(raw)
        assert out["liveTest"] is None

    def test_other_buckets_still_default_and_untouched(self):
        # F-155 must not perturb the three pre-existing buckets' own contract.
        raw = json.dumps({"attestation": {"a": 1}})
        out = pl.split_judged_bundle(raw)
        assert out == {"attestation": {"a": 1}, "judged": None, "vetJudged": [], "liveTest": None}


# ── CLI end-to-end: the task's own test plan, verified against real fixtures ──

class TestCliEndToEnd:
    def test_vulnerable_verdict_caps_the_grade_and_reason_surfaces_in_json(self, tmp_path, capsys):
        bundle = _bundle_file(tmp_path, {"liveTest": {"seed": "s1", "verdicts": [
            {"tool": "redteam", "id": "PI-01", "verdict": "VULNERABLE"}]}})
        rc = main(["--home", SAFE] + BASE + ["--full", "--json", "--judged-bundle", bundle])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["live_injection_capped"] is True
        assert payload["live_injection_cap_reason"] == "redteam:PI-01"
        assert payload["score"] <= LIVE_INJECTION_CAP
        assert payload["grade"] == "F"

    def test_reason_surfaces_in_the_printed_report(self, tmp_path, capsys):
        bundle = _bundle_file(tmp_path, {"liveTest": {"verdicts": [
            {"tool": "canary", "id": "canary", "verdict": "VULNERABLE"}]}})
        rc = main(["--home", SAFE] + BASE + ["--full", "--judged-bundle", bundle])
        assert rc == 0
        out = capsys.readouterr().out
        assert "canary:canary" in out
        assert "Live-test exception (F-155)" in out

    def test_resistant_verdict_byte_identical_to_nothing_submitted(self, tmp_path, capsys):
        bundle = _bundle_file(tmp_path, {"liveTest": {"seed": "s1", "verdicts": [
            {"tool": "canary", "id": "canary", "verdict": "RESISTANT"}]}})
        main(["--home", SAFE] + BASE + ["--full", "--json", "--judged-bundle", bundle])
        with_resistant = json.loads(capsys.readouterr().out)
        main(["--home", SAFE] + BASE + ["--full", "--json"])
        without_bundle = json.loads(capsys.readouterr().out)
        assert _drop_elapsed(with_resistant) == _drop_elapsed(without_bundle)

    def test_nothing_submitted_byte_identical_across_runs(self, capsys):
        main(["--home", SAFE] + BASE + ["--full", "--json"])
        a = json.loads(capsys.readouterr().out)
        main(["--home", SAFE] + BASE + ["--full", "--json"])
        b = json.loads(capsys.readouterr().out)
        assert _drop_elapsed(a) == _drop_elapsed(b)
        assert a["live_injection_capped"] is False
        assert a["live_injection_cap_reason"] is None

    def test_tighter_cap_already_applied_on_home_vuln(self, tmp_path, capsys):
        # home_vuln already caps to F/49 via a real CRITICAL FAIL -- a VULNERABLE
        # verdict is real but non-binding (mirrors the scoring.py unit test above,
        # now proven end-to-end through the real CLI/fixture path).
        bundle = _bundle_file(tmp_path, {"liveTest": {"verdicts": [
            {"tool": "canary", "id": "canary", "verdict": "VULNERABLE"}]}})
        rc = main(["--home", VULN] + BASE + ["--full", "--json", "--judged-bundle", bundle])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["score"] == 49
        assert payload["grade"] == "F"
        assert payload["live_injection_capped"] is False

    def test_forged_malformed_payload_rejected_without_moving_grade(self, tmp_path, capsys):
        main(["--home", SAFE] + BASE + ["--full", "--json"])
        clean_payload = json.loads(capsys.readouterr().out)

        cases = [
            '{"liveTest": "not-a-dict"}',
            '{"liveTest": {"verdicts": "not-a-list"}}',
            '{"liveTest": {"verdicts": [{"tool": "evil", "id": "X", "verdict": "VULNERABLE"}]}}',
            '{"liveTest": {"verdicts": [{"tool": "canary", "id": "canary", "verdict": "HACKED"}]}}',
            '{"liveTest": {"verdicts": [{"tool": "canary", "id": "'
            "'; DROP TABLE --" + '", "verdict": "VULNERABLE"}]}}',
            "{not valid json",
        ]
        for i, raw in enumerate(cases):
            bundle = _bundle_file(tmp_path, raw, name=f"bundle{i}.json")
            rc = main(["--home", SAFE] + BASE + ["--full", "--json", "--judged-bundle", bundle])
            assert rc == 0
            payload = json.loads(capsys.readouterr().out)
            assert payload["score"] == clean_payload["score"], raw
            assert payload["grade"] == clean_payload["grade"], raw
            assert payload["live_injection_capped"] is False, raw

    def test_oversized_bundle_rejected_without_moving_grade(self, tmp_path, capsys):
        main(["--home", SAFE] + BASE + ["--full", "--json"])
        clean_payload = json.loads(capsys.readouterr().out)

        huge = json.dumps({"liveTest": {"verdicts": [], "pad": "y" * (pl.MAX_BUNDLE_BYTES + 100)}})
        bundle = _bundle_file(tmp_path, huge)
        rc = main(["--home", SAFE] + BASE + ["--full", "--json", "--judged-bundle", bundle])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["score"] == clean_payload["score"]
        assert payload["live_injection_capped"] is False

    def test_replayed_payload_produces_the_same_capped_result_each_time(self, tmp_path, capsys):
        bundle = _bundle_file(tmp_path, {"liveTest": {"seed": "s1", "verdicts": [
            {"tool": "redteam", "id": "PI-01", "verdict": "VULNERABLE"}]}})
        main(["--home", SAFE] + BASE + ["--full", "--json", "--judged-bundle", bundle])
        first = json.loads(capsys.readouterr().out)
        main(["--home", SAFE] + BASE + ["--full", "--json", "--judged-bundle", bundle])
        second = json.loads(capsys.readouterr().out)
        assert _drop_elapsed(first) == _drop_elapsed(second)

    # ── history/trend/baseline recordability (seeded vs unseeded) ────────────

    def test_unseeded_vulnerable_verdict_not_recorded_into_history(self, tmp_path, capsys):
        hist = tmp_path / "history.jsonl"
        bundle = _bundle_file(tmp_path, {"liveTest": {"verdicts": [
            {"tool": "canary", "id": "canary", "verdict": "VULNERABLE"}]}})
        rc = main(["--home", SAFE, "--no-native", "--full", "--json",
                  "--judged-bundle", bundle, "--history", str(hist)])
        assert rc == 0
        assert not hist.exists()

    def test_seeded_vulnerable_verdict_is_recorded_into_history(self, tmp_path, capsys):
        hist = tmp_path / "history.jsonl"
        bundle = _bundle_file(tmp_path, {"liveTest": {"seed": "s1", "verdicts": [
            {"tool": "canary", "id": "canary", "verdict": "VULNERABLE"}]}})
        rc = main(["--home", SAFE, "--no-native", "--full", "--json",
                  "--judged-bundle", bundle, "--history", str(hist)])
        assert rc == 0
        rows = history_load(str(hist))
        assert len(rows) == 1
        assert rows[0]["score"] <= LIVE_INJECTION_CAP

    def test_resistant_verdict_still_records_normally(self, tmp_path, capsys):
        # RESISTANT never hits, so the reproducibility gate never even applies --
        # history recording proceeds exactly as it would with no bundle at all.
        hist = tmp_path / "history.jsonl"
        bundle = _bundle_file(tmp_path, {"liveTest": {"verdicts": [
            {"tool": "canary", "id": "canary", "verdict": "RESISTANT"}]}})
        rc = main(["--home", SAFE, "--no-native", "--full", "--json",
                  "--judged-bundle", bundle, "--history", str(hist)])
        assert rc == 0
        rows = history_load(str(hist))
        assert len(rows) == 1

    def test_no_bundle_at_all_records_normally(self, tmp_path, capsys):
        hist = tmp_path / "history.jsonl"
        rc = main(["--home", SAFE, "--no-native", "--full", "--json", "--history", str(hist)])
        assert rc == 0
        rows = history_load(str(hist))
        assert len(rows) == 1


class TestTrendMonitorReachC135:
    """C-135 finding on this task: `--trend` and `--monitor` both returned from
    `_main`'s dispatch cascade BEFORE the `liveTest` bucket in `--judged-bundle` was
    ever parsed, so a VULNERABLE verdict -- seeded or not -- could never bind
    LIVE_INJECTION_CAP for either mode: the UNCAPPED score got shown AND recorded
    into history.jsonl / baked into the --monitor drift baseline, contradicting
    SKILL.md / docs/OUTPUT_SCHEMA.md Sec.12 / docs/USAGE.md, which all promise a
    seeded liveTest verdict reaches --trend/--monitor. Exact repro from the review
    comment, now pinning the fixed (capped) behaviour permanently.
    """

    def _seeded_bundle(self, tmp_path: Path) -> str:
        return _bundle_file(tmp_path, {"liveTest": {"seed": "s1", "verdicts": [
            {"tool": "canary", "id": "canary", "verdict": "VULNERABLE"}]}})

    def _unseeded_bundle(self, tmp_path: Path) -> str:
        return _bundle_file(tmp_path, {"liveTest": {"verdicts": [
            {"tool": "canary", "id": "canary", "verdict": "VULNERABLE"}]}})

    def test_home_safe_baseline_is_uncapped_98_a(self, capsys):
        # Sanity anchor: without a live-test bundle, home_safe's own default score
        # really is 98/A -- so the 49/F assertions below are a genuine cap, not two
        # coincidentally-equal runs.
        #
        # --no-sockets (B-374, C-135 round 2, 2026-07-31): without it, this read the
        # REAL host's live listening sockets (F-156/B340), which is nondeterministic
        # across machines/CI runs -- B340 now correctly reads UNKNOWN (not the old
        # false-positive FAIL) for an unattributable non-loopback listener sharing
        # home_safe's declared gateway.bind (127.0.0.1:8080) port number, but that
        # UNKNOWN-vs-FAIL split still depends on whatever happens to be listening on
        # this host, so the exact uncapped score is only deterministic with sockets
        # scanning disabled. Only the actual VALUE (79 -> 98, C -> A) changed; the
        # test's own point -- this is a real, non-49 baseline -- is unaffected.
        rc = main(["--home", SAFE, "--no-native", "--full", "--json", "--no-sockets"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["score"] == 98
        assert payload["grade"] == "A"

    def test_json_reference_is_capped_49_f(self, tmp_path, capsys):
        bundle = self._seeded_bundle(tmp_path)
        rc = main(["--home", SAFE, "--no-native", "--full", "--json",
                   "--judged-bundle", bundle])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["score"] == LIVE_INJECTION_CAP == 49
        assert payload["grade"] == "F"

    def test_trend_shows_and_records_the_capped_score(self, tmp_path, capsys):
        bundle = self._seeded_bundle(tmp_path)
        hist = tmp_path / "history.jsonl"
        rc = main(["--home", SAFE, "--no-native", "--full", "--trend", "--ascii",
                   "--judged-bundle", bundle, "--history", str(hist)])
        assert rc == 0
        out = capsys.readouterr().out
        assert " F  49 " in out
        rows = history_load(str(hist))
        assert len(rows) == 1
        assert rows[0]["score"] == LIVE_INJECTION_CAP == 49
        assert rows[0]["grade"] == "F"

    def test_monitor_shows_and_records_the_capped_score(self, tmp_path, capsys):
        bundle = self._seeded_bundle(tmp_path)
        state = tmp_path / "state.json"
        events = tmp_path / "events.jsonl"
        hist = tmp_path / "history.jsonl"
        rc = main(["--home", SAFE, "--no-native", "--full", "--monitor", "--ascii",
                   "--judged-bundle", bundle, "--state", str(state),
                   "--events", str(events), "--history", str(hist)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Current: 49/100  Grade: F" in out
        baseline = load_state(str(state))
        assert baseline is not None
        assert baseline["score"] == LIVE_INJECTION_CAP == 49
        assert baseline["grade"] == "F"
        rows = history_load(str(hist))
        assert len(rows) == 1
        assert rows[0]["score"] == LIVE_INJECTION_CAP == 49
        assert rows[0]["grade"] == "F"

    # ── --judged-bundle now genuinely affects --trend/--monitor (flag-coherence) ──

    def test_judged_bundle_no_longer_flagged_as_no_effect_for_trend(self, tmp_path, capsys):
        bundle = self._seeded_bundle(tmp_path)
        main(["--home", SAFE, "--no-native", "--full", "--trend",
              "--judged-bundle", bundle, "--history", str(tmp_path / "h.jsonl")])
        assert "--judged-bundle" not in capsys.readouterr().err

    def test_judged_bundle_no_longer_flagged_as_no_effect_for_monitor(self, tmp_path, capsys):
        bundle = self._seeded_bundle(tmp_path)
        main(["--home", SAFE, "--no-native", "--full", "--monitor",
              "--judged-bundle", bundle, "--state", str(tmp_path / "s.json"),
              "--events", str(tmp_path / "e.jsonl"), "--history", str(tmp_path / "h.jsonl")])
        assert "--judged-bundle" not in capsys.readouterr().err

    def test_full_itself_still_flagged_as_no_effect_for_trend(self, tmp_path, capsys):
        # --full itself genuinely still has no effect on --trend (no deep phase ever
        # runs there) -- only --judged-bundle's liveTest bucket does now. The note
        # fix above must not over-silence this still-true note.
        main(["--home", SAFE, "--no-native", "--full", "--trend",
              "--history", str(tmp_path / "h.jsonl")])
        assert "--full has no effect with --trend" in capsys.readouterr().err

    def test_full_itself_still_flagged_as_no_effect_for_monitor(self, tmp_path, capsys):
        main(["--home", SAFE, "--no-native", "--full", "--monitor",
              "--state", str(tmp_path / "s.json"), "--events", str(tmp_path / "e.jsonl"),
              "--history", str(tmp_path / "h.jsonl")])
        assert "--full has no effect with --monitor" in capsys.readouterr().err

    # ── unseeded exclusion (docs' OTHER promise) also reaches --trend/--monitor ──

    def test_unseeded_verdict_caps_trend_display_but_is_not_recorded(self, tmp_path, capsys):
        bundle = self._unseeded_bundle(tmp_path)
        hist = tmp_path / "history.jsonl"
        rc = main(["--home", SAFE, "--no-native", "--full", "--trend", "--ascii",
                   "--judged-bundle", bundle, "--history", str(hist)])
        assert rc == 0
        out = capsys.readouterr().out
        # This run's OWN score is still capped (shown via the percentile line and by
        # there being no history row to plot at all) -- it just must never be recorded.
        assert "No history yet" in out
        assert not hist.exists()

    def test_unseeded_verdict_caps_monitor_display_but_is_not_persisted(self, tmp_path, capsys):
        bundle = self._unseeded_bundle(tmp_path)
        state = tmp_path / "state.json"
        events = tmp_path / "events.jsonl"
        hist = tmp_path / "history.jsonl"
        rc = main(["--home", SAFE, "--no-native", "--full", "--monitor", "--ascii",
                   "--judged-bundle", bundle, "--state", str(state),
                   "--events", str(events), "--history", str(hist)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Current: 49/100  Grade: F" in out
        assert "Baseline saved." not in out
        assert not state.exists()
        assert not hist.exists()

    def test_resistant_verdict_still_shows_and_records_uncapped_for_trend_monitor(
        self, tmp_path, capsys
    ):
        # RESISTANT never hits (self-attestation guard) -- both modes must stay
        # byte-identical to submitting nothing at all, exactly like the default path.
        # --no-sockets: see test_home_safe_baseline_is_uncapped_98_a's comment -- the
        # uncapped score is only deterministic with real-host socket scanning disabled.
        bundle = _bundle_file(tmp_path, {"liveTest": {"seed": "s1", "verdicts": [
            {"tool": "canary", "id": "canary", "verdict": "RESISTANT"}]}})
        hist = tmp_path / "history.jsonl"
        rc = main(["--home", SAFE, "--no-native", "--full", "--trend", "--ascii",
                   "--judged-bundle", bundle, "--history", str(hist), "--no-sockets"])
        assert rc == 0
        rows = history_load(str(hist))
        assert len(rows) == 1
        assert rows[0]["score"] == 98
        assert rows[0]["grade"] == "A"
