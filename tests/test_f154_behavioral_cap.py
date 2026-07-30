"""F-154 — behavioral T1/T2/T3/B191 findings reach the grade as a cap-only signal,
gated on `--behavioral`/`--full` having actually executed the analysis this run.

Reuses `RUNTIME_SIGNAL_CAP`'s SHAPE (cap-only, applied after the severity caps, never
touches earned/total) but is its OWN, dedicated tier (`BEHAVIORAL_SIGNAL_CAP`) — distinct
from both RUNTIME_SIGNAL_CAP (I-025, a corroborated trajaudit indicator match, computed
automatically from ctx alone) and LIVE_INJECTION_CAP (F-155, a self-reported live
injection-test verdict). T1/T2/T3/B191 stay `scored=False` PERMANENTLY (Golden Rule #5)
— the cap is the ONLY channel through which they can ever move the grade.

Covers, per the task's own test plan:
  - `home_safe` — no behavioral signal fires (no trajectory sidecar at all): grade
    byte-identical to today, --full or not.
  - A fixture trajectory that fires T1 — the ceiling binds, the grade drops,
    `behavioral_capped` is True.
  - A run with no trajectory sidecar present — signal absent, so no cap and no
    UNKNOWN penalty (a missing log must not become a punishment).
  - Direction assertion: a clean behavioral run can never RAISE the score.
  - Gated on actual execution: a plain (non---behavioral, non---full) invocation, and a
    `--full --fast` one, never run the analysis and therefore never cap, regardless of
    what the trajectory sidecar actually contains.

Offline, deterministic, no network. Uses the shipped fixtures only.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from clawseccheck.behavioral import BEHAVIORAL_CHECK_IDS, analyze, grade_cap_signal
from clawseccheck.catalog import CRITICAL, FAIL, LOW, MEDIUM, PASS, UNKNOWN, WARN, Finding
from clawseccheck.cli import main
from clawseccheck.collector import collect
from clawseccheck.report import render_html, render_json, render_report
from clawseccheck.scoring import BEHAVIORAL_SIGNAL_CAP, ScoreResult, _behavioral_cap_signal, compute

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE = str(FIXTURES / "home_safe")
NO_SIDECAR = str(FIXTURES / "traj_no_sidecar")
TRIFECTA = FIXTURES / "traj_behavioral_trifecta"
CLEAN_TRAJ = FIXTURES / "traj_behavioral_clean"
BASE = ["--no-native", "--no-host", "--no-sockets", "--no-history"]


def _pass_finding(fid: str = "B9", severity: str = LOW) -> Finding:
    return Finding(id=fid, title="t", severity=severity, status=PASS,
                    detail="d", fix="f", framework="fw", scored=True)


def _fail_finding(fid: str = "B1", severity: str = CRITICAL) -> Finding:
    return Finding(id=fid, title="t", severity=severity, status=FAIL,
                    detail="d", fix="f", framework="fw", scored=True)


def _combined_home(tmp_path: Path, traj_fixture: Path) -> Path:
    """A config from `home_safe` plus a trajectory sidecar copied in from
    *traj_fixture* — `traj_behavioral_trifecta`/`traj_behavioral_clean` carry no
    `openclaw.json` of their own (CONFIG_BLIND_CAP would otherwise mask the behavioral
    cap), so this builds the combination the CLI end-to-end tests need."""
    home = tmp_path / "home"
    shutil.copytree(SAFE, home)
    for p in traj_fixture.rglob("*"):
        if p.is_file():
            rel = p.relative_to(traj_fixture)
            dst = home / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(p, dst)
    return home


def _drop_elapsed(payload: dict) -> dict:
    out = dict(payload)
    if "phases" in out:
        out["phases"] = [
            {k: v for k, v in p.items() if k != "elapsed_s"} for p in out["phases"]
        ]
    return out


# ── scoring.py: compute() unit tests ─────────────────────────────────────────

class TestBehavioralCapScoring:
    def test_t1_caps_an_otherwise_perfect_score(self):
        findings = [_pass_finding()]
        clean = compute(findings)
        capped = compute(findings, behavioral_fired_ids=frozenset({"T1"}))
        assert clean.behavioral_capped is False
        assert clean.behavioral_cap_reason is None
        assert capped.behavioral_capped is True
        assert capped.behavioral_cap_reason == "T1 behavioral trifecta"
        assert capped.score <= BEHAVIORAL_SIGNAL_CAP
        assert capped.score < clean.score

    def test_t3_caps_at_the_medium_ceiling_not_t1s_high_ceiling(self):
        findings = [_pass_finding()]
        t1 = compute(findings, behavioral_fired_ids=frozenset({"T1"}))
        t3 = compute(findings, behavioral_fired_ids=frozenset({"T3"}))
        assert t3.score > t1.score, "T3 (advisory) must cap looser than T1 (proven chain)"
        assert t3.behavioral_cap_reason == "T3 capability drift"

    def test_t2_and_b191_share_t3s_medium_ceiling(self):
        findings = [_pass_finding()]
        t2 = compute(findings, behavioral_fired_ids=frozenset({"T2"}))
        t3 = compute(findings, behavioral_fired_ids=frozenset({"T3"}))
        b191 = compute(findings, behavioral_fired_ids=frozenset({"B191"}))
        assert t2.score == t3.score == b191.score

    def test_multiple_fired_detectors_tightest_wins(self):
        findings = [_pass_finding()]
        result = compute(findings, behavioral_fired_ids=frozenset({"T1", "T3"}))
        assert result.score <= BEHAVIORAL_SIGNAL_CAP
        assert "T1 behavioral trifecta" in result.behavioral_cap_reason
        assert "T3 capability drift" in result.behavioral_cap_reason

    def test_unrecognized_id_dropped_defensively(self):
        findings = [_pass_finding()]
        result = compute(findings, behavioral_fired_ids=frozenset({"NOT-A-REAL-ID"}))
        assert result.behavioral_capped is False
        assert result.behavioral_cap_reason is None

    def test_nothing_fired_byte_identical_to_default_compute(self):
        findings = [_pass_finding(), _fail_finding(fid="B2", severity=LOW)]
        assert compute(findings) == compute(findings, behavioral_fired_ids=frozenset())
        assert compute(findings) == compute(findings, ctx=None, live_test_vulnerable=False,
                                            live_test_reason=None,
                                            behavioral_fired_ids=frozenset())

    def test_behavioral_capped_false_when_tighter_cap_already_applied(self):
        # A genuine CRITICAL FAIL already caps at <=49, tighter than BEHAVIORAL_SIGNAL_CAP's
        # <=79 — the behavioral signal is real but not independently BINDING (mirrors
        # DEGRADED_CHECK_CAP/LIVE_INJECTION_CAP's own "tighter cap already applied" test).
        findings = [_fail_finding(), _pass_finding()]
        result = compute(findings, behavioral_fired_ids=frozenset({"T1"}))
        assert result.score <= 49
        assert result.behavioral_capped is False

    def test_total_zero_with_only_behavioral_signal_forces_f_not_na(self):
        result = compute([], behavioral_fired_ids=frozenset({"T1"}))
        assert result.assessable is True
        assert result.grade == "F"
        assert result.behavioral_capped is True
        assert result.behavioral_cap_reason == "T1 behavioral trifecta"

    def test_total_zero_with_nothing_at_all_stays_na(self):
        result = compute([])
        assert result.assessable is False
        assert result.grade == "N/A"
        assert result.behavioral_capped is False

    def test_never_earns_or_costs_an_ordinary_scored_point(self):
        findings = [_pass_finding()]
        clean = compute(findings)
        capped = compute(findings, behavioral_fired_ids=frozenset({"T1"}))
        assert clean.raw_score == capped.raw_score == 100

    def test_composes_with_live_injection_cap_tightest_wins(self):
        # F-154 and F-155 are DIFFERENT tiers (Dave's design) — verify they compose
        # rather than being merged/conflated: LIVE_INJECTION_CAP (<=49) is tighter than
        # BEHAVIORAL_SIGNAL_CAP's own T1 ceiling (<=79), so when both fire the live-
        # injection one binds and the behavioral one is real-but-non-binding.
        findings = [_pass_finding()]
        result = compute(findings, live_test_vulnerable=True, live_test_reason="canary:canary",
                        behavioral_fired_ids=frozenset({"T1"}))
        assert result.live_injection_capped is True
        assert result.behavioral_capped is False
        assert result.score <= 49


class TestBehavioralCapSignalHelper:
    def test_hit_false_and_default_cap_when_nothing_fired(self):
        hit, reason, cap = _behavioral_cap_signal(frozenset())
        assert hit is False and reason is None
        assert cap == BEHAVIORAL_SIGNAL_CAP

    def test_reason_is_sorted_and_stable(self):
        # Alphabetical id order ("B191" < "T1"), deterministic regardless of set
        # iteration order.
        hit, reason, cap = _behavioral_cap_signal(frozenset({"B191", "T1"}))
        assert hit is True
        assert reason == "B191 audit-trail divergence; T1 behavioral trifecta"


# ── behavioral.py: grade_cap_signal reducer ──────────────────────────────────

class TestBehavioralGradeCapSignal:
    def test_no_findings_key_returns_empty(self):
        assert grade_cap_signal({}) == frozenset()

    def test_only_warn_status_counted(self):
        findings = [
            Finding(id="T1", title="t", severity=MEDIUM, status=PASS, detail="d", fix="f",
                    framework="fw", scored=False),
            Finding(id="T3", title="t", severity=MEDIUM, status=WARN, detail="d", fix="f",
                    framework="fw", scored=False),
            Finding(id="B191", title="t", severity=MEDIUM, status=UNKNOWN, detail="d", fix="f",
                    framework="fw", scored=False),
        ]
        assert grade_cap_signal({"findings": findings}) == frozenset({"T3"})

    def test_unrelated_ids_ignored(self):
        findings = [
            Finding(id="B1", title="t", severity=CRITICAL, status=WARN, detail="d", fix="f",
                    framework="fw", scored=False),
        ]
        assert grade_cap_signal({"findings": findings}) == frozenset()

    def test_real_trifecta_fixture_fires_t1(self):
        ctx = collect(TRIFECTA)
        result = analyze(ctx)
        fired = grade_cap_signal(result)
        assert "T1" in fired

    def test_real_clean_trajectory_fires_nothing(self):
        ctx = collect(CLEAN_TRAJ)
        result = analyze(ctx)
        fired = grade_cap_signal(result)
        assert fired == frozenset()

    def test_no_sidecar_at_all_fires_nothing(self):
        ctx = collect(Path(NO_SIDECAR))
        result = analyze(ctx)
        fired = grade_cap_signal(result)
        assert fired == frozenset()


# ── report.py rendering ───────────────────────────────────────────────────────

def _score(**kw) -> ScoreResult:
    defaults = dict(
        score=79, grade="C", capped=False, raw_score=79,
        failed_critical=0, failed_high=0, failed_medium=0, failed_low=0,
        assessable=True, cap_severity=None,
        runtime_capped=False, runtime_cap_reason=None,
        config_blind_capped=False, degraded_capped=False, degraded_count=0,
        live_injection_capped=False, live_injection_cap_reason=None,
        behavioral_capped=False, behavioral_cap_reason=None,
    )
    defaults.update(kw)
    return ScoreResult(**defaults)


class TestReportRendering:
    def test_nothing_fired_no_new_text_in_text_report(self):
        out = render_report([], _score(), ascii_only=True)
        assert "Behavioral exception" not in out
        assert "behavioral detector fired (" not in out

    def test_capped_explanation_present_when_binding(self):
        out = render_report([], _score(score=79, raw_score=98, grade="C",
                                       behavioral_capped=True,
                                       behavioral_cap_reason="T1 behavioral trifecta"),
                            ascii_only=True)
        assert (
            "(capped from 98 - a behavioral detector fired (T1 behavioral trifecta))"
        ) in out
        assert "Behavioral exception (F-154): this run's grade WAS capped" in out
        assert "T1 behavioral trifecta" in out

    def test_html_no_new_text_when_not_capped(self):
        html = render_html([], _score())
        assert "behavioral detector" not in html.lower()

    def test_html_shows_cap_when_binding(self):
        html = render_html([], _score(score=79, raw_score=98, grade="C",
                                      behavioral_capped=True,
                                      behavioral_cap_reason="T3 capability drift"))
        assert "behavioral detector fired" in html
        assert "T3 capability drift" in html

    def test_json_carries_behavioral_fields_when_capped(self):
        payload = json.loads(render_json([], _score(behavioral_capped=True,
                                                     behavioral_cap_reason="T1 behavioral trifecta")))
        assert payload["behavioral_capped"] is True
        assert payload["behavioral_cap_reason"] == "T1 behavioral trifecta"

    def test_json_default_fields_absent_signal(self):
        payload = json.loads(render_json([], _score()))
        assert payload["behavioral_capped"] is False
        assert payload["behavioral_cap_reason"] is None


# ── CLI end-to-end: the task's own test plan, verified against real fixtures ──

class TestCliEndToEnd:
    def test_home_safe_full_grade_byte_identical_to_plain(self, capsys):
        """home_safe carries no trajectory sidecar — no behavioral signal fires, so
        --full's grade must be byte-identical to a plain audit (regression on the
        existing contract)."""
        main(["--home", SAFE] + BASE + ["--json"])
        plain = json.loads(capsys.readouterr().out)
        main(["--home", SAFE] + BASE + ["--full", "--json"])
        full = json.loads(capsys.readouterr().out)
        assert plain["score"] == full["score"]
        assert plain["grade"] == full["grade"]
        assert full["behavioral_capped"] is False
        assert full["behavioral_cap_reason"] is None

    def test_full_fires_t1_caps_the_grade(self, tmp_path, capsys):
        home = _combined_home(tmp_path, TRIFECTA)
        main(["--home", str(home)] + BASE + ["--json"])
        plain = json.loads(capsys.readouterr().out)
        main(["--home", str(home)] + BASE + ["--full", "--json"])
        full = json.loads(capsys.readouterr().out)
        assert full["behavioral_capped"] is True
        assert full["behavioral_cap_reason"] == "T1 behavioral trifecta"
        assert full["score"] <= BEHAVIORAL_SIGNAL_CAP
        assert full["score"] < plain["score"], "T1 must actually lower the grade under --full"

    def test_plain_audit_never_caps_even_though_t1_would_fire(self, tmp_path, capsys):
        """The cap is gated on the analysis having ACTUALLY run — a plain (non---full,
        non---behavioral) invocation never runs `behavioral.analyze`, so it must never
        cap regardless of what the trajectory sidecar contains."""
        home = _combined_home(tmp_path, TRIFECTA)
        main(["--home", str(home)] + BASE + ["--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["behavioral_capped"] is False
        assert payload["behavioral_cap_reason"] is None

    def test_full_fast_skips_the_analysis_no_cap(self, tmp_path, capsys):
        """--full --fast skips P8 (the behavioral phase) entirely — the same --fast
        skip pipeline.run_pipeline itself honors — so it must not cap either, even
        though T1 would fire on a full replay."""
        home = _combined_home(tmp_path, TRIFECTA)
        main(["--home", str(home)] + BASE + ["--full", "--fast", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["behavioral_capped"] is False

    def test_full_clean_trajectory_never_caps(self, tmp_path, capsys):
        """A trajectory sidecar IS present and IS analysed under --full, but nothing in
        it fires (T1/T2/T3 clean, B191 has no divergence) — no cap, no punishment for
        having a (clean) log at all."""
        home = _combined_home(tmp_path, CLEAN_TRAJ)
        main(["--home", str(home)] + BASE + ["--json"])
        plain = json.loads(capsys.readouterr().out)
        main(["--home", str(home)] + BASE + ["--full", "--json"])
        full = json.loads(capsys.readouterr().out)
        assert full["behavioral_capped"] is False
        assert full["score"] == plain["score"], (
            "a clean behavioral replay must never move the score, in either direction"
        )

    def test_no_trajectory_sidecar_present_no_cap_no_unknown_penalty(self, capsys):
        """No trajectory sidecar exists at all (traj_no_sidecar) — the signal is simply
        absent under --full, so there is no cap AND no UNKNOWN-style penalty: a missing
        log must not become a punishment."""
        main(["--home", NO_SIDECAR] + BASE + ["--json"])
        plain = json.loads(capsys.readouterr().out)
        main(["--home", NO_SIDECAR] + BASE + ["--full", "--json"])
        full = json.loads(capsys.readouterr().out)
        assert full["behavioral_capped"] is False
        assert full["score"] == plain["score"]

    def test_direction_a_clean_behavioral_run_can_never_raise_the_score(self, tmp_path, capsys):
        """Cap-only, both directions: --full's behavioral replay can only ever LOWER
        the score (when something fires) or leave it UNCHANGED (when nothing does) —
        never raise it above the plain grade."""
        for traj_fixture in (CLEAN_TRAJ, TRIFECTA):
            home = _combined_home(tmp_path / traj_fixture.name, traj_fixture)
            main(["--home", str(home)] + BASE + ["--json"])
            plain = json.loads(capsys.readouterr().out)
            main(["--home", str(home)] + BASE + ["--full", "--json"])
            full = json.loads(capsys.readouterr().out)
            assert full["score"] <= plain["score"], traj_fixture.name

    def test_replayed_run_produces_the_same_capped_result_each_time(self, tmp_path, capsys):
        home = _combined_home(tmp_path, TRIFECTA)
        main(["--home", str(home)] + BASE + ["--full", "--json"])
        first = json.loads(capsys.readouterr().out)
        main(["--home", str(home)] + BASE + ["--full", "--json"])
        second = json.loads(capsys.readouterr().out)
        assert _drop_elapsed(first) == _drop_elapsed(second)

    def test_report_text_names_the_behavioral_exception_when_capped(self, tmp_path, capsys):
        home = _combined_home(tmp_path, TRIFECTA)
        main(["--home", str(home)] + BASE + ["--full"])
        out = capsys.readouterr().out
        assert "Behavioral exception (F-154)" in out
        assert "T1 behavioral trifecta" in out


# ── the exact ids, still permanently unscored (Golden Rule #5) ───────────────

def test_behavioral_check_ids_stay_scored_false_permanently():
    from clawseccheck.catalog import BY_ID

    assert set(BEHAVIORAL_CHECK_IDS) == {"T1", "T2", "T3", "B191"}
    for cid in BEHAVIORAL_CHECK_IDS:
        assert BY_ID[cid].scored is False, (cid, "must stay scored=False permanently")
