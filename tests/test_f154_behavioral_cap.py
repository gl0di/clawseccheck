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

Also covers the two C-135 round-2 review findings and their fixes (TestFinding1GroupChannel
Corroboration, TestFinding2B191SubSignalSplit, plus their CLI end-to-end counterparts in
TestCliEndToEnd):
  - Finding 1 (HIGH): T1's group/channel ingress leg armed on origin kind alone, with no
    way to tell an owner-only private bot group apart from a genuinely stranger-exposed
    one. Fixed by requiring the channel's own config groupPolicy to be non-owner-reachable.
  - Finding 2 (MEDIUM): B191 folded three sub-signals into one WARN, so grade_cap_signal
    could not avoid capping on bare "divergence" alone — near-certain-benign background
    noise per the check's own docstring. Fixed via Finding.sub_signals.

Offline, deterministic, no network. Uses the shipped fixtures only.
"""
from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path

from clawseccheck.behavioral import (
    BEHAVIORAL_CHECK_IDS,
    analyze,
    check_behavioral_trifecta,
    grade_cap_signal,
    group_events_by_thread,
)
from clawseccheck.catalog import CRITICAL, FAIL, LOW, MEDIUM, PASS, UNKNOWN, WARN, Finding
from clawseccheck.cli import main
from clawseccheck.collector import Context, collect
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


# ── F-154 round 2 (C-135 review, both findings) ──────────────────────────────
#
# Finding 1 (HIGH): T1's group/channel ingress leg armed unconditionally on origin
# kind alone, with no way to tell an owner-only private bot group apart from a
# genuinely stranger-exposed one — the exact ambiguity already reasoned through for
# direct/DM origin, never extended to group/channel. Fixed in behavioral.py by
# requiring the channel's OWN config groupPolicy to be non-owner-reachable
# (`_group_untrusted_origin_channels`) before a group/channel-origin message arms.
#
# Finding 2 (MEDIUM, very common): B191 folded three sub-signals into one WARN, so
# grade_cap_signal could not tell "only bare divergence fired" (near-certain-benign
# per the check's own docstring) apart from a genuinely strong signal (blocked/
# evasive), permanently ceilinging any long-lived, healthy install at B. Fixed via
# `Finding.sub_signals` + `_B191_STRONG_SUB_SIGNALS` in behavioral.grade_cap_signal.
# ---------------------------------------------------------------------------------


def _owner_only_group_repro() -> dict:
    """The EXACT C-135 repro (reviewer's comment on this task): an owner-only private
    bot group — prompt.submitted origin=group, then a sensitive-hint tool call, then a
    bash/exec call, single thread. An everyday devops/coding-agent turn, not an
    externally-exposed surface."""
    return group_events_by_thread([
        {"type": "prompt.submitted", "name": None, "seq": 1, "ts": "1",
         "sessionId": "s1", "threadId": "th1", "origin": "group",
         "originChannel": "telegram"},
        {"type": "tool.call", "name": "check_vault_credential_status", "seq": 2, "ts": "2",
         "sessionId": "s1", "threadId": "th1", "origin": "group", "originChannel": "telegram"},
        {"type": "tool.call", "name": "bash", "seq": 3, "ts": "3",
         "sessionId": "s1", "threadId": "th1", "origin": "group", "originChannel": "telegram"},
    ])


class TestFinding1GroupChannelCorroboration:
    """Finding 1's own repro, at the check/grade_cap_signal layer (no CLI needed —
    the CLI end-to-end equivalents live in TestCliEndToEnd below)."""

    def test_owner_only_group_repro_does_not_arm_t1(self):
        groups = _owner_only_group_repro()
        f = check_behavioral_trifecta(groups)  # no channel-policy evidence supplied
        assert f.status == PASS

    def test_owner_only_group_repro_does_not_reach_grade_cap_signal(self):
        groups = _owner_only_group_repro()
        result = {"findings": [check_behavioral_trifecta(groups)]}
        assert grade_cap_signal(result) == frozenset()

    def test_owner_only_group_repro_end_to_end_via_analyze(self, tmp_path):
        """Same repro through the real `analyze()` entry point — `ctx.config` carries
        NO untrusted groupPolicy for 'telegram' (the common, unconfigured/owner-only
        shape), so T1 must stay PASS and cap-eligible fired set stays empty."""
        home = tmp_path / "openclaw"
        d = home / "agents" / "main" / "sessions"
        d.mkdir(parents=True)
        rec_lines = [
            json.dumps({
                "traceSchema": "openclaw-trajectory", "schemaVersion": 1,
                "type": "prompt.submitted", "ts": "1", "seq": 1, "sessionId": "s1",
                "sessionKey": "agent:main:telegram:group:555000111",
                "data": {"threadId": "th1", "turnId": "th1"},
            }),
            json.dumps({
                "traceSchema": "openclaw-trajectory", "schemaVersion": 1,
                "type": "tool.call", "ts": "2", "seq": 2, "sessionId": "s1",
                "sessionKey": "agent:main:telegram:group:555000111",
                "data": {"name": "check_vault_credential_status", "threadId": "th1", "turnId": "th1"},
            }),
            json.dumps({
                "traceSchema": "openclaw-trajectory", "schemaVersion": 1,
                "type": "tool.call", "ts": "3", "seq": 3, "sessionId": "s1",
                "sessionKey": "agent:main:telegram:group:555000111",
                "data": {"name": "bash", "threadId": "th1", "turnId": "th1"},
            }),
        ]
        (d / "s.trajectory.jsonl").write_text("\n".join(rec_lines) + "\n", encoding="utf-8")
        # No channels config at all -- the common unconfigured/owner-only shape.
        ctx = Context(home=home, config={})
        result = analyze(ctx)
        t1 = next(f for f in result["findings"] if f.id == "T1")
        assert t1.status == PASS
        assert grade_cap_signal(result) == frozenset()

    def test_genuinely_open_group_repro_still_arms_t1_and_reaches_grade_cap_signal(self):
        """The counterpart the task's own test plan asks for: with an available
        discriminator showing this channel's group surface IS non-owner-reachable
        (groupPolicy='open'), the identical sequence must still fire -- T1's real
        detection target (a genuinely stranger-exposed group) is preserved."""
        groups = _owner_only_group_repro()
        f = check_behavioral_trifecta(groups, untrusted_origin_channels=frozenset({"telegram"}))
        assert f.status == WARN
        result = {"findings": [f]}
        assert grade_cap_signal(result) == frozenset({"T1"})


class TestFinding2B191SubSignalSplit:
    """Finding 2's own repro: a host whose audit_events shows ONLY the divergence
    sub-signal must not cap; one where a strong sub-signal (blocked/evasive) fires
    still must."""

    @staticmethod
    def _ctx_with_audit_events(tmp_path, rows) -> Context:
        ctx = Context(home=tmp_path / "openclaw")
        ctx.audit_events_found = True
        ctx.audit_events = rows
        ctx.audit_events_total_rows = len(rows)
        return ctx

    def test_bare_divergence_only_warns_but_does_not_reach_grade_cap_signal(self, tmp_path):
        """audit_events has a session with NO matching trajectory record (divergence),
        and NO blocked/evasive row at all -- the check's own docstring calls this
        expected, near-certain-benign background noise (a rotated trajectory cap, or
        tracing turned off on purpose). Must WARN (still reported) but must NOT cap."""
        ctx = self._ctx_with_audit_events(
            tmp_path, [{"status": "succeeded", "tool_name": "bash", "session_id": "sess-old"}]
        )
        result = analyze(ctx)  # no trajectory sidecar at all -> every audit session "diverges"
        b191 = next(f for f in result["findings"] if f.id == "B191")
        assert b191.status == WARN
        assert b191.sub_signals == frozenset({"divergence"})
        assert grade_cap_signal(result) == frozenset()

    def test_strong_subsignal_blocked_still_reaches_grade_cap_signal(self, tmp_path):
        """A genuine runtime policy denial (blocked/tool_blocked) alongside the SAME
        divergence -- the strong sub-signal must still cap, even mixed with the weak
        one."""
        ctx = self._ctx_with_audit_events(tmp_path, [
            {"status": "blocked", "error_code": "tool_blocked", "tool_name": "bash",
             "session_id": "sess-old"},
        ])
        result = analyze(ctx)
        b191 = next(f for f in result["findings"] if f.id == "B191")
        assert b191.status == WARN
        assert "blocked" in b191.sub_signals
        assert grade_cap_signal(result) == frozenset({"B191"})

    def test_strong_subsignal_evasive_still_reaches_grade_cap_signal(self, tmp_path):
        ctx = self._ctx_with_audit_events(
            tmp_path, [{"status": "succeeded", "tool_name": "unknown", "session_id": "sess-old"}]
        )
        result = analyze(ctx)
        b191 = next(f for f in result["findings"] if f.id == "B191")
        assert b191.status == WARN
        assert "evasive" in b191.sub_signals
        assert grade_cap_signal(result) == frozenset({"B191"})


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

    # ── F-154 round 2 (C-135 review) — Finding 1, real CLI end-to-end repro ──────

    def _home_with_group_policy(self, tmp_path, group_policy) -> Path:
        """`home_safe` with `channels.telegram.groupPolicy` overridden and the EXACT
        C-135 repro trajectory (owner-only-shaped group chat: prompt.submitted
        origin=group, a sensitive-hint call, a bash/exec call) added. Everything else
        (gateway/tools/agents/plugins/logging/models) stays home_safe's, so only the
        one variable under test — this channel's group-facing policy — changes."""
        home = tmp_path / "home"
        shutil.copytree(SAFE, home)
        cfg_path = home / "openclaw.json"
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        cfg["channels"]["telegram"]["groupPolicy"] = group_policy
        cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
        d = home / "agents" / "main" / "sessions"
        d.mkdir(parents=True, exist_ok=True)
        rec_lines = [
            json.dumps({
                "traceSchema": "openclaw-trajectory", "schemaVersion": 1,
                "type": "prompt.submitted", "ts": "1", "seq": 1, "sessionId": "s1",
                "sessionKey": "agent:main:telegram:group:555000111",
                "data": {"threadId": "th1", "turnId": "th1"},
            }),
            json.dumps({
                "traceSchema": "openclaw-trajectory", "schemaVersion": 1,
                "type": "tool.call", "ts": "2", "seq": 2, "sessionId": "s1",
                "sessionKey": "agent:main:telegram:group:555000111",
                "data": {"name": "check_vault_credential_status", "threadId": "th1", "turnId": "th1"},
            }),
            json.dumps({
                "traceSchema": "openclaw-trajectory", "schemaVersion": 1,
                "type": "tool.call", "ts": "3", "seq": 3, "sessionId": "s1",
                "sessionKey": "agent:main:telegram:group:555000111",
                "data": {"name": "bash", "threadId": "th1", "turnId": "th1"},
            }),
        ]
        (d / "s.trajectory.jsonl").write_text("\n".join(rec_lines) + "\n", encoding="utf-8")
        return home

    def test_owner_only_group_chat_repro_full_does_not_cap(self, tmp_path, capsys):
        """THE C-135 FINDING 1 REPRO, re-run after the fix: an owner-only private bot
        group ('groupPolicy' left at a non-owner-UNreachable value, 'owner') firing the
        exact sequence the reviewer used (prompt.submitted origin=group -> a
        vault/credential-hinted call -> bash) must no longer cap --full's grade."""
        home = self._home_with_group_policy(tmp_path, "owner")
        main(["--home", str(home)] + BASE + ["--json"])
        plain = json.loads(capsys.readouterr().out)
        main(["--home", str(home)] + BASE + ["--full", "--json"])
        full = json.loads(capsys.readouterr().out)
        assert full["behavioral_capped"] is False
        assert full["behavioral_cap_reason"] is None
        assert full["score"] == plain["score"]

    def test_genuinely_open_group_chat_repro_full_still_caps(self, tmp_path, capsys):
        """Counterpart: the SAME sequence, but this channel's group surface really is
        non-owner-reachable ('groupPolicy'='allowlist' -- home_safe's own unmodified
        value, deliberately NOT 'open': that value alone trips an unrelated CRITICAL
        finding (B2, "anyone can command"), which would cap the grade tighter than
        BEHAVIORAL_SIGNAL_CAP for a reason unrelated to this fix and mask what this
        test means to prove) — T1's actual detection target must still fire and cap."""
        home = self._home_with_group_policy(tmp_path, "allowlist")
        main(["--home", str(home)] + BASE + ["--json"])
        plain = json.loads(capsys.readouterr().out)
        main(["--home", str(home)] + BASE + ["--full", "--json"])
        full = json.loads(capsys.readouterr().out)
        assert full["behavioral_capped"] is True
        assert full["behavioral_cap_reason"] == "T1 behavioral trifecta"
        assert full["score"] <= BEHAVIORAL_SIGNAL_CAP
        assert full["score"] < plain["score"]

    # ── F-154 round 2 (C-135 review) — Finding 2, real CLI end-to-end repro ──────

    _AUDIT_EVENTS_DDL = (
        "CREATE TABLE audit_events ("
        "sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE, "
        "source_id TEXT NOT NULL UNIQUE, source_sequence INTEGER NOT NULL, "
        "occurred_at INTEGER NOT NULL, kind TEXT NOT NULL, action TEXT NOT NULL, "
        "status TEXT NOT NULL, error_code TEXT, actor_type TEXT NOT NULL, "
        "actor_id TEXT NOT NULL, agent_id TEXT NOT NULL, session_key TEXT, session_id TEXT, "
        "run_id TEXT NOT NULL, tool_call_id TEXT, tool_name TEXT)"
    )

    def _home_with_audit_events(self, tmp_path, rows) -> Path:
        """`home_safe` (no trajectory sidecar — so EVERY audit_events session_id
        "diverges" by construction) plus a real state DB carrying *rows*. Reproduces
        the C-135 Finding 2 scenario: 'home_safe drops from 98/A to 89/B under --full'
        on bare divergence alone."""
        home = tmp_path / "home"
        shutil.copytree(SAFE, home)
        state = home / "state"
        state.mkdir(exist_ok=True)
        conn = sqlite3.connect(state / "openclaw.sqlite")
        try:
            conn.execute(self._AUDIT_EVENTS_DDL)
            for i, row in enumerate(rows):
                conn.execute(
                    "INSERT INTO audit_events (event_id, source_id, source_sequence, "
                    "occurred_at, kind, action, status, error_code, actor_type, actor_id, "
                    "agent_id, session_key, session_id, run_id, tool_call_id, tool_name) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        f"ev-{i}", f"src-{i}", i, 1_700_000_000_000 + i,
                        "tool_action", "tool.action.finished",
                        row.get("status", "succeeded"), row.get("error_code"),
                        "agent", "main", "main", f"key-{row.get('session_id', 's1')}",
                        row.get("session_id", "s1"), f"run-{i}", f"call-{i}",
                        row.get("tool_name", "bash"),
                    ),
                )
            conn.commit()
        finally:
            conn.close()
        return home

    def test_b191_bare_divergence_repro_full_does_not_cap(self, tmp_path, capsys):
        """THE C-135 FINDING 2 REPRO, re-run after the fix: no trajectory sidecar at
        all (so audit_events' one session unavoidably "diverges") and no blocked/
        evasive row — bare divergence alone must no longer drop --full's grade."""
        home = self._home_with_audit_events(tmp_path, [{"session_id": "sess-old"}])
        main(["--home", str(home)] + BASE + ["--json"])
        plain = json.loads(capsys.readouterr().out)
        main(["--home", str(home)] + BASE + ["--full", "--json"])
        full = json.loads(capsys.readouterr().out)
        assert full["behavioral_capped"] is False
        assert full["behavioral_cap_reason"] is None
        assert full["score"] == plain["score"]

    def test_b191_strong_signal_repro_full_still_caps(self, tmp_path, capsys):
        """Counterpart: a genuine runtime policy denial (blocked/tool_blocked) —
        alongside the SAME unavoidable divergence — must still cap."""
        home = self._home_with_audit_events(tmp_path, [
            {"session_id": "sess-old", "status": "blocked", "error_code": "tool_blocked"},
        ])
        main(["--home", str(home)] + BASE + ["--json"])
        plain = json.loads(capsys.readouterr().out)
        main(["--home", str(home)] + BASE + ["--full", "--json"])
        full = json.loads(capsys.readouterr().out)
        assert full["behavioral_capped"] is True
        assert full["behavioral_cap_reason"] == "B191 audit-trail divergence"
        # B191 shares T2/T3's looser MEDIUM ceiling (89), not T1's tighter HIGH one
        # (BEHAVIORAL_SIGNAL_CAP=79) — see TestBehavioralCapScoring.
        # test_t2_and_b191_share_t3s_medium_ceiling.
        assert full["score"] <= 89
        assert full["score"] < plain["score"]


# ── the exact ids, still permanently unscored (Golden Rule #5) ───────────────

def test_behavioral_check_ids_stay_scored_false_permanently():
    from clawseccheck.catalog import BY_ID

    assert set(BEHAVIORAL_CHECK_IDS) == {"T1", "T2", "T3", "B191"}
    for cid in BEHAVIORAL_CHECK_IDS:
        assert BY_ID[cid].scored is False, (cid, "must stay scored=False permanently")
