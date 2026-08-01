"""B-313 — a crashed/timed-out check must never raise the grade.

Reproduced empirically (v3.56.0, dev @ 6be1097): crashing the check functions that own
`fixtures/home_vuln`'s baseline FAILs moved the run from F/49 (capped=True, cap=CRITICAL)
to B/88 (capped=False, cap=None) with zero user-facing disclosure. Root cause:
`_check_error_finding`/`_check_budget_finding` (checks/__init__.py) both mark the
degraded finding `scored=False`, and `scoring.compute()`'s `f.scored` filter dropped it
from BOTH `earned` and `total` — the would-be FAIL and its severity cap both vanished.

Fix: `scoring.DEGRADED_CHECK_CAP` — a cap-only signal (never touches `earned`/`total`,
mirrors `CONFIG_BLIND_CAP`/`RUNTIME_SIGNAL_CAP`) that fires whenever any finding's `id`
starts with `"ERR:"`, capping the score at the same CRITICAL ceiling CONFIG_BLIND_CAP
uses ("cannot rule out a CRITICAL", applied at check-granularity instead of
config-granularity). Report renderers (text/HTML/JSON) disclose the degraded count
unconditionally, above the grade. `assessment_coverage` counts degraded checks as
unassessed instead of making them invisible to the one metric that measures exactly
that.

Offline, deterministic, no I/O beyond in-memory string building + the shipped fixtures.
"""
from __future__ import annotations

from pathlib import Path

import clawseccheck.checks as checks_mod
from clawseccheck.catalog import CRITICAL, FAIL, MEDIUM, UNKNOWN, Finding
from clawseccheck.collector import collect
from clawseccheck.report import render_html, render_json, render_report
from clawseccheck.scoring import DEGRADED_CHECK_CAP, ScoreResult, assessment_coverage, compute

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
VULN = FIXTURES / "home_vuln"


def _err_finding(name: str = "check_boom", severity: str = MEDIUM) -> Finding:
    return Finding(
        id=f"ERR:{name}",
        title=f"Check '{name}' could not run",
        severity=severity,
        status=UNKNOWN,
        detail="crashed",
        fix="re-run",
        framework="Engine robustness",
        scored=False,
    )


def _fail_finding(fid: str = "B1", severity: str = CRITICAL) -> Finding:
    return Finding(
        id=fid, title="t", severity=severity, status=FAIL,
        detail="d", fix="f", framework="fw", scored=True,
    )


# ── End-to-end repro, mirroring the task's own measurement ─────────────────────────────

class TestEndToEndCrashAndTimeout:
    def test_crashing_the_failing_checks_never_raises_the_grade(self, monkeypatch):
        ctx = collect(VULN)
        baseline = checks_mod.run_all(ctx)
        baseline_score = compute(baseline)
        fail_positions = [
            i for i, f in enumerate(baseline)
            if f.status == FAIL and f.scored and not getattr(f, "suppressed", False)
        ]
        assert fail_positions, "fixtures/home_vuln must have real scored FAILs to crash"

        def _boom(_ctx):
            raise KeyError("boom")

        crashing = list(checks_mod.CHECKS)
        for i in fail_positions:
            crashing[i] = _boom
        monkeypatch.setattr(checks_mod, "CHECKS", crashing)

        crashed = checks_mod.run_all(ctx)
        crashed_score = compute(crashed)

        assert crashed_score.score <= baseline_score.score
        assert crashed_score.grade == "F"
        assert crashed_score.degraded_capped is True
        assert crashed_score.degraded_count == len(fail_positions)

    def test_one_crash_plus_one_timeout_still_caps(self, monkeypatch):
        ctx = collect(VULN)
        baseline = checks_mod.run_all(ctx)
        clean_score = compute(baseline)

        def _boom(_ctx):
            raise KeyError("boom")

        from clawseccheck.scanbudget import ScanBudgetExceeded

        def _hang(_ctx):
            raise ScanBudgetExceeded("timed out")

        crashing = list(checks_mod.CHECKS)
        crashing[0] = _boom
        crashing[1] = _hang
        monkeypatch.setattr(checks_mod, "CHECKS", crashing)

        degraded = checks_mod.run_all(ctx)
        errs = [f for f in degraded if f.id.startswith("ERR:")]
        assert len(errs) == 2

        degraded_score = compute(degraded)
        assert degraded_score.score <= clean_score.score
        assert degraded_score.degraded_count == 2


# ── scoring.py unit tests (direct Finding construction) ────────────────────────────────

class TestDegradedCheckCap:
    def test_single_degraded_check_caps_an_otherwise_perfect_score(self):
        findings = [
            Finding(id="B9", title="t", severity="LOW", status="PASS",
                    detail="d", fix="f", framework="fw", scored=True),
            _err_finding(),
        ]
        result = compute(findings)
        assert result.degraded_capped is True
        assert result.degraded_count == 1
        assert result.score <= DEGRADED_CHECK_CAP
        assert result.grade in ("D", "F")

    def test_degraded_capped_false_when_a_tighter_cap_already_applied(self):
        # A genuine CRITICAL FAIL already caps at DEGRADED_CHECK_CAP's own ceiling —
        # the degraded signal is real (count > 0) but not independently *binding*.
        findings = [_fail_finding(), _err_finding()]
        result = compute(findings)
        assert result.degraded_count == 1
        assert result.score <= DEGRADED_CHECK_CAP

    def test_no_degraded_findings_leaves_cap_inert(self):
        findings = [
            Finding(id="B9", title="t", severity="LOW", status="PASS",
                    detail="d", fix="f", framework="fw", scored=True),
        ]
        result = compute(findings)
        assert result.degraded_capped is False
        assert result.degraded_count == 0
        assert result.score == 100

    def test_total_zero_with_only_a_degraded_signal_forces_f_not_na(self):
        # Mirrors B-306's own total==0 fix: a degraded check alone (nothing else scored)
        # must not fall through to the neutral "N/A" bypass.
        result = compute([_err_finding()])
        assert result.assessable is True
        assert result.grade == "F"
        assert result.degraded_capped is True
        assert result.degraded_count == 1

    def test_degraded_finding_never_earns_or_costs_an_ordinary_point(self):
        # scored=False findings must stay outside earned/total — only the cap moves.
        only_pass = compute([
            Finding(id="B9", title="t", severity="LOW", status="PASS",
                    detail="d", fix="f", framework="fw", scored=True),
        ])
        with_degraded = compute([
            Finding(id="B9", title="t", severity="LOW", status="PASS",
                    detail="d", fix="f", framework="fw", scored=True),
            _err_finding(),
        ])
        assert only_pass.raw_score == with_degraded.raw_score == 100


class TestAssessmentCoverageCountsDegraded:
    def test_degraded_finding_counts_toward_unknown(self):
        cov = assessment_coverage([
            Finding(id="B9", title="t", severity="LOW", status="PASS",
                    detail="d", fix="f", framework="fw", scored=True),
            _err_finding(),
        ])
        assert cov["scored_total"] == 2
        assert cov["unknown"] == 1
        assert cov["assessable"] == 1

    def test_pure_degraded_run_is_not_scored_total_zero(self):
        cov = assessment_coverage([_err_finding(), _err_finding("check_other")])
        assert cov["scored_total"] == 2
        assert cov["unknown"] == 2
        assert cov["assessable_frac"] == 0.0


# ── report.py rendering ──────────────────────────────────────────────────────────────

def _score(**kw) -> ScoreResult:
    defaults = dict(
        score=88, grade="B", capped=False, raw_score=88,
        failed_critical=0, failed_high=0, failed_medium=0, failed_low=0,
        assessable=True, cap_severity=None,
        runtime_capped=False, runtime_cap_reason=None,
        config_blind_capped=False, degraded_capped=False, degraded_count=0,
    )
    defaults.update(kw)
    return ScoreResult(**defaults)


class TestReportBanner:
    # B-399: the wording changed from "N checks did not run (crashed or timed out)" to
    # "N checks could not reach a reliable verdict this run (crashed, timed out, or hit
    # unreadable/corrupted input)" — deliberately, because `_degraded_signal` now ALSO
    # fires for a check that ran to completion and honestly reported its own UNKNOWN as
    # engine-side (`Finding.engine_degraded`); "did not run"/"crashed or timed out" would
    # be a factually wrong renderer message for that case (the check DID run). Same
    # signal, same cap, same "N checks"/"check(s)" count — only the prose is updated
    # here, matching a real, deliberate behavior change per this project's own testing
    # protocol (not silenced, updated with the reason recorded).
    def test_banner_present_above_the_grade_line_text(self):
        out = render_report([], _score(degraded_count=2, degraded_capped=False,
                                        score=49, grade="F", raw_score=49),
                             ascii_only=True)
        assert "2 checks could not reach a reliable verdict this run" in out
        assert out.index("could not reach a reliable verdict") < out.index("Score: 49/100")

    def test_capped_explanation_present_when_binding(self):
        out = render_report([], _score(degraded_count=1, degraded_capped=True,
                                        score=49, grade="F", raw_score=88),
                             ascii_only=True)
        assert (
            "(capped from 88 - 1 check(s) could not reach a reliable verdict this run:"
            " cannot rule out a CRITICAL condition)"
        ) in out

    def test_no_banner_when_nothing_degraded(self):
        out = render_report([], _score(), ascii_only=True)
        assert "could not reach a reliable verdict" not in out

    def test_html_shows_incomplete_banner(self):
        html = render_html([], _score(degraded_count=3))
        assert "3 checks could not reach a reliable verdict this run" in html
        assert "Incomplete" in html

    def test_json_carries_degraded_fields(self):
        import json
        payload = json.loads(
            render_json([], _score(degraded_count=1, degraded_capped=True,
                                    score=49, raw_score=88))
        )
        assert payload["degraded_count"] == 1
        assert payload["degraded_capped"] is True
