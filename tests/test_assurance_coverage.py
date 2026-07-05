"""Tests for R11 (assurance honesty): assessment_coverage() + its two report-layer
signals — C-166 (low-coverage caution line) and C-165 (hedged staleness nudge).

Both signals are human-report-only: they never touch score/grade/findings, and
they never appear in machine outputs (render_json/render_card/render_svg/SARIF —
out of scope for this file, untouched by the implementation).

All tests are offline and deterministic — no network calls, no file writes,
except the real-fixture pass which reads bundled read-only fixtures via the
real audit() pipeline (tmp_path not needed; fixtures/ is read-only input).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.catalog import CRITICAL, FAIL, HIGH, PASS, UNKNOWN, WARN, Finding
from clawseccheck.report import render_report
from clawseccheck.scoring import ScoreResult, assessment_coverage, compute

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _f(id_: str, status: str, severity: str = HIGH, scored: bool = True,
       suppressed: bool = False) -> Finding:
    return Finding(
        id=id_,
        title=f"Check {id_}",
        severity=severity,
        status=status,
        detail=f"detail for {id_}",
        fix=f"fix for {id_}",
        framework="Test",
        scored=scored,
        suppressed=suppressed,
    )


def _score(**kw) -> ScoreResult:
    defaults = dict(score=75, grade="C", capped=False, raw_score=75,
                    failed_critical=0, failed_high=0)
    defaults.update(kw)
    return ScoreResult(**defaults)


# ---------------------------------------------------------------------------
# assessment_coverage() — pure helper unit tests
# ---------------------------------------------------------------------------

class TestAssessmentCoverageHelper:
    def test_hand_built_mix_counts_and_fracs(self):
        """4 scored PASS/FAIL/WARN/UNKNOWN + 1 scored=False + 1 suppressed.

        Scored-in-scope: PASS, FAIL, WARN, UNKNOWN (4 total, 1 unknown).
        scored=False and suppressed=True must both be excluded entirely.
        """
        findings = [
            _f("P1", PASS),
            _f("F1", FAIL),
            _f("W1", WARN),
            _f("U1", UNKNOWN),
            _f("A1", PASS, scored=False),          # advisory — excluded
            _f("S1", FAIL, suppressed=True),        # suppressed — excluded
        ]
        cov = assessment_coverage(findings)
        assert cov["scored_total"] == 4
        assert cov["unknown"] == 1
        assert cov["assessable"] == 3
        assert cov["assessable"] + cov["unknown"] == cov["scored_total"]
        assert cov["assessable_frac"] == pytest.approx(0.75)
        assert cov["unknown_frac"] == pytest.approx(0.25)

    def test_empty_findings_both_fracs_zero(self):
        cov = assessment_coverage([])
        assert cov["scored_total"] == 0
        assert cov["assessable"] == 0
        assert cov["unknown"] == 0
        assert cov["assessable_frac"] == 0.0
        assert cov["unknown_frac"] == 0.0

    def test_all_unknown(self):
        findings = [_f("U1", UNKNOWN), _f("U2", UNKNOWN, severity=CRITICAL)]
        cov = assessment_coverage(findings)
        assert cov["scored_total"] == 2
        assert cov["unknown"] == 2
        assert cov["assessable"] == 0
        assert cov["assessable_frac"] == 0.0
        assert cov["unknown_frac"] == 1.0

    def test_all_assessable_no_unknown(self):
        findings = [_f("P1", PASS), _f("F1", FAIL), _f("W1", WARN)]
        cov = assessment_coverage(findings)
        assert cov["scored_total"] == 3
        assert cov["unknown"] == 0
        assert cov["assessable"] == 3
        assert cov["assessable_frac"] == 1.0
        assert cov["unknown_frac"] == 0.0

    def test_skill_archive_path_traversal_excluded_like_compute(self):
        """SKILL_ARCHIVE_PATH_TRAVERSAL is a real third status compute() excludes
        from its scored selection (same as UNKNOWN) — the helper must mirror that."""
        findings = [
            _f("P1", PASS),
            _f("B13", "SKILL_ARCHIVE_PATH_TRAVERSAL"),
        ]
        cov = assessment_coverage(findings)
        assert cov["scored_total"] == 1
        assert cov["assessable"] == 1
        assert cov["unknown"] == 0

    def test_invariant_holds_across_random_ish_mixes(self):
        """assessable + unknown == scored_total for several shapes."""
        cases = [
            [_f("A", PASS), _f("B", FAIL), _f("C", UNKNOWN)],
            [_f("A", WARN), _f("B", WARN, scored=False)],
            [_f("A", UNKNOWN, suppressed=True), _f("B", PASS)],
        ]
        for findings in cases:
            cov = assessment_coverage(findings)
            assert cov["assessable"] + cov["unknown"] == cov["scored_total"]


# ---------------------------------------------------------------------------
# C-166 — low-coverage caution line
# ---------------------------------------------------------------------------

def _findings_with_coverage(n_assessable: int, n_unknown: int) -> list[Finding]:
    findings = [_f(f"P{i}", PASS) for i in range(n_assessable)]
    findings += [_f(f"U{i}", UNKNOWN) for i in range(n_unknown)]
    return findings


class TestLowCoverageLine:
    def test_clean_high_coverage_no_low_coverage_line(self):
        """assessable_frac >= 0.35 -> no 'Low coverage' line."""
        findings = _findings_with_coverage(n_assessable=7, n_unknown=3)  # 0.70
        score = compute(findings)
        out = render_report(findings, score)
        assert "Low coverage" not in out

    def test_bad_low_coverage_line_appears_with_counts(self):
        """assessable_frac ~0.18 -> 'Low coverage' line with X/Y count."""
        findings = _findings_with_coverage(n_assessable=4, n_unknown=18)  # 4/22 ~ 0.182
        score = compute(findings)
        assert score.assessable  # has real scored findings, not N/A
        out = render_report(findings, score)
        assert "Low coverage" in out
        assert "4/22" in out

    def test_low_coverage_line_absent_on_na_path(self):
        """When nothing is scorable at all (score.assessable is False), the C-166
        line must not double-warn on top of the N/A path."""
        findings = [_f("U1", UNKNOWN), _f("U2", UNKNOWN)]
        score = compute(findings)
        assert score.assessable is False
        out = render_report(findings, score)
        assert "Low coverage" not in out

    def test_low_coverage_line_absent_when_no_findings_at_all(self):
        score = _score(score=100, grade="A", capped=False, raw_score=100)
        out = render_report([], score)
        assert "Low coverage" not in out


# ---------------------------------------------------------------------------
# C-165 — hedged staleness nudge
# ---------------------------------------------------------------------------

class TestStalenessNudge:
    def test_clean_moderate_unknown_frac_no_staleness_nudge(self):
        """unknown_frac 0.60 (below 0.85 threshold) -> no nudge, even with a big
        enough scored_total and openclaw_detected=True."""
        findings = _findings_with_coverage(n_assessable=8, n_unknown=12)  # 12/20 = 0.60
        score = compute(findings)
        out = render_report(findings, score, openclaw_detected=True)
        assert "may be stale" not in out

    def test_bad_high_unknown_frac_enough_scored_detected_shows_nudge(self):
        """unknown_frac 0.90, scored_total >= 20, openclaw_detected=True -> nudge
        fires, and the honest hedge ('Either... or...') must be present."""
        findings = _findings_with_coverage(n_assessable=2, n_unknown=18)  # 18/20 = 0.90
        score = compute(findings)
        out = render_report(findings, score, openclaw_detected=True)
        assert "may be stale" in out
        assert "Either this is a minimal setup, or ClawSecCheck may be stale" in out
        assert "offline notice; no network call" in out

    def test_guard_scored_total_below_minimum_suppresses_nudge(self):
        """unknown_frac 0.90 but scored_total < 20 -> no nudge (DRIFT_MIN_SCORED guard)."""
        findings = _findings_with_coverage(n_assessable=1, n_unknown=9)  # 9/10 = 0.90, total=10
        score = compute(findings)
        out = render_report(findings, score, openclaw_detected=True)
        assert "may be stale" not in out

    def test_guard_openclaw_not_detected_suppresses_nudge(self):
        """Even with a qualifying unknown_frac + scored_total, no OpenClaw config
        detected must suppress the nudge (the signal is meaningless without a
        detected setup to be stale against)."""
        findings = _findings_with_coverage(n_assessable=2, n_unknown=18)
        score = compute(findings)
        out = render_report(findings, score, openclaw_detected=False)
        assert "may be stale" not in out

    def test_staleness_nudge_absent_on_na_path(self):
        findings = [_f("U1", UNKNOWN), _f("U2", UNKNOWN)]
        score = compute(findings)
        assert score.assessable is False
        out = render_report(findings, score, openclaw_detected=True)
        assert "may be stale" not in out

    def test_staleness_nudge_absent_when_no_findings_at_all(self):
        score = _score(score=100, grade="A", capped=False, raw_score=100)
        out = render_report([], score, openclaw_detected=True)
        assert "may be stale" not in out


# ---------------------------------------------------------------------------
# Zero-false-positive on real configs (decisive gate — CLAUDE.md Golden Rule #5)
# ---------------------------------------------------------------------------

def _thin_and_representative_fixtures():
    """The thinnest available real fixtures plus the canonical home_safe/home_vuln
    pair — exactly the set flagged by the orchestrator as most likely to trip
    either new signal, since they carry the lowest assessable_frac in the corpus."""
    names = ["home_safe", "home_vuln", "clean_b13_doc_example", "clean_b103_brew"]
    homes = []
    for name in names:
        p = FIXTURES / name
        if p.is_dir():
            homes.append(p)
    return homes


REAL_HOMES = _thin_and_representative_fixtures()


def test_real_fixture_corpus_is_non_empty():
    assert REAL_HOMES, "expected home_safe/home_vuln/clean_b13_doc_example/clean_b103_brew"


@pytest.mark.parametrize("home", REAL_HOMES, ids=lambda p: p.name)
def test_no_false_positive_signal_on_real_config(home):
    """Neither C-166 ('Low coverage') nor C-165 ('may be stale') may fire on any
    real bundled fixture. If one does, the threshold is wrong — STOP, do not
    loosen this test (per the orchestrator's explicit instruction)."""
    ctx, findings, score = audit(home)
    out = render_report(findings, score, openclaw_detected=ctx.config_found)
    assert "Low coverage" not in out, (
        f"§5 violation: {home.name!r} tripped the C-166 low-coverage line — "
        "the LOW_COVERAGE_FRAC threshold may be wrong; do not loosen this test."
    )
    assert "may be stale" not in out, (
        f"§5 violation: {home.name!r} tripped the C-165 staleness nudge — "
        "the DRIFT_UNKNOWN_FRAC/DRIFT_MIN_SCORED thresholds may be wrong; "
        "do not loosen this test."
    )
