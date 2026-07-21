"""Tests for the 'Why this score' breakdown and scope-clarity line in render_report.

All tests are offline and deterministic — no network calls, no file writes.
"""
from __future__ import annotations

from clawseccheck.catalog import CRITICAL, FAIL, HIGH, LOW, MEDIUM, PASS, UNKNOWN, WARN, Finding
from clawseccheck.report import render_report
from clawseccheck.scoring import ScoreResult, compute


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _score(**kw) -> ScoreResult:
    """Build a ScoreResult with sensible defaults overridden by **kw."""
    defaults = dict(score=75, grade="C", capped=False, raw_score=75,
                    failed_critical=0, failed_high=0)
    defaults.update(kw)
    return ScoreResult(**defaults)


def _finding(id_: str, status: str, severity: str = HIGH,
             scored: bool = True) -> Finding:
    return Finding(
        id=id_,
        title=f"Check {id_}",
        severity=severity,
        status=status,
        detail=f"detail for {id_}",
        fix=f"fix for {id_}",
        framework="Test",
        scored=scored,
    )


def _mixed_findings() -> list[Finding]:
    """Return a deterministic mixed set: 3 PASS, 2 WARN, 2 FAIL, 1 UNKNOWN, 1 advisory."""
    return [
        _finding("T1", PASS, HIGH),
        _finding("T2", PASS, MEDIUM),
        _finding("T3", PASS, LOW),
        _finding("T4", WARN, MEDIUM),
        _finding("T5", WARN, LOW),
        _finding("T6", FAIL, HIGH),
        _finding("T7", FAIL, MEDIUM),
        _finding("T8", UNKNOWN, HIGH),          # excluded from breakdown
        _finding("T9", PASS, LOW, scored=False), # advisory/unscored — excluded
    ]


# ---------------------------------------------------------------------------
# #1 — Breakdown counts appear and are correct
# ---------------------------------------------------------------------------

class TestBreakdownCounts:
    def test_breakdown_line_appears_in_report(self):
        findings = _mixed_findings()
        score = compute(findings)
        out = render_report(findings, score)
        assert "Why" in out
        assert "/100" in out

    def test_n_scored_is_seven_not_nine(self):
        """UNKNOWN (T8) and advisory/scored=False (T9) must be excluded."""
        findings = _mixed_findings()
        score = compute(findings)
        out = render_report(findings, score)
        # 7 scored + non-UNKNOWN entries: T1..T7
        assert "7 scored checks" in out

    def test_n_pass_count_is_three(self):
        findings = _mixed_findings()
        score = compute(findings)
        out = render_report(findings, score)
        assert "3 pass" in out

    def test_n_warn_count_is_two(self):
        findings = _mixed_findings()
        score = compute(findings)
        out = render_report(findings, score)
        assert "2 warn" in out

    def test_n_fail_count_is_two(self):
        findings = _mixed_findings()
        score = compute(findings)
        out = render_report(findings, score)
        assert "2 fail" in out

    def test_breakdown_detail_line_appears_when_fails_or_warns_exist(self):
        findings = _mixed_findings()
        score = compute(findings)
        out = render_report(findings, score)
        # The detail line lists severity counts of FAIL+WARN items
        assert "FAIL" in out or "WARN" in out

    def test_no_detail_line_when_all_pass(self):
        """When there are only PASSes the detail severity line should be absent."""
        findings = [
            _finding("P1", PASS, HIGH),
            _finding("P2", PASS, MEDIUM),
        ]
        score = compute(findings)
        out = render_report(findings, score)
        # No "(N FAIL, N WARN — incl. ...)" parenthetical line
        assert "incl." not in out

    def test_severity_counts_in_detail_line(self):
        """The detail line must name the severities that contributed FAIL/WARN."""
        findings = [
            _finding("F1", FAIL, CRITICAL),
            _finding("F2", FAIL, HIGH),
            _finding("W1", WARN, HIGH),
            _finding("P1", PASS, MEDIUM),
        ]
        score = compute(findings)
        out = render_report(findings, score)
        assert "1 CRITICAL" in out
        assert "2 HIGH" in out

    def test_unknown_findings_not_counted_in_breakdown(self):
        """An all-UNKNOWN set must still produce a breakdown with 0 scored."""
        findings = [_finding("U1", UNKNOWN, HIGH)]
        score = _score(score=0, grade="F", capped=False, raw_score=0)
        out = render_report(findings, score)
        assert "0 scored checks" in out

    def test_suppressed_findings_excluded_from_breakdown(self):
        """Suppressed findings must not appear in n_pass/n_warn/n_fail."""
        f_supp = Finding(
            id="S1", title="Suppressed", severity=HIGH, status=FAIL,
            detail="d", fix="f", framework="Test", suppressed=True,
        )
        f_pass = _finding("P1", PASS, MEDIUM)
        findings = [f_supp, f_pass]
        score = _score(score=100, grade="A", capped=False, raw_score=100)
        out = render_report(findings, score)
        # Only 1 scored non-suppressed check (P1); template always uses "scored checks"
        assert "1 scored checks" in out
        assert "1 pass" in out


# ---------------------------------------------------------------------------
# #1 — Cap explanation: present for CRITICAL FAIL, absent otherwise
# ---------------------------------------------------------------------------

class TestBreakdownCapExplanation:
    def test_cap_line_appears_when_critical_fail_present(self):
        # 1 CRITICAL FAIL + 4 MEDIUM PASS -> raw=55, capped to 49
        findings = [
            _finding("C1", FAIL, CRITICAL),
            _finding("P1", PASS, MEDIUM),
            _finding("P2", PASS, MEDIUM),
            _finding("P3", PASS, MEDIUM),
            _finding("P4", PASS, MEDIUM),
        ]
        score = compute(findings)
        assert score.capped, "fixture must produce a capped score"
        out = render_report(findings, score)
        assert "capped" in out.lower()
        assert "CRITICAL" in out

    def test_cap_line_appears_when_high_fail_present(self):
        # 1 HIGH FAIL + 8 MEDIUM PASS -> raw=80, capped to 79
        findings = [_finding("H1", FAIL, HIGH)] + [
            _finding(f"P{i}", PASS, MEDIUM) for i in range(1, 9)
        ]
        score = compute(findings)
        assert score.capped, "fixture must produce a capped score"
        out = render_report(findings, score)
        assert "capped" in out.lower()
        assert "HIGH" in out

    def test_breakdown_uses_raw_score_so_arithmetic_reconciles(self):
        """B-013: when a cap fires, the 'Why X/100' line must show the RAW
        pass-rate (which matches the pass/warn/fail counts), not the capped score
        — otherwise the explained number contradicts its own arithmetic."""
        findings = [_finding(f"P{i}", PASS, HIGH) for i in range(9)]
        findings.append(_finding("C1", FAIL, CRITICAL))
        score = compute(findings)
        assert score.capped and score.raw_score != score.score
        out = render_report(findings, score)
        # The breakdown explains the RAW number...
        assert f"Why {score.raw_score}/100" in out
        # ...and the separate capped line discloses raw -> capped.
        assert f"capped from {score.raw_score}" in out
        # The headline score line still shows the capped score.
        assert f"{score.score}/100" in out

    def test_cap_line_labels_medium_when_medium_fail_caps(self):
        """B-011/B-013: a MEDIUM-only cap must label the cap as MEDIUM, not HIGH."""
        findings = [_finding("M1", FAIL, MEDIUM)] + [
            _finding(f"P{i}", PASS, LOW) for i in range(200)
        ]
        score = compute(findings)
        assert score.capped and score.cap_severity == MEDIUM
        out = render_report(findings, score)
        assert "MEDIUM" in out

    def test_cap_line_absent_when_no_critical_or_high_fail(self):
        findings = [
            _finding("P1", PASS, HIGH),
            _finding("W1", WARN, MEDIUM),
        ]
        score = compute(findings)
        assert not score.capped, "fixture must not produce a capped score"
        out = render_report(findings, score)
        # The capped line uses the literal "(capped from"
        assert "(capped from" not in out


# ---------------------------------------------------------------------------
# #2 — Scope-clarity line
# ---------------------------------------------------------------------------

class TestScopeNote:
    def test_scope_note_appears_in_report(self):
        findings = _mixed_findings()
        score = compute(findings)
        out = render_report(findings, score)
        assert "This score reflects your configuration" in out

    def test_scope_note_mentions_canary(self):
        findings = _mixed_findings()
        score = compute(findings)
        out = render_report(findings, score)
        assert "--canary" in out

    def test_scope_note_mentions_vet_mcp(self):
        findings = _mixed_findings()
        score = compute(findings)
        out = render_report(findings, score)
        assert "--vet-mcp" in out

    def test_scope_note_mentions_behavioral(self):
        """B-285/LOG-1: the scope note now also points at the two log-mining modes
        (previously recommended nowhere) that surface a trifecta already recorded in
        the user's own trajectory sidecar."""
        findings = _mixed_findings()
        score = compute(findings)
        out = render_report(findings, score)
        assert "--behavioral" in out

    def test_scope_note_mentions_analyze_trajectory(self):
        findings = _mixed_findings()
        score = compute(findings)
        out = render_report(findings, score)
        assert "--analyze-trajectory" in out

    def test_scope_note_appears_on_clean_report(self):
        """The scope note must appear even when there are no issues."""
        score = _score(score=100, grade="A", capped=False, raw_score=100)
        out = render_report([], score)
        assert "--canary" in out
        assert "--vet-mcp" in out

    def test_scope_note_appears_exactly_once(self):
        """The scope note must not be repeated."""
        findings = _mixed_findings()
        score = compute(findings)
        out = render_report(findings, score)
        assert out.count("--vet-mcp") == 1


class TestL1L2Framing:
    """F-038: a static audit bounds capability, not runtime behavior — grade A is not
    a runtime guarantee against the Lethal Trifecta."""

    def test_static_framing_line_appears(self):
        findings = _mixed_findings()
        out = render_report(findings, compute(findings))
        assert "Static audit" in out
        assert "not statically lethal-capable" in out

    def test_names_runtime_chaining_honestly(self):
        out = render_report(_mixed_findings(), compute(_mixed_findings()))
        assert "runtime" in out
        assert "Lethal Trifecta" in out  # ties the caveat to the trifecta

    def test_appears_on_a_clean_grade_a_report(self):
        # The whole point: even a perfect config must not read as "runtime-proof".
        score = _score(score=100, grade="A", capped=False, raw_score=100)
        out = render_report([], score)
        assert "Static audit" in out
        assert "runtime-proof" in out

    def test_framing_appears_exactly_once(self):
        out = render_report(_mixed_findings(), compute(_mixed_findings()))
        assert out.count("Static audit —") == 1


class TestTamperPostureLine:
    """F-081: an optional 'Tamper posture' sub-grade line, human-report only.

    Presentation-layer only — must never change the main Score/Grade line."""

    def test_main_score_line_byte_identical_with_or_without_tamper(self):
        findings = _mixed_findings()
        score = compute(findings)
        tamper = ScoreResult(score=89, grade="B", capped=True, raw_score=95,
                              failed_critical=0, failed_high=0, cap_severity="WARN")
        out_without = render_report(findings, score)
        out_with = render_report(findings, score, tamper=tamper)
        score_line = f"Score: {score.score}/100   Grade: {score.grade}"
        assert score_line in out_without
        assert score_line in out_with

    def test_tamper_posture_line_absent_when_tamper_none(self):
        findings = _mixed_findings()
        score = compute(findings)
        out = render_report(findings, score)
        assert "Tamper posture" not in out

    def test_tamper_posture_line_present_with_correct_grade(self):
        findings = _mixed_findings()
        score = compute(findings)
        tamper = ScoreResult(score=49, grade="F", capped=True, raw_score=90,
                              failed_critical=0, failed_high=1, cap_severity="B22-FAIL")
        out = render_report(findings, score, tamper=tamper)
        assert "Tamper posture: F (49/100" in out
        assert "B20/B22/B42/B78/B85/B86/C5" in out
