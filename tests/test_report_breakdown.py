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
        out = render_report(findings, score, lang="en")
        assert "Why" in out
        assert "/100" in out

    def test_n_scored_is_seven_not_nine(self):
        """UNKNOWN (T8) and advisory/scored=False (T9) must be excluded."""
        findings = _mixed_findings()
        score = compute(findings)
        out = render_report(findings, score, lang="en")
        # 7 scored + non-UNKNOWN entries: T1..T7
        assert "7 scored checks" in out

    def test_n_pass_count_is_three(self):
        findings = _mixed_findings()
        score = compute(findings)
        out = render_report(findings, score, lang="en")
        assert "3 pass" in out

    def test_n_warn_count_is_two(self):
        findings = _mixed_findings()
        score = compute(findings)
        out = render_report(findings, score, lang="en")
        assert "2 warn" in out

    def test_n_fail_count_is_two(self):
        findings = _mixed_findings()
        score = compute(findings)
        out = render_report(findings, score, lang="en")
        assert "2 fail" in out

    def test_breakdown_detail_line_appears_when_fails_or_warns_exist(self):
        findings = _mixed_findings()
        score = compute(findings)
        out = render_report(findings, score, lang="en")
        # The detail line lists severity counts of FAIL+WARN items
        assert "FAIL" in out or "WARN" in out

    def test_no_detail_line_when_all_pass(self):
        """When there are only PASSes the detail severity line should be absent."""
        findings = [
            _finding("P1", PASS, HIGH),
            _finding("P2", PASS, MEDIUM),
        ]
        score = compute(findings)
        out = render_report(findings, score, lang="en")
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
        out = render_report(findings, score, lang="en")
        assert "1 CRITICAL" in out
        assert "2 HIGH" in out

    def test_unknown_findings_not_counted_in_breakdown(self):
        """An all-UNKNOWN set must still produce a breakdown with 0 scored."""
        findings = [_finding("U1", UNKNOWN, HIGH)]
        score = _score(score=0, grade="F", capped=False, raw_score=0)
        out = render_report(findings, score, lang="en")
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
        out = render_report(findings, score, lang="en")
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
        out = render_report(findings, score, lang="en")
        assert "capped" in out.lower()
        assert "CRITICAL" in out

    def test_cap_line_appears_when_high_fail_present(self):
        # 1 HIGH FAIL + 8 MEDIUM PASS -> raw=80, capped to 79
        findings = [_finding("H1", FAIL, HIGH)] + [
            _finding(f"P{i}", PASS, MEDIUM) for i in range(1, 9)
        ]
        score = compute(findings)
        assert score.capped, "fixture must produce a capped score"
        out = render_report(findings, score, lang="en")
        assert "capped" in out.lower()
        assert "HIGH" in out

    def test_cap_line_absent_when_no_critical_or_high_fail(self):
        findings = [
            _finding("P1", PASS, HIGH),
            _finding("W1", WARN, MEDIUM),
        ]
        score = compute(findings)
        assert not score.capped, "fixture must not produce a capped score"
        out = render_report(findings, score, lang="en")
        # The capped line uses the literal "(capped from"
        assert "(capped from" not in out


# ---------------------------------------------------------------------------
# #2 — Scope-clarity line
# ---------------------------------------------------------------------------

class TestScopeNote:
    def test_scope_note_appears_in_report(self):
        findings = _mixed_findings()
        score = compute(findings)
        out = render_report(findings, score, lang="en")
        assert "This score reflects your configuration" in out

    def test_scope_note_mentions_canary(self):
        findings = _mixed_findings()
        score = compute(findings)
        out = render_report(findings, score, lang="en")
        assert "--canary" in out

    def test_scope_note_mentions_vet_mcp(self):
        findings = _mixed_findings()
        score = compute(findings)
        out = render_report(findings, score, lang="en")
        assert "--vet-mcp" in out

    def test_scope_note_appears_on_clean_report(self):
        """The scope note must appear even when there are no issues."""
        score = _score(score=100, grade="A", capped=False, raw_score=100)
        out = render_report([], score, lang="en")
        assert "--canary" in out
        assert "--vet-mcp" in out

    def test_scope_note_appears_exactly_once(self):
        """The scope note must not be repeated."""
        findings = _mixed_findings()
        score = compute(findings)
        out = render_report(findings, score, lang="en")
        assert out.count("--vet-mcp") == 1


# ---------------------------------------------------------------------------
# Hebrew (lang="he") path — no KeyError / missing-string crash
# ---------------------------------------------------------------------------

class TestHebrewPath:
    def test_he_render_does_not_raise(self):
        findings = _mixed_findings()
        score = compute(findings)
        out = render_report(findings, score, lang="he")
        assert out  # non-empty

    def test_he_breakdown_present(self):
        """Hebrew report must contain the breakdown (no missing-key crash)."""
        findings = _mixed_findings()
        score = compute(findings)
        out = render_report(findings, score, lang="he")
        # Hebrew score breakdown starts with "מדוע"
        assert "מדוע" in out

    def test_he_scope_note_present(self):
        findings = _mixed_findings()
        score = compute(findings)
        out = render_report(findings, score, lang="he")
        out = out.replace("‏", "").replace("⁦", "").replace("⁩", "")  # drop RTL marks
        # Both flag names are literal ASCII in Hebrew text too
        assert "--canary" in out
        assert "--vet-mcp" in out

    def test_he_capped_report_does_not_raise(self):
        findings = [
            _finding("C1", FAIL, CRITICAL),
            _finding("P1", PASS, HIGH),
        ]
        score = compute(findings)
        out = render_report(findings, score, lang="he")
        assert out

    def test_he_breakdown_detail_present_when_fails_exist(self):
        findings = [
            _finding("F1", FAIL, HIGH),
            _finding("P1", PASS, MEDIUM),
        ]
        score = compute(findings)
        out = render_report(findings, score, lang="he")
        # Hebrew detail line contains "נכשלות" (failures)
        assert "נכשלות" in out
