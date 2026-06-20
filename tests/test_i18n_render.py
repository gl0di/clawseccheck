"""Tests for i18n integration in the render layer (Stage 2).

All tests are offline and deterministic. They use the real audit() on the
existing fixtures so no Finding objects need to be constructed by hand.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck import audit
from clawseccheck.report import render_card, render_html, render_monitor, render_prompts, render_report

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _audit_vuln():
    """Return (findings, score) for home_vuln (always has FAIL/WARN issues)."""
    _, findings, score = audit(FIXTURES / "home_vuln", include_native=False)
    return findings, score


def _audit_safe():
    """Return (findings, score) for home_safe (always clean)."""
    _, findings, score = audit(FIXTURES / "home_safe", include_native=False)
    return findings, score


# ---------------------------------------------------------------------------
# render_report
# ---------------------------------------------------------------------------

class TestRenderReportLang:
    def test_en_default_equals_explicit_en(self):
        findings, score = _audit_vuln()
        assert render_report(findings, score) == render_report(findings, score, lang="en")

    def test_en_no_lang_arg_equals_lang_en(self):
        findings, score = _audit_safe()
        assert render_report(findings, score) == render_report(findings, score, lang="en")

    def test_he_contains_hebrew_title(self):
        findings, score = _audit_vuln()
        out = render_report(findings, score, lang="he")
        # Hebrew title from STRINGS["report.title"]["he"]
        assert "ביקורת אבטחה" in out

    def test_he_contains_hebrew_score_label(self):
        findings, score = _audit_vuln()
        out = render_report(findings, score, lang="he")
        # Hebrew "Score" from STRINGS["report.score_line"]["he"] starts with "ציון"
        assert "ציון:" in out

    def test_he_contains_hebrew_to_fix(self):
        findings, score = _audit_vuln()
        out = render_report(findings, score, lang="he")
        # Hebrew "things to fix" from STRINGS["report.to_fix"]["he"]
        assert "לתיקון" in out

    def test_he_has_hebrew_check_title_for_known_finding(self):
        findings, score = _audit_vuln()
        out = render_report(findings, score, lang="he")
        out = out.replace("‏", "").replace("⁦", "").replace("⁩", "")  # drop RTL marks
        # B2 finding ("Gateway exposure") should render in Hebrew
        # TITLES["B2"]["he"] = "חשיפת ה-Gateway ואימות ערוצים"
        issues = [f for f in findings if f.status in ("FAIL", "WARN")]
        if any(f.id == "B2" for f in issues):
            assert "חשיפת ה-Gateway" in out

    def test_he_why_label_is_hebrew(self):
        findings, score = _audit_vuln()
        # At least one finding with detail should produce Hebrew "why" label
        issues = [f for f in findings if f.status in ("FAIL", "WARN") and f.detail]
        if issues:
            out = render_report(findings, score, lang="he")
            assert "מדוע:" in out

    def test_he_fix_label_is_hebrew(self):
        findings, score = _audit_vuln()
        out = render_report(findings, score, lang="he")
        assert "תיקון:" in out

    def test_en_score_line_format(self):
        findings, score = _audit_vuln()
        out = render_report(findings, score, lang="en")
        assert f"Score: {score.score}/100" in out
        assert f"Grade: {score.grade}" in out

    def test_he_clean_report_contains_no_issues_hebrew(self):
        """Use an empty findings list to force the 'no issues' path."""
        from clawseccheck.scoring import ScoreResult
        score = ScoreResult(score=100, grade="A", capped=False, raw_score=100,
                            failed_critical=0, failed_high=0)
        out = render_report([], score, lang="he")
        out = out.replace("‏", "").replace("⁦", "").replace("⁩", "")  # drop RTL marks
        # STRINGS["report.no_issues"]["he"]
        assert "ClawSecCheck לא מצא בעיות" in out

    def test_en_clean_report_unchanged(self):
        """Use an empty findings list to force the 'no issues' path."""
        from clawseccheck.scoring import ScoreResult
        score = ScoreResult(score=100, grade="A", capped=False, raw_score=100,
                            failed_critical=0, failed_high=0)
        out_default = render_report([], score)
        assert "No issues found by ClawSecCheck" in out_default


# ---------------------------------------------------------------------------
# render_card
# ---------------------------------------------------------------------------

class TestRenderCardLang:
    def test_en_default_equals_explicit_en(self):
        findings, score = _audit_vuln()
        assert render_card(score, findings) == render_card(score, findings, lang="en")

    def test_he_contains_hebrew_security_label(self):
        findings, score = _audit_vuln()
        out = render_card(score, findings, lang="he")
        # STRINGS["card.security_label"]["he"] = "אבטחת OpenClaw"
        assert "אבטחת OpenClaw" in out

    def test_he_contains_hebrew_audited_by(self):
        findings, score = _audit_vuln()
        out = render_card(score, findings, lang="he")
        # STRINGS["card.audited_by"]["he"] = "נבדק על ידי ClawSecCheck"
        assert "נבדק על ידי ClawSecCheck" in out

    def test_en_contains_english_security_label(self):
        findings, score = _audit_vuln()
        out = render_card(score, findings, lang="en")
        assert "OpenClaw Security" in out

    def test_en_contains_english_audited_by(self):
        findings, score = _audit_vuln()
        out = render_card(score, findings, lang="en")
        assert "audited by ClawSecCheck" in out

    def test_box_layout_preserved_in_he(self):
        """Box-drawing characters must still be present for RTL output."""
        findings, score = _audit_vuln()
        out = render_card(score, findings, lang="he")
        assert "┌" in out and "┐" in out
        assert "└" in out and "┘" in out

    def test_score_present_in_both_langs(self):
        findings, score = _audit_vuln()
        for lang in ("en", "he"):
            out = render_card(score, findings, lang=lang)
            assert str(score.score) in out
            assert score.grade in out


# ---------------------------------------------------------------------------
# render_monitor
# ---------------------------------------------------------------------------

class TestRenderMonitorLang:
    def _make_score(self, s=80, g="B"):
        return type("S", (), {"score": s, "grade": g})()

    def test_en_default_equals_explicit_en(self):
        score = self._make_score()
        assert render_monitor([], score) == render_monitor([], score, lang="en")

    def test_he_title_is_hebrew(self):
        score = self._make_score()
        out = render_monitor([], score, lang="he")
        # STRINGS["monitor.title"]["he"] = "ClawSecCheck - מנטור איומים"
        assert "מנטור איומים" in out

    def test_he_no_threats_is_hebrew(self):
        score = self._make_score()
        out = render_monitor([], score, lang="he")
        # STRINGS["monitor.no_threats"]["he"]
        assert "אין איומים חדשים" in out

    def test_he_baseline_is_hebrew(self):
        score = self._make_score()
        out = render_monitor([], score, baseline=True, lang="he")
        # STRINGS["monitor.baseline"]["he"]
        assert "קו הבסיס נשמר" in out

    def test_he_changes_detected_is_hebrew(self):
        score = self._make_score()
        alerts = [("HIGH", "some alert message")]
        out = render_monitor(alerts, score, lang="he")
        # STRINGS["monitor.changes"]["he"]
        assert "זוהה" in out

    def test_en_title_unchanged(self):
        score = self._make_score()
        out = render_monitor([], score, lang="en")
        assert "ClawSecCheck - Threat Monitor" in out

    def test_en_no_threats_unchanged(self):
        score = self._make_score()
        out = render_monitor([], score, lang="en")
        assert "No new threats since last check" in out


# ---------------------------------------------------------------------------
# render_prompts
# ---------------------------------------------------------------------------

class TestRenderPromptsLang:
    def test_en_default_equals_explicit_en(self):
        findings, _ = _audit_vuln()
        assert render_prompts(findings) == render_prompts(findings, lang="en")

    def test_en_nothing_to_fix_default_equals_lang_en(self):
        findings, _ = _audit_safe()
        clean = [f for f in findings if f.status not in ("FAIL", "WARN")]
        assert render_prompts(clean) == render_prompts(clean, lang="en")

    def test_he_title_is_hebrew(self):
        findings, _ = _audit_vuln()
        out = render_prompts(findings, lang="he")
        # STRINGS["prompts.title"]["he"]
        assert "הנחיות תיקון" in out

    def test_he_intro_is_hebrew(self):
        findings, _ = _audit_vuln()
        out = render_prompts(findings, lang="he")
        # STRINGS["prompts.intro"]["he"]
        assert "הדבק כל אחת" in out

    def test_he_nothing_to_fix_is_hebrew(self):
        findings, _ = _audit_safe()
        clean = [f for f in findings if f.status not in ("FAIL", "WARN")]
        out = render_prompts(clean, lang="he")
        # STRINGS["prompts.nothing"]["he"]
        assert "אין מה לתקן" in out

    def test_en_title_unchanged(self):
        findings, _ = _audit_vuln()
        out = render_prompts(findings, lang="en")
        assert "ClawSecCheck - copy-paste fix prompts" in out

    def test_en_nothing_to_fix_unchanged(self):
        findings, _ = _audit_safe()
        clean = [f for f in findings if f.status not in ("FAIL", "WARN")]
        out = render_prompts(clean, lang="en")
        assert "Nothing to fix" in out

    def test_prompt_body_stays_english_in_he(self):
        """The copy-paste prompt text itself (the quoted string) stays English."""
        findings, _ = _audit_vuln()
        out = render_prompts(findings, lang="he")
        assert "Please fix it" in out


# ---------------------------------------------------------------------------
# render_html
# ---------------------------------------------------------------------------

class TestRenderHtmlLang:
    def test_en_contains_lang_en(self):
        findings, score = _audit_safe()
        out = render_html(findings, score, lang="en")
        assert 'lang="en"' in out

    def test_en_does_not_contain_dir_rtl(self):
        findings, score = _audit_safe()
        out = render_html(findings, score, lang="en")
        assert 'dir="rtl"' not in out

    def test_he_contains_lang_he(self):
        findings, score = _audit_safe()
        out = render_html(findings, score, lang="he")
        assert 'lang="he"' in out

    def test_he_contains_dir_rtl(self):
        findings, score = _audit_safe()
        out = render_html(findings, score, lang="he")
        assert 'dir="rtl"' in out

    def test_he_contains_rtl_css(self):
        findings, score = _audit_safe()
        out = render_html(findings, score, lang="he")
        assert "text-align:right" in out

    def test_en_no_rtl_css(self):
        findings, score = _audit_safe()
        out = render_html(findings, score, lang="en")
        # text-align:right should NOT appear in en output
        assert "text-align:right" not in out

    def test_he_title_is_hebrew(self):
        findings, score = _audit_safe()
        out = render_html(findings, score, lang="he")
        assert "דוח ביקורת אבטחה" in out

    def test_he_h1_is_hebrew(self):
        findings, score = _audit_safe()
        out = render_html(findings, score, lang="he")
        # STRINGS["html.h1"]["he"]
        assert "דוח ביקורת אבטחה של ClawSecCheck" in out

    def test_he_no_issues_is_hebrew(self):
        """Use an empty findings list to force the 'no issues' HTML path."""
        from clawseccheck.scoring import ScoreResult
        score = ScoreResult(score=100, grade="A", capped=False, raw_score=100,
                            failed_critical=0, failed_high=0)
        out = render_html([], score, lang="he")
        # STRINGS["html.no_issues"]["he"]
        assert "לא נמצאו בעיות" in out

    def test_he_findings_labels_are_hebrew(self):
        findings, score = _audit_vuln()
        out = render_html(findings, score, lang="he")
        # STRINGS["html.label_why2"]["he"] = "מדוע:" and "html.label_fix2"]["he"] = "תיקון:"
        issues_with_detail = [f for f in findings
                               if f.status in ("FAIL", "WARN") and f.detail]
        if issues_with_detail:
            assert "מדוע:" in out
        assert "תיקון:" in out

    def test_en_findings_labels_are_english(self):
        findings, score = _audit_vuln()
        out = render_html(findings, score, lang="en")
        issues_with_detail = [f for f in findings
                               if f.status in ("FAIL", "WARN") and f.detail]
        if issues_with_detail:
            assert "Why:" in out
        assert "Fix:" in out

    def test_he_section_heading_is_hebrew(self):
        findings, score = _audit_safe()
        out = render_html(findings, score, lang="he")
        # STRINGS["html.section_findings"]["he"] = "ממצאים"
        assert "ממצאים" in out

    def test_en_default_equals_no_lang_arg(self):
        findings, score = _audit_safe()
        assert render_html(findings, score) == render_html(findings, score, lang="en")

    def test_html_still_escapes_in_he(self):
        """HTML escaping must work correctly regardless of lang."""
        from clawseccheck.catalog import FAIL, Finding
        findings = [
            Finding(
                id="TEST1",
                title="Title <b>bold</b>",
                severity="HIGH",
                status=FAIL,
                detail="Detail & more",
                fix="Fix <it>",
                framework="Test",
            )
        ]
        score = type("S", (), {
            "score": 50, "grade": "D", "capped": False,
            "raw_score": 50, "failed_critical": 0, "failed_high": 1,
        })()
        out = render_html(findings, score, lang="he")
        assert "&lt;b&gt;" in out
        assert "&amp;" in out
        assert "<b>bold</b>" not in out
