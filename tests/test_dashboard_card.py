"""Deterministic chat Dashboard card — `--dashboard` / render_dashboard (B-077).

Live testing (F-070) showed the host LLM drops the 🦞 header and family frame when
asked to COMPOSE them, so Sections 1-2 are one code-rendered paste. These tests pin
that contract: mascot, score-bar, family emoji, severity dots, pure-ASCII degradation
— and, per the reports-only doctrine (F-074), the ABSENCE of any remediation surface.

All tests are offline and deterministic — no network calls, no file writes.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import CRITICAL, FAIL, HIGH, LOW, MEDIUM, PASS, WARN, Finding
from clawseccheck.cli import main
from clawseccheck.report import _sev_token, render_dashboard
from clawseccheck.scoring import compute

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _f(id_, status, severity=HIGH, **kw):
    return Finding(id=id_, title=f"title {id_}", severity=severity, status=status,
                   detail=f"detail {id_}", fix=f"fix {id_}", framework="Test", **kw)


# ─── Severity token (🔴/🟠/🟡/⚪ dots, Component-2 mock) ─────────────────────

class TestSevToken:
    def test_each_severity_gets_its_dot(self):
        assert _sev_token(CRITICAL) == "🔴 CRITICAL"
        assert _sev_token(HIGH) == "🟠 HIGH"
        assert _sev_token(MEDIUM) == "🟡 MEDIUM"
        assert _sev_token(LOW) == "⚪ LOW"

    def test_ascii_folds_to_bracket(self):
        assert _sev_token(CRITICAL, ascii_only=True) == "[CRITICAL]"
        assert _sev_token(LOW, ascii_only=True).isascii()

    def test_unknown_severity_falls_back_not_crashes(self):
        assert "BOGUS" in _sev_token("BOGUS")

    def test_color_is_additive(self):
        from clawseccheck.ansi import strip_ansi
        colored = _sev_token(CRITICAL, color=True)
        assert "\x1b[" in colored
        assert strip_ansi(colored) == _sev_token(CRITICAL)


# ─── render_dashboard (Sections 1-2) ─────────────────────────────────────────

class TestRenderDashboard:
    def _out(self, **kw):
        findings = [
            _f("B2", FAIL, CRITICAL),   # exposure
            _f("A1", FAIL, CRITICAL),   # trifecta → privilege
            _f("B3", WARN, MEDIUM, confidence=MEDIUM),  # excluded from Section 3
            _f("B1", PASS, HIGH),
        ]
        return render_dashboard(findings, compute(findings), **kw), findings

    def test_header_has_mascot_grade_and_score(self):
        out, findings = self._out()
        score = compute(findings)
        first = out.splitlines()[0]
        assert first.startswith("🦞 OpenClaw Security Audit · Grade ")
        assert f"· {score.score}/100" in first

    def test_score_bar_and_issue_count(self):
        out, _ = self._out()
        bar_line = out.splitlines()[1]
        assert "█" in bar_line or "░" in bar_line
        # 3 non-suppressed FAIL/WARN (incl. the MEDIUM-confidence one — Section-1 counts
        # ALL issues; Section 3 below filters to high-confidence only).
        assert "3 issues" in bar_line

    def test_no_fix_surfaces(self):
        # Reports-only (F-074): no FIX FIRST, no fix: lines, no projection offers.
        out, _ = self._out()
        assert "FIX FIRST" not in out
        assert "fix:" not in out
        assert "Projected" not in out

    def test_findings_header_and_family_emoji(self):
        out, _ = self._out()
        assert "· Findings ·" in out
        assert "│ 🌐 Exposure & Network" in out
        assert "│ 🔑 Privilege & Execution" in out

    def test_severity_dots_used(self):
        out, _ = self._out()
        assert "🔴 CRITICAL" in out
        assert "⛔" not in out

    def test_single_issue_singular(self):
        findings = [_f("B2", FAIL, CRITICAL)]
        out = render_dashboard(findings, compute(findings))
        assert "1 issue" in out
        assert "1 issues" not in out

    def test_ascii_is_pure_ascii(self):
        out, _ = self._out(ascii_only=True)
        assert out.isascii()
        assert "[Exposure & Network]" in out

    def test_no_score_line_or_receipt(self):
        # It is the chat card, not the full report.
        out, _ = self._out()
        assert "Score:" not in out
        assert "Scan receipt" not in out


# ─── CLI integration ─────────────────────────────────────────────────────────

class TestCliDashboard:
    def test_dashboard_flag_prints_card(self, capsys):
        rc = main(["--home", str(FIXTURES / "home_vuln"), "--no-native", "--no-history",
                   "--dashboard"])
        assert rc == 0
        out = capsys.readouterr().out
        assert out.startswith("🦞 OpenClaw Security Audit")
        assert "│ 🌐 Exposure & Network" in out
        assert "Scan receipt" not in out

    def test_dashboard_ascii(self, capsys):
        rc = main(["--home", str(FIXTURES / "home_vuln"), "--no-native", "--no-history",
                   "--ascii", "--dashboard"])
        assert rc == 0
        out = capsys.readouterr().out
        assert out.isascii()
        assert "[Exposure & Network]" in out
