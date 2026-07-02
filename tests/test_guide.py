"""Tests for clawseccheck/guide.py — suggest_actions + render_next_actions.

All tests are offline and deterministic. Uses real audit() on fixtures
(include_native=False) so no Finding objects need manual construction.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN, Finding
from clawseccheck.guide import Action, render_next_actions, suggest_actions
from clawseccheck.scoring import ScoreResult

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _audit_vuln():
    _, findings, score = audit(FIXTURES / "home_vuln", include_native=False)
    return findings, score


def _audit_safe():
    _, findings, score = audit(FIXTURES / "home_safe", include_native=False)
    return findings, score


def _make_score(score=80, grade="B", capped=False, raw=80, fc=0, fh=0):
    return ScoreResult(score=score, grade=grade, capped=capped,
                       raw_score=raw, failed_critical=fc, failed_high=fh)


# ---------------------------------------------------------------------------
# suggest_actions on home_vuln
# ---------------------------------------------------------------------------

class TestSuggestActionsVuln:
    def test_no_fix_action_ever(self):
        """Reports-only (F-074): no suggested action may generate or offer remediation."""
        findings, score = _audit_vuln()
        for a in suggest_actions(findings, score):
            assert a.id != "fix_guidance"
            assert "--fix" not in a.command and "--prompts" not in a.command

    def test_actions_sorted_by_priority_then_id(self):
        findings, score = _audit_vuln()
        actions = suggest_actions(findings, score)
        keys = [(a.priority, a.id) for a in actions]
        assert keys == sorted(keys)

    def test_track_trend_always_present(self):
        findings, score = _audit_vuln()
        ids = [a.id for a in suggest_actions(findings, score)]
        assert "track_trend" in ids

    def test_commands_use_real_invocation_not_audit_py(self):
        # A skill/CLI user has the `clawseccheck` command, not a bare `audit.py`.
        findings, score = _audit_vuln()
        for a in suggest_actions(findings, score):
            assert "audit.py" not in a.command, f"{a.id} hint uses audit.py: {a.command!r}"
            assert a.command.startswith("clawseccheck "), f"{a.id}: {a.command!r}"

    def test_share_grade_always_present(self):
        findings, score = _audit_vuln()
        ids = [a.id for a in suggest_actions(findings, score)]
        assert "share_grade" in ids

    def test_track_trend_priority_8(self):
        findings, score = _audit_vuln()
        actions = suggest_actions(findings, score)
        tt = next(a for a in actions if a.id == "track_trend")
        assert tt.priority == 8

    def test_share_grade_priority_9(self):
        findings, score = _audit_vuln()
        actions = suggest_actions(findings, score)
        sg = next(a for a in actions if a.id == "share_grade")
        assert sg.priority == 9


# ---------------------------------------------------------------------------
# suggest_actions on home_safe
# ---------------------------------------------------------------------------

class TestSuggestActionsSafe:
    def test_track_trend_still_present(self):
        findings, score = _audit_safe()
        ids = [a.id for a in suggest_actions(findings, score)]
        assert "track_trend" in ids

    def test_share_grade_still_present(self):
        findings, score = _audit_safe()
        ids = [a.id for a in suggest_actions(findings, score)]
        assert "share_grade" in ids

    def test_safe_has_fewer_urgent_actions_than_vuln(self):
        findings_v, score_v = _audit_vuln()
        findings_s, score_s = _audit_safe()
        actions_v = suggest_actions(findings_v, score_v)
        actions_s = suggest_actions(findings_s, score_s)
        urgent_v = [a for a in actions_v if a.priority <= 3]
        urgent_s = [a for a in actions_s if a.priority <= 3]
        assert len(urgent_v) >= len(urgent_s)


# ---------------------------------------------------------------------------
# Conditional triggers
# ---------------------------------------------------------------------------

class TestConditionalTriggers:
    def _findings_with(self, **status_by_id):
        """Build minimal Finding list with given id->status mapping."""
        out = []
        for fid, status in status_by_id.items():
            out.append(Finding(id=fid, title="t", severity="MEDIUM",
                               status=status, detail="", fix="", framework="f"))
        return out

    def test_vet_skills_triggered_by_b13_fail(self):
        score = _make_score()
        findings = self._findings_with(B13=FAIL)
        ids = [a.id for a in suggest_actions(findings, score)]
        assert "vet_skills" in ids

    def test_vet_skills_triggered_by_b13_warn(self):
        score = _make_score()
        findings = self._findings_with(B13=WARN)
        ids = [a.id for a in suggest_actions(findings, score)]
        assert "vet_skills" in ids

    def test_vet_skills_not_triggered_by_b13_pass(self):
        score = _make_score()
        findings = self._findings_with(B13=PASS)
        ids = [a.id for a in suggest_actions(findings, score)]
        assert "vet_skills" not in ids

    def test_vet_skills_not_triggered_by_b13_unknown(self):
        score = _make_score()
        findings = self._findings_with(B13=UNKNOWN)
        ids = [a.id for a in suggest_actions(findings, score)]
        assert "vet_skills" not in ids

    def test_setup_monitoring_triggered_by_b16_fail(self):
        score = _make_score()
        findings = self._findings_with(B16=FAIL)
        ids = [a.id for a in suggest_actions(findings, score)]
        assert "setup_monitoring" in ids

    def test_setup_monitoring_triggered_by_b16_warn(self):
        score = _make_score()
        findings = self._findings_with(B16=WARN)
        ids = [a.id for a in suggest_actions(findings, score)]
        assert "setup_monitoring" in ids

    def test_setup_monitoring_not_triggered_by_b16_pass(self):
        score = _make_score()
        findings = self._findings_with(B16=PASS)
        ids = [a.id for a in suggest_actions(findings, score)]
        assert "setup_monitoring" not in ids

    def test_live_test_triggered_by_b17_warn(self):
        score = _make_score()
        findings = self._findings_with(B17=WARN)
        ids = [a.id for a in suggest_actions(findings, score)]
        assert "live_test" in ids

    def test_live_test_triggered_by_b21_fail(self):
        score = _make_score()
        findings = self._findings_with(B21=FAIL)
        ids = [a.id for a in suggest_actions(findings, score)]
        assert "live_test" in ids

    def test_live_test_triggered_by_a1_trifecta(self):
        score = _make_score()
        a1 = Finding(id="A1", title="t", severity="CRITICAL", status=WARN,
                     detail="", fix="", framework="f",
                     evidence=["e1", "e2"])
        ids = [a.id for a in suggest_actions([a1], score)]
        assert "live_test" in ids

    def test_live_test_not_triggered_by_a1_one_evidence(self):
        score = _make_score()
        a1 = Finding(id="A1", title="t", severity="CRITICAL", status=WARN,
                     detail="", fix="", framework="f",
                     evidence=["e1"])
        ids = [a.id for a in suggest_actions([a1], score)]
        assert "live_test" not in ids

    def test_review_mcp_triggered_by_b15_not_unknown(self):
        score = _make_score()
        findings = self._findings_with(B15=WARN)
        ids = [a.id for a in suggest_actions(findings, score)]
        assert "review_mcp" in ids

    def test_review_mcp_triggered_by_b24_not_unknown(self):
        score = _make_score()
        findings = self._findings_with(B24=PASS)
        ids = [a.id for a in suggest_actions(findings, score)]
        assert "review_mcp" in ids

    def test_review_mcp_not_triggered_when_both_unknown(self):
        score = _make_score()
        findings = self._findings_with(B15=UNKNOWN, B24=UNKNOWN)
        ids = [a.id for a in suggest_actions(findings, score)]
        assert "review_mcp" not in ids

    def test_review_mcp_not_triggered_when_absent(self):
        score = _make_score()
        ids = [a.id for a in suggest_actions([], score)]
        assert "review_mcp" not in ids


# ---------------------------------------------------------------------------
# render_next_actions
# ---------------------------------------------------------------------------

class TestRenderNextActions:
    def _sample_actions(self):
        return [
            Action(id="live_test", title="Run a live injection test",
                   command="clawseccheck --canary", why="Urgent.", priority=0),
            Action(id="track_trend", title="Track score",
                   command="clawseccheck --trend", why="See drift.", priority=8),
            Action(id="share_grade", title="Share grade",
                   command="clawseccheck --badge grade.svg", why="Safe.", priority=9),
        ]

    def test_contains_header(self):
        actions = self._sample_actions()
        out = render_next_actions(actions)
        assert "What you can do next:" in out

    def test_contains_command(self):
        actions = self._sample_actions()
        out = render_next_actions(actions)
        assert "clawseccheck --canary" in out

    def test_numbered_items(self):
        actions = self._sample_actions()
        out = render_next_actions(actions)
        assert "1." in out
        assert "2." in out

    def test_limit_respected(self):
        actions = self._sample_actions()
        out = render_next_actions(actions, limit=1)
        assert "1." in out
        assert "2." not in out

    def test_limit_5_default_caps_output(self):
        # Build 7 actions
        many = [
            Action(id=f"a{i}", title=f"T{i}", command=f"cmd{i}",
                   why=f"W{i}", priority=i)
            for i in range(7)
        ]
        out = render_next_actions(many)
        assert "6." not in out

    def test_empty_actions_returns_all_clear(self):
        out = render_next_actions([])
        assert "good shape" in out or "re-run" in out

    def test_empty_does_not_contain_header(self):
        out = render_next_actions([])
        assert "What you can do next:" not in out

    def test_why_text_present(self):
        actions = self._sample_actions()
        out = render_next_actions(actions)
        assert "Urgent." in out

    def test_run_label_present(self):
        actions = self._sample_actions()
        out = render_next_actions(actions)
        assert "run:" in out

    def test_ends_with_newline(self):
        actions = self._sample_actions()
        assert render_next_actions(actions).endswith("\n")
        assert render_next_actions([]).endswith("\n")

    def test_ascii_only_is_pure_ascii(self):
        findings, score = _audit_vuln()
        actions = suggest_actions(findings, score)
        out = render_next_actions(actions, ascii_only=True)
        out.encode("ascii")  # must not raise

    def test_en_default_uses_english(self):
        actions = self._sample_actions()
        out = render_next_actions(actions)
        assert "What you can do next:" in out

    def test_real_vuln_render_contains_header(self):
        findings, score = _audit_vuln()
        actions = suggest_actions(findings, score)
        out = render_next_actions(actions)
        assert "What you can do next:" in out

    def test_real_safe_render_contains_header_or_all_clear(self):
        findings, score = _audit_safe()
        actions = suggest_actions(findings, score)
        out = render_next_actions(actions)
        # safe fixture may still have warn findings -> header present; or all clear
        assert "What you can do next:" in out or "good shape" in out
