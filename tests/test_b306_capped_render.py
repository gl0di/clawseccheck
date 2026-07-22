"""B-306 (C-135 follow-up #3, 2026-07-21) — renderer gate on the granular cap signals.

An independent adversarial (C-135) review of the `total == 0` fix in `scoring.py` (see
`tests/test_b306_config_blind_score_cap.py::TestReproC_TotalZeroBypass` and the sibling
"runtime signal alone" case) found that branch always hardcodes `capped=False` — correct
per `scoring.py`'s own semantics and the documented JSON contract (`docs/OUTPUT_SCHEMA.md`:
"can be true alongside capped: false") — but `render_report`/`render_html` gated their
entire "(capped from N - ...)" explanation on `score.capped` alone. That silently dropped
the explanation in exactly the scenario B-306 exists to make loud: a blind config or a
corroborated runtime signal forcing a real F/0 out of what would otherwise have been the
neutral "N/A" bypass.

This is a RENDERING-GATE fix only (report.py reading `config_blind_capped`/
`runtime_capped` directly instead of relying on `capped` implying them) — `scoring.py`'s
ScoreResult semantics and the JSON schema/docs are untouched and stay exactly as
documented.

Offline, deterministic, no I/O beyond in-memory string building.
"""
from __future__ import annotations

from clawseccheck.catalog import HIGH
from clawseccheck.report import render_html, render_report
from clawseccheck.scoring import ScoreResult


def _score(**kw) -> ScoreResult:
    """Build a ScoreResult with the scoring.py `total == 0` branch's real defaults
    (score=raw_score=0, capped=False, assessable=True) overridden by **kw."""
    defaults = dict(
        score=0, grade="F", capped=False, raw_score=0,
        failed_critical=0, failed_high=0, failed_medium=0, failed_low=0,
        assessable=True, cap_severity=None,
        runtime_capped=False, runtime_cap_reason=None,
        config_blind_capped=False,
    )
    defaults.update(kw)
    return ScoreResult(**defaults)


# ── render_report (plain-text) ────────────────────────────────────────────────────────

class TestRenderReportConfigBlindZeroTotal:
    """scoring.py's `total == 0` branch with only `config_blind_capped` firing —
    the reviewer's primary repro."""

    def _score_here(self) -> ScoreResult:
        return _score(config_blind_capped=True)

    def test_capped_explanation_line_is_present(self):
        out = render_report([], self._score_here(), ascii_only=True)
        assert (
            "(capped from 0 - openclaw.json unreadable/unparseable this run:"
            " cannot rule out a CRITICAL condition)"
        ) in out

    def test_explanation_appears_before_the_why_breakdown_line(self):
        # B-013 self-contradiction discipline: the explanation must precede (not follow)
        # the "Why 0/100: ... 0 pass, 0 warn, 0 fail" line, or a reader sees the confusing
        # "nothing scored" line before learning WHY the grade is a forced F.
        out = render_report([], self._score_here(), ascii_only=True)
        cap_idx = out.index("openclaw.json unreadable/unparseable")
        why_idx = out.index("Why 0/100:")
        assert cap_idx < why_idx


class TestRenderReportRuntimeSignalZeroTotal:
    """Symmetric case: nothing else scored, config IS readable, but a corroborated
    runtime signal alone forced the F. The trajaudit-indicator match is the only
    remaining runtime cap source (B164's exfil_evidence cap arm was RETRACTED, C-135
    8th round, Dave's 2026-07-22 ruling — see tests/test_i025_runtime_cap.py)."""

    def _score_here(self) -> ScoreResult:
        return _score(runtime_capped=True, runtime_cap_reason="trajaudit indicator match")

    def test_capped_explanation_line_is_present(self):
        out = render_report([], self._score_here(), ascii_only=True)
        assert (
            "(capped from 0 - corroborated runtime signal: a trajectory-indicator match)"
        ) in out


class TestRenderReportBothSignalsZeroTotal:
    """Only the `total == 0` branch can produce config_blind_capped AND runtime_capped
    both True at once (the ordinary severity-cap path keeps them mutually exclusive
    because CONFIG_BLIND_CAP <= RUNTIME_SIGNAL_CAP always wins first) — the config-blind
    message must take display priority but still name the co-occurring runtime signal."""

    def _score_here(self) -> ScoreResult:
        return _score(
            config_blind_capped=True,
            runtime_capped=True, runtime_cap_reason="trajaudit indicator match",
        )

    def test_config_blind_message_wins_but_mentions_runtime_too(self):
        out = render_report([], self._score_here(), ascii_only=True)
        assert "openclaw.json unreadable/unparseable this run" in out
        assert (
            "; also a corroborated runtime signal (a trajectory-indicator match)"
        ) in out
        # Only one capped-explanation line, not two competing ones.
        assert out.count("capped from 0") == 1


class TestRenderReportRegressionOrdinaryPaths:
    """The ordinary (total != 0) severity/runtime-cap paths must render byte-identical
    to before this change — this is a rendering-gate widening, not a behaviour change
    for any case that already worked."""

    def test_severity_cap_unaffected(self):
        score = _score(score=79, grade="C", capped=True, raw_score=96, cap_severity=HIGH)
        out = render_report([], score, ascii_only=True)
        assert "(capped from 96 - open HIGH finding)" in out

    def test_runtime_cap_only_unaffected(self):
        score = _score(
            score=79, grade="C", capped=True, raw_score=96,
            runtime_capped=True, runtime_cap_reason="trajaudit indicator match",
        )
        out = render_report([], score, ascii_only=True)
        assert (
            "(capped from 96 - corroborated runtime signal: a trajectory-indicator match)"
        ) in out

    def test_config_blind_cap_unaffected(self):
        score = _score(score=49, grade="F", capped=True, raw_score=90, config_blind_capped=True)
        out = render_report([], score, ascii_only=True)
        assert (
            "(capped from 90 - openclaw.json unreadable/unparseable this run:"
            " cannot rule out a CRITICAL condition)"
        ) in out
        assert "; also" not in out

    def test_no_cap_at_all_shows_no_capped_line(self):
        score = _score(score=100, grade="A", capped=False, raw_score=100)
        out = render_report([], score, ascii_only=True)
        assert "capped from" not in out


# ── render_html ────────────────────────────────────────────────────────────────────────

class TestRenderHtmlConfigBlindZeroTotal:
    def test_capped_paragraph_is_present(self):
        score = _score(config_blind_capped=True)
        html = render_html([], score)
        assert 'class="capped"' in html
        assert "openclaw.json unreadable/unparseable this run" in html
        assert "from 0 (" in html

    def test_no_cap_at_all_omits_the_paragraph(self):
        score = _score(score=100, grade="A", capped=False, raw_score=100)
        html = render_html([], score)
        assert 'class="capped"' not in html


class TestRenderHtmlRuntimeSignalZeroTotal:
    def test_capped_paragraph_is_present(self):
        score = _score(runtime_capped=True, runtime_cap_reason="trajaudit indicator match")
        html = render_html([], score)
        assert 'class="capped"' in html
        assert "corroborated runtime signal: a trajectory-indicator match" in html
        assert "B164" not in html


class TestRenderHtmlRegressionOrdinaryPaths:
    def test_severity_cap_unaffected(self):
        score = _score(score=79, grade="C", capped=True, raw_score=96, cap_severity=HIGH)
        html = render_html([], score)
        assert "from 96 (open HIGH finding)" in html

    def test_config_blind_cap_unaffected(self):
        score = _score(score=49, grade="F", capped=True, raw_score=90, config_blind_capped=True)
        html = render_html([], score)
        assert "from 90 (openclaw.json unreadable/unparseable this run" in html
