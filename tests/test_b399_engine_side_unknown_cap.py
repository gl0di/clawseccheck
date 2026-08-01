"""B-399 — an engine-side UNKNOWN must never score identically to a clean PASS.

## The bug

`scoring.compute()` scored a HIGH-severity check that resolved to UNKNOWN as 100/A —
byte-identical to a clean PASS — regardless of WHY it was UNKNOWN. The same check at
FAIL scores 14/F (raw 0, capped to `FAIL_CAPS[HIGH]`). `CONFIG_BLIND_CAP` /
`DEGRADED_CHECK_CAP` / (this branch predates `LIVE_INJECTION_CAP`) bind only on their
own narrow, specific triggers — never on a plain UNKNOWN in general — so any check that
resolves to UNKNOWN because the ENGINE could not determine its state (a crash, a
timeout, an input it expected to read that turned out unreadable/corrupt/malformed, a
scan-budget escape) silently scored as though it had passed cleanly. That is the
"amplifier" this task closes: it made every current and future UNKNOWN-producing check a
potential free pass, with no FAIL for `scripts/fleet_fp_gate.py` to ever catch.

## The fix (Option 3 from the ticket — the narrowest, most defensible)

`Finding` gained one new field, `engine_degraded: bool = False` (catalog.py). A check (or
a shared helper it calls) opts a specific UNKNOWN finding INTO the existing
`DEGRADED_CHECK_CAP` by setting `engine_degraded=True` — but ONLY when the cause is
engine-side, never for "there was nothing to check" (a genuinely-absent config/feature).
`scoring._degraded_signal` (previously B-313's `"ERR:"`-id-prefix-only check) now ALSO
counts any `status == UNKNOWN` finding with `engine_degraded=True`, composed with a
single `or` — no new `ScoreResult` field, no new cap tier, same CRITICAL ceiling
(`DEGRADED_CHECK_CAP == FAIL_CAPS[CRITICAL] == 49`).

Retrofitted at the ONE shared idiom already used by ~30 checks across checks/*.py:
`_config_unreadable()` (checks/_shared.py) — the helper that returns an UNKNOWN when
`ctx.config_parse_error` is True (openclaw.json present but unparseable/unreadable).
That single change protects A1, B41, B48, and every other of its ~30 callers for free.
Also retrofitted at `_check_error_finding`/`_check_budget_finding` (checks/__init__.py,
redundant with the pre-existing `"ERR:"` prefix, kept for a single source of truth) and
at `coverage_gap_finding` (checks/_vet.py, the `VET-COVERAGE` scan-budget-escape
verdict) — see `TestRealScanBudgetEscapeNoLongerGradesA` below.

## A note on B-394

The ticket's DoD asks to demonstrate that "B-394's escaped-budget path no longer
produces grade A". `git log`/`grep -r "B-394"` turn up NOTHING in this checkout — this
worktree's branch point predates B-394 landing on `dev`/`main` (confirmed via
`git merge-base --is-ancestor`; B-394's own commit exists on a sibling worktree's
history, timestamped the same day this task was assigned). There is therefore no
`vet_skill()`/`_merge_mcp_tool_surface()` try/except-around-`_run_content_ring` to
exercise directly in this branch.

What DOES exist here, already, is B-394's own direct predecessor and closest real
analog: F-148's cooperative per-target CPU budget inside `_run_content_ring`
(checks/_vet.py) — when it is exhausted, the ring already emits a `coverage_gap_finding`
(`VET-COVERAGE`, UNKNOWN, HIGH) with the SAME "scan cut short" shape B-394 later hardened
for two more call sites. `coverage_gap_finding`'s own docstring already documents having
measured this exact bug pre-B-399: "a benign skill whose ring was cut short graded A/100
while the same skill fully scanned graded B/83 — hitting the ceiling BOUGHT a cleaner
verdict." `TestRealScanBudgetEscapeNoLongerGradesA` below reproduces that exact scenario
end-to-end through the real `_run_content_ring` function (not a synthetic Finding) and
proves it no longer grades A. This is flagged here prominently for the supervising
review, per this task's own instructions, rather than silently substituted.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import CRITICAL, FAIL, HIGH, LOW, MEDIUM, PASS, UNKNOWN, WARN, Finding
from clawseccheck.checks._config import check_dangerous_overrides
from clawseccheck.checks._vet import _run_content_ring, coverage_gap_finding
from clawseccheck.collector import Context
from clawseccheck.report import render_html, render_json, render_report
from clawseccheck.scoring import DEGRADED_CHECK_CAP, ScoreResult, assessment_coverage, compute

_SEVERITIES = (LOW, MEDIUM, HIGH, CRITICAL)


def _f(status: str, severity: str, *, fid: str = "TEST", engine_degraded: bool = False,
       scored: bool = True) -> Finding:
    return Finding(
        id=fid, title="t", severity=severity, status=status,
        detail="d", fix="f", framework="fw", scored=scored,
        engine_degraded=engine_degraded,
    )


def _clean_pass_pool() -> list[Finding]:
    """An otherwise-perfect, fully-PASSing baseline across every severity — the raw
    score is 100/A before any extra finding is added."""
    return [_f(PASS, sev, fid=f"BASE-{sev}") for sev in _SEVERITIES]


# ── Table test: {PASS, WARN, FAIL, UNKNOWN-absent, UNKNOWN-engine-side} x severity ─────

class TestStatusSeverityTable:
    """Add ONE extra finding of each (status, severity) combination to an otherwise-
    perfect PASS baseline and compare the resulting score. This is the meaningful
    comparison (not a lone finding in isolation): it answers "what does one additional
    problem of this shape do to an otherwise-clean config's grade".
    """

    @pytest.mark.parametrize("severity", _SEVERITIES)
    def test_pass_leaves_a_clean_baseline_at_100(self, severity):
        findings = [*_clean_pass_pool(), _f(PASS, severity)]
        result = compute(findings)
        assert result.score == 100
        assert result.grade == "A"

    @pytest.mark.parametrize("severity", _SEVERITIES)
    def test_warn_lowers_the_score_below_100(self, severity):
        findings = [*_clean_pass_pool(), _f(WARN, severity)]
        result = compute(findings)
        assert result.score < 100

    @pytest.mark.parametrize("severity", _SEVERITIES)
    def test_fail_caps_at_its_own_severity_ceiling(self, severity):
        from clawseccheck.scoring import FAIL_CAPS
        findings = [*_clean_pass_pool(), _f(FAIL, severity)]
        result = compute(findings)
        assert result.score <= FAIL_CAPS[severity]

    @pytest.mark.parametrize("severity", _SEVERITIES)
    def test_genuinely_absent_unknown_never_penalizes_a_clean_baseline(self, severity):
        """The narrow, deliberate half of Option 3: "there is nothing to check" must
        NOT drag down an otherwise-clean score — this is what makes the design narrow
        rather than "cap on any UNKNOWN"."""
        findings = [*_clean_pass_pool(), _f(UNKNOWN, severity, engine_degraded=False)]
        result = compute(findings)
        assert result.score == 100
        assert result.grade == "A"
        assert result.degraded_capped is False

    @pytest.mark.parametrize("severity", _SEVERITIES)
    def test_engine_side_unknown_always_caps_regardless_of_its_own_severity(self, severity):
        """B-313's own severity-agnostic design (the wrapper never knows the crashing
        check's real severity) carries over unchanged to B-399's extension: an
        engine-side UNKNOWN caps at the CRITICAL ceiling regardless of the finding's
        OWN catalogued severity — "cannot rule out a CRITICAL" is a worst-case
        assumption about what the degraded check might have found, independent of what
        it happened to be checking."""
        findings = [*_clean_pass_pool(), _f(UNKNOWN, severity, engine_degraded=True)]
        result = compute(findings)
        assert result.score <= DEGRADED_CHECK_CAP
        assert result.grade in ("D", "F")
        assert result.degraded_capped is True
        assert result.degraded_count == 1

    @pytest.mark.parametrize("severity", _SEVERITIES)
    def test_engine_side_unknown_scores_worse_than_genuinely_absent_at_the_same_severity(
        self, severity
    ):
        absent = compute([*_clean_pass_pool(), _f(UNKNOWN, severity, engine_degraded=False)])
        engine = compute([*_clean_pass_pool(), _f(UNKNOWN, severity, engine_degraded=True)])
        assert engine.score < absent.score

    @pytest.mark.parametrize("severity", _SEVERITIES)
    def test_engine_side_unknown_never_scores_as_well_as_a_clean_pass(self, severity):
        clean = compute([*_clean_pass_pool(), _f(PASS, severity)])
        engine = compute([*_clean_pass_pool(), _f(UNKNOWN, severity, engine_degraded=True)])
        assert engine.score < clean.score
        assert engine.grade != clean.grade


# ── Dedicated "do not score the same" test (explicit, per the ticket's own wording) ────

class TestEngineSideVsAbsentDoNotScoreTheSame:
    def test_direct_reproduction_high_severity_100_vs_capped(self):
        """The exact repro from the ticket: a HIGH check resolving to UNKNOWN used to
        score 100/A — byte-identical to a clean PASS — no matter why. Post-fix: a
        genuinely-absent HIGH UNKNOWN still legitimately scores 100/A (nothing was
        there to examine), but an engine-side HIGH UNKNOWN does not."""
        absent = _f(UNKNOWN, HIGH, engine_degraded=False)
        engine = _f(UNKNOWN, HIGH, engine_degraded=True)
        clean_pass = _f(PASS, HIGH)

        r_absent = compute([*_clean_pass_pool(), absent])
        r_engine = compute([*_clean_pass_pool(), engine])
        r_pass = compute([*_clean_pass_pool(), clean_pass])

        assert r_absent.score == r_pass.score == 100
        assert r_engine.score <= DEGRADED_CHECK_CAP
        assert r_engine.score != r_absent.score
        assert r_engine.grade != r_absent.grade

    def test_lone_finding_total_zero_branch_also_differs(self):
        """Mirrors B-313's own total==0 fix, one level in: a lone genuinely-absent
        UNKNOWN (nothing else scored) is honestly "not assessable" (B-014's N/A, never a
        fake F) — but a lone engine-side UNKNOWN forces the F/assessable=True result
        B-313 already established for a lone degraded check, not N/A."""
        r_absent = compute([_f(UNKNOWN, CRITICAL, engine_degraded=False)])
        r_engine = compute([_f(UNKNOWN, CRITICAL, engine_degraded=True)])

        assert r_absent.assessable is False
        assert r_absent.grade == "N/A"

        assert r_engine.assessable is True
        assert r_engine.grade == "F"
        assert r_engine.degraded_capped is True


# ── engine_degraded is meaningless (and inert) outside status == UNKNOWN ───────────────

class TestEngineDegradedOnlyMeaningfulOnUnknown:
    @pytest.mark.parametrize("status", [PASS, WARN, FAIL])
    def test_flag_set_on_a_non_unknown_finding_has_no_scoring_effect(self, status):
        """`Finding.engine_degraded`'s own docstring says it is "meaningless outside
        status == UNKNOWN". `_degraded_signal` enforces that structurally (gates on
        `f.status == UNKNOWN` in addition to the flag), not just by convention — this
        proves a future misuse (setting the flag on a FAIL/WARN/PASS finding) cannot
        silently inflate `degraded_count`."""
        with_flag = compute([*_clean_pass_pool(), _f(status, HIGH, engine_degraded=True)])
        without_flag = compute([*_clean_pass_pool(), _f(status, HIGH, engine_degraded=False)])
        assert with_flag.degraded_count == without_flag.degraded_count == 0
        assert with_flag.degraded_capped == without_flag.degraded_capped is False
        assert with_flag.score == without_flag.score

    def test_err_prefixed_and_engine_degraded_on_the_same_finding_is_not_double_counted(self):
        """`_check_error_finding`/`_check_budget_finding` now set BOTH the `"ERR:"` id
        prefix AND `engine_degraded=True` on the same Finding (belt-and-suspenders, one
        source of truth). `_degraded_signal`'s `or` must count that finding once, not
        twice."""
        both = Finding(
            id="ERR:some_check", title="t", severity=MEDIUM, status=UNKNOWN,
            detail="d", fix="f", framework="fw", scored=False, engine_degraded=True,
        )
        result = compute([*_clean_pass_pool(), both])
        assert result.degraded_count == 1


# ── assessment_coverage must count a scored=False engine-degraded finding too ──────────

class TestAssessmentCoverageCountsEngineDegraded:
    def test_scored_false_engine_degraded_finding_counts_toward_unknown(self):
        """Mirrors the existing B-313 guarantee for `"ERR:"`-prefixed findings
        (tests/test_b313_degraded_check_cap.py) — a `scored=False` finding that is
        ONLY reachable via `engine_degraded=True` (not the `"ERR:"` id prefix) must not
        silently vanish from the one metric that measures how much of the catalog could
        actually be assessed."""
        vet_coverage_shaped = _f(UNKNOWN, HIGH, fid="VET-COVERAGE",
                                  engine_degraded=True, scored=False)
        cov = assessment_coverage([_f(PASS, HIGH, fid="B9"), vet_coverage_shaped])
        assert cov["scored_total"] == 2
        assert cov["unknown"] == 1
        assert cov["assessable"] == 1

    def test_genuinely_absent_scored_false_finding_is_unaffected(self):
        """A plain `scored=False`, non-degraded UNKNOWN keeps its pre-existing
        behavior: invisible to this metric, exactly as before this task (this is the
        SAME "advisory, opted fully out" shape most of the checks/*.py `scored=False`
        catalog entries already use)."""
        absent_shaped = _f(UNKNOWN, HIGH, fid="B99", engine_degraded=False, scored=False)
        cov = assessment_coverage([_f(PASS, HIGH, fid="B9"), absent_shaped])
        assert cov["scored_total"] == 1
        assert cov["unknown"] == 0


# ── Cross-renderer agreement: text / HTML / JSON must agree on grade + cap disclosure ──

class TestCrossRendererAgreement:
    """report.py's text (`render_report`), HTML (`render_html`), and JSON
    (`render_json`) renderers must all agree on the grade and on whether/why the
    engine-side-degraded cap bound, for the SAME `ScoreResult` — this project has shipped
    renderer-disagreement bugs on a capped score before (B-306's own history). SARIF
    (`sarif.py`) is deliberately out of scope here: its `render_sarif` accepts an
    optional `score` parameter but never reads `.grade`/`.degraded_capped`/
    `.degraded_count` from it (grep-verified) — SARIF has no aggregate-grade concept to
    disagree with the other three, so there is nothing to assert cross-renderer parity
    against for THIS signal.
    """

    def _score(self) -> ScoreResult:
        return ScoreResult(
            score=49, grade="F", capped=True, raw_score=88,
            failed_critical=0, failed_high=0, failed_medium=0, failed_low=0,
            assessable=True, cap_severity=None,
            runtime_capped=False, runtime_cap_reason=None,
            config_blind_capped=False,
            degraded_capped=True, degraded_count=1,
        )

    def test_text_html_json_agree_on_grade(self):
        score = self._score()
        text = render_report([], score, ascii_only=True)
        html = render_html([], score)
        payload = __import__("json").loads(render_json([], score))

        assert "Grade: F" in text
        assert payload["grade"] == score.grade == "F"
        # The HTML renderer paints the grade letter into a styled span; assert the
        # letter appears in the score line rather than assuming exact markup.
        assert f"Score: {score.score}" in text or str(score.score) in text
        assert str(score.score) in html

    def test_text_html_json_agree_the_degraded_cap_bound(self):
        score = self._score()
        text = render_report([], score, ascii_only=True)
        html = render_html([], score)
        payload = __import__("json").loads(render_json([], score))

        assert "could not reach a reliable verdict this run: cannot rule out" in text
        assert "could not reach a reliable verdict this run: cannot rule out" in html
        assert payload["degraded_capped"] is True
        assert payload["degraded_count"] == 1

    def test_text_html_json_agree_when_nothing_is_capped(self):
        clean = ScoreResult(
            score=100, grade="A", capped=False, raw_score=100,
            failed_critical=0, failed_high=0, failed_medium=0, failed_low=0,
            assessable=True, cap_severity=None,
            runtime_capped=False, runtime_cap_reason=None,
            config_blind_capped=False,
            degraded_capped=False, degraded_count=0,
        )
        text = render_report([], clean, ascii_only=True)
        html = render_html([], clean)
        payload = __import__("json").loads(render_json([], clean))

        assert "could not reach a reliable verdict" not in text
        assert "could not reach a reliable verdict" not in html
        assert payload["degraded_capped"] is False
        assert payload["degraded_count"] == 0


# ── Real check-function integration: the actual _config_unreadable retrofit ────────────

class TestRealConfigUnreadableRetrofit:
    """`check_dangerous_overrides` (B48, HIGH, scored=True) is a real, ordinary,
    CHECKS-registered full-audit check (checks/_config.py) whose FIRST line is
    `_config_unreadable("B48", ctx)`. This proves the retrofit at the single shared
    helper (checks/_shared.py) protects a real check with zero check-level code change,
    not just a synthetic Finding built by hand."""

    def test_b48_marks_its_config_unreadable_unknown_as_engine_degraded(self):
        ctx = Context(home=Path("/nonexistent"), config_found=True, config_parse_error=True)
        finding = check_dangerous_overrides(ctx)
        assert finding.status == UNKNOWN
        assert finding.severity == HIGH
        assert finding.engine_degraded is True

    def test_real_b48_unknown_caps_the_grade_even_without_passing_ctx(self):
        """Deliberately calls `compute(findings)` WITHOUT `ctx` — CONFIG_BLIND_CAP (the
        pre-existing, ctx-only mechanism that already covers `config_parse_error` at the
        WHOLE-RUN level) is therefore completely inert here. Only DEGRADED_CHECK_CAP's
        new `engine_degraded` half can be doing the capping below, proving this is
        independent, additive coverage — not a restatement of CONFIG_BLIND_CAP."""
        ctx = Context(home=Path("/nonexistent"), config_found=True, config_parse_error=True)
        finding = check_dangerous_overrides(ctx)

        before_like = compute([*_clean_pass_pool(), _f(PASS, HIGH)])
        after = compute([*_clean_pass_pool(), finding])  # ctx=None

        assert before_like.score == 100
        assert after.score <= DEGRADED_CHECK_CAP
        assert after.grade in ("D", "F")
        assert after.degraded_capped is True


# ── Real end-to-end integration: the F-148/B-394-analog scan-budget escape ─────────────

class TestRealScanBudgetEscapeNoLongerGradesA:
    """See the module docstring's "A note on B-394" section: this exercises the REAL
    `_run_content_ring` cooperative CPU-budget mechanism (checks/_vet.py, F-148) end to
    end — not a synthetic Finding — reproducing exactly the scenario
    `coverage_gap_finding`'s own docstring already measured pre-B-399 ("a benign skill
    whose ring was cut short graded A/100... hitting the ceiling BOUGHT a cleaner
    verdict"). This is this branch's closest real analog to B-394's own escaped-budget
    path.
    """

    def _ctx_with_a_skill(self) -> Context:
        ctx = Context(home=Path("/nonexistent"))
        ctx.installed_skills = {"demo": "echo hello world " * 500}
        return ctx

    def test_forcing_the_budget_to_zero_produces_an_engine_degraded_vet_coverage_finding(self):
        ctx = self._ctx_with_a_skill()
        # An effectively-zero-but-nonzero budget: cpu_deadline(0.0) disables the cap
        # entirely (scanbudget.py's own `if budget_s and budget_s > 0`), so a tiny
        # positive value is needed to force the FIRST cooperative check to already be
        # over budget — deterministic, no timing flakiness, no monkeypatching of the
        # clock required.
        ring = _run_content_ring(ctx, target_budget_s=1e-9)
        coverage = [fx for fx in ring if fx.id == "VET-COVERAGE"]
        assert coverage, "expected the cooperative budget-exhaustion path to fire"
        assert coverage[0].status == UNKNOWN
        assert coverage[0].engine_degraded is True

    def test_the_escaped_budget_path_no_longer_grades_a(self):
        ctx = self._ctx_with_a_skill()
        ring = _run_content_ring(ctx, target_budget_s=1e-9)
        assert any(fx.id == "VET-COVERAGE" for fx in ring)

        result = compute([*_clean_pass_pool(), *ring])
        assert result.score <= DEGRADED_CHECK_CAP
        assert result.grade in ("D", "F")
        assert result.degraded_capped is True

    def test_a_fully_completed_ring_scan_is_unaffected(self):
        """Control: with a generous budget the ring completes normally (no
        VET-COVERAGE finding at all) and the run scores on its own merits, unchanged by
        this task — proves the cap is conditional on the REAL escape firing, not
        unconditionally applied to every vet-shaped finding set."""
        ctx = self._ctx_with_a_skill()
        ring = _run_content_ring(ctx)  # default (generous) budget
        assert not any(fx.id == "VET-COVERAGE" for fx in ring)

    def test_coverage_gap_finding_itself_is_marked_engine_degraded(self):
        f = coverage_gap_finding("content-ring coverage is incomplete: test")
        assert f.id == "VET-COVERAGE"
        assert f.status == UNKNOWN
        assert f.engine_degraded is True
