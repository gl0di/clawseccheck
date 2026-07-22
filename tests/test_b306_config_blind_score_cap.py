"""B-306 (C-135 follow-up) — the AGGREGATE grade half of the blind-run bug.

The check-level fix in `tests/test_b306_a1_blind_run_guard.py` made A1/B41 degrade to
UNKNOWN instead of a fabricated WARN/PASS when `ctx.config_parse_error` is True — but an
independent adversarial (C-135) review proved that fix alone does NOT close the bug's own
named symptom: converting a config-derived FAIL into an UNKNOWN removes it from
`FAIL_CAPS`' severity-cap loop (`scoring.compute`), which only binds when some check is
STILL a FAIL after the run. Two real reproductions on real-shaped fixtures showed the
aggregate grade could still rise — in the worse case all the way to A/98 — the exact
"hiding evidence improves the grade" defect this project's Golden Rule #5 exists to
prevent, one layer above the individual check.

This file pins the fix: `scoring.CONFIG_BLIND_CAP`, a cap-only mechanism (mirrors
I-025/B-309's `RUNTIME_SIGNAL_CAP` shape exactly) gated purely on the real, collector-
derived `ctx.config_parse_error` boolean (B-166) — never a keyword/text match, never a
tuned threshold on the UNKNOWN fraction, so it cannot regress into the keyword-widening
whack-a-mole this project has already learned to avoid.

Offline, read-only of the tmp_path sandbox, stdlib only.
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import CRITICAL, FAIL, HIGH, LOW, PASS, UNKNOWN, Finding
from clawseccheck.collector import Context, collect
from clawseccheck.scoring import CONFIG_BLIND_CAP, compute

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _f(severity, status, scored=True, fid="X"):
    return Finding(fid, "t", severity, status, "d", "fix", "fw", scored)


def _blind_ctx(tmp_path) -> Context:
    ctx = Context(home=tmp_path)
    ctx.config_parse_error = True
    return ctx


def _readable_ctx(tmp_path) -> Context:
    ctx = Context(home=tmp_path)
    ctx.config_parse_error = False
    return ctx


# ── Unit level: scoring.compute() in isolation ───────────────────────────────────────

class TestConfigBlindCapUnit:
    def test_constant_matches_critical_fail_cap(self):
        # CONFIG_BLIND_CAP is deliberately the SAME ceiling FAIL_CAPS[CRITICAL] already
        # imposes — "cannot read the config" is treated as "cannot rule out a CRITICAL",
        # never worse and never better.
        assert CONFIG_BLIND_CAP == 49

    def test_blind_with_no_fail_at_all_is_still_capped(self, tmp_path):
        # The Repro-B shape: every scored check happens to be PASS/UNKNOWN this run (no
        # FAIL survives to feed the ordinary severity-cap loop) — without this cap the
        # weighted pass-rate alone would report a clean A.
        findings = [_f(LOW, PASS) for _ in range(20)]
        r = compute(findings, _blind_ctx(tmp_path))
        assert r.score <= CONFIG_BLIND_CAP
        assert r.grade == "F"
        assert r.config_blind_capped is True
        assert r.capped is True

    def test_blind_tightens_an_existing_high_cap(self, tmp_path):
        # Repro-A shape: a real, non-config-derived HIGH FAIL survives (so the ordinary
        # severity loop alone would cap at 79) but the config itself is unreadable too —
        # the tighter, CRITICAL-level cap must still win. A large PASS pool (weight-diluted
        # denominator) is needed so the raw pass-rate actually clears 79 and the severity
        # cap is the one demonstrably binding first, before the config-blind cap tightens
        # it further.
        findings = [_f(HIGH, FAIL)] + [_f(LOW, PASS) for _ in range(100)]
        r = compute(findings, _blind_ctx(tmp_path))
        assert r.raw_score > 79  # sanity: the severity cap alone would have to do work
        assert r.score <= CONFIG_BLIND_CAP
        assert r.config_blind_capped is True
        assert r.cap_severity == HIGH  # still names the real HIGH FAIL that also fired

    def test_blind_non_binding_when_a_real_critical_fail_already_caps_as_hard(self, tmp_path):
        # A genuine, non-config CRITICAL FAIL already caps at 49 on its own — the config-
        # blind cap fires at the identical ceiling, so it must NOT claim to be the
        # binding reason (mirrors runtime_capped's own "only-when-actually-binding" rule).
        findings = [_f(CRITICAL, FAIL)] + [_f(LOW, PASS) for _ in range(20)]
        r = compute(findings, _blind_ctx(tmp_path))
        assert r.score <= CONFIG_BLIND_CAP
        assert r.config_blind_capped is False
        assert r.cap_severity == CRITICAL

    def test_readable_config_is_completely_unaffected(self, tmp_path):
        findings = [_f(LOW, PASS) for _ in range(20)]
        r_readable = compute(findings, _readable_ctx(tmp_path))
        r_none = compute(findings, None)
        assert r_readable.score == r_none.score == 100
        assert r_readable.config_blind_capped is False
        assert r_none.config_blind_capped is False

    def test_ctx_none_is_inert_regression(self):
        # Every pre-existing caller that never passes ctx must be byte-identical.
        findings = [_f(HIGH, FAIL)] + [_f(LOW, PASS) for _ in range(20)]
        r = compute(findings)
        assert r.config_blind_capped is False
        assert r.score <= 79

    def test_missing_config_parse_error_attr_is_inert(self):
        # A bare object without the attribute at all (getattr default False) must not
        # crash and must not cap — defensive against a future caller passing something
        # ctx-shaped but incomplete.
        class Bare:
            pass
        findings = [_f(LOW, PASS) for _ in range(5)]
        r = compute(findings, Bare())
        assert r.config_blind_capped is False
        assert r.score == 100

    def test_not_assessable_short_circuit_stays_safe_when_ctx_is_not_blind(self):
        # Nothing scorable at all (e.g. every finding UNKNOWN/advisory) and NO cap signal
        # -> the existing N/A early-return path (B-014), unaffected by this task.
        r = compute([_f(LOW, UNKNOWN)], None)
        assert r.assessable is False
        assert r.grade == "N/A"
        assert r.config_blind_capped is False

    def test_not_assessable_short_circuit_is_no_longer_a_bypass_when_blind(self, tmp_path):
        # C-135 follow-up #2 (real end-to-end bypass, 2026-07-21): nothing scorable AND
        # a blind config -- must NOT silently fall back to a neutral "N/A" (which the
        # brand-color layer renders grey, not the alarming red an F gets, and which the
        # capped-score explanation banner skips because `capped` was False). It must
        # resolve to a real, capped F instead, exactly like a lone scored FAIL of that
        # severity with nothing else measured already does via the ordinary path.
        r = compute([_f(LOW, UNKNOWN)], _blind_ctx(tmp_path))
        assert r.assessable is True
        assert r.grade == "F"
        assert r.score == 0
        assert r.config_blind_capped is True

    def test_composes_with_runtime_cap_tighter_wins(self, tmp_path):
        # A corroborated runtime signal (RUNTIME_SIGNAL_CAP=79) fires in the SAME run as
        # a blind config (CONFIG_BLIND_CAP=49) — the tighter cap must win, and the
        # non-binding one must honestly report itself as not the driver. The trajaudit
        # indicator match is the sole remaining runtime cap source (B164's exfil_evidence
        # cap arm was RETRACTED, C-135 8th round, Dave's 2026-07-22 ruling — see
        # tests/test_i025_runtime_cap.py) — collect() the real fixture that trips it and
        # layer the blind-config state on top.
        ctx = collect(FIXTURES / "traj_incident_acted")
        ctx.config_parse_error = True
        findings = [_f(LOW, PASS) for _ in range(20)]
        r = compute(findings, ctx)
        assert r.score <= CONFIG_BLIND_CAP
        assert r.config_blind_capped is True
        assert r.runtime_capped is False  # already at/under 79 before the runtime step

    def test_total_zero_bypass_also_closed_for_runtime_signal_alone(self, tmp_path):
        # Symmetric case: nothing else scored this run, config IS readable (no
        # config_blind), but a corroborated runtime signal (trajaudit indicator match)
        # fired. Must not fall back to "N/A" either -- same bypass, the other eligible
        # signal.
        ctx = collect(FIXTURES / "traj_incident_acted")
        ctx.config_parse_error = False
        r = compute([_f(LOW, UNKNOWN)], ctx)
        assert r.assessable is True
        assert r.grade == "F"
        assert r.score == 0
        assert r.config_blind_capped is False
        assert r.runtime_capped is True
        assert r.runtime_cap_reason == "trajaudit indicator match"


# ── Integration level: real fixtures through the real `audit()` entry point ──────────
# Per project doctrine ("verify end-to-end, not traces"): reproduce the C-135 reviewer's
# own two repros against checked-in fixtures (never the user's real ~/.openclaw), and pin
# the actual invariant the bug's DoD asks for — hiding the config never improves the
# grade — as a direct before/after comparison, not just a fixed fixture value.

def _copy_fixture(name: str, tmp_path: Path) -> Path:
    dest = tmp_path / name
    shutil.copytree(FIXTURES / name, dest)
    return dest


class TestReproA_HomeVulnTruncated:
    """The reviewer's Repro A shape: a real 3/3-trifecta config, truncated mid-run."""

    def test_blind_run_never_scores_better_than_readable(self, tmp_path):
        home = _copy_fixture("home_vuln", tmp_path)
        ctx_readable, findings_readable, score_readable = audit(home)
        assert ctx_readable.config_parse_error is False
        assert score_readable.grade == "F"

        cfg_text = (home / "openclaw.json").read_text()
        (home / "openclaw.json").write_text(cfg_text[: len(cfg_text) // 2])

        ctx_blind, findings_blind, score_blind = audit(home)
        assert ctx_blind.config_parse_error is True
        assert score_blind.score <= score_readable.score, (
            "hiding openclaw.json must never IMPROVE the grade: readable="
            f"{score_readable.score}/{score_readable.grade}, blind="
            f"{score_blind.score}/{score_blind.grade}"
        )
        assert score_blind.score <= CONFIG_BLIND_CAP
        assert score_blind.config_blind_capped is True


class TestReproB_HomeSafePlusRealTrifectaTruncated:
    """The reviewer's Repro B shape (strictly worse pre-fix): a home_safe-shaped clean
    config edited to add a genuine 3/3 trifecta, then truncated. Pre-fix this reached
    A/98 once BOTH A1 and B2 correctly-but-insufficiently degraded to UNKNOWN and no
    independent-of-config FAIL remained to cap anything."""

    def test_blind_run_never_scores_better_than_readable(self, tmp_path):
        home = _copy_fixture("home_safe", tmp_path)
        cfg_path = home / "openclaw.json"
        cfg = json.loads(cfg_path.read_text())
        cfg.setdefault("channels", {}).setdefault("telegram", {})["dmPolicy"] = "open"
        cfg.setdefault("tools", {})["allow"] = ["exec", "email_send"]
        cfg["tools"]["exec"] = {"mode": "full"}
        cfg_path.write_text(json.dumps(cfg))
        os.chmod(cfg_path, 0o600)

        ctx_readable, findings_readable, score_readable = audit(home)
        assert ctx_readable.config_parse_error is False
        readable_fail_ids = sorted(f.id for f in findings_readable if f.status == FAIL)
        assert "A1" in readable_fail_ids  # confirm the edit really produced a true FAIL
        assert score_readable.score <= CONFIG_BLIND_CAP  # a real CRITICAL FAIL (A1) itself

        raw = cfg_path.read_text()
        cfg_path.write_text(raw[: len(raw) // 2])

        ctx_blind, findings_blind, score_blind = audit(home)
        assert ctx_blind.config_parse_error is True
        assert score_blind.score <= score_readable.score, (
            "hiding openclaw.json must never IMPROVE the grade: readable="
            f"{score_readable.score}/{score_readable.grade}, blind="
            f"{score_blind.score}/{score_blind.grade}"
        )
        assert score_blind.score <= CONFIG_BLIND_CAP, (
            "pre-fix this reached A/98 — the aggregate cap must now hold it at the "
            "CRITICAL ceiling even though every config-derived FAIL degraded to UNKNOWN"
        )
        assert score_blind.grade == "F"
        assert score_blind.config_blind_capped is True


class TestRegressionRealShapedFixturesUnaffected:
    """The guard must be completely inert on the two real-shaped fixtures the rest of
    the suite pins scores against — a readable config never sees this cap."""

    def test_home_safe_unaffected(self):
        ctx, findings, score = audit(FIXTURES / "home_safe")
        assert ctx.config_parse_error is False
        assert score.config_blind_capped is False

    def test_home_vuln_unaffected(self):
        ctx, findings, score = audit(FIXTURES / "home_vuln")
        assert ctx.config_parse_error is False
        assert score.config_blind_capped is False


class TestReproC_TotalZeroBypass:
    """C-135 follow-up #2 (2026-07-21): the reviewer's own real end-to-end repro — a
    minimal/fresh OpenClaw home (no skills, no MCP servers) with openclaw.json truncated
    AND a `.clawseccheckignore` that happens to suppress the only two checks (B9, B16)
    that still score off a blind ``ctx.config == {}`` (every other config-derived check
    was already guarded to UNKNOWN by this task's first half). Pre-fix this reached
    `scored == []`, `total == 0`, and fell through to `assessable=False`/grade="N/A" —
    a neutral grey badge, not the CRITICAL-ceiling F this project's own doctrine assigns
    everywhere else a config goes dark. Runs through the real `audit()` entry point
    (same call the CLI itself makes), never a hand-built ScoreResult."""

    def test_blind_run_with_nothing_else_scored_does_not_fall_back_to_na(self, tmp_path):
        (tmp_path / "openclaw.json").write_text('{"mcp": {"servers": ')  # truncated JSON
        os.chmod(tmp_path / "openclaw.json", 0o600)
        (tmp_path / ".clawseccheckignore").write_text("B9\nB16\n")

        ctx, findings, score = audit(tmp_path)

        assert ctx.config_parse_error is True
        scored_non_unknown = [
            f for f in findings
            if f.scored and f.status not in (UNKNOWN, "SKILL_ARCHIVE_PATH_TRAVERSAL")
            and (not getattr(f, "suppressed", False) or f.status == FAIL)
        ]
        assert scored_non_unknown == [], (
            "test setup assumption broken: something else scored this run, so this no "
            "longer reproduces the total==0 bypass shape"
        )
        assert score.assessable is True, (
            "must NOT silently revert to the honest-but-wrong N/A short-circuit just "
            "because nothing else happened to score on top of the blind config"
        )
        assert score.grade == "F", "a neutral grey N/A badge is the exact bypass this pins"
        assert score.score == 0
        assert score.config_blind_capped is True
