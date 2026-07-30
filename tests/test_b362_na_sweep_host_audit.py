"""B-362 (4th slice) — extend Finding.not_applicable (F-138/F-139/F-140 mechanism) to
``checks/_host.py``'s ``check_audit_log`` (B10).

B10 is architecturally different from the config-key-absence sites migrated in prior
slices (browser cluster / B31 / B26 / B140 / B72): OpenClaw exposes NO config toggle
for audit logging at all (`logging.audit` / `audit.enabled` do not exist anywhere in
the schema -- `openclaw security audit` is a standalone CLI command, grounded against
the installed dist's `security-cli-*.js`). So the UNKNOWN branch here is a structural
fact true of every openclaw.json, not a property of any one config's content -- but it
is still gated on `_surface_absent` (not set unconditionally), so an unreadable/absent/
truncated config still degrades to an ordinary unresolved UNKNOWN rather than a false
"nothing to see here" (the `logging.redactSensitive` signal that decides WARN vs this
branch would itself be unknown in that case).

Same three-part shape as ``tests/test_f140_not_applicable_degrades.py`` /
``tests/test_b362_na_sweep_capability_agents.py``: (1) the flag fires when the surface
is genuinely absent, (2) it degrades to False on an incomplete read, (3) it never fires
falsely when the check reaches a real (non-UNKNOWN) verdict.

Offline, read-only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.adjudication import build_judge_packet
from clawseccheck.catalog import UNKNOWN, WARN, Finding
from clawseccheck.checks import check_audit_log
from clawseccheck.collector import LIMIT_DOMAIN_CONFIG, Context, note_limit
from clawseccheck.report import render_report
from clawseccheck.scoring import ScoreResult


def _ctx(cfg: dict, **kw) -> Context:
    defaults = dict(home=Path("/nonexistent"), config_found=True, config_parse_error=False)
    defaults.update(kw)
    c = Context(**defaults)
    c.config = cfg
    return c


def _score() -> ScoreResult:
    return ScoreResult(score=90, grade="A", capped=False, raw_score=90,
                        failed_critical=0, failed_high=0)


# ---------------------------------------------------------------------------
# B10 — check_audit_log
# ---------------------------------------------------------------------------

def test_b10_no_logging_config_at_all_sets_not_applicable():
    f = check_audit_log(_ctx({}))
    assert f.status == UNKNOWN
    assert f.not_applicable is True


def test_b10_redact_present_but_not_off_still_not_applicable():
    """`logging.redactSensitive` set to a real (non-"off") value is a genuinely
    different config shape from the key being absent entirely, and it lands on the
    exact same not_applicable branch -- pinned so this can't silently change."""
    f = check_audit_log(_ctx({"logging": {"redactSensitive": "tools"}}))
    assert f.status == UNKNOWN
    assert f.not_applicable is True


def test_b10_redact_off_never_reaches_the_absence_branch():
    """Adversarial: redactSensitive == "off" is a real, actionable signal (WARN) --
    it must never be reported not_applicable."""
    f = check_audit_log(_ctx({"logging": {"redactSensitive": "off"}}))
    assert f.status == WARN
    assert f.not_applicable is False


def test_b10_domain_tagged_limit_hit_keeps_flag_false():
    ctx = _ctx({})
    note_limit(ctx.limit_hits, LIMIT_DOMAIN_CONFIG, "hit the config scan cap")
    f = check_audit_log(ctx)
    assert f.status == UNKNOWN
    assert f.not_applicable is False


def test_b10_config_parse_error_keeps_flag_false():
    f = check_audit_log(_ctx({}, config_parse_error=True))
    assert f.not_applicable is False


def test_b10_config_not_found_keeps_flag_false():
    f = check_audit_log(_ctx({}, config_found=False))
    assert f.not_applicable is False


def test_b10_not_applicable_finding_excluded_from_judge_packet():
    ctx = _ctx({})
    f = check_audit_log(ctx)
    assert f.not_applicable is True  # control
    packet = build_judge_packet(ctx, [f])
    assert packet == []


def test_report_distinguishes_not_applicable_from_real_unknown_for_b10():
    real_unknown = Finding(
        id="B999", title="Synthetic unresolved check", severity="LOW", status=UNKNOWN,
        detail="could not determine", fix="—", framework="Test", not_applicable=False,
    )
    na = check_audit_log(_ctx({}))
    out = render_report([real_unknown, na], _score())
    assert "not assessed (config can't tell)" in out
    assert "not applicable (no such surface in your config)" in out
