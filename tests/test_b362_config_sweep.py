"""B-362 (4th slice) — extend Finding.not_applicable (F-138/F-139/F-140 mechanism,
already used by the browser cluster in tests/test_b362_browser_not_applicable.py and
the capability/agents sweep in tests/test_b362_na_sweep_capability_agents.py) to
config-absence UNKNOWN sites in checks/_config.py.

* B2 (``check_gateway``) — the whole-config-empty branch ("No config loaded — cannot
  assess gateway."). Every condition this check grades (bind, auth mode, trusted-proxy
  identity headers, open channels) is a plain ``ctx.config`` read, so a genuinely empty
  (but completely-read) config means none of that surface exists to misconfigure.
  Mirrors the existing ``check_control_plane_mutation`` precedent for the same "no
  gateway config" wording. The SIBLING "gateway config value is present but malformed"
  branch is deliberately left a real UNKNOWN — a present-but-corrupt value is not "no
  such surface", it is "cannot tell what was intended" — so this file pins that it is
  NOT flipped (test_b2_malformed_gateway_value_stays_real_unknown).

Same three-part shape as the prior B-362 test files: (1) the flag fires when the
surface is genuinely absent, (2) it degrades to False on an incomplete read, (3) it
never fires falsely when the surface exists in a form the check itself parses into a
non-UNKNOWN verdict.

Offline, read-only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.adjudication import build_judge_packet
from clawseccheck.catalog import UNKNOWN, Finding
from clawseccheck.checks import check_gateway
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
# B2 — check_gateway, whole-config-empty branch
# ---------------------------------------------------------------------------

def test_b2_empty_config_sets_not_applicable():
    f = check_gateway(_ctx({}))
    assert f.status == UNKNOWN
    assert f.not_applicable is True


def test_b2_domain_tagged_limit_hit_keeps_flag_false():
    ctx = _ctx({})
    note_limit(ctx.limit_hits, LIMIT_DOMAIN_CONFIG, "hit the config scan cap")
    f = check_gateway(ctx)
    assert f.status == UNKNOWN
    assert f.not_applicable is False


def test_b2_config_parse_error_keeps_flag_false():
    f = check_gateway(_ctx({}, config_parse_error=True))
    assert f.not_applicable is False


def test_b2_config_not_found_keeps_flag_false():
    """A host with NO openclaw.json at all (config_found=False) must never be marked
    not_applicable -- that would smear report.py's honest non-OpenClaw wording (see
    _surface_absent's own docstring)."""
    f = check_gateway(_ctx({}, config_found=False))
    assert f.not_applicable is False


def test_b2_not_applicable_finding_excluded_from_judge_packet():
    ctx = _ctx({})
    f = check_gateway(ctx)
    assert f.not_applicable is True  # control
    packet = build_judge_packet(ctx, [f])
    assert packet == []


def test_b2_malformed_gateway_value_stays_real_unknown():
    """Adversarial: a present-but-malformed `gateway` value (not a dict) is a genuinely
    different config shape from the whole config being empty -- this is "cannot tell
    what was intended", not "no such surface", so it must NEVER be reported
    not_applicable even though it also reaches UNKNOWN."""
    f = check_gateway(_ctx({"gateway": "not-an-object", "other": 1}))
    assert f.status == UNKNOWN
    assert f.not_applicable is False


def test_b2_real_gateway_config_never_reaches_the_absence_branch():
    """Adversarial: a genuinely configured (and unsafe) gateway must never be reported
    not_applicable -- it reaches a real FAIL verdict instead."""
    f = check_gateway(_ctx({"gateway": {"bind": "0.0.0.0", "auth": {"mode": "none"}}}))
    assert f.status != UNKNOWN
    assert f.not_applicable is False


def test_report_distinguishes_not_applicable_from_real_unknown_for_b2():
    real_unknown = Finding(
        id="B999", title="Synthetic unresolved check", severity="LOW", status=UNKNOWN,
        detail="could not determine", fix="—", framework="Test", not_applicable=False,
    )
    na = check_gateway(_ctx({}))
    out = render_report([real_unknown, na], _score())
    assert "not assessed (config can't tell)" in out
    assert "not applicable (no such surface in your config)" in out
