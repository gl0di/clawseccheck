"""B-362 (follow-up pass) — extend Finding.not_applicable (F-138/F-139/F-140 mechanism,
also used by B-362's own first slice for the browser cluster in
``tests/test_b362_browser_not_applicable.py``) to four more config-absence UNKNOWN
sites, one each in ``checks/_capability.py`` and three in ``checks/_agents.py``:

* B31 (``check_effective_tools``) — no tool deny-policy configured anywhere
  (``tools.deny`` / top-level and per-agent ``toolsBySender.*.deny``). With no deny
  list declared, there is no "illusory deny" gap for a mutating tool to slip past.
* B26 (``check_untrusted_context``) — no channels configured. Same "no channels"
  locus already migrated for B25/session-visibility in the prior B-362 slice; here
  it gates untrusted-context exposure instead of sender identity / session scope.
* B140 (``check_wildcard_group_ingress``) — no channels configured. Same locus as
  B26, gating wildcard group-ingress instead.
* B72 (``check_subagents_allow_agents``) — neither
  ``agents.defaults.subagents.allowAgents`` nor any per-agent
  ``agents.list[].subagents.allowAgents`` is configured. Grounded in the check's own
  docstring citation (docs.openclaw.ai/agents/subagents): with the field unset
  anywhere, OpenClaw's own default restricts subagent spawning to the requesting
  agent only, so the wildcard-delegation surface this check grades genuinely does
  not exist.

Same three-part shape as ``tests/test_f140_not_applicable_degrades.py`` /
``tests/test_f140_not_applicable_adversarial.py`` / ``tests/test_b362_browser_not_applicable.py``:
(1) the flag fires when the surface is genuinely absent, (2) it degrades to False on
an incomplete read, (3) it never fires falsely when the surface exists in a form the
check itself parses into a non-UNKNOWN verdict.

Offline, read-only.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.adjudication import build_judge_packet
from clawseccheck.catalog import PASS, UNKNOWN, WARN, Finding
from clawseccheck.checks import (
    check_effective_tools,
    check_subagents_allow_agents,
    check_untrusted_context,
    check_wildcard_group_ingress,
)
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
# B31 — check_effective_tools
# ---------------------------------------------------------------------------

def test_b31_no_deny_policy_anywhere_sets_not_applicable():
    f = check_effective_tools(_ctx({}))
    assert f.status == UNKNOWN
    assert f.not_applicable is True


def test_b31_empty_deny_lists_still_not_applicable():
    """An explicit but empty tools.deny / toolsBySender behaves identically to
    absence for _b31_collect_deny_lists (an empty list is falsy at every scope), so
    this is a genuinely different config shape from B-31's `not test_b31_no_deny_...`
    above, and it lands on the exact same not_applicable branch -- pinned so a future
    change to the truthiness gate can't silently start treating this differently."""
    f = check_effective_tools(_ctx({"tools": {"deny": []}, "toolsBySender": {}}))
    assert f.status == UNKNOWN
    assert f.not_applicable is True


def test_b31_real_deny_list_never_reaches_the_absence_branch():
    """Adversarial: a genuinely configured (non-empty) deny list must never be
    reported not_applicable -- it reaches a real PASS/WARN verdict instead."""
    f = check_effective_tools(_ctx({"tools": {"deny": ["group:fs"]}}))
    assert f.status != UNKNOWN
    assert f.not_applicable is False


def test_b31_domain_tagged_limit_hit_keeps_flag_false():
    ctx = _ctx({})
    note_limit(ctx.limit_hits, LIMIT_DOMAIN_CONFIG, "hit the config scan cap")
    f = check_effective_tools(ctx)
    assert f.status == UNKNOWN
    assert f.not_applicable is False


def test_b31_config_parse_error_keeps_flag_false():
    f = check_effective_tools(_ctx({}, config_parse_error=True))
    assert f.not_applicable is False


def test_b31_config_not_found_keeps_flag_false():
    f = check_effective_tools(_ctx({}, config_found=False))
    assert f.not_applicable is False


def test_b31_not_applicable_finding_excluded_from_judge_packet():
    ctx = _ctx({})
    f = check_effective_tools(ctx)
    assert f.not_applicable is True  # control
    packet = build_judge_packet(ctx, [f])
    assert packet == []


# ---------------------------------------------------------------------------
# B26 / B140 — share one locus: ctx.config["channels"] with no real provider entry.
# ---------------------------------------------------------------------------

_CHANNEL_CHECKS = pytest.mark.parametrize(
    "check_fn", [check_untrusted_context, check_wildcard_group_ingress],
    ids=["B26", "B140"],
)


@_CHANNEL_CHECKS
def test_channels_key_entirely_absent_sets_not_applicable(check_fn):
    f = check_fn(_ctx({}))
    assert f.status == UNKNOWN
    assert f.not_applicable is True


@_CHANNEL_CHECKS
def test_channels_present_but_only_defaults_still_not_applicable(check_fn):
    """`channels: {"defaults": {...}}` with no real provider entry is a genuinely
    different config shape from the key being absent entirely, and it lands on the
    exact same not_applicable branch (the "defaults" key is filtered out by both
    checks before counting providers) -- pinned so that filter can't silently change
    without this being noticed."""
    f = check_fn(_ctx({"channels": {"defaults": {"contextVisibility": "all"}}}))
    assert f.status == UNKNOWN
    assert f.not_applicable is True


@_CHANNEL_CHECKS
def test_a_real_channel_provider_never_reaches_the_absence_branch(check_fn):
    """Adversarial: ANY real provider key (even an empty dict) is enough to make
    `providers` non-empty, so both checks reach a real verdict instead of the
    not_applicable branch."""
    f = check_fn(_ctx({"channels": {"telegram": {}}}))
    assert f.status != UNKNOWN
    assert f.not_applicable is False


@_CHANNEL_CHECKS
def test_channels_domain_tagged_limit_hit_keeps_flag_false(check_fn):
    ctx = _ctx({})
    note_limit(ctx.limit_hits, LIMIT_DOMAIN_CONFIG, "hit the config scan cap")
    f = check_fn(ctx)
    assert f.status == UNKNOWN
    assert f.not_applicable is False


@_CHANNEL_CHECKS
def test_channels_config_parse_error_keeps_flag_false(check_fn):
    f = check_fn(_ctx({}, config_parse_error=True))
    assert f.not_applicable is False


@_CHANNEL_CHECKS
def test_channels_config_not_found_keeps_flag_false(check_fn):
    f = check_fn(_ctx({}, config_found=False))
    assert f.not_applicable is False


@_CHANNEL_CHECKS
def test_channels_not_applicable_finding_excluded_from_judge_packet(check_fn):
    ctx = _ctx({})
    f = check_fn(ctx)
    assert f.not_applicable is True  # control
    packet = build_judge_packet(ctx, [f])
    assert packet == []


# ---------------------------------------------------------------------------
# B72 — check_subagents_allow_agents
# ---------------------------------------------------------------------------

def test_b72_allow_agents_entirely_unconfigured_sets_not_applicable():
    f = check_subagents_allow_agents(_ctx({}))
    assert f.status == UNKNOWN
    assert f.not_applicable is True


def test_b72_subagents_dict_present_but_no_allow_agents_key_still_not_applicable():
    """`agents: {"defaults": {"subagents": {}}}` -- the subagents container exists but
    the allowAgents key itself is absent, a genuinely different config shape from the
    whole `agents` key being absent, and it lands on the exact same not_applicable
    branch (has_config's dig() returns None either way)."""
    f = check_subagents_allow_agents(_ctx({"agents": {"defaults": {"subagents": {}}}}))
    assert f.status == UNKNOWN
    assert f.not_applicable is True


def test_b72_explicit_empty_allow_agents_list_never_reaches_the_absence_branch():
    """Adversarial: an explicit (even empty) allowAgents list IS a declaration --
    `isinstance(defaults_allow, list)` is True for `[]` -- so has_config becomes True
    and the check reaches a real PASS verdict instead of the not_applicable branch."""
    f = check_subagents_allow_agents(
        _ctx({"agents": {"defaults": {"subagents": {"allowAgents": []}}}})
    )
    assert f.status == PASS
    assert f.not_applicable is False


def test_b72_wildcard_allow_agents_never_reaches_the_absence_branch():
    """A second adversarial angle: a real (dangerous) allowAgents value must never be
    marked not_applicable either -- it reaches WARN."""
    f = check_subagents_allow_agents(
        _ctx({"agents": {"defaults": {"subagents": {"allowAgents": ["*"]}}}})
    )
    assert f.status == WARN
    assert f.not_applicable is False


def test_b72_domain_tagged_limit_hit_keeps_flag_false():
    ctx = _ctx({})
    note_limit(ctx.limit_hits, LIMIT_DOMAIN_CONFIG, "hit the config scan cap")
    f = check_subagents_allow_agents(ctx)
    assert f.status == UNKNOWN
    assert f.not_applicable is False


def test_b72_config_parse_error_keeps_flag_false():
    f = check_subagents_allow_agents(_ctx({}, config_parse_error=True))
    assert f.not_applicable is False


def test_b72_config_not_found_keeps_flag_false():
    f = check_subagents_allow_agents(_ctx({}, config_found=False))
    assert f.not_applicable is False


def test_b72_not_applicable_finding_excluded_from_judge_packet():
    ctx = _ctx({})
    f = check_subagents_allow_agents(ctx)
    assert f.not_applicable is True  # control
    packet = build_judge_packet(ctx, [f])
    assert packet == []


# ---------------------------------------------------------------------------
# report.py visibly distinguishes the two UNKNOWN sub-cases (regression control --
# report.py's rendering itself is exercised end-to-end by test_b362_browser_not_
# applicable.py and the F-140 suite; this just confirms these four checks' real
# findings feed it correctly).
# ---------------------------------------------------------------------------

def test_report_distinguishes_not_applicable_from_real_unknown_for_b31():
    real_unknown = Finding(
        id="B999", title="Synthetic unresolved check", severity="LOW", status=UNKNOWN,
        detail="could not determine", fix="—", framework="Test", not_applicable=False,
    )
    na = check_effective_tools(_ctx({}))
    out = render_report([real_unknown, na], _score())
    assert "not assessed (config can't tell)" in out
    assert "not applicable (no such surface in your config)" in out
