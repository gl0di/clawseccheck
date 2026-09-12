"""CLAWSECCHECK-B-672 — `_enabled_tools()` resolves tool grants per scope.

Before this fix, `_enabled_tools(cfg)` (checks/_shared.py) read the global config
only, and additionally treated `gateway.tools.allow` as a `tools.allow` fallback. Both
were wrong, in opposite directions:

* UNDER-report: a per-agent `tools.alsoAllow` (or a per-agent `tools.profile` that is
  itself powerful) genuinely widens the effective tool set — the real resolver merges
  it directly into the resolved profile policy (`??`-replacing, never AND-ing, the
  global `tools.alsoAllow`/`tools.profile`) — but was invisible to every one of
  `_enabled_tools()`'s ~20 call sites (check_human_approval, check_egress,
  check_egress_inventory, check_sandbox, _meaningful_tool_surface,
  report._capability_graph, ...).
* OVER-report: `gateway.tools.allow` grants nothing at all — the real resolver only
  ever uses it to remove entries from a fixed HTTP-surface tool-deny list — yet it was
  echoed as if it were an agent's own `tools.allow`, inventing a capability the config
  never actually granted.

A per-agent EXPLICIT `tools.allow` is the negative control throughout this file: it is
a separate, independently AND-ed policy layer that can only NARROW the profile's
grant, never widen it, so it must NOT surface here — unlike `tools.alsoAllow`, which
merges directly into the profile policy and genuinely widens.

Cases mirror the task's own measured K0-K3 / L0-L2 repro table, executed end to end
against the real check functions rather than just `_enabled_tools()` in isolation
(`check_human_approval`/`check_egress` are the two the bug report's own vendor-ground-
truth measurement used; `check_sandbox` is added here for the profile-widening vector,
which the alsoAllow-only K-series didn't exercise).
"""
from pathlib import Path

from clawseccheck.catalog import UNKNOWN, WARN
from clawseccheck.collector import Context, collect
from clawseccheck.checks import (
    check_egress,
    check_human_approval,
    check_sandbox,
)
from clawseccheck.checks._shared import _enabled_tools, _agent_tools_widenings
from clawseccheck.report import _capability_graph

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _mk(cfg: dict) -> Context:
    return Context(home=Path("/tmp/nonexistent-b672-fixture-home"), config=cfg)


def _main_node(ctx: Context) -> dict:
    graph = _capability_graph(ctx)
    return next(n for n in graph["nodes"] if n["id"] == "main")


# --- inline K0-K3 / L0-L2 controls, matching the task's own measured table exactly ---


def test_k0_nothing_grants_nothing():
    ctx = _mk({})
    assert _enabled_tools(ctx.config) == []
    node = _main_node(ctx)
    assert node["can_egress"] is False and node["secrets_visible"] is False


def test_k1_global_allow_is_a_control():
    ctx = _mk({"tools": {"allow": ["http_post", "postgres"]}})
    assert set(_enabled_tools(ctx.config)) == {"http_post", "postgres"}
    node = _main_node(ctx)
    assert node["can_egress"] is True and node["secrets_visible"] is True


def test_k2_per_agent_alsoallow_widens_past_weak_global_profile():
    # profile: minimal (global) + agent alsoAllow: [http_post, postgres] -- the K2
    # defect: the real resolver grants both tools to this agent (merged into the
    # profile policy), and the previous _enabled_tools() returned [].
    ctx = _mk({
        "tools": {"profile": "minimal"},
        "agents": {"entries": {"main": {"tools": {"alsoAllow": ["http_post", "postgres"]}}}},
    })
    assert set(_enabled_tools(ctx.config)) == {"http_post", "postgres"}
    node = _main_node(ctx)
    assert node["can_egress"] is True and node["secrets_visible"] is True


def test_k3_per_agent_explicit_allow_does_not_widen_negative_control():
    # Same shape as K2, but the per-agent field is `allow`, not `alsoAllow`. A per-agent
    # `allow` is a separate AND-ed policy layer that only NARROWS the global profile's
    # grant -- it must not surface here. Without this control, a fix that treats ANY
    # per-agent tools key as widening re-opens the false positive B-668 already ruled
    # out for the sibling fs-tool helper.
    ctx = _mk({
        "tools": {"profile": "minimal"},
        "agents": {"entries": {"main": {"tools": {"allow": ["http_post", "postgres"]}}}},
    })
    assert _enabled_tools(ctx.config) == []
    node = _main_node(ctx)
    assert node["can_egress"] is False and node["secrets_visible"] is False


def test_l0_nothing_grants_nothing():
    ctx = _mk({})
    assert _enabled_tools(ctx.config) == []


def test_l1_gateway_tools_allow_naming_denylist_entries_is_still_not_a_grant():
    # gateway.tools.allow's only effect is removing names from a FIXED 12-entry HTTP
    # tool-deny list -- it is never pushed as an allow policy. Even when the named
    # tools are members of that deny list, _enabled_tools() must not report them as
    # granted: it answers "what can the agent do", not "what is exempted from one
    # gateway-HTTP-surface deny list".
    ctx = _mk({"gateway": {"tools": {"allow": ["cron", "gateway", "nodes"]}}})
    assert _enabled_tools(ctx.config) == []


def test_l2_gateway_tools_allow_is_not_a_tools_allow_fallback():
    # The over-report this task fixes: with no tools.allow and no profile,
    # gateway.tools.allow used to be echoed as if it were the agent's own grant.
    ctx = _mk({"gateway": {"tools": {"allow": ["http_post", "postgres"]}}})
    assert _enabled_tools(ctx.config) == []
    node = _main_node(ctx)
    assert node["can_egress"] is False and node["secrets_visible"] is False


def test_global_alsoallow_alone_is_now_read():
    # A THIRD, previously-unmeasured gap sharing the same root cause: even at GLOBAL
    # scope, a bare tools.alsoAllow (no tools.allow at all) was invisible, because the
    # old code only ever read `tools.allow or gateway.tools.allow`.
    ctx = _mk({"tools": {"alsoAllow": ["http_post"]}})
    assert "http_post" in _enabled_tools(ctx.config)


def test_agent_powerful_profile_widens_the_exec_tag():
    # The OTHER real widening vector alongside alsoAllow: a per-agent tools.profile
    # replaces (??-coalesces over) a weaker global one, so a global "minimal" + agent
    # "coding" genuinely grants exec/write -- and the synthetic "exec" tag several
    # consumers key on (check_sandbox among them) must see it.
    ctx = _mk({
        "tools": {"profile": "minimal"},
        "agents": {"entries": {"main": {"tools": {"profile": "coding"}}}},
    })
    assert "exec" in _enabled_tools(ctx.config)


def test_agent_weak_profile_does_not_falsely_widen_negative_control():
    ctx = _mk({
        "tools": {"profile": "minimal"},
        "agents": {"entries": {"main": {"tools": {"profile": "readonly"}}}},
    })
    assert "exec" not in _enabled_tools(ctx.config)


def test_global_alsoallow_still_denied_negative_control():
    # C-135: a naive "just echo alsoAllow" fix fires here -- deny wins in the real
    # resolver, so a token present in BOTH tools.alsoAllow and tools.deny is not
    # granted at all.
    ctx = _mk({"tools": {"alsoAllow": ["http_post"], "deny": ["http_post"]}})
    assert _enabled_tools(ctx.config) == []


def test_agent_alsoallow_still_denied_by_global_deny_negative_control():
    ctx = _mk({
        "tools": {"profile": "minimal", "deny": ["http_post"]},
        "agents": {"entries": {"main": {"tools": {"alsoAllow": ["http_post"]}}}},
    })
    assert _enabled_tools(ctx.config) == []


def test_agents_defaults_alsoallow_still_denied_by_global_deny_negative_control():
    ctx = _mk({
        "tools": {"profile": "minimal", "deny": ["http_post"]},
        "agents": {"defaults": {"tools": {"alsoAllow": ["http_post"]}}},
    })
    assert _enabled_tools(ctx.config) == []


def test_agent_tools_widenings_helper_attributes_by_agent_label():
    also_allow, powerful_profiles = _agent_tools_widenings({
        "agents": {"entries": {
            "web": {"tools": {"alsoAllow": ["http_post"]}},
            "coder": {"tools": {"profile": "coding"}},
        }},
    })
    assert also_allow == [("agents.entries.web", "http_post")]
    assert powerful_profiles == [("agents.entries.coder", "coding")]


def test_agents_defaults_tools_widens_when_no_roster_declared():
    # The second DECLARED per-agent surface _b68_fs_tools_granted already models
    # (its own "S3" section): resolveEffectiveToolPolicy falls back to
    # agents.defaults.tools as the resolved agentTools ONLY when the config declares
    # no roster key at all -- confirmed by executing toolgrant.granted().
    ctx = _mk({
        "tools": {"profile": "minimal"},
        "agents": {"defaults": {"tools": {"alsoAllow": ["http_post"]}}},
    })
    assert "http_post" in _enabled_tools(ctx.config)


def test_agents_defaults_tools_ignored_once_a_roster_is_declared_negative_control():
    # Same agents.defaults.tools.alsoAllow, but agents.entries is now a declared (even
    # if empty) roster key. The real resolver ignores agents.defaults.tools entirely
    # once a roster key exists -- reading it here would manufacture a capability the
    # runtime never grants, the same K3 shape one layer up.
    ctx = _mk({
        "tools": {"profile": "minimal"},
        "agents": {"entries": {}, "defaults": {"tools": {"alsoAllow": ["http_post"]}}},
    })
    assert _enabled_tools(ctx.config) == []


def test_legacy_agents_list_shape_widens_too():
    # B-699: both roster shapes are live on real installs; the widening must not be
    # blind to the pre-2026.8.1 array form.
    ctx = _mk({
        "tools": {"profile": "minimal"},
        "agents": {"list": [{"id": "main", "tools": {"alsoAllow": ["http_post"]}}]},
    })
    assert "http_post" in _enabled_tools(ctx.config)


# --- real fixtures, through the real CLI-facing collection path ---


def test_warn_fixture_agent_alsoallow_widens_enabled_tools():
    home = FIXTURES / "warn_b672_agent_alsoallow_widens_enabled_tools"
    ctx = collect(home)
    assert "http_post" in _enabled_tools(ctx.config)
    f = check_egress(ctx)
    assert f.status == WARN, f.detail
    f2 = check_human_approval(ctx)
    assert f2.status == WARN, f2.detail


def test_clean_fixture_agent_allow_does_not_widen_enabled_tools():
    home = FIXTURES / "clean_b672_agent_allow_does_not_widen_enabled_tools"
    ctx = collect(home)
    assert _enabled_tools(ctx.config) == []
    f = check_egress(ctx)
    assert f.status == UNKNOWN, f.detail
    f2 = check_human_approval(ctx)
    assert f2.status == UNKNOWN, f2.detail


def test_clean_fixture_gateway_tools_allow_not_a_grant():
    home = FIXTURES / "clean_b672_gateway_tools_allow_not_a_grant"
    ctx = collect(home)
    assert _enabled_tools(ctx.config) == []
    f = check_egress(ctx)
    assert f.status == UNKNOWN, f.detail
    f2 = check_human_approval(ctx)
    assert f2.status == UNKNOWN, f2.detail


def test_warn_fixture_agent_profile_widens_exec_tag():
    home = FIXTURES / "warn_b672_agent_profile_widens_exec_tag"
    ctx = collect(home)
    assert "exec" in _enabled_tools(ctx.config)
    f = check_sandbox(ctx)
    assert f.status == WARN, f.detail
