"""B-726 -- toolpolicy's scopes were global+agents only, so a per-channel/per-group
``tools``/``toolsBySender`` block never reached the write-reach model at all.

These layers only ever NARROW (the vendor ANDs them on top of everything else), so being
blind to one cannot manufacture a grant -- it can only make ``unconfined_write_scopes``
miss a REMOVAL, which keeps the more severe verdict on a config that is actually confined.
That is a false-positive FAIL, a Golden Rule #5 hard blocker, and it is what
``check_fs_write_exposure`` (B55) downgrades on when ``unconfined_write_scopes`` comes back
empty (see the ``write_scopes is not None and not write_scopes`` branch there).

Grounded in ``toolpolicy.py``'s own SCOPE docstring ("PARTIALLY RESOLVED", 2026-09-23): with
NO route binding declared anywhere in ``cfg.bindings``, ``resolveAgentRoute`` (executed
in-memory against the installed dist, not merely read) proves every channel/guild/group
message on every provider and account reaches the DEFAULT agent and nothing else -- so a
per-channel narrowing block can be credited to that one scope soundly. A declared route
binding reopens the question (the real target could be a DIFFERENT agent), so the model
stops there rather than guessing -- ``test_channel_narrowing_does_NOT_exclude_when_a_route_binding_exists``
is the control that proves this stays off.
"""
import json
import os
import tempfile
from pathlib import Path

import clawseccheck.checks as C
from clawseccheck.catalog import FAIL, WARN
from clawseccheck.collector import collect
from clawseccheck.toolpolicy import (
    _has_route_binding,
    declares_channel_tools_narrowing,
    undecided_write_scopes,
    unconfined_write_scopes,
)

_OPEN = {"channels": {"telegram": {"dmPolicy": "open", "groupPolicy": "open"}}}
_WRITE = {"tools": {"allow": ["write"]}}
_WRITE_TOOLS = ["write", "edit", "apply_patch"]

# The exact six-path shape C-484's schema-walk recovered:
# channels.discord.accounts.<id>.guilds.<id>.channels.<id>.tools/.toolsBySender.
_GUILD_DENY_WRITE = {
    "discord": {
        "accounts": {
            "default": {
                "guilds": {
                    "g1": {
                        "channels": {
                            "c1": {"tools": {"deny": ["write", "edit", "apply_patch"]}}
                        }
                    }
                }
            }
        }
    }
}

_ROUTE_BINDING = [{"type": "route", "agentId": "worker", "match": {"channel": "telegram"}}]
_ACP_BINDING = [{"type": "acp", "agentId": "worker", "acp": {},
                 "match": {"channel": "discord", "peer": {"kind": "channel", "id": "x"}}}]


def _b55_for(cfg):
    home = Path(tempfile.mkdtemp(prefix="b726-"))
    path = home / "openclaw.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(path, 0o600)
    ctx = collect(home)
    ctx.installed_dist_version = "2026.9.5"
    return next(f for f in C.run_all(ctx) if f.id == "B55")


# ======================================================================================
# 1. declares_channel_tools_narrowing -- schema-shape coverage
# ======================================================================================

def test_no_channels_at_all_is_false():
    assert declares_channel_tools_narrowing({}) is False
    assert declares_channel_tools_narrowing({"channels": {}}) is False
    assert declares_channel_tools_narrowing(
        {"channels": {"telegram": {"dmPolicy": "open"}}}) is False


def test_discord_guild_channel_nesting_the_exact_c484_paths():
    assert declares_channel_tools_narrowing({"channels": _GUILD_DENY_WRITE}) is True


def test_flat_groups_shape_toolsbysender():
    cfg = {"channels": {"slack": {"groups": {"g1": {"toolsBySender": {"u1": {"deny": ["write"]}}}}}}}
    assert declares_channel_tools_narrowing(cfg) is True


def test_provider_level_groups_no_account():
    cfg = {"channels": {"telegram": {"groups": {"*": {"tools": {"profile": "minimal"}}}}}}
    assert declares_channel_tools_narrowing(cfg) is True


def test_account_level_groups_no_guild():
    cfg = {"channels": {"telegram": {"accounts": {"default": {"groups": {"c1": {"tools": {}}}}}}}}
    assert declares_channel_tools_narrowing(cfg) is True


def test_a_channel_block_with_neither_key_does_not_count():
    """requireMention / introHint / other per-channel config is not a tools narrowing."""
    cfg = {"channels": {"telegram": {"groups": {"*": {"requireMention": False}}}}}
    assert declares_channel_tools_narrowing(cfg) is False


def test_non_dict_channel_shapes_do_not_crash():
    for bad in ({"channels": "nope"}, {"channels": {"telegram": "nope"}},
                {"channels": {"telegram": {"accounts": "nope"}}},
                {"channels": {"telegram": {"accounts": {"a": {"guilds": "nope"}}}}}):
        assert declares_channel_tools_narrowing(bad) is False


# ======================================================================================
# 2. _has_route_binding -- route vs acp vs legacy no-type
#
# Mirrors an in-memory execution of the installed dist's own resolveAgentRoute /
# isRouteBinding (see the toolpolicy.py module docstring): a binding is a route unless
# its "type" is LITERALLY "acp"; a legacy binding with no "type" field at all IS a route.
# ======================================================================================

def test_no_bindings_at_all():
    assert _has_route_binding({}) is False
    assert _has_route_binding({"bindings": []}) is False


def test_explicit_route_binding():
    assert _has_route_binding({"bindings": _ROUTE_BINDING}) is True


def test_legacy_binding_with_no_type_still_counts():
    assert _has_route_binding(
        {"bindings": [{"agentId": "w", "match": {"channel": "discord"}}]}) is True


def test_acp_only_binding_does_not_count():
    assert _has_route_binding({"bindings": _ACP_BINDING}) is False


def test_a_mix_counts_as_having_a_route():
    assert _has_route_binding({"bindings": _ACP_BINDING + _ROUTE_BINDING}) is True


# ======================================================================================
# 3. The composition -- unconfined_write_scopes / undecided_write_scopes
# ======================================================================================

def test_channel_narrowing_excludes_the_default_scope_when_no_binding_exists():
    cfg = {**_WRITE, "channels": _GUILD_DENY_WRITE}
    assert unconfined_write_scopes(cfg, _WRITE_TOOLS) == []


def test_channel_narrowing_does_NOT_exclude_when_a_route_binding_exists():
    """The sound half stops at the edge of what it can prove: a declared route binding
    means some OTHER scope might be the real target, and attribution needs the full
    binding-precedence matcher this module does not port -- so nothing is excluded here,
    matching the pre-existing quiet-direction behaviour (this is the soundness control)."""
    cfg = {**_WRITE, "channels": _GUILD_DENY_WRITE, "bindings": _ROUTE_BINDING}
    assert unconfined_write_scopes(cfg, _WRITE_TOOLS) == ["main"]


def test_an_acp_only_binding_still_excludes():
    """An ACP binding does not participate in resolveAgentRoute at all (see the module
    docstring's executed probe), so it must not disable the exclusion the way a real
    route binding does."""
    cfg = {**_WRITE, "channels": _GUILD_DENY_WRITE, "bindings": _ACP_BINDING}
    assert unconfined_write_scopes(cfg, _WRITE_TOOLS) == []


def test_a_non_default_agent_scope_is_unaffected():
    """The exclusion is scoped to the DEFAULT agent only -- a second, non-default agent's
    write exposure is untouched by channel narrowing: it is not the routing target this
    module can prove for the unbound-channel case."""
    cfg = {**_WRITE, "channels": _GUILD_DENY_WRITE,
           "agents": {"entries": {"main": {"default": True}, "w": {}}}}
    assert unconfined_write_scopes(cfg, _WRITE_TOOLS) == ["w"]


def test_no_channel_narrowing_leaves_the_default_scope_reachable():
    """Control: without any channels.* tools/toolsBySender block at all, nothing changes
    -- this is the pre-existing, already vendor-validated behaviour
    (tests/test_f186_write_reach.py)."""
    cfg = {**_WRITE, "channels": {"telegram": {"dmPolicy": "open"}}}
    assert unconfined_write_scopes(cfg, _WRITE_TOOLS) == ["main"]


def test_undecided_write_scopes_excludes_the_same_way():
    """A scope kept in `undecided_write_scopes` ONLY because sandbox.mode 'non-main'
    leaves its confinement undecided must ALSO be removed by channel narrowing -- the two
    exclusions (_has_opaque_narrowing and this one) sit at the same place in
    `_write_scopes` and neither is gated by `undecided_only`."""
    cfg = {**_WRITE, "channels": _GUILD_DENY_WRITE,
           "agents": {"defaults": {"sandbox": {"mode": "non-main"}}}}
    assert undecided_write_scopes(cfg, _WRITE_TOOLS) == []


def test_no_config_still_returns_none():
    assert unconfined_write_scopes({}, _WRITE_TOOLS) is None
    assert unconfined_write_scopes(None, _WRITE_TOOLS) is None


# ======================================================================================
# 4. End to end -- B55 (check_fs_write_exposure)
# ======================================================================================

def test_b55_downgrades_fail_to_warn_when_a_channel_block_removes_write():
    cfg = {**_OPEN, **_WRITE, "channels": {**_OPEN["channels"], **_GUILD_DENY_WRITE}}
    f = _b55_for(cfg)
    assert f.status == WARN
    assert any("no unconfined scope is granted a write tool" in e for e in (f.evidence or []))


def test_b55_stays_fail_when_the_same_block_coexists_with_a_route_binding():
    """Soundness control: a declared route binding means the channel COULD route
    elsewhere, so this static model must not guess -- the pre-existing FAIL stands."""
    cfg = {**_OPEN, **_WRITE, "channels": {**_OPEN["channels"], **_GUILD_DENY_WRITE},
           "bindings": _ROUTE_BINDING}
    assert _b55_for(cfg).status == FAIL


def test_b55_stays_fail_without_any_channel_block():
    """Control: the FAIL is not coming from some unrelated new suppression."""
    assert _b55_for({**_OPEN, **_WRITE}).status == FAIL
