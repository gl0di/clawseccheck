"""B55 must not credit a per-channel/per-group ``tools`` block to an agent scope.

The grounding is in ``toolpolicy.py``'s module docstring (the "STILL OPEN" note). In short,
the vendor applies a group block per TURN, not per agent: ``resolveGroupToolPolicyOutcome``
reads group ids only from the server-built session key, so a DM turn gets no group policy
at all, and a block on one provider never reaches another provider's turn. A block's
presence also says nothing about what it resolves to: a specific group's own ``tools``
REPLACES ``groups["*"]``, and ``tools: {}`` narrows nothing.

An earlier attempt dropped the default agent's whole scope from ``unconfined_write_scopes``
whenever any such block existed. That turned every FAIL below into a WARN. Each case is an
open Telegram DM (``dmPolicy: "open"`` + ``allowFrom: ["*"]``) plus a global write grant.
That is a real FAIL whatever the group blocks say, because the DM never passes through them.

Each FAIL case has a paired control that is not a FAIL. The first control is the same
blocks with the DM closed, so the FAIL is carried by the open DM and not by a blanket
verdict. The second is a narrowing on the scope's OWN policy, which the model still
credits. The invariant test pins the rule itself: channel blocks never move the scope
answer.
"""
import copy
import json
import os

import pytest

import clawseccheck.checks as C
from clawseccheck.catalog import FAIL, WARN
from clawseccheck.collector import collect
from clawseccheck.toolpolicy import unconfined_write_scopes

_WT = ["write", "edit", "apply_patch"]
_WRITE = {"tools": {"allow": ["write"]}}
_OPEN_DM = {"dmPolicy": "open", "allowFrom": ["*"]}
_CLOSED_DM = {"dmPolicy": "pairing"}

# Telegram group blocks from the review. None of them can narrow a DM turn. Several narrow
# nothing even for a group turn, because a block that merely EXISTS was being credited.
_GROUP_BLOCKS = {
    "deny-browser-with-requireMention": {
        "-100123": {"requireMention": True, "tools": {"deny": ["browser"]}}},
    "wildcard-group-denies-the-write-family": {"*": {"tools": {"deny": list(_WT)}}},
    "empty-tools": {"-100123": {"tools": {}}},
    "alsoAllow-write": {"-100123": {"tools": {"alsoAllow": ["write"]}}},
    "allow-star": {"-100123": {"tools": {"allow": ["*"]}}},
    "empty-toolsBySender": {"-100123": {"toolsBySender": {}}},
}

# A narrowing block on a DIFFERENT provider than the open ingress.
_OTHER_PROVIDER_BLOCKS = {
    "slack-group-denies-write": {
        "slack": {"groups": {"C1": {"tools": {"deny": ["write"]}}}}},
    # The earlier attempt's own end-to-end case: a Discord guild channel denying the write
    # family, the exact nesting the schema walk recovered.
    "discord-guild-channel-denies-the-family": {
        "discord": {"accounts": {"default": {"guilds": {"g1": {"channels": {
            "c1": {"tools": {"deny": list(_WT)}}}}}}}}},
}


def _tg(dm, groups=None):
    node = dict(dm)
    if groups is not None:
        node["groups"] = copy.deepcopy(groups)
    return node


def _b55(tmp_path, cfg):
    path = tmp_path / "openclaw.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(path, 0o600)
    ctx = collect(tmp_path)
    ctx.installed_dist_version = "2026.9.5"
    return next(f for f in C.run_all(ctx) if f.id == "B55")


# ------------------------------------------------------------------ the defects, pinned

@pytest.mark.parametrize("groups", list(_GROUP_BLOCKS.values()), ids=list(_GROUP_BLOCKS))
def test_an_open_dm_keeps_its_fail_whatever_the_group_blocks_say(tmp_path, groups):
    cfg = {**_WRITE, "channels": {"telegram": _tg(_OPEN_DM, groups)}}
    assert unconfined_write_scopes(cfg, _WT) == ["main"]
    f = _b55(tmp_path, cfg)
    assert f.status == FAIL, f.detail


@pytest.mark.parametrize("extra", list(_OTHER_PROVIDER_BLOCKS.values()),
                         ids=list(_OTHER_PROVIDER_BLOCKS))
def test_a_block_on_another_provider_does_not_narrow_the_open_dm(tmp_path, extra):
    cfg = {**_WRITE, "channels": {"telegram": _tg(_OPEN_DM), **copy.deepcopy(extra)}}
    assert unconfined_write_scopes(cfg, _WT) == ["main"]
    f = _b55(tmp_path, cfg)
    assert f.status == FAIL, f.detail


# ------------------------------------------------------------------ paired controls

@pytest.mark.parametrize("groups", list(_GROUP_BLOCKS.values()), ids=list(_GROUP_BLOCKS))
def test_control_the_same_blocks_behind_a_closed_dm_are_not_a_fail(tmp_path, groups):
    """With no open ingress the check reaches its non-FAIL branch on these same blocks.
    So the FAIL above comes from the open DM, not from a blanket verdict."""
    cfg = {**_WRITE, "channels": {"telegram": _tg(_CLOSED_DM, groups)}}
    assert _b55(tmp_path, cfg).status == WARN


def test_control_a_narrowing_on_the_scope_own_policy_is_still_credited(tmp_path):
    """The model still credits narrowing where it can be attributed: the scope's OWN tools
    block. Here the only unconfined agent denies the write family itself, so no scope can
    write and the open DM is a WARN. A channel block is the unattributable kind."""
    cfg = {**_WRITE, "channels": {"telegram": _tg(_OPEN_DM)},
           "agents": {"defaults": {"sandbox": {"mode": "all"}},
                      "entries": {"main": {"default": True},
                                  "w": {"tools": {"deny": list(_WT)},
                                        "sandbox": {"mode": "off"}}}}}
    assert unconfined_write_scopes(cfg, _WT) == []
    assert _b55(tmp_path, cfg).status == WARN


# ------------------------------------------------------------------ the invariant

def _strip_channel_tool_blocks(node):
    if isinstance(node, dict):
        return {k: _strip_channel_tool_blocks(v) for k, v in node.items()
                if k not in ("tools", "toolsBySender")}
    return node


_INVARIANT_CASES = {
    **{f"telegram-{k}": {"telegram": _tg(_OPEN_DM, v)} for k, v in _GROUP_BLOCKS.items()},
    **{f"closed-dm-{k}": {"telegram": _tg(_CLOSED_DM, v)} for k, v in _GROUP_BLOCKS.items()},
    **{k: {"telegram": _tg(_OPEN_DM), **v} for k, v in _OTHER_PROVIDER_BLOCKS.items()},
    "account-level-wildcard-denies-the-family": {"telegram": {"accounts": {"a": {
        **_OPEN_DM, "groups": {"*": {"tools": {"deny": list(_WT)},
                                     "toolsBySender": {"*": {"deny": list(_WT)}}}}}}}},
}


@pytest.mark.parametrize("bindings", [None, [{"agentId": "main", "match": {"channel": "slack"}}]],
                         ids=["no-binding", "route-binding"])
@pytest.mark.parametrize("channels", list(_INVARIANT_CASES.values()), ids=list(_INVARIANT_CASES))
def test_channel_tool_blocks_never_move_the_scope_answer(channels, bindings):
    """Crediting a channel block to a scope is the unsound step, whatever routing says, so
    the scope answer must be the same with every channel-level tools block stripped."""
    cfg = {**_WRITE, "channels": copy.deepcopy(channels)}
    if bindings is not None:
        cfg["bindings"] = bindings
    stripped = {**cfg, "channels": _strip_channel_tool_blocks(cfg["channels"])}
    assert unconfined_write_scopes(cfg, _WT) == unconfined_write_scopes(stripped, _WT) == ["main"]
