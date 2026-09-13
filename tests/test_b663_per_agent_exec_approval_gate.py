"""CLAWSECCHECK-B-663 — B8 affirmed "Destructive actions require human approval" while a
named agent's own `tools.exec` override left it with no gate at all.

`check_human_approval` (B8) used to read only the GLOBAL `tools.exec` layer. OpenClaw
resolves the policy an agent actually runs under by layering `agents.list[]`/
`agents.entries` `tools.exec` OVER the global one, and the agent layer WINS -- so an
agent could sit outside a gate the owner set globally while B8 kept affirming the gate
held. This file pins the five repro rows from the bug report (measured against the
pre-fix `dev` tree, `check_human_approval` called directly on constructed configs),
including the positive control (row 1: B8 *can* WARN, so this was never a dead check).

Grounded against the INSTALLED openclaw@2026.9.4 dist (re-verified for this fix; the
task's original citations were against 2026.7.1-2 and had already gone stale once, per
the task's own re-grounding comment against 2026.8.2):

  * `resolveNodeExecConfigPolicy` (`daemon-DW2kkFGl.mjs:1520`):
    `applyExecPolicyLayer(applyExecPolicyLayer(defaults, globalExec), agentExec)`
  * `applyExecPolicyLayer` (`exec-policy-Dbl6pUSh.mjs:4`) -- confirmed UNCHANGED from the
    original citation, including the "mode-deletion" subtlety: when a layer sets only
    `security`/`ask` (no `mode`), the BASE's `mode` key is deleted outright rather than
    surviving underneath the override. This is row 3 below, and the one a naive
    "merge the two raw dicts" fix would get wrong.
  * `resolveExecPolicyForMode` (`exec-approvals-core-BZ3ECkXD.mjs:53`) -- the closed
    5-row mode table, unchanged.
  * `resolveAgentConfig` / `normalizeAgentId` (`agent-scope-config-Bh5RAia-.mjs`,
    `agent-id-GA8mwdTG.mjs`) -- first roster entry whose NORMALISED (lowercased) id
    matches wins; a later entry with a colliding normalised id is unreachable and must
    not be read. `toolgrant._normalize_agent_id` already ports this and is reused here
    rather than a second copy.

Fix lives in `clawseccheck/checks/_shared.py` (`_layer_exec_policy`,
`_exec_policy_is_gated`, `_agents_without_exec_gate`) and
`clawseccheck/checks/_lifecycle.py` (`check_human_approval`'s new per-agent branch).
`_has_approval_gate` itself (the GLOBAL-scope predicate) is UNCHANGED -- see
`tests/test_b08.py`, which must stay green untouched.

C-303 note: the real fleet's `tools` block carries only `profile`/`web` -- no
`tools.exec` anywhere, global or per-agent -- so `fleet_fp_gate.py compare` is
structurally incapable of exercising this (same as the bug report's own DoD says).
Verification here is entirely via constructed configs, which is the sanctioned vehicle
for this specific gap.
"""
from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, WARN
from clawseccheck.checks import (
    _agents_without_exec_gate,
    _exec_policy_is_gated,
    _has_approval_gate,
    _layer_exec_policy,
    check_human_approval,
)
from clawseccheck.checks import _lifecycle as _lifecycle_mod
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def _agent_cfg(global_exec: dict, *agents: dict) -> dict:
    """One `tools.exec` global block plus N `agents.list[]` entries, each
    `{"id": ..., "exec": {...}}` (or `{"id": ..., "exec": None}` for "no override")."""
    roster = []
    for a in agents:
        entry = {"id": a["id"]}
        if a.get("exec") is not None:
            entry["tools"] = {"exec": a["exec"]}
        roster.append(entry)
    return {"tools": {"exec": global_exec}, "agents": {"list": roster}}


# ---------------------------------------------------------------------------
# The five repro rows from the bug report, pinned exactly (measured against the
# pre-fix tree; rows 3-5 were the false PASS this task exists to close).
# ---------------------------------------------------------------------------

def test_row1_mode_full_no_gate_anywhere_warns_positive_control():
    """Positive control: B8 CAN still WARN with no per-agent layer involved at all --
    this is not a dead check that always PASSes once destructive tools are detected."""
    f = check_human_approval(_ctx({"tools": {"exec": {"mode": "full"}}}))
    assert f.status == WARN
    assert "no clear approval gate" in f.detail


def test_row2_mode_ask_global_gate_passes():
    f = check_human_approval(_ctx({"tools": {"exec": {"mode": "ask"}}}))
    assert f.status == PASS
    assert f.detail == "Destructive actions require human approval."


def test_row3_mode_ask_plus_agent_security_full_warns():
    """THE MODE-DELETION ROW. Global `mode: "ask"` resolves to
    (security=allowlist, ask=on-miss). The agent sets ONLY `security: "full"` -- no
    `mode` key -- which per `applyExecPolicyLayer` DELETES the inherited `mode` and
    replaces security/ask wholesale: security="full" (from the agent), ask="on-miss"
    (inherited, since the agent didn't set ask). That resolves to UNGATED. A fix that
    instead let the global's `mode` win over this per-field override would still say
    PASS here -- this is the row a naive "merge the raw dicts" implementation misses."""
    cfg = _agent_cfg({"mode": "ask"}, {"id": "main", "exec": {"security": "full"}})
    f = check_human_approval(_ctx(cfg))
    assert f.status == WARN, f"expected WARN (mode-deletion), got {f.status}: {f.detail}"
    assert "main" in f.detail


def test_row4_mode_ask_plus_agent_mode_full_warns():
    cfg = _agent_cfg({"mode": "ask"}, {"id": "main", "exec": {"mode": "full"}})
    f = check_human_approval(_ctx(cfg))
    assert f.status == WARN
    assert "main" in f.detail


def test_row5_mode_deny_plus_agent_mode_full_warns():
    """The starkest row: the owner set `deny` globally, one named agent is `full`."""
    cfg = _agent_cfg({"mode": "deny"}, {"id": "main", "exec": {"mode": "full"}})
    f = check_human_approval(_ctx(cfg))
    assert f.status == WARN
    assert "main" in f.detail


# ---------------------------------------------------------------------------
# Two agents: one narrowed (still gated), one widened (ungated) relative to the
# global. The narrowed one must not fire -- only the widened one should be named.
# ---------------------------------------------------------------------------

def test_two_agents_narrowed_and_widened_only_the_widened_one_fires():
    cfg = _agent_cfg(
        {"mode": "ask"},
        {"id": "narrow", "exec": {"mode": "deny"}},
        {"id": "wide", "exec": {"mode": "full"}},
    )
    f = check_human_approval(_ctx(cfg))
    assert f.status == WARN
    assert "wide" in f.detail
    assert "narrow" not in f.detail


def test_two_agents_both_narrowed_still_passes():
    cfg = _agent_cfg(
        {"mode": "ask"},
        {"id": "a", "exec": {"mode": "deny"}},
        {"id": "b", "exec": {"mode": "allowlist"}},
    )
    f = check_human_approval(_ctx(cfg))
    assert f.status == PASS


# ---------------------------------------------------------------------------
# Agent-id collision after normalisation ("Main" vs "main"): first match wins, the
# shadowed entry must not be read at all -- in EITHER direction.
# ---------------------------------------------------------------------------

def test_id_collision_first_entry_ungated_wins_even_though_shadowed_one_is_gated():
    """"Main" (first, ungated) shadows "main" (second, gated). The real runtime
    resolves the agent id "main" to the FIRST roster entry whose normalised id
    matches -- "Main" -- so the effective policy is ungated and B8 must WARN, naming
    the entry as authored ("Main"), not the normalised form."""
    cfg = _agent_cfg(
        {"mode": "ask"},
        {"id": "Main", "exec": {"mode": "full"}},
        {"id": "main", "exec": {"mode": "deny"}},
    )
    f = check_human_approval(_ctx(cfg))
    assert f.status == WARN
    assert "Main" in f.detail


def test_id_collision_shadowed_ungated_entry_is_unreachable_and_must_not_fire():
    """The reverse: "Main" (first, gated) shadows "main" (second, ungated). The second
    entry is UNREACHABLE at runtime -- resolveAgentConfig only ever sees "Main" for the
    id "main" -- so it must not be read, even though it looks dangerous on paper."""
    cfg = _agent_cfg(
        {"mode": "ask"},
        {"id": "Main", "exec": {"mode": "deny"}},
        {"id": "main", "exec": {"mode": "full"}},
    )
    f = check_human_approval(_ctx(cfg))
    assert f.status == PASS, (
        f"the shadowed 'main' entry must be invisible; got {f.status}: {f.detail}"
    )


# ---------------------------------------------------------------------------
# agents.entries (2026.8.1+ record roster shape) -- must be read exactly like
# agents.list, via collector.agent_roster (B-699).
# ---------------------------------------------------------------------------

def test_agents_entries_record_shape_widened_agent_warns():
    cfg = {
        "tools": {"exec": {"mode": "deny"}},
        "agents": {"entries": {"web": {"tools": {"exec": {"mode": "full"}}}}},
    }
    f = check_human_approval(_ctx(cfg))
    assert f.status == WARN
    assert "web" in f.detail


# ---------------------------------------------------------------------------
# An agent with no override at all inherits the (already-checked) global policy and
# must never be named.
# ---------------------------------------------------------------------------

def test_agent_with_no_override_inherits_global_and_is_not_named():
    cfg = _agent_cfg({"mode": "ask"}, {"id": "quiet", "exec": None})
    assert _agents_without_exec_gate(cfg) == []
    assert check_human_approval(_ctx(cfg)).status == PASS


def test_agent_with_empty_dict_override_is_a_noop_like_no_layer_at_all():
    """`applyExecPolicyLayer` early-returns `base` unless the layer sets `mode` or an
    explicit `security`/`ask` -- an empty `{}` sets neither, so it must not be read as
    "explicit full/ungated", the failure shape a bare `if agent_exec:` truthiness
    check would produce for `{}` in some other languages (not Python, but worth
    pinning since `{}` is a real value `tools.exec` can hold on a hand-edited file)."""
    cfg = _agent_cfg({"mode": "ask"}, {"id": "x", "exec": {}})
    assert _agents_without_exec_gate(cfg) == []


# ---------------------------------------------------------------------------
# Never FAIL -- B8 has no FAIL branch, per catalog.
# ---------------------------------------------------------------------------

def test_never_fail():
    configs = [
        {},
        {"tools": {"exec": {"mode": "full"}}},
        _agent_cfg({"mode": "ask"}, {"id": "main", "exec": {"security": "full"}}),
        _agent_cfg({"mode": "deny"}, {"id": "main", "exec": {"mode": "full"}}),
        {"tools": {"exec": {"mode": "ask"}}, "agents": {"list": [None, "garbage", 42]}},
        {"tools": {"exec": {"mode": "ask"}},
         "agents": {"list": [{"id": 123, "tools": {"exec": {"mode": "full"}}}]}},
        {"tools": {"exec": {"mode": "ask"}},
         "agents": {"list": [{"id": "", "tools": {"exec": {"mode": "full"}}}]}},
        {"tools": {"exec": {"mode": "ask"}},
         "agents": {"list": [{"id": "x", "tools": "not-a-dict"}]}},
        {"tools": {"exec": {"mode": "ask"}},
         "agents": {"list": [{"id": "x", "tools": {"exec": ["garbage"]}}]}},
        {"tools": {"exec": {"mode": "ask"}},
         "agents": {"list": [{"id": "x", "tools": {"exec": {"mode": 123}}}]}},
        {"tools": {"exec": {"mode": "ask"}}, "agents": {"entries": None}},
        {"tools": {"exec": {"mode": "ask"}}, "agents": "garbage"},
        {"tools": {"exec": {"mode": "ask"}}, "agents": {"list": "garbage"}},
    ]
    for cfg in configs:
        f = check_human_approval(_ctx(cfg))
        assert f.status != FAIL, f"unexpected FAIL for {cfg}: {f.detail}"


# ---------------------------------------------------------------------------
# Direct unit tests of the new helpers (mirrors test_b08.py's own direct
# _has_approval_gate unit tests).
# ---------------------------------------------------------------------------

def test_layer_exec_policy_mode_replaces_the_whole_pair():
    assert _layer_exec_policy("full", "off", {"mode": "deny"}) == ("deny", "off")
    assert _layer_exec_policy("deny", "on-miss", {"mode": "full"}) == ("full", "off")


def test_layer_exec_policy_security_only_deletes_the_inherited_mode_identity():
    """The mode-deletion subtlety, isolated from check_human_approval: layering
    `{"security": "full"}` over a base already carrying `ask="on-miss"` (as if a
    `mode: "ask"` had produced it) keeps that inherited `ask`, but the "mode" identity
    itself is gone -- the result is exactly (security, ask), never re-derived from a
    stale mode."""
    assert _layer_exec_policy("allowlist", "on-miss", {"security": "full"}) == (
        "full", "on-miss")


def test_layer_exec_policy_ask_only_keeps_base_security():
    assert _layer_exec_policy("allowlist", "off", {"ask": "always"}) == (
        "allowlist", "always")


def test_layer_exec_policy_empty_or_absent_layer_is_a_noop():
    assert _layer_exec_policy("full", "off", {}) == ("full", "off")
    assert _layer_exec_policy("full", "off", None) == ("full", "off")


def test_layer_exec_policy_unrecognized_mode_string_falls_through_to_security_ask():
    """A `mode` OpenClaw does not accept is not in `_EXEC_MODE_SECURITY_ASK`, so it must
    not raise/KeyError -- it falls through to the security/ask branch (both absent
    here, so this is a pure no-op, same as an empty layer)."""
    assert _layer_exec_policy("full", "off", {"mode": "bogus"}) == ("full", "off")


def test_exec_policy_is_gated_matches_the_mode_table_boundary():
    # Every _EXEC_MODE_SECURITY_ASK output except "full" is gated.
    assert _exec_policy_is_gated("deny", "off") is True
    assert _exec_policy_is_gated("allowlist", "off") is True
    assert _exec_policy_is_gated("allowlist", "on-miss") is True
    assert _exec_policy_is_gated("full", "off") is False
    # "full" + ask="always" is the one full-security state that IS gated (every
    # request is prompted regardless of the allow list).
    assert _exec_policy_is_gated("full", "always") is True


def test_agents_without_exec_gate_names_every_ungated_agent_not_just_the_first():
    cfg = _agent_cfg(
        {"mode": "ask"},
        {"id": "a", "exec": {"mode": "full"}},
        {"id": "b", "exec": {"mode": "full"}},
        {"id": "c", "exec": {"mode": "deny"}},
    )
    assert _agents_without_exec_gate(cfg) == ["a", "b"]


# ---------------------------------------------------------------------------
# `_has_approval_gate` (the GLOBAL-scope predicate) is untouched by this fix --
# test_b08.py already pins it directly; this is a light smoke check that it still
# agrees with the resolved-triple helper on the plain global-only cases.
# ---------------------------------------------------------------------------

def test_has_approval_gate_unchanged_for_global_only_configs():
    assert _has_approval_gate({"tools": {"exec": {"mode": "ask"}}}) is True
    assert _has_approval_gate({"tools": {"exec": {"mode": "full"}}}) is False


# ---------------------------------------------------------------------------
# Mutation test: if `check_human_approval` stopped calling the per-agent walk (i.e.
# this fix were reverted), the WRONG rows from the bug report would silently go back
# to PASS. Prove the test suite actually depends on the new code path by patching it
# out and confirming the reverted behavior reproduces exactly the bug this task closes
# -- so the passing tests above are not vacuously green.
# ---------------------------------------------------------------------------

def test_mutation_reverting_the_per_agent_walk_reproduces_the_original_bug(monkeypatch):
    monkeypatch.setattr(_lifecycle_mod, "_agents_without_exec_gate", lambda cfg: [])
    cfg = _agent_cfg({"mode": "ask"}, {"id": "main", "exec": {"mode": "full"}})
    f = check_human_approval(_ctx(cfg))
    assert f.status == PASS, (
        "with the per-agent walk stubbed out, check_human_approval must reproduce the "
        "original B-663 bug (a false PASS) -- if it doesn't, check_human_approval no "
        "longer calls _agents_without_exec_gate at all, which this test exists to catch"
    )


def test_mutation_control_the_real_row5_config_would_have_failed_under_the_stub(monkeypatch):
    """Same stub as above, applied to the starkest repro row (global deny, agent
    full), spelled out separately so a reviewer can see the exact before/after this
    task fixed without cross-referencing the earlier row5 test."""
    cfg = _agent_cfg({"mode": "deny"}, {"id": "main", "exec": {"mode": "full"}})
    # Unpatched: the fix is live, so this must WARN (already asserted by
    # test_row5_mode_deny_plus_agent_mode_full_warns, re-asserted here for locality).
    assert check_human_approval(_ctx(cfg)).status == WARN
    monkeypatch.setattr(_lifecycle_mod, "_agents_without_exec_gate", lambda cfg: [])
    assert check_human_approval(_ctx(cfg)).status == PASS


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
