"""F-186 -- B55's "which scopes can actually write outside the workspace" answer.

B55 used to decide, for an UNCONFINED scope that sets its own ``tools`` block, whether the
block "may remove the write family" with a token heuristic. That heuristic was wrong in both
directions (measured by executing the vendor's resolver, not by reading it):

* false FAIL: ``allow:[write]`` + ``deny:[write,edit,apply_patch]``, ``allow:['*']`` +
  ``deny:['group:fs']`` and ``profile:coding`` + ``deny:['group:fs']`` all cannot write, and
  the heuristic convicted them (its allow branch returned before it ever looked at deny);
* false negative: ``profile:messaging`` + ``alsoAllow:[write]`` DOES write, and the heuristic
  read any ``profile`` as narrowing and downgraded it to WARN.

The replacement is not a new model. It COMPOSES two already-validated ones:
``toolgrant.granted`` (does this scope's resolved policy grant tool T -- a port of
``resolveConfiguredToolPolicies`` + ``isToolAllowedByPolicies``) and the per-scope
confinement half of ``toolpolicy`` (``tools.fs.workspaceOnly`` / sandbox). The composition is
a plain AND of the two, so this file grades the PARTS against the vendor and the COMPOSITION
against their conjunction; it does not claim a third vendor oracle.

The battery ``tests/data/write_reach_battery.json`` was captured by EXECUTING the installed
openclaw@2026.9.4 dist BEFORE any of this code existed (so it is not fitted to it), over
every ``fixtures/*/openclaw.json`` that parses non-empty plus a generated edge table, for the
tools the earlier ``toolgrant`` battery never asked about (``fs_write``, ``write_file``,
``writefile``, ``fs_delete``, ``fs_move``) as well as write/edit/apply_patch. Per scope it
records the tools granted (``resolveConfiguredToolPolicies`` -> ``isToolAllowedByPolicies``,
``sandboxMode`` null) and ``resolveEffectiveToolFsWorkspaceOnly``. The suite replays it
offline: no node, no dist.

Deliberately outside the comparison, stated rather than hidden:

* a config with a sandbox block in ``agents`` -- sandbox confinement is a third layer the
  vendor battery does not exercise (it is graded by tests/test_b712_sandbox_three_state.py);
* a scope whose own tools carry ``byProvider``/``toolsBySender`` -- layers this code cannot
  resolve; treating them as possible narrowing is the quiet direction by design.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import clawseccheck.checks as C
from clawseccheck import toolgrant, toolpolicy
from clawseccheck.catalog import FAIL, PASS, WARN
from clawseccheck.collector import agent_roster, collect, dig
from clawseccheck.toolpolicy import unconfined_write_scopes, undecided_write_scopes

ROOT = Path(__file__).resolve().parent.parent
BATTERY = json.loads((Path(__file__).resolve().parent / "data" / "write_reach_battery.json")
                     .read_text(encoding="utf-8"))
TOOLS = BATTERY["tools"]


def _rows():
    for row in BATTERY["fixtures"]:
        cfg = json.loads((ROOT / "fixtures" / row["label"] / "openclaw.json")
                         .read_text(encoding="utf-8"))
        yield row["label"], cfg, row["scopes"]
    for row in BATTERY["edges"]:
        yield row["label"], row["cfg"], row["scopes"]


ROWS = list(_rows())


def _scope_key(sid: str) -> str:
    # "(no id)" is a roster entry with no id: the runtime treats it as the main agent.
    if sid == "(no id)":
        return "main"
    return toolgrant.GLOBAL_SCOPE if sid == "global" else sid


# ------------------------------------------------------------------ battery invariants

def test_battery_is_a_real_sweep():
    assert len(BATTERY["fixtures"]) >= 500
    assert len(BATTERY["edges"]) >= 200
    cells = [(bool(s["granted"]), s["workspaceOnly"]) for _, _, sc in ROWS for s in sc]
    for combo in [(True, False), (True, True), (False, False)]:
        assert sum(1 for c in cells if c == combo) >= 30, combo
    assert TOOLS == ["write", "edit", "apply_patch", "fs_write", "write_file", "writefile",
                     "fs_delete", "fs_move"]
    assert any(t not in ("write", "edit", "apply_patch")
               for _, _, sc in ROWS for s in sc for t in s["granted"]), (
        "the battery never exercises a legacy write name -- it would not test the new tools")


# ------------------------------------------------------------------ half 1: the grant

def test_grant_matches_the_vendor_for_every_write_name():
    bad = []
    n = 0
    for label, cfg, scopes in ROWS:
        for s in scopes:
            for tool in TOOLS:
                n += 1
                got = toolgrant.granted(cfg, tool, _scope_key(s["id"]))
                if got != (tool in s["granted"]):
                    bad.append((label, s["id"], tool, got))
    assert n > 6000
    assert not bad, f"{len(bad)} disagreement(s) with the vendor, first: {bad[:5]}"


# ------------------------------------------------------------------ half 2: the composition

def _has_sandbox(cfg) -> bool:
    return "sandbox" in json.dumps(cfg.get("agents") or {})


def _opaque(tools) -> bool:
    return isinstance(tools, dict) and any(k in tools for k in ("byProvider", "toolsBySender"))


def _expected_scopes(cfg, scopes):
    """Scope NAMES (toolpolicy's normalised form) the vendor data says are granted a write
    tool AND not workspace-confined."""
    roster = agent_roster(cfg)
    tools_of = {(a.id if isinstance(a.id, str) else "(no id)"): (a.entry or {}).get("tools")
                for a in roster}
    out = set()
    for s in scopes:
        if not s["granted"] or s["workspaceOnly"]:
            continue
        if s["id"] == "global":
            # no roster: agents.defaults.tools is this scope's own tools
            defaults = dig(cfg, "agents.defaults.tools") if not roster else None
            if _opaque(defaults):
                continue
            out.add("main")
        else:
            if _opaque(tools_of.get(s["id"])):
                continue
            out.add("main" if s["id"] == "(no id)" else toolpolicy._normalize_agent_id(s["id"]))
    return out


def test_composition_equals_grant_and_not_confined():
    bad = []
    fired = 0
    compared = 0
    for label, cfg, scopes in ROWS:
        if _has_sandbox(cfg):
            continue
        compared += 1
        got = unconfined_write_scopes(cfg, TOOLS)
        want = _expected_scopes(cfg, scopes)
        fired += bool(want)
        if set(got or []) != want:
            bad.append((label, sorted(got or []), sorted(want)))
    assert compared > 500
    assert fired > 100, "non-vacuity: the battery must contain many scopes that ARE reachable"
    assert not bad, f"{len(bad)} disagreement(s), first: {bad[:5]}"


def test_a_constant_grant_would_be_caught_by_the_battery(monkeypatch):
    """Control: a stubbed-out grant model must disagree, or the comparison above is vacuous."""
    monkeypatch.setattr(toolpolicy, "granted", lambda *a, **k: True)
    diffs = 0
    for _label, cfg, scopes in ROWS:
        if _has_sandbox(cfg):
            continue
        if set(unconfined_write_scopes(cfg, TOOLS) or []) != _expected_scopes(cfg, scopes):
            diffs += 1
    assert diffs > 50


# ------------------------------------------------------------------ shape / edge behaviour

def test_no_config_is_none():
    assert unconfined_write_scopes({}, TOOLS) is None
    assert unconfined_write_scopes(None, TOOLS) is None
    assert undecided_write_scopes({}, TOOLS) is None


def test_the_tool_list_is_the_callers_not_a_hardcoded_one():
    cfg = {"tools": {"allow": ["fs_move"]}}
    assert unconfined_write_scopes(cfg, ["fs_move"]) == ["main"]
    assert unconfined_write_scopes(cfg, ["write"]) == []


def test_by_provider_on_the_scope_is_possible_narrowing():
    cfg = {"agents": {"list": [{"id": "w", "tools": {"profile": "coding",
                                                       "byProvider": {"x": {"deny": ["write"]}}}}]}}
    assert unconfined_write_scopes(cfg, TOOLS) == []


def test_raw_agent_id_reaches_the_grant_model():
    """toolgrant's id normaliser is two-branch (``a-`` stays ``a-``); toolpolicy's strips it.
    The grant must be asked with the RAW id, or an entry named ``a-`` is never found."""
    cfg = {"agents": {"list": [{"id": "a-", "tools": {"profile": "coding"}}]}}
    assert unconfined_write_scopes(cfg, TOOLS) == ["a"]


# ------------------------------------------------------------------ an agent id spelled "global"
# "global" is a LEGAL agent id, distinct from ``toolgrant.GLOBAL_SCOPE`` (CLAWSECCHECK-C-561: a
# private sentinel type, not the string "global"). The vendor gives the id no special meaning
# (executed against the installed dist, 2026-09-19: an agent with that id resolves exactly like
# one named ``w``, in both directions below), so a roster row with that id must be asked with
# its string id, never with the ``GLOBAL_SCOPE`` sentinel. Before the sentinel existed, asking
# with the plain string "global" WAS asking with the sentinel (they were the same value) unless
# a caller also passed a now-removed ``agent=True`` keyword — the entry lookup was skipped,
# that agent's own ``tools`` block was ignored, and B55 convicted an agent that cannot write
# (and missed one that can).

def _rename_agent_to_global(cfg, old_id):
    """A deep copy of ``cfg`` in which the ONE list-shape agent ``old_id`` is renamed
    ``global`` -- or None when the rename is not a clean metamorphosis of this config."""
    agents = cfg.get("agents")
    roster = agents.get("list") if isinstance(agents, dict) else None
    if not isinstance(roster, list):
        return None
    hit = [a for a in roster if isinstance(a, dict) and a.get("id") == old_id]
    others = [a.get("id") for a in roster if isinstance(a, dict) and a.get("id") != old_id]
    if len(hit) != 1 or any(toolpolicy._normalize_agent_id(i) == "global" for i in others
                            if isinstance(i, str)):
        return None
    out = json.loads(json.dumps(cfg))
    for a in out["agents"]["list"]:
        if isinstance(a, dict) and a.get("id") == old_id:
            a["id"] = "global"
    return out


def _renamed_grant_disagreements(scope_for_renamed_id="global"):
    """Ask ``toolgrant.granted`` about the renamed agent using ``scope_for_renamed_id`` --
    the string ``"global"`` (its real, spelled-out roster id; the correct call post-C-561)
    by default, or the ``GLOBAL_SCOPE`` sentinel itself (simulating a caller who conflates
    the sentinel with the string it used to equal -- the mirror-image mistake the sentinel
    makes newly possible)."""
    bad, n = [], 0
    for label, cfg, scopes in ROWS:
        for s in scopes:
            if s["id"] in ("global", "(no id)"):
                continue
            renamed = _rename_agent_to_global(cfg, s["id"])
            if renamed is None:
                continue
            for tool in TOOLS:
                n += 1
                got = toolgrant.granted(renamed, tool, scope_for_renamed_id)
                if got != (tool in s["granted"]):
                    bad.append((label, s["id"], tool))
    return bad, n


def test_renaming_an_agent_to_global_never_changes_its_grant():
    """Metamorphic, over the whole vendor battery: only the id string changed, so the vendor
    answer for that scope is the recorded one. Asking with the plain string "global" -- its
    real roster id -- is now, post-C-561, simply the CORRECT call: no flag is needed because
    the sentinel and the string can never collide."""
    bad, n = _renamed_grant_disagreements("global")
    assert n > 1000, "non-vacuity: the battery must contain many renameable agents"
    assert not bad, f"{len(bad)} disagreement(s), first: {bad[:5]}"


def test_the_global_scope_sentinel_alone_would_have_disagreed():
    """Control: asking with the ``GLOBAL_SCOPE`` sentinel itself -- as if the renamed agent's
    id and the global scope were still the same value -- collapses back to the pre-C-561
    collision, so the comparison above is not vacuous. It bites exactly on conflating the
    sentinel with the string "global" it used to equal."""
    bad, _n = _renamed_grant_disagreements(toolgrant.GLOBAL_SCOPE)
    assert bad


def _decisions(cfg):
    """Every caller of ``toolgrant.granted`` that names a roster agent, as plain values: the
    B55/B68 write-tool enumeration (``_capability``) and the alsoAllow/profile widenings
    (``_shared``). The unconfined-scope half is graded by the tests above."""
    from clawseccheck.checks import _agent_tools_widenings
    from clawseccheck.checks._capability import _b55_write_tools_granted, _b68_fs_tools_granted
    return (_b68_fs_tools_granted(cfg), _b55_write_tools_granted(cfg),
            _agent_tools_widenings(cfg))


def test_renaming_an_agent_to_global_changes_no_other_consumer_of_the_grant():
    """Metamorphic, like the grant test, but over the OTHER callers -- the ones that decide
    B55's / B68's "is any write tool granted at all" before the unconfined-scope half is
    reached, and were missed by the first version of this fix. Only the id string changed, so
    each answer must equal the original's (the agent's NAME appears only in evidence text, so
    the comparison is on the tool sets)."""
    def strip(d):
        (b68_tools, b68_enum), (w_tools, w_enum, _view, legacy), (also, powerful) = d
        return (sorted(b68_tools), b68_enum, sorted(w_tools), w_enum, sorted(legacy or []),
                sorted(str(t) for _, t in also), sorted(str(p) for _, p in powerful))

    bad, n = [], 0
    for label, cfg, scopes in ROWS:
        for s in scopes:
            if s["id"] in ("global", "(no id)"):
                continue
            renamed = _rename_agent_to_global(cfg, s["id"])
            if renamed is None:
                continue
            n += 1
            if strip(_decisions(renamed)) != strip(_decisions(cfg)):
                bad.append((label, s["id"]))
    assert n > 100, "non-vacuity: the battery must contain many renameable agents"
    assert not bad, f"{len(bad)} config(s) changed verdict inputs when an agent was renamed " \
                    f"'global', first: {bad[:5]}"


@pytest.mark.parametrize("shape", ["list", "entries"])
def test_an_agent_id_global_granted_write_only_by_alsoallow_is_not_a_pass(shape):
    """The reported shape: global profile ``minimal``, the agent's own ``alsoAllow: [write]``.
    Same verdict for ``global`` as for ``w``; it used to read PASS "no write tool granted"."""
    def cfg(agent_id):
        return {**_OPEN, "tools": {"profile": "minimal"},
                "agents": {"defaults": _SANDBOXED,
                           **_roster(shape, agent_id, {"sandbox": {"mode": "off"},
                                                       "tools": {"alsoAllow": ["write"]}})}}
    control = _b55_for(cfg("w"))
    got = _b55_for(cfg("global"))
    assert got.status == control.status
    assert got.status != PASS


def test_an_agent_id_global_alsoallow_is_seen_by_the_widening_reader():
    from clawseccheck.checks import _agent_tools_widenings
    cfg = {"tools": {"profile": "minimal"},
           "agents": {"list": [{"id": "global", "tools": {"alsoAllow": ["write"]}}]}}
    also, _powerful = _agent_tools_widenings(cfg)
    assert [t for _, t in also] == ["write"]


def _roster(shape, agent_id, w):
    if shape == "list":
        return {"list": [dict(_MAIN, id="main"), dict(w, id=agent_id)]}
    return {"entries": {"main": _MAIN, agent_id: w}}


@pytest.mark.parametrize("shape", ["list", "entries"])
@pytest.mark.parametrize("agent_id", ["w", "global"])
def test_an_agent_id_global_that_cannot_write_is_not_a_fail(shape, agent_id):
    cfg = {**_OPEN, "tools": {"allow": ["write"]},
           "agents": {"defaults": _SANDBOXED,
                      **_roster(shape, agent_id, {"sandbox": {"mode": "off"},
                                                  "tools": {"deny": ["write", "edit",
                                                                     "apply_patch"]}})}}
    assert unconfined_write_scopes(cfg, TOOLS) == []
    assert _b55_for(cfg).status == WARN


@pytest.mark.parametrize("shape", ["list", "entries"])
@pytest.mark.parametrize("agent_id", ["w", "global"])
def test_an_agent_id_global_that_can_write_is_found(shape, agent_id):
    """The reverse direction: the agent's OWN profile grants write under a global profile
    that does not, and the agent is unconfined."""
    cfg = {**_OPEN, "tools": {"profile": "minimal"},
           "agents": {"defaults": _SANDBOXED,
                      **_roster(shape, agent_id, {"sandbox": {"mode": "off"},
                                                  "tools": {"profile": "coding"}})}}
    assert unconfined_write_scopes(cfg, TOOLS) == [agent_id]


def test_the_default_agent_spelled_global_keeps_its_own_tools():
    """The DEFAULT agent is the synthesised no-roster-row case only when no row names it; a
    row spelled "global" that is the default must not fall back to the global scope."""
    cfg = {**_OPEN, "tools": {"allow": ["write"]},
           "agents": {"defaults": {"sandbox": {"mode": "off"}},
                      "list": [{"id": "global", "default": True,
                                "tools": {"deny": ["write", "edit", "apply_patch"]}}]}}
    assert unconfined_write_scopes(cfg, TOOLS) == []


# ------------------------------------------------------------------ B55 verdicts

_OPEN = {"channels": {"telegram": {"dmPolicy": "open", "groupPolicy": "open"}}}
_SANDBOXED = {"sandbox": {"mode": "all"}}
_MAIN = {"default": True}


_TMP_PATH_FACTORY = None


@pytest.fixture(autouse=True, scope="module")
def _tmp_path_factory_bridge(tmp_path_factory):
    """Bridge for `_b55_for()` below, a plain helper called from many test bodies rather
    than a fixture itself — keeps every throwaway home inside pytest's own tmp tree
    instead of system /tmp. Mirrors `_oracle_scratch` in
    tests/test_toolgrant_dist_grounding.py."""
    global _TMP_PATH_FACTORY
    previous = _TMP_PATH_FACTORY
    _TMP_PATH_FACTORY = tmp_path_factory
    yield
    _TMP_PATH_FACTORY = previous


def _b55_for(cfg):
    home = _TMP_PATH_FACTORY.mktemp("f186")
    path = home / "openclaw.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(path, 0o600)
    ctx = collect(home)
    ctx.installed_dist_version = "2026.8.2"
    return next(f for f in C.run_all(ctx) if f.id == "B55")


def _b55_agent(tools, global_allow=("write",), agent_sandbox_off=True):
    w = {"tools": tools}
    if agent_sandbox_off:
        w["sandbox"] = {"mode": "off"}
    return _b55_for({**_OPEN, "tools": {"allow": list(global_allow)},
                     "agents": {"defaults": _SANDBOXED, "entries": {"main": _MAIN, "w": w}}})


@pytest.mark.parametrize("tools,why", [
    ({"allow": ["write"], "deny": ["write", "edit", "apply_patch"]},
     "allow names write, but the same block denies the family"),
    ({"allow": ["*"], "deny": ["group:fs"]}, "wildcard allow minus group:fs"),
    ({"profile": "coding", "deny": ["group:fs"]}, "coding profile minus group:fs"),
], ids=["allow-and-deny", "star-minus-group-fs", "coding-minus-group-fs"])
def test_an_unconfined_agent_that_cannot_write_is_not_a_fail(tools, why):
    """Was a false FAIL: the coarse heuristic looked only at allow (and returned)."""
    f = _b55_agent(tools)
    assert f.status == WARN, why


def test_a_profile_plus_alsoallow_that_grants_write_is_a_fail():
    """Was a false NEGATIVE: any `profile` was read as narrowing, but messaging + alsoAllow
    grants write (executed against the vendor)."""
    f = _b55_agent({"profile": "messaging", "alsoAllow": ["write"]},
                   global_allow=("write", "message"))
    assert f.status == FAIL


@pytest.mark.parametrize("tools", [{}, {"deny": ["exec"]}, {"alsoAllow": ["web_fetch"]}],
                         ids=["empty", "deny-exec", "alsoallow-other"])
def test_an_unconfined_agent_that_inherits_the_grant_still_fails(tools):
    assert _b55_agent(tools).status == FAIL


def test_a_confined_agent_is_still_a_warn():
    f = _b55_for({**_OPEN, "tools": {"allow": ["write"], "fs": {"workspaceOnly": True}},
                  "agents": {"defaults": _SANDBOXED, "entries": {"main": _MAIN, "w": {}}}})
    assert f.status == WARN


@pytest.mark.parametrize("name", ["fs_write", "write_file", "writefile", "fs_delete", "fs_move"])
def test_a_legacy_write_name_granted_to_an_unconfined_agent_fails(name):
    f = _b55_for({**_OPEN, "tools": {"allow": [name]},
                  "agents": {"defaults": _SANDBOXED,
                             "entries": {"main": _MAIN, "w": {"sandbox": {"mode": "off"}}}}})
    assert f.status == FAIL


def test_the_designed_bad_fixture_still_fails():
    cfg = json.loads((ROOT / "fixtures" / "bad_b55_fs_write_broad" / "openclaw.json")
                     .read_text(encoding="utf-8"))
    assert _b55_for(cfg).status == FAIL


def test_the_clean_evidence_names_what_was_established():
    f = _b55_agent({"allow": ["write"], "deny": ["write", "edit", "apply_patch"]})
    assert f.status == WARN
    assert any("granted a write tool" in e for e in (f.evidence or []))
