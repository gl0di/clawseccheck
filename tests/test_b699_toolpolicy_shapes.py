"""B-699 — `toolpolicy` answers the same thing in both roster shapes.

The B-699 fix routed `toolpolicy._agent_entries` through `collector.agent_roster`, and the
commit records the measurement that made it urgent: with the global confined and one agent
exposed, reading only `agents.list` returned

    scopes_reaching_outside_workspace:  ["agent 'worker'"] -> []
    confined_scopes:                    [False] -> [True]        <- exposed reads as confined

an INVERSION rather than a silence, because both layers this module reads default to the
permissive end. Nothing pinned that: `tests/test_b666_read_reach.py` is a 48-case edge
table written before 2026.8.1 existed and mentions `entries` zero times, so every one of
its cases exercises the shape the fix was NOT about.

This file is the parity pin. It asserts the four public answers are identical for the same
roster expressed either way, and it carries its own non-vacuity control — a battery that
compares two identical computations proves nothing unless at least one case would notice
the roster going missing.
"""
import pytest

from clawseccheck.toolpolicy import (
    confined_scopes,
    read_reaches_outside_workspace,
    scopes_reaching_outside_workspace,
    workspace_only,
)


def _as_entries(cfg):
    """The same roster in the 2026.8.1 record shape.

    The `id` field is DROPPED, not moved into the entry: 2026.8.1 rejects an `id` inside
    an entry (`unrecognized_keys@agents.entries.<k>`), and the record KEY is what the
    runtime resolves the agent to. An entry with no id keeps its positional name so the
    two shapes describe the same roster.
    """
    agents = cfg.get("agents")
    if not isinstance(agents, dict) or not isinstance(agents.get("list"), list):
        return cfg
    entries = {}
    for index, entry in enumerate(agents["list"]):
        if not isinstance(entry, dict):
            continue
        rest = {k: v for k, v in entry.items() if k != "id"}
        key = entry.get("id") if isinstance(entry.get("id"), str) else f"agent{index}"
        entries[key] = rest
    out = dict(cfg)
    out["agents"] = {k: v for k, v in agents.items() if k != "list"}
    out["agents"]["entries"] = entries
    return out


# The case the commit measured, first — global confined, one agent exposed.
_GLOBAL_CONFINED_AGENT_EXPOSED = {
    "tools": {"fs": {"workspaceOnly": True}},
    "agents": {"list": [{"id": "worker", "tools": {"fs": {"workspaceOnly": False}}}]},
}

_BATTERY = [
    ("global-confined-agent-exposed", _GLOBAL_CONFINED_AGENT_EXPOSED),
    ("global-exposed-agent-confined", {
        "tools": {"fs": {"workspaceOnly": False}},
        "agents": {"list": [{"id": "w", "tools": {"fs": {"workspaceOnly": True}}}]}}),
    ("no-global-field-at-all", {
        "agents": {"list": [{"id": "w", "tools": {"fs": {"workspaceOnly": True}}}]}}),
    ("agent-says-nothing", {
        "tools": {"fs": {"workspaceOnly": True}},
        "agents": {"list": [{"id": "w"}]}}),
    ("two-agents-disagree", {
        "tools": {"fs": {"workspaceOnly": True}},
        "agents": {"list": [
            {"id": "a", "tools": {"fs": {"workspaceOnly": False}}},
            {"id": "b", "tools": {"fs": {"workspaceOnly": True}}}]}}),
    ("agent-overrides-the-profile", {
        "tools": {"profile": "minimal", "fs": {"workspaceOnly": True}},
        "agents": {"list": [{"id": "w", "tools": {"profile": "full"}}]}}),
    ("agent-with-a-sandbox", {
        "tools": {"fs": {"workspaceOnly": False}},
        "agents": {"defaults": {"sandbox": {"mode": "all"}},
                   "list": [{"id": "w"}]}}),
    ("empty-roster", {"tools": {"fs": {"workspaceOnly": True}},
                      "agents": {"list": []}}),
]

# NOT in the parity battery, deliberately: an array entry with no `id` has no faithful
# record-shape counterpart. A record entry always HAS a key — that is the shape — so any
# translation of an id-less entry has to invent one, and the two shapes then disagree
# about the agent's NAME (`main` vs the invented key) for a reason that is the harness's
# doing, not the code's. Asserted separately below instead of being papered over.

_ANSWERS = (
    ("workspace_only", workspace_only),
    ("read_reaches_outside_workspace", read_reaches_outside_workspace),
    ("confined_scopes", confined_scopes),
    ("scopes_reaching_outside_workspace", scopes_reaching_outside_workspace),
)


@pytest.mark.parametrize("label,cfg", _BATTERY, ids=[n for n, _c in _BATTERY])
def test_both_roster_shapes_give_the_same_answer(label, cfg):
    other = _as_entries(cfg)
    assert other is not cfg and "entries" in other["agents"], "translation did nothing"
    for name, fn in _ANSWERS:
        assert fn(cfg) == fn(other), f"{label}: {name} differs between roster shapes"


def test_the_translation_actually_produces_the_record_shape():
    """Guards the harness, not the code. A translator that quietly returned its input
    would make every assertion above compare a config with itself."""
    out = _as_entries(_GLOBAL_CONFINED_AGENT_EXPOSED)
    assert "list" not in out["agents"]
    assert out["agents"]["entries"] == {"worker": {"tools": {"fs": {"workspaceOnly": False}}}}


def test_an_entry_id_field_is_dropped_not_carried():
    """2026.8.1 rejects `id` inside an entry, so a translation that kept it would be
    testing a config OpenClaw would refuse to load."""
    out = _as_entries({"agents": {"list": [{"id": "w", "tools": {}}]}})
    assert "id" not in out["agents"]["entries"]["w"]


def test_the_battery_would_notice_the_roster_going_missing():
    """The non-vacuity control. Comparing two computations of the same thing proves
    nothing if neither reads the roster — so at least one battery case must change its
    answer when the roster is removed, in BOTH shapes."""
    noticed_list = noticed_entries = 0
    for _label, cfg in _BATTERY:
        blind = {k: v for k, v in cfg.items() if k != "agents"}
        if scopes_reaching_outside_workspace(cfg) != scopes_reaching_outside_workspace(blind) \
                or confined_scopes(cfg) != confined_scopes(blind):
            noticed_list += 1
        entries = _as_entries(cfg)
        if scopes_reaching_outside_workspace(entries) != scopes_reaching_outside_workspace(blind) \
                or confined_scopes(entries) != confined_scopes(blind):
            noticed_entries += 1
    assert noticed_list, "no battery case reads the roster in the array shape"
    assert noticed_entries, "no battery case reads the roster in the record shape"


def test_an_id_less_array_entry_still_resolves_to_the_default_agent():
    """The case excluded from the battery above, pinned on its own.

    In the legacy array an entry may omit `id`, and the runtime resolves it to the default
    agent — so the honest label is `main`, not a position. B-699 did not change this and
    must not: the record shape cannot express it (a key is mandatory), so the array shape
    is the only place this semantic lives.
    """
    cfg = {"tools": {"fs": {"workspaceOnly": True}},
           "agents": {"list": [{"tools": {"fs": {"workspaceOnly": False}}}]}}
    assert scopes_reaching_outside_workspace(cfg) == ["agent 'main'"]


def test_the_inversion_the_fix_was_about_is_gone():
    """The specific measurement from the B-699 commit, asserted on the NEW shape: an
    exposed agent under a confined global must not read as confined."""
    cfg = _as_entries(_GLOBAL_CONFINED_AGENT_EXPOSED)
    assert scopes_reaching_outside_workspace(cfg) == ["agent 'worker'"]
    assert confined_scopes(cfg) == [False]
