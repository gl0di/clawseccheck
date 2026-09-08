"""Both agent-roster shapes must produce the same verdict, or the audit lies about agents.

OpenClaw 2026.8.1 replaced `agents.list` (an ARRAY whose entries carry an `id` field) with
`agents.entries` (a RECORD keyed by id, which REJECTS an `id` field inside an entry). We read
only the array, so on a 2026.8.1 config every per-agent check saw an empty roster -- and
several then asserted a CLEAN verdict about it, on configs our own fixtures call dangerous:

    fixtures/bad_b4_peragent_sandbox               B4   FAIL -> PASS "Execution is sandboxed."
    fixtures/warn_b409_profile_alsoallow_widening  A1   WARN -> PASS   (also B55, B68)
    fixtures/bad_b283_fs_per_agent_optout          B68  WARN -> PASS
    fixtures/bad_b351_codemode_agent_only          B351 WARN -> PASS

A1 is the lethal-trifecta headline check. That is Golden Rule #4 -- a positive assertion about
a setting the check never read -- so the equivalence sweep below is the test that matters: it
compares the WHOLE finding set of every agent-declaring fixture in both shapes, rather than
naming checks one at a time. A new per-agent check cannot regress silently past it.

`agent_roster` is a faithful port of `readAgentRosterProperty` + `listAgentEntriesWithSource`
(`dist/agent-scope-config-*.js`), whose semantics were EXECUTED rather than read. The table
below is not hand-written: it is the vendor's own answers, recorded from a differential run
against the installed 2026.8.1 dist over these cases plus all 67 agent-declaring fixture
configs -- 84 comparisons, zero disagreements. Two rows are traps a careful reading got WRONG
before the measurement:

* `entries-own-id` -- the KEY wins over an entry's own `id` (`{...entry, id}`). The legacy
  module still carries the opposite (`Object.assign({id}, entry)`); the modern one governs.
* `entries-null` / `entries-not-record` -- `entries` is chosen when the KEY is present, not
  when its value is usable, and the `list` beside it is NOT consulted. "Try entries, else
  list" would disagree with the runtime about which agents exist.

Offline, stdlib only, writes nothing outside tmp_path. Running node is deliberately NOT part
of the shipped test -- the same arrangement as tests/test_b666_read_reach.py, whose 48-case
table came from an out-of-band differential run for the same reason.
"""
from __future__ import annotations

import copy
import json
import os

import pytest

from clawseccheck.checks import run_all
from clawseccheck.collector import agent_roster, collect

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (label, config, expected [(id, path), ...]) -- recorded from the installed 2026.8.1 dist.
_VENDOR_TABLE = [
    ("agents-array", {"agents": []}, []),
    ("agents-missing", {}, []),
    ("agents-not-object", {"agents": "x"}, []),
    ("entries-and-list", {"agents": {"entries": {"a": {}}, "list": [{"id": "b"}]}},
     [("a", "agents.entries.a")]),
    ("entries-bad-values", {"agents": {"entries": {"a": "x", "b": {}, "c": []}}},
     [("b", "agents.entries.b")]),
    ("entries-default-mark", {"agents": {"entries": {"a": {"default": True}, "b": {}}}},
     [("a", "agents.entries.a"), ("b", "agents.entries.b")]),
    ("entries-empty", {"agents": {"entries": {}}}, []),
    ("entries-not-record", {"agents": {"entries": "junk", "list": [{"id": "b"}]}}, []),
    ("entries-null", {"agents": {"entries": None, "list": [{"id": "b"}]}}, []),
    ("entries-own-id", {"agents": {"entries": {"web": {"id": "OTHER"}}}},
     [("web", "agents.entries.web")]),
    ("entries-plain", {"agents": {"entries": {"web": {"workspace": "/w"}, "api": {}}}},
     [("web", "agents.entries.web"), ("api", "agents.entries.api")]),
    ("entries-upper-key", {"agents": {"entries": {"WeB": {}}}},
     [("WeB", "agents.entries.WeB")]),
    ("list-holes", {"agents": {"list": [None, {"id": "a"}, "x", 0, {"id": "b"}]}},
     [("a", "agents.list[1]"), ("b", "agents.list[4]")]),
    ("list-no-id", {"agents": {"list": [{"workspace": "/w"}]}},
     [(None, "agents.list[0]")]),
    ("list-not-array", {"agents": {"list": {"a": {}}}}, []),
    ("list-null", {"agents": {"list": None}}, []),
    ("list-plain", {"agents": {"list": [{"id": "a"}, {"id": "b"}]}},
     [("a", "agents.list[0]"), ("b", "agents.list[1]")]),
]


@pytest.mark.parametrize("label,cfg,expected", _VENDOR_TABLE,
                         ids=[row[0] for row in _VENDOR_TABLE])
def test_roster_matches_the_vendor_resolver(label, cfg, expected):
    """Every row is what `listAgentEntriesWithSource` actually returned, not what the
    function looks like it should return."""
    assert [(a.id, a.path) for a in agent_roster(cfg)] == expected, label


def test_the_table_covers_both_shapes_and_their_failure_modes():
    """Anti-vacuity. A table that lost its `entries` rows would still pass every row above
    while proving nothing about the shape this whole task exists for."""
    labels = {row[0] for row in _VENDOR_TABLE}
    assert {"entries-plain", "entries-own-id", "entries-null", "entries-and-list",
            "list-plain", "list-holes"} <= labels
    seen = {p.rsplit(".", 1)[0] if p.startswith("agents.entries") else "agents.list"
            for _l, _c, exp in _VENDOR_TABLE for _i, p in exp}
    assert "agents.entries" in seen and "agents.list" in seen


def test_the_entry_carries_its_id_so_existing_readers_keep_working():
    """The record shape has no `id` field; the port injects it, as the vendor does. Without
    that, every `agent.get("id")` in the tree silently returns None on a 2026.8.1 config."""
    (only,) = agent_roster({"agents": {"entries": {"web": {"workspace": "/w"}}}})
    assert only.entry["id"] == "web"
    assert only.entry["workspace"] == "/w"


def test_the_callers_config_is_not_mutated():
    """`entry` is a NEW dict for the record shape. Injecting into the caller's object would
    write back an `id` field that the schema rejects inside an entry."""
    cfg = {"agents": {"entries": {"web": {}}}}
    agent_roster(cfg)
    assert cfg == {"agents": {"entries": {"web": {}}}}


# --------------------------------------------------- the equivalence sweep that matters

def _to_entries_shape(cfg):
    """The same config, expressed the way OpenClaw 2026.8.1 requires, or None."""
    out = copy.deepcopy(cfg)
    agents = out.get("agents")
    if not isinstance(agents, dict) or not isinstance(agents.get("list"), list):
        return None
    entries = {}
    for i, e in enumerate(agents["list"]):
        if not isinstance(e, dict):
            continue
        key = e.get("id") if isinstance(e.get("id"), str) else "agent" + str(i)
        entries[key] = {k: v for k, v in e.items() if k != "id"}
    if not entries:
        return None
    agents.pop("list")
    agents["entries"] = entries
    return out


def _agent_fixtures():
    root = os.path.join(REPO_ROOT, "fixtures")
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in sorted(filenames):
            if not name.endswith(".json"):
                continue
            path = os.path.join(dirpath, name)
            try:
                with open(path, encoding="utf-8") as fh:
                    cfg = json.load(fh)
            except Exception:
                continue
            if isinstance(cfg, dict) and _to_entries_shape(cfg) is not None:
                yield os.path.relpath(path, root), cfg


_FIXTURES = sorted(_agent_fixtures())


def _verdicts(tmp_path, cfg, tag):
    home = tmp_path / tag
    home.mkdir(parents=True, exist_ok=True)
    target = home / "openclaw.json"
    target.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(str(target), 0o600)
    return {f.id: f.status for f in run_all(collect(str(home)))}


@pytest.mark.parametrize("name,cfg", _FIXTURES, ids=[n for n, _c in _FIXTURES])
def test_the_same_config_gets_the_same_verdicts_in_either_shape(tmp_path, name, cfg):
    """The whole finding set, not a named check. This is what caught the fake PASSes: a
    per-check assertion only covers the checks someone remembered to name."""
    old = _verdicts(tmp_path, cfg, "old")
    new = _verdicts(tmp_path, _to_entries_shape(cfg), "new")
    moved = {k: (old.get(k), new.get(k)) for k in set(old) | set(new)
             if old.get(k) != new.get(k)}
    assert not moved, (name, moved)


def test_the_sweep_is_not_vacuous():
    """It must actually be looking at agent-declaring fixtures. An empty list would make
    every assertion above pass while testing nothing."""
    assert len(_FIXTURES) >= 15, len(_FIXTURES)


@pytest.mark.parametrize("name", [
    "bad_b4_peragent_sandbox", "warn_b409_profile_alsoallow_widening",
    "bad_b283_fs_per_agent_optout", "bad_b351_codemode_agent_only",
])
def test_the_four_fixtures_that_went_clean_are_in_the_sweep(name):
    """The regression's own witnesses, named so a future fixture rename cannot quietly drop
    them out of the parametrize above."""
    assert any(n.split(os.sep)[0] == name for n, _c in _FIXTURES), name
