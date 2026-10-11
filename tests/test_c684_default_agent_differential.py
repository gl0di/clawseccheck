"""C-684 — the three "which agent is the default" rules, graded by EXECUTING the vendor.

``collector._default_agent_id`` (B-610 workspace derivation), ``skillprovenance._default_agent_id``
(its leaf copy) and ``toolpolicy._default_agent_id`` (the agent a "global" surface belongs to) all
used one rule: the first entry whose ``default`` is truthy, else ``agents[0]``. That is the
shape of a vendor function that no longer exists in that form, and none of the three was ever
compared with what the installed OpenClaw does. This file does the comparison, by running the
vendor's own functions in node over a generated battery (``tests/_toolgrantoracle._rewrite`` is
the same mechanical import-rewrite the tool-grant oracle uses; the bodies are the vendor's
bytes). Expected values below come from that execution and from nothing else.

WHICH VENDOR FUNCTION EACH COPY MIRRORS (measured, not read):

* collector and skillprovenance derive WORKSPACE DIRECTORIES, so the function is
  ``resolveAgentWorkspaceDir`` (the agent runtime's). It decides "the plain workspace
  belongs to agent X" with ``tryResolveLegacyDataOwnerAgentId`` = ONE raw ``default === true``
  marker (not under ``ownership: "explicit"``), else the SOLE agent, else NOBODY: with two
  or more agents and no unique marker every agent gets a derived directory. There is no
  ``agents[0]`` fallback in it. (``resolveMemoryHostAgentWorkspaceDir`` in ``config-utils-*``
  does keep an ``agents[0]`` fallback - the old rule's actual ancestor - but that one places
  the MEMORY-SEARCH workspace, not the agent's. ``test_the_memory_host_variant_is_a_different_function``
  pins that the two disagree, so nobody re-points the port at the wrong one.)
* toolpolicy asks which agent the un-scoped ("global") surface runs as. The vendor expression
  is ``resolveSessionAgentIdStrict`` with no selected agent: ``tryResolveLegacyDataOwnerAgentId(cfg)
  ?? resolveDefaultAgentId(cfg)``. Where that has no answer it THROWS
  (``AgentSelectionRequiredError``), and a port cannot copy a throw: those rows are the
  UNDETERMINED set, enumerated and pinned below instead of being given an invented answer.

Local-only: skipped wherever node or the installed dist is absent.
"""
from __future__ import annotations

import copy
import functools
import itertools
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from _distgrounding import SEALED_BUNDLES, require_dist

import _toolgrantoracle as oracle
from clawseccheck import collector, skillprovenance, toolpolicy

# --------------------------------------------------------------------------- the oracle

#: module role -> (declaration regex, names to export by their real names)
_MODULES = {
    "scope": (r"^function resolveAgentWorkspaceDir\(",
              ["resolveAgentWorkspaceDir", "resolveDefaultAgentId",
               "tryResolveLegacyDataOwnerAgentId"]),
    "roster": (r"^function tryResolveRawLegacyDefaultAgentId\(",
               ["tryResolveRawLegacyDefaultAgentId", "listAgentEntries"]),
    "utils": (r"^function resolveMemoryHostAgentWorkspaceDir\(",
              ["resolveMemoryHostAgentWorkspaceDir"]),
}

_HARNESS = r"""
import { readFileSync } from "node:fs";
const inp = JSON.parse(readFileSync(0, "utf8"));
const M = {};
for (const [role, file] of Object.entries(inp.modules)) M[role] = await import("file://" + file);
const attempt = (f) => {
  try { const v = f(); return v === undefined ? null : v; }
  catch (e) { return "THROWS:" + (e && e.name ? e.name : "?"); }
};
const rows = [];
for (const { label, cfg } of inp.rows) {
  const env = { HOME: inp.home };
  const entries = attempt(() => M.roster.listAgentEntries(cfg)) || [];
  rows.push({
    label,
    // `session_main` is resolveSessionAgentIdStrict's own expression for "no agent selected".
    session_main: attempt(() => M.scope.tryResolveLegacyDataOwnerAgentId(cfg)
      ?? M.scope.resolveDefaultAgentId(cfg)),
    // Arrays, not id-keyed objects: a nameless entry has no key to be filed under.
    core: entries.map((e) => ({
      id: typeof e.id === "string" ? e.id : null,
      ws: attempt(() => M.scope.resolveAgentWorkspaceDir(cfg, e.id, env)),
    })),
    memory: entries.map((e) => attempt(() => M.utils.resolveMemoryHostAgentWorkspaceDir(cfg, e.id, env))),
  });
}
process.stdout.write(JSON.stringify(rows));
"""


@functools.lru_cache(maxsize=None)
def _locate(dist: Path, role: str) -> Path:
    pattern = _MODULES[role][0]
    symbol = re.search(r"function (\w+)", pattern).group(1).encode()
    rx = re.compile(pattern.encode(), re.M)
    hits = []
    for path in sorted(dist.glob("*.mjs")):
        if path.name in SEALED_BUNDLES:
            continue
        data = path.read_bytes()
        if symbol in data and rx.search(data):
            hits.append(path)
    assert len(hits) == 1, (
        f"{len(hits)} bundle(s) declare {pattern!r} ({[p.name for p in hits]}); the {role!r} "
        f"module needs exactly one - re-locate it with `grep -rlE {pattern!r} {dist}`")
    return hits[0]


def _execute(rows, scratch: Path) -> "tuple[list, str]":
    dist = require_dist()
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed - this differential executes the vendor")
    home = scratch / "home"
    home.mkdir()
    modules = {}
    for role, (_, exports) in _MODULES.items():
        target = scratch / f"{role}.mjs"
        target.write_text(oracle._rewrite(_locate(dist, role), exports, dist), encoding="utf-8")
        modules[role] = str(target)
    (scratch / "harness.mjs").write_text(_HARNESS, encoding="utf-8")
    payload = json.dumps({"modules": modules, "home": str(home),
                          "rows": [{"label": lab, "cfg": cfg} for lab, cfg in rows]})
    env = {"HOME": str(home), "PATH": os.environ.get("PATH", ""), "LANG": "C"}
    proc = subprocess.run([node, str(scratch / "harness.mjs")], input=payload,
                          capture_output=True, text=True, env=env, cwd=str(scratch), timeout=180)
    assert proc.returncode == 0, f"node exited {proc.returncode}: {proc.stderr.strip()[-600:]}"
    return json.loads(proc.stdout), str(home / ".openclaw")


# --------------------------------------------------------------------------- the battery

#: What an agent's ``default`` field can hold. ``True`` is the only value the vendor honours.
_MARKERS = ("absent", True, False, None, "yes", 1, "true")


def _entry(agent_id: str, marker) -> dict:
    entry: dict = {"id": agent_id}
    if marker != "absent":
        entry["default"] = marker
    return entry


def _shape(entries: "list[dict]", shape: str) -> dict:
    """The same roster written as ``agents.list`` or as the 2026.8.1 ``agents.entries`` record."""
    if shape == "list":
        return {"list": entries}
    return {"entries": {e["id"]: {k: v for k, v in e.items() if k != "id"} for e in entries}}


def _battery() -> "list[tuple[str, dict]]":
    rows: "list[tuple[str, dict]]" = [
        ("no agents key", {}),
        ("agents without roster", {"agents": {}}),
        ("empty list", {"agents": {"list": []}}),
        ("empty entries", {"agents": {"entries": {}}}),
        ("entries null", {"agents": {"entries": None, "list": [{"id": "b"}]}}),
    ]
    ids = ("main", "b", "c")
    for count in (1, 2, 3):
        # Three agents x every marker would be 343 rows per shape; the values that matter
        # (honoured, falsy, truthy-but-not-true, absent) are kept for the third agent.
        pool = _MARKERS if count < 3 else ("absent", True, False, "yes")
        for markers in itertools.product(pool, repeat=count):
            roster = [_entry(i, m) for i, m in zip(ids, markers)]
            for shape in ("list", "entries"):
                for ownership in (None, "explicit", "implicit"):
                    agents = _shape(roster, shape)
                    if ownership:
                        agents["ownership"] = ownership
                    rows.append((f"{shape}/{ownership}/{markers}", {"agents": agents}))
    # explicit ownership WITH a recorded system agent: the field that does NOT place a workspace
    system = {"ownership": "explicit", "defaults": {"systemAgent": {"agentId": "b"}}}
    rows.append(("explicit + systemAgent", {"agents": {**system, "list": [{"id": "main"}, {"id": "b"}]}}))
    rows.append(("explicit + systemAgent + marker",
                 {"agents": {**system, "list": [{"id": "main", "default": True}, {"id": "b"}]}}))
    # defaults.workspace changes the DERIVED shape (rule 3), not who is the default
    for mark in ("absent", True):
        for roster in ([{"id": "main"}], [{"id": "main"}, {"id": "b"}]):
            marked = [_entry(e["id"], mark if e["id"] == "b" or len(roster) == 1 else "absent")
                      for e in roster]
            rows.append((f"defaults.workspace/{len(roster)}/{mark}",
                         {"agents": {"defaults": {"workspace": "/ws"}, "list": marked}}))
    # ids that need normalising, junk entries, a nameless entry, an own workspace
    rows += [
        ("normalise", {"agents": {"list": [{"id": " Foo Bar "}, {"id": "X", "default": True}]}}),
        ("normalise, nobody marked", {"agents": {"list": [{"id": " Foo Bar "}, {"id": "X"}]}}),
        ("junk entries", {"agents": {"list": ["junk", None, 5, {"id": "b"}]}}),
        ("junk before the marker", {"agents": {"list": ["junk", {"id": "b"}, {"id": "c", "default": True}]}}),
        ("nameless sole entry", {"agents": {"list": [{}]}}),
        ("nameless marked entry", {"agents": {"list": [{"default": True}, {"id": "b"}]}}),
        ("own workspace on the sole agent", {"agents": {"list": [{"id": "a", "workspace": "/own"}]}}),
        ("own workspace beside an unmarked peer",
         {"agents": {"list": [{"id": "a", "workspace": "/own"}, {"id": "b"}]}}),
        ("entry id loses to record key", {"agents": {"entries": {"web": {"id": "OTHER"}, "x": {}}}}),
        ("same id twice, both marked",
         {"agents": {"list": [{"id": "a", "default": True}, {"id": "A", "default": True}]}}),
        ("same id twice, one marked",
         {"agents": {"list": [{"id": "a", "default": True}, {"id": "A"}]}}),
    ]
    return rows


@pytest.fixture(scope="module")
def vendor(tmp_path_factory):
    require_dist()
    rows = _battery()
    answers, state = _execute(rows, tmp_path_factory.mktemp("c684-oracle"))
    assert len(answers) == len(rows)
    return {"rows": rows, "answers": answers, "state": state}


def _cases(vendor):
    return list(zip(vendor["rows"], vendor["answers"]))


# --------------------------------------------------------------------------- collector + leaf

def _expected_derived(cfg: dict, answer: dict, state: str) -> "list[str]":
    """The derived-workspace list the VENDOR implies, in the shape both copies emit.

    Built only from ``resolveAgentWorkspaceDir``'s own output: a directory under the state dir
    named ``workspace-<id>`` is rule 4, one under ``agents.defaults.workspace`` is rule 3, and
    the plain workspace (``<state>/workspace`` or the defaults value itself) is rule 2 and is
    never derived. An agent with its own ``workspace`` is collected elsewhere (rule 1).
    """
    defaults = (cfg.get("agents") or {}).get("defaults") or {}
    fallback = defaults.get("workspace") if isinstance(defaults.get("workspace"), str) else ""
    out = []
    for item in answer["core"]:
        path = item["ws"]
        assert isinstance(path, str), (answer["label"], item)
        if item["id"] is None:
            continue  # both copies skip a nameless entry's derived path
        own = _own_workspace(cfg, item["id"])
        if own:
            continue
        if path.startswith(state + "/workspace-"):
            out.append("workspace-" + path[len(state + "/workspace-"):])
        elif fallback and path.startswith(fallback.rstrip("/") + "/"):
            out.append(str(Path(fallback) / path[len(fallback.rstrip("/") + "/"):]))
    return out


def _own_workspace(cfg: dict, agent_id: str) -> bool:
    agents = cfg.get("agents") or {}
    roster = agents.get("entries") if "entries" in agents else agents.get("list")
    items = roster.items() if isinstance(roster, dict) else enumerate(roster or [])
    for key, val in items:
        if not isinstance(val, dict):
            continue
        ident = key if isinstance(roster, dict) else val.get("id")
        if ident == agent_id and isinstance(val.get("workspace"), str) and val["workspace"].strip():
            return True
    return False


@pytest.mark.parametrize("module", [collector, skillprovenance], ids=["collector", "skillprovenance"])
def test_derived_workspaces_match_resolve_agent_workspace_dir(vendor, module):
    """Every battery row: the directories we derive are exactly the ones the vendor derives."""
    failures = []
    for (label, cfg), answer in _cases(vendor):
        expected = _expected_derived(cfg, {**answer, "label": label}, vendor["state"])
        got = module._derived_agent_workspaces(copy.deepcopy(cfg))
        if got != expected:
            failures.append(f"{label}: vendor implies {expected}, {module.__name__} derives {got}")
    assert not failures, f"{len(failures)} of {len(vendor['rows'])} rows disagree:\n" + "\n".join(failures[:25])


def test_the_two_workspace_copies_agree_over_the_whole_battery(vendor):
    for (label, cfg), _answer in _cases(vendor):
        assert collector._derived_agent_workspaces(copy.deepcopy(cfg)) == \
            skillprovenance._derived_agent_workspaces(copy.deepcopy(cfg)), label


# --------------------------------------------------------------------------- toolpolicy

def _vendor_main(answer: dict) -> "str | None":
    """The vendor's answer when it HAS one; ``None`` when it throws."""
    value = answer["session_main"]
    return None if (value is None or str(value).startswith("THROWS:")) else value


def test_toolpolicy_default_agent_matches_the_vendor_wherever_the_vendor_answers(vendor):
    failures = []
    definite = 0
    for (label, cfg), answer in _cases(vendor):
        want = _vendor_main(answer)
        if want is None:
            continue
        definite += 1
        got = toolpolicy._default_agent_id(copy.deepcopy(cfg))
        if got != want:
            failures.append(f"{label}: vendor {want!r}, toolpolicy {got!r}")
    assert definite > 100, "the battery stopped exercising definite answers - the guard is vacuous"
    assert not failures, f"{len(failures)} rows disagree:\n" + "\n".join(failures[:25])


def test_the_rows_where_the_vendor_throws_are_the_undetermined_set(vendor):
    """The vendor THROWS on these, so there is no id to port and none is invented here.

    Characterised from the vendor's own output so the set is visible: it is exactly the
    configs with two or more agents and no unique ``default: true`` marker (or marked under
    ``ownership: "explicit"``), plus a roster that is present but empty. toolpolicy keeps its
    previous behaviour there - see ``toolpolicy._default_agent_id``; deciding what a "global"
    surface means when no agent is the default is an owner decision, not a port.
    """
    undetermined = [(lab, cfg) for (lab, cfg), ans in _cases(vendor) if _vendor_main(ans) is None]
    assert len(undetermined) > 100
    for label, cfg in undetermined:
        agents = cfg.get("agents") or {}
        roster = agents.get("entries") if "entries" in agents else agents.get("list")
        items = list(roster.values()) if isinstance(roster, dict) else \
            [e for e in (roster or []) if isinstance(e, dict)]
        items = [e for e in items if isinstance(e, dict)]
        marked = [e for e in items if e.get("default") is True]
        honoured = len(marked) == 1 and agents.get("ownership") != "explicit"
        assert (len(items) == 0 and "agents" in cfg) or (len(items) >= 2 and not honoured), label


def test_toolpolicy_ignores_a_non_boolean_marker_ahead_of_the_real_one():
    cfg = {"agents": {"list": [{"id": "a", "default": "yes"}, {"id": "b", "default": True}]}}
    assert toolpolicy._default_agent_id(cfg) == "b"


# --------------------------------------------------------------------------- controls

def test_the_memory_host_variant_is_a_different_function(vendor):
    """Why the port targets ``resolveAgentWorkspaceDir`` and not the ``config-utils`` function.

    The first reading of this task pointed at ``resolveDefaultAgentId`` in ``config-utils-*``
    ("the workspace-derivation one"). Executed, it places the MEMORY-SEARCH workspace and keeps
    an ``agents[0]`` fallback the agent runtime's own function does not have. If the two ever
    agree on a two-unmarked-agents row this control is stale and the port needs re-deciding.
    """
    probe = next(a for (lab, _), a in _cases(vendor) if lab == "list/None/('absent', 'absent')")
    first_core, first_memory = probe["core"][0]["ws"], probe["memory"][0]
    assert first_core.endswith("/.openclaw/workspace-main"), first_core
    assert first_memory.endswith("/.openclaw/workspace"), first_memory


def _old_default_agent_id(entries) -> str:
    """The rule all three copies used before C-684, kept only so the battery can convict it."""
    for entry in entries:
        if isinstance(entry, dict) and entry.get("default"):
            return collector._normalize_agent_id(entry.get("id"))
    return collector._normalize_agent_id(entries[0].get("id")) if entries else "main"


@pytest.mark.parametrize("label", [
    "list/None/(True, True)",               # two entries marked: the old rule took the first
    "list/None/('yes', True)",              # a truthy non-boolean marker ahead of the real one
    "list/None/('absent', 'absent')",       # nobody marked: the old rule invented agents[0]
    "list/explicit/(True, 'absent')",       # explicit ownership: the marker is not consulted
    "entries/None/(True, True)",            # the same through the 2026.8.1 record shape
])
def test_the_old_rule_is_convicted_by_this_battery(vendor, monkeypatch, label):
    """A control that cannot fail controls nothing: put the OLD rule back behind
    ``_derived_agent_workspaces`` and require the vendor-derived expectation to reject it."""
    (_, cfg), answer = next(c for c in _cases(vendor) if c[0][0] == label)
    expected = _expected_derived(cfg, {**answer, "label": label}, vendor["state"])
    assert collector._derived_agent_workspaces(copy.deepcopy(cfg)) == expected
    monkeypatch.setattr(collector, "_default_agent_id", lambda entries, *a, **k: _old_default_agent_id(entries))
    assert collector._derived_agent_workspaces(copy.deepcopy(cfg)) != expected
