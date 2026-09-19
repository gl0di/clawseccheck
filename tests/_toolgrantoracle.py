"""Executes OpenClaw's own tool-grant code, so ``clawseccheck/toolgrant.py`` is graded by
the vendor and never by a description of it.

This is the GENERATOR half of ``tests/data/toolgrant_battery.json`` and the ORACLE half of
``tests/test_toolgrant_dist_grounding.py``. The first battery was captured by a one-shot
node script that was never committed, which left the file un-reproducible: nobody could
say which OpenClaw build it described, or re-run it on the next one, except by rebuilding
the script from a docstring. This module is that script, kept.

Local-only by construction: it needs the installed dist (``require_dist``) and ``node``.
Everything that imports it at collection time (the battery test) does so offline — none of
the functions below run until called, and the callers skip when the dist is absent.

    python3.12 tests/_toolgrantoracle.py --write     # regenerate the pinned battery
    python3.12 tests/_toolgrantoracle.py --check     # is the pinned battery still what the
                                                     # installed vendor answers? (exit 1 if not)
    python3.12 tests/_toolgrantoracle.py --tables    # print the vendor's tables as JSON

HOW THE VENDOR IS REACHED. Bundle filenames are content-hashed and the export names inside
are minified (``resolveConfiguredToolPolicies as t``), so neither is a stable handle. A
symbol is located by the line that DECLARES it (``function resolveConfiguredToolPolicies(``)
and must be declared in exactly one bundle — a coin toss between two is a failure, never a
first-match (``_distgrounding.dist_file``'s rule, restated here for content rather than
filename). The two symbols the resolver IMPORTS (``resolveAgentConfig``,
``hasAgentRosterProperty``) are taken from the resolver's own import clause instead, because
``resolveAgentConfig`` really is declared in two unrelated bundles and only one is the copy
the resolver runs. Each located bundle is then copied to a scratch directory with two mechanical
edits and NOTHING else: its relative imports are pointed at the installed dist by absolute
``file://`` URL, and its ``export {...}`` clause is replaced by an export of the declared
names by their REAL names. That second edit is what makes the module tables reachable at
all — ``CORE_TOOL_PROFILES``, ``TOOL_NAME_ALIASES`` and the shipped-policy maps are not
exported by the vendor, only the functions that read them are, so a dump that stops at the
public surface can only ever see the answers, never the table. The bodies are the vendor's
bytes; a rewrite that fails to apply is an error (``_rewrite`` asserts each edit landed).

SAFETY. What is loaded is the tool-policy resolver's own import graph (policy, catalog,
roster and scope modules, plus the logger / session / plugin-registry modules the resolver
imports). No CLI, gateway or update entry point is imported, and nothing in that graph runs at
import time — checked: the scratch ``$HOME`` is still empty afterwards. The node process gets
that scratch ``$HOME`` and a minimal environment, so it can neither read the real
``~/.openclaw`` (which holds live tokens) nor write anywhere else. Nothing here is imported
by ``clawseccheck/``.

WHAT "SCOPE" MEANS HERE — unchanged from the first battery, so the two are comparable:
``global`` is a query with NO explicit agent (``agentTools`` resolved from ``agents.defaults``
only when the config owns no roster), and each roster id is a query for that agent. The
``agentTools`` derivation is ``resolveEffectiveToolPolicy``'s own three lines, copied
verbatim into the harness below, because that function is too entangled with sessions and
provider routing to call whole.
"""
from __future__ import annotations

import argparse
import functools
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from _distgrounding import require_dist

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
FIXTURES = ROOT / "fixtures"
BATTERY = TESTS / "data" / "toolgrant_battery.json"

#: The tools the parametrized, per-cell gate covers (the original battery's family).
TOOL_FAMILY = ("read", "write", "edit", "apply_patch", "exec", "automations")
#: Added when the catalog moved under a re-baseline: ``gateway`` entered the minimal / coding
#: / messaging profiles and ``plugins`` entered coding, so the stale profile table disagreed on
#: ~500 gateway cells and 15 each for plugins and ls while the family above stayed at zero;
#: ``ls`` had drifted a release earlier; ``openclaw`` and ``pdf`` are catalog entries the port
#: had never seen at all.
#: These are checked one test per tool (``test_toolgrant_battery.py``), not one per cell.
EXTENDED_TOOLS = ("gateway", "plugins", "ls", "openclaw", "pdf")
BATTERY_TOOLS = TOOL_FAMILY + EXTENDED_TOOLS

_NODE_TIMEOUT_S = 120

#: Where the throwaway rewrite/HOME directory is made. ``None`` means the system temp
#: directory (fine for the CLI); the test module points it at pytest's ``tmp_path`` so the
#: suite writes nothing outside it.
SCRATCH_ROOT = None

# --------------------------------------------------------------------------- locating

#: name of the module role -> (declaration regex, names to export by their real names)
_MODULES = {
    "policies": (r"^function resolveConfiguredToolPolicies\(", ["resolveConfiguredToolPolicies"]),
    "match": (r"^function isToolAllowedByPolicies\(", ["isToolAllowedByPolicies"]),
    "scope": (r"^function resolveAgentConfig\(", ["resolveAgentConfig"]),
    "roster": (r"^function hasAgentRosterProperty\(", ["hasAgentRosterProperty", "listAgentEntries"]),
    "catalog": (
        r"^function resolveCoreToolProfilePolicy\(",
        ["CORE_TOOL_PROFILES", "CORE_TOOL_GROUPS", "resolveCoreToolProfilePolicy", "PROFILE_OPTIONS"],
    ),
    "shared": (
        r"^const TOOL_NAME_ALIASES\b",
        ["TOOL_NAME_ALIASES", "TOOL_GROUPS", "normalizeToolPolicyName"],
    ),
    "shipped": (
        r"^const SHIPPED_PLUGIN_POLICY_FAMILY_CORE_TOOLS\b",
        ["SHIPPED_PLUGIN_POLICY_FAMILY_CORE_TOOLS", "SHIPPED_CORE_POLICY_RENAMES"],
    ),
}


#: Modules the resolver IMPORTS rather than owns, and the local name it imports them by.
#: Declaring the symbol is not enough to identify these — ``resolveAgentConfig`` is declared
#: in two unrelated bundles (a lookup by id in ``config-utils`` and the real per-agent config
#: builder in ``agent-scope-config``) — so the bundle is whichever one the resolver's own
#: import clause names. That is the copy the vendor actually runs.
_IMPORTED_BY_POLICIES = {"scope": "resolveAgentConfig", "roster": "hasAgentRosterProperty"}


def _bundle_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _declares(path: Path, role: str) -> bool:
    return path in _scan(require_dist())[role]


@functools.lru_cache(maxsize=None)
def _scan(dist: Path) -> dict:
    """``{role: (bundle, ...)}`` for every bundle under ``dist`` declaring that role's symbol.

    One pass, bytes, no decoding: the dist is ~230 MB, and reading it once per role was most
    of the run. Only the small list of matches is kept, never the text."""
    rxs = {}
    for role, (pattern, _) in _MODULES.items():
        symbol = re.search(r"(?:function|const) (\w+)", pattern).group(1).encode()
        rxs[role] = (symbol, re.compile(pattern.encode(), re.M))
    found = {role: [] for role in _MODULES}
    for path in sorted(list(dist.glob("*.mjs")) + list(dist.glob("*.js"))):
        data = path.read_bytes()
        for role, (symbol, rx) in rxs.items():
            # A substring test first: an anchored multi-line regex over 70 MB is ~25x slower.
            if symbol in data and rx.search(data):
                found[role].append(path)
    return {role: tuple(paths) for role, paths in found.items()}


def locate(role: str) -> Path:
    """The ONE dist bundle for ``role`` — or an AssertionError naming how to re-locate it.

    Zero matches means the symbol moved or was renamed (the dist IS installed, so this is a
    finding, not a reason to stand down); two or more means a first-match would be a coin
    toss. Roles in ``_IMPORTED_BY_POLICIES`` are taken from the resolver's own import clause
    and then required to declare the symbol.
    """
    dist = require_dist()
    pattern = _MODULES[role][0]
    if role in _IMPORTED_BY_POLICIES:
        name = _IMPORTED_BY_POLICIES[role]
        text = _bundle_text(locate("policies"))
        hits = re.findall(
            r'import\s*\{[^}]*\bas\s+%s\b[^}]*\}\s*from\s*"\./([^"]+)"' % re.escape(name), text
        )
        if len(hits) != 1 or not (dist / hits[0]).is_file() or not _declares(dist / hits[0], role):
            raise AssertionError(
                f"the resolver no longer imports {name!r} from one bundle that declares it "
                f"({hits or 'no import found'}). Re-locate it with "
                f"`grep -n {name} {locate('policies')}` and re-ground the harness."
            )
        return dist / hits[0]
    found = list(_scan(dist)[role])
    if len(found) != 1:
        raise AssertionError(
            f"{len(found)} bundle(s) under {dist} declare {pattern!r} "
            f"({', '.join(p.name for p in found) or 'none'}); the {role!r} module needs exactly "
            f"one. Re-locate it with `grep -rlE {pattern!r} {dist}/*` and re-ground the harness."
        )
    return found[0]


def _rewrite(path: Path, exports, dist: Path) -> str:
    """Bundle text with relative imports made absolute and the export clause replaced."""
    src = path.read_text(encoding="utf-8")
    base = "file://" + str(dist) + "/"
    src, n_from = re.subn(r'(\bfrom\s+")\./', lambda m: m.group(1) + base, src)
    src, n_bare = re.subn(r'(^import\s+")\./', lambda m: m.group(1) + base, src, flags=re.M)
    assert n_from + n_bare, f"{path.name}: no relative import was rewritten — bundle shape moved"
    clauses = list(re.finditer(r"^export\s*\{[^}]*\};?[ \t]*$", src, re.M))
    assert len(clauses) == 1, f"{path.name}: expected one export clause, found {len(clauses)}"
    for name in exports:
        assert re.search(r"\b(?:function|const)\s+%s\b" % re.escape(name), src), (
            f"{path.name} no longer declares {name!r}"
        )
    return src[: clauses[0].start()] + "export { %s };\n" % ", ".join(exports)


# --------------------------------------------------------------------------- the harness

_HARNESS = r"""
import { readFileSync } from "node:fs";
const cfgOf = JSON.parse(readFileSync(0, "utf8"));
const M = {};
for (const [role, file] of Object.entries(cfgOf.modules)) M[role] = await import("file://" + file);

const out = {};

if (cfgOf.want.includes("tables")) {
  const cat = M.catalog;
  const profiles = {};
  const keys = new Set([...Object.keys(cat.CORE_TOOL_PROFILES), ...cat.PROFILE_OPTIONS.map((p) => p.id)]);
  for (const key of [...keys].sort()) profiles[key] = cat.resolveCoreToolProfilePolicy(key) ?? null;
  // Pairs, not an object: assigning probes["__proto__"] sets a prototype instead of a key.
  const probes = ["", "MINIMAL", " coding ", "readonly", "constructor", "__proto__", "toString"]
    .map((bad) => [bad, cat.resolveCoreToolProfilePolicy(bad) ?? null]);
  out.tables = {
    profiles,
    profile_options: cat.PROFILE_OPTIONS.map((p) => p.id),
    profile_probes: Object.fromEntries(probes),
    groups: { ...M.shared.TOOL_GROUPS },
    core_groups: { ...cat.CORE_TOOL_GROUPS },
    aliases: Object.fromEntries(M.shared.TOOL_NAME_ALIASES),
    shipped_family: Object.fromEntries(M.shipped.SHIPPED_PLUGIN_POLICY_FAMILY_CORE_TOOLS),
    shipped_renames: Object.fromEntries(M.shipped.SHIPPED_CORE_POLICY_RENAMES),
  };
}

if (cfgOf.want.includes("grants")) {
  const { resolveConfiguredToolPolicies } = M.policies;
  const { isToolAllowedByPolicies } = M.match;
  const { resolveAgentConfig } = M.scope;
  const { hasAgentRosterProperty, listAgentEntries } = M.roster;

  // resolveEffectiveToolPolicy's agentTools derivation, verbatim in shape:
  //   agentConfig = config && agentId ? resolveAgentConfig(config, agentId) : undefined
  //   agentTools  = agentConfig?.tools ?? (config && !hasAgentRosterProperty(config) ? agents.defaults.tools : undefined)
  const agentToolsFor = (cfg, agentId) => {
    const agentConfig = agentId ? resolveAgentConfig(cfg, agentId) : undefined;
    return agentConfig?.tools ?? (!hasAgentRosterProperty(cfg) ? cfg.agents?.defaults?.tools : undefined);
  };
  const rows = [];
  for (const { label, cfg } of cfgOf.rows) {
    const ids = [...new Set(
      listAgentEntries(cfg).map((e) => e.id).filter((id) => typeof id === "string" && id.trim() !== ""),
    )].sort();
    const results = {};
    for (const tool of cfgOf.tools) results[tool] = {};
    for (const scope of ["global", ...ids]) {
      const agentId = scope === "global" ? undefined : scope;
      const policies = resolveConfiguredToolPolicies({
        cfg, agentTools: agentToolsFor(cfg, agentId), agentId, sandboxMode: null,
      });
      for (const tool of cfgOf.tools) results[tool][scope] = isToolAllowedByPolicies(tool, policies);
    }
    rows.push({ label, agents: ids, results });
  }
  out.grants = rows;
}

process.stdout.write(JSON.stringify(out));
"""


def _require_node() -> str:
    node = shutil.which("node")
    if not node:
        raise RuntimeError("node is not on PATH — the tool-grant oracle needs it")
    return node


def _execute(want, rows=(), tools=()) -> dict:
    dist = require_dist()
    node = _require_node()
    with tempfile.TemporaryDirectory(prefix="toolgrant-oracle-", dir=SCRATCH_ROOT) as tmp:
        scratch = Path(tmp)
        (scratch / "home").mkdir()
        modules = {}
        for role, (_, exports) in _MODULES.items():
            path = locate(role)
            target = scratch / f"{role}.mjs"
            target.write_text(_rewrite(path, exports, dist), encoding="utf-8")
            modules[role] = str(target)
        harness = scratch / "harness.mjs"
        harness.write_text(_HARNESS, encoding="utf-8")
        payload = json.dumps({
            "modules": modules,
            "want": list(want),
            "rows": [{"label": label, "cfg": cfg} for label, cfg in rows],
            "tools": list(tools),
        })
        env = {"HOME": str(scratch / "home"), "PATH": os.environ.get("PATH", ""), "LANG": "C"}
        proc = subprocess.run(
            [node, str(harness)], input=payload, capture_output=True, text=True,
            env=env, cwd=str(scratch), timeout=_NODE_TIMEOUT_S,
        )
    if proc.returncode != 0:
        raise RuntimeError(f"node exited {proc.returncode}: {proc.stderr.strip()[-600:]}")
    return json.loads(proc.stdout)


# --------------------------------------------------------------------------- public API

@functools.lru_cache(maxsize=None)
def _vendor_tables_cached() -> str:
    return json.dumps(_execute(["tables"])["tables"])


def vendor_tables() -> dict:
    """The vendor's profile / group / alias tables, read from the objects the predicate uses.

    Executed once per process; every caller gets its own copy, so a test that mutates the
    result cannot poison the next one."""
    return json.loads(_vendor_tables_cached())


def vendor_grants(rows, tools=BATTERY_TOOLS) -> list:
    """``[{label, agents, results: {tool: {scope: bool}}}]`` for ``rows`` = ``[(label, cfg)]``."""
    return _execute(["grants"], rows=rows, tools=tools)["grants"]


def corpus_rows() -> list:
    """Every non-empty ``fixtures/*/openclaw.json`` that parses as plain JSON, by label.

    Plain ``json.loads`` on purpose: the battery test reads its configs the same way, so a
    row this function returns is a row the test can replay.
    """
    rows = []
    for path in sorted(FIXTURES.glob("*/openclaw.json")):
        try:
            cfg = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(cfg, dict) and cfg:
            rows.append((path.parent.name, cfg))
    return rows


def synthetic_configs(tables: dict) -> list:
    """Deterministic ``[(label, cfg)]`` built from the vendor's own tables.

    No fixture config names a ``group:*`` entry at all (measured on 2026-09-19: 0 of 575), so
    on its own the corpus grades a stale group table GREEN: 522 of 6,688 cells were wrong
    against 2026.9.5 and not one was in the six-tool family the corpus exercises. These configs exist to make every table entry reachable — every group as an
    allow and a deny, every profile with and without ``alsoAllow``, the alias spellings, and
    both roster shapes. Group and profile ids come from ``tables`` (the vendor), so a new
    group is swept the day it appears rather than the day someone remembers it.
    """
    out = []

    def add(slug, cfg):
        out.append((f"synthetic/{slug}", cfg))

    profiles = sorted(tables["profiles"])
    groups = sorted(tables["groups"])
    for p in profiles:
        add(f"profile/{p}", {"tools": {"profile": p}})
    for p in profiles:
        if p == "full":
            continue
        for extra in ("gateway", "pdf", "group:automation"):
            add(f"profile/{p}+also/{extra}", {"tools": {"profile": p, "alsoAllow": [extra]}})
    for p in profiles:
        for g in ("group:openclaw", "group:automation", "group:fs", "group:media"):
            add(f"profile/{p}+deny/{g}", {"tools": {"profile": p, "deny": [g]}})
    for g in groups:
        add(f"group/{g}/allow", {"tools": {"allow": [g]}})
        add(f"group/{g}/deny", {"tools": {"deny": [g]}})
        add(f"group/{g}/minimal-also", {"tools": {"profile": "minimal", "alsoAllow": [g]}})
    spellings = ["gateway", "plugins", "ls", "openclaw", "pdf", "bash", "cron", "apply-patch",
                 "CRON", " GATEWAY ", "canvas", "show_widget", "update_plan", "progress_card",
                 "*", "g*", "*s", "read", "write"]
    for name in spellings:
        add(f"name/{name.strip()}/allow", {"tools": {"allow": [name]}})
    for name in ("gateway", "plugins", "ls", "openclaw", "pdf", "bash", "cron", "write"):
        add(f"name/{name}/deny", {"tools": {"profile": "full", "deny": [name]}})
    add("roster/list", {
        "tools": {"profile": "minimal"},
        "agents": {"list": [
            {"id": "a", "tools": {"profile": "coding"}},
            {"id": "b", "tools": {"alsoAllow": ["plugins", "pdf"]}},
            {"id": "c", "tools": {"deny": ["group:automation"]}},
        ]},
    })
    add("roster/entries", {
        "tools": {"profile": "coding"},
        "agents": {"entries": {
            "a": {"tools": {"profile": "messaging"}},
            "b": {"tools": {"allow": ["openclaw"]}},
            "c": {"tools": {"profile": "full", "deny": ["gateway"]}},
        }},
    })
    add("roster/defaults-only", {"agents": {"defaults": {"tools": {"profile": "coding"}}}})
    add("roster/defaults-ignored", {
        "agents": {"defaults": {"tools": {"profile": "minimal"}}, "entries": {"a": {}}},
    })
    return out


def all_tool_ids(tables: dict) -> list:
    """Every tool name the vendor tables mention, plus names that must NOT be granted."""
    names = set()
    for members in tables["groups"].values():
        names.update(members)
    for policy in tables["profiles"].values():
        names.update(policy.get("allow") or [])
    names.update(tables["aliases"])
    names.update(tables["aliases"].values())
    names.update(tables["shipped_family"])
    names.update(t for v in tables["shipped_family"].values() for t in v)
    names.update(tables["shipped_renames"])
    names.update(tables["shipped_renames"].values())
    names.update({"nonexistent_tool", "bundle-mcp"})
    names.discard("*")
    return sorted(names)


def build_battery(tools=BATTERY_TOOLS) -> list:
    """The battery as pinned: fixture rows plus synthetic rows, sorted by label.

    Synthetic rows carry their own ``cfg`` and ``"synthetic": true`` (there is no fixture to
    read it back from); fixture rows carry neither, and are read from ``fixtures/`` on replay.
    """
    synthetic = synthetic_configs(vendor_tables())
    configs = dict(corpus_rows()) | dict(synthetic)
    rows = vendor_grants(list(configs.items()), tools)
    by_label = dict(synthetic)
    for row in rows:
        if row["label"] in by_label:
            row["synthetic"] = True
            row["cfg"] = by_label[row["label"]]
    return sorted(rows, key=lambda row: row["label"])


def pinned_rows(pinned: list) -> list:
    """``[(label, cfg)]`` for a pinned battery — embedded cfg for synthetic rows, else the fixture."""
    out = []
    for row in pinned:
        if "cfg" in row:
            out.append((row["label"], row["cfg"]))
        else:
            out.append((row["label"], json.loads(
                (FIXTURES / row["label"] / "openclaw.json").read_text(encoding="utf-8"))))
    return out


def recheck(pinned: list) -> list:
    """Re-run the vendor over exactly the pinned rows and return every cell that moved.

    Unlike ``diff_battery(pinned, build_battery())`` this ignores fixtures added since the
    battery was written (they are simply not covered yet, which is a fact to report, not a
    disagreement) — so it stays green while other work adds fixtures, and goes red when the
    INSTALLED VENDOR's answer for something already pinned changes, which is the upgrade signal.
    """
    tools = sorted({t for row in pinned for t in row["results"]})
    fresh = vendor_grants(pinned_rows(pinned), tools)
    return diff_battery(pinned, fresh)


def render(battery) -> str:
    """Byte-stable serialization (sorted keys, one-space indent, trailing newline)."""
    return json.dumps(battery, indent=1, sort_keys=True) + "\n"


def diff_tables(ours: dict, vendor: dict, what: str) -> list:
    """Every way ``ours`` differs from ``vendor`` — WHOLE-table, order-sensitive.

    ``ours`` and ``vendor`` are ``{key: value}`` maps whose values are lists, dicts or
    scalars. A key on one side only, a member on one side only, a different order and a
    different scalar are all named. Returns ``[]`` when identical. The equality is exact on
    purpose: the tables are transcriptions of a dump, so the honest question is "is this
    the dump", and an order-only change is reported as such rather than ignored.
    """
    problems = []
    for key in sorted(set(ours) | set(vendor), key=str):
        if key not in vendor:
            problems.append(f"{what}[{key!r}] is in toolgrant.py but not in the vendor")
        elif key not in ours:
            problems.append(f"{what}[{key!r}] is in the vendor but not in toolgrant.py")
        elif ours[key] != vendor[key]:
            a, b = ours[key], vendor[key]
            if isinstance(a, list) and isinstance(b, list):
                gone = [x for x in a if x not in b]
                new = [x for x in b if x not in a]
                if gone or new:
                    problems.append(
                        f"{what}[{key!r}]: toolgrant.py has {gone or '-'} the vendor lacks; "
                        f"vendor has {new or '-'} toolgrant.py lacks"
                    )
                else:
                    problems.append(f"{what}[{key!r}]: same members, different order")
            else:
                problems.append(f"{what}[{key!r}]: toolgrant.py has {a!r}, vendor has {b!r}")
    return problems


def diff_battery(pinned: list, fresh: list) -> list:
    """Cells that differ between two batteries (same shape as ``build_battery``)."""
    problems = []
    a = {row["label"]: row for row in pinned}
    b = {row["label"]: row for row in fresh}
    for label in sorted(set(a) | set(b)):
        if label not in b:
            problems.append(f"{label}: pinned but no longer a fixture")
            continue
        if label not in a:
            problems.append(f"{label}: a fixture the pinned battery does not cover")
            continue
        if a[label]["agents"] != b[label]["agents"]:
            problems.append(f"{label}: scopes {a[label]['agents']} -> {b[label]['agents']}")
        for tool in sorted(set(a[label]["results"]) | set(b[label]["results"])):
            pa = a[label]["results"].get(tool, {})
            pb = b[label]["results"].get(tool, {})
            for scope in sorted(set(pa) | set(pb)):
                if pa.get(scope) != pb.get(scope):
                    problems.append(f"{label}/{scope}/{tool}: pinned {pa.get(scope)} -> {pb.get(scope)}")
    return problems


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="regenerate tests/data/toolgrant_battery.json")
    mode.add_argument("--check", action="store_true", help="fail unless the pinned battery equals a fresh run")
    mode.add_argument("--tables", action="store_true", help="print the vendor tables as JSON")
    args = parser.parse_args(argv)

    if args.tables:
        print(json.dumps(vendor_tables(), indent=1))
        return 0
    if args.write:
        fresh = build_battery()
        BATTERY.write_text(render(fresh), encoding="utf-8")
        cells = sum(len(v) for row in fresh for v in row["results"].values())
        print(f"wrote {BATTERY} — {len(fresh)} rows, {cells} cells, tools {list(BATTERY_TOOLS)}")
        return 0
    pinned = json.loads(BATTERY.read_text(encoding="utf-8"))
    problems = recheck(pinned)
    for line in problems[:50]:
        print(line)
    uncovered = sorted({label for label, _ in corpus_rows()} - {row["label"] for row in pinned})
    if uncovered:
        print(f"note: {len(uncovered)} fixture(s) not covered by the pinned battery (run --write)")
    print(f"{len(problems)} difference(s) between the pinned battery and the installed vendor")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
