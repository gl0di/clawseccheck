"""CLAWSECCHECK-B-1113 -- B333's tool-filter port is raw-only; OpenClaw 2026.11.5 added ALIASES.

`createMcpToolFilter(filter, scope)` resolves an entry that has no `*` and is not an exact
inventory name as an alias (`<safeServerName>__<sanitised tool fragment>`): an exclude alias
hides every owner, an include alias matches only a unique unsuffixed owner, and an entry that
resolves to nothing matches nothing. Our port models the scope-less (raw-only) behaviour, so
on 2026.11.5+ an include alias made B333 drop a tool that really waives its gate (a false
negative) and an exclude alias made it a false WARN.

The decided fix is an honest UNKNOWN, not a port of the resolver (`safeServerName` depends on
declaration-order collision suffixes and cross-source merge order we cannot prove). The claim
that matters is SOUNDNESS: wherever the scoped and the raw vendor filter differ, our alias
helper flags at least one entry. That is asserted against the real vendor below.
"""
import json
import os
import shutil
import subprocess

import pytest
from _distgrounding import dist_file
from test_b706_codex_annotations_enforced import _alias_map

import clawseccheck.checks as C
from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    _MCP_SCOPED_ALIAS_FILTER_MIN,
    _b333_modern_surface_verdict,
    _mcp_normalize_tool_filter,
    _mcp_tool_filter_alias_entries,
)
from clawseccheck.collector import collect
from clawseccheck.mcpsurface import from_tool_defs

RO = {"readOnlyHint": True}


def _tool(name, annotations=None):
    t = {"name": name, "description": "does a thing", "inputSchema": {"type": "object"}}
    if annotations is not None:
        t["annotations"] = annotations
    return t


def _verdict(tool_filter, build, tools=None, name="srv"):
    spec = {"command": "c", "tools": tools or [_tool("fetch", RO)]}
    if tool_filter is not None:
        spec["toolFilter"] = tool_filter
    surface = from_tool_defs(name, spec["tools"])
    return _b333_modern_surface_verdict(surface, name, spec, build)


NEW = (2026, 11, 6)
OLD = (2026, 11, 4)


def test_the_floor_is_the_release_that_introduced_aliases():
    assert _MCP_SCOPED_ALIAS_FILTER_MIN == (2026, 11, 5)


# ---------------------------------------------------------------------------------------
# The helper
# ---------------------------------------------------------------------------------------

def test_an_include_alias_is_unknown_not_pass_on_a_new_build():
    assert _verdict(None, NEW) == (WARN, ["fetch"])  # control: no filter still WARNs
    status, entries = _verdict({"include": ["srv__fetch"]}, NEW)
    assert status == UNKNOWN and entries == ["srv__fetch"]


def test_an_exclude_alias_is_unknown_not_warn_on_a_new_build():
    assert _verdict({"exclude": ["other"]}, NEW) == (WARN, ["fetch"])  # control
    status, entries = _verdict({"exclude": ["srv__fetch"]}, NEW)
    assert status == UNKNOWN and entries == ["srv__fetch"]


def test_a_build_below_the_floor_keeps_todays_result():
    # include alias: raw-only semantics -> the tool is dropped -> PASS (None)
    assert _verdict({"include": ["srv__fetch"]}, OLD) is None
    # exclude alias: matches nothing raw -> the tool stays -> WARN
    assert _verdict({"exclude": ["srv__fetch"]}, OLD) == (WARN, ["fetch"])


def test_an_unknown_build_is_unknown():
    assert _verdict({"include": ["srv__fetch"]}, None)[0] == UNKNOWN
    assert _verdict({"exclude": ["srv__fetch"]}, None)[0] == UNKNOWN
    assert _verdict(None, None) == (WARN, ["fetch"])  # control


def test_the_floor_itself_is_a_new_build():
    assert _verdict({"include": ["srv__fetch"]}, (2026, 11, 5))[0] == UNKNOWN
    assert _verdict({"include": ["srv__fetch"]}, (2026, 11, 5, 1))[0] == UNKNOWN


def test_unknown_wins_only_when_some_tool_would_waive_its_gate():
    """If nothing waives the gate with the filter ignored, PASS holds whatever the alias
    resolves to, so UNKNOWN would be noise."""
    tools = [_tool("fetch", {"destructiveHint": True})]
    assert _verdict({"include": ["srv__fetch"]}, NEW, tools) is None
    assert _verdict({"include": ["srv__fetch"]}, None, tools) is None


_TA = [_tool("toolA", RO), _tool("toolB", RO)]


def test_a_certain_warn_is_not_downgraded_by_an_extra_include_alias():
    """`toolA` is an exact inventory name, so the raw match keeps it reachable whatever
    `srv__x` turns out to mean: an include entry can only add matches."""
    assert _verdict({"include": ["toolA"]}, NEW, _TA) == (WARN, ["toolA"])  # control
    assert _verdict({"include": ["toolA", "srv__x"]}, NEW, _TA) == (WARN, ["toolA"])
    assert _verdict({"include": ["toolA", "srv__x"]}, None, _TA) == (WARN, ["toolA"])
    # a raw glob is just as certain as an exact name
    assert _verdict({"include": ["tool*", "srv__x"]}, NEW, _TA) == (WARN, ["toolA", "toolB"])


def test_an_include_that_is_only_an_alias_is_unknown_not_allow_all():
    assert _verdict({"include": ["srv__x"]}, NEW, _TA)[0] == UNKNOWN
    # control: with no non-alias include the certain set is empty, NOT "every tool"
    assert _verdict({"include": ["srv__x", "nothere"]}, NEW, _TA)[0] == UNKNOWN


def test_an_exclude_alias_makes_everything_uncertain_even_with_a_raw_include():
    assert _verdict({"include": ["toolA"]}, NEW, _TA) == (WARN, ["toolA"])  # control
    status, entries = _verdict({"include": ["toolA"], "exclude": ["srv__x"]}, NEW, _TA)
    assert status == UNKNOWN and entries == ["srv__x"]


def test_a_raw_exclude_still_removes_the_certain_tool():
    """include [toolA, srv__x] + raw exclude [toolA]: toolA is certainly out, so there is
    nothing certain left -- but another tool waives with the filter ignored and the alias
    might keep it, so UNKNOWN."""
    status, entries = _verdict({"include": ["toolA", "srv__x"], "exclude": ["toolA"]}, NEW, _TA)
    assert status == UNKNOWN and entries == ["srv__x"]
    # control: a raw exclude of the OTHER tool leaves toolA certain
    assert _verdict({"include": ["toolA", "srv__x"], "exclude": ["toolB"]}, NEW, _TA) == (
        WARN, ["toolA"])


def test_a_glob_containing_double_underscore_is_not_alias_shaped():
    assert _mcp_tool_filter_alias_entries({"include": ["srv__*"]}, ["fetch"]) == []
    assert _mcp_tool_filter_alias_entries({"exclude": ["*__fetch"]}, ["fetch"]) == []
    assert _verdict({"exclude": ["srv__*"]}, NEW) == (WARN, ["fetch"])  # control


def test_an_exact_tool_name_containing_double_underscore_is_not_alias_shaped():
    tools = [_tool("my__tool", RO)]
    assert _mcp_tool_filter_alias_entries({"include": ["my__tool"]}, ["my__tool"]) == []
    assert _verdict({"include": ["my__tool"]}, NEW, tools) == (WARN, ["my__tool"])
    # control: the same entry against an inventory that does not hold it IS alias-shaped
    assert _mcp_tool_filter_alias_entries({"include": ["my__tool"]}, ["other"]) == ["my__tool"]


def test_an_entry_without_double_underscore_is_never_an_alias():
    assert _mcp_tool_filter_alias_entries({"include": ["nope"], "exclude": ["srv_x"]},
                                          ["fetch"]) == []


def test_a_whitespace_padded_entry_is_trimmed_like_the_vendor_does():
    assert _mcp_tool_filter_alias_entries({"include": ["  srv__fetch \n"]}, ["x"]) == ["srv__fetch"]
    # padded exact name is still an exact name
    assert _mcp_tool_filter_alias_entries({"include": [" my__tool "]}, ["my__tool"]) == []
    # a character JS trim() keeps is NOT stripped, so the entry stays what it is
    assert _mcp_tool_filter_alias_entries({"include": ["\x1csrv__fetch"]}, ["x"]) == ["\x1csrv__fetch"]
    assert _mcp_tool_filter_alias_entries({"include": ["   "]}, ["x"]) == []


def test_include_and_exclude_are_both_read_and_deduplicated():
    f = {"include": ["srv__a", "srv__a"], "exclude": ["srv__b", "srv__a"]}
    assert _mcp_tool_filter_alias_entries(f, []) == ["srv__a", "srv__b"]
    assert _mcp_tool_filter_alias_entries(None, []) == []


# ---------------------------------------------------------------------------------------
# The check, end to end
# ---------------------------------------------------------------------------------------

def _finding(tmp_path, cfg, installed, cid="B333"):
    home = tmp_path / "home"
    home.mkdir()
    path = home / "openclaw.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(path, 0o600)
    ctx = collect(home)
    ctx.installed_dist_version = installed
    return next(f for f in C.run_all(ctx) if f.id == cid)


def _cfg(tool_filter=None):
    server = {"command": "srv", "tools": [_tool("fetch", RO)]}
    if tool_filter is not None:
        server["toolFilter"] = tool_filter
    return {"mcp": {"servers": {"srv": server}}}


def _tmp(tmp_path, leaf):
    p = tmp_path / leaf
    p.mkdir()
    return p


def test_the_check_reports_unknown_for_an_include_alias_on_a_new_build(tmp_path):
    control = _finding(_tmp(tmp_path, "a"), _cfg(), "2026.11.6")
    assert control.status == WARN
    f = _finding(_tmp(tmp_path, "b"), _cfg({"include": ["srv__fetch"]}), "2026.11.6")
    assert f.status == UNKNOWN
    text = (f.detail or "") + " " + " ".join(f.evidence or [])
    assert "srv__fetch" in text
    assert "2026.11.5" in (f.detail or "") and "alias" in (f.detail or "")


def test_the_check_reports_unknown_for_an_exclude_alias_on_a_new_build(tmp_path):
    f = _finding(tmp_path, _cfg({"exclude": ["srv__fetch"]}), "2026.11.6")
    assert f.status == UNKNOWN


def test_the_check_keeps_todays_result_below_the_floor(tmp_path):
    f = _finding(_tmp(tmp_path, "a"), _cfg({"include": ["srv__fetch"]}), "2026.11.4")
    assert f.status == PASS
    f = _finding(_tmp(tmp_path, "b"), _cfg({"exclude": ["srv__fetch"]}), "2026.11.4")
    assert f.status == WARN


def _stamped(tool_filter, stamp):
    cfg = _cfg(tool_filter)
    cfg["meta"] = {"lastTouchedVersion": stamp}
    return cfg


def test_a_stale_stamp_below_the_floor_never_selects_the_raw_path(tmp_path):
    """C-135 finding on B-1113: a config stamp is written at save time, so after an upgrade
    it understates the running build. With no installed build detected, a stamp below
    2026.11.5 must leave the build unknown (UNKNOWN), not select the raw path, which gives
    a missed WARN for an include alias and a false WARN for an exclude alias."""
    f = _finding(_tmp(tmp_path, "a"), _stamped({"include": ["srv__fetch"]}, "2026.10.1"), None)
    assert f.status == UNKNOWN
    f = _finding(_tmp(tmp_path, "b"), _stamped({"exclude": ["srv__fetch"]}, "2026.10.1"), None)
    assert f.status == UNKNOWN
    # Positive controls: the same stale stamp without an alias still WARNs, and an
    # INSTALLED build below the floor still selects the raw path.
    f = _finding(_tmp(tmp_path, "c"), _stamped(None, "2026.10.1"), None)
    assert f.status == WARN
    f = _finding(_tmp(tmp_path, "d"), _stamped({"include": ["srv__fetch"]}, "2026.10.1"), "2026.11.4")
    assert f.status == PASS


def test_a_stamp_at_or_above_the_floor_keeps_the_gate_on(tmp_path):
    f = _finding(tmp_path, _stamped({"include": ["srv__fetch"]}, "2026.11.6"), None)
    assert f.status == UNKNOWN


# ---------------------------------------------------------------------------------------
# Differential against the real vendor
# ---------------------------------------------------------------------------------------

_SCRIPT = """
import { readFileSync } from "node:fs";
const ns = await import(process.argv[2]);
const M = JSON.parse(process.argv[4]);
const normalize = ns[M.normalizeMcpToolFilter];
const create = ns[M.createMcpToolFilter];
const cases = JSON.parse(readFileSync(process.argv[3], "utf8"));
console.log(JSON.stringify(cases.map(([raw, scope, name]) => {
  const norm = normalize(raw ?? undefined);
  return { scoped: create(norm, scope)(name), raw: create(norm)(name) };
})));
"""

_NAMES = ["fetch", "a.b", "a.c", "a:c", "9lives", "my__tool", "x"]
_SCOPE = {"safeServerName": "srv", "toolNames": _NAMES}

_FILTERS = [
    {"include": ["srv__fetch"]},                       # include alias, unique unsuffixed owner
    {"exclude": ["srv__fetch"]},                       # exclude alias
    {"include": ["srv__fetch-2"]},                     # suffixed include: no unsuffixed owner
    {"exclude": ["srv__fetch-2"]},                     # suffixed exclude: hides every owner
    {"include": ["srv__tool-9lives"]},                 # leading digit -> `tool-` prefix
    {"exclude": ["srv__tool-9lives"]},
    {"include": ["srv__a-b"]},                         # punctuation tool name `a.b`
    {"exclude": ["srv__a-b"]},
    {"include": ["srv__a-c"]},                         # ambiguous: a.c and a:c both map here
    {"exclude": ["srv__a-c"]},
    {"include": ["srv__nobody"]},                      # no owner at all
    {"exclude": ["srv__nobody"]},
    {"include": ["srv__*"]},                           # glob containing `__`
    {"exclude": ["*__fetch"]},
    {"include": ["my__tool"]},                         # raw name containing `__`
    {"exclude": ["my__tool"]},
    {"include": ["  srv__fetch  "]},                   # whitespace padded alias
    {"exclude": ["  srv__x  "]},
    {"include": ["fetch"], "exclude": ["srv__a-b"]},   # mixed raw include + alias exclude
    {"include": ["srv__fetch", "x"]},
    {"exclude": ["srv__tool-9lives", "srv__a-c"]},
    {"include": ["fetch", "x"]},                       # control: raw only, no `__`
    {"exclude": ["a.b"]},
]

_CASES = [(f, _SCOPE, n) for f in _FILTERS for n in _NAMES]


def _run_vendor(tmp_path):
    module = dist_file("mcp-tool-filter-*.js", symbol="createMcpToolFilter",
                       contains="function createMcpToolFilter(")
    (tmp_path / "f.mjs").write_text(_SCRIPT, encoding="utf-8")
    (tmp_path / "cases.json").write_text(json.dumps([list(c) for c in _CASES]),
                                         encoding="utf-8")
    proc = subprocess.run(
        ["node", str(tmp_path / "f.mjs"), str(module), str(tmp_path / "cases.json"),
         _alias_map(module, ("normalizeMcpToolFilter", "createMcpToolFilter"))],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def _flagged(tool_filter):
    return _mcp_tool_filter_alias_entries(_mcp_normalize_tool_filter(tool_filter), _NAMES)


@pytest.mark.skipif(shutil.which("node") is None, reason="no node on this machine")
def test_every_case_where_the_scoped_vendor_differs_from_raw_is_flagged(tmp_path):
    """The soundness claim. Wherever resolving aliases against the inventory changes the
    answer, the helper must have flagged an entry -- otherwise B333 would still speak
    (WARN or PASS) about a tool whose reachability it cannot know."""
    dist = _run_vendor(tmp_path)
    assert len(dist) == len(_CASES)

    differing, missed, agreeing_alias = [], [], []
    for (flt, _scope, name), got in zip(_CASES, dist):
        flagged = _flagged(flt)
        if got["scoped"] != got["raw"]:
            differing.append((flt, name))
            if not flagged:
                missed.append(f"{flt!r} / {name!r}: scoped={got['scoped']} raw={got['raw']}")
        elif any("__" in e for e in (flt.get("include", []) + flt.get("exclude", []))):
            agreeing_alias.append((flt, name))
    assert not missed, "\n".join(missed)
    # The battery must actually exercise the difference, and a flag that is merely
    # over-eager must be visible as such: a no-op helper would pass neither.
    assert len(differing) >= 5, len(differing)
    assert agreeing_alias, "no case where the vendor agrees yet the entry contains __"


def test_the_battery_has_a_filter_the_helper_leaves_alone():
    """Control for the differential: a helper that flags everything would satisfy the
    soundness test trivially."""
    assert _flagged({"include": ["fetch", "x"]}) == []
    assert _flagged({"include": ["my__tool"]}) == []
    assert _flagged({"include": ["srv__*"]}) == []
    assert _flagged({"include": ["srv__fetch"]}) == ["srv__fetch"]
