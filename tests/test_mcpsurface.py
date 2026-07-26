"""Tests for clawseccheck.mcpsurface — the three-sources-to-one-canonical-form leaf.

Covers:
- from_tool_defs: happy path, malformed entries dropped not guessed, caps/truncated
- from_manifest: {"tools":[...]}, {"server":..,"tools":[...]}, bare list, bad file
- from_trajectory: mcp__server__tool grouping, native tools dropped, host_sanitized
- from_probe_json: formatMcpProbeResult shape, name-to-server split, names-only
- render_for_ring: label wording, names-only -> {}, empty surface -> {}
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck import mcpsurface as ms


# ---------------------------------------------------------------------------
# from_tool_defs
# ---------------------------------------------------------------------------

def test_from_tool_defs_happy_path():
    surface = ms.from_tool_defs(
        "srv",
        [
            {
                "name": "lookup",
                "title": "Lookup",
                "description": "Look something up.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "the query", "default": "x"}
                    },
                },
                "annotations": {"readOnlyHint": True},
            }
        ],
    )
    assert surface is not None
    assert surface.server == "srv"
    assert surface.source == "manifest"
    assert surface.completeness == "full"
    assert surface.host_sanitized is False
    assert surface.truncated is False
    assert len(surface.tools) == 1
    tool = surface.tools[0]
    assert tool.name == "lookup"
    assert tool.title == "Lookup"
    assert tool.description == "Look something up."
    assert tool.server == "srv"
    assert tool.annotations == {"readOnlyHint": True}
    assert len(tool.params) == 1
    assert tool.params[0].name == "query"
    assert tool.params[0].description == "the query"
    assert tool.params[0].default == "x"
    assert tool.params[0].schema_type == "string"


def test_from_tool_defs_not_a_list_returns_none():
    assert ms.from_tool_defs("srv", {"name": "not-a-list"}) is None
    assert ms.from_tool_defs("srv", None) is None
    assert ms.from_tool_defs("srv", []) is None


def test_from_tool_defs_malformed_entries_dropped_not_guessed():
    surface = ms.from_tool_defs(
        "srv",
        [
            "not-a-dict",
            {"description": "no name field"},
            {"name": "", "description": "blank name"},
            {"name": "  ", "description": "whitespace-only name"},
            {"name": "real_tool", "description": "fine"},
        ],
    )
    assert surface is not None
    assert [t.name for t in surface.tools] == ["real_tool"]


def test_from_tool_defs_all_malformed_returns_none():
    assert ms.from_tool_defs("srv", [{"no": "name"}, "junk"]) is None


def test_from_tool_defs_tool_count_cap_sets_truncated():
    tools = [{"name": f"t{i}", "description": "d"} for i in range(ms._MAX_TOOLS_PER_SERVER + 5)]
    surface = ms.from_tool_defs("srv", tools)
    assert surface is not None
    assert surface.truncated is True
    assert len(surface.tools) == ms._MAX_TOOLS_PER_SERVER


def test_from_tool_defs_param_count_cap_sets_truncated():
    props = {f"p{i}": {"type": "string"} for i in range(ms._MAX_PARAMS_PER_TOOL + 5)}
    surface = ms.from_tool_defs(
        "srv", [{"name": "t", "inputSchema": {"type": "object", "properties": props}}]
    )
    assert surface is not None
    assert surface.truncated is True
    assert len(surface.tools[0].params) == ms._MAX_PARAMS_PER_TOOL


def test_from_tool_defs_long_text_is_bounded():
    huge = "A" * (ms._MAX_TEXT_LEN * 3)
    surface = ms.from_tool_defs("srv", [{"name": "t", "description": huge}])
    assert surface is not None
    assert len(surface.tools[0].description) == ms._MAX_TEXT_LEN


# ---------------------------------------------------------------------------
# from_manifest
# ---------------------------------------------------------------------------

def test_from_manifest_bare_tools_dump(tmp_path):
    p = tmp_path / "dump.json"
    p.write_text(json.dumps({"tools": [{"name": "a", "description": "d"}]}), encoding="utf-8")
    surface = ms.from_manifest(p)
    assert surface is not None
    assert surface.server == "dump"  # file-stem fallback
    assert [t.name for t in surface.tools] == ["a"]


def test_from_manifest_explicit_server_name(tmp_path):
    p = tmp_path / "dump.json"
    p.write_text(
        json.dumps({"server": "real-name", "tools": [{"name": "a", "description": "d"}]}),
        encoding="utf-8",
    )
    surface = ms.from_manifest(p)
    assert surface is not None
    assert surface.server == "real-name"


def test_from_manifest_bare_list(tmp_path):
    p = tmp_path / "toollist.json"
    p.write_text(json.dumps([{"name": "a", "description": "d"}]), encoding="utf-8")
    surface = ms.from_manifest(p)
    assert surface is not None
    assert surface.server == "toollist"


def test_from_manifest_missing_file_returns_none(tmp_path):
    assert ms.from_manifest(tmp_path / "nope.json") is None


def test_from_manifest_unparseable_json_returns_none(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    assert ms.from_manifest(p) is None


def test_from_manifest_wrong_shape_returns_none(tmp_path):
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps({"command": "npx"}), encoding="utf-8")
    assert ms.from_manifest(p) is None


def test_from_manifest_oversized_file_is_truncated(tmp_path, monkeypatch):
    monkeypatch.setattr(ms, "_MAX_FILE_BYTES", 40)
    p = tmp_path / "dump.json"
    p.write_text(json.dumps({"tools": [{"name": "a", "description": "d" * 200}]}), encoding="utf-8")
    surface = ms.from_manifest(p)
    # Truncated read likely breaks JSON parsing entirely -> None is an acceptable,
    # honest outcome (never a guessed partial parse of corrupted JSON).
    assert surface is None or surface.truncated is True


# ---------------------------------------------------------------------------
# from_trajectory
# ---------------------------------------------------------------------------

def _write_compiled_event(home: Path, tools: list[dict]) -> None:
    sessions_dir = home / "agents" / "main" / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    rec = {
        "traceSchema": "openclaw-trajectory",
        "schemaVersion": 1,
        "type": "context.compiled",
        "data": {"tools": tools},
    }
    (sessions_dir / "session-1.trajectory.jsonl").write_text(
        json.dumps(rec) + "\n", encoding="utf-8"
    )


def test_from_trajectory_groups_by_namespaced_server(tmp_path):
    _write_compiled_event(
        tmp_path,
        [
            {"name": "mcp__alpha__search", "description": "search alpha"},
            {"name": "mcp__alpha__lookup", "description": "lookup alpha"},
            {"name": "mcp__beta__fetch", "description": "fetch beta"},
            {"name": "native_tool", "description": "not MCP, no namespace"},
        ],
    )
    surfaces = ms.from_trajectory(tmp_path)
    by_server = {s.server: s for s in surfaces}
    assert set(by_server) == {"alpha", "beta"}
    assert {t.name for t in by_server["alpha"].tools} == {
        "mcp__alpha__search",
        "mcp__alpha__lookup",
    }
    assert all(s.source == "trajectory" for s in surfaces)
    assert all(s.completeness == "full" for s in surfaces)
    assert all(s.host_sanitized is True for s in surfaces)


def test_from_trajectory_no_files_returns_empty(tmp_path):
    assert ms.from_trajectory(tmp_path) == []


def test_from_trajectory_bare_double_underscore_name(tmp_path):
    _write_compiled_event(tmp_path, [{"name": "gamma__do_thing", "description": "d"}])
    surfaces = ms.from_trajectory(tmp_path)
    assert len(surfaces) == 1
    assert surfaces[0].server == "gamma"


# ---------------------------------------------------------------------------
# from_probe_json
# ---------------------------------------------------------------------------

def _probe_dump(servers: dict, tools: list[str]) -> dict:
    return {
        "generatedAt": "2026-07-25T00:00:00.000Z",
        "servers": {name: {"launch": "…", "tools": len([t for t in tools if t.startswith(f"mcp__{name}__")])} for name in servers},
        "tools": sorted(tools),
        "diagnostics": [],
    }


def test_from_probe_json_splits_names_by_server(tmp_path):
    dump = _probe_dump(
        {"alpha": {}, "beta": {}},
        ["mcp__alpha__search", "mcp__alpha__lookup", "mcp__beta__fetch"],
    )
    p = tmp_path / "probe.json"
    p.write_text(json.dumps(dump), encoding="utf-8")
    surfaces = ms.from_probe_json(p)
    by_server = {s.server: s for s in surfaces}
    assert set(by_server) == {"alpha", "beta"}
    for s in surfaces:
        assert s.completeness == "names-only"
        assert s.source == "probe-names"
        assert s.host_sanitized is False


def test_from_probe_json_ignores_names_for_unknown_server(tmp_path):
    dump = _probe_dump({"alpha": {}}, ["mcp__alpha__search", "mcp__ghost__vanish"])
    p = tmp_path / "probe.json"
    p.write_text(json.dumps(dump), encoding="utf-8")
    surfaces = ms.from_probe_json(p)
    assert [s.server for s in surfaces] == ["alpha"]


def test_from_probe_json_bad_shape_returns_empty(tmp_path):
    p = tmp_path / "probe.json"
    p.write_text(json.dumps({"nope": True}), encoding="utf-8")
    assert ms.from_probe_json(p) == []


def test_from_probe_json_missing_file_returns_empty(tmp_path):
    assert ms.from_probe_json(tmp_path / "nope.json") == []


# ---------------------------------------------------------------------------
# render_for_ring
# ---------------------------------------------------------------------------

def test_render_for_ring_label_names_the_server_not_a_skill():
    surface = ms.from_tool_defs("acme", [{"name": "t", "description": "does a thing"}])
    rendered = ms.render_for_ring(surface)
    assert len(rendered) == 1
    (label, text), = rendered.items()
    assert label == "MCP tool surface of server 'acme'"
    assert "skill" not in label.lower()
    assert "does a thing" in text


def test_render_for_ring_names_only_is_empty():
    surface = ms.ToolSurface(
        server="acme",
        tools=[ms.ToolDef(name="t", server="acme")],
        source="probe-names",
        completeness="names-only",
    )
    assert ms.render_for_ring(surface) == {}


def test_render_for_ring_no_tools_is_empty():
    surface = ms.ToolSurface(server="acme", tools=[], source="manifest", completeness="full")
    assert ms.render_for_ring(surface) == {}


def test_render_for_ring_excludes_param_text():
    # Parameter text is deliberately NOT rendered into the ring blob -- that surface
    # is already scanned by checks/_mcp.py's own WARN-only-calibrated param-override
    # detection (B-338); blending it into the ring would let a generic FAIL-capable
    # ring check (e.g. B64) re-FAIL on parameter text the project spent four C-135
    # rounds capping at WARN. See fixtures/bad_b338_mcp_param_anchored.json.
    surface = ms.from_tool_defs(
        "acme",
        [
            {
                "name": "t",
                "description": "d",
                "inputSchema": {
                    "type": "object",
                    "properties": {"q": {"type": "string", "description": "the query param"}},
                },
            }
        ],
    )
    rendered = ms.render_for_ring(surface)
    (text,) = rendered.values()
    assert "the query param" not in text
    assert text == "t\nd"
