"""B333 (F-143/W2.1) — MCP tool safety-hint annotations declared but not enforced.

Grounded against dist openclaw@2026.7.1-2 (2026-07-25): when OpenClaw registers an MCP
tool it stores exactly {serverName, safeServerName, toolName, title, description,
inputSchema, fallbackDescription} — `annotations` is NEVER stored. readOnlyHint /
destructiveHint / openWorldHint / idempotentHint exist only in the
@modelcontextprotocol/sdk vendor .d.ts types (compile-time only); OpenClaw's runtime
never reads them.

WARN    — a config-embedded (source == "manifest") tool declares one of the four hint
          keys. This is a host limitation, not server wrongdoing — the wording must say
          OpenClaw does not READ the hints, never that the server "lied".
UNKNOWN — no MCP servers configured, no embedded rich tool definitions to inspect, or
          the only annotation evidence available came from a source (trajectory /
          probe-names) that structurally cannot carry annotations at all.
PASS    — embedded tool definitions were inspected and none declare any hint.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck import mcpsurface as ms
from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import _b333_surface_verdict, check_mcp_unenforced_annotations
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def _mcp(servers: dict) -> Context:
    return _ctx({"mcp": {"servers": servers}})


_NO_ANNOTATION_TOOLS = [
    {
        "name": "save_note",
        "description": "Saves a note to the workspace notebook.",
        "inputSchema": {
            "type": "object",
            "properties": {"body": {"type": "string", "description": "the note body"}},
        },
    }
]

_DESTRUCTIVE_TOOLS = [
    {
        "name": "delete_file",
        "description": "Deletes a file from the workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "the file path"}},
        },
        "annotations": {"destructiveHint": True},
    }
]


# --------------------------------------------------------------------------- UNKNOWN
def test_b333_unknown_no_mcp_servers():
    f = check_mcp_unenforced_annotations(_ctx({}))
    assert f.id == "B333"
    assert f.status == UNKNOWN
    assert "No MCP servers configured" in f.detail


def test_b333_unknown_servers_without_embedded_tool_defs():
    """mcp.servers present but `tools` is absent (or a bare name allowlist, not a rich
    tools/list) — no annotation data is available to assess, so this is UNKNOWN, not a
    guessed PASS."""
    f = check_mcp_unenforced_annotations(_mcp({"local": {"command": "npx", "args": ["srv"]}}))
    assert f.status == UNKNOWN
    assert "no embedded" in f.detail.lower() or "no embedded" in f.detail


def test_b333_unknown_bare_name_allowlist_not_mistaken_for_tool_defs():
    """`tools` as a bare name-string allowlist (the common real-world shape) is not a
    rich tools/list — from_tool_defs returns None for it, so this must not silently
    read as PASS."""
    f = check_mcp_unenforced_annotations(
        _mcp({"local": {"command": "npx", "args": ["srv"], "tools": ["read_file", "write_file"]}})
    )
    assert f.status == UNKNOWN


def test_b333_unknown_path_explicit_via_helper_trajectory_source():
    """Explicit coverage of the UNKNOWN path: a ToolSurface WITH an annotation but
    sourced from OpenClaw's own retained/compiled form ("trajectory") proves nothing —
    that source structurally never carries annotations at all, so its presence here is
    synthetic/adversarial, not evidence of what the server declared. Must be UNKNOWN,
    never WARN."""
    tool = ms.ToolDef(name="delete_file", annotations={"destructiveHint": True}, server="srv")
    surface = ms.ToolSurface(
        server="srv", tools=[tool], source="trajectory", completeness="full", host_sanitized=True
    )
    verdict = _b333_surface_verdict(surface)
    assert verdict is not None
    status, hinted = verdict
    assert status == UNKNOWN
    assert hinted == ["delete_file"]


def test_b333_unknown_path_explicit_via_helper_probe_names_source():
    """Same as above for the other structurally-annotation-free source, probe-names."""
    tool = ms.ToolDef(name="delete_file", annotations={"readOnlyHint": False}, server="srv")
    surface = ms.ToolSurface(
        server="srv", tools=[tool], source="probe-names", completeness="names-only"
    )
    verdict = _b333_surface_verdict(surface)
    assert verdict is not None
    assert verdict[0] == UNKNOWN


# --------------------------------------------------------------------------- WARN
def test_b333_warn_manifest_source_destructive_hint():
    f = check_mcp_unenforced_annotations(
        _mcp({"files-mcp": {"command": "npx", "args": ["srv"], "tools": _DESTRUCTIVE_TOOLS}})
    )
    assert f.status == WARN
    assert "files-mcp" in "".join(f.evidence)
    assert "delete_file" in "".join(f.evidence)
    # The exact wording constraint from the spec: state the host fact, never accuse the
    # server of lying.
    assert "OpenClaw does not read destructiveHint" in f.detail
    assert "readOnlyHint" in f.detail
    assert "lie" not in f.detail.lower()
    assert "lied" not in f.detail.lower()


def test_b333_warn_evidence_names_the_server_and_tool():
    f = check_mcp_unenforced_annotations(
        _mcp({"files-mcp": {"tools": _DESTRUCTIVE_TOOLS}})
    )
    assert f.status == WARN
    assert f.evidence
    assert any("files-mcp" in e and "delete_file" in e for e in f.evidence)


def test_b333_helper_manifest_source_returns_warn():
    tool = ms.ToolDef(name="delete_file", annotations={"destructiveHint": True}, server="srv")
    surface = ms.ToolSurface(server="srv", tools=[tool], source="manifest", completeness="full")
    verdict = _b333_surface_verdict(surface)
    assert verdict is not None
    status, hinted = verdict
    assert status == WARN
    assert hinted == ["delete_file"]


# --------------------------------------------------------------------------- PASS
def test_b333_pass_no_annotations_anywhere():
    f = check_mcp_unenforced_annotations(
        _mcp({"notes-mcp": {"command": "npx", "args": ["srv"], "tools": _NO_ANNOTATION_TOOLS}})
    )
    assert f.status == PASS


def test_b333_helper_no_annotations_returns_none():
    tool = ms.ToolDef(name="lookup", server="srv")
    surface = ms.ToolSurface(server="srv", tools=[tool], source="manifest", completeness="full")
    assert _b333_surface_verdict(surface) is None


# --------------------------------------------------------------------------- fixtures
def test_b333_clean_fixture_passes():
    f = check_mcp_unenforced_annotations(collect(FIXTURES / "clean_b333_mcp_no_annotations"))
    assert f.status == PASS


def test_b333_bad_fixture_warns():
    f = check_mcp_unenforced_annotations(collect(FIXTURES / "bad_b333_mcp_annotation_ignored"))
    assert f.status == WARN
    assert "OpenClaw does not read destructiveHint" in f.detail


def test_b333_registered_in_audit():
    from clawseccheck import audit

    _, findings, _ = audit(FIXTURES / "bad_b333_mcp_annotation_ignored", include_native=False)
    ids = {f.id for f in findings}
    assert "B333" in ids, f"B333 not in audit findings: {sorted(ids)}"
