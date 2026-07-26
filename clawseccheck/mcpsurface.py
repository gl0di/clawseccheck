"""MCP tool-surface: three sources -> one canonical form.

Leaf module (Layer 1): imports only ``trajectory`` + stdlib — nothing from
``checks/``, so there is no import cycle. It feeds ``checks/_mcp.py``'s
``vet_mcp``, which runs the resulting surface through the existing
``SKILL_CONTENT_RING`` via a synthetic ``Context`` — the same mechanism
``vet_skill`` already uses for installed skills. No new detection logic lives
here; this module only normalises MCP tool-surface data into the shape the
ring already understands.

Read-only, offline (GR#1/GR#2): nothing here launches an MCP server, performs
a live handshake, or makes a network call. All three sources are local files
the caller already has:

  - ``from_tool_defs`` / the inline path: a server's own config-embedded
    ``tools`` list (already loaded by the caller — no file I/O here).
  - ``from_manifest``: a dump the user produced with an external tool
    (mcporter, an MCP inspector) and handed us the resulting local JSON.
  - ``from_trajectory``: what the host already compiled and sent the model,
    read from local trajectory sidecars (post-hoc forensic evidence only).
  - ``from_probe_json``: an ``openclaw mcp probe --json`` dump the user ran
    themselves — names only, grounded on OpenClaw's own
    ``formatMcpProbeResult`` (dist, 2026.7.1-2).

All manifest/probe/trajectory inputs are attacker-influenced (a malicious MCP
server controls its own tool descriptions), so every loader is bounded the
same way ``collector.py`` bounds config/bootstrap reads: file size, server
count, tools-per-server, params-per-tool, and text length all have caps.
Hitting a cap sets ``ToolSurface.truncated = True`` — callers must treat that
as "cannot give a confident PASS", never silently drop the excess (B-092).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from . import trajectory as _trajectory

# Caps -- see the module docstring: every input here is attacker-influenced.
_MAX_FILE_BYTES = 2_000_000
_MAX_TOOLS_PER_SERVER = 500
_MAX_PARAMS_PER_TOOL = 100
_MAX_TEXT_LEN = 4000
_MAX_PROBE_NAMES = 100_000

_NAMESPACE_SEP = "__"


def _bounded_text(value: object, limit: int = _MAX_TEXT_LEN) -> str:
    if not isinstance(value, str):
        return ""
    return value[:limit]


@dataclass
class ToolParam:
    name: str
    description: str = ""
    default: str = ""
    schema_type: str = ""


@dataclass
class ToolDef:
    name: str
    title: str = ""
    description: str = ""
    params: list = field(default_factory=list)
    annotations: "dict | None" = None
    server: str = ""


@dataclass
class ToolSurface:
    server: str
    tools: list
    source: str  # "manifest" | "trajectory" | "probe-names"
    completeness: str  # "full" | "names-only" | "partial"
    host_sanitized: bool = False  # True only for "trajectory" -- see from_trajectory
    truncated: bool = False  # a cap was hit -> callers must not report a confident PASS


def _params_from_schema(schema: object) -> tuple[list, bool]:
    """Extract ToolParam entries from a JSON-Schema ``inputSchema``-shaped dict.

    Returns ``(params, truncated)``.
    """
    if not isinstance(schema, dict):
        return [], False
    props = schema.get("properties")
    if not isinstance(props, dict):
        return [], False
    truncated = len(props) > _MAX_PARAMS_PER_TOOL
    out = []
    for pname, pdef in list(props.items())[:_MAX_PARAMS_PER_TOOL]:
        if not isinstance(pdef, dict):
            out.append(ToolParam(name=_bounded_text(str(pname), 200)))
            continue
        out.append(
            ToolParam(
                name=_bounded_text(str(pname), 200),
                description=_bounded_text(pdef.get("description")),
                default=_bounded_text(str(pdef["default"])) if "default" in pdef else "",
                schema_type=_bounded_text(str(pdef["type"])) if "type" in pdef else "",
            )
        )
    return out, truncated


def _tool_def_from_dict(raw: object, server: str) -> tuple["ToolDef | None", bool]:
    """Build one ToolDef from a raw ``tools/list``-shaped dict.

    Returns ``(tool_or_none, truncated)``. ``None`` for a malformed entry —
    never a guess (mirrors ``trajectory._compiled_tool_entry``).
    """
    if not isinstance(raw, dict):
        return None, False
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        return None, False
    params, truncated = _params_from_schema(raw.get("inputSchema"))
    annotations = raw.get("annotations")
    tool = ToolDef(
        name=_bounded_text(name.strip(), 200),
        title=_bounded_text(raw.get("title")),
        description=_bounded_text(raw.get("description")),
        params=params,
        annotations=annotations if isinstance(annotations, dict) else None,
        server=server,
    )
    return tool, truncated


def from_tool_defs(
    server: str,
    tools: object,
    *,
    source: str = "manifest",
    completeness: str = "full",
    host_sanitized: bool = False,
) -> "ToolSurface | None":
    """Build a ToolSurface from an already-parsed list of raw tool dicts.

    *tools* is a ``tools/list``-shaped list — each entry
    ``{name, description, inputSchema, annotations, ...}`` — the shape both an
    MCP server's own ``tools/list`` response and an inline
    ``mcp.servers.<name>.tools`` spec use. This is the entry point ``vet_mcp``
    calls directly for the config-embedded path (no file round-trip needed —
    the spec dict is already in memory). Returns ``None`` when *tools* is not
    a non-empty list, or contains no parseable tool dict.
    """
    if not isinstance(tools, list) or not tools:
        return None
    truncated = len(tools) > _MAX_TOOLS_PER_SERVER
    out: list = []
    for raw in tools[:_MAX_TOOLS_PER_SERVER]:
        tool, param_truncated = _tool_def_from_dict(raw, server)
        if param_truncated:
            truncated = True
        if tool is not None:
            out.append(tool)
    if not out:
        return None
    return ToolSurface(
        server=server,
        tools=out,
        source=source,
        completeness=completeness,
        host_sanitized=host_sanitized,
        truncated=truncated,
    )


def from_manifest(path: "str | Path") -> "ToolSurface | None":
    """Read a user-produced tool-surface dump and build a ToolSurface.

    We never talk to an MCP server ourselves (GR#2) — the caller runs their
    own tool (mcporter, an MCP inspector) and hands us the resulting local
    JSON file. Accepts:

      - ``{"tools": [...]}``                 a raw ``tools/list`` response
      - ``{"server": "<name>", "tools": [...]}``
      - ``[...]``                            a bare list of tool dicts

    The server name defaults to the file stem when not given explicitly.
    Returns ``None`` if the file cannot be read, parsed, or matched to one of
    these shapes — never a guess.
    """
    p = Path(str(path)).expanduser()
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    truncated_read = len(text) > _MAX_FILE_BYTES
    if truncated_read:
        text = text[:_MAX_FILE_BYTES]
    try:
        data = json.loads(text)
    except ValueError:
        return None

    server = p.stem
    tools: object = None
    if isinstance(data, list):
        tools = data
    elif isinstance(data, dict):
        name = data.get("server")
        if isinstance(name, str) and name.strip():
            server = name.strip()
        raw_tools = data.get("tools")
        if isinstance(raw_tools, list):
            tools = raw_tools
    if tools is None:
        return None
    surface = from_tool_defs(server, tools, source="manifest", completeness="full")
    if surface is not None and truncated_read:
        surface.truncated = True
    return surface


def _server_from_namespaced_name(name: str) -> "str | None":
    """Split an OpenClaw MCP tool name into its owning server.

    OpenClaw namespaces MCP tool names as ``mcp__<server>__<tool>`` (see
    ``checks/_mcp.py``'s ``check_mcp_bypass_highblast``, grounded the same
    way) — or, in a handful of older/plugin call sites, bare
    ``<server>__<tool>``. Returns ``None`` for a name with no ``__`` — that is
    a native/built-in tool, not an MCP one, and out of scope here.
    """
    if not isinstance(name, str) or _NAMESPACE_SEP not in name:
        return None
    head, _, rest = name.partition(_NAMESPACE_SEP)
    if head == "mcp" and _NAMESPACE_SEP in rest:
        server, _, _ = rest.partition(_NAMESPACE_SEP)
        return server or None
    return head or None


def from_trajectory(home: "str | Path") -> list:
    """Build ToolSurfaces from what the host actually compiled and sent the model.

    POST-HOC FORENSIC evidence only (via
    ``trajectory.read_compiled_tool_descriptions``): it reports what WAS sent
    to the model in sessions that already ran — it cannot pre-clear a live MCP
    server, and a server that served a clean description in the past may serve
    a poisoned one later.

    Tool defs are grouped back into one ToolSurface per server using the
    ``mcp__<server>__<tool>`` naming convention; entries with no server prefix
    are native tools and are dropped. ``host_sanitized=True`` on every surface
    here — the host's own metadata sanitizer already ran on this text before
    it reached the model (see the design doc §2.2 for what that sanitizer
    does and does not catch).
    """
    tool_dicts, meta = _trajectory.read_compiled_tool_descriptions(Path(str(home)).expanduser())
    truncated = bool(meta.get("truncated"))
    by_server: dict = {}
    for entry in tool_dicts:
        name = entry.get("name", "")
        server = _server_from_namespaced_name(name)
        if server is None:
            continue
        params = [
            ToolParam(
                name=_bounded_text(pname, 200),
                description=_bounded_text(pdesc),
                default=_bounded_text(pdefault),
            )
            for pname, pdesc, pdefault in entry.get("params", [])
        ]
        by_server.setdefault(server, []).append(
            ToolDef(
                name=_bounded_text(name, 200),
                description=_bounded_text(entry.get("description")),
                params=params,
                server=server,
            )
        )
    return [
        ToolSurface(
            server=server,
            tools=tools,
            source="trajectory",
            completeness="full",
            host_sanitized=True,
            truncated=truncated,
        )
        for server, tools in sorted(by_server.items())
    ]


def from_probe_json(path: "str | Path") -> list:
    """Read an ``openclaw mcp probe --json`` dump and build names-only ToolSurfaces.

    Grounded on OpenClaw's own ``formatMcpProbeResult``
    (``mcp-cli-*.js``, dist ``openclaw@2026.7.1-2``, 2026-07-25): the JSON
    carries a per-server ``servers`` map (name -> metadata, including a tool
    COUNT) and one GLOBAL, flattened, alphabetically-sorted ``tools`` array of
    tool NAMES ONLY — no descriptions, no ``inputSchema``. There is no
    first-party dump of the full surface (design doc §2.3), which is exactly
    why this source exists alongside ``from_manifest``.

    Names are split back to their owning server with the same
    ``mcp__<server>__<tool>`` convention ``from_trajectory`` uses, and cross-
    checked against the dump's own ``servers`` keys when present. Every
    surface returned has ``completeness="names-only"`` — there is nothing here
    for the content ring to scan, by design; ``render_for_ring`` reflects that
    with an empty render rather than guessing from names alone.
    """
    p = Path(str(path)).expanduser()
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if len(text) > _MAX_FILE_BYTES:
        text = text[:_MAX_FILE_BYTES]
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    names = data.get("tools")
    if not isinstance(names, list):
        return []
    servers_field = data.get("servers")
    known_servers = set(servers_field) if isinstance(servers_field, dict) else None

    truncated = len(names) > _MAX_PROBE_NAMES
    by_server: dict = {}
    for raw in names[:_MAX_PROBE_NAMES]:
        if not isinstance(raw, str):
            continue
        server = _server_from_namespaced_name(raw)
        if server is None:
            continue
        if known_servers is not None and server not in known_servers:
            continue
        by_server.setdefault(server, []).append(_bounded_text(raw, 200))

    surfaces = []
    for server, tool_names in sorted(by_server.items()):
        server_truncated = truncated or len(tool_names) > _MAX_TOOLS_PER_SERVER
        surfaces.append(
            ToolSurface(
                server=server,
                tools=[
                    ToolDef(name=n, server=server) for n in tool_names[:_MAX_TOOLS_PER_SERVER]
                ],
                source="probe-names",
                completeness="names-only",
                host_sanitized=False,
                truncated=server_truncated,
            )
        )
    return surfaces


def render_for_ring(surface: ToolSurface) -> dict:
    """Render one ToolSurface into the ``{label: text}`` shape SKILL_CONTENT_RING expects.

    The label always names the subject as *"MCP tool surface of server
    'X'"* — never "skill" — so a ring finding built from it (and any renderer
    that later prints ``ctx.installed_skills`` keys verbatim) stays honest
    about what was actually scanned.

    ``completeness == "names-only"`` renders to an EMPTY dict on purpose:
    there is no description text for the ring to scan, and running 39
    description-scanning checks against bare tool names would either find
    nothing (a false PASS) or match spuriously on names alone — neither is
    honest. Absence of clues is not clean evidence (B-092): callers must
    treat "nothing rendered" as a reason to report UNKNOWN, not PASS.

    Deliberately renders tool name/title/description only — NOT parameter
    text (``ToolParam.description``/``default``). checks/_mcp.py's own
    ``_PARAM_OVERRIDE_INSTR_RE``/``_param_override_reason`` already scans the
    parameter surface, calibrated to WARN-only after four C-135 rounds
    (B-338) retracted its FAIL capability there — parameter fields carry a
    materially higher false-positive rate than a tool's own description
    (legitimate fields documenting example/quoted input). The generic ring
    checks (e.g. B64) have no notion of that calibration and would FAIL on
    parameter text unconditionally; reproduced end-to-end via
    fixtures/bad_b338_mcp_param_anchored.json, whose own pinned test expects
    WARN, not FAIL. Keeping parameter text out of the ring blob leaves that
    calibrated surface exactly where it already lives, unaffected by this
    wiring.
    """
    if surface.completeness == "names-only" or not surface.tools:
        return {}
    label = f"MCP tool surface of server '{surface.server}'"
    parts: list[str] = []
    for tool in surface.tools:
        parts.append(tool.name)
        if tool.title:
            parts.append(tool.title)
        if tool.description:
            parts.append(tool.description)
    return {label: "\n".join(parts)}
