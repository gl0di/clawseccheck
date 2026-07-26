"""RISK-22 (F-146/W2.4): toxic flow within a SINGLE MCP server's own tool set.

mcptrustchecker's MTC-FLOW-* class: a server can expose all three legs of a
confused-deputy chain among its OWN declared tools -- an untrusted-input tool, a
sensitive-read tool, and an egress tool -- with every individual tool innocuous in
isolation. RISK-02 (Lethal Trifecta) already covers the WHOLE-AGENT shape; this
chain narrows the same three roles to co-residence on ONE server.

Advisory-only: not a check_* function, not in CHECKS, does not move the A-F grade.
Classification reuses the SAME verb-class hint tuples RISK-02 keys tool-name
classification on (INPUT_TOOL_HINTS / SENSITIVE_TOOL_HINTS / OUTBOUND_TOOL_HINTS),
applied per-tool to name+title+description rather than to the whole agent's tool
list -- no new keyword enum.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.collector import Context
from clawseccheck import mcpsurface
from clawseccheck.risk import (
    _mcp_toxic_flow_candidates,
    _mcp_tool_roles,
    risk_paths,
)


def _ctx(tools):
    c = Context(home=Path("/nonexistent"))
    c.config = {
        "mcp": {
            "servers": {
                "srv": {
                    "command": "node",
                    "args": ["server.js"],
                    "tools": tools,
                }
            }
        }
    }
    return c


def _risk22(tools):
    ctx = _ctx(tools)
    paths = risk_paths(ctx, findings=[])
    return next((p for p in paths if p.id == "RISK-22"), None)


_READ_ONLY_TOOLS = [
    {"name": "list_files", "description": "Lists files in the local workspace."},
    {"name": "get_status", "description": "Returns the current job status."},
]

_FETCH_AND_EGRESS_TOOLS = [
    {"name": "fetch_url", "description": "Fetches a web page over HTTP."},
    {"name": "send_email", "description": "Sends an email to the given recipient."},
]

_ALL_THREE_ROLES_TOOLS = [
    {"name": "fetch_url", "description": "Fetches a web page over HTTP."},
    {"name": "read_secret", "description": "Reads a stored credential from the vault."},
    {"name": "send_email", "description": "Sends an email to the given recipient."},
]


# --------------------------------------------------------------------------- clean

def test_read_only_server_does_not_fire():
    """No untrusted-input, no sensitive-read, no egress tool -> silent."""
    assert _risk22(_READ_ONLY_TOOLS) is None


def test_fetch_and_egress_without_sensitive_read_does_not_fire():
    """Only two of the three legs (input + egress) -> silent; missing sensitive-read."""
    assert _risk22(_FETCH_AND_EGRESS_TOOLS) is None


def test_no_mcp_servers_configured_does_not_fire():
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = {}
    assert not any(p.id == "RISK-22" for p in risk_paths(ctx, findings=[]))


# --------------------------------------------------------------------------- bad

def test_all_three_roles_co_resident_fires():
    p = _risk22(_ALL_THREE_ROLES_TOOLS)
    assert p is not None, "RISK-22 did not fire for a genuine input+sensitive+egress co-residence"
    assert p.severity == "MEDIUM"
    assert "srv" in p.title or "srv" in p.why
    assert "fetch_url" in p.why and "read_secret" in p.why and "send_email" in p.why
    # advisory, not proven -- must read as a precondition, never an incident
    assert "precondition" in p.why.lower()
    assert "not an incident" in p.why.lower() or "no exploit is proven" in p.why.lower()


def test_roles_split_across_two_servers_does_not_fire():
    """RISK-02 (whole-agent) covers cross-server capability; RISK-22 is CO-RESIDENCE
    on one server only, so three legs split across three narrow servers must NOT
    fire this chain."""
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = {
        "mcp": {
            "servers": {
                "fetcher": {"command": "node", "tools": [
                    {"name": "fetch_url", "description": "Fetches a web page."},
                ]},
                "vault": {"command": "node", "tools": [
                    {"name": "read_secret", "description": "Reads a stored credential."},
                ]},
                "mailer": {"command": "node", "tools": [
                    {"name": "send_email", "description": "Sends an email."},
                ]},
            }
        }
    }
    assert not any(p.id == "RISK-22" for p in risk_paths(ctx, findings=[]))


def test_deterministic_pick_when_multiple_servers_qualify():
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = {
        "mcp": {
            "servers": {
                "z-server": {"command": "node", "tools": _ALL_THREE_ROLES_TOOLS},
                "a-server": {"command": "node", "tools": _ALL_THREE_ROLES_TOOLS},
            }
        }
    }
    p = next(pp for pp in risk_paths(ctx, findings=[]) if pp.id == "RISK-22")
    assert p.chain[0].startswith("a-server."), "must pick the alphabetically-first server, not dict order"


# --------------------------------------------------------------------------- completeness contract

def test_names_only_surface_does_not_fire(monkeypatch):
    """At completeness='names-only' there is no description text to classify roles
    from with any confidence -- the chain must stay silent even when the bare NAMES
    alone would suggest all three roles."""
    import clawseccheck.risk as risk_mod

    names_only_surface = mcpsurface.ToolSurface(
        server="probe-srv",
        tools=[
            mcpsurface.ToolDef(name="fetch_url", server="probe-srv"),
            mcpsurface.ToolDef(name="read_secret", server="probe-srv"),
            mcpsurface.ToolDef(name="send_email", server="probe-srv"),
        ],
        source="probe-names",
        completeness="names-only",
    )
    monkeypatch.setattr(risk_mod, "_mcp_tool_surfaces", lambda cfg: [names_only_surface])

    ctx = Context(home=Path("/nonexistent"))
    ctx.config = {}
    assert not any(p.id == "RISK-22" for p in risk_paths(ctx, findings=[]))


def test_names_only_is_undetermined_not_clean(monkeypatch):
    """The completeness gap must be a NAMED, distinguishable status -- never silently
    folded into "clean" (which would conflate "we didn't check" with "checked, and
    it's clean")."""
    import clawseccheck.risk as risk_mod

    names_only_surface = mcpsurface.ToolSurface(
        server="probe-srv",
        tools=[mcpsurface.ToolDef(name="fetch_url", server="probe-srv")],
        source="probe-names",
        completeness="names-only",
    )
    monkeypatch.setattr(risk_mod, "_mcp_tool_surfaces", lambda cfg: [names_only_surface])

    candidates = _mcp_toxic_flow_candidates({})
    assert len(candidates) == 1
    assert candidates[0]["status"] == "undetermined"
    assert candidates[0]["status"] != "clean"
    assert "names-only" in candidates[0]["reason"]


def test_full_completeness_with_two_legs_is_named_clean(monkeypatch):
    """Contrast case for the previous test: a FULL surface that genuinely lacks a
    role is "clean", not "undetermined" -- the two states must stay distinguishable
    in both directions."""
    import clawseccheck.risk as risk_mod

    full_surface = mcpsurface.from_tool_defs("srv", _READ_ONLY_TOOLS)
    monkeypatch.setattr(risk_mod, "_mcp_tool_surfaces", lambda cfg: [full_surface])

    candidates = _mcp_toxic_flow_candidates({})
    assert len(candidates) == 1
    assert candidates[0]["status"] == "clean"


# --------------------------------------------------------------------------- classification

def test_role_classified_from_description_not_just_name():
    """Verb-class corroboration: a plainly-worded description can establish a role
    even when the bare tool name alone would not."""
    tool = mcpsurface.ToolDef(name="run", description="Fetches the latest RSS feed items.")
    assert "untrusted-input" in _mcp_tool_roles(tool)


def test_role_classification_is_case_insensitive():
    tool = mcpsurface.ToolDef(name="ReadSecret", description="Reads a VAULT credential.")
    assert "sensitive-read" in _mcp_tool_roles(tool)
