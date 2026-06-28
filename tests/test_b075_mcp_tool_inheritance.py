"""B75 — MCP tool-inheritance bypass check (attestation-based).

Grounded on GitHub issue #63399: globally-registered mcp.servers tools are
auto-injected into ALL agents, bypassing per-agent tools.allow/deny filters.

UNKNOWN  — no attestation
WARN     — attested agent holds MCP-namespaced tools AND mcp.servers configured
PASS     — no MCP bleed, or no mcp.servers configured
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_mcp_tool_inheritance
from clawseccheck.collector import Context


def _ctx(attestation=None, mcp_servers=None) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    if mcp_servers:
        c.config = {"mcp": {"servers": mcp_servers}}
    c.bootstrap = {}
    c.installed_skills = {}
    if attestation is not None:
        c.attestation = attestation
    return c


_SLACK_SERVER = {"slack": {"command": "npx", "args": ["-y", "@slack/mcp"]}}


# --------------------------------------------------------------------------- UNKNOWN
def test_b75_unknown_without_attestation():
    f = check_mcp_tool_inheritance(_ctx())
    assert f.id == "B75"
    assert f.status == UNKNOWN


def test_b75_unknown_with_empty_attestation():
    f = check_mcp_tool_inheritance(_ctx(attestation={}))
    assert f.status == UNKNOWN


# --------------------------------------------------------------------------- WARN
def test_b75_warn_mcp_bleed():
    """Agent holds MCP-namespaced tools + mcp.servers configured → WARN."""
    att = {
        "agents": [
            {"name": "researcher", "tools": ["web_search", "mcp__slack__send_message", "mcp__slack__read_channel"]}
        ]
    }
    f = check_mcp_tool_inheritance(_ctx(attestation=att, mcp_servers=_SLACK_SERVER))
    assert f.status == WARN
    assert "researcher" in f.detail
    assert f.evidence


def test_b75_warn_multiple_agents_with_bleed():
    att = {
        "agents": [
            {"name": "writer", "tools": ["mcp__files__write", "mcp__files__read"]},
            {"name": "reader", "tools": ["mcp__files__read"]},
        ]
    }
    mcp = {"files": {"command": "mcp-files"}}
    f = check_mcp_tool_inheritance(_ctx(attestation=att, mcp_servers=mcp))
    assert f.status == WARN
    assert len(f.evidence) == 2


def test_b75_warn_double_underscore_pattern():
    """Any tool with __ (double underscore) counts as MCP-namespaced."""
    att = {"agents": [{"name": "agent", "tools": ["server__do_thing"]}]}
    mcp = {"server": {"command": "mcp-server"}}
    f = check_mcp_tool_inheritance(_ctx(attestation=att, mcp_servers=mcp))
    assert f.status == WARN


def test_b75_warn_many_tools_truncated_in_evidence():
    tools = [f"mcp__s__{i}" for i in range(10)]
    att = {"agents": [{"name": "fat-agent", "tools": tools}]}
    mcp = {"s": {"command": "mcp-s"}}
    f = check_mcp_tool_inheritance(_ctx(attestation=att, mcp_servers=mcp))
    assert f.status == WARN
    # Evidence entry should reference the count and include "(+7 more)"
    assert any("+7 more" in ev for ev in f.evidence)


# --------------------------------------------------------------------------- PASS
def test_b75_pass_no_mcp_tools_in_agents():
    att = {"agents": [{"name": "helper", "tools": ["read_file", "web_search"]}]}
    f = check_mcp_tool_inheritance(_ctx(attestation=att, mcp_servers=_SLACK_SERVER))
    assert f.status == PASS


def test_b75_pass_no_mcp_servers_configured():
    """Agent holds MCP-namespaced tools but no mcp.servers → not a bypass → PASS."""
    att = {"agents": [{"name": "agent", "tools": ["mcp__slack__send_message"]}]}
    f = check_mcp_tool_inheritance(_ctx(attestation=att, mcp_servers=None))
    assert f.status == PASS


def test_b75_pass_empty_agent_list():
    att = {"agents": []}
    f = check_mcp_tool_inheritance(_ctx(attestation=att, mcp_servers=_SLACK_SERVER))
    assert f.status == UNKNOWN


def test_b75_pass_clean_agent_with_mcp_servers():
    att = {"agents": [{"name": "orchestrator", "tools": ["delegate", "summarize"]}]}
    f = check_mcp_tool_inheritance(_ctx(attestation=att, mcp_servers=_SLACK_SERVER))
    assert f.status == PASS


# --------------------------------------------------------------------------- metadata
def test_b75_is_advisory_not_scored():
    from clawseccheck.catalog import CATALOG
    meta = next((m for m in CATALOG if m.id == "B75"), None)
    assert meta is not None
    assert meta.scored is False


def test_b75_confidence_is_attested():
    from clawseccheck.catalog import CATALOG
    meta = next((m for m in CATALOG if m.id == "B75"), None)
    assert meta is not None
    assert meta.confidence == "ATTESTED"
