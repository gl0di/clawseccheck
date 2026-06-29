"""B76 — High-blast MCP tool-inheritance bypass check (scored, attestation-based).

Grounded on OpenClaw #63399: globally-registered mcp.servers tools bypass per-agent
filters and are injected into ALL agents at runtime.

B76 is the scored twin of B75: it focuses on MCP tools whose verb classifies as
EXEC, EGRESS, DESTRUCTIVE, or MAILBOX_CONFIG (high_blast_classes).

UNKNOWN  — no attestation
WARN     — attested agent holds high-blast MCP tools AND mcp.servers configured
PASS     — no high-blast MCP tools found, or no mcp.servers configured
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import HIGH, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_mcp_bypass_highblast
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
_FILES_SERVER = {"files": {"command": "mcp-files"}}


# --------------------------------------------------------------------------- UNKNOWN
def test_b76_unknown_no_attestation():
    f = check_mcp_bypass_highblast(_ctx())
    assert f.id == "B76"
    assert f.status == UNKNOWN


def test_b76_unknown_empty_attestation():
    f = check_mcp_bypass_highblast(_ctx(attestation={}))
    assert f.status == UNKNOWN


def test_b76_unknown_empty_agent_list():
    f = check_mcp_bypass_highblast(_ctx(attestation={"agents": []}, mcp_servers=_SLACK_SERVER))
    assert f.status == UNKNOWN


# --------------------------------------------------------------------------- PASS
def test_b76_pass_no_mcp_servers():
    """High-blast MCP tools present but no mcp.servers configured → PASS (not applicable)."""
    att = {"agents": [{"name": "bot", "tools": ["mcp__slack__send_message"]}]}
    f = check_mcp_bypass_highblast(_ctx(attestation=att, mcp_servers=None))
    assert f.status == PASS


def test_b76_pass_low_blast_only():
    """Agents hold only read/search/list MCP tools — no high-blast → PASS."""
    att = {
        "agents": [
            {"name": "reader", "tools": [
                "mcp__slack__list_channels",
                "mcp__drive__get",
                "mcp__files__read",
                "web_search",
            ]}
        ]
    }
    f = check_mcp_bypass_highblast(_ctx(attestation=att, mcp_servers=_SLACK_SERVER))
    assert f.status == PASS


def test_b76_pass_no_mcp_tools_at_all():
    """Agent holds only plain (non-MCP) tools → PASS."""
    att = {"agents": [{"name": "helper", "tools": ["read_file", "web_search"]}]}
    f = check_mcp_bypass_highblast(_ctx(attestation=att, mcp_servers=_SLACK_SERVER))
    assert f.status == PASS


def test_b76_pass_provider_name_not_verb():
    """'SendGrid' in the MCP namespace must not trigger EGRESS — only the verb matters."""
    # mcp__SendGrid__list_templates → verb='list_templates' → REVERSIBLE
    att = {"agents": [{"name": "agent", "tools": ["mcp__SendGrid__list_templates"]}]}
    mcp = {"SendGrid": {"command": "sendgrid-mcp"}}
    f = check_mcp_bypass_highblast(_ctx(attestation=att, mcp_servers=mcp))
    assert f.status == PASS


# --------------------------------------------------------------------------- WARN
def test_b76_warn_egress_mcp():
    """Agent holds EGRESS MCP tool (send_message) → WARN."""
    att = {"agents": [{"name": "bot", "tools": ["mcp__slack__send_message", "mcp__slack__list_channels"]}]}
    f = check_mcp_bypass_highblast(_ctx(attestation=att, mcp_servers=_SLACK_SERVER))
    assert f.status == WARN
    assert "bot" in f.detail
    assert f.evidence


def test_b76_warn_exec_mcp():
    """Agent holds EXEC MCP tool (bash) → WARN."""
    att = {"agents": [{"name": "worker", "tools": ["mcp__tools__bash", "mcp__files__read"]}]}
    mcp = {"tools": {"command": "mcp-shell"}}
    f = check_mcp_bypass_highblast(_ctx(attestation=att, mcp_servers=mcp))
    assert f.status == WARN
    assert "worker" in f.detail


def test_b76_warn_destructive_mcp():
    """Agent holds DESTRUCTIVE MCP tool (delete_forever) → WARN."""
    att = {"agents": [{"name": "cleaner", "tools": ["mcp__drive__delete_forever"]}]}
    mcp = {"drive": {"command": "drive-mcp"}}
    f = check_mcp_bypass_highblast(_ctx(attestation=att, mcp_servers=mcp))
    assert f.status == WARN
    assert "cleaner" in f.detail


def test_b76_warn_multiple_agents():
    """Multiple agents with high-blast tools — all cited in evidence."""
    att = {
        "agents": [
            {"name": "sender", "tools": ["mcp__slack__send_message"]},
            {"name": "execer", "tools": ["mcp__shell__bash"]},
        ]
    }
    mcp = {"slack": _SLACK_SERVER["slack"], "shell": {"command": "shell-mcp"}}
    f = check_mcp_bypass_highblast(_ctx(attestation=att, mcp_servers=mcp))
    assert f.status == WARN
    assert len(f.evidence) == 2
    assert any("sender" in ev for ev in f.evidence)
    assert any("execer" in ev for ev in f.evidence)


def test_b76_warn_evidence_has_tool_names():
    """Evidence entries must name the specific high-blast tool(s)."""
    att = {"agents": [{"name": "bot", "tools": ["mcp__slack__send_message"]}]}
    f = check_mcp_bypass_highblast(_ctx(attestation=att, mcp_servers=_SLACK_SERVER))
    assert f.status == WARN
    assert any("send_message" in ev for ev in f.evidence)


def test_b76_warn_mixed_agent_only_highblast_flagged():
    """One agent has only low-blast MCP tools; the other has high-blast → only the latter in evidence."""
    att = {
        "agents": [
            {"name": "reader", "tools": ["mcp__drive__get", "mcp__drive__list"]},
            {"name": "poster", "tools": ["mcp__slack__send_message"]},
        ]
    }
    f = check_mcp_bypass_highblast(_ctx(attestation=att, mcp_servers=_SLACK_SERVER))
    assert f.status == WARN
    assert len(f.evidence) == 1
    assert "poster" in f.evidence[0]


# --------------------------------------------------------------------------- metadata
def test_b76_is_scored():
    from clawseccheck.catalog import CATALOG
    meta = next((m for m in CATALOG if m.id == "B76"), None)
    assert meta is not None
    assert meta.scored is True


def test_b76_confidence_is_attested():
    from clawseccheck.catalog import CATALOG, ATTESTED
    meta = next((m for m in CATALOG if m.id == "B76"), None)
    assert meta is not None
    assert meta.confidence == ATTESTED


def test_b76_severity_is_high():
    from clawseccheck.catalog import CATALOG
    meta = next((m for m in CATALOG if m.id == "B76"), None)
    assert meta is not None
    assert meta.severity == HIGH
