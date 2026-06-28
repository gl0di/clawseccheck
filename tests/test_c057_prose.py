"""C-057 prose clarity: B4 phantom-sandbox WARN, B15 stdio framing, B24 dedup.

Accuracy is unchanged (no verdict flips); these assert the wording is clearer.
"""
from __future__ import annotations

import re
from pathlib import Path

from clawseccheck.catalog import FAIL, UNKNOWN, WARN
from clawseccheck.checks import check_mcp, check_mcp_hardening, check_sandbox
from clawseccheck.collector import Context

_HEBREW = re.compile(r"[֐-׿]")


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.include_host = True
    return c


# ---------------------------------------------------------------------------
# B4: phantom top-level `sandbox` block is named explicitly
# ---------------------------------------------------------------------------

def test_b4_phantom_sandbox_with_exec_warns_and_explains():
    cfg = {"sandbox": {"mode": "enabled"}, "tools": {"allow": ["exec"]}}
    f = check_sandbox(_ctx(cfg))
    assert f.status == WARN
    assert "top-level 'sandbox'" in f.detail
    assert "agents.defaults.sandbox" in f.detail
    assert "agents.defaults.sandbox" in f.fix


def test_b4_phantom_sandbox_no_exec_is_unknown_and_explains():
    cfg = {"sandbox": {"mode": "enabled"}}
    f = check_sandbox(_ctx(cfg))
    assert f.status == UNKNOWN
    assert "top-level 'sandbox'" in f.detail



def test_b4_no_phantom_keeps_original_warn():
    # exec but no sandbox key at all -> original message, not the phantom one.
    f = check_sandbox(_ctx({"tools": {"allow": ["exec"]}}))
    assert f.status == WARN
    assert "top-level 'sandbox'" not in f.detail


# ---------------------------------------------------------------------------
# B15: transport-aware framing (stdio/local vs remote)
# ---------------------------------------------------------------------------

def test_b15_stdio_server_uses_local_framing():
    cfg = {"mcp": {"servers": {"local-fs": {"command": "npx", "args": ["server-fs"]}}}}
    f = check_mcp(_ctx(cfg))
    assert f.status == WARN
    assert "Local (stdio)" in f.detail
    assert "Remote MCP servers" not in f.detail


def test_b15_remote_url_uses_remote_framing():
    cfg = {"mcp": {"servers": {"r": {"url": "https://mcp.example.com"}}}}
    f = check_mcp(_ctx(cfg))
    assert f.status == WARN
    assert "Remote MCP servers" in f.detail


def test_b15_remote_transport_uses_remote_framing():
    cfg = {"mcp": {"servers": {"r": {"transport": "sse"}}}}
    f = check_mcp(_ctx(cfg))
    assert "Remote MCP servers" in f.detail



# ---------------------------------------------------------------------------
# B24: dedup — specifics in evidence, detail is a summary (no doubled line)
# ---------------------------------------------------------------------------

def test_b24_detail_is_summary_not_doubled():
    cfg = {"mcp": {"servers": {"local-fs": {"command": "npx -y @scope/pkg@latest"}}}}
    f = check_mcp_hardening(_ctx(cfg))
    assert f.status in (WARN, FAIL)
    assert "see evidence" in f.detail
    # The per-server specifics live in evidence, and must NOT also be embedded in the detail.
    assert f.evidence, "expected evidence bullets"
    reason = f.evidence[0]
    # the detailed reason text should not be duplicated inside the summary detail
    assert reason not in f.detail

