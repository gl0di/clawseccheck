"""C047 — advisory UNKNOWN for non-local MCP server endpoints.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import re
from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN
from clawseccheck.checks import check_mcp_external_endpoint
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
_HEBREW = re.compile(r"[֐-׿]")


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def _mcp(servers: dict) -> Context:
    return _ctx({"mcp": {"servers": servers}})


def test_c047_no_mcp_passes():
    assert check_mcp_external_endpoint(_ctx({})).status == PASS


def test_c047_localhost_url_passes():
    f = check_mcp_external_endpoint(_mcp({"local": {"url": "http://localhost:8123/sse"}}))
    assert f.status == PASS


def test_c047_loopback_ip_passes():
    f = check_mcp_external_endpoint(_mcp({"local": {"url": "https://127.0.0.1:9000/mcp"}}))
    assert f.status == PASS


def test_c047_stdio_server_passes():
    f = check_mcp_external_endpoint(_mcp({"local": {"command": "npx", "args": ["server-fs"]}}))
    assert f.status == PASS


def test_c047_external_url_is_unknown():
    f = check_mcp_external_endpoint(_mcp({"corp": {"url": "https://mcp.example.com/api"}}))
    assert f.status == UNKNOWN
    assert any("corp" in line for line in f.evidence)


def test_c047_unix_socket_url_passes():
    f = check_mcp_external_endpoint(_mcp({"sock": {"url": "unix:///tmp/mcp.sock"}}))
    assert f.status == PASS



def test_c047_bad_fixture_unknown():
    assert check_mcp_external_endpoint(collect(FIXTURES / "bad_c047_mcp_external")).status == UNKNOWN


def test_c047_clean_fixture_passes():
    assert check_mcp_external_endpoint(collect(FIXTURES / "clean_c047_mcp_localhost")).status == PASS


def test_c047_registered_in_audit():
    from clawseccheck import audit

    _, findings, _ = audit(FIXTURES / "bad_c047_mcp_external", include_native=False)
    ids = {f.id for f in findings}
    assert "C047" in ids, f"C047 not in audit findings: {sorted(ids)}"
