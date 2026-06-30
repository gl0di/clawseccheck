"""B15: MCP server check — PASS when all servers have explicit tool allowlists."""
from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_mcp
from clawseccheck.collector import Context


def _ctx(cfg):
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def test_b15_pass_when_all_servers_have_tool_allowlists():
    cfg = {
        "mcp": {
            "servers": {
                "fs": {"command": "npx", "args": ["server-fs"], "tools": ["read_file", "list_dir"]},
                "git": {"command": "npx", "args": ["server-git"], "tools": ["git_status"]},
            }
        }
    }
    f = check_mcp(_ctx(cfg))
    assert f.status == PASS
    assert "allowlist" in f.detail.lower()


def test_b15_warn_when_one_server_lacks_tool_restrictions():
    cfg = {
        "mcp": {
            "servers": {
                "fs": {"command": "npx", "args": ["server-fs"], "tools": ["read_file"]},
                "unrestricted": {"command": "npx", "args": ["server-other"]},
            }
        }
    }
    f = check_mcp(_ctx(cfg))
    assert f.status == WARN


def test_b15_warn_when_tools_is_empty_list():
    cfg = {
        "mcp": {
            "servers": {
                "fs": {"command": "npx", "args": ["server-fs"], "tools": []},
            }
        }
    }
    f = check_mcp(_ctx(cfg))
    assert f.status == WARN


def test_b15_unknown_when_no_servers():
    f = check_mcp(_ctx({}))
    assert f.status == UNKNOWN


def test_b15_mcpservers_legacy_key_with_restrictions_passes():
    """B-038: B15 PASSes when legacy mcpServers key is used and all servers have tool allowlists."""
    cfg = {
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "."],
                "tools": ["read_file", "list_directory"],
            }
        }
    }
    f = check_mcp(_ctx(cfg))
    assert f.status == PASS
