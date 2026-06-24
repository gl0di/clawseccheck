"""B24 — MCP server hardening tests.

Conservative philosophy: FAIL only on positive evidence of a risky pattern;
WARN for likely-insecure defaults; PASS when servers exist but none trigger;
UNKNOWN when no MCP servers are configured.
"""
from pathlib import Path

from clawseccheck.checks import check_mcp_hardening
from clawseccheck.collector import Context


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def _mcp(servers: dict) -> Context:
    """Wrap servers dict under cfg['mcpServers'] (the most common real-world key)."""
    return _ctx({"mcpServers": servers})


# ---- UNKNOWN when no MCP configured ----

def test_b24_no_mcp_unknown():
    assert check_mcp_hardening(_ctx({})).status == "UNKNOWN"


def test_b24_empty_mcp_dict_unknown():
    assert check_mcp_hardening(_ctx({"mcpServers": {}})).status == "UNKNOWN"


# ---- PASS when servers exist but no risky patterns ----

def test_b24_clean_stdio_server_passes():
    ctx = _mcp({"my-tool": {"command": "node", "args": ["dist/index.js"]}})
    assert check_mcp_hardening(ctx).status == "PASS"


def test_b24_pinned_npx_passes():
    ctx = _mcp({"tool": {"command": "npx", "args": ["-y", "some-pkg@1.2.3"]}})
    assert check_mcp_hardening(ctx).status == "PASS"


def test_b24_remote_url_with_allowlist_warns_not_fails():
    # remote URL + allowedHosts -> WARN (not FAIL) — the allowedHosts is a mitigation
    ctx = _mcp({"remote": {
        "url": "https://mcp.example.com/api",
        "allowedHosts": ["mcp.example.com"],
    }})
    # allowedHosts is present so no WARN for missing allowlist; no other risk -> PASS
    assert check_mcp_hardening(ctx).status == "PASS"


# ---- WARN patterns ----

def test_b24_npx_at_latest_warns():
    ctx = _mcp({"tool": {"command": "npx", "args": ["-y", "some-pkg@latest"]}})
    f = check_mcp_hardening(ctx)
    assert f.status == "WARN"
    ev = " ".join(f.evidence)
    assert "unpinned" in ev.lower() or "@latest" in ev


def test_b24_npx_url_warns():
    ctx = _mcp({"tool": {
        "command": "npx",
        "args": ["-y", "https://registry.example.com/pkg"],
    }})
    assert check_mcp_hardening(ctx).status == "WARN"


def test_b24_uvx_url_warns():
    ctx = _mcp({"tool": {"command": "uvx", "args": ["https://example.com/run"]}})
    assert check_mcp_hardening(ctx).status == "WARN"


def test_b24_curl_in_command_warns():
    ctx = _mcp({"tool": {"command": "curl", "args": ["https://example.com/run.sh"]}})
    assert check_mcp_hardening(ctx).status == "WARN"


def test_b24_openai_api_key_env_warns():
    ctx = _mcp({"tool": {
        "command": "node",
        "args": ["index.js"],
        "env": {"OPENAI_API_KEY": "sk-real-key"},
    }})
    assert check_mcp_hardening(ctx).status == "WARN"


def test_b24_aws_secret_env_warns():
    ctx = _mcp({"tool": {
        "command": "node",
        "args": ["index.js"],
        "env": {"AWS_SECRET_ACCESS_KEY": "something"},
    }})
    assert check_mcp_hardening(ctx).status == "WARN"


def test_b24_remote_url_no_allowlist_warns():
    ctx = _mcp({"remote": {"url": "https://mcp.example.com/api"}})
    f = check_mcp_hardening(ctx)
    assert f.status == "WARN"
    ev = " ".join(f.evidence)
    assert "allowedHosts" in ev or "allowlist" in ev.lower()


# ---- FAIL patterns ----

def test_b24_env_wildcard_in_key_fails():
    ctx = _mcp({"tool": {
        "command": "node",
        "args": ["index.js"],
        "env": {"*": "*"},
    }})
    f = check_mcp_hardening(ctx)
    assert f.status == "FAIL"
    assert "*" in " ".join(f.evidence)


def test_b24_env_wildcard_string_fails():
    ctx = _mcp({"tool": {
        "command": "node",
        "args": ["index.js"],
        "env": "*",
    }})
    f = check_mcp_hardening(ctx)
    assert f.status == "FAIL"


def test_b24_token_passthrough_true_fails():
    ctx = _mcp({"tool": {
        "command": "node",
        "args": ["index.js"],
        "tokenPassthrough": True,
    }})
    f = check_mcp_hardening(ctx)
    assert f.status == "FAIL"
    assert "tokenPassthrough" in " ".join(f.evidence)


def test_b24_token_passthrough_hyphen_fails():
    ctx = _mcp({"tool": {
        "command": "node",
        "args": ["index.js"],
        "token-passthrough": True,
    }})
    assert check_mcp_hardening(ctx).status == "FAIL"


def test_b24_allowed_hosts_wildcard_fails():
    ctx = _mcp({"tool": {
        "command": "node",
        "args": ["index.js"],
        "allowedHosts": ["*"],
    }})
    f = check_mcp_hardening(ctx)
    assert f.status == "FAIL"
    assert "*" in " ".join(f.evidence)


def test_b24_allowed_hosts_metadata_ip_fails():
    ctx = _mcp({"tool": {
        "command": "node",
        "args": ["index.js"],
        "allowedHosts": ["169.254.169.254"],
    }})
    f = check_mcp_hardening(ctx)
    assert f.status == "FAIL"
    assert "169.254.169.254" in " ".join(f.evidence)


def test_b24_allowed_hosts_internal_ip_fails():
    ctx = _mcp({"tool": {
        "command": "node",
        "args": ["index.js"],
        "allowedHosts": ["192.168.1.100"],
    }})
    assert check_mcp_hardening(ctx).status == "FAIL"


def test_b24_allowed_hosts_rfc1918_10_fails():
    ctx = _mcp({"tool": {
        "command": "node",
        "args": ["index.js"],
        "allowedHosts": ["10.0.0.1"],
    }})
    assert check_mcp_hardening(ctx).status == "FAIL"


def test_b24_allowed_hosts_localhost_fails():
    ctx = _mcp({"tool": {
        "command": "node",
        "args": ["index.js"],
        "allowedHosts": ["localhost"],
    }})
    assert check_mcp_hardening(ctx).status == "FAIL"


# ---- Alternative config key shapes ----

def test_b24_cfg_mcp_key_is_detected():
    ctx = _ctx({"mcp": {"tool": {"tokenPassthrough": True, "command": "node", "args": []}}})
    assert check_mcp_hardening(ctx).status == "FAIL"


def test_b24_tools_mcp_key_is_detected():
    ctx = _ctx({"tools": {"mcp": {"tool": {"env": {"*": "*"}, "command": "node", "args": []}}}})
    assert check_mcp_hardening(ctx).status == "FAIL"


def test_b24_plugins_mcp_key_is_detected():
    ctx = _ctx({"plugins": {"mcp": {"tool": {"tokenPassthrough": True, "command": "node", "args": []}}}})
    assert check_mcp_hardening(ctx).status == "FAIL"


# ---- Evidence list is populated on FAIL/WARN ----

def test_b24_fail_populates_evidence():
    ctx = _mcp({"tool": {"command": "node", "args": [], "tokenPassthrough": True}})
    f = check_mcp_hardening(ctx)
    assert f.status == "FAIL"
    assert len(f.evidence) >= 1


def test_b24_warn_populates_evidence():
    ctx = _mcp({"tool": {"command": "npx", "args": ["pkg@latest"]}})
    f = check_mcp_hardening(ctx)
    assert f.status == "WARN"
    assert len(f.evidence) >= 1


# ---- Non-risky env vars do NOT warn ----

def test_b24_benign_env_var_does_not_warn():
    ctx = _mcp({"tool": {
        "command": "node",
        "args": ["index.js"],
        "env": {"NODE_ENV": "production", "PORT": "3000"},
    }})
    assert check_mcp_hardening(ctx).status == "PASS"


# ---- Multiple servers: worst-case status wins ----

def test_b24_mixed_servers_fail_wins():
    ctx = _mcp({
        "clean": {"command": "node", "args": ["dist/index.js"]},
        "risky": {"command": "node", "args": [], "tokenPassthrough": True},
    })
    assert check_mcp_hardening(ctx).status == "FAIL"


def test_b24_mixed_clean_and_warn():
    ctx = _mcp({
        "clean": {"command": "node", "args": ["dist/index.js"]},
        "outdated": {"command": "npx", "args": ["pkg@latest"]},
    })
    assert check_mcp_hardening(ctx).status == "WARN"
