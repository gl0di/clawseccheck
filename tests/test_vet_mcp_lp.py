"""Tests for F-007: MCP least-privilege cross-check (LP1).

Covers:
- LP1: oauth.scope present + read-only + command exercises network/shell/file_write
  capabilities -> suspicious (WARN via vet_mcp)
- clean: scope present + no elevated capabilities -> PASS (no LP signal)
- no-scope: absent oauth.scope -> PASS (LP3 dropped; absent scope is normal)
- no-scope with capability-bearing command -> still PASS (LP3 dropped)
- scope present + broad/wildcard -> no LP1 (already flagged by broad-scope check;
  LP2 deduped)
- scope present + write token -> LP1 does not fire (scope already covers write)
- shell capability with read-only scope -> LP1 fires
- file_write capability with read-only scope -> LP1 fires
- multiple elevated capabilities -> all named in the LP1 message
- _vet_mcp_least_privilege unit-level tests (direct helper)
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.checks import _vet_mcp_least_privilege, vet_mcp


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _home_with_mcp(tmp_path: Path, servers: dict) -> Path:
    cfg = {"mcp": {"servers": servers}}
    (tmp_path / "openclaw.json").write_text(json.dumps(cfg), encoding="utf-8")
    return tmp_path


# ---------------------------------------------------------------------------
# Unit-level: _vet_mcp_least_privilege
# ---------------------------------------------------------------------------

class TestLPHelperDirectly:
    """White-box tests of the LP helper — fast, no vet_mcp overhead."""

    def test_no_scope_is_silent(self):
        """Absent oauth.scope -> no LP signal (LP3 dropped)."""
        spec = {"command": "node", "args": ["dist/server.js"]}
        d, s = _vet_mcp_least_privilege("srv", spec)
        assert d == [] and s == []

    def test_no_scope_with_network_cmd_is_silent(self):
        """Even a fetch/curl arg with no scope -> silent (LP3 dropped)."""
        spec = {"command": "node", "args": ["dist/server.js", "--transport", "fetch"]}
        d, s = _vet_mcp_least_privilege("srv", spec)
        assert d == [] and s == []

    def test_scope_present_no_elevated_caps_is_silent(self):
        """Read-only scope + no elevated capabilities (node dist/server.js) -> silent."""
        spec = {"command": "node", "args": ["dist/server.js"], "oauth": {"scope": "read"}}
        d, s = _vet_mcp_least_privilege("srv", spec)
        assert d == [] and s == []

    def test_lp1_network_cap_with_readonly_scope(self):
        """network capability (fetch) + read-only scope -> LP1 suspicious."""
        spec = {
            "command": "node",
            "args": ["dist/server.js", "--transport", "fetch"],
            "oauth": {"scope": "read"},
        }
        d, s = _vet_mcp_least_privilege("net-tool", spec)
        assert d == []
        assert len(s) == 1
        assert "LP1" in s[0]
        assert "network" in s[0]
        assert "read" in s[0]

    def test_lp1_shell_cap_with_readonly_scope(self):
        """shell capability (bash) + read-only scope -> LP1 suspicious."""
        spec = {
            "command": "bash",
            "args": ["-c", "ls"],
            "oauth": {"scope": "read:files"},
        }
        d, s = _vet_mcp_least_privilege("shell-tool", spec)
        assert d == []
        assert any("LP1" in x and "shell" in x for x in s)

    def test_lp1_file_write_cap_with_readonly_scope(self):
        """file_write capability + read-only scope -> LP1 suspicious."""
        spec = {
            "command": "node",
            "args": ["server.js", "write_text", "/tmp/out"],
            "oauth": {"scope": "view"},
        }
        d, s = _vet_mcp_least_privilege("write-tool", spec)
        assert d == []
        assert any("LP1" in x and "file_write" in x for x in s)

    def test_lp1_curl_cap_with_list_scope(self):
        """curl in args + scope='list' -> LP1 (network cap, read-only scope)."""
        spec = {
            "command": "node",
            "args": ["server.js", "curl", "https://api.example.com"],
            "oauth": {"scope": "list"},
        }
        d, s = _vet_mcp_least_privilege("curl-tool", spec)
        assert any("LP1" in x for x in s)

    def test_scope_with_write_token_no_lp1(self):
        """Scope already has 'write' token -> LP1 does not fire."""
        spec = {
            "command": "node",
            "args": ["dist/server.js", "--transport", "fetch"],
            "oauth": {"scope": "read write"},
        }
        d, s = _vet_mcp_least_privilege("rw-tool", spec)
        assert d == [] and s == []

    def test_broad_scope_no_lp1(self):
        """Wildcard scope ('*') is not read-only -> LP1 does not fire."""
        spec = {
            "command": "node",
            "args": ["dist/server.js", "--transport", "fetch"],
            "oauth": {"scope": "*"},
        }
        d, s = _vet_mcp_least_privilege("wide-tool", spec)
        assert d == [] and s == []

    def test_admin_scope_no_lp1(self):
        """'admin' scope has write tokens -> LP1 does not fire."""
        spec = {
            "command": "node",
            "args": ["dist/server.js", "--transport", "fetch"],
            "oauth": {"scope": "admin"},
        }
        d, s = _vet_mcp_least_privilege("admin-tool", spec)
        assert d == [] and s == []

    def test_mcp_only_cap_with_readonly_scope_is_silent(self):
        """mcp-server in package name (mcp family) is not elevated -> silent."""
        spec = {
            "command": "npx",
            "args": ["-y", "some-mcp-server@1.2.3"],
            "oauth": {"scope": "read"},
        }
        d, s = _vet_mcp_least_privilege("mcp-tool", spec)
        assert d == [] and s == []

    def test_env_read_only_cap_with_readonly_scope_is_silent(self):
        """env_read (os.environ) is not elevated -> silent."""
        spec = {
            "command": "node",
            "args": ["server.js", "os.environ"],
            "oauth": {"scope": "read"},
        }
        d, s = _vet_mcp_least_privilege("env-tool", spec)
        assert d == [] and s == []

    def test_non_dict_spec_is_silent(self):
        """Non-dict spec -> no crash, no signal."""
        d, s = _vet_mcp_least_privilege("bad", "not-a-dict")  # type: ignore[arg-type]
        assert d == [] and s == []

    def test_empty_spec_is_silent(self):
        """Empty spec -> no crash, no signal."""
        d, s = _vet_mcp_least_privilege("empty", {})
        assert d == [] and s == []

    def test_lp1_message_contains_scope_value(self):
        """LP1 message includes the actual scope value."""
        spec = {
            "command": "node",
            "args": ["dist/server.js", "--transport", "fetch"],
            "oauth": {"scope": "read:calendar"},
        }
        _, s = _vet_mcp_least_privilege("cal-tool", spec)
        assert any("read:calendar" in x for x in s)

    def test_lp1_message_prefixed_with_server_name(self):
        """LP1 message is prefixed with the server name (for vet_mcp stripping)."""
        spec = {
            "command": "node",
            "args": ["dist/server.js", "--transport", "fetch"],
            "oauth": {"scope": "read"},
        }
        _, s = _vet_mcp_least_privilege("my-server", spec)
        assert s[0].startswith("my-server: ")


# ---------------------------------------------------------------------------
# Integration: vet_mcp end-to-end
# ---------------------------------------------------------------------------

def test_vet_mcp_lp1_network_scope_is_warn(tmp_path):
    """vet_mcp: LP1 (network cap + read-only scope) -> WARN."""
    home = _home_with_mcp(tmp_path, {
        "net-tool": {
            "command": "node",
            "args": ["dist/server.js", "--transport", "fetch"],
            "oauth": {"scope": "read"},
        }
    })
    findings = vet_mcp(home=str(home))
    assert len(findings) == 1
    f = findings[0]
    assert f.status == "WARN", f"expected WARN, got {f.status}: {f.detail}"
    assert "LP1" in f.detail or any("LP1" in e for e in (f.evidence or []))


def test_vet_mcp_lp1_shell_scope_is_warn(tmp_path):
    """vet_mcp: shell cap (bash in args) + read-only scope -> WARN."""
    home = _home_with_mcp(tmp_path, {
        "shell-tool": {
            "command": "node",
            "args": ["dist/server.js", "bash", "-c", "ls"],
            "oauth": {"scope": "view"},
        }
    })
    findings = vet_mcp(home=str(home))
    assert findings[0].status == "WARN"
    assert "LP1" in findings[0].detail or any("LP1" in e for e in (findings[0].evidence or []))


def test_vet_mcp_clean_node_readonly_scope_is_pass(tmp_path):
    """vet_mcp: node dist/server.js + scope=read, no elevated caps -> PASS."""
    home = _home_with_mcp(tmp_path, {
        "read-only-tool": {
            "command": "node",
            "args": ["dist/server.js"],
            "oauth": {"scope": "read"},
        }
    })
    findings = vet_mcp(home=str(home))
    assert findings[0].status == "PASS", (
        f"expected PASS, got {findings[0].status}: {findings[0].detail}"
    )


def test_vet_mcp_no_scope_pinned_is_pass(tmp_path):
    """vet_mcp: no oauth.scope at all -> PASS (LP3 dropped; absent scope is normal)."""
    home = _home_with_mcp(tmp_path, {
        "good": {"command": "npx", "args": ["-y", "some-mcp-server@1.2.3"]}
    })
    findings = vet_mcp(home=str(home))
    assert findings[0].status == "PASS", (
        f"expected PASS, got {findings[0].status}: {findings[0].detail}"
    )


def test_vet_mcp_no_scope_fetch_arg_is_pass(tmp_path):
    """vet_mcp: network-bearing arg but no oauth.scope -> PASS (LP3 dropped)."""
    home = _home_with_mcp(tmp_path, {
        "fetch-server": {
            "command": "node",
            "args": ["dist/server.js", "--transport", "fetch"],
        }
    })
    findings = vet_mcp(home=str(home))
    assert findings[0].status == "PASS", (
        f"expected PASS, got {findings[0].status}: {findings[0].detail}"
    )


def test_vet_mcp_lp1_evidence_present(tmp_path):
    """vet_mcp LP1 finding populates the evidence list."""
    home = _home_with_mcp(tmp_path, {
        "net-tool": {
            "command": "node",
            "args": ["dist/server.js", "--transport", "fetch"],
            "oauth": {"scope": "read"},
        }
    })
    f = vet_mcp(home=str(home))[0]
    assert f.evidence, "LP1 finding must have evidence"
    assert any("LP1" in e for e in f.evidence)


def test_vet_mcp_lp1_not_scored(tmp_path):
    """LP1 finding via vet_mcp is not scored (MCP-VET findings are unscored)."""
    home = _home_with_mcp(tmp_path, {
        "net-tool": {
            "command": "node",
            "args": ["dist/server.js", "--transport", "fetch"],
            "oauth": {"scope": "read"},
        }
    })
    f = vet_mcp(home=str(home))[0]
    assert f.scored is False


def test_vet_mcp_write_scope_no_lp1(tmp_path):
    """vet_mcp: write scope + network cap -> no LP1 (scope already covers write)."""
    home = _home_with_mcp(tmp_path, {
        "rw-tool": {
            "command": "node",
            "args": ["dist/server.js", "--transport", "fetch"],
            "oauth": {"scope": "read write"},
        }
    })
    f = vet_mcp(home=str(home))[0]
    # May be WARN for other reasons (e.g. remote transport from b24) but not LP1.
    assert not any("LP1" in e for e in (f.evidence or []))
    assert "LP1" not in (f.detail or "")


# ---------------------------------------------------------------------------
# i18n: LP1 detail strings have Hebrew translations
# ---------------------------------------------------------------------------




# ---------------------------------------------------------------------------
# Fixture-based: ensure the shipped fixtures produce the right signals
# ---------------------------------------------------------------------------

def test_fixture_clean_f007_lp_matched_is_pass(tmp_path):
    """fixtures/clean_f007_lp_matched.json: no LP signal -> PASS."""
    import json as _json
    fixture = Path(__file__).resolve().parent.parent / "fixtures" / "clean_f007_lp_matched.json"
    data = _json.loads(fixture.read_text(encoding="utf-8"))
    (tmp_path / "openclaw.json").write_text(_json.dumps(data), encoding="utf-8")
    f = vet_mcp(home=str(tmp_path))[0]
    assert f.status == "PASS", f"expected PASS from clean fixture, got {f.status}: {f.detail}"


def test_fixture_bad_f007_lp1_under_declared_is_warn(tmp_path):
    """fixtures/bad_f007_lp1_under_declared.json: LP1 fires -> WARN."""
    import json as _json
    fixture = Path(__file__).resolve().parent.parent / "fixtures" / "bad_f007_lp1_under_declared.json"
    data = _json.loads(fixture.read_text(encoding="utf-8"))
    (tmp_path / "openclaw.json").write_text(_json.dumps(data), encoding="utf-8")
    f = vet_mcp(home=str(tmp_path))[0]
    assert f.status == "WARN", f"expected WARN from bad LP1 fixture, got {f.status}: {f.detail}"
    assert "LP1" in f.detail or any("LP1" in e for e in (f.evidence or []))
