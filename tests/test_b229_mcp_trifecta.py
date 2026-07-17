"""B-229 — MCP-granted capability folds into the lethal-trifecta legs (A1).

A1 (check_trifecta) historically derived capability only from tools.*/credentials/,
never from mcp.servers, so a data/fs/db/secret MCP server (sensitive leg) or a
remote/network MCP endpoint (outbound leg) contributed zero to the trifecta. This
covers: the new leg-detection heuristics (_mcp_fs_root_is_broad / _mcp_sensitive_reason
/ _mcp_leg_contributions), the bad/clean fixture pair, and a regression sweep proving
existing MCP-bearing clean fixtures + home_safe are unaffected (zero new false-FAIL,
per CLAUDE.md Golden Rule #5 / C-135).

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import FAIL, PASS
from clawseccheck.checks import (
    _mcp_fs_root_is_broad,
    _mcp_leg_contributions,
    _mcp_sensitive_reason,
    check_trifecta,
)
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict, home: str = "/nonexistent") -> Context:
    c = Context(home=Path(home))
    c.config = cfg
    return c


def _a1(cfg: dict) -> object:
    return check_trifecta(_ctx(cfg))


# ── _mcp_fs_root_is_broad: broad vs. project-scoped roots ───────────────────────────

def test_broad_root_slash():
    assert _mcp_fs_root_is_broad("/") is True


def test_broad_root_home_tilde():
    assert _mcp_fs_root_is_broad("~") is True
    assert _mcp_fs_root_is_broad("~/") is True


def test_broad_root_user_home_dir():
    assert _mcp_fs_root_is_broad("/home/dave") is True
    assert _mcp_fs_root_is_broad("/Users/dave") is True


def test_narrow_root_project_dir_not_broad():
    """A single project directory under a home is project-scoped, not broad (§5)."""
    assert _mcp_fs_root_is_broad("/home/dave/myproject") is False


def test_narrow_root_relative_dot_not_broad():
    assert _mcp_fs_root_is_broad(".") is False
    assert _mcp_fs_root_is_broad("workspace") is False


def test_flag_arg_not_a_root():
    assert _mcp_fs_root_is_broad("-y") is False


# ── _mcp_sensitive_reason: known-name + broad-root heuristics ───────────────────────

def test_known_data_pkg_flags_regardless_of_args():
    reason = _mcp_sensitive_reason(
        "npx @modelcontextprotocol/server-postgres postgres://db/prod", []
    )
    assert reason and "postgres" in reason


def test_fs_server_at_broad_root_flags():
    blob = "npx -y @modelcontextprotocol/server-filesystem /"
    reason = _mcp_sensitive_reason(blob, ["-y", "@modelcontextprotocol/server-filesystem", "/"])
    assert reason and "broad path" in reason


def test_fs_server_at_narrow_root_does_not_flag():
    """§5 zero-FP: a project-scoped fs root is a weaker signal — do not raise the leg."""
    blob = "npx -y @modelcontextprotocol/server-filesystem /home/dave/myproject"
    reason = _mcp_sensitive_reason(
        blob, ["-y", "@modelcontextprotocol/server-filesystem", "/home/dave/myproject"]
    )
    assert reason == ""


def test_bare_keyword_without_mcp_naming_anchor_does_not_flag():
    """A bare 'db-helper' package (no @scope/server-<cap> / mcp-server-<cap> naming) must
    NOT trigger via a loose keyword match — the naming anchor is required (§5 zero-FP)."""
    blob = "npx @tools/db-helper --host localhost --port 5432"
    assert _mcp_sensitive_reason(blob, ["@tools/db-helper", "--host", "localhost", "--port", "5432"]) == ""


def test_benign_weather_api_does_not_flag():
    blob = "https://api.weather-example.com/mcp"
    assert _mcp_sensitive_reason(blob, []) == ""


# ── _mcp_leg_contributions: remote/loopback outbound wiring ─────────────────────────

def test_remote_url_contributes_outbound():
    contribs = _mcp_leg_contributions({"mcp": {"servers": {"w": {"url": "https://x.example.com/mcp"}}}})
    assert contribs["outbound actions"]
    assert "w" in contribs["outbound actions"][0]


def test_loopback_url_does_not_contribute_outbound():
    contribs = _mcp_leg_contributions({"mcp": {"servers": {"w": {"url": "http://localhost:8080/sse"}}}})
    assert contribs["outbound actions"] == []


def test_local_stdio_server_does_not_contribute_outbound():
    contribs = _mcp_leg_contributions(
        {"mcp": {"servers": {"w": {"command": "npx", "args": ["-y", "server-fs"]}}}}
    )
    assert contribs["outbound actions"] == []


# ── A1 integration: leg-isolation on a bare in-memory config ────────────────────────

def test_a1_fs_mcp_at_root_alone_raises_sensitive_leg():
    a1 = _a1({"mcp": {"servers": {"fs": {
        "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
    }}}})
    assert "sensitive data" in (a1.evidence or [])


def test_a1_narrow_fs_mcp_alone_does_not_raise_sensitive_leg():
    a1 = _a1({"mcp": {"servers": {"fs": {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/dave/myproject"],
    }}}})
    assert "sensitive data" not in (a1.evidence or [])


def test_a1_remote_mcp_alone_raises_outbound_leg():
    a1 = _a1({"mcp": {"servers": {"w": {"url": "https://api.example.com/mcp"}}}})
    assert "outbound actions" in (a1.evidence or [])
    assert "sensitive data" not in (a1.evidence or [])


def test_a1_detail_names_mcp_server_as_capability_source():
    """The leg detail names the MCP server as the source (evidence itself stays the
    fixed 3 leg-name keys — see _LEG_KEYS / existing exact-match evidence tests)."""
    a1 = _a1({
        "channels": {"telegram": {"enabled": True, "dmPolicy": "open"}},
        "mcp": {"servers": {"fs": {
            "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
        }}},
        "tools": {"web": {"fetch": {"enabled": True}}, "exec": {"mode": "ask"}},
    })
    assert a1.status == FAIL
    assert "MCP server 'fs'" in a1.detail
    assert "broad path" in a1.detail


# ── Fixture pair: bad (3/3 FAIL) / clean (stays <=2/3) ───────────────────────────────

def test_bad_fixture_fs_mcp_at_root_is_full_trifecta_fail():
    ctx = collect(FIXTURES / "bad_b229_mcp_fs_root_trifecta")
    a1 = check_trifecta(ctx)
    assert a1.status == FAIL
    assert set(a1.evidence) == {"untrusted input", "sensitive data", "outbound actions"}
    assert "MCP server 'fs'" in a1.detail


def test_clean_fixture_benign_remote_mcp_stays_two_of_three():
    ctx = collect(FIXTURES / "clean_b229_mcp_remote_benign")
    a1 = check_trifecta(ctx)
    assert a1.status != FAIL
    assert "sensitive data" not in (a1.evidence or [])
    assert len(a1.evidence) <= 2


def test_bad_fixture_registered_in_full_audit():
    _, findings, score = audit(FIXTURES / "bad_b229_mcp_fs_root_trifecta")
    a1 = {f.id: f for f in findings}["A1"]
    assert a1.status == FAIL
    assert score.failed_critical >= 1


def test_clean_fixture_registered_in_full_audit_no_a1_fail():
    _, findings, _ = audit(FIXTURES / "clean_b229_mcp_remote_benign")
    a1 = {f.id: f for f in findings}["A1"]
    assert a1.status != FAIL


# ── Regression sweep (C-135 / Golden Rule #5): zero new false-positive FAIL ─────────

# Existing MCP-bearing fixtures that must NOT flip to A1=FAIL now that MCP capability
# is wired into the trifecta legs.
_EXISTING_MCP_CLEAN_FIXTURES = (
    "clean_b104_wired",
    "clean_b150_mcp_curl_no_pipe",
    "clean_b166_mcp_exfil_args",
    "clean_c014_egress_inventory",
    "clean_c047_mcp_localhost",
    "reliability/clean_multimodal_workstation",
)


def test_existing_mcp_bearing_clean_fixtures_stay_a1_non_fail():
    for name in _EXISTING_MCP_CLEAN_FIXTURES:
        _, findings, _ = audit(FIXTURES / name)
        a1 = {f.id: f for f in findings}["A1"]
        assert a1.status != FAIL, f"{name}: A1 regressed to FAIL — {a1.detail}"


def test_home_safe_unaffected():
    _, findings, score = audit(FIXTURES / "home_safe")
    a1 = {f.id: f for f in findings}["A1"]
    assert a1.status == PASS
    assert len(a1.evidence) <= 2
    assert not [f for f in findings if f.status == FAIL]
    assert score.grade == "A"
