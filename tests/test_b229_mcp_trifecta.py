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

import pytest

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


# ── C-135 round 2, FP-A: shared/service dirs one level under /home or /Users are NOT
#    "the whole user home" — only a plausible per-user home basename is broad. ───────

def test_macos_shared_folder_not_broad():
    """/Users/Shared is a standard OS-created macOS shared folder on every Mac, not a
    private per-user home — must NOT be treated as broad."""
    assert _mcp_fs_root_is_broad("/Users/Shared") is False


def test_linux_shared_service_dirs_not_broad():
    for p in ("/home/shared", "/home/data", "/home/projects",
              "/home/workspace", "/home/app"):
        assert _mcp_fs_root_is_broad(p) is False, f"{p} wrongly treated as broad"


def test_semantically_identical_non_home_shares_stay_non_broad():
    """Same shared-dir shape under a non-/home/-/Users/ parent already correctly stays
    non-broad (unaffected by the denylist — these never matched the home/users branch)."""
    for p in ("/srv/shared", "/mnt/data", "/opt/shared"):
        assert _mcp_fs_root_is_broad(p) is False


def test_real_per_user_home_still_broad():
    """A plausible per-user home basename (not in the shared/service denylist) still
    counts as broad — the true-positive case must not regress."""
    for p in ("/home/alice", "/Users/dave", "/home/quentin", "/Users/nathan"):
        assert _mcp_fs_root_is_broad(p) is True, f"{p} wrongly excluded"


# ── C-135 round 3, FN-2: service-account / secret-bearing home dirs were wrongly
#    suppressed by the round-2 denylist — removed, so they go back to broad/FAIL. ──

def test_service_account_home_dirs_are_broad_again():
    """A filesystem MCP rooted at a service-account home is a genuine sensitive-data
    grant (git's ~/.ssh deploy keys + every repo it serves; backup dumps; a webroot's
    configs/.env; a repo-hosting account) — these must FAIL, not PASS."""
    for p in ("/home/git", "/home/backup", "/home/backups", "/home/www",
              "/home/srv", "/home/web", "/home/repo", "/home/repos"):
        assert _mcp_fs_root_is_broad(p) is True, f"{p} wrongly excluded (FN-2 regression)"


def test_home_purpose_word_ambiguity_is_accepted_residual():
    """Accepted residual (GR#5 tie-break, documented next to _MCP_HOME_SHARED_BASENAMES):
    a single conventionally-shared/scratch/dev-workspace basename directly under /home or
    /Users (e.g. 'data', 'projects', 'workspace') is statically undecidable — it can
    equally be a team's shared scratch folder (the common case) or someone's private home
    named after its purpose. Golden Rule #5 tie-breaks a hard-blocker false-positive FAIL
    toward PASS, accepting the narrower risk of a false negative on the rarer case. This
    pins that deliberate choice as intentional, not a bug to "fix" by re-adding these
    names to the service-account denylist."""
    for p in ("/home/shared", "/Users/Shared", "/home/data", "/home/projects",
              "/home/workspace", "/home/public", "/home/guest", "/home/default",
              "/home/common", "/home/app", "/home/apps", "/home/media",
              "/home/docs", "/home/doc", "/home/tmp", "/home/temp"):
        assert _mcp_fs_root_is_broad(p) is False, f"{p}: accepted residual regressed"


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


def test_known_vault_pkg_still_flags():
    """True-positive control: a real secrets/vault MCP must still flag (must not
    regress when the FP-B benign-compound denylist is added)."""
    reason = _mcp_sensitive_reason("npx -y @modelcontextprotocol/server-vault", [])
    assert reason and "vault" in reason


# ── C-135 round 2, FP-B: benign-compound package names (diagram/docs/schema tools that
#    inspect a data store's SHAPE, not its contents) must NOT flag as data access. ────

def test_database_diagram_compound_does_not_flag():
    blob = "npx -y mcp-server-database-diagram"
    assert _mcp_sensitive_reason(blob, ["-y", "mcp-server-database-diagram"]) == ""


def test_redis_docs_compound_does_not_flag():
    blob = "npx -y mcp-server-redis-docs"
    assert _mcp_sensitive_reason(blob, ["-y", "mcp-server-redis-docs"]) == ""


def test_database_schema_compound_does_not_flag():
    blob = "npx -y @scope/server-database-schema"
    assert _mcp_sensitive_reason(blob, ["-y", "@scope/server-database-schema"]) == ""


# ── C-135 round 3, FN-1: "viewer"/"explorer"/"dashboard"/"scanner" were removed from
#    the benign-compound denylist — a READER of the actual data must flag, not PASS. ──

def test_reader_browser_compounds_now_flag():
    """These suffixes name a tool that reads the real contents (a vault-viewer reads
    secrets, a postgres-viewer/mongodb-explorer/redis-viewer reads DB rows, an
    s3-explorer/gdrive-viewer reads cloud objects, a database-scanner dumps a DB) — NOT
    a shape-only tool. Must flag as data access (the round-2 denylist wrongly suppressed
    these; round 3 removes them)."""
    for pkg in (
        "mcp-server-vault-viewer",
        "mcp-server-secret-explorer",
        "mcp-server-credentials-dashboard",
        "mcp-server-postgres-viewer",
        "mcp-server-mongodb-explorer",
        "mcp-server-redis-viewer",
        "mcp-server-s3-explorer",
        "mcp-server-gdrive-viewer",
        "mcp-server-database-scanner",
    ):
        blob = f"npx -y {pkg}"
        reason = _mcp_sensitive_reason(blob, ["-y", pkg])
        assert reason, f"{pkg}: wrongly suppressed (FN-1 regression)"


def test_shape_only_compounds_still_suppressed():
    """True shape-only tools (diagram/designer/docs/documentation/schema/erd) still do
    NOT flag — the round-3 tightening only removed the reader/browser suffixes."""
    for pkg in (
        "mcp-server-database-diagram",
        "mcp-server-database-designer",
        "mcp-server-redis-docs",
        "mcp-server-vault-documentation",
        "@scope/server-database-schema",
        "mcp-server-database-erd",
    ):
        blob = f"npx -y {pkg}"
        assert _mcp_sensitive_reason(blob, ["-y", pkg]) == "", f"{pkg}: wrongly flagged"


def test_bare_data_keyword_without_compound_suffix_still_flags():
    """Sanity control: the denylist only suppresses a keyword immediately followed by a
    benign suffix — a real 'server-database' (no diagram/docs/schema tail) still flags."""
    blob = "npx -y @modelcontextprotocol/server-database"
    reason = _mcp_sensitive_reason(blob, ["-y", "@modelcontextprotocol/server-database"])
    assert reason and "database" in reason


def test_remote_url_substring_never_flags_sensitive_data():
    """FP-B core fix: a REMOTE server's url/host is never consulted for the
    sensitive-data leg — a 'mcp-database-docs' hostname grants no local data access.
    _mcp_leg_contributions (the real production path) builds the sensitive-data probe
    from command+args only and never feeds it the url, so this hostname substring
    cannot manufacture a spurious sensitive leg; the remote endpoint correctly still
    raises the outbound leg instead."""
    contribs = _mcp_leg_contributions(
        {"mcp": {"servers": {"dbdocs": {"url": "https://mcp-database-docs.example.com/mcp"}}}}
    )
    assert contribs["sensitive data"] == []
    assert contribs["outbound actions"]  # the remote endpoint still raises outbound


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


# ── C-135 round 3 pins: full 3/3 FAIL for the two FN classes just closed ────────────

@pytest.mark.parametrize(
    "pkg",
    [
        "mcp-server-vault-viewer",
        "mcp-server-secret-explorer",
        "mcp-server-postgres-viewer",
        "mcp-server-database-scanner",
    ],
)
def test_a1_reader_browser_mcp_is_full_trifecta_fail(pkg):
    a1 = _a1({
        "channels": {"telegram": {"enabled": True, "dmPolicy": "open"}},
        "tools": {"web": {"fetch": {"enabled": True}}},
        "mcp": {"servers": {"r": {"command": "npx", "args": ["-y", pkg]}}},
    })
    assert a1.status == FAIL, f"{pkg}: FN-1 regression — did not FAIL 3/3"
    assert set(a1.evidence) == {"untrusted input", "sensitive data", "outbound actions"}


@pytest.mark.parametrize("root", ["/home/git", "/home/backup", "/home/www"])
def test_a1_service_account_home_fs_mcp_is_full_trifecta_fail(root):
    a1 = _a1({
        "channels": {"telegram": {"enabled": True, "dmPolicy": "open"}},
        "tools": {"web": {"fetch": {"enabled": True}}},
        "mcp": {"servers": {"fs": {
            "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", root],
        }}},
    })
    assert a1.status == FAIL, f"{root}: FN-2 regression — did not FAIL 3/3"
    assert set(a1.evidence) == {"untrusted input", "sensitive data", "outbound actions"}


@pytest.mark.parametrize(
    "cfg_mcp",
    [
        {"erd": {"command": "npx", "args": ["-y", "mcp-server-database-diagram"]}},
        {"docs": {"command": "npx", "args": ["-y", "mcp-server-redis-docs"]}},
    ],
)
def test_a1_shape_only_mcp_stays_two_of_three(cfg_mcp):
    a1 = _a1({
        "channels": {"telegram": {"enabled": True, "dmPolicy": "allowlist"}},
        "tools": {"web": {"fetch": {"enabled": True}}},
        "mcp": {"servers": cfg_mcp},
    })
    assert a1.status != FAIL
    assert "sensitive data" not in (a1.evidence or [])
    assert len(a1.evidence) <= 2


@pytest.mark.parametrize("root", ["/home/shared", "/Users/Shared", "/home/data", "/home/projects"])
def test_a1_accepted_residual_shared_home_fs_mcp_stays_two_of_three(root):
    a1 = _a1({
        "channels": {"telegram": {"enabled": True, "dmPolicy": "allowlist"}},
        "tools": {"web": {"fetch": {"enabled": True}}},
        "mcp": {"servers": {"fs": {
            "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", root],
        }}},
    })
    assert a1.status != FAIL
    assert "sensitive data" not in (a1.evidence or [])
    assert len(a1.evidence) <= 2


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


# ── FP-A fixture: server-filesystem at /Users/Shared and /home/shared ───────────────

def test_clean_fixture_shared_home_dirs_stays_two_of_three():
    """FP-A regression pin: a filesystem MCP rooted at a shared/service dir under
    /Users or /home (not a private per-user home) must NOT raise the sensitive leg,
    even paired with an untrusted channel + outbound tool that would reach 3/3 if it
    wrongly did."""
    ctx = collect(FIXTURES / "clean_b229_mcp_shared_home_dir")
    a1 = check_trifecta(ctx)
    assert a1.status != FAIL
    assert "sensitive data" not in (a1.evidence or [])
    assert len(a1.evidence) <= 2


def test_clean_fixture_shared_home_dirs_no_fail_in_full_audit():
    _, findings, _ = audit(FIXTURES / "clean_b229_mcp_shared_home_dir")
    assert not [f for f in findings if f.status == FAIL]


# ── FP-B fixture: local database-diagram compound + remote database-docs URL ───────

def test_clean_fixture_benign_compound_names_stays_two_of_three():
    """FP-B regression pin: a local database-DIAGRAM package and a remote
    database-DOCS URL must NOT raise the sensitive leg, even paired with an untrusted
    channel + outbound tool that would reach 3/3 if either wrongly did."""
    ctx = collect(FIXTURES / "clean_b229_mcp_benign_compound_names")
    a1 = check_trifecta(ctx)
    assert a1.status != FAIL
    assert "sensitive data" not in (a1.evidence or [])
    assert len(a1.evidence) <= 2


def test_clean_fixture_benign_compound_names_no_fail_in_full_audit():
    _, findings, _ = audit(FIXTURES / "clean_b229_mcp_benign_compound_names")
    assert not [f for f in findings if f.status == FAIL]


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
    "clean_b229_mcp_remote_benign",
    "clean_b229_mcp_shared_home_dir",
    "clean_b229_mcp_benign_compound_names",
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
