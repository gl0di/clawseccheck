"""B-247 — A1 trifecta intake-leg is blind to MCP servers (a B-229 residual).

B-229 wired mcp.servers into 2 of the 3 lethal-trifecta legs (sensitive data /
outbound actions) but never the untrusted-input leg: _trifecta_legs' untrusted-input
clause read only channels / INPUT_TOOL_HINTS / tools.web.fetch, so a semantically
identical MCP intake source (e.g. the canonical @modelcontextprotocol/server-fetch, or
an email/imap/gmail/rss/feed/slack/inbox/github-issues-reading server) raised nothing
— an all-MCP lethal trifecta could reach 2/3 and score PASS/WARN forever, no matter how
much untrusted external content the agent actually ingested through MCP.

This covers: the new leg-detection heuristic (_mcp_intake_reason / _MCP_INTAKE_CAP_RE),
the isolating-control fixture pair proving intake is the ONLY variable that flips the
verdict, the thin-surface WARN path (A1 has no UNKNOWN status — WARN is its "cannot
determine" state) for an MCP-intake-only config, and a regression sweep proving the
existing B-229 fixtures + home_safe are unaffected (zero new false-FAIL, CLAUDE.md
Golden Rule #5 / C-135).

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import FAIL, PASS, WARN
from clawseccheck.checks import (
    _mcp_intake_reason,
    _mcp_leg_contributions,
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


# ── _mcp_intake_reason: known-name heuristics, MCP-naming anchored ──────────────────

def test_canonical_fetch_server_flags():
    reason = _mcp_intake_reason("npx -y @modelcontextprotocol/server-fetch")
    assert reason and "fetch" in reason


def test_web_search_compound_flags():
    reason = _mcp_intake_reason("npx -y mcp-server-web-search")
    assert reason and "web-search" in reason


def test_browser_compound_flags():
    reason = _mcp_intake_reason("npx -y mcp-server-browser")
    assert reason and "browser" in reason


def test_scraper_compound_flags():
    reason = _mcp_intake_reason("npx -y mcp-server-scraper")
    assert reason and "scraper" in reason


def test_email_imap_gmail_flag():
    for pkg in ("mcp-server-email", "mcp-server-imap", "mcp-server-gmail"):
        assert _mcp_intake_reason(f"npx -y {pkg}"), f"{pkg}: should flag intake"


def test_rss_feed_flag():
    for pkg in ("mcp-server-rss", "mcp-server-feed"):
        assert _mcp_intake_reason(f"npx -y {pkg}"), f"{pkg}: should flag intake"


def test_slack_flags():
    reason = _mcp_intake_reason("npx -y mcp-server-slack")
    assert reason and "slack" in reason


def test_inbox_flags():
    reason = _mcp_intake_reason("npx -y mcp-server-inbox")
    assert reason and "inbox" in reason


def test_github_issues_flags():
    reason = _mcp_intake_reason("npx -y mcp-server-github-issues")
    assert reason and "github-issues" in reason


def test_bare_keyword_without_mcp_naming_anchor_does_not_flag():
    """A bare 'fetch-helper' package (no @scope/server-<cap> / mcp-server-<cap> naming)
    must NOT trigger via a loose keyword match — the naming anchor is required (§5)."""
    assert _mcp_intake_reason("npx @tools/fetch-helper --url https://x") == ""


def test_bare_web_keyword_does_not_flag_intake():
    """Deliberately narrower than INPUT_TOOL_HINTS's bare 'web': a package merely
    containing 'web' (webhook / web3 / website-monitor) is NOT an intake source — only
    the 'web-search'/'websearch' compound counts. This is the specific asymmetry-repair
    boundary: 'webhook' stays an outbound-leg concern, never intake."""
    for pkg in ("mcp-server-webhook", "mcp-server-web3", "mcp-server-website-monitor"):
        assert _mcp_intake_reason(f"npx -y {pkg}") == "", f"{pkg}: wrongly flagged intake"


def test_filesystem_server_does_not_flag_intake():
    """A filesystem MCP is the sensitive-data leg's domain (_MCP_FS_PKG_RE) — folding it
    into intake too would duplicate/contradict that existing leg, so it must not flag
    here regardless of root breadth."""
    reason = _mcp_intake_reason(
        "npx -y @modelcontextprotocol/server-filesystem /"
    )
    assert reason == ""


def test_database_server_does_not_flag_intake():
    assert _mcp_intake_reason("npx -y @modelcontextprotocol/server-postgres") == ""


def test_benign_compound_suffix_does_not_flag_intake():
    """Reuses the shared shape-only-compound denylist: a 'slack-docs' package
    documents the API, it does not read live messages."""
    assert _mcp_intake_reason("npx -y mcp-server-slack-docs") == ""


def test_reader_suffix_still_flags_intake():
    """Sanity control: the denylist only suppresses a keyword immediately followed by a
    shape-only suffix — a real reader-suffixed package still flags."""
    reason = _mcp_intake_reason("npx -y mcp-server-inbox-reader")
    assert reason and "inbox" in reason


# ── _mcp_intake_reason: remote url IS consulted (unlike the sensitive-data probe) ───

def test_remote_url_with_naming_anchor_flags_intake():
    reason = _mcp_intake_reason("https://mcp.example.com/mcp-server-fetch")
    assert reason and "fetch" in reason


def test_remote_url_without_naming_anchor_does_not_flag():
    """A hostname/path substring alone (no mcp-server-/@scope/server-/mcp- anchor)
    stays unflagged — same anti-FP scoping as the local-blob case."""
    assert _mcp_intake_reason("https://fetchdata.example.com/mcp") == ""


# ── _mcp_leg_contributions: the new 'untrusted input' key ───────────────────────────

def test_leg_contributions_reports_untrusted_input_key():
    contribs = _mcp_leg_contributions(
        {"mcp": {"servers": {"w": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-fetch"]}}}}
    )
    assert "untrusted input" in contribs
    assert contribs["untrusted input"]
    assert "w" in contribs["untrusted input"][0]


def test_leg_contributions_calculator_mcp_does_not_raise_untrusted_input():
    contribs = _mcp_leg_contributions(
        {"mcp": {"servers": {"calc": {"command": "npx", "args": ["-y", "mcp-server-calculator"]}}}}
    )
    assert contribs["untrusted input"] == []


def test_leg_contributions_does_not_touch_existing_sensitive_or_outbound():
    """A pure intake MCP must not manufacture sensitive-data or outbound-actions
    contributions — the three legs stay independently computed."""
    contribs = _mcp_leg_contributions(
        {"mcp": {"servers": {"w": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-fetch"]}}}}
    )
    assert contribs["sensitive data"] == []
    assert contribs["outbound actions"] == []


# ── A1 integration: leg-isolation on a bare in-memory config ────────────────────────

def test_a1_fetch_mcp_alone_raises_untrusted_input_leg():
    a1 = _a1({"mcp": {"servers": {"w": {
        "command": "npx", "args": ["-y", "@modelcontextprotocol/server-fetch"],
    }}}})
    assert "untrusted input" in (a1.evidence or [])


def test_a1_calculator_mcp_alone_does_not_raise_untrusted_input_leg():
    a1 = _a1({"mcp": {"servers": {"calc": {
        "command": "npx", "args": ["-y", "mcp-server-calculator"],
    }}}})
    assert "untrusted input" not in (a1.evidence or [])


def test_a1_isolating_control_swap_intake_flips_to_full_trifecta_fail():
    """The core repro: two configs identical except for the intake MCP server. Swapping
    a benign calculator MCP for a fetch MCP is the ONLY change and must be the ONLY
    thing that flips A1 from <=2/3 to 3/3 FAIL."""
    base = {
        "mcpServers": {"postgres-secret": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-postgres", "postgres://db/prod"],
        }},
        "mcp": {"servers": {"relay": {"url": "https://relay.example.com/mcp"}}},
        "tools": {"profile": "coding"},
    }
    no_intake = dict(base, mcp={"servers": {
        **base["mcp"]["servers"],
        "calc": {"command": "npx", "args": ["-y", "mcp-server-calculator"]},
    }})
    with_intake = dict(base, mcp={"servers": {
        **base["mcp"]["servers"],
        "web-research": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-fetch"]},
    }})

    a1_before = _a1(no_intake)
    a1_after = _a1(with_intake)

    assert a1_before.status != FAIL
    assert "untrusted input" not in (a1_before.evidence or [])

    assert a1_after.status == FAIL
    assert set(a1_after.evidence) == {"untrusted input", "sensitive data", "outbound actions"}


def test_a1_detail_names_mcp_server_as_intake_capability_source():
    a1 = _a1({
        "mcpServers": {"postgres-secret": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-postgres", "postgres://db/prod"],
        }},
        "mcp": {"servers": {
            "web-research": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-fetch"]},
        }},
        "tools": {"profile": "coding"},
    })
    assert a1.status == FAIL
    assert "MCP server 'web-research'" in a1.detail
    assert "fetch" in a1.detail


# ── Fixture trio: bad (3/3 FAIL) / clean isolating-control / clean thin-surface WARN ─

def test_bad_fixture_mcp_intake_is_full_trifecta_fail():
    ctx = collect(FIXTURES / "bad_b247_mcp_intake_trifecta")
    a1 = check_trifecta(ctx)
    assert a1.status == FAIL
    assert set(a1.evidence) == {"untrusted input", "sensitive data", "outbound actions"}
    assert "MCP server 'web-research'" in a1.detail


def test_bad_fixture_registered_in_full_audit():
    _, findings, score = audit(FIXTURES / "bad_b247_mcp_intake_trifecta")
    a1 = {f.id: f for f in findings}["A1"]
    assert a1.status == FAIL
    assert score.failed_critical >= 1


def test_clean_isolating_control_fixture_stays_two_of_three():
    """Same sensitive-data (postgres) + outbound (profile:coding + relay) MCP surface
    as the bad fixture, but the intake MCP is a benign calculator — must NOT reach
    3/3, proving the intake source is the isolating variable."""
    ctx = collect(FIXTURES / "clean_b247_mcp_no_intake_stays_two_of_three")
    a1 = check_trifecta(ctx)
    assert a1.status != FAIL
    assert "untrusted input" not in (a1.evidence or [])
    assert len(a1.evidence) <= 2


def test_clean_isolating_control_fixture_no_fail_in_full_audit():
    _, findings, _ = audit(FIXTURES / "clean_b247_mcp_no_intake_stays_two_of_three")
    assert not [f for f in findings if f.status == FAIL]


def test_clean_intake_alone_fixture_is_not_fail():
    """A single fetch-capable MCP server with no other declared capability: only the
    untrusted-input leg is live (1/3), so A1 must not FAIL. A1 has no UNKNOWN status;
    its 'cannot determine' state is the thin-surface WARN (B-033) — the config declares
    no other tool surface, so the outbound leg's OFF reading can't be trusted and A1
    hedges to WARN rather than a false PASS. This is the check's UNKNOWN-equivalent
    coverage for the new intake signal."""
    ctx = collect(FIXTURES / "clean_b247_mcp_intake_alone_thin_surface")
    a1 = check_trifecta(ctx)
    assert a1.status != FAIL
    assert a1.status == WARN
    assert "untrusted input" in (a1.evidence or [])
    assert "Cannot determine from config" in a1.detail


def test_clean_intake_alone_fixture_no_fail_in_full_audit():
    _, findings, _ = audit(FIXTURES / "clean_b247_mcp_intake_alone_thin_surface")
    assert not [f for f in findings if f.status == FAIL]


# ── Regression sweep (C-135 / Golden Rule #5): zero new false-positive FAIL ─────────

# Existing MCP-bearing fixtures (from B-229 and elsewhere) that must NOT flip to
# A1=FAIL now that MCP capability is ALSO wired into the untrusted-input leg.
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
    "bad_b229_mcp_fs_root_trifecta",
)


def test_existing_mcp_bearing_fixtures_a1_verdict_unaffected():
    """The bad_b229 fixture is included too: it must still FAIL (unaffected, its fs
    server carries no intake keyword), and every clean fixture must stay non-FAIL."""
    for name in _EXISTING_MCP_CLEAN_FIXTURES:
        _, findings, _ = audit(FIXTURES / name)
        a1 = {f.id: f for f in findings}["A1"]
        if name.startswith("bad_"):
            assert a1.status == FAIL, f"{name}: A1 unexpectedly stopped failing"
        else:
            assert a1.status != FAIL, f"{name}: A1 regressed to FAIL — {a1.detail}"


def test_home_safe_unaffected():
    _, findings, score = audit(FIXTURES / "home_safe")
    a1 = {f.id: f for f in findings}["A1"]
    assert a1.status == PASS
    assert len(a1.evidence) <= 2
    assert not [f for f in findings if f.status == FAIL]
    assert score.grade == "A"
