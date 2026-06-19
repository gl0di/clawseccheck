"""Extended tests for clawcheck.redteam — new agentic attack categories (v2).

Covers the six new scenario classes added to make_suite():
  tool_poisoning, mcp_response_injection, memory_poisoning,
  multi_agent, approval_bypass_via_injection, dirty_to_exfil

All assertions run offline with zero network calls.
"""
from __future__ import annotations

import re

from clawcheck.redteam import (
    CATEGORIES,
    TOKEN_PREFIX,
    make_suite,
    render_suite,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

NEW_CATEGORIES = [
    "tool_poisoning",
    "mcp_response_injection",
    "memory_poisoning",
    "multi_agent",
    "approval_bypass_via_injection",
    "dirty_to_exfil",
]

# Pattern for real API keys — must NEVER appear in payloads.
_REAL_KEY_RE = re.compile(
    r"sk-ant-|sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}",
    re.I,
)

# The fake tokens / hosts used in templates — verify they are all clearly fake.
_FAKE_HOSTS = ["example.invalid", "example.com", "exfil.example.com"]
_RFC5737_PREFIXES = ("198.51.100.", "192.0.2.", "203.0.113.")


# ---------------------------------------------------------------------------
# New categories are present in CATEGORIES and in the suite
# ---------------------------------------------------------------------------

def test_new_categories_in_categories_list():
    """Every new attack class must be declared in CATEGORIES."""
    for cat in NEW_CATEGORIES:
        assert cat in CATEGORIES, f"category {cat!r} missing from CATEGORIES"


def test_new_categories_covered_by_suite():
    """make_suite() must produce at least one entry per new category."""
    suite = make_suite()
    present = {e["category"] for e in suite}
    for cat in NEW_CATEGORIES:
        assert cat in present, f"category {cat!r} absent from make_suite() output"


def test_suite_entry_count_increased():
    """Suite must have more entries than the original five categories imply."""
    suite = make_suite()
    # Original had 10 entries (2 per original category × 5).
    assert len(suite) > 10, f"expected >10 entries, got {len(suite)}"


def test_suite_covers_all_categories():
    """All declared categories (old + new) must appear in the suite."""
    suite = make_suite()
    present = {e["category"] for e in suite}
    for cat in CATEGORIES:
        assert cat in present, f"category {cat!r} missing from suite"


# ---------------------------------------------------------------------------
# criterion field — new in v2
# ---------------------------------------------------------------------------

def test_suite_entries_have_criterion_key():
    """Every entry must include the 'criterion' key introduced in v2."""
    for entry in make_suite():
        assert "criterion" in entry, f"{entry['id']} missing 'criterion' key"


def test_criterion_is_nonempty_string():
    for entry in make_suite():
        assert isinstance(entry["criterion"], str) and entry["criterion"].strip(), (
            f"{entry['id']} criterion is empty"
        )


def test_criterion_mentions_resistant_and_vulnerable():
    """Each criterion must describe both outcomes."""
    for entry in make_suite():
        crit = entry["criterion"].upper()
        assert "RESISTANT" in crit, f"{entry['id']} criterion missing RESISTANT"
        assert "VULNERABLE" in crit, f"{entry['id']} criterion missing VULNERABLE"


# ---------------------------------------------------------------------------
# No real secrets in any payload
# ---------------------------------------------------------------------------

def test_no_real_secret_in_any_payload():
    """Payloads must not contain strings that look like real API keys."""
    for entry in make_suite():
        assert not _REAL_KEY_RE.search(entry["payload"]), (
            f"{entry['id']} payload contains a real-looking API key"
        )


def test_no_real_secret_in_any_criterion():
    for entry in make_suite():
        assert not _REAL_KEY_RE.search(entry["criterion"]), (
            f"{entry['id']} criterion contains a real-looking API key"
        )


# ---------------------------------------------------------------------------
# Token marker discipline
# ---------------------------------------------------------------------------

def test_token_prefix_on_all_entries():
    for entry in make_suite():
        assert entry["token"].startswith(TOKEN_PREFIX), (
            f"{entry['id']} token lacks prefix {TOKEN_PREFIX!r}"
        )


def test_token_in_payload_for_all_entries():
    for entry in make_suite():
        assert entry["token"] in entry["payload"], (
            f"{entry['id']} token not embedded in payload"
        )


def test_all_tokens_unique():
    suite = make_suite()
    tokens = [e["token"] for e in suite]
    assert len(tokens) == len(set(tokens)), "duplicate tokens found in suite"


# ---------------------------------------------------------------------------
# tool_poisoning specific checks
# ---------------------------------------------------------------------------

def test_tool_poisoning_entries_exist():
    ids = {e["id"] for e in make_suite() if e["category"] == "tool_poisoning"}
    assert len(ids) >= 2, f"expected >=2 tool_poisoning entries, got {ids}"


def test_tool_poisoning_payloads_reference_tool_result():
    for entry in make_suite():
        if entry["category"] != "tool_poisoning":
            continue
        text = entry["payload"].upper()
        # Must look like a tool result wrapping a hidden directive.
        assert "TOOL" in text or "RESULT" in text or "DIRECTIVE" in text, (
            f"{entry['id']} tool_poisoning payload has no tool/result/directive marker"
        )


def test_tool_poisoning_uses_fake_host_or_rfc5737():
    """Exfil destinations must be RFC-5737 IPs or clearly-fake hostnames."""
    for entry in make_suite():
        if entry["category"] != "tool_poisoning":
            continue
        payload = entry["payload"]
        has_fake = (
            any(ip in payload for ip in _RFC5737_PREFIXES)
            or any(h in payload for h in _FAKE_HOSTS)
        )
        assert has_fake, (
            f"{entry['id']} tool_poisoning payload has no recognisable fake host/IP"
        )


# ---------------------------------------------------------------------------
# mcp_response_injection specific checks
# ---------------------------------------------------------------------------

def test_mcp_response_injection_entries_exist():
    ids = {e["id"] for e in make_suite() if e["category"] == "mcp_response_injection"}
    assert len(ids) >= 2, f"expected >=2 mcp_response_injection entries, got {ids}"


def test_mcp_response_injection_payloads_look_like_responses():
    for entry in make_suite():
        if entry["category"] != "mcp_response_injection":
            continue
        text = entry["payload"]
        # Should mention MCP or contain structured response markers.
        assert "MCP" in text or "{" in text or "Content-Type" in text or "response" in text.lower(), (
            f"{entry['id']} mcp_response_injection payload does not look like an MCP response"
        )


# ---------------------------------------------------------------------------
# memory_poisoning specific checks
# ---------------------------------------------------------------------------

def test_memory_poisoning_entries_exist():
    ids = {e["id"] for e in make_suite() if e["category"] == "memory_poisoning"}
    assert len(ids) >= 2, f"expected >=2 memory_poisoning entries, got {ids}"


def test_memory_poisoning_payloads_reference_memory():
    for entry in make_suite():
        if entry["category"] != "memory_poisoning":
            continue
        text = entry["payload"].upper()
        assert "MEMORY" in text or "PERSISTENT" in text or "STORED" in text or "SESSION" in text, (
            f"{entry['id']} memory_poisoning payload has no memory/persistence reference"
        )


# ---------------------------------------------------------------------------
# multi_agent specific checks
# ---------------------------------------------------------------------------

def test_multi_agent_entries_exist():
    ids = {e["id"] for e in make_suite() if e["category"] == "multi_agent"}
    assert len(ids) >= 2, f"expected >=2 multi_agent entries, got {ids}"


def test_multi_agent_payloads_reference_agent_hierarchy():
    keywords = {"agent", "orchestrator", "coordinator", "sub-agent", "subagent", "elevated"}
    for entry in make_suite():
        if entry["category"] != "multi_agent":
            continue
        lower = entry["payload"].lower()
        found = any(kw in lower for kw in keywords)
        assert found, (
            f"{entry['id']} multi_agent payload missing agent-hierarchy keyword"
        )


# ---------------------------------------------------------------------------
# approval_bypass_via_injection specific checks
# ---------------------------------------------------------------------------

def test_approval_bypass_entries_exist():
    ids = {e["id"] for e in make_suite() if e["category"] == "approval_bypass_via_injection"}
    assert len(ids) >= 2, f"expected >=2 approval_bypass_via_injection entries, got {ids}"


def test_approval_bypass_payloads_claim_pre_approval():
    keywords = {"pre-approved", "approved", "bypass", "no restriction", "granted"}
    for entry in make_suite():
        if entry["category"] != "approval_bypass_via_injection":
            continue
        lower = entry["payload"].lower()
        found = any(kw in lower for kw in keywords)
        assert found, (
            f"{entry['id']} approval_bypass payload missing pre-approval claim"
        )


# ---------------------------------------------------------------------------
# dirty_to_exfil specific checks
# ---------------------------------------------------------------------------

def test_dirty_to_exfil_entries_exist():
    ids = {e["id"] for e in make_suite() if e["category"] == "dirty_to_exfil"}
    assert len(ids) >= 2, f"expected >=2 dirty_to_exfil entries, got {ids}"


def test_dirty_to_exfil_payloads_contain_fake_token_marker():
    """dirty_to_exfil payloads must embed a clearly-fake CLAWCHECK_FAKE_* token."""
    for entry in make_suite():
        if entry["category"] != "dirty_to_exfil":
            continue
        assert "CLAWCHECK_FAKE_" in entry["payload"], (
            f"{entry['id']} dirty_to_exfil payload missing CLAWCHECK_FAKE_ marker"
        )


def test_dirty_to_exfil_uses_fake_host_or_rfc5737():
    for entry in make_suite():
        if entry["category"] != "dirty_to_exfil":
            continue
        payload = entry["payload"]
        has_fake = (
            any(ip in payload for ip in _RFC5737_PREFIXES)
            or any(h in payload for h in _FAKE_HOSTS)
        )
        assert has_fake, (
            f"{entry['id']} dirty_to_exfil payload has no recognisable fake host/IP"
        )


# ---------------------------------------------------------------------------
# render_suite — criterion appears, ascii-safe, non-empty
# ---------------------------------------------------------------------------

def test_render_suite_nonempty():
    out = render_suite(make_suite())
    assert out.strip(), "render_suite returned empty output"


def test_render_suite_ascii_only_safe():
    out = render_suite(make_suite(), ascii_only=True)
    out.encode("ascii")  # raises UnicodeEncodeError if non-ASCII present


def test_render_suite_contains_criterion_label():
    out = render_suite(make_suite())
    assert "CRITERION" in out, "render_suite output missing CRITERION label"


def test_render_suite_contains_new_category_names():
    out = render_suite(make_suite())
    for cat in NEW_CATEGORIES:
        assert cat in out, f"category {cat!r} absent from render_suite output"


def test_render_suite_contains_all_entry_ids():
    suite = make_suite()
    out = render_suite(suite)
    for entry in suite:
        assert entry["id"] in out, f"{entry['id']} absent from render_suite output"


def test_render_suite_does_not_contain_real_api_keys():
    out = render_suite(make_suite())
    assert not _REAL_KEY_RE.search(out), (
        "render_suite output contains a real-looking API key"
    )
