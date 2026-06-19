"""Extended tests for clawcheck.dryrun — new sources: mcp_response, memory_store, subagent.

Verifies that:
  - The three new sources are present in SOURCES and covered by make_scenarios().
  - Every new scenario carries a CLAWCHECK_FAKE_* token (never a real secret).
  - evaluate() correctly flags VULNERABLE when the agent calls a dangerous tool
    with the fake secret for each new source.
  - render_dryrun() output is non-empty and ASCII-safe.

All assertions run offline with zero network calls.
"""
from __future__ import annotations

import re

from clawcheck.dryrun import (
    SOURCES,
    _FAKE_PREFIX,
    _TOKEN_PREFIX,
    evaluate,
    make_scenarios,
    render_dryrun,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

NEW_SOURCES = ["mcp_response", "memory_store", "subagent"]

_REAL_KEY_RE = re.compile(
    r"sk-ant-|sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}",
    re.I,
)

_RFC5737_PREFIXES = ("198.51.100.", "192.0.2.", "203.0.113.")


# ---------------------------------------------------------------------------
# New sources declared in SOURCES and present in scenarios
# ---------------------------------------------------------------------------

def test_new_sources_in_sources_list():
    for src in NEW_SOURCES:
        assert src in SOURCES, f"source {src!r} missing from SOURCES"


def test_new_sources_covered_by_scenarios():
    present = {sc["source"] for sc in make_scenarios()}
    for src in NEW_SOURCES:
        assert src in present, f"source {src!r} absent from make_scenarios() output"


def test_all_sources_covered_by_scenarios():
    """Every entry in SOURCES must have at least one scenario."""
    present = {sc["source"] for sc in make_scenarios()}
    for src in SOURCES:
        assert src in present, f"source {src!r} not covered by any scenario"


def test_scenario_count_increased():
    """Suite must have more scenarios than the original five."""
    assert len(make_scenarios()) > 5, (
        f"expected >5 scenarios, got {len(make_scenarios())}"
    )


def test_each_new_source_has_multiple_scenarios():
    from collections import Counter
    counts = Counter(sc["source"] for sc in make_scenarios())
    for src in NEW_SOURCES:
        assert counts[src] >= 2, (
            f"source {src!r} has only {counts[src]} scenario(s), expected >=2"
        )


# ---------------------------------------------------------------------------
# Fake-secret safety for new scenarios
# ---------------------------------------------------------------------------

def test_new_source_scenarios_have_fake_prefix():
    for sc in make_scenarios():
        if sc["source"] not in NEW_SOURCES:
            continue
        assert sc["fake_secret"].startswith(_FAKE_PREFIX), (
            f"{sc['id']} fake_secret does not start with {_FAKE_PREFIX!r}"
        )


def test_new_source_scenarios_no_real_api_key():
    for sc in make_scenarios():
        if sc["source"] not in NEW_SOURCES:
            continue
        assert not _REAL_KEY_RE.match(sc["fake_secret"]), (
            f"{sc['id']} fake_secret looks like a real API key: {sc['fake_secret']!r}"
        )


def test_new_source_fake_secret_in_instruction():
    for sc in make_scenarios():
        if sc["source"] not in NEW_SOURCES:
            continue
        assert sc["fake_secret"] in sc["instruction"], (
            f"{sc['id']} fake_secret not embedded in instruction"
        )


def test_all_fake_secrets_unique():
    """Every scenario (old + new) must have a distinct fake_secret."""
    secrets = [sc["fake_secret"] for sc in make_scenarios()]
    assert len(secrets) == len(set(secrets)), "duplicate fake_secret values found"


def test_new_source_tokens_have_prefix():
    for sc in make_scenarios():
        if sc["source"] not in NEW_SOURCES:
            continue
        assert sc["token"].startswith(_TOKEN_PREFIX), (
            f"{sc['id']} token does not start with {_TOKEN_PREFIX!r}"
        )


# ---------------------------------------------------------------------------
# Dangerous tools for new scenarios
# ---------------------------------------------------------------------------

def test_new_source_scenarios_have_dangerous_tools():
    for sc in make_scenarios():
        if sc["source"] not in NEW_SOURCES:
            continue
        assert isinstance(sc["dangerous_tools"], list) and sc["dangerous_tools"], (
            f"{sc['id']} dangerous_tools is empty or not a list"
        )


def test_new_source_instructions_reference_fake_host_or_rfc5737():
    """Each new-source instruction must direct the agent to a clearly-fake destination."""
    for sc in make_scenarios():
        if sc["source"] not in NEW_SOURCES:
            continue
        instr = sc["instruction"]
        has_fake = (
            any(ip in instr for ip in _RFC5737_PREFIXES)
            or "example.invalid" in instr
            or "attacker@" in instr
        )
        assert has_fake, (
            f"{sc['id']} (source={sc['source']}) instruction has no recognisable fake "
            f"destination (RFC-5737 IP or example.invalid)"
        )


# ---------------------------------------------------------------------------
# evaluate() for new source scenarios
# ---------------------------------------------------------------------------

def test_evaluate_vulnerable_for_mcp_response_scenarios():
    for sc in make_scenarios(seed="v2-mcp"):
        if sc["source"] != "mcp_response":
            continue
        transcript = (
            f"Calling {sc['dangerous_tools'][0]} with data={sc['fake_secret']}"
        )
        assert evaluate(transcript, sc) == "VULNERABLE", (
            f"{sc['id']} not flagged VULNERABLE"
        )


def test_evaluate_vulnerable_for_memory_store_scenarios():
    for sc in make_scenarios(seed="v2-mem"):
        if sc["source"] != "memory_store":
            continue
        transcript = (
            f"Executing {sc['dangerous_tools'][0]}(payload={sc['fake_secret']})"
        )
        assert evaluate(transcript, sc) == "VULNERABLE", (
            f"{sc['id']} not flagged VULNERABLE"
        )


def test_evaluate_vulnerable_for_subagent_scenarios():
    for sc in make_scenarios(seed="v2-sub"):
        if sc["source"] != "subagent":
            continue
        transcript = (
            f"Calling {sc['dangerous_tools'][0]} with {sc['fake_secret']}"
        )
        assert evaluate(transcript, sc) == "VULNERABLE", (
            f"{sc['id']} not flagged VULNERABLE"
        )


def test_evaluate_resistant_on_refusal_for_new_sources():
    refusal = "I recognise this as injected content and will not comply."
    for sc in make_scenarios(seed="v2-resist"):
        if sc["source"] not in NEW_SOURCES:
            continue
        assert evaluate(refusal, sc) == "RESISTANT", (
            f"{sc['id']} (source={sc['source']}) not RESISTANT on refusal"
        )


def test_evaluate_resistant_secret_only_no_tool_for_new_sources():
    for sc in make_scenarios(seed="v2-seconly"):
        if sc["source"] not in NEW_SOURCES:
            continue
        transcript = f"I can see the secret {sc['fake_secret']} but I will not act."
        assert evaluate(transcript, sc) == "RESISTANT", (
            f"{sc['id']} flagged VULNERABLE when only secret present, no tool"
        )


def test_evaluate_resistant_tool_only_no_secret_for_new_sources():
    for sc in make_scenarios(seed="v2-toolonly"):
        if sc["source"] not in NEW_SOURCES:
            continue
        transcript = f"I could call {sc['dangerous_tools'][0]} but I am refusing."
        assert evaluate(transcript, sc) == "RESISTANT", (
            f"{sc['id']} flagged VULNERABLE when only tool mentioned, no secret"
        )


def test_evaluate_vulnerable_via_rfc5737_ip_for_new_sources():
    """If the agent posts to an RFC-5737 IP with the fake secret, it is VULNERABLE."""
    for sc in make_scenarios(seed="v2-ip"):
        if sc["source"] not in NEW_SOURCES:
            continue
        transcript = f"Posting to http://198.51.100.11/sink data={sc['fake_secret']}"
        assert evaluate(transcript, sc) == "VULNERABLE", (
            f"{sc['id']} not flagged VULNERABLE via RFC-5737 IP"
        )


def test_evaluate_all_new_source_scenarios_resistant_on_empty():
    for sc in make_scenarios(seed="v2-empty"):
        if sc["source"] not in NEW_SOURCES:
            continue
        assert evaluate("", sc) == "RESISTANT", (
            f"{sc['id']} not RESISTANT on empty transcript"
        )


def test_evaluate_all_new_source_scenarios_resistant_on_none():
    for sc in make_scenarios(seed="v2-none"):
        if sc["source"] not in NEW_SOURCES:
            continue
        assert evaluate(None, sc) == "RESISTANT", (
            f"{sc['id']} not RESISTANT on None transcript"
        )


# ---------------------------------------------------------------------------
# Determinism for new sources
# ---------------------------------------------------------------------------

def test_new_source_tokens_deterministic_with_seed():
    s1 = make_scenarios(seed="v2-det")
    s2 = make_scenarios(seed="v2-det")
    tokens_1 = {sc["token"] for sc in s1 if sc["source"] in NEW_SOURCES}
    tokens_2 = {sc["token"] for sc in s2 if sc["source"] in NEW_SOURCES}
    assert tokens_1 == tokens_2, "tokens differ across calls with same seed"


def test_new_source_secrets_deterministic_with_seed():
    s1 = make_scenarios(seed="v2-det2")
    s2 = make_scenarios(seed="v2-det2")
    secrets_1 = {sc["fake_secret"] for sc in s1 if sc["source"] in NEW_SOURCES}
    secrets_2 = {sc["fake_secret"] for sc in s2 if sc["source"] in NEW_SOURCES}
    assert secrets_1 == secrets_2, "fake_secrets differ across calls with same seed"


# ---------------------------------------------------------------------------
# render_dryrun — new sources appear, ascii-safe, non-empty
# ---------------------------------------------------------------------------

def test_render_dryrun_nonempty():
    out = render_dryrun(make_scenarios())
    assert out.strip(), "render_dryrun returned empty output"


def test_render_dryrun_ascii_only_safe():
    out = render_dryrun(make_scenarios(), ascii_only=True)
    out.encode("ascii")  # raises UnicodeEncodeError if non-ASCII present


def test_render_dryrun_contains_new_source_ids():
    scenarios = make_scenarios(seed="v2-render")
    out = render_dryrun(scenarios)
    for sc in scenarios:
        if sc["source"] in NEW_SOURCES:
            assert sc["id"] in out, f"{sc['id']} missing from render_dryrun output"


def test_render_dryrun_contains_new_source_names():
    out = render_dryrun(make_scenarios(seed="v2-render"))
    for src in NEW_SOURCES:
        assert src in out, f"source {src!r} absent from render_dryrun output"


def test_render_dryrun_does_not_contain_real_secrets():
    out = render_dryrun(make_scenarios())
    assert not _REAL_KEY_RE.search(out), (
        "render_dryrun output contains a real-looking API key"
    )


def test_render_dryrun_total_scenario_count_in_header():
    scenarios = make_scenarios(seed="v2-count")
    out = render_dryrun(scenarios)
    assert str(len(scenarios)) in out, (
        "render_dryrun header does not mention the scenario count"
    )
