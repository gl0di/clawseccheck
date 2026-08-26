"""B351 — code mode swaps the model's tool surface for `exec` + `wait`.

Grounded on the installed dist's own RESOLVER (openclaw@2026.7.1-2), not on the
descriptions map:

    normalizeCodeModeRawConfig(v)   code-mode-D5mNEiYV.js:36-41
        true  -> {enabled: true}    <- the boolean shorthand is REAL
        false -> {enabled: false}
        record-> itself
        else  -> undefined

    readCodeModeRawConfig(cfg, id)  :42-49
        agentRaw ? {...globalRaw, ...agentRaw} : globalRaw   <- per-agent merges OVER
                                                                global, BOTH directions

    resolveCodeModeConfig(...)      :61-78
        enabled: readBoolean(raw.enabled, false)             <- only a real bool counts

Two lying-PASSes are pinned here, because a naive reader hits both: reading `.enabled` off
the boolean shorthand sees nothing and reports "off"; reading only `tools.codeMode` misses
an `agents.list[]` entry that turns it on independently.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import BY_ID, MEDIUM, PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    CHECKS,
    _b351_enabled,
    _b351_normalize_agent_id,
    _b351_raw_code_mode,
    _b351_resolvable_agents,
    check_code_mode_tool_surface,
)
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _f(name: str):
    return check_code_mode_tool_surface(collect(FIXTURES / name))


def _ctx(cfg, tmp_path):
    return Context(home=tmp_path, config=cfg, config_found=True)


# --------------------------------------------------------------- off stays quiet
@pytest.mark.parametrize("name", [
    "clean_b351_codemode_absent",
    "clean_b351_codemode_false_shorthand",
    "clean_b351_codemode_object_disabled",
])
def test_clean_fixtures_pass(name):
    f = _f(name)
    assert f.status == PASS, f"{name}: expected PASS, got {f.status}: {f.detail}"
    assert "QuickJS code mode is off" in f.detail


# --------------------------------------------------------------- lying-PASS #1
def test_the_boolean_shorthand_is_not_missed():
    """`codeMode: true` has no `.enabled` key at all.

    A check written as `dig(cfg, "tools.codeMode.enabled")` returns None here and reports
    the feature off — on the shape most likely to be typed by hand. This is the whole
    reason the check mirrors the vendor's normaliser instead of reading a nested key.
    """
    f = _f("bad_b351_codemode_true_shorthand")
    assert f.status == WARN, f"got {f.status}: {f.detail}"
    assert "on for every agent" in f.detail


# --------------------------------------------------------------- lying-PASS #2
def test_an_agent_can_turn_it_on_while_global_is_off():
    """The per-agent override, which a global-only read cannot see."""
    f = _f("bad_b351_codemode_agent_only")
    assert f.status == WARN, f"got {f.status}: {f.detail}"
    assert "off globally but ON for" in f.detail
    assert "builder" in f.detail
    assert any("builder" in e for e in (f.evidence or [])), "the agent must reach evidence"


def test_the_agent_that_did_not_enable_it_is_not_named():
    """`main` carries no codeMode; naming it would misattribute the finding."""
    f = _f("bad_b351_codemode_agent_only")
    assert "main" not in f.detail.replace("domain", "")


# --------------------------------------------------------------- narrowing is not a hole
def test_global_on_with_an_agent_narrowed_off_still_reports():
    """Global-on remains on for any agent id NOT in agents.list.

    `resolveAgentEntry` returns undefined for an unlisted id, so `agentRaw` is undefined
    and the global value is used wholesale — narrowing one listed agent does not turn the
    feature off. The detail must say so rather than implying it is contained.
    """
    f = _f("bad_b351_codemode_global_on_agent_narrowed")
    assert f.status == WARN
    assert "on globally" in f.detail and "narrowed off" in f.detail


def test_an_agent_object_without_enabled_inherits_global(tmp_path):
    """`{...globalRaw, ...agentRaw}`: an agent object carrying only tuning keys does NOT
    reset `enabled`, so global's value survives the spread."""
    cfg = {"tools": {"codeMode": {"enabled": True}},
           "agents": {"list": [{"id": "a", "tools": {"codeMode": {"timeoutMs": 100}}}]}}
    assert check_code_mode_tool_surface(_ctx(cfg, tmp_path)).status == WARN


# --------------------------------------------------------------- the vendor's own gate
def test_only_a_real_boolean_enables_it(tmp_path):
    """`readBoolean(raw.enabled, false)` — a truthy non-bool is NOT on."""
    for truthy in ("true", 1, "yes", [1]):
        cfg = {"tools": {"codeMode": {"enabled": truthy}}}
        f = check_code_mode_tool_surface(_ctx(cfg, tmp_path))
        assert f.status == PASS, f"{truthy!r}: got {f.status}"


def test_the_normaliser_matches_the_vendors_shapes():
    assert _b351_raw_code_mode(True) == {"enabled": True}
    assert _b351_raw_code_mode(False) == {"enabled": False}
    assert _b351_raw_code_mode({"enabled": True}) == {"enabled": True}
    for junk in ("on", 1, [], None, 0.5):
        assert _b351_raw_code_mode(junk) is None, junk
    assert _b351_enabled({}) is False
    assert _b351_enabled({"enabled": True}) is True
    assert _b351_enabled({"enabled": "true"}) is False


# --------------------------------------------------------------- UNKNOWN, not a fake PASS
def test_an_unread_config_is_unknown(tmp_path):
    f = check_code_mode_tool_surface(Context(home=tmp_path, config={}, config_found=False))
    assert f.status == UNKNOWN
    assert f.not_applicable is False, "nothing was read — this is a real UNKNOWN"


def test_a_read_but_empty_config_is_not_applicable(tmp_path):
    f = check_code_mode_tool_surface(Context(home=tmp_path, config={}, config_found=True))
    assert f.status == UNKNOWN and f.not_applicable is True


# --------------------------------------------------------------- hostile shapes
def test_malformed_shapes_do_not_raise(tmp_path):
    for cfg in (
        {"tools": "minimal"},
        {"tools": {"codeMode": "on"}},
        {"tools": {"codeMode": []}},
        {"agents": {"list": "not-a-list"}},
        {"agents": {"list": [None, 7, "x"]}},
        {"tools": {"codeMode": True}, "agents": {"list": [{"tools": "no"}]}},
    ):
        f = check_code_mode_tool_surface(_ctx(cfg, tmp_path))
        assert f.status in (PASS, WARN, UNKNOWN), cfg
        assert "\n" not in f.detail


def test_an_agent_with_no_id_is_labelled_by_the_id_it_resolves_to(tmp_path):
    """An entry with no `id` is NOT skipped — `normalizeAgentId(undefined)` returns the
    default agent id, so the vendor reaches it as `main`. Labelling it by list index
    would name something the resolver never produces."""
    cfg = {"agents": {"list": [{"tools": {"codeMode": True}}]}}
    f = check_code_mode_tool_surface(_ctx(cfg, tmp_path))
    assert f.status == WARN
    assert "agents.list[main]" in f.detail


# ------------------------------------------------- agent identity is the vendor's
# Found by an independent adversarial pass: the check looped raw list entries while the
# vendor resolves by NORMALISED id, first match wins. It reported an agent that cannot
# exist. Every expectation below was produced by EXECUTING the installed dist's own
# `normalizeAgentId`, not by reading its regex.

_VENDOR_NORMALIZED = {
    None: "main", "": "main", "   ": "main", "!!!": "main",
    "main": "main", "Main": "main", "  MAIN  ": "main",
    "Legacy": "legacy", "my agent": "my-agent", "-x-": "x", "builder": "builder",
    "a" * 70: "a" * 64,
}


@pytest.mark.parametrize("raw,expected", list(_VENDOR_NORMALIZED.items()))
def test_the_id_port_matches_the_vendor(raw, expected):
    assert _b351_normalize_agent_id(raw) == expected


def test_a_non_string_id_is_treated_as_absent():
    """The schema types `id` as a string, so a number never loads; the vendor would
    throw on `(5).trim()`. Treating it as absent is the non-crashing equivalent."""
    assert _b351_normalize_agent_id(5) == "main"


def test_a_shadowed_duplicate_agent_is_not_reported(tmp_path):
    """THE FALSE POSITIVE. `"Main"` and `"main"` normalise to one id, and
    `resolveAgentEntry` takes the FIRST match — so the second entry is unreachable and
    its codeMode never applies. Verified against the real dist: `listAgentIds` yields
    `["main"]` and resolving `main` gives enabled=false.
    """
    cfg = {"tools": {"codeMode": False},
           "agents": {"list": [{"id": "Main", "name": "Primary"},
                               {"id": "main", "name": "Legacy",
                                "tools": {"codeMode": True}}]}}
    f = check_code_mode_tool_surface(_ctx(cfg, tmp_path))
    assert f.status == PASS, f"shadowed entry must not fire: {f.detail}"


def test_the_first_entry_wins_including_when_it_enables(tmp_path):
    """The positive control for the test above: swap the order and it MUST fire, so the
    de-dup cannot be a blanket silencer."""
    cfg = {"tools": {"codeMode": False},
           "agents": {"list": [{"id": "main", "tools": {"codeMode": True}},
                               {"id": "Main"}]}}
    f = check_code_mode_tool_surface(_ctx(cfg, tmp_path))
    assert f.status == WARN and "agents.list[main]" in f.detail


def test_an_unnamed_entry_collides_with_an_explicit_main(tmp_path):
    """The collision is not hypothetical: no-id normalises to `main`, so an entry with
    no id and one called `main` are the same agent."""
    cfg = {"agents": {"list": [{"id": "main"}, {"tools": {"codeMode": True}}]}}
    assert check_code_mode_tool_surface(_ctx(cfg, tmp_path)).status == PASS
    ids = [aid for aid, _ in _b351_resolvable_agents(cfg["agents"]["list"])]
    assert ids == ["main"], ids


# ------------------------------------------------- the claim is scoped to one engine
def test_the_pass_text_names_the_engine_it_actually_read(tmp_path):
    """A second, unrelated path reaches the same user-visible property:
    `plugins.entries.<name>.config.appServer.codeModeOnly` drives Codex app-server runs
    through a different engine this check does not read. An unqualified "code mode is
    off" would be believed and would be wrong there, so the verdict names QuickJS.
    """
    f = check_code_mode_tool_surface(_ctx({"tools": {"profile": "minimal"}}, tmp_path))
    assert f.status == PASS
    assert "QuickJS code mode is off" in f.detail


# --------------------------------------------------------------- wiring and doctrine
def test_the_check_is_actually_registered():
    assert check_code_mode_tool_surface in CHECKS


def test_it_never_fails():
    for name in ("bad_b351_codemode_true_shorthand", "bad_b351_codemode_agent_only",
                 "bad_b351_codemode_global_on_agent_narrowed"):
        assert _f(name).status != "FAIL", name


def test_catalog_entry_matches_what_the_check_emits():
    meta = BY_ID["B351"]
    assert meta.severity == MEDIUM and meta.surface == "tools"
    emitted = _f("bad_b351_codemode_true_shorthand")
    assert emitted.id == "B351" and emitted.title == meta.title
