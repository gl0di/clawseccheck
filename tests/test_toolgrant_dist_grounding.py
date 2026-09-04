"""``clawseccheck/toolgrant.py`` grounded against the installed OpenClaw dist directly —
never against a sibling copy in this repo.

The brief this module answers named the exact failure mode to avoid: a guard that
compares ``toolpolicy.py``'s alias table against ``checks/_shared.py``'s alias table (or
vice versa) stays green when BOTH copies are equally wrong, because a peer is not a
producer. ``checks/_shared.py::_TOOL_NAME_ALIASES`` and ``toolpolicy.py``'s own copy both
carry only ``{"bash": "exec", "apply-patch": "apply_patch"}`` — missing the real dist's
third entry, ``"cron": "automations"``. Every test below reads the INSTALLED DIST, not
either of those files.

Local-only: skipped wherever the installed OpenClaw dist is absent (CI, a machine without
it) — never silently weakened into a false pass. Ground truth is **openclaw@2026.9.1** at
the time of writing; a filename cited here rotates on upgrade (content-hashed bundles), so
re-locate a moved symbol with ``grep -rl '<symbolName>' dist/*.js``, not by trusting the
literal glob below to still resolve.

B-728: the locator is ``tests/_distgrounding.py``, shared, and it distinguishes "OpenClaw
is not installed" (skip) from "installed, and this anchor no longer matches" (fail, naming
the symbol). Each citation below therefore passes ``contains=`` — a constant the right
bundle DECLARES — so the anchor is the symbol and the filename is only a prefilter. That
is not cosmetic: ``tool-policy-match-*.js`` matches two bundles on 2026.9.1 and
``agent-id-*.js`` four, exactly one of each declaring the symbol asserted here.
"""
from __future__ import annotations

import re

import pytest
from _distgrounding import dist_text

from clawseccheck import toolgrant


# --------------------------------------------------------------------- alias table (3, not 2)

def test_dist_tool_name_aliases_has_three_entries_including_cron():
    text = dist_text("tool-policy-shared-*.js", symbol="TOOL_NAME_ALIASES",
                     contains="TOOL_NAME_ALIASES")
    match = re.search(r"const TOOL_NAME_ALIASES = \{([^}]*)\}", text)
    assert match, "TOOL_NAME_ALIASES literal not found — re-ground toolgrant._TOOL_NAME_ALIASES"
    entries = {}
    for raw in match.group(1).split(","):
        raw = raw.strip()
        if not raw:
            continue
        key, _, value = raw.partition(":")
        key = key.strip().strip('"')
        value = value.strip().strip('"')
        if key and value:
            entries[key] = value
    assert entries == {"bash": "exec", "apply-patch": "apply_patch", "cron": "automations"}, entries
    assert toolgrant._TOOL_NAME_ALIASES == entries


def test_our_alias_table_disagrees_with_the_two_narrower_sibling_copies():
    """Not a bug in the siblings (each is scoped to what its own predicate needs) — pinned
    so nobody "fixes" this module by copying either narrower table back in."""
    from clawseccheck import toolpolicy
    from clawseccheck.checks import _shared

    assert toolpolicy._TOOL_NAME_ALIASES == {"bash": "exec", "apply-patch": "apply_patch"}
    assert _shared._TOOL_NAME_ALIASES == {"bash": "exec", "apply-patch": "apply_patch"}
    assert toolgrant._TOOL_NAME_ALIASES == {
        "bash": "exec", "apply-patch": "apply_patch", "cron": "automations",
    }


def test_cron_alias_resolves_the_same_as_automations():
    cfg = {"tools": {"allow": ["cron"]}}
    assert toolgrant.granted(cfg, "automations") is True
    assert toolgrant.granted(cfg, "cron") is True
    assert toolgrant.granted(cfg, "exec") is False


# --------------------------------------------------------------------- profile / group tables

def test_dist_profile_enum_matches_the_known_set():
    text = dist_text("zod-schema.agent-runtime-*.js", symbol="ToolProfileSchema",
                     contains="ToolProfileSchema")
    block = re.search(r"ToolProfileSchema = union\(\[(.*?)\]\)", text, re.S)
    assert block, "ToolProfileSchema not found — re-ground _CORE_TOOL_PROFILES's key set"
    found = set(re.findall(r'literal\("([a-z]+)"\)', block.group(1)))
    assert found == set(toolgrant._CORE_TOOL_PROFILES)


def test_dist_read_and_write_are_coding_only_and_full_is_wildcard():
    text = dist_text("tool-catalog-*.js", symbol="CORE_TOOL_DEFINITIONS",
                     contains="CORE_TOOL_DEFINITIONS")
    for tool_id in ("read", "write", "edit", "apply_patch", "exec"):
        entry = re.search(r'id: "%s",(.*?)profiles: \[([^\]]*)\]' % tool_id, text, re.S)
        assert entry, f"the {tool_id!r} tool entry moved — re-ground CORE_TOOL_PROFILES"
        named = set(re.findall(r'"([a-z]+)"', entry.group(2)))
        assert named == {"coding"}, (tool_id, named)
    automations_entry = re.search(r"profiles: \[\"coding\"\]", text)
    assert automations_entry, "no coding-only profile entries found at all — pattern rotted"
    wildcard = re.search(r'full:\s*\{\s*allow:\s*\["\*"\]\s*\}', text)
    assert wildcard, 'the "full" profile is no longer allow-all — re-ground'


def test_dist_group_fs_members_match_ours():
    text = dist_text("tool-catalog-*.js", symbol="CORE_TOOL_DEFINITIONS",
                     contains="CORE_TOOL_DEFINITIONS")
    for tool_id in ("read", "write", "edit", "apply_patch"):
        assert re.search(r'id: "%s",\s*\n\s*description: [^\n]*,\s*\n\s*sectionId: "fs"' % tool_id, text), (
            f"{tool_id} no longer sits in sectionId \"fs\" — re-ground group:fs"
        )
    assert toolgrant._CORE_TOOL_GROUPS["group:fs"] == ["read", "write", "edit", "apply_patch"]


# --------------------------------------------------------------------- write => apply_patch

def test_dist_still_lets_write_allow_apply_patch():
    text = dist_text("tool-policy-match-*.js", symbol="writeAllowsApplyPatch",
                     contains="writeAllowsApplyPatch")
    assert "writeAllowsApplyPatch" in text, "the implication flag moved — re-ground granted()"
    assert 'normalized === "apply_patch"' in text and 'matchesAnyGlobPattern("write", allow)' in text


def test_write_only_allowlist_grants_apply_patch_but_not_edit():
    cfg = {"tools": {"allow": ["write"]}}
    assert toolgrant.granted(cfg, "apply_patch") is True
    assert toolgrant.granted(cfg, "edit") is False
    assert toolgrant.granted(cfg, "write") is True


# ------------------------------------------------------------------- agents.defaults.tools

def test_dist_agent_tools_falls_back_to_agents_defaults_only_without_a_roster():
    text = dist_text("agent-tools.policy-*.js", symbol="implicitDefaultTools",
                     contains="implicitDefaultTools")
    assert "implicitDefaultTools" in text
    assert "hasAgentRosterProperty" in text


def test_agents_defaults_tools_is_a_real_scope_with_no_roster():
    """toolpolicy.py:47-49 calls agents.defaults.tools "deliberately NOT a scope" -- true
    for THAT module's read-confinement predicate (resolveAgentConfig never merges it), but
    wrong as a general claim: resolveEffectiveToolPolicy's own agentTools derivation reads
    it as a FALLBACK precisely when there is no roster to read instead."""
    cfg = {"agents": {"defaults": {"tools": {"allow": ["write"]}}}}
    assert "entries" not in cfg["agents"] and "list" not in cfg["agents"]
    assert toolgrant.granted(cfg, "write", toolgrant.GLOBAL_SCOPE) is True
    assert toolgrant.granted(cfg, "write", "main") is True
    assert toolgrant.granted(cfg, "write", "anything-at-all") is True
    assert toolgrant.granted(cfg, "read") is False


def test_agents_defaults_tools_is_ignored_once_a_roster_exists():
    cfg = {
        "agents": {
            "defaults": {"tools": {"allow": ["write"]}},
            "entries": {"main": {}},
        },
    }
    # the roster now governs; agents.defaults.tools is never consulted, so with no other
    # tools declared anywhere the permissive default applies (nothing restricts anything).
    assert toolgrant.granted(cfg, "read", "main") is True
    assert toolgrant.granted(cfg, "read", toolgrant.GLOBAL_SCOPE) is True


# --------------------------------------------------------------------- agent-id normalization

_AGENT_ID_CASES = [
    ("main", "main"),
    ("Main", "main"),
    ("MAIN ", "main"),
    ("a-", "a-"),
    ("a_", "a_"),
    ("-a", "a"),
    ("a b", "a-b"),
    ("", "main"),
    (" ", "main"),
    (None, "main"),
    ("a" * 70, "a" * 64),
    ("a@b", "a-b"),
    ("A-B_c9", "a-b_c9"),
    ("9start", "9start"),
    ("_x", "_x"),
    ("---", "main"),
]


@pytest.mark.parametrize("raw,expected", _AGENT_ID_CASES, ids=[repr(c[0]) for c in _AGENT_ID_CASES])
def test_normalize_agent_id_matches_our_own_port(raw, expected):
    """Pinned against the dist-measured table (agent-id-*.js, normalizeAgentId) captured
    once by executing the real function -- see the module docstring's citation. "a-" is
    the case that distinguishes the real two-branch resolver from a naive
    fold-then-strip-dashes port: an ALREADY-VALID id is lowercased and returned as-is,
    trailing dash included, while an invalid one goes through the fold/strip/truncate path."""
    assert toolgrant._normalize_agent_id(raw) == expected


def test_dist_normalize_agent_id_two_branch_shape_is_still_current():
    text = dist_text("agent-id-*.js", symbol="normalizeAgentIdStrict",
                     contains="normalizeAgentIdStrict")
    assert "VALID_ID_RE" in text and "normalizeAgentIdStrict" in text, (
        "normalizeAgentId's shape moved -- re-run the differential capture and re-pin "
        "_AGENT_ID_CASES above"
    )
