"""CLAWSECCHECK-C-683: openclaw@2026.10.1 added two catalog tools, ``skills_search`` and
``skills_read`` (tool-catalog: sectionId ``agents``, profiles ``["coding"]``,
``includeInOpenClawGroup: true``), and one matcher rule in ``createToolPolicyMatcher``
(the tool-policy-match bundle)::

    if (normalized === "skills_read" && matchesAnyGlobPattern("read", allow)
            && !matchesAnyGlobPattern("read", deny)) return true;

``skills_read`` is therefore granted by any policy whose allow list names ``read`` (directly,
through ``group:fs`` or a glob) unless ``read`` is denied - the same shape as the existing
``write`` => ``apply_patch`` rule, except that it also reads the DENY list. An explicit
``skills_read`` entry still wins through the ordinary match, even beside ``deny: [read]``.

``toolgrant.py`` carries no build window: its tables track the newest grounded build
(``tests/test_toolgrant_dist_grounding.py`` compares them whole against the installed dist),
so a config evaluated for an older install answers with the current tables. Only the two new
names are affected, and nothing in ``clawseccheck/`` asks about them by name.

The first block pins the semantics offline. The last test is the differential against the
installed dist (local-only, skipped where node or the dist is absent, same as the sibling
dist-grounding module).
"""
from __future__ import annotations

import shutil

import pytest
from _distgrounding import require_dist

import _toolgrantoracle as oracle
from clawseccheck import toolgrant
from clawseccheck.toolgrant import GLOBAL_SCOPE, granted

NEW_TOOLS = ("skills_search", "skills_read")


def _g(tools: dict, tool: str, scope=GLOBAL_SCOPE) -> bool:
    return granted({"tools": tools}, tool, scope)


# --------------------------------------------------------------------- the tables

def test_the_two_new_tools_sit_after_skill_workshop_in_every_table_that_carries_it():
    for table in (
        toolgrant._CORE_TOOL_GROUPS["group:openclaw"],
        toolgrant._CORE_TOOL_GROUPS["group:agents"],
        toolgrant._CORE_TOOL_PROFILES["coding"],
    ):
        i = table.index("skill_workshop")
        assert table[i:i + 3] == ["skill_workshop", "skills_search", "skills_read"], table


def test_only_the_coding_profile_and_the_agents_groups_carry_them():
    for name, members in toolgrant._CORE_TOOL_PROFILES.items():
        if name == "full":  # allow-all, by "*" rather than by name
            continue
        assert [t in members for t in NEW_TOOLS] == ([True, True] if name == "coding" else [False, False]), name
    carriers = sorted(g for g, members in toolgrant._CORE_TOOL_GROUPS.items()
                      if any(t in members for t in NEW_TOOLS))
    assert carriers == ["group:agents", "group:openclaw"]


@pytest.mark.parametrize("tool", NEW_TOOLS)
def test_profiles_and_groups_grant_the_new_tools(tool):
    assert _g({"profile": "coding"}, tool) is True
    assert _g({"profile": "full"}, tool) is True
    assert _g({"profile": "messaging"}, tool) is False
    assert _g({"profile": "minimal"}, tool) is False
    assert _g({"allow": ["group:agents"]}, tool) is True
    assert _g({"allow": ["group:openclaw"]}, tool) is True
    assert _g({"allow": ["group:web"]}, tool) is False
    # a group-level deny removes them, and so does a plain name deny
    assert _g({"profile": "coding", "deny": ["group:agents"]}, tool) is False
    assert _g({"profile": "coding", "deny": [tool]}, tool) is False


# --------------------------------------------------------------------- read => skills_read

@pytest.mark.parametrize("allow", [
    ["read"], ["group:fs"], ["re*"], [" READ "], ["write", "read"], ["Group:FS"],
])
def test_an_allow_that_names_read_grants_skills_read(allow):
    assert _g({"allow": allow}, "read") is True
    assert _g({"allow": allow}, "skills_read") is True


@pytest.mark.parametrize("allow", [
    ["write"], ["edit", "apply_patch", "ls"], ["exec"], ["group:runtime"], ["group:web"],
])
def test_an_allow_without_read_does_not_grant_skills_read(allow):
    assert _g({"allow": allow}, "skills_read") is False


def test_the_implication_is_one_way_and_does_not_reach_skills_search():
    assert _g({"allow": ["read"]}, "skills_search") is False
    assert _g({"allow": ["skills_read"]}, "read") is False
    assert _g({"allow": ["skills_search"]}, "skills_read") is False


def test_a_denied_read_withholds_the_implied_grant():
    # allow names read, but read is denied: neither read nor skills_read is granted
    assert _g({"allow": ["read"], "deny": ["read"]}, "read") is False
    assert _g({"allow": ["read"], "deny": ["read"]}, "skills_read") is False
    assert _g({"allow": ["read"], "deny": ["group:fs"]}, "skills_read") is False
    assert _g({"allow": ["read"], "deny": ["re*"]}, "skills_read") is False
    # denying the new tool itself wins over the implication
    assert _g({"allow": ["read"], "deny": ["skills_read"]}, "skills_read") is False
    # ... while an unrelated deny leaves it granted
    assert _g({"allow": ["read"], "deny": ["write"]}, "skills_read") is True


def test_an_explicit_skills_read_entry_is_granted_even_beside_a_read_deny():
    """The implication is the SECOND route; the ordinary allow match runs first and only the
    deny list's own match on ``skills_read`` can stop it (so ``deny: [read]`` does not)."""
    assert _g({"allow": ["skills_read"], "deny": ["read"]}, "skills_read") is True
    assert _g({"allow": ["skills_read", "read"], "deny": ["read"]}, "skills_read") is True
    assert _g({"allow": ["skills_read"], "deny": ["group:fs"]}, "skills_read") is True


def test_the_implication_is_evaluated_per_policy_inside_the_and():
    """Global allow [write] is its own AND-ed layer: an agent whose own allow names read
    still loses skills_read at that agent, exactly as read itself is lost."""
    cfg = {"tools": {"allow": ["write"]},
           "agents": {"list": [{"id": "a", "tools": {"allow": ["read"]}}]}}
    assert granted(cfg, "read", "a") is False
    assert granted(cfg, "skills_read", "a") is False
    cfg = {"tools": {"allow": ["read", "write"]},
           "agents": {"list": [{"id": "a", "tools": {"allow": ["read"]}},
                               {"id": "b", "tools": {"allow": ["write"]}}]}}
    assert granted(cfg, "skills_read", "a") is True
    assert granted(cfg, "skills_read", "b") is False
    assert granted(cfg, "skills_read", GLOBAL_SCOPE) is True


def test_also_allow_read_on_a_narrow_profile_grants_skills_read():
    assert _g({"profile": "minimal", "alsoAllow": ["read"]}, "skills_read") is True
    assert _g({"profile": "minimal"}, "skills_read") is False
    # deny is read per policy layer: the profile layer (allow = profile + alsoAllow, no deny)
    # still grants skills_read, and the raw layer's deny names read, not skills_read - so a
    # read deny alone does not withhold it here (the vendor, executed below, agrees).
    cfg = {"profile": "minimal", "alsoAllow": ["read"], "deny": ["read"]}
    assert _g(cfg, "read") is False
    assert _g(cfg, "skills_read") is True
    assert _g({**cfg, "deny": ["read", "skills_read"]}, "skills_read") is False


def test_the_alias_and_case_folding_of_the_tool_name_is_unchanged():
    assert _g({"allow": ["read"]}, " Skills_Read ") is True
    assert _g({"allow": ["write"]}, "SKILLS_READ") is False


def test_a_blind_config_still_grants_nothing():
    assert granted({}, "skills_read") is False
    assert granted({}, "skills_read", "a") is False


# --------------------------------------------------------------------- the vendor, executed

_DIFF_CONFIGS = [
    ("c683/allow-read", {"tools": {"allow": ["read"]}}),
    ("c683/allow-group-fs", {"tools": {"allow": ["group:fs"]}}),
    ("c683/allow-glob", {"tools": {"allow": ["re*"]}}),
    ("c683/allow-write", {"tools": {"allow": ["write"]}}),
    ("c683/allow-read-deny-read", {"tools": {"allow": ["read"], "deny": ["read"]}}),
    ("c683/allow-read-deny-fs", {"tools": {"allow": ["read"], "deny": ["group:fs"]}}),
    ("c683/allow-read-deny-skills", {"tools": {"allow": ["read"], "deny": ["skills_read"]}}),
    ("c683/allow-skills-deny-read", {"tools": {"allow": ["skills_read"], "deny": ["read"]}}),
    ("c683/allow-skills-search", {"tools": {"allow": ["skills_search"]}}),
    ("c683/minimal+read", {"tools": {"profile": "minimal", "alsoAllow": ["read"]}}),
    ("c683/minimal+read-deny-read", {"tools": {"profile": "minimal", "alsoAllow": ["read"],
                                              "deny": ["read"]}}),
    ("c683/minimal+read-deny-both", {"tools": {"profile": "minimal", "alsoAllow": ["read"],
                                              "deny": ["read", "skills_read"]}}),
    ("c683/coding", {"tools": {"profile": "coding"}}),
    ("c683/coding-deny-read", {"tools": {"profile": "coding", "deny": ["read"]}}),
    ("c683/messaging", {"tools": {"profile": "messaging"}}),
    ("c683/group-agents", {"tools": {"allow": ["group:agents"]}}),
    ("c683/global-write-agent-read", {
        "tools": {"allow": ["write"]},
        "agents": {"list": [{"id": "a", "tools": {"allow": ["read"]}}]}}),
    ("c683/global-read-agent-write", {
        "tools": {"allow": ["read"]},
        "agents": {"list": [{"id": "a", "tools": {"allow": ["write"]}}]}}),
]


def test_granted_matches_the_installed_vendor_on_the_skills_cells():
    require_dist()
    if not shutil.which("node"):
        pytest.skip("node is not installed - the differential executes the vendor")
    tools = ["read", "skills_read", "skills_search"]
    rows = oracle.vendor_grants(_DIFF_CONFIGS, tools=tools)
    configs = dict(_DIFF_CONFIGS)
    wrong, seen = [], {t: set() for t in tools}
    for row in rows:
        for tool, per_scope in row["results"].items():
            for scope, expected in per_scope.items():
                seen[tool].add(expected)
                key = GLOBAL_SCOPE if scope == "global" else scope
                if granted(configs[row["label"]], tool, key) is not expected:
                    wrong.append((row["label"], scope, tool, expected))
    assert not wrong, wrong
    # non-vacuity: the cells reach both answers for both new tools
    assert seen["skills_read"] == {True, False} and seen["skills_search"] == {True, False}
