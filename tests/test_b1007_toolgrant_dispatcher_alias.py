"""openclaw@2026.10.10 renamed the Tool Search call-through tool ``tool_call`` to
``dispatch_action`` and kept the old name working two ways: a ``TOOL_NAME_ALIASES`` entry
(``tool_call -> dispatch_action``) and a matcher rule (``legacyDispatcher`` in
``createToolPolicyMatcher``) that also tests the literal ``"tool_call"`` against allow/deny
patterns when the asked tool is ``dispatch_action``. Both are absent before 2026.10.10, where
``tool_call`` is an ordinary tool id. ``toolgrant.granted()`` models both, gated on
``version``. The 2026.10.10 answers below are the vendor's own, executed through
``tests/_toolgrantoracle.py`` and pinned as the ``synthetic/name/*`` battery rows; this file
states them offline so CI (no dist) holds the rule too.
"""
from __future__ import annotations

import pytest

from clawseccheck import toolgrant

V10_9 = (2026, 10, 9)
V10_10 = (2026, 10, 10)
NEWEST = None


# ------------------------------------------------------------------ the alias (bad -> fires)

@pytest.mark.parametrize("version", [V10_10, (2026, 10, 10, 1), (2026, 11, 0), NEWEST])
@pytest.mark.parametrize("tool", ["dispatch_action", "tool_call", " TOOL_CALL "])
def test_allow_tool_call_grants_the_dispatcher_on_10_10(version, tool):
    assert toolgrant.granted({"tools": {"allow": ["tool_call"]}}, tool, version=version) is True


@pytest.mark.parametrize("version", [V10_10, NEWEST])
@pytest.mark.parametrize("tool", ["dispatch_action", "tool_call"])
def test_deny_either_spelling_denies_the_dispatcher_on_10_10(version, tool):
    for entry in ("tool_call", "dispatch_action", "TOOL_CALL"):
        cfg = {"tools": {"profile": "full", "deny": [entry]}}
        assert toolgrant.granted(cfg, tool, version=version) is False, entry


# ------------------------------------------------------- legacyDispatcher (glob on old name)

@pytest.mark.parametrize("pattern", ["tool_*", "*_call", "tool_c*l"])
def test_a_glob_for_the_old_name_reaches_the_renamed_tool_on_10_10(pattern):
    """The alias folds an ENTRY that equals "tool_call"; a glob is not that key, so only the
    matcher's legacyDispatcher rule explains these (executed on 2026.10.10)."""
    assert toolgrant.granted({"tools": {"allow": [pattern]}}, "dispatch_action") is True
    assert toolgrant.granted({"tools": {"profile": "full", "deny": [pattern]}},
                             "dispatch_action") is False


def test_legacy_rule_does_not_leak_to_other_tools():
    """Clean side: the rule is keyed on dispatch_action alone."""
    assert toolgrant.granted({"tools": {"allow": ["tool_*"]}}, "read") is False
    assert toolgrant.granted({"tools": {"profile": "full", "deny": ["tool_*"]}}, "read") is True
    assert toolgrant.granted({"tools": {"allow": ["dispatch_*"]}}, "read") is False


def test_both_spellings_across_allow_and_deny_deny_wins_on_10_10():
    cfg_a = {"tools": {"allow": ["tool_call"], "deny": ["dispatch_action"]}}
    cfg_b = {"tools": {"allow": ["dispatch_action"], "deny": ["tool_call"]}}
    for cfg in (cfg_a, cfg_b):
        assert toolgrant.granted(cfg, "dispatch_action") is False
        assert toolgrant.granted(cfg, "tool_call") is False


# ------------------------------------------------------------- before 10.10: neither rule

def test_on_10_9_tool_call_is_an_ordinary_tool_id():
    assert toolgrant._normalize_tool_name("tool_call", V10_9) == "tool_call"
    assert toolgrant._normalize_tool_name("tool_call", V10_10) == "dispatch_action"
    assert toolgrant._normalize_tool_name("tool_call") == "dispatch_action"
    # The other three aliases are not gated.
    for alias, target in (("bash", "exec"), ("apply-patch", "apply_patch"), ("cron", "automations")):
        assert toolgrant._normalize_tool_name(alias, V10_9) == target


def test_on_10_9_the_two_spellings_are_unrelated():
    cfg_a = {"tools": {"allow": ["tool_call"], "deny": ["dispatch_action"]}}
    assert toolgrant.granted(cfg_a, "tool_call", version=V10_9) is True
    assert toolgrant.granted(cfg_a, "dispatch_action", version=V10_9) is False
    cfg_b = {"tools": {"allow": ["dispatch_action"], "deny": ["tool_call"]}}
    assert toolgrant.granted(cfg_b, "tool_call", version=V10_9) is False
    assert toolgrant.granted(cfg_b, "dispatch_action", version=V10_9) is True


def test_on_10_9_a_glob_for_the_old_name_does_not_reach_dispatch_action():
    assert toolgrant.granted({"tools": {"allow": ["tool_*"]}}, "dispatch_action", version=V10_9) is False
    assert toolgrant.granted({"tools": {"allow": ["tool_*"]}}, "tool_call", version=V10_9) is True


# ------------------------------------------------- unknown build: newest grounded semantics

@pytest.mark.parametrize("version", [None, (), (2026,), "2026.10.9", [2026, 10, 9],
                                     (2026, "10", 9), (2026, 10, None), (True, 10, 9)])
def test_an_unknown_or_malformed_build_answers_with_the_newest_rules(version):
    """Same default as retiredformats.find_retired: an unreadable build is judged as the
    newest grounded one, never as an older build picked at random."""
    assert toolgrant._dispatcher_rules_apply(version) is True
    assert toolgrant.granted({"tools": {"allow": ["tool_*"]}}, "dispatch_action", version=version) is True


def test_the_gate_is_the_first_build_that_ships_the_rename():
    assert toolgrant._TOOL_CALL_ALIAS_SINCE == V10_10
    assert toolgrant._dispatcher_rules_apply(V10_9) is False
    assert toolgrant._dispatcher_rules_apply((2026, 9, 30)) is False
    assert toolgrant._dispatcher_rules_apply(V10_10) is True
