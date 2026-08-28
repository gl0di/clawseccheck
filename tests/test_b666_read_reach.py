"""B-666 — clawseccheck/toolpolicy.py must answer the way the real OpenClaw does.

A1's "sensitive data" leg used to be raised by a directory NAME. Replacing that with a
grounded question — "can this agent's file-read tool open a file outside its workspace?" —
is only an improvement if the answer matches the runtime's, so this module is a
differential test against ``resolveEffectiveToolFsRootExpansionAllowed``.

The table below is not hand-authored: every expectation was produced by CALLING that
function in the installed dist (node, ``local-roots-*.js``) on the same config, and the
same comparison was run across all 574 non-empty configs in the local corpus — fixtures
plus the clawrange corpus — in every scope, with zero disagreements. What is shipped here
is the edge set: the cases where a plausible-looking port diverges, each one a mistake
this port made or nearly made.

Two expectations in particular are the whole reason the port exists, and both sit at the
PERMISSIVE end, where getting them backwards inverts a verdict instead of muting one:

  * ``{"tools": {}}`` -> True. An absent ``tools.fs.workspaceOnly`` does NOT confine file
    tools. ``createToolFsPolicy`` is ``{ workspaceOnly: params.workspaceOnly === true }``.
  * ``{"tools": {"profile": "MINIMAL"}}`` -> True. ``CORE_TOOL_PROFILES[profile]`` is an
    exact object index — an unrecognized profile string restricts nothing at all, even
    though the same runtime lowercases and trims TOOL names before matching them.
"""
from __future__ import annotations

import re

import pytest
from _realhome import REAL_HOME

from clawseccheck import toolpolicy
from clawseccheck.checks import _shared

# (label, config, what the installed OpenClaw answered)
CASES = [
    ('tools_null', {'tools': None}, True),
    ('tools_empty', {'tools': {}}, True),
    ('profile_coding', {'tools': {'profile': 'coding'}}, True),
    ('profile_minimal', {'tools': {'profile': 'minimal'}}, False),
    ('profile_messaging', {'tools': {'profile': 'messaging'}}, False),
    ('profile_full', {'tools': {'profile': 'full'}}, True),
    ('profile_upper', {'tools': {'profile': 'MINIMAL'}}, True),
    ('profile_spaced', {'tools': {'profile': ' minimal '}}, True),
    ('profile_bogus', {'tools': {'profile': 'readonly'}}, True),
    ('profile_nonstring', {'tools': {'profile': 5}}, True),
    ('wsonly_true', {'tools': {'fs': {'workspaceOnly': True}}}, False),
    ('wsonly_false', {'tools': {'fs': {'workspaceOnly': False}}}, True),
    ('wsonly_string', {'tools': {'fs': {'workspaceOnly': 'true'}}}, True),
    ('wsonly_null', {'tools': {'fs': {'workspaceOnly': None}}}, True),
    ('fs_empty', {'tools': {'fs': {}}}, True),
    ('allow_empty', {'tools': {'allow': []}}, True),
    ('allow_read', {'tools': {'allow': ['read']}}, True),
    ('allow_READ', {'tools': {'allow': ['READ']}}, True),
    ('allow_read_spaced', {'tools': {'allow': ['  read  ']}}, True),
    ('allow_message', {'tools': {'allow': ['message']}}, False),
    ('allow_star', {'tools': {'allow': ['*']}}, True),
    ('allow_glob', {'tools': {'allow': ['re*']}}, True),
    ('allow_glob_mid', {'tools': {'allow': ['r*d']}}, True),
    ('allow_group_fs', {'tools': {'allow': ['group:fs']}}, True),
    ('allow_group_web', {'tools': {'allow': ['group:web']}}, False),
    ('allow_nonstring', {'tools': {'allow': [5, None, 'read']}}, True),
    ('allow_string_not_list', {'tools': {'allow': 'read'}}, True),
    ('deny_read', {'tools': {'deny': ['read']}}, False),
    ('deny_group_fs', {'tools': {'deny': ['group:fs']}}, False),
    ('deny_star', {'tools': {'deny': ['*']}}, False),
    ('deny_glob', {'tools': {'deny': ['re*']}}, False),
    ('allow_star_deny_read', {'tools': {'allow': ['*'], 'deny': ['read']}}, False),
    ('full_deny_read', {'tools': {'profile': 'full', 'deny': ['read']}}, False),
    ('coding_deny_group_fs', {'tools': {'profile': 'coding', 'deny': ['group:fs']}}, False),
    ('alsoallow_only', {'tools': {'alsoAllow': ['message']}}, True),
    ('alsoallow_only_read', {'tools': {'alsoAllow': ['read']}}, True),
    ('alsoallow_star', {'tools': {'alsoAllow': ['*']}}, True),
    ('allow_plus_also', {'tools': {'allow': ['message'], 'alsoAllow': ['read']}}, True),
    ('allow_empty_plus_also', {'tools': {'allow': [], 'alsoAllow': ['message']}}, True),
    ('minimal_alsoallow_read', {'tools': {'profile': 'minimal', 'alsoAllow': ['read']}}, True),
    ('minimal_alsoallow_empty', {'tools': {'profile': 'minimal', 'alsoAllow': []}}, False),
    ('messaging_alsoallow_groupfs', {'tools': {'profile': 'messaging', 'alsoAllow': ['group:fs']}}, True),
    ('coding_wsonly_true', {'tools': {'profile': 'coding', 'fs': {'workspaceOnly': True}}}, False),
    ('minimal_wsonly_false', {'tools': {'profile': 'minimal', 'fs': {'workspaceOnly': False}}}, False),
    ('allow_bash_alias', {'tools': {'allow': ['bash']}}, False),
    ('allow_applypatch_alias', {'tools': {'allow': ['apply-patch']}}, False),
    ('deny_empty', {'tools': {'deny': []}}, True),
    ('allow_and_deny_empty', {'tools': {'allow': [], 'deny': []}}, True),
]

# B-519: REAL_HOME, not Path.home() — conftest redirects $HOME for the session, so
# Path.home() here would point at a throwaway dir, find no dist, and skip vacuously.
OPENCLAW_DIST = REAL_HOME / ".npm-global" / "lib" / "node_modules" / "openclaw" / "dist"


@pytest.mark.parametrize("label,cfg,expected", CASES, ids=[c[0] for c in CASES])
def test_matches_the_installed_runtime(label, cfg, expected):
    assert toolpolicy.read_reaches_outside_workspace(cfg) is expected


def test_the_table_exercises_both_answers():
    """A table that only ever expects one answer would pass with a constant function."""
    answers = {c[2] for c in CASES}
    assert answers == {True, False}, answers
    assert sum(1 for c in CASES if c[2]) >= 10
    assert sum(1 for c in CASES if not c[2]) >= 10


def test_a_blind_config_is_not_evidence_of_exposure():
    """The one DELIBERATE divergence from the runtime.

    The dist answers True for ``{}`` — nothing said, so nothing restricts. For us ``{}``
    is what an unparseable openclaw.json collapses to (B-166/B-306), and a config we
    never read cannot be evidence about what it grants. ``check_trifecta`` returns UNKNOWN
    on that path long before it asks; this is belt and braces, pinned so a later "make it
    match the dist exactly" cleanup has to read this comment first.
    """
    assert toolpolicy.read_reaches_outside_workspace({}) is False
    assert toolpolicy.read_reaches_outside_workspace(None) is False
    assert toolpolicy.scopes_reaching_outside_workspace({}) == []


def test_agent_scope_is_resolved_separately_from_global():
    """An agent that opts out of a global confinement is its own exposed scope."""
    cfg = {
        "tools": {"allow": ["read"], "fs": {"workspaceOnly": True}},
        "agents": {"list": [{"id": "helper", "tools": {"fs": {"workspaceOnly": False}}}]},
    }
    assert toolpolicy.read_reaches_outside_workspace(cfg) is False
    assert toolpolicy.scopes_reaching_outside_workspace(cfg) == ["agent 'helper'"]


def test_agent_without_an_id_is_the_main_agent_not_a_skipped_entry():
    """``normalizeAgentId(undefined)`` folds to "main", so such an entry is live.

    Found by re-probing the dist: a first pass called it with ``agentId: undefined``,
    which short-circuits before the lookup, and the answer read as "this entry does not
    apply". Called with "main" — the id the runtime actually folds to — the same entry
    resolves and the opt-out takes effect.
    """
    cfg = {
        "tools": {"allow": ["read"], "fs": {"workspaceOnly": True}},
        "agents": {"list": [{"name": "helper", "tools": {"fs": {"workspaceOnly": False}}}]},
    }
    assert toolpolicy.scopes_reaching_outside_workspace(cfg) == ["agent 'main'"]


def test_agent_defaults_block_is_not_a_scope():
    """``resolveAgentConfig`` reads ``entry.tools`` from agents.list and never merges
    ``agents.defaults.tools`` — so a confinement written there does not apply, and
    treating it as one would invent protection the runtime does not give."""
    cfg = {"agents": {"defaults": {"tools": {"fs": {"workspaceOnly": True}}}}}
    assert toolpolicy.read_reaches_outside_workspace(cfg) is True


def test_alias_table_agrees_with_the_checks_leaf():
    """This module keeps its own copy of TOOL_NAME_ALIASES because it is a leaf and may
    not import the check layer (the skillprovenance.py arrangement). A copy is only safe
    with a guard, so this is the guard."""
    assert toolpolicy._TOOL_NAME_ALIASES == _shared._TOOL_NAME_ALIASES


# --------------------------------------------------------------------- dist grounding
# Local-only: these read the installed OpenClaw. They are the layer that catches the
# constants above going stale on an upgrade, which no amount of self-consistent unit
# testing can. Skipped where the dist is absent (CI), never silently weakened.

def _dist_text(pattern: str) -> str:
    files = sorted(OPENCLAW_DIST.glob(pattern))
    if not files:
        pytest.skip(f"installed OpenClaw dist not found ({pattern})")
    return "\n".join(f.read_text(encoding="utf-8", errors="replace") for f in files)


def test_dist_still_defaults_workspace_only_to_false():
    text = _dist_text("local-roots-*.js")
    assert "function createToolFsPolicy" in text, "the resolver was renamed — re-ground it"
    body = text.split("function createToolFsPolicy", 1)[1][:200]
    assert "workspaceOnly: params.workspaceOnly === true" in body, body


def test_dist_profile_enum_matches_the_known_set():
    text = _dist_text("zod-schema.agent-runtime-*.js")
    block = re.search(r"ToolProfileSchema = union\(\[(.*?)\]\)", text, re.S)
    assert block, "ToolProfileSchema not found — re-ground _KNOWN_PROFILES"
    found = set(re.findall(r'literal\("([a-z]+)"\)', block.group(1)))
    assert found == set(toolpolicy._KNOWN_PROFILES), found


def test_dist_still_grants_read_to_exactly_the_profiles_we_name():
    """`read` is a `coding` tool, and `full` is ``allow: ["*"]``. Any other profile
    gaining it would silently widen this predicate."""
    text = _dist_text("tool-catalog-*.js")
    entry = re.search(r'id: "read",(.*?)profiles: \[([^\]]*)\]', text, re.S)
    assert entry, "the read tool entry moved — re-ground _PROFILES_GRANTING_READ"
    named = set(re.findall(r'"([a-z]+)"', entry.group(2)))
    wildcard = re.search(r'full: \{ allow: \["\*"\] \}', text)
    assert wildcard, 'the "full" profile is no longer allow-all — re-ground'
    assert named | {"full"} == set(toolpolicy._PROFILES_GRANTING_READ), named
