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

import clawseccheck.toolpolicy as _toolpolicy
from _distgrounding import dist_text, require_dist

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

# B-519 (why REAL_HOME, not Path.home()) and B-728 (why zero matches is a FAIL, not a
# skip) both live in tests/_distgrounding.py — one locator, three outcomes.


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

def test_dist_still_defaults_workspace_only_to_false():
    """The tripwire for the one semantic `toolpolicy.py` is built on: an ABSENT
    `tools.fs.workspaceOnly` means NOT confined.

    C-472 RE-ANCHORED this. It used to grep `local-roots-*.js` for
    `function createToolFsPolicy`, and OpenClaw 2026.8.1 deleted that helper from the
    entire dist — so the test failed on a NAME while the semantic it guards was untouched.
    The lesson is in the assertion order below: a name is exactly what an upgrade moves, so
    the BEHAVIOUR is asserted first and independently, and the source anchor second.

    The `=== true` now lives one function further along, in `tool-fs-policy-*.js`:

        function resolveToolFsConfig(params) {
            const globalFs = cfg?.tools?.fs;
            return { workspaceOnly: (agent fs)?.workspaceOnly ?? globalFs?.workspaceOnly };
        }
        function resolveEffectiveToolFsWorkspaceOnly(params) {
            return resolveToolFsConfig(params).workspaceOnly === true;
        }
    """
    # 1. The BEHAVIOUR we depend on, asserted against our own port. This survives any
    #    rename in the dist, and it is the thing that would actually hurt if it flipped:
    #    both layers default to the permissive end, so a wrong answer here INVERTS a
    #    verdict rather than muting it.
    assert _toolpolicy.workspace_only({}) is False
    assert _toolpolicy.workspace_only({"tools": {"fs": {}}}) is False
    assert _toolpolicy.workspace_only({"tools": {"fs": {"workspaceOnly": True}}}) is True
    assert _toolpolicy.workspace_only({"tools": {"fs": {"workspaceOnly": "yes"}}}) is False

    # 2. The source anchor, on the function that owns the comparison today.
    text = dist_text("tool-fs-policy-*.js", symbol="resolveEffectiveToolFsWorkspaceOnly",
                     contains="resolveEffectiveToolFsWorkspaceOnly")
    assert "function resolveEffectiveToolFsWorkspaceOnly" in text, (
        "the resolver moved again — re-ground it, and check whether the `=== true` "
        "semantic moved with it"
    )
    body = text.split("function resolveEffectiveToolFsWorkspaceOnly", 1)[1][:200]
    assert "workspaceOnly === true" in body, body


def test_dist_profile_enum_matches_the_known_set():
    text = dist_text("zod-schema.agent-runtime-*.js", symbol="ToolProfileSchema",
                     contains="ToolProfileSchema")
    block = re.search(r"ToolProfileSchema = union\(\[(.*?)\]\)", text, re.S)
    assert block, "ToolProfileSchema not found — re-ground _KNOWN_PROFILES"
    found = set(re.findall(r'literal\("([a-z]+)"\)', block.group(1)))
    assert found == set(toolpolicy._KNOWN_PROFILES), found


def test_dist_still_grants_read_to_exactly_the_profiles_we_name():
    """`read` is a `coding` tool, and `full` is ``allow: ["*"]``. Any other profile
    gaining it would silently widen this predicate."""
    text = dist_text("tool-catalog-*.js", symbol="CORE_TOOL_DEFINITIONS",
                     contains="CORE_TOOL_DEFINITIONS")
    entry = re.search(r'id: "read",(.*?)profiles: \[([^\]]*)\]', text, re.S)
    assert entry, "the read tool entry moved — re-ground _PROFILES_GRANTING_READ"
    named = set(re.findall(r'"([a-z]+)"', entry.group(2)))
    wildcard = re.search(r'full: \{ allow: \["\*"\] \}', text)
    assert wildcard, 'the "full" profile is no longer allow-all — re-ground'
    assert named | {"full"} == set(toolpolicy._PROFILES_GRANTING_READ), named


def test_module_docstring_dist_citation_still_declares_the_predicate():
    """C-477: the module docstring names the dist bundle
    ``resolveEffectiveToolFsRootExpansionAllowed`` lives in. It used to pin a hash
    (``local-roots-CAoJyC6u.js``) that both rotated on upgrade AND was the wrong file
    even when current -- that bundle only IMPORTS the predicate; it is DECLARED in
    ``tool-fs-policy-*.js``, beside ``resolveEffectiveToolFsWorkspaceOnly``. Re-derive
    the citation from the docstring text itself, so a future re-pin that goes stale (or
    wrong again) fails here instead of reading as grounded while being dead.
    """
    dist = require_dist()
    doc = toolpolicy.__doc__ or ""
    match = re.search(
        r"``resolveEffectiveToolFsRootExpansionAllowed``[^(]*\(dist ``([^`]+)``",
        doc,
    )
    assert match, "docstring no longer cites a dist location for the predicate"
    pattern = match.group(1)
    files = sorted(dist.glob(pattern))
    assert files, f"citation {pattern!r} does not resolve against the installed dist"
    text = "\n".join(f.read_text(encoding="utf-8", errors="replace") for f in files)
    assert "function resolveEffectiveToolFsRootExpansionAllowed" in text, (
        f"docstring cites {pattern!r} but the predicate is not declared there — "
        "re-ground the citation"
    )
