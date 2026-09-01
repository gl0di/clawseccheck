"""B-667 — A1's "sensitive data" leg must know OpenClaw's own tool ids.

`SENSITIVE_TOOL_HINTS` is a generic keyword vocabulary matched as a SUBSTRING of the
joined tool names. OpenClaw's real fs tool ids are `read`/`write`/`edit`/`apply_patch`
(dist `tool-catalog-*.js`), and `"fs_read" in "read"` is False — so a config that wrote
`tools.allow: ["read"]` granted a file-read tool by name and the leg stayed off. Five
configs in the local corpus do exactly that.

The fix is an EXACT-id set, not a wider hint tuple: adding "read" to a substring list
would convict a tool named `thread` or `spreadsheet`. Both halves are pinned below —
the id is seen, and the near-misses are not.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from _realhome import REAL_HOME

from clawseccheck.checks import _shared
from clawseccheck.checks._shared import (
    SENSITIVE_TOOL_IDS,
    _trifecta_leg_sources,
    _trifecta_legs,
)
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
OPENCLAW_DIST = REAL_HOME / ".npm-global" / "lib" / "node_modules" / "openclaw" / "dist"


def _sensitive(cfg, attestation=None):
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = cfg
    if attestation is not None:
        ctx.attestation = attestation
    return _trifecta_leg_sources(ctx)["sensitive data"]


# ------------------------------------------------------------------ the reported defect

def test_an_allowlisted_read_tool_raises_the_leg():
    assert _sensitive({"tools": {"allow": ["read"]}}) == ["tools.allow entry 'read'"]


def test_the_real_fixture_that_exposed_it_now_reports_the_leg():
    from clawseccheck.collector import collect

    ctx = collect(str(FIXTURES / "bad_b283_fs_unconfined_absent"))
    assert _trifecta_legs(ctx)["sensitive data"] is True


@pytest.mark.parametrize("name", ["memory_get", "memory_search"])
def test_the_other_content_returning_tools_raise_it_too(name):
    assert _sensitive({"tools": {"allow": [name]}}) == [f"tools.allow entry {name!r}"]


# --------------------------------------------------------- the trap a hint list falls in

@pytest.mark.parametrize(
    "name",
    ["thread", "spreadsheet", "unread_messages", "copywriter", "credit", "editorial",
     "already", "readme_writer", "bread"],
)
def test_a_name_merely_containing_an_id_is_not_a_match(name):
    """Exactly why the fix is not `SENSITIVE_TOOL_HINTS + ("read", "write", "edit")`."""
    assert _sensitive({"tools": {"allow": [name]}}) == []


def test_the_excluded_ids_stay_excluded():
    """Mutation tools do not hand existing content back to the model — to edit or patch,
    the model must already hold it. `sessions_history` is "Read *sanitized* session
    history". Each exclusion is a decision, so each is pinned."""
    for name in ("write", "edit", "apply_patch", "sessions_history", "sessions_list"):
        assert _sensitive({"tools": {"allow": [name]}}) == [], name


# ------------------------------------------------------------------------ the fold

def test_the_comparison_uses_openclaws_own_normalization():
    for written in ("Read", "READ", "  read  "):
        assert _sensitive({"tools": {"allow": [written]}}), written


def test_a_namespaced_config_entry_is_not_the_core_tool():
    """OpenClaw's allowlist matcher does not strip namespaces either, so
    `mcp__srv__read` names that server's tool. MCP sensitivity is B229's."""
    assert _sensitive({"tools": {"allow": ["mcp__srv__read"]}}) == []


def test_non_string_entries_are_dropped_not_coerced():
    assert _sensitive({"tools": {"allow": [5, None, {"read": True}]}}) == []


# ------------------------------------------------------------------- the grant fields

def test_also_allow_is_a_grant_field_too():
    assert _sensitive({"tools": {"alsoAllow": ["read"]}}) == ["tools.alsoAllow entry 'read'"]


def test_gateway_tools_allow_is_the_fallback_pair():
    assert _sensitive({"gateway": {"tools": {"allow": ["read"]}}}) == [
        "gateway.tools.allow entry 'read'"
    ]


def test_deny_wins_over_allow():
    """`makeToolPolicyMatcher` tests deny first and returns false on a hit, so a tool in
    both lists is not granted. Found by the C-135 pass on this change."""
    assert _sensitive({"tools": {"allow": ["read"], "deny": ["read"]}}) == []
    assert _sensitive({"tools": {"alsoAllow": ["read"], "deny": ["READ"]}}) == []
    assert _sensitive({"tools": {"allow": ["read"], "deny": ["write"]}}) != []


# ------------------------------------------------------------------- the attestation

def test_an_attested_read_tool_raises_the_leg():
    """`--attest` could previously only ever CLEAR a leg: any roster silenced A1's
    hedges, so declaring a file-read tool truthfully improved the verdict. It is trusted
    symmetrically now."""
    att = {"agents": [{"name": "bot", "tools": ["read"]}]}
    assert _sensitive({}, att) == ["attested agent 'bot' holds 'read'"]


def test_an_attested_namespaced_tool_is_normalized_to_its_verb():
    att = {"agents": [{"name": "bot", "tools": ["mcp__files__read"]}]}
    assert _sensitive({}, att) == ["attested agent 'bot' holds 'mcp__files__read'"]


def test_an_attested_roster_without_a_data_tool_raises_nothing():
    att = {"agents": [{"name": "bot", "tools": ["chat", "message"]}]}
    assert _sensitive({}, att) == []


def test_a_junk_attestation_is_tolerated():
    for att in ({}, {"agents": "nope"}, {"agents": [None, 5]}, {"agents": [{"tools": None}]}):
        assert _sensitive({}, att) == [], att


# ------------------------------------------------------------------------- invariants

def test_the_bool_wrapper_still_mirrors_the_sources():
    """B-493's parity invariant, re-checked on the new sources."""
    for cfg, att in (
        ({"tools": {"allow": ["read"]}}, None),
        ({"tools": {"allow": ["thread"]}}, None),
        ({}, {"agents": [{"name": "a", "tools": ["memory_get"]}]}),
    ):
        ctx = Context(home=Path("/nonexistent"))
        ctx.config = cfg
        if att is not None:
            ctx.attestation = att
        assert _trifecta_legs(ctx) == {
            k: bool(v) for k, v in _trifecta_leg_sources(ctx).items()
        }


def test_the_id_set_and_the_hint_tuple_stay_disjoint_in_kind():
    """A hint is a substring probe and an id is an exact name; putting an id into the
    hint tuple would reintroduce the `thread` false positive this module exists to stop."""
    for tool_id in SENSITIVE_TOOL_IDS:
        assert tool_id not in _shared.SENSITIVE_TOOL_HINTS, tool_id


# --------------------------------------------------------------------- dist grounding
# Local-only: proves the ids are real OpenClaw tools and that the exclusions are
# deliberate rather than typos. Skipped where the dist is absent (CI).

def _catalog_text() -> str:
    files = sorted(OPENCLAW_DIST.glob("tool-catalog-*.js"))
    if not files:
        pytest.skip("installed OpenClaw dist not found")
    return files[0].read_text(encoding="utf-8", errors="replace")


# C-472: ONE parser, because two copies of it drifted apart the moment the catalog moved.
#
# OpenClaw 2026.8.1 restructured the records. A tool is now
#
#     { id: "write", description: "Create or overwrite files",
#       sectionId: "fs", profiles: ["coding"] }
#
# and `label:` survives only on the 14 CATEGORY records (`agents`, `coding`, `fs`, …).
# The old regex anchored on `id:` + `label:` adjacency, so it stopped matching tools
# entirely and matched categories instead: 14 ids, none of them a tool, while every
# assertion below still read as if it were looking at the tool set.
#
# `sectionId` is the discriminator, and it is exact rather than convenient: no category
# record carries one. Measured on the installed catalog — 67 distinct ids = 55 tools +
# 14 categories, with ZERO in neither bucket. (The upgrade triage recorded "67 tool ids";
# 67 is the id TOTAL, of which 55 are tools.)
def _tool_ids(text: str) -> set:
    """Ids of TOOL records — the ones carrying `sectionId`."""
    return set(re.findall(
        r'\n\t*id: "([a-z0-9_]+)",\n\t*description:[^\n]*\n\t*sectionId:', text))


def _category_ids(text: str) -> set:
    """Ids of CATEGORY records — the ones carrying `label`."""
    return set(re.findall(r'\n\t*id: "([a-z0-9_]+)",\n\t*label:', text))


def test_the_catalog_parse_accounts_for_every_id():
    """The anti-vacuity guard, and deliberately stronger than a size floor.

    A floor (`len(ids) > 20`) only catches a catastrophic reshape; this catches ANY of
    them, because it requires the two record shapes to PARTITION the ids with nothing left
    over. The 2026.8.1 reshape would have failed here immediately, where the floor let a
    parse of 14 categories stand in for the tool set.
    """
    text = _catalog_text()
    tools, categories = _tool_ids(text), _category_ids(text)
    every = set(re.findall(r'\n\t*id: "([a-z0-9_]+)",', text))
    assert len(tools) > 20, f"only {len(tools)} tool ids — the parse went stale"
    assert categories, "no category records — the parse went stale"
    # NOT asserted: that the two sets are disjoint. Measured — `nodes` and `sessions` are
    # each BOTH a tool and a category, so the catalog shares one id namespace between the
    # two record kinds. An earlier version of this test assumed otherwise and failed on
    # the real catalog; the assumption was mine, not a defect in the parse.
    unaccounted = every - tools - categories
    assert not unaccounted, (
        f"{len(unaccounted)} catalog id(s) match neither record shape: "
        f"{sorted(unaccounted)[:10]} — the catalog changed again, fix the parser"
    )


def test_every_id_is_a_real_core_tool():
    ids = _tool_ids(_catalog_text())
    missing = sorted(SENSITIVE_TOOL_IDS - ids)
    assert not missing, f"not tools OpenClaw defines: {missing}"


def test_the_excluded_tools_still_exist_so_the_exclusion_is_a_choice():
    ids = _tool_ids(_catalog_text())
    for name in ("write", "edit", "apply_patch", "sessions_history"):
        assert name in ids, f"{name} is gone from the catalog — revisit the exclusion"


def test_sessions_history_is_still_described_as_sanitized():
    """The one word the exclusion rests on."""
    text = _catalog_text()
    summary = re.search(r'SESSIONS_HISTORY_TOOL_DISPLAY_SUMMARY = "([^"]*)"', text)
    assert summary, "the summary constant moved — re-ground the exclusion"
    assert "sanitized" in summary.group(1).lower(), summary.group(1)
