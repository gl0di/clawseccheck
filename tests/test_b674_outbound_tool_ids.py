"""B-674 — the outbound leg must know OpenClaw's own write-capable tool ids too.

`OUTBOUND_TOOL_HINTS` is a generic keyword vocabulary matched as a SUBSTRING of the
joined tool names. OpenClaw's real write-capable fs tool ids are
`write`/`edit`/`apply_patch` (dist `tool-catalog-*.js`), and none of the three is a
substring of any `OUTBOUND_TOOL_HINTS` entry ("write" is not inside "send"/"webhook"/
"exec"/"shell"/"deploy"/"publish"/"http_post"/"email_send") — so a config that wrote
`tools.allow: ["write"]` under a profile `_profile_is_powerful` does not already catch
(e.g. "minimal" widened with `alsoAllow`) granted a mutation tool by name and the
outbound leg stayed off.

Same fix shape as B-667's `SENSITIVE_TOOL_IDS` for the inbound/sensitive leg: an
EXACT-id set, not a wider hint tuple — adding "write" to a substring list would convict
a tool named `copywriter`, and "edit" would convict `credit`/`editorial`.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from _distgrounding import dist_file

from clawseccheck.checks import _shared
from clawseccheck.checks._shared import (
    OUTBOUND_TOOL_IDS,
    _trifecta_leg_sources,
    _trifecta_legs,
)
from clawseccheck.collector import Context


def _outbound(cfg, attestation=None):
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = cfg
    if attestation is not None:
        ctx.attestation = attestation
    return _trifecta_leg_sources(ctx)["outbound actions"]


# ------------------------------------------------------------------ the reported defect

@pytest.mark.parametrize("name", ["write", "edit", "apply_patch"])
def test_an_allowlisted_write_capable_tool_raises_the_leg_under_a_narrow_profile(name):
    """The gap this closes: a profile `_profile_is_powerful` does NOT already catch, so
    the only prior source of the outbound leg is the exact-id layer being added here."""
    cfg = {"tools": {"profile": "minimal", "alsoAllow": [name]}}
    assert _outbound(cfg) == [f"tools.alsoAllow entry {name!r}"]


@pytest.mark.parametrize("name", ["write", "edit", "apply_patch"])
def test_a_bare_allowlisted_tool_raises_the_leg(name):
    assert _outbound({"tools": {"allow": [name]}}) == [f"tools.allow entry {name!r}"]


def test_a_powerful_profile_already_covered_this_and_still_does():
    """No regression: `tools.profile: "coding"` was already an outbound source via
    `_profile_is_powerful` before this change, independent of the new exact-id layer."""
    sources = _outbound({"tools": {"profile": "coding"}})
    assert any("powerful profile" in s for s in sources)


# --------------------------------------------------------- the trap a hint list falls in

@pytest.mark.parametrize(
    "name",
    ["copywriter", "credit", "editorial", "rewrite", "unedited", "edition",
     "applying_patch", "patchwork"],
)
def test_a_name_merely_containing_an_id_is_not_a_match(name):
    """Exactly why the fix is not `OUTBOUND_TOOL_HINTS + ("write", "edit", "apply_patch")`."""
    assert _outbound({"tools": {"allow": [name]}}) == []


def test_read_is_not_an_outbound_id():
    """`read` belongs to the sensitive-data leg (B-667), not the outbound one — it hands
    content back rather than mutating anything."""
    assert _outbound({"tools": {"allow": ["read"]}}) == []


# ------------------------------------------------------------------------ the fold

def test_the_comparison_uses_openclaws_own_normalization():
    for written in ("Write", "WRITE", "  write  "):
        assert _outbound({"tools": {"allow": [written]}}), written


def test_a_namespaced_config_entry_is_not_the_core_tool():
    assert _outbound({"tools": {"allow": ["mcp__srv__write"]}}) == []


def test_non_string_entries_are_dropped_not_coerced():
    assert _outbound({"tools": {"allow": [5, None, {"write": True}]}}) == []


# ------------------------------------------------------------------- the grant fields

def test_also_allow_is_a_grant_field_too():
    assert _outbound({"tools": {"alsoAllow": ["write"]}}) == ["tools.alsoAllow entry 'write'"]


def test_gateway_tools_allow_is_the_fallback_pair():
    assert _outbound({"gateway": {"tools": {"allow": ["write"]}}}) == [
        "gateway.tools.allow entry 'write'"
    ]


def test_deny_wins_over_allow():
    assert _outbound({"tools": {"allow": ["write"], "deny": ["write"]}}) == []
    assert _outbound({"tools": {"alsoAllow": ["write"], "deny": ["WRITE"]}}) == []
    assert _outbound({"tools": {"allow": ["write"], "deny": ["edit"]}}) != []


# ------------------------------------------------------------------- the attestation

def test_an_attested_write_tool_raises_the_leg():
    att = {"agents": [{"name": "bot", "tools": ["write"]}]}
    assert _outbound({}, att) == ["attested agent 'bot' holds 'write'"]


def test_an_attested_namespaced_tool_is_normalized_to_its_verb():
    att = {"agents": [{"name": "bot", "tools": ["mcp__files__edit"]}]}
    assert _outbound({}, att) == ["attested agent 'bot' holds 'mcp__files__edit'"]


def test_an_attested_roster_without_a_write_tool_raises_nothing():
    att = {"agents": [{"name": "bot", "tools": ["chat", "message"]}]}
    assert _outbound({}, att) == []


def test_a_junk_attestation_is_tolerated():
    for att in ({}, {"agents": "nope"}, {"agents": [None, 5]}, {"agents": [{"tools": None}]}):
        assert _outbound({}, att) == [], att


# ------------------------------------------------------------------------- invariants

def test_the_bool_wrapper_still_mirrors_the_sources():
    """B-493's parity invariant, re-checked on the new outbound sources."""
    for cfg, att in (
        ({"tools": {"allow": ["write"]}}, None),
        ({"tools": {"allow": ["copywriter"]}}, None),
        ({}, {"agents": [{"name": "a", "tools": ["edit"]}]}),
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
    hint tuple would reintroduce the `copywriter` false positive this module exists to
    stop."""
    for tool_id in OUTBOUND_TOOL_IDS:
        assert tool_id not in _shared.OUTBOUND_TOOL_HINTS, tool_id


# --------------------------------------------------------------------- dist grounding
# Local-only: proves the ids are real OpenClaw tools. Skipped where the dist is absent
# (CI). Reuses the same catalog-parse shape B-667's test pins (C-472's ONE parser).

def _catalog_text() -> str:
    return dist_file("tool-catalog-*.js", symbol="CORE_TOOL_DEFINITIONS",
                     contains="CORE_TOOL_DEFINITIONS").read_text(
        encoding="utf-8", errors="replace")


def _tool_ids(text: str) -> set:
    return set(re.findall(
        r'\n\t*id: "([a-z0-9_]+)",\n\t*description:[^\n]*\n\t*sectionId:', text))


def test_every_id_is_a_real_core_tool():
    ids = _tool_ids(_catalog_text())
    missing = sorted(OUTBOUND_TOOL_IDS - ids)
    assert not missing, f"not tools OpenClaw defines: {missing}"


def test_every_id_carries_the_fs_section():
    """OUTBOUND_TOOL_IDS is specifically the write-capable FS family — same `sectionId`
    as SENSITIVE_TOOL_IDS's `read`, grounded the same way `_B55_FS_WRITE_TOOLS` already
    is (checks/_shared.py, B55/B-395)."""
    text = _catalog_text()
    for name in OUTBOUND_TOOL_IDS:
        m = re.search(
            r'\n\t*id: "%s",\n\t*description:[^\n]*\n\t*sectionId: "([a-z]+)"' % re.escape(name),
            text,
        )
        assert m, f"{name}: could not locate its sectionId in the catalog"
        assert m.group(1) == "fs", f"{name}: sectionId is {m.group(1)!r}, expected 'fs'"
