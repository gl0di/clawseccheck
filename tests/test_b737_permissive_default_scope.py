"""CLAWSECCHECK-B-737 — one semantic test for "does the operator's tool policy decide
this scope", replacing three independently-drifting predicates.

Before this, B55/B68's NOT-ENUMERABLE branch (`_b68_fs_tools_granted` — G1 — found no
grant) fell straight to UNKNOWN, even on configs where OpenClaw's own resolver grants
every fs tool by PERMISSIVE DEFAULT (no `tools` block, an empty one, a `gateway`-only
config, an id-less `agents.list` entry G1's own truthiness/id gates skip, ...). Three
prior fix rounds (614ea8f8 / 67551f76 / ad3079b9, all superseded — see git reflog / the
SHAs in `_scratch/wave20/b-737-build.md`) each patched a hand-written "declared" key
list and each broke a different repro the other rounds had fixed.

This closes the residual with ONE real question, asked per SCOPE the vendor actually
resolves (`toolgrant.resolved_scopes`): does any operator-written policy LAYER
(`toolgrant.policy_layers`) constrain it? No new key vocabulary — `resolved_scopes`
reuses `granted()`'s own three-layer resolution order (via the shared `_policies`) and
`toolpolicy`'s existing opaque-key set (now owned by `toolgrant`, aliased from there).

This file is the design's full test matrix (`_scratch/wave20/b-737-design.md` §3),
turned into assertions, plus the mutation-kill list from the same section.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck import toolgrant
from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    check_exec_applypatch_workspace,
    check_fs_write_exposure,
    run_all,
)
from clawseccheck.checks._capability import (
    _B68_FS_TOOLS,
    _fs_scope_grants,
)
from clawseccheck.collector import Context
from clawseccheck.risk import risk_paths

# Channel "+ch" throughout the design doc: a declared, untrusted-content, NOT-proven-open
# channel (pairing) -- enough to arm RISK-12 (B55 FAIL/WARN + untrusted ingress) without
# also satisfying B55's own `open_ch` (proven-open) gate, exactly as the design's repros do.
_CH = {"channels": {"telegram": {"enabled": True, "dmPolicy": "pairing"}}}


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def _verdicts(cfg: dict):
    """(B55 status, B68 status, RISK-12 fires) for a synthetic in-memory config,
    through the real check registry + risk engine -- never a hand-built findings list,
    so this exercises exactly what `audit()` would compute."""
    ctx = _ctx(cfg)
    findings = run_all(ctx)
    by_id = {f.id: f for f in findings}
    risk_ids = {p.id for p in risk_paths(ctx, findings)}
    return by_id["B55"].status, by_id["B68"].status, "RISK-12" in risk_ids


def _b55(cfg: dict):
    return check_fs_write_exposure(_ctx(cfg))


def _b68(cfg: dict):
    return check_exec_applypatch_workspace(_ctx(cfg))


# =====================================================================================
# Original report
# =====================================================================================

def test_empty_config_stays_unknown_no_risk():
    # {} is `granted()`'s own deliberate divergence (a config never actually parsed is not
    # evidence of a grant) -- `resolved_scopes({})` returns None, same as `granted({}, ...)`
    # returns False. Never a guess.
    assert _verdicts({}) == (UNKNOWN, UNKNOWN, False)


def test_channel_alone_warns_default_and_arms_risk12():
    b55, b68, risk12 = _verdicts(dict(_CH))
    assert (b55, b68, risk12) == (WARN, WARN, True)


def test_empty_tools_block_warns_default_no_risk():
    assert _verdicts({"tools": {}}) == (WARN, WARN, False)


def test_minimal_profile_passes_unchanged():
    # A real, well-formed, restrictive policy -- G1's own path, untouched by B-737.
    assert _verdicts({"tools": {"profile": "minimal"}}) == (PASS, PASS, False)


# =====================================================================================
# targeted-r1
# =====================================================================================

def test_r1_d1a_idd_minimal_profile_roster_now_passes_fully_resolved_b943():
    """B-943: was `..._is_unknown_not_false_warn` — the per-scope residual now
    distinguishes "resolved, nothing granted" from "could not resolve" instead of
    collapsing both into UNKNOWN. A single named scope on a genuine, well-formed
    `minimal` profile is exactly the former: fully resolved (not opaque), and grants
    nothing in the fs family — PASS, naming the scope, not UNKNOWN."""
    cfg = {"agents": {"list": [{"id": "main", "tools": {"profile": "minimal"}}]}, **_CH}
    assert _verdicts(cfg) == (PASS, PASS, False)


def test_r1_d1b_every_agent_restricts_itself_now_passes_fully_resolved_b943():
    """B-943: was `..._is_unknown_not_false_warn`. Both named scopes are well-formed
    and non-opaque (`main` denies group:fs, `ops` runs the real `messaging` profile),
    so every scope `resolved_scopes` returns was genuinely examined and neither grants
    anything in the fs family — a real "resolved, and resolved to nothing" PASS, not
    the "could not resolve" UNKNOWN this used to fall back to."""
    cfg = {
        "agents": {
            "entries": {
                "main": {"tools": {"deny": ["group:fs"]}},
                "ops": {"tools": {"profile": "messaging"}},
            }
        },
        **_CH,
    }
    assert _verdicts(cfg) == (PASS, PASS, False)


def test_r1_d2_channel_alone_arms_risk12_deliberately():
    # Restated from test_channel_alone_warns_default_and_arms_risk12: this is the
    # consistency-table row (design §1) -- the same vendor state (default agent, no
    # policy layer, write granted, untrusted channel) as an id'd agent with settings-only
    # `tools` noise, which already armed RISK-12 on base. Reviewer 2 named this the
    # correct answer.
    assert _verdicts(dict(_CH)) == (WARN, WARN, True)


def test_r1_per_agent_allow_read_only_still_passes_g1_path_unchanged():
    cfg = {"agents": {"list": [{"id": "main", "tools": {"allow": ["read"]}}]}}
    b55, _, _ = _verdicts(cfg)
    assert b55 == PASS


@pytest.mark.parametrize("tools_value", ["none", [], None])
def test_r1_non_mapping_global_tools_is_unknown(tools_value):
    assert _verdicts({"tools": tools_value}) == (UNKNOWN, UNKNOWN, False)


def test_r1_global_byprovider_only_is_unknown_opaque():
    cfg = {"tools": {"byProvider": {"openai": {"profile": "minimal"}}}}
    assert _verdicts(cfg) == (UNKNOWN, UNKNOWN, False)


def test_r1_global_deny_write_family_b55_now_passes_b68_warns_declared_read():
    """B-943: B55 was UNKNOWN here (`..._b55_unknown_b68_warns_declared_read`); its
    family is write/edit/apply_patch only, all explicitly denied at the one (global)
    scope, which is non-opaque and fully resolved — a genuine "resolved to nothing" for
    B55's narrower family. B68's family also includes `read`, which is NOT denied and
    IS granted, so B68 stays WARN exactly as before — the two checks asking different
    tool families is exactly why they can land on different sides of this fix."""
    cfg = {"tools": {"deny": ["write", "edit", "apply_patch"]}}
    b55, b68, risk12 = _verdicts(cfg)
    assert (b55, b68, risk12) == (PASS, WARN, False)
    f68 = _b68(cfg)
    assert "read" in ", ".join(f68.evidence)


# =====================================================================================
# fix-r1 (self-found)
# =====================================================================================

def test_toolscope_case9_defaults_ignored_beside_roster_warns_default():
    cfg = {
        "agents": {
            "defaults": {"tools": {"allow": ["write"]}},
            "entries": {"main": {}},
        },
        **_CH,
    }
    f55 = _b55(cfg)
    assert f55.status == WARN
    assert any("ignored" in e and "roster" in e for e in f55.evidence)
    b55, b68, risk12 = _verdicts(cfg)
    assert (b55, b68, risk12) == (WARN, WARN, True)


def test_b903_mixed_roster_warns_default_naming_the_default_scope():
    cfg = {
        "agents": {
            "entries": {
                "main": {"tools": {"profile": "minimal"}},
                "ops": {},
            }
        },
        **_CH,
    }
    f55 = _b55(cfg)
    assert f55.status == WARN
    assert any("ops" in e for e in f55.evidence)
    assert not any("main" in e for e in f55.evidence if "permissive default" in e)
    b55, b68, risk12 = _verdicts(cfg)
    assert (b55, b68, risk12) == (WARN, WARN, True)


# =====================================================================================
# targeted-r2
# =====================================================================================

def test_r2_idless_exec_only_no_channel_warns_default():
    cfg = {"agents": {"list": [{"tools": {"exec": {"mode": "ask"}}}]}}
    assert _verdicts(cfg) == (WARN, WARN, False)


def test_r2_idless_exec_only_plus_channel_arms_risk12():
    cfg = {"agents": {"list": [{"tools": {"exec": {"mode": "ask"}}}]}, **_CH}
    assert _verdicts(cfg) == (WARN, WARN, True)


def test_r2_idless_minimal_profile_plus_channel_now_passes_b943():
    """B-943: was `..._is_unknown`. The id-less entry self-matches the single resolved
    scope (`""`, normalised to "main"), non-opaque, genuine `minimal` profile — fully
    resolved and grants nothing in the fs family, so PASS naming that scope."""
    cfg = {"agents": {"list": [{"tools": {"profile": "minimal"}}]}, **_CH}
    assert _verdicts(cfg) == (PASS, PASS, False)


def test_r2_empty_roster_key_plus_defaults_profile_is_g1_path_unchanged():
    # `agents.list` DECLARED (even empty) -- `_has_agent_roster` is True, so this is NOT
    # the "no roster key at all" default-agent shape; it stays whatever G1 already gives
    # it (unaffected by B-737 either way).
    cfg = {"agents": {"list": [], "defaults": {"tools": {"profile": "minimal"}}}}
    b55, _, _ = _verdicts(cfg)
    assert b55 == WARN


# =====================================================================================
# targeted-r3
# =====================================================================================

def test_r3_idless_deny_write_family_plus_channel_b55_now_passes_b68_warns_read_no_risk():
    """B-943: B55 was UNKNOWN here (`..._b55_unknown_b68_warns_read_no_risk`) — same
    split as `test_r1_global_deny_write_family_b55_now_passes_b68_warns_declared_read`,
    on the id-less roster-entry sibling: B55's write-only family resolves to nothing
    (PASS), B68's read+write family still finds `read` granted (WARN, unchanged)."""
    cfg = {"agents": {"list": [{"tools": {"deny": ["write", "edit", "apply_patch"]}}]}, **_CH}
    b55, b68, risk12 = _verdicts(cfg)
    assert (b55, b68, risk12) == (PASS, WARN, False)


def test_r3_idless_deny_group_fs_plus_channel_now_passes_both_b943():
    """B-943: was `..._is_unknown_both`. This is the id-less sibling of the ticket's own
    repro shape (a single, well-formed, fully-resolved scope denying the whole
    `group:fs` family) — both B55 and B68 now PASS, naming the one resolved scope,
    instead of collapsing into UNKNOWN the way an actually-unresolvable config does."""
    cfg = {"agents": {"list": [{"tools": {"deny": ["group:fs"]}}]}, **_CH}
    assert _verdicts(cfg) == (PASS, PASS, False)


@pytest.mark.parametrize(
    "entries",
    [
        [{"tools": {"exec": {"mode": "ask"}}}, {"tools": {"profile": "minimal"}}],
        [{"tools": {"profile": "minimal"}}, {"tools": {"exec": {"mode": "ask"}}}],
    ],
    ids=["noise_then_minimal", "minimal_then_noise"],
)
def test_r3_two_idless_entries_both_normalize_to_main_is_unknown(entries):
    cfg = {"agents": {"list": entries}}
    assert _verdicts(cfg) == (UNKNOWN, UNKNOWN, False)


def test_r3_idless_byprovider_only_is_unknown_opaque():
    cfg = {"agents": {"list": [{"tools": {"byProvider": {"openai": {"profile": "minimal"}}}}]}}
    assert _verdicts(cfg) == (UNKNOWN, UNKNOWN, False)


def test_r3_idless_toolsbysender_only_is_unknown_opaque():
    cfg = {"agents": {"list": [{"tools": {"toolsBySender": {"*": {"profile": "minimal"}}}}]}}
    assert _verdicts(cfg) == (UNKNOWN, UNKNOWN, False)


def test_r3_named_byprovider_only_is_unknown_opaque():
    """B-938: this used to be the one shape design §6 follow-up #1 deliberately did NOT
    fix -- G1's OWN scoped loop (`_b68_fs_tools_granted`) granted a NAMED agent whose only
    `tools` key is `byProvider` a vacuous full grant, because `_pick_policy` ignores
    `byProvider` entirely (an empty `_policies()` list, `all(...)` over zero policies is
    vacuously True) and G1's own gate never asked `resolved_scopes` whether the scope was
    opaque before calling `toolgrant.granted`. G1 now consults the same
    `resolved_scopes(...).opaque` verdict `_fs_scope_grants` already trusts for this exact
    class, so it skips the scope instead of granting it, matching the id-less sibling shape
    (`test_r3_idless_byprovider_only_is_unknown_opaque`) B-737 already got right."""
    cfg = {"agents": {"list": [{"id": "main", "tools": {"byProvider": {"openai": {}}}}]}, **_CH}
    b55, b68, risk12 = _verdicts(cfg)
    assert (b55, b68, risk12) == (UNKNOWN, UNKNOWN, False)


def test_r3_named_toolsbysender_only_is_unknown_opaque():
    """Same shape as `test_r3_named_byprovider_only_is_unknown_opaque` (B-938), the other
    `OPAQUE_NARROWING_KEYS` member, on a NAMED roster entry instead of the id-less sibling
    `test_r3_idless_toolsbysender_only_is_unknown_opaque`."""
    cfg = {
        "agents": {"list": [{"id": "main", "tools": {"toolsBySender": {"*": {}}}}]},
        **_CH,
    }
    b55, b68, risk12 = _verdicts(cfg)
    assert (b55, b68, risk12) == (UNKNOWN, UNKNOWN, False)


# =====================================================================================
# Consistency controls and extra shapes
# =====================================================================================

def test_control_idd_exec_noise_plus_channel_g1_path_unchanged():
    cfg = {"agents": {"list": [{"id": "main", "tools": {"exec": {"mode": "ask"}}}]}, **_CH}
    assert _verdicts(cfg) == (WARN, WARN, True)


def test_control_entries_main_exec_plus_channel_g1_path_unchanged():
    cfg = {"agents": {"entries": {"main": {"tools": {"exec": {"mode": "ask"}}}}}, **_CH}
    assert _verdicts(cfg) == (WARN, WARN, True)


def test_control_defaults_exec_no_roster_plus_channel_g1_path_unchanged():
    cfg = {"agents": {"defaults": {"tools": {"exec": {"mode": "ask"}}}}, **_CH}
    assert _verdicts(cfg) == (WARN, WARN, True)


def test_extra_idless_allow_write_plus_channel_lost_detection_now_warns_declared():
    """Base UNKNOWN (G1 skips an id-less agent entirely): a real, declared, explicit
    `tools.allow: ["write"]` on an id-less roster entry used to be invisible. Now caught
    via `resolved_scopes`' `""` query (self-matches the id-less entry, `_agent_entry_tools`
    normalises it to "main") -- WARN declared, never a guess at FAIL."""
    cfg = {"agents": {"list": [{"tools": {"allow": ["write"]}}]}, **_CH}
    f55 = _b55(cfg)
    assert f55.status == WARN
    assert f55.status != FAIL
    b55, b68, risk12 = _verdicts(cfg)
    assert (b55, b68, risk12) == (WARN, WARN, True)


def test_extra_empty_list_roster_plus_channel_warns_default():
    cfg = {"agents": {"list": []}, **_CH}
    assert _verdicts(cfg) == (WARN, WARN, True)


def test_extra_gated_default_grant_no_channel_warns_not_pass_ruling():
    """Dave's ruling (design §2.2): a default (undeclared) grant never gets the
    gated-and-no-ingress PASS, even though a genuinely declared-and-scoped grant does.
    A default grant is stricter BY DESIGN, not an accident of wording."""
    cfg = {"tools": {"exec": {"mode": "ask"}}}
    f55 = _b55(cfg)
    assert f55.status == WARN
    assert f55.status != PASS
    assert _verdicts(cfg) == (WARN, WARN, False)


def test_extra_gated_default_grant_plus_channel_warns_and_arms_risk12():
    cfg = {"tools": {"exec": {"mode": "ask"}}, **_CH}
    assert _verdicts(cfg) == (WARN, WARN, True)


def test_extra_open_dm_no_tools_never_fails():
    cfg = {"channels": {"telegram": {"enabled": True, "dmPolicy": "open"}}}
    f55 = _b55(cfg)
    assert f55.status == WARN
    assert f55.status != FAIL
    b55, b68, risk12 = _verdicts(cfg)
    assert (b55, b68, risk12) == (WARN, WARN, True)


def test_extra_idless_fs_workspace_only_true_warns_b55_unknown_b68_every_scope_confined():
    cfg = {"agents": {"list": [{"tools": {"fs": {"workspaceOnly": True}}}]}}
    b55, b68, risk12 = _verdicts(cfg)
    assert (b55, b68, risk12) == (WARN, UNKNOWN, False)


def test_extra_empty_allow_list_is_a_noop_layer_not_provenance():
    assert _verdicts({"tools": {"allow": []}}) == (WARN, WARN, False)


def test_extra_entries_byprovider_plus_bare_scope_still_warns():
    """Verdict-only (design's extras row), mechanism updated by B-938: `main` is a NAMED
    agent whose only `tools` key is `byProvider`. Before B-938, G1's own `scoped` loop
    (`_b68_fs_tools_granted`) processed `main` (it has an id and a truthy `tools`), called
    `toolgrant.granted` on it, and got a vacuous "everything granted" because `_pick_policy`
    ignores `byProvider` entirely -- so G1 was ALREADY enumerable there and `_fs_scope_grants`
    never ran for this config at all. Now G1 consults `resolved_scopes(...).opaque` and skips
    `main`, which makes G1 NOT enumerable (`scoped` stays empty), so `_fs_scope_grants` runs:
    `main` is skipped again there (still opaque), and `ops` -- an id'd agent with an empty
    `tools` block, `policy_layers` empty -- is read as OpenClaw's own PERMISSIVE DEFAULT, the
    same B-737 provenance class as every other undeclared scope. `ops` now genuinely appears
    in the evidence, driving the same WARN/WARN/True triple the design predicted for a
    different reason than before."""
    cfg = {
        "agents": {
            "entries": {
                "main": {"tools": {"byProvider": {"openai": {}}}},
                "ops": {},
            }
        },
        **_CH,
    }
    assert _verdicts(cfg) == (WARN, WARN, True)


def test_extra_named_minimal_profile_no_channel_now_passes_b943():
    """B-943: was `..._is_unknown`. Matches `test_minimal_profile_passes_unchanged`'s
    GLOBAL-profile PASS, just scoped to a single named agent instead — no reason a
    per-agent `minimal` profile should read any less resolved than a global one."""
    cfg = {"agents": {"entries": {"main": {"tools": {"profile": "minimal"}}}}}
    assert _verdicts(cfg) == (PASS, PASS, False)


@pytest.mark.parametrize("allow_value", ["write", {}])
def test_extra_malformed_global_allow_is_unknown(allow_value):
    assert _verdicts({"tools": {"allow": allow_value}}) == (UNKNOWN, UNKNOWN, False)


def test_extra_idless_unknown_profile_is_unknown_malformed():
    """`_fs_scope_grants`'s malformed-profile detection specifically, isolated from
    `_agent_profile_widenings`'s OWN, unrelated, pre-existing "powerful profile" test
    (`checks/_shared._profile_is_powerful`): that helper is case-INSENSITIVE and treats
    any profile string containing "code" as powerful, so `profile: "Coding"` (the
    design's own example) is caught by G1's widenings path regardless of id -- verified:
    `_agent_profile_widenings` returns non-empty for it, so `_b68_fs_tools_granted`
    is ALREADY enumerable and `resolved_scopes` never runs (see
    `test_extra_idd_profile_name_substring_match_still_widens_unaffected_by_b941` for the
    id'd sibling of THAT case, still unaffected). "Messaging" (wrong case, no "exec"/
    "code" substring) isolates the malformed-profile path this design actually added:
    `toolgrant._CORE_TOOL_PROFILES` is case-sensitive, so "Messaging" resolves to
    nothing there, `_block_well_formed` rejects it, and `resolved_scopes` returns
    None -- UNKNOWN, not a guess. CLAWSECCHECK-B-941 closed the id'd sibling of THIS
    exact config (`test_extra_idd_unknown_profile_is_unknown_malformed` below), which
    used to disagree with this id-less one -- see that test for the history."""
    cfg = {"agents": {"list": [{"tools": {"profile": "Messaging"}}]}}
    assert _verdicts(cfg) == (UNKNOWN, UNKNOWN, False)
    assert toolgrant.resolved_scopes(cfg) is None


@pytest.mark.parametrize(
    "profile_value",
    [["x"], {"x": 1}],
    ids=["list_valued_profile", "dict_valued_profile"],
)
def test_extra_idless_unhashable_profile_is_unknown_not_a_crash(profile_value):
    """Review finding (B-737 fix round 1, BLOCKER): an id-less `agents.list` entry whose
    own `tools.profile` is unhashable (a list or a dict, not a malformed-but-hashable
    string like "Messaging") used to raise `TypeError: unhashable type` out of
    `_block_well_formed`'s `tools["profile"] not in _CORE_TOOL_PROFILES` membership test
    -- `run_all`'s per-check isolation (B-101) caught it and degraded B55/B68 to
    `ERR:check_fs_write_exposure` / `ERR:check_exec_applypatch_workspace` (UNKNOWN,
    scored=False, engine_degraded=True), and the 'B55'/'B68' ids were absent from the
    findings list entirely -- not even a plain UNKNOWN under their own ids. Same quiet
    direction as every other malformed shape here: UNKNOWN under B55/B68, no ERR, no
    engine degradation, matching base (pre-B-737) behaviour for this exact config."""
    cfg = {"agents": {"list": [{"tools": {"profile": profile_value}}]}}
    assert toolgrant.resolved_scopes(cfg) is None
    ctx = _ctx(cfg)
    findings = run_all(ctx)
    by_id = {f.id: f for f in findings}
    assert "B55" in by_id and "B68" in by_id
    assert by_id["B55"].status == UNKNOWN
    assert by_id["B68"].status == UNKNOWN
    assert not any(f.id.startswith("ERR") for f in findings)
    assert _verdicts(cfg) == (UNKNOWN, UNKNOWN, False)


def test_extra_idd_unknown_profile_is_unknown_malformed():
    """CLAWSECCHECK-B-941 (was `test_extra_idd_unknown_profile_pre_existing_g1_quirk_
    unaffected`, pinning the OLD, wrong WARN verdict for this exact config -- renamed
    because the fix it names is no longer "unaffected"). The id'd sibling of
    `test_extra_idless_unknown_profile_is_unknown_malformed` above: a named roster agent
    with the SAME schema-invalid `tools.profile` ("Messaging" -- wrong case, no "exec"/
    "code" substring, so `_agent_profile_widenings`'s heuristic does not fire either)
    used to resolve to nothing via `toolgrant._profile_policy`, leaving `_policies`
    empty for that scope -- `all(...)` over an empty policy list vacuously grants every
    tool via G1's own per-agent `toolgrant.granted` call in `_b68_fs_tools_granted`,
    reported as a confident full-grant WARN. That call is now skipped whenever
    `toolgrant._policies(cfg, scope)` is empty AND `toolgrant._unresolved_profile(cfg,
    scope)` says the reason is exactly this (an unrecognised profile silently dropping
    out of the AND-ed list) -- NOT the blunter `toolgrant._block_well_formed`, which
    would also incorrectly reject a scope where a real OTHER layer (e.g. a global
    `alsoAllow` wildcard) still resolves the grant despite this agent's own unrecognised
    profile (see `clean_b409_weak_agent_profile_no_widening` in `tests/test_b55.py`).
    So this scope falls through to `_fs_scope_grants` and lands on the honest UNKNOWN
    the id-less sibling already had -- the two configs no longer disagree only because
    of whether the roster entry happens to carry an `id`."""
    cfg = {"agents": {"list": [{"id": "main", "tools": {"profile": "Messaging"}}]}}
    assert _verdicts(cfg) == (UNKNOWN, UNKNOWN, False)
    assert toolgrant.resolved_scopes(cfg) is None


def test_extra_idd_profile_name_substring_match_still_widens_unaffected_by_b941():
    """Control for B-941: `profile: "Coding"` (capital C) is ALSO not a real
    `toolgrant._CORE_TOOL_PROFILES` key, but unlike "Messaging" above it contains the
    substring "code", so `checks/_shared._profile_is_powerful` (case-insensitive,
    deliberately catching typos/near-misses of a powerful profile name -- its own
    module comment) treats it as powerful regardless of id. `_agent_profile_widenings`
    therefore returns non-empty for this config BEFORE `_b68_fs_tools_granted` ever
    reaches the per-agent `toolgrant.granted` call B-941 gated, so this WARN is driven
    by that separate, intentional heuristic, not by the malformed-profile vacuous-grant
    bug -- B-941's fix must not (and does not) change it. This is the id'd sibling of
    the id-less case documented in `test_extra_idless_unknown_profile_is_unknown_
    malformed`'s own docstring."""
    cfg = {"agents": {"list": [{"id": "main", "tools": {"profile": "Coding"}}]}}
    b55, _, _ = _verdicts(cfg)
    assert b55 == WARN


def test_extra_defaults_tools_malformed_profile_is_unknown():
    """CLAWSECCHECK-B-941's sibling shape: the SAME vacuous-grant bug, reached through
    `agents.defaults.tools` instead of a roster entry -- no roster declared at all, so
    `_b68_fs_tools_granted`'s second `scoped` contribution (`agents.defaults.tools`)
    used to call `toolgrant.granted(cfg, t)` unconditionally once the key was merely
    present, with the same "unrecognised profile resolves to an empty, vacuously-
    granting policy list" defect. Now gated on the same `toolgrant._policies(cfg)`-
    empty-plus-`toolgrant._unresolved_profile(cfg)` test as the roster loop above, so
    it falls through to `_fs_scope_grants` and lands on UNKNOWN, same as every other
    malformed-profile shape in this file."""
    cfg = {"agents": {"defaults": {"tools": {"profile": "Messaging"}}}}
    assert _verdicts(cfg) == (UNKNOWN, UNKNOWN, False)
    assert toolgrant.resolved_scopes(cfg) is None


@pytest.mark.parametrize(
    "profile_value",
    [["x"], {"x": 1}],
    ids=["list_valued_profile", "dict_valued_profile"],
)
def test_extra_global_non_string_profile_no_roster_is_unknown_not_pass(profile_value):
    """CLAWSECCHECK-B-963: `{"tools": {"profile": ["x"]}}` (or an equivalent dict), with
    NO `agents` key at all -- so resolution happens entirely at `GLOBAL_SCOPE`, the ONE
    code path that never went through `toolgrant.resolved_scopes` (B-737's fix covers
    the rostered/`agents.defaults` shapes; this config has neither). `_tool_policy_view`
    used to read `profile is not None` as "this view is enumerable" regardless of type,
    so a non-string profile with no other grant signal made `_b68_fs_tools_granted`
    return `([], True)` -- "fully resolved, nothing granted" -- which both B55 and B68
    read as a confident PASS. `checks/_shared._profile_is_powerful` is crash-safe for a
    list/dict (`str(profile or "").lower()` matches nothing for `"['x']"`/`"{'x': 1}"`),
    so nothing downstream ever surfaced the malformation. A real OpenClaw config could
    never carry this value (`ToolProfileSchema` is a string enum), so the honest answer
    is UNKNOWN, not PASS. `_tool_policy_view.enumerable` now requires `isinstance(
    profile, str)`, matching `toolgrant._block_well_formed`'s own guard for the
    identical malformed-input class."""
    cfg = {"tools": {"profile": profile_value}}
    assert "agents" not in cfg
    assert _verdicts(cfg) == (UNKNOWN, UNKNOWN, False)


def test_extra_global_valid_string_profile_no_roster_unaffected_by_b963():
    """Control for B-963: a well-formed, real global `tools.profile` string (no
    `agents` key either) must keep resolving normally -- the fix narrows `enumerable`
    to exclude non-string values only; it must not turn every global-profile config
    into UNKNOWN. "minimal" is not a powerful profile, so both checks stay PASS."""
    cfg = {"tools": {"profile": "minimal"}}
    assert _verdicts(cfg) == (PASS, PASS, False)


# =====================================================================================
# Unit / mutation coverage on toolgrant.policy_layers / resolved_scopes directly
# =====================================================================================

def test_policy_layers_empty_config_and_no_op_allow():
    assert toolgrant.policy_layers({}) == []
    assert toolgrant.policy_layers({"tools": {"allow": []}}) == []
    assert toolgrant.policy_layers({"tools": {"deny": []}}) == []


def test_policy_layers_real_allow_is_a_layer():
    layers = toolgrant.policy_layers({"tools": {"allow": ["read"]}})
    assert len(layers) == 1


def test_resolved_scopes_malformed_variants_return_none():
    for bad in ("none", [], None):
        assert toolgrant.resolved_scopes({"tools": bad}) is None
    assert toolgrant.resolved_scopes({"tools": {"allow": "write"}}) is None
    assert toolgrant.resolved_scopes({"tools": {"allow": {}}}) is None
    assert toolgrant.resolved_scopes({"tools": {"profile": "Coding"}}) is None
    assert toolgrant.resolved_scopes({}) is None


@pytest.mark.parametrize("bad_profile", [["x"], {"x": 1}])
def test_resolved_scopes_unhashable_profile_returns_none_not_raise(bad_profile):
    # Review finding (fix round 1): an unhashable `profile` (list/dict) must take the
    # same None/UNKNOWN direction as a hashable-but-unrecognised one ("Coding" above),
    # never raise `TypeError: unhashable type` out of the `in _CORE_TOOL_PROFILES` test.
    assert toolgrant.resolved_scopes({"tools": {"profile": bad_profile}}) is None
    assert toolgrant.resolved_scopes(
        {"agents": {"list": [{"tools": {"profile": bad_profile}}]}}
    ) is None


def test_resolved_scopes_duplicate_normalized_id_returns_none():
    cfg = {"agents": {"list": [{"tools": {"a": 1}}, {"tools": {"b": 2}}]}}
    # Both entries are id-less -> both normalize to "main" -> ambiguous -> None.
    assert toolgrant.resolved_scopes(cfg) is None


def test_resolved_scopes_opaque_flag_set_for_byprovider_and_toolsbysender():
    for key in toolgrant.OPAQUE_NARROWING_KEYS:
        cfg = {"tools": {key: {"x": True}}}
        scopes = toolgrant.resolved_scopes(cfg)
        assert scopes is not None and len(scopes) == 1
        assert scopes[0].opaque is True


def test_resolved_scopes_no_roster_scope_is_global_scope_sentinel():
    scopes = toolgrant.resolved_scopes({"tools": {}})
    assert scopes is not None and len(scopes) == 1
    assert scopes[0].scope is toolgrant.GLOBAL_SCOPE


def test_resolved_scopes_roster_scope_uses_raw_or_empty_id():
    scopes = toolgrant.resolved_scopes(
        {"agents": {"list": [{"id": "ops", "tools": {}}, {"tools": {}}]}}
    )
    assert scopes is not None and len(scopes) == 2
    by_scope = {s.scope: s for s in scopes}
    assert "ops" in by_scope
    assert "" in by_scope  # id-less entry queried by "" (self-matches via normalization)


# --------------------------- mutation-kill list (design §3) ---------------------------

def test_mutant_querying_global_scope_instead_of_roster_ids_is_killed():
    """If `resolved_scopes` asked GLOBAL_SCOPE instead of each roster id, D1a
    (id'd `main`, profile minimal) would incorrectly see the GLOBAL layer (empty) rather
    than the agent's own minimal-profile layer, and misreport provenance/grant.

    B-943: the correct verdict here is PASS, not UNKNOWN (see
    `test_r1_d1a_idd_minimal_profile_roster_now_passes_fully_resolved_b943`) -- an empty
    global layer would still resolve GLOBAL_SCOPE (non-opaque), so the mutant would
    still land on a fully-resolved, non-empty grant (nothing restricts it) and answer
    WARN/PASS-with-a-real-grant, not this test's expected PASS-with-nothing-granted --
    still a mismatch, so the kill holds under the new verdict too."""
    cfg = {"agents": {"list": [{"id": "main", "tools": {"profile": "minimal"}}]}, **_CH}
    assert _verdicts(cfg) == (PASS, PASS, False)


def test_mutant_dropping_the_opaque_skip_is_killed():
    cfg = {"agents": {"list": [{"tools": {"byProvider": {"openai": {}}}}]}}
    assert _verdicts(cfg) == (UNKNOWN, UNKNOWN, False)


def test_mutant_dropping_the_global_opaque_check_is_killed():
    cfg = {"tools": {"byProvider": {"openai": {"profile": "minimal"}}}}
    assert _verdicts(cfg) == (UNKNOWN, UNKNOWN, False)


@pytest.mark.parametrize("tools_value", ["none", "write"])
def test_mutant_dropping_the_malformed_check_is_killed(tools_value):
    assert toolgrant.resolved_scopes({"tools": tools_value}) is None


def test_mutant_dropping_the_duplicate_id_check_is_killed():
    cfg = {"agents": {"list": [{"tools": {"profile": "minimal"}}, {"tools": {"allow": ["read"]}}]}}
    assert toolgrant.resolved_scopes(cfg) is None


def test_mutant_counting_noop_layers_as_provenance_is_killed():
    assert toolgrant.policy_layers({"tools": {"allow": []}}) == []
    assert _verdicts({"tools": {"allow": []}})[0] == WARN  # WARN default, not PASS/UNKNOWN


def test_mutant_dropping_b68_confinement_is_killed():
    cfg = {"agents": {"list": [{"tools": {"fs": {"workspaceOnly": True}}}]}}
    _, b68, _ = _verdicts(cfg)
    assert b68 == UNKNOWN


def test_mutant_dropping_the_gated_pass_guard_is_killed():
    f55 = _b55({"tools": {"exec": {"mode": "ask"}}})
    assert f55.status == WARN and f55.status != PASS


def test_mutant_readding_a_risk12_guard_is_killed():
    # D2: channel alone must arm RISK-12 -- a re-added evidence-string guard (the exact
    # defect risk.py's B-737 docstring update warns against reintroducing) would silence
    # this while leaving the id'd-noise control (below) firing, which is the
    # inconsistency this design closes.
    assert _verdicts(dict(_CH))[2] is True
    control_cfg = {"agents": {"list": [{"id": "main", "tools": {"exec": {"mode": "ask"}}}]}, **_CH}
    assert _verdicts(control_cfg)[2] is True


# =====================================================================================
# Never-FAIL invariant for the B-737 residual specifically
# =====================================================================================

@pytest.mark.parametrize(
    "cfg",
    [
        dict(_CH),
        {"agents": {"list": [{"tools": {"exec": {"mode": "ask"}}}]}, **_CH},
        {"agents": {"list": [{"tools": {"allow": ["write"]}}]}, **_CH},
        {"channels": {"telegram": {"enabled": True, "dmPolicy": "open"}}},
        {"agents": {"list": []}, **_CH},
    ],
    ids=["channel_alone", "idless_exec", "idless_allow_write", "open_dm", "empty_roster"],
)
def test_b737_residual_never_reaches_fail(cfg):
    """`explicit_write_grant` is necessarily False whenever B55's write_tools came from
    `_fs_scope_grants` (design §2.2's proof: G1 already found no group:fs deny, no named
    allow/alsoAllow/profile token, and no per-agent widening -- exactly the precondition
    for reaching this residual at all). FAIL is structurally unreachable; this is the
    regression lock for that invariant."""
    assert _b55(cfg).status != FAIL


def test_fs_scope_grants_none_on_malformed_config():
    assert _fs_scope_grants({"tools": "none"}, _B68_FS_TOOLS) is None


def test_fs_scope_grants_inert_defaults_tools_flag():
    cfg = {"agents": {"defaults": {"tools": {"allow": ["write"]}}, "entries": {"main": {}}}}
    result = _fs_scope_grants(cfg, _B68_FS_TOOLS)
    assert result is not None
    assert result.inert_defaults_tools is True


# =====================================================================================
# B-943 — "resolved, nothing granted" is a real PASS, distinct from "could not resolve"
# =====================================================================================
#
# Before this, `_fs_scope_grants` returning a non-None result with both tool sets empty
# was treated identically to `None` (both callers reset `scope_grants` to `None` and fell
# to the base UNKNOWN) -- collapsing "every scope was genuinely examined and grants
# nothing" into "could not tell". This section pins the new three-way split: a real grant
# (already covered above), a genuinely resolved empty grant (PASS, naming the checked
# scopes), and a genuinely unresolvable config (UNKNOWN, unchanged) -- plus the two
# structural edges (a mixed opaque/resolved scope set, and every scope confined away)
# that deliberately still take the UNKNOWN side despite a non-None result.

def test_b943_ticket_repro_named_agent_denies_group_fs_passes_naming_the_scope():
    """The ticket's own exact repro: one named, well-formed, fully-resolved scope
    (`provenance="declared"`, deny-only) that grants nothing in the fs family. Must be
    PASS, not UNKNOWN, on both B55 and B68, and the PASS evidence must name the scope
    that was actually checked ("main") rather than a bare "trust me"."""
    cfg = {"agents": {"entries": {"main": {"tools": {"deny": ["group:fs"]}}}}}
    b55, b68, risk12 = _verdicts(cfg)
    assert (b55, b68, risk12) == (PASS, PASS, False)
    f55 = _b55(cfg)
    f68 = _b68(cfg)
    assert "main" in ", ".join(f55.evidence)
    assert "main" in ", ".join(f68.evidence)


def test_b943_fs_scope_grants_fully_resolved_and_checked_scopes_on_ticket_repro():
    """Unit-level pin on `_fs_scope_grants` itself, isolated from the check wiring
    above: `fully_resolved` is True and `checked_scopes` names exactly the one scope
    that was examined, with both tool sets empty."""
    cfg = {"agents": {"entries": {"main": {"tools": {"deny": ["group:fs"]}}}}}
    result = _fs_scope_grants(cfg, _B68_FS_TOOLS)
    assert result is not None
    assert result.fully_resolved is True
    assert result.checked_scopes == ("main",)
    assert not result.default_tools and not result.declared_tools


def test_b943_adversarial_mixed_opaque_and_resolved_scope_stays_unknown_not_pass():
    """C-135: the sharpest adversarial shape for this change -- one scope that
    genuinely resolves to nothing in the fs family (`main`, deny group:fs) SITTING
    BESIDE one scope this module cannot read at all (`ops`, a bare `byProvider` block,
    opaque). A caller must not read "the scopes I COULD examine found nothing" as
    "nothing is granted anywhere" when another named scope was never actually examined
    -- `fully_resolved` must be False here (opaque_scopes non-empty), so both checks
    stay UNKNOWN, not the false PASS a naive "were both tool sets empty" test would
    produce."""
    cfg = {
        "agents": {
            "entries": {
                "main": {"tools": {"deny": ["group:fs"]}},
                "ops": {"tools": {"byProvider": {"openai": {}}}},
            }
        }
    }
    result = _fs_scope_grants(cfg, _B68_FS_TOOLS)
    assert result is not None
    assert result.fully_resolved is False
    assert result.opaque_scopes == ("ops",)
    assert not result.default_tools and not result.declared_tools
    assert _verdicts(cfg) == (UNKNOWN, UNKNOWN, False)


def test_b943_adversarial_every_scope_confined_away_stays_unknown_not_pass():
    """C-135: the other structural edge -- under B68's `confinement=True`, a scope can
    be skipped for being confined rather than for being opaque. If EVERY scope is
    confined away, `checked_scopes` is empty even though `fully_resolved` is True (no
    scope was opaque) -- there is nothing to name a PASS claim against, so this must
    stay UNKNOWN rather than a PASS asserting "verified" over zero actually-examined
    scopes.

    The id-less roster shape is required to actually REACH `_fs_scope_grants`'s
    confinement branch: an id'd agent's own truthy `tools` block is picked up directly
    by G1's per-agent loop (`_b68_fs_tools_granted`'s `scoped`, which does not consider
    confinement at all), so G1 is already enumerable and the per-scope residual never
    runs -- this is also why `test_extra_idless_fs_workspace_only_true_warns_b55_
    unknown_b68_every_scope_confined` above (pre-existing, unchanged by this fix) is
    id-less too. B68's own global short-circuit only covers GLOBAL confinement, and
    does not apply to this per-agent one either, so this config genuinely reaches the
    residual this test targets."""
    cfg = {"agents": {"list": [{"tools": {"fs": {"workspaceOnly": True}}}]}}
    result = _fs_scope_grants(cfg, _B68_FS_TOOLS, confinement=True)
    assert result is not None
    assert result.fully_resolved is True
    assert result.checked_scopes == ()
    _, b68, _ = _verdicts(cfg)
    assert b68 == UNKNOWN
