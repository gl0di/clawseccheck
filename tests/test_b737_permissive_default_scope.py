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

def test_r1_d1a_idd_minimal_profile_roster_is_unknown_not_false_warn():
    cfg = {"agents": {"list": [{"id": "main", "tools": {"profile": "minimal"}}]}, **_CH}
    assert _verdicts(cfg) == (UNKNOWN, UNKNOWN, False)


def test_r1_d1b_every_agent_restricts_itself_is_unknown_not_false_warn():
    cfg = {
        "agents": {
            "entries": {
                "main": {"tools": {"deny": ["group:fs"]}},
                "ops": {"tools": {"profile": "messaging"}},
            }
        },
        **_CH,
    }
    assert _verdicts(cfg) == (UNKNOWN, UNKNOWN, False)


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


def test_r1_global_deny_write_family_b55_unknown_b68_warns_declared_read():
    cfg = {"tools": {"deny": ["write", "edit", "apply_patch"]}}
    b55, b68, risk12 = _verdicts(cfg)
    assert (b55, b68, risk12) == (UNKNOWN, WARN, False)
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


def test_r2_idless_minimal_profile_plus_channel_is_unknown():
    cfg = {"agents": {"list": [{"tools": {"profile": "minimal"}}]}, **_CH}
    assert _verdicts(cfg) == (UNKNOWN, UNKNOWN, False)


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

def test_r3_idless_deny_write_family_plus_channel_b55_unknown_b68_warns_read_no_risk():
    cfg = {"agents": {"list": [{"tools": {"deny": ["write", "edit", "apply_patch"]}}]}, **_CH}
    b55, b68, risk12 = _verdicts(cfg)
    assert (b55, b68, risk12) == (UNKNOWN, WARN, False)


def test_r3_idless_deny_group_fs_plus_channel_is_unknown_both():
    cfg = {"agents": {"list": [{"tools": {"deny": ["group:fs"]}}]}, **_CH}
    assert _verdicts(cfg) == (UNKNOWN, UNKNOWN, False)


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


def test_r3_side_finding_named_byprovider_stays_warn_via_g1_not_fixed_here():
    """The one shape this task deliberately does NOT fix (design §6 follow-up #1): G1's
    OWN scoped loop (`_b68_fs_tools_granted`) grants a NAMED agent whose only `tools` key
    is `byProvider` -- it never resolves via `resolved_scopes` (opaque-aware) at all,
    because G1 already finds it "enumerable" first. Filed for 4.3.1; pinned here so a
    future fix has a red test to turn green, and so THIS task cannot be credited with
    fixing it by accident."""
    cfg = {"agents": {"list": [{"id": "main", "tools": {"byProvider": {"openai": {}}}}]}, **_CH}
    b55, b68, risk12 = _verdicts(cfg)
    assert (b55, b68, risk12) == (WARN, WARN, True)


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
    """Verdict-only (design's extras row): `main` is a NAMED agent whose only `tools` key
    is `byProvider`, so this is actually the SAME pre-existing G1 gap as
    `test_r3_side_finding_named_byprovider_stays_warn_via_g1_not_fixed_here` -- G1's own
    `scoped` loop (`_b68_fs_tools_granted`) processes `main` (it has an id and a truthy
    `tools`), calls `toolgrant.granted` on it, and gets a vacuous "everything granted"
    because `_pick_policy` ignores `byProvider` entirely -- so G1 is ALREADY enumerable
    here and `_fs_scope_grants` (this design's own code) never runs. `ops` never appears
    in the evidence because of that, not because of anything B-737 changed; the "scope
    ops only" phrasing in the design's own extras table undersells this interaction. The
    verdict triple is still what the design predicts."""
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


def test_extra_named_minimal_profile_no_channel_is_unknown():
    cfg = {"agents": {"entries": {"main": {"tools": {"profile": "minimal"}}}}}
    assert _verdicts(cfg) == (UNKNOWN, UNKNOWN, False)


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
    `test_extra_idd_unknown_profile_pre_existing_g1_quirk_unaffected` for the id'd
    sibling, unaffected either way). "Messaging" (wrong case, no "exec"/"code"
    substring) isolates the malformed-profile path this design actually added:
    `toolgrant._CORE_TOOL_PROFILES` is case-sensitive, so "Messaging" resolves to
    nothing there, `_block_well_formed` rejects it, and `resolved_scopes` returns
    None -- UNKNOWN, not a guess."""
    cfg = {"agents": {"list": [{"tools": {"profile": "Messaging"}}]}}
    assert _verdicts(cfg) == (UNKNOWN, UNKNOWN, False)
    assert toolgrant.resolved_scopes(cfg) is None


def test_extra_idd_unknown_profile_pre_existing_g1_quirk_unaffected():
    """Pre-existing G1 behaviour (design's own note: file for 4.3.1, low): a named agent
    with a SCHEMA-INVALID `tools.profile` resolves the profile to nothing (unrecognised
    key), which leaves `policies` empty and therefore vacuously grants everything via
    G1's own `toolgrant.granted` call -- untouched by B-737 either way."""
    cfg = {"agents": {"list": [{"id": "main", "tools": {"profile": "Coding"}}]}}
    b55, _, _ = _verdicts(cfg)
    assert b55 == WARN


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
    than the agent's own minimal-profile layer, and misreport provenance/grant."""
    cfg = {"agents": {"list": [{"id": "main", "tools": {"profile": "minimal"}}]}, **_CH}
    assert _verdicts(cfg) == (UNKNOWN, UNKNOWN, False)


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
