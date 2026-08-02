"""B55 / C-013 — filesystem-write tool exposure check + RISK-12 chain.

B55's CheckMeta is advisory (scored=False): the WARN/PASS/UNKNOWN branches name a
broad/ungated fs-write grant and feed RISK-12 (write + untrusted ingress =
tamper/persistence), while the general write/least-privilege dimension stays with the
SCORED checks B3/B22/B31. It must never WARN/FAIL on a genuinely scoped config (§5
zero-false-positive).

B-315 originally downgraded the broad-reach case FAIL->WARN (an unscored check must
never FAIL — Dave's ruling: scored=False caps at WARN). B-376/B-369 (2026-07-31)
re-escalated it: ClawRange's false-negative hunter found real misses on two grounded,
PROVEN-broad-reach mutations, so this branch now follows the B186 narrow-FAIL-override
precedent instead — CheckMeta stays scored=False, and only this one Finding carries
scored=True (see tests/test_b315_unscored_never_fails.py for the cross-check
invariant). Everything short of proven broad reach (an allowlist/paired channel, or no
broad-reach signal at all) is unaffected and still stays WARN.

B-395: the escalation above raised confidence without fixing detection. B55 re-derived
the grant set itself, matching only the legacy, non-canonical alias names in
_FS_WRITE_TOOL_HINTS ("fs_write" is not a real OpenClaw tool id) against a raw list —
so the REAL tool ids (write/edit/apply_patch), group:fs, a wildcard "*" allowlist,
tools.profile, and tools.alsoAllow all produced a confident, lying PASS. Fixed by
delegating grant resolution to _b68_fs_tools_granted (the same helper B68 already uses
for this identical tool family), keeping the legacy aliases as an additional union.
"""
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.collector import collect
from clawseccheck.checks import (
    check_fs_write_exposure,
    _agent_profile_widenings,
    _b68_fs_tools_granted,
)
from clawseccheck.collector import Context
from clawseccheck.risk import risk_paths, _has_exec_or_write_tools

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _by_id(findings):
    return {f.id: f for f in findings}


def _b55_cfg(cfg: dict):
    """B55 against a synthetic in-memory config, no fixture dir needed."""
    ctx = Context(home=None)
    ctx.config = cfg
    return check_fs_write_exposure(ctx)


def _b55(home: Path):
    return check_fs_write_exposure(collect(home))


def _write_config(tmp_path: Path, body: str) -> Path:
    (tmp_path / "openclaw.json").write_text(body, encoding="utf-8")
    return tmp_path


# --------------------------------------------------------------------------- FAIL (B-376/B-369)
def test_broad_fs_write_fails_on_bad_fixture():
    f = _b55(FIXTURES / "bad_b55_fs_write_broad")
    assert f.id == "B55"
    assert f.status == FAIL
    assert f.scored is True  # per-finding override — this specific Finding participates
    assert any("fs_write" in e for e in f.evidence)
    assert any("no approval gate" in e for e in f.evidence)


def test_bad_fixture_b55_is_scored_in_audit_but_checkmeta_is_not():
    """The whole audit must run; this FAIL must be visible to scoring.compute() even
    though CheckMeta.scored stays False for B55's other branches."""
    from clawseccheck.catalog import BY_ID

    assert BY_ID["B55"].scored is False
    _, findings, _ = audit(FIXTURES / "bad_b55_fs_write_broad")
    b55 = _by_id(findings)["B55"]
    assert b55.status == FAIL and b55.scored is True


# --------------------------------------------------------------------------- PASS
# B-410 (gap #2 in the B55 docstring, third C-135 round on this same PASS branch):
# this fixture's tools.exec.mode="ask" gate paired with its declared-but-not-open
# allowlist channel used to clear straight to PASS via the old `not open_ch` test --
# exactly the conflation the docstring names ("channels declared, none proven open"
# treated the same as "no proven ingress at all"). tools.exec.mode is not
# write-specific, so an untrusted-content channel still reaching the write grant
# must WARN, matching the ungated boundary already pinned by
# test_b55_allowlist_channel_does_not_escalate_to_fail. This test used to assert
# PASS on the pre-fix premise; corrected here rather than preserved as a stale pin
# (see test_gated_with_no_channels_declared_stays_pass below for the genuinely
# scoped PASS case this fixture no longer represents).
def test_gated_declared_allowlist_channel_no_longer_passes_on_clean_fixture():
    f = _b55(FIXTURES / "clean_b55_fs_write_scoped")
    assert f.status == WARN, f.detail
    assert f.status != FAIL  # still WARN-capped, not escalated


# The counterpart PASS case B-410 preserves: no channel declared at all (so no proven
# ingress either way, open or merely-allowlisted) plus an approval gate stays a
# defensible PASS -- this is what "clean_b55_fs_write_scoped" was meant to pin before
# its channel policy made it the gap #2 repro instead.
def test_gated_with_no_channels_declared_stays_pass(tmp_path):
    home = _write_config(
        tmp_path,
        '{"tools": {"allow": ["fs_write"], "exec": {"mode": "ask"}}}',
    )
    f = _b55(home)
    assert f.status == PASS, f.detail


# B-410's exact ticket repro: tools.profile "full" (a B-395 grant-detection path) +
# tools.exec.mode "ask" + a channel declared with only dmPolicy="allowlist"/
# groupPolicy="allowlist" (untrusted content reachable, never proven open). Used to
# PASS; must now WARN.
def test_b410_exact_repro_no_longer_passes(tmp_path):
    home = _write_config(
        tmp_path,
        '{"tools": {"profile": "full", "exec": {"mode": "ask"}},'
        ' "channels": {"telegram": {"enabled": true, "dmPolicy": "allowlist",'
        ' "groupPolicy": "allowlist"}}}',
    )
    f = _b55(home)
    assert f.status == WARN, f.detail
    assert f.status != PASS


# B-410's other declared-but-not-open sub-case: a "pairing" dmPolicy channel is
# untrusted content the same way "allowlist" is (_external_input_channels covers
# both), so it must warn under a gate too, matching
# test_b55_paired_channel_does_not_escalate_to_fail's ungated boundary.
def test_gated_paired_channel_declared_still_warns_not_pass(tmp_path):
    home = _write_config(
        tmp_path,
        '{"channels": {"telegram": {"dmPolicy": "pairing"}},'
        ' "tools": {"allow": ["fs_write"], "exec": {"mode": "ask"}}}',
    )
    f = _b55(home)
    assert f.status == WARN, f.detail
    assert f.status != PASS


def test_no_write_tool_passes(tmp_path):
    home = _write_config(tmp_path, '{"tools": {"allow": ["web_fetch", "fs_read"]}}')
    assert _b55(home).status == PASS


# B-395 (C-135 round 2): tools.elevated.allowFrom does not scope write-tool
# reachability at all (grounded: it gates the exec/bash escalation surface only) — a
# tight elevated allowlist alone, with no channels declared at all (so no proven
# reach either way) and no approval gate, is correctly WARN, not a confident PASS.
# This test used to assert PASS on the old (disproven) premise that a tight elevated
# allowlist scopes write access; corrected here rather than preserved as a stale pin.
def test_tight_elevated_allowlist_alone_does_not_grant_pass(tmp_path):
    home = _write_config(
        tmp_path,
        '{"tools": {"allow": ["fs_write"], "elevated": {"allowFrom": ["owner@example.com"]}}}',
    )
    f = _b55(home)
    assert f.status == WARN, f.detail


# C-135 (2026-07-31, original round): the real tools.elevated.allowFrom shape is a
# dict keyed by provider (see B3's check_least_privilege), not the flat list/bare "*"
# form — kept here as a shape-parsing regression test.
#
# B-395 (C-135 round 2, 2026-08-01): a tight (dict-shaped or not) elevated allowlist
# does NOT scope write-tool reachability — an open channel with a write tool granted
# must still FAIL regardless of what tools.elevated.allowFrom says. This test used to
# assert the opposite (PASS); that assertion was itself the bug this round found and
# fixed, not a case to keep passing.
def test_tight_elevated_allowlist_does_not_clear_an_open_channel_fail(tmp_path):
    home = _write_config(
        tmp_path,
        '{"channels": {"telegram": {"dmPolicy": "open"}},'
        ' "tools": {"allow": ["fs_write"], "elevated": '
        '{"allowFrom": {"telegram": ["987654321"]}}}}',
    )
    f = _b55(home)
    assert f.status == FAIL, f.detail
    assert f.scored is True


def test_dict_shaped_wildcard_allowlist_still_fails(tmp_path):
    home = _write_config(
        tmp_path,
        '{"channels": {"telegram": {"dmPolicy": "open"}},'
        ' "tools": {"allow": ["fs_write"], "elevated": '
        '{"allowFrom": {"telegram": ["*"]}}}}',
    )
    f = _b55(home)
    assert f.status == FAIL, f.detail
    assert f.scored is True


# B-395 (C-135 on the FAIL branch, grounded against the installed OpenClaw dist):
# tools.elevated gates the exec/bash privileged-command escalation surface, never
# ordinary write/edit/apply_patch reachability -- it is not one of OpenClaw's tool-
# policy resolution layers. A wildcard tools.elevated.allowFrom with NO open channel
# and NO other untrusted ingress path used to hard-FAIL asserting "reachable by
# untrusted senders" — a factually false claim with zero ingress path in the config.
def test_wildcard_elevated_allowfrom_alone_does_not_fail_without_open_reach(tmp_path):
    home = _write_config(
        tmp_path,
        '{"tools": {"allow": ["write", "edit", "apply_patch"], "elevated": '
        '{"allowFrom": {"telegram": ["*"]}}},'
        ' "channels": {"telegram": {"dmPolicy": "allowlist", "allowFrom": ["123"]}}}',
    )
    f = _b55(home)
    assert f.status != FAIL, f.detail
    assert "reachable by untrusted senders" not in f.detail


def test_wildcard_elevated_allowfrom_alone_does_not_fail_with_elevated_disabled(tmp_path):
    home = _write_config(
        tmp_path,
        '{"tools": {"allow": ["write"], "elevated": '
        '{"enabled": false, "allowFrom": {"telegram": ["*"]}}},'
        ' "channels": {"telegram": {"dmPolicy": "allowlist", "allowFrom": ["123"]}}}',
    )
    f = _b55(home)
    assert f.status != FAIL, f.detail


def test_open_channel_not_scoped_by_exec_gate_fails(tmp_path):
    """B-369's exact mutation: an exec-only approval gate does not scope write tools,
    so it cannot clear an otherwise-broad-reach fs_write grant."""
    home = _write_config(
        tmp_path,
        '{"channels": {"telegram": {"dmPolicy": "open"}},'
        ' "tools": {"allow": ["fs_write"], "exec": {"mode": "ask"}}}',
    )
    f = _b55(home)
    assert f.status == FAIL, f.detail
    assert f.scored is True
    assert any("open-ingress bypasses exec-style approval" in e for e in f.evidence)


# C-135 (2026-07-31): B68 (check_exec_applypatch_workspace, same file) already treats
# tools.fs.workspaceOnly=true / agents.defaults.sandbox.mode="all" as sufficient
# confinement for this identical tool family. An adversarial review of the FAIL
# escalation found B55 never consulted either field, so a workspace-confined or fully
# sandboxed write grant still hard-FAILed as "arbitrary" — downgraded to WARN instead:
# still reachable, but not arbitrary, so not scored=True.
def test_workspace_confined_write_downgrades_to_warn_not_fail(tmp_path):
    home = _write_config(
        tmp_path,
        '{"channels": {"telegram": {"dmPolicy": "open"}},'
        ' "tools": {"allow": ["fs_write"], "fs": {"workspaceOnly": true}}}',
    )
    f = _b55(home)
    assert f.status == WARN, f.detail
    assert f.scored is False
    assert any("confined to the workspace" in e for e in f.evidence)


def test_fully_sandboxed_write_downgrades_to_warn_not_fail(tmp_path):
    home = _write_config(
        tmp_path,
        '{"channels": {"discord": {"dmPolicy": "open", "groupPolicy": "open"}},'
        ' "tools": {"allow": ["apply_patch"]},'
        ' "agents": {"defaults": {"sandbox": {"mode": "all"}}}}',
    )
    f = _b55(home)
    assert f.status == WARN, f.detail
    assert f.scored is False


# --------------------------------------------------------------------------- WARN
def test_ungated_write_without_broad_reach_warns(tmp_path):
    home = _write_config(
        tmp_path,
        '{"channels": {"telegram": {"dmPolicy": "allowlist"}},'
        ' "tools": {"allow": ["apply_patch"]}}',
    )
    f = _b55(home)
    assert f.status == WARN, f.detail
    assert any("apply_patch" in e for e in f.evidence)


# B-057 invariant: the FAIL gate uses _open_channels (open-only) BY DESIGN. An allowlist
# or paired channel is untrusted *content* but not proven-broad reach, so a write tool
# behind one stays WARN — never FAIL. Widening the gate to _external_input_channels would
# flip these to FAIL: a §5 false-positive. These lock that boundary explicitly.
def test_b55_allowlist_channel_does_not_escalate_to_fail(tmp_path):
    home = _write_config(
        tmp_path,
        '{"channels": {"telegram": {"dmPolicy": "allowlist"}},'
        ' "tools": {"allow": ["fs_write"]}}',
    )
    f = _b55(home)
    assert f.status == WARN, f.detail
    assert f.status != FAIL


def test_b55_paired_channel_does_not_escalate_to_fail(tmp_path):
    home = _write_config(
        tmp_path,
        '{"channels": {"telegram": {"dmPolicy": "pairing"}},'
        ' "tools": {"allow": ["fs_write"]}}',
    )
    assert _b55(home).status == WARN


# --------------------------------------------------------------------------- UNKNOWN
def test_no_tool_allowlist_is_unknown(tmp_path):
    home = _write_config(tmp_path, '{"gateway": {"bind": "127.0.0.1:8080"}}')
    f = _b55(home)
    assert f.status == UNKNOWN
    assert "not determinable" not in f.detail  # uses "cannot be enumerated" phrasing
    assert "enumerated" in f.detail


# --------------------------------------------------------------------------- RISK-12
def test_risk12_fires_on_broad_write_plus_untrusted_ingress():
    ctx, findings, _ = audit(FIXTURES / "bad_b55_fs_write_broad")
    ids = {p.id for p in risk_paths(ctx, findings)}
    assert "RISK-12" in ids


# B-410: "clean_b55_fs_write_scoped" declares an allowlist channel (untrusted
# content, never proven open) alongside the write grant, so B55 now correctly WARNs
# on it (see test_gated_declared_allowlist_channel_no_longer_passes_on_clean_fixture)
# -- and RISK-12 (keyed on B55 FAIL/WARN + untrusted ingress) now correctly fires
# too. This test used to assert RISK-12 stayed silent on the pre-fix PASS premise;
# corrected here rather than preserved as a stale pin.
def test_risk12_fires_on_declared_allowlist_channel_gated_config():
    ctx, findings, _ = audit(FIXTURES / "clean_b55_fs_write_scoped")
    ids = {p.id for p in risk_paths(ctx, findings)}
    assert "RISK-12" in ids


# The counterpart RISK-12-stays-silent case B-410 preserves: no channel declared at
# all, so B55 genuinely PASSes (test_gated_with_no_channels_declared_stays_pass) and
# RISK-12 has no ingress leg to fire on.
def test_risk12_silent_when_no_channels_declared(tmp_path):
    home = _write_config(
        tmp_path,
        '{"tools": {"allow": ["fs_write"], "exec": {"mode": "ask"}}}',
    )
    ctx, findings, _ = audit(home)
    ids = {p.id for p in risk_paths(ctx, findings)}
    assert "RISK-12" not in ids


def test_risk_hint_recognizes_canonical_write_tool_names():
    """B-395 blast radius: risk.py's own _hint tuples had the identical naming gap —
    RISK-01/03/12 silently dropped on a canonical (non-"fs_write"-aliased) grant."""
    assert _has_exec_or_write_tools(["fs_write"])  # legacy alias, unchanged
    assert _has_exec_or_write_tools(["write"])
    assert _has_exec_or_write_tools(["edit"])


def test_risk_hint_does_not_substring_match_bare_write_or_edit(tmp_path):
    """C-135 on the risk.py fix itself: folding bare "write"/"edit" into _hint()'s
    SUBSTRING tuple (rather than exact list membership) produced a CRITICAL RISK-01
    false alarm on any tool name merely containing those fragments as substrings
    ("edit" ⊂ "credit_score", "write" ⊂ "underwriter"/"copywriter") — real tool names
    with zero relation to filesystem writes."""
    for benign_tool in ("check_credit_score", "underwriter_lookup", "copywriter_assistant"):
        assert not _has_exec_or_write_tools([benign_tool, "web_search"]), benign_tool


def test_risk01_does_not_fire_on_a_benign_tool_name_containing_write_substring(tmp_path):
    home = _write_config(
        tmp_path,
        '{"channels": {"telegram": {"dmPolicy": "open"}},'
        ' "tools": {"allow": ["underwriter_lookup", "web_search"]}}',
    )
    ctx, findings, _ = audit(home)
    ids = {p.id for p in risk_paths(ctx, findings)}
    assert "RISK-01" not in ids
    assert "RISK-03" not in ids


# --------------------------------------------------------------------- B-395 direction 1
# lying PASS on the canonical tool names / wildcard / unenumerable allowlist shapes.

def test_canonical_write_tool_name_is_detected(tmp_path):
    home = _write_config(tmp_path, '{"tools": {"allow": ["write"]}}')
    f = _b55(home)
    assert f.status != PASS, f.detail
    assert "write" in f.evidence[0]


def test_canonical_edit_tool_name_is_detected(tmp_path):
    home = _write_config(tmp_path, '{"tools": {"allow": ["edit"]}}')
    assert _b55(home).status != PASS


def test_canonical_apply_patch_tool_name_is_detected(tmp_path):
    home = _write_config(tmp_path, '{"tools": {"allow": ["apply_patch"]}}')
    assert _b55(home).status != PASS


def test_group_fs_allowlist_token_is_detected(tmp_path):
    home = _write_config(tmp_path, '{"tools": {"allow": ["group:fs"]}}')
    assert _b55(home).status != PASS


def test_wildcard_allowlist_token_is_detected(tmp_path):
    home = _write_config(tmp_path, '{"tools": {"allow": ["*"]}}')
    f = _b55(home)
    assert f.status != PASS, (
        f"a wildcard allowlist grants EVERY tool, including write -- got PASS: {f.detail}"
    )


def test_scalar_allow_shape_is_unknown_not_pass(tmp_path):
    home = _write_config(tmp_path, '{"tools": {"allow": "fs_write"}}')
    f = _b55(home)
    assert f.status == UNKNOWN, f.detail


def test_mapping_allow_shape_is_unknown_not_pass(tmp_path):
    home = _write_config(tmp_path, '{"tools": {"allow": {"fs_write": true}}}')
    f = _b55(home)
    assert f.status == UNKNOWN, f.detail


def test_denied_legacy_alias_does_not_count_as_granted(tmp_path):
    home = _write_config(
        tmp_path,
        '{"tools": {"allow": ["fs_write", "web_fetch"], "deny": ["fs_write"]}}',
    )
    f = _b55(home)
    assert f.status == PASS, f.detail


def test_powerful_profile_alone_is_now_enumerable_not_unknown(tmp_path):
    """A pure side-effect of delegating to _b68_fs_tools_granted: a powerful
    tools.profile with no explicit allowlist at all is enumerable (matches B68's own
    behavior for the identical config shape), not an unconditional UNKNOWN."""
    home = _write_config(tmp_path, '{"tools": {"profile": "full"}}')
    f = _b55(home)
    assert f.status != UNKNOWN, f.detail


# --------------------------------------------------------------------- B-395 round 2
# C-135 found the four new grant-detection paths (wildcard/group:fs/profile/alsoAllow)
# were only ever exercised through the bottom bare-WARN fallback (no channels, no
# elevated field at all) -- never through the actual open_ch/fs_confined decision
# tree, which is exactly how the tight_allowlist false-PASS bug slipped through. These
# run each new path through open_ch=True (unconfined -> FAIL) and confined (-> WARN).

@pytest.mark.parametrize(
    "tools_json",
    [
        '{"allow": ["*"]}',
        '{"allow": ["group:fs"]}',
        '{"profile": "full"}',
        '{"allow": ["read"], "alsoAllow": ["write"]}',
    ],
    ids=["wildcard", "group_fs", "profile", "alsoAllow"],
)
def test_new_grant_path_open_channel_unconfined_fails(tmp_path, tools_json):
    home = _write_config(
        tmp_path,
        '{"channels": {"telegram": {"dmPolicy": "open"}}, "tools": ' + tools_json + "}",
    )
    f = _b55(home)
    assert f.status == FAIL, f.detail
    assert f.scored is True


@pytest.mark.parametrize(
    "tools_json",
    [
        '{"allow": ["*"], "fs": {"workspaceOnly": true}}',
        '{"allow": ["group:fs"], "fs": {"workspaceOnly": true}}',
        '{"profile": "full", "fs": {"workspaceOnly": true}}',
        '{"allow": ["read"], "alsoAllow": ["write"], "fs": {"workspaceOnly": true}}',
    ],
    ids=["wildcard", "group_fs", "profile", "alsoAllow"],
)
def test_new_grant_path_open_channel_confined_warns_not_fails(tmp_path, tools_json):
    home = _write_config(
        tmp_path,
        '{"channels": {"telegram": {"dmPolicy": "open"}}, "tools": ' + tools_json + "}",
    )
    f = _b55(home)
    assert f.status == WARN, f.detail
    assert f.scored is False


# B-410 third dimension on this same new-grant-path matrix: a channel that is
# DECLARED but only dmPolicy="allowlist" (untrusted content, never proven open) plus
# a gated tools.exec.mode used to clear straight to PASS for every one of the four
# B-395 grant-detection paths -- the same conflation gap #2 in the B55 docstring
# describes, now closed. Every path here must WARN, not PASS.
@pytest.mark.parametrize(
    "tools_json",
    [
        '{"allow": ["*"], "exec": {"mode": "ask"}}',
        '{"allow": ["group:fs"], "exec": {"mode": "ask"}}',
        '{"profile": "full", "exec": {"mode": "ask"}}',
        '{"allow": ["read"], "alsoAllow": ["write"], "exec": {"mode": "ask"}}',
    ],
    ids=["wildcard", "group_fs", "profile", "alsoAllow"],
)
def test_new_grant_path_declared_not_open_channel_gated_warns_not_pass(tmp_path, tools_json):
    home = _write_config(
        tmp_path,
        '{"channels": {"telegram": {"dmPolicy": "allowlist"}}, "tools": ' + tools_json + "}",
    )
    f = _b55(home)
    assert f.status == WARN, f.detail
    assert f.status != PASS


def test_b55_and_b68_never_disagree_on_the_same_config():
    """The ticket's own test-plan requirement: B55 and _b68_fs_tools_granted must
    agree on whether a write-capable tool is granted for the same config shape (up to
    B55's own narrower write-only subset and its additional legacy-alias union)."""
    matrix = [
        {"tools": {"allow": ["write"]}},
        {"tools": {"allow": ["edit"]}},
        {"tools": {"allow": ["read"]}},
        {"tools": {"allow": ["apply_patch"]}},
        {"tools": {"allow": ["group:fs"]}},
        {"tools": {"allow": ["*"]}},
        {"tools": {"profile": "full"}},
        {"tools": {"profile": "minimal"}},
        {"tools": {"alsoAllow": ["write"]}},
        {},
    ]
    for cfg in matrix:
        granted, enumerable = _b68_fs_tools_granted(cfg)
        b55 = _b55_cfg(cfg)
        b68_says_write_granted = enumerable and bool(set(granted) & {"write", "edit", "apply_patch"})
        b55_says_write_granted = b55.status != UNKNOWN and b55.status != PASS
        assert b68_says_write_granted == b55_says_write_granted, (
            f"disagreement on {cfg}: B68 granted={granted} enumerable={enumerable}, "
            f"B55 status={b55.status} detail={b55.detail!r}"
        )


def test_b44_b55_b68_b84_all_agree_alsoallow_and_gateway_shapes():
    """B-423/B-411 cross-check invariant: B44/B55/B68/B84 now all resolve the global
    tools.* layer through one shared _tool_policy_view (checks/_capability.py) instead
    of four independent accumulators. This asserts they never disagree on whether a
    given config's alsoAllow-only implicit-wildcard grant (B-411) or gateway.tools.allow
    de-denylist (B-423, never an additive grant) reaches "everything is granted" --
    covering exactly the two shapes the fixture corpus has zero coverage of
    (`grep -rl alsoAllow fixtures/` -> 0 files)."""
    from clawseccheck.checks import (
        _profile_is_powerful,
        _tool_policy_view,
        check_attestation_mismatch,
        check_declared_effective_proven,
        check_exec_applypatch_workspace,
    )

    matrix = [
        {"tools": {"alsoAllow": ["read"]}},  # implicit wildcard: grants everything
        {"tools": {"alsoAllow": ["write"]}},  # implicit wildcard: grants everything
        {"tools": {"profile": "minimal", "alsoAllow": ["read"]}},  # profile guard: narrow
        {"tools": {"profile": "coding", "alsoAllow": ["read"]}},  # powerful profile: full
        {"gateway": {"tools": {"allow": ["write", "exec"]}}},  # de-denylist only: no grant
        {"tools": {"allow": ["read"]}, "gateway": {"tools": {"allow": ["exec"]}}},  # gateway ignored
        {"tools": {"allow": ["apply_patch"], "deny": ["apply-patch"]}},  # alias-folded deny
    ]
    att = {"tools": ["read"], "proven_tools": ["read"], "untrusted_to_action": "gated"}
    all_tools_universe = {"read", "write", "edit", "apply_patch"}
    for cfg in matrix:
        view = _tool_policy_view(cfg)
        expected_fs = (
            all_tools_universe
            if (view.grants_all or "group:fs" in view.named)
            else (set(view.named) & all_tools_universe)
        )
        if view.profile is not None and _profile_is_powerful(view.profile):
            expected_fs = expected_fs | all_tools_universe
        expected_fs = expected_fs - view.denied

        granted, enumerable = _b68_fs_tools_granted(cfg)
        assert not enumerable or set(granted) == expected_fs, (cfg, granted, expected_fs)

        b55 = _b55_cfg(cfg)
        b55_says_write = b55.status not in (UNKNOWN, PASS)
        expects_write = bool(expected_fs & {"write", "edit", "apply_patch"})
        assert b55_says_write == expects_write, (cfg, b55.status, expected_fs)

        b68 = check_exec_applypatch_workspace(Context(home=None, config=cfg))
        b68_says_granted = b68.status == WARN and enumerable and bool(granted)
        assert b68_says_granted == (enumerable and bool(expected_fs)), (cfg, b68.status, expected_fs)

        # B44/B84 never claim a tool absent from view.named -- grants_all has no
        # enumerable token, so it never appears in either check's evidence.
        b44 = check_attestation_mismatch(Context(home=None, config=cfg, attestation=att))
        for ev in b44.evidence or []:
            assert not ev.startswith("granted but not attested") or any(
                t in ev for t in view.named
            ), (cfg, ev, view.named)

        b84 = check_declared_effective_proven(Context(home=None, config=cfg, attestation=att))
        for ev in b84.evidence or []:
            if "never proven" not in ev:
                continue
            assert any(t in ev for t in view.named) or not view.named, (cfg, ev, view.named)


# --------------------------------------------------------------------------- B-409
# Per-agent tools.profile WIDENING: the one policy layer this module's grant model was
# blind to that can produce a false PASS rather than a merely-missed WARN (every other
# per-agent/per-channel/per-sender layer this file doesn't read is narrowing-only,
# tool-policy-match-CgU98OQh.js:32-34). Grounded: agents.list[N].tools.profile is
# `??`-coalesced against the global tools.profile (agent-tools.policy-YD9HuYgO.js:94,
# :232) -- it REPLACES the global profile in the AND-ed policies[] list rather than
# adding a second, narrowing entry, so a global "minimal" + per-agent "coding" grants
# write/edit/apply_patch to that agent even though the global layer alone grants
# nothing. Deliberately WARN-only: this can push a verdict from PASS toward WARN, but
# it never sets explicit_write_grant, so it cannot alone drive a FAIL -- the seven
# still-unread narrowing layers (per-agent allow/deny, channel/group, toolsBySender,
# byProvider) could remove the grant for that specific agent, unseen by this check.


def test_agent_profile_widenings_empty_with_no_agents_declared():
    assert _agent_profile_widenings({"tools": {"profile": "minimal"}}) == []
    assert _agent_profile_widenings({}) == []


def test_agent_profile_widenings_silent_when_global_already_powerful():
    cfg = {
        "tools": {"profile": "coding"},
        "agents": {"list": [{"id": "a", "tools": {"profile": "full"}}]},
    }
    assert _agent_profile_widenings(cfg) == []


def test_agent_profile_widenings_silent_on_a_narrowing_override():
    cfg = {
        "tools": {"profile": "coding"},
        "agents": {"list": [{"id": "a", "tools": {"profile": "minimal"}}]},
    }
    assert _agent_profile_widenings(cfg) == []


def test_agent_profile_widenings_detects_a_widening_override():
    cfg = {
        "tools": {"profile": "minimal"},
        "agents": {"list": [{"id": "worker", "tools": {"profile": "coding"}}]},
    }
    assert _agent_profile_widenings(cfg) == [("agents.list[0].tools.profile", "coding")]


def test_agent_profile_widenings_detects_multiple_agents_independently():
    cfg = {
        "tools": {},
        "agents": {
            "list": [
                {"id": "a", "tools": {"profile": "minimal"}},
                {"id": "b", "tools": {"profile": "full"}},
                {"id": "c"},
            ]
        },
    }
    assert _agent_profile_widenings(cfg) == [("agents.list[1].tools.profile", "full")]


def test_agent_profile_widenings_tolerates_malformed_shapes():
    # agents.list not a list, entries not dicts, profile not a non-empty string --
    # none of these should raise, all should be silently skipped.
    assert _agent_profile_widenings({"agents": {"list": "not-a-list"}}) == []
    assert _agent_profile_widenings({"agents": {"list": [None, "x", 5]}}) == []
    assert _agent_profile_widenings(
        {"agents": {"list": [{"id": "a", "tools": {"profile": ""}}]}}
    ) == []
    assert _agent_profile_widenings(
        {"agents": {"list": [{"id": "a", "tools": {"profile": 7}}]}}
    ) == []


def test_b68_fs_tools_granted_widening_makes_an_otherwise_blind_config_enumerable():
    # No global grant signal at all -- would be ([], False) before B-409.
    cfg = {"agents": {"list": [{"id": "worker", "tools": {"profile": "coding"}}]}}
    granted, enumerable = _b68_fs_tools_granted(cfg)
    assert enumerable is True
    assert set(granted) >= {"write", "edit", "apply_patch"}


def test_b68_fs_tools_granted_widening_does_not_defeat_a_global_deny():
    # A global group:fs deny is its own AND-ed policy layer in OpenClaw's real
    # resolver -- always intersects, regardless of which profile substitutes in.
    cfg = {
        "tools": {"deny": ["group:fs"]},
        "agents": {"list": [{"id": "worker", "tools": {"profile": "coding"}}]},
    }
    granted, enumerable = _b68_fs_tools_granted(cfg)
    assert granted == []
    assert enumerable is True


def test_b68_fs_tools_granted_widening_intersects_a_real_global_allowlist():
    # C-135 round 2's exact repro at the unit level: a non-empty, non-wildcard global
    # tools.allow is its own separate AND-ed policy layer and must bound the widened
    # profile grant, not be overridden by it.
    cfg = {
        "tools": {"allow": ["read", "write"], "deny": ["write"]},
        "agents": {"list": [{"id": "coder", "tools": {"profile": "coding"}}]},
    }
    granted, enumerable = _b68_fs_tools_granted(cfg)
    assert granted == ["read"]
    assert enumerable is True


def test_b68_fs_tools_granted_widening_unaffected_by_a_wildcard_global_allow():
    cfg = {
        "tools": {"allow": ["*"]},
        "agents": {"list": [{"id": "coder", "tools": {"profile": "coding"}}]},
    }
    granted, enumerable = _b68_fs_tools_granted(cfg)
    assert set(granted) == {"read", "write", "edit", "apply_patch"}
    assert enumerable is True


def test_b68_fs_tools_granted_widening_full_when_global_allow_absent():
    cfg = {"agents": {"list": [{"id": "coder", "tools": {"profile": "coding"}}]}}
    granted, enumerable = _b68_fs_tools_granted(cfg)
    assert set(granted) == {"read", "write", "edit", "apply_patch"}
    assert enumerable is True


def test_b55_widening_alone_warns_not_pass_not_fail_on_open_channel(tmp_path):
    home = _write_config(
        tmp_path,
        '{"channels": {"telegram": {"dmPolicy": "open"}},'
        ' "tools": {"profile": "minimal"},'
        ' "agents": {"list": [{"id": "worker", "tools": {"profile": "coding"}}]}}',
    )
    f = _b55(home)
    assert f.status == WARN, f.detail
    assert f.status != FAIL
    assert f.scored is False
    assert any("tools.profile widening" in e or "B-409" in e for e in f.evidence)


def test_b55_widening_stays_pass_when_no_channel_declared_and_gated(tmp_path):
    home = _write_config(
        tmp_path,
        '{"tools": {"profile": "minimal", "exec": {"mode": "ask"}},'
        ' "agents": {"list": [{"id": "worker", "tools": {"profile": "coding"}}]}}',
    )
    f = _b55(home)
    assert f.status == PASS, f.detail


def test_b55_narrowing_per_agent_profile_does_not_disturb_verdict():
    # Unchanged from pre-B-409 behavior: global "coding" already grants write
    # explicitly; the narrower per-agent profile is not modelled (accepted gap #1)
    # and must not be mistaken for a widening either -- _agent_profile_widenings
    # correctly returns [] here (global already powerful), so the verdict is driven
    # entirely by the pre-existing global-profile grant path, unchanged by this fix.
    f = _b55_cfg(
        {
            "tools": {"profile": "coding", "exec": {"mode": "ask"}},
            "agents": {"list": [{"id": "reader", "tools": {"profile": "minimal"}}]},
        }
    )
    assert f.status == PASS, f.detail


def test_clean_agent_profile_narrower_fixture_passes():
    f = _b55(FIXTURES / "clean_agent_profile_narrower")
    assert f.status == PASS, f.detail


def test_warn_b55_agent_profile_widens_fixture_warns_not_fails():
    f = _b55(FIXTURES / "warn_b55_agent_profile_widens")
    assert f.status == WARN, f.detail
    assert f.status != FAIL


# --------------------------------------------------------- B-409 C-135 round 2
# CONFIRMED false FAIL, found by an independent adversarial review of the first
# version of the widening fix above: `tools.allow: ["read","write"], deny: ["write"]`
# plus a powerful per-agent profile used to FAIL (scored=True) on a config whose TRUE
# effective grant is exactly {"read"}. Root cause: `pickSandboxToolPolicy(cfg.tools)`
# (the tools.allow/alsoAllow/deny layer) is its OWN separate, always-pushed, AND-ed
# policy entry in OpenClaw's real resolver (agent-tools.policy-YD9HuYgO.js:92-98) --
# independent of which profile substitutes in. The first version unioned the WHOLE
# fs-tool family into `granted` whenever a widening existed, ignoring that a real,
# non-empty global tools.allow still constrains what the widened profile can reach.
# Fixed by intersecting the widening with view.named when it is a real, non-empty,
# non-wildcard allowlist (see _b68_fs_tools_granted's docstring for the full account).
def test_b409_c135_exact_repro_no_longer_fails(tmp_path):
    home = _write_config(
        tmp_path,
        '{"tools": {"allow": ["read", "write"], "deny": ["write"]},'
        ' "agents": {"list": [{"id": "coder", "tools": {"profile": "coding"}}]},'
        ' "channels": {"telegram": {"enabled": true, "dmPolicy": "open"}}}',
    )
    granted, enumerable = _b68_fs_tools_granted(
        {
            "tools": {"allow": ["read", "write"], "deny": ["write"]},
            "agents": {"list": [{"id": "coder", "tools": {"profile": "coding"}}]},
        }
    )
    assert granted == ["read"], granted
    f = _b55(home)
    assert f.status == PASS, f.detail
    assert f.status != FAIL


def test_b409_c135_multi_token_deny_variant_no_longer_fails(tmp_path):
    # The reviewer's variant B: multiple write-family tokens named AND denied.
    home = _write_config(
        tmp_path,
        '{"tools": {"allow": ["read", "write", "edit"], "deny": ["write", "edit"]},'
        ' "agents": {"list": [{"id": "coder", "tools": {"profile": "coding"}}]},'
        ' "channels": {"telegram": {"dmPolicy": "open"}}}',
    )
    f = _b55(home)
    assert f.status == PASS, f.detail


def test_b409_widening_still_applies_when_global_allow_is_a_wildcard(tmp_path):
    # grants_all (explicit "*") imposes no restriction on this axis, so the widening
    # should still apply without intersection -- confirms the fix isn't over-corrected
    # into never widening through a genuinely permissive global allow layer.
    home = _write_config(
        tmp_path,
        '{"tools": {"allow": ["*"]},'
        ' "agents": {"list": [{"id": "coder", "tools": {"profile": "coding"}}]},'
        ' "channels": {"telegram": {"dmPolicy": "open"}}}',
    )
    f = _b55(home)
    assert f.status == FAIL, f.detail  # "*" alone is already an explicit grant


def test_b409_profile_substring_false_positive_stays_bounded_by_allowlist(tmp_path):
    # _profile_is_powerful's substring fallback matches "code" anywhere, including
    # "barcode-reader" -- a real false-positive widening detection. It must stay
    # harmless because the corrected fix intersects with the real global allowlist
    # regardless of whether the widening detection itself is precise.
    home = _write_config(
        tmp_path,
        '{"tools": {"allow": ["read", "write"], "deny": ["write"]},'
        ' "agents": {"list": [{"id": "x", "tools": {"profile": "barcode-reader"}}]},'
        ' "channels": {"telegram": {"dmPolicy": "open"}}}',
    )
    f = _b55(home)
    assert f.status == PASS, f.detail


def test_b409_explicit_write_grant_ignores_a_denied_named_token(tmp_path):
    # Direct regression for the explicit_write_grant deny-subtraction fix: a write
    # token that is BOTH named in tools.allow AND denied must not count as "explicit"
    # on its own (matching legacy_write's existing deny-subtracted pattern).
    home = _write_config(
        tmp_path,
        '{"tools": {"allow": ["write"], "deny": ["write"]},'
        ' "channels": {"telegram": {"dmPolicy": "open"}}}',
    )
    f = _b55(home)
    assert f.status == PASS, f.detail


def test_b409_evidence_does_not_assert_widening_when_no_global_profile_set(tmp_path):
    # GR#4: evidence must not assert "widens beyond the global tools.profile" when no
    # global tools.profile was declared at all -- there is nothing to widen beyond.
    home = _write_config(
        tmp_path,
        '{"agents": {"list": [{"id": "worker", "tools": {"profile": "coding"}}]},'
        ' "channels": {"telegram": {"dmPolicy": "open"}}}',
    )
    f = _b55(home)
    assert f.status == WARN, f.detail
    assert any("no global tools.profile is set" in e for e in f.evidence)
    assert not any("widens beyond the global tools.profile" in e for e in f.evidence)


def test_b409_evidence_asserts_widening_when_global_profile_is_weak(tmp_path):
    home = _write_config(
        tmp_path,
        '{"tools": {"profile": "minimal"},'
        ' "agents": {"list": [{"id": "worker", "tools": {"profile": "coding"}}]},'
        ' "channels": {"telegram": {"dmPolicy": "open"}}}',
    )
    f = _b55(home)
    assert f.status == WARN, f.detail
    assert any("widens beyond the global tools.profile" in e for e in f.evidence)
