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
from clawseccheck.checks import check_fs_write_exposure, _b68_fs_tools_granted
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
def test_scoped_fs_write_passes_on_clean_fixture():
    f = _b55(FIXTURES / "clean_b55_fs_write_scoped")
    assert f.status == PASS, f.detail


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


def test_risk12_silent_on_scoped_config():
    ctx, findings, _ = audit(FIXTURES / "clean_b55_fs_write_scoped")
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
