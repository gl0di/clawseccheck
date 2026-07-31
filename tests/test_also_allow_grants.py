"""tools.alsoAllow -- additive third tool-grant source (I-028).

OpenClaw's schema FORBIDS tools.allow + tools.alsoAllow together and RECOMMENDS
tools.profile + tools.alsoAllow instead, so the schema-recommended real-world shape
carries an EMPTY tools.allow / gateway.tools.allow and grants everything through
alsoAllow. Before this change, B44/B68/B84 read only tools.allow/gateway.tools.allow
(an 'or'-chain that also only ever took the first truthy source) and so read that
recommended shape as granting nothing.

This adds a THIRD additive grant channel, which only ever WIDENS what a check sees
as granted -- so the hazard this file's job is to try to trigger is a NEW wrong
WARN/FAIL on a legitimate config, not a missed one. The single subtlest case is a
POWERFUL tools.profile (already grants every fs tool) plus a narrow alsoAllow: the
narrow token must never narrow that verdict back down (pinned explicitly below).

Offline, deterministic, stdlib only (+ pytest for parametrize).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    _b68_fs_tools_granted,
    check_attestation_mismatch,
    check_declared_effective_proven,
    check_exec_applypatch_workspace,
)
from clawseccheck.collector import Context


def _ctx(config=None, attestation=None):
    return Context(home=Path("/nonexistent"), config=config or {}, attestation=attestation or {})


# =====================================================================================
# _b68_fs_tools_granted -- direct unit tests of the accumulator (B-283 (b) / I-028)
# =====================================================================================

def test_helper_alsoallow_narrow_harmless_tool_does_not_widen_enumerability():
    # clean: alsoAllow names only a non-fs-family tool -> no new grant, not enumerable.
    granted, enumerable = _b68_fs_tools_granted({"tools": {"alsoAllow": ["search"]}})
    assert granted == []
    assert enumerable is False


def test_helper_alsoallow_broad_fs_tool_with_empty_allow_now_grants():
    # bad: EMPTY tools.allow, alsoAllow grants a broad/dangerous fs tool.
    granted, enumerable = _b68_fs_tools_granted({"tools": {"allow": [], "alsoAllow": ["write"]}})
    assert enumerable is True
    assert granted == ["write"]

    # Equivalent tools.allow-only-visible config: the old or-chain never read
    # tools.alsoAllow at all, so an empty tools.allow with alsoAllow simply absent is
    # exactly what the pre-I-028 reader effectively saw for this config -- not
    # enumerable, i.e. it could NOT have produced the WARN this grant now causes.
    granted_old, enumerable_old = _b68_fs_tools_granted({"tools": {"allow": []}})
    assert enumerable_old is False
    assert granted_old == []


def test_helper_dedupes_same_tool_in_allow_and_alsoallow():
    granted, enumerable = _b68_fs_tools_granted(
        {"tools": {"allow": ["write"], "alsoAllow": ["write"]}}
    )
    assert enumerable is True
    assert granted == ["write"]


def test_helper_deny_wins_over_alsoallow():
    granted, enumerable = _b68_fs_tools_granted(
        {"tools": {"alsoAllow": ["write", "read"], "deny": ["write"]}}
    )
    assert enumerable is True
    assert granted == ["read"]


def test_helper_group_fs_deny_beats_group_fs_alsoallow():
    granted, enumerable = _b68_fs_tools_granted(
        {"tools": {"alsoAllow": ["group:fs"], "deny": ["group:fs"]}}
    )
    assert granted == []
    assert enumerable is True


def test_helper_group_fs_in_alsoallow_grants_whole_family_minus_denied():
    granted, enumerable = _b68_fs_tools_granted(
        {"tools": {"alsoAllow": ["group:fs"], "deny": ["write"]}}
    )
    assert enumerable is True
    assert granted == sorted({"read", "edit", "apply_patch"})


def test_helper_powerful_profile_plus_narrow_alsoallow_does_not_narrow():
    # THE subtlest hazard: a POWERFUL profile already grants every fs tool; a narrow
    # alsoAllow must only ever WIDEN, never narrow that verdict down to its own tokens.
    granted, enumerable = _b68_fs_tools_granted(
        {"tools": {"profile": "coding", "alsoAllow": ["read"]}}
    )
    assert enumerable is True
    assert granted == sorted({"read", "write", "edit", "apply_patch"})


def test_helper_non_powerful_profile_plus_alsoallow_still_adds_narrow_grant():
    # Additive in the other direction too: a non-powerful profile grants nothing on its
    # own, but alsoAllow still adds exactly what it names (never more).
    granted, enumerable = _b68_fs_tools_granted(
        {"tools": {"profile": "minimal", "alsoAllow": ["read"]}}
    )
    assert enumerable is True
    assert granted == ["read"]


def test_helper_unknown_preserved_when_alsoallow_names_no_fs_tool():
    # No allowlist, no profile, alsoAllow names something outside the fs family -> must
    # stay not-enumerable (never a fake PASS/empty-grant claim).
    granted, enumerable = _b68_fs_tools_granted({"tools": {"alsoAllow": ["network_search"]}})
    assert enumerable is False
    assert granted == []


@pytest.mark.parametrize(
    "bad_also_allow",
    [
        None,
        "",
        "write",
        {},
        {"write": True},
        [1, None, {"a": 1}, ["nested", {"deep": [1, 2, {"deeper": None}]}]],
        True,
        3.14,
        [None, None, None],
    ],
)
def test_helper_malformed_alsoallow_shapes_do_not_raise(bad_also_allow):
    granted, enumerable = _b68_fs_tools_granted({"tools": {"alsoAllow": bad_also_allow}})
    assert isinstance(granted, list)
    assert isinstance(enumerable, bool)


# =====================================================================================
# check_exec_applypatch_workspace (B68) -- end to end through the real check function
# =====================================================================================

def test_b68_check_clean_alsoallow_narrow_harmless_tool_stays_unknown():
    f = check_exec_applypatch_workspace(_ctx({"tools": {"alsoAllow": ["search"]}}))
    assert f.status == UNKNOWN


def test_b68_check_bad_empty_allow_alsoallow_broad_fs_tool_warns():
    f = check_exec_applypatch_workspace(
        _ctx({"tools": {"allow": [], "alsoAllow": ["write"]}})
    )
    assert f.status == WARN
    granted_evidence = next(e for e in f.evidence if e.startswith("filesystem tools granted"))
    assert granted_evidence == "filesystem tools granted: write"

    # Equivalent old-or-chain-visible config: EMPTY tools.allow, no profile, alsoAllow
    # wasn't a recognised grant source pre-I-028 -> not enumerable, so the old code
    # could not have produced this WARN for the schema-recommended allow-empty shape.
    f_old = check_exec_applypatch_workspace(_ctx({"tools": {"allow": []}}))
    assert f_old.status == UNKNOWN


def test_b68_check_dedupes_same_tool_in_allow_and_alsoallow():
    f = check_exec_applypatch_workspace(
        _ctx({"tools": {"allow": ["write"], "alsoAllow": ["write"]}})
    )
    assert f.status == WARN
    granted_evidence = next(e for e in f.evidence if e.startswith("filesystem tools granted"))
    assert granted_evidence == "filesystem tools granted: write"


def test_b68_check_deny_wins_over_alsoallow():
    f = check_exec_applypatch_workspace(
        _ctx({"tools": {"alsoAllow": ["write", "read"], "deny": ["write"]}})
    )
    assert f.status == WARN
    granted_evidence = next(e for e in f.evidence if e.startswith("filesystem tools granted"))
    assert granted_evidence == "filesystem tools granted: read"


def test_b68_check_group_fs_deny_beats_group_fs_alsoallow():
    f = check_exec_applypatch_workspace(
        _ctx({"tools": {"alsoAllow": ["group:fs"], "deny": ["group:fs"]}})
    )
    assert f.status == PASS


def test_b68_check_group_fs_alsoallow_grants_whole_family_minus_denied():
    f = check_exec_applypatch_workspace(
        _ctx({"tools": {"alsoAllow": ["group:fs"], "deny": ["write"]}})
    )
    assert f.status == WARN
    granted_evidence = next(e for e in f.evidence if e.startswith("filesystem tools granted"))
    assert granted_evidence == "filesystem tools granted: apply_patch, edit, read"


def test_b68_check_powerful_profile_plus_narrow_alsoallow_keeps_full_family():
    # Pinned explicitly per spec: the narrow alsoAllow token must not narrow a
    # POWERFUL profile's "every fs tool granted" verdict down to just itself.
    f = check_exec_applypatch_workspace(
        _ctx({"tools": {"profile": "coding", "alsoAllow": ["read"]}})
    )
    assert f.status == WARN
    granted_evidence = next(e for e in f.evidence if e.startswith("filesystem tools granted"))
    assert granted_evidence == "filesystem tools granted: apply_patch, edit, read, write"


@pytest.mark.parametrize(
    "bad_also_allow",
    [None, "", "write", {}, [1, None, {"a": 1}, ["nested"]], True, 3.14],
)
def test_b68_check_malformed_alsoallow_does_not_raise(bad_also_allow):
    f = check_exec_applypatch_workspace(_ctx({"tools": {"alsoAllow": bad_also_allow}}))
    assert f.status in (PASS, WARN, UNKNOWN)


# =====================================================================================
# check_attestation_mismatch (B44) -- alsoAllow folds into the granted allow-list
# =====================================================================================

def test_b44_clean_alsoallow_narrow_harmless_tool_passes():
    cfg = {"tools": {"alsoAllow": ["search_threads"]}}
    att = {"tools": ["search_threads"]}
    f = check_attestation_mismatch(_ctx(config=cfg, attestation=att))
    assert f.status == PASS


def test_b44_bad_alsoallow_undisclosed_high_blast_tool_warns():
    cfg = {"tools": {"allow": [], "alsoAllow": ["send_email"]}}
    att = {"tools": ["search"]}
    f = check_attestation_mismatch(_ctx(config=cfg, attestation=att))
    assert f.status == WARN
    assert any("send_email" in e for e in f.evidence)

    # Equivalent old-or-chain-visible config: empty tools.allow, gateway.tools.allow
    # and alsoAllow both absent -> nothing listed at all -> UNKNOWN. The old code could
    # not have raised this WARN for the recommended allow-empty/alsoAllow-granting shape.
    cfg_old = {"tools": {"allow": []}}
    f_old = check_attestation_mismatch(_ctx(config=cfg_old, attestation=att))
    assert f_old.status == UNKNOWN


def test_b44_dedupes_same_tool_in_allow_and_alsoallow():
    cfg = {"tools": {"allow": ["send_email"], "alsoAllow": ["send_email"]}}
    att = {"tools": ["search"]}
    f = check_attestation_mismatch(_ctx(config=cfg, attestation=att))
    assert f.status == WARN
    matches = [e for e in f.evidence if "send_email" in e]
    assert len(matches) == 1


def test_b44_alsoallow_merges_with_gateway_allow_not_or_chained():
    # Both tools.alsoAllow and gateway.tools.allow name (different) undisclosed
    # high-blast tools -- both must surface, proving a real merge, not "first truthy
    # source wins".
    cfg = {
        "tools": {"alsoAllow": ["send_email"]},
        "gateway": {"tools": {"allow": ["delete_forever"]}},
    }
    att = {"tools": ["search"]}
    f = check_attestation_mismatch(_ctx(config=cfg, attestation=att))
    assert f.status == WARN
    assert any("send_email" in e for e in f.evidence)
    assert any("delete_forever" in e for e in f.evidence)


@pytest.mark.parametrize(
    "bad_also_allow",
    [None, "", "write", {}, [1, None, {"a": 1}, ["nested"]], True, 3.14],
)
def test_b44_malformed_alsoallow_does_not_raise(bad_also_allow):
    cfg = {"tools": {"alsoAllow": bad_also_allow}}
    att = {"tools": ["search"]}
    f = check_attestation_mismatch(_ctx(config=cfg, attestation=att))
    assert f.status in (PASS, WARN, UNKNOWN)


# =====================================================================================
# check_declared_effective_proven (B84) -- alsoAllow folds into `declared` (informational)
# =====================================================================================

def test_b84_alsoallow_declared_tool_that_is_proven_no_dead_grant_note():
    cfg = {"tools": {"alsoAllow": ["search_threads"]}}
    att = {
        "tools": ["search_threads"],
        "proven_tools": ["search_threads"],
        "untrusted_to_action": "gated",
    }
    f = check_declared_effective_proven(_ctx(config=cfg, attestation=att))
    assert f.status == PASS
    assert not any("never proven" in e for e in f.evidence)


def test_b84_alsoallow_dead_grant_is_informational_never_flips_to_warn():
    # send_email is declared via alsoAllow only and never proven; posture is even
    # ungated -- but nothing PROVEN is high-blast, so this must stay PASS. Widening
    # `declared` must never itself flip the verdict (declared is informational-only).
    cfg = {"tools": {"alsoAllow": ["send_email"]}}
    att = {
        "tools": ["search_threads", "send_email"],
        "proven_tools": ["search_threads"],
        "untrusted_to_action": "ungated",
    }
    f = check_declared_effective_proven(_ctx(config=cfg, attestation=att))
    assert f.status == PASS
    assert any("send_email" in e and "never proven" in e for e in f.evidence)


def test_b84_dead_grant_evidence_not_doubled_when_tool_in_allow_and_alsoallow():
    cfg = {"tools": {"allow": ["send_email"], "alsoAllow": ["send_email"]}}
    att = {
        "tools": ["send_email", "search_threads"],
        "proven_tools": ["search_threads"],
        "untrusted_to_action": "gated",
    }
    f = check_declared_effective_proven(_ctx(config=cfg, attestation=att))
    assert f.status == PASS
    dead_grant_lines = [e for e in f.evidence if "never proven" in e]
    assert len(dead_grant_lines) == 1
    assert dead_grant_lines[0].count("send_email") == 1


@pytest.mark.parametrize(
    "bad_also_allow",
    [None, "", "write", {}, [1, None, {"a": 1}, ["nested"]], True, 3.14],
)
def test_b84_malformed_alsoallow_does_not_raise(bad_also_allow):
    cfg = {"tools": {"alsoAllow": bad_also_allow}}
    att = {
        "tools": ["search"],
        "proven_tools": ["search"],
        "untrusted_to_action": "gated",
    }
    f = check_declared_effective_proven(_ctx(config=cfg, attestation=att))
    assert f.status in (PASS, WARN, UNKNOWN)
