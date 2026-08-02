"""tools.alsoAllow -- additive third tool-grant source (I-028), then B-423/B-411.

OpenClaw's schema FORBIDS tools.allow + tools.alsoAllow together and RECOMMENDS
tools.profile + tools.alsoAllow instead, so the schema-recommended real-world shape
carries an EMPTY tools.allow and grants everything through alsoAllow. I-028 first
added alsoAllow as an additive grant channel; B-423/B-411 (2026-08-02) then
retracted two remaining wrong assumptions from that pass, grounded directly against
the installed OpenClaw dist:

1. (B-423) gateway.tools.allow is NOT an additive grant -- it only REMOVES entries
   from OpenClaw's default HTTP tool-deny list (a de-denylist over one surface,
   tool-resolution-XVJDzZpY.js:49-50). B44 used to union it into the declared-tool
   comparison; it no longer reads it at all. B31/behavioral.py/_config.py's OWN
   gateway.tools.allow readings are untouched -- this file only covers B44/B55/B68/B84.
2. (B-411) tools.alsoAllow-only (tools.allow absent or an explicit empty list) grants
   EVERY tool via OpenClaw's own unionAllow implicit-wildcard injection
   (sandbox-tool-policy-ClB7s2K0.js:9-14), not just the literal tokens it names -- I-028's
   "grants exactly its own tokens" premise is retracted for that shape. SUPPRESSED when
   tools.profile is set (a separate, non-unionAllow policy layer) -- THE tripwire test for
   this guard is `test_helper_powerful_profile_plus_narrow_alsoallow_does_not_narrow`'s
   sibling below: do not let a future "harmonisation" drop the profile-is-None condition.

All four checks (B44/B55/B68/B84) now resolve the global tools.* layer through the one
shared `_tool_policy_view` (checks/_capability.py) instead of their own accumulators, so
this file also pins that they agree with each other.

Offline, deterministic, stdlib only (+ pytest for parametrize).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    _b68_fs_tools_granted,
    _tool_policy_view,
    check_attestation_mismatch,
    check_declared_effective_proven,
    check_exec_applypatch_workspace,
    check_fs_write_exposure,
)
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(config=None, attestation=None):
    return Context(home=Path("/nonexistent"), config=config or {}, attestation=attestation or {})


# =====================================================================================
# _b68_fs_tools_granted -- direct unit tests of the accumulator (B-283 (b) / I-028)
# =====================================================================================

def test_helper_alsoallow_only_grants_every_fs_tool_via_implicit_wildcard():
    # B-411: alsoAllow-only (tools.allow absent) triggers OpenClaw's unionAllow
    # implicit "*" injection -- EVERY tool is granted, not just "search" itself.
    # (Retracts the pre-B-411 "narrow tool does not widen enumerability" premise.)
    granted, enumerable = _b68_fs_tools_granted({"tools": {"alsoAllow": ["search"]}})
    assert enumerable is True
    assert granted == ["apply_patch", "edit", "read", "write"]


def test_helper_alsoallow_broad_fs_tool_with_empty_allow_now_grants():
    # bad: EMPTY tools.allow, alsoAllow present -> B-411 implicit wildcard grants
    # every fs tool, not just "write" (the ticket's headline case).
    granted, enumerable = _b68_fs_tools_granted({"tools": {"allow": [], "alsoAllow": ["write"]}})
    assert enumerable is True
    assert granted == ["apply_patch", "edit", "read", "write"]

    # Equivalent tools.allow-only-visible config: the old or-chain never read
    # tools.alsoAllow at all, so an empty tools.allow with alsoAllow simply absent is
    # exactly what the pre-I-028 reader effectively saw for this config -- not
    # enumerable, i.e. it could NOT have produced the WARN this grant now causes.
    granted_old, enumerable_old = _b68_fs_tools_granted({"tools": {"allow": []}})
    assert enumerable_old is False
    assert granted_old == []


def test_helper_dedupes_same_tool_in_allow_and_alsoallow():
    # MUST NOT CHANGE: tools.allow is non-empty ("write") -> unionAllow's implicit-
    # wildcard trigger (base absent/empty) does not fire, plain concat branch only.
    granted, enumerable = _b68_fs_tools_granted(
        {"tools": {"allow": ["write"], "alsoAllow": ["write"]}}
    )
    assert enumerable is True
    assert granted == ["write"]


def test_helper_deny_wins_over_alsoallow():
    # B-411: alsoAllow-only grants everything via the implicit wildcard, but deny is
    # subtracted last -- deny still wins over the wider base.
    granted, enumerable = _b68_fs_tools_granted(
        {"tools": {"alsoAllow": ["write", "read"], "deny": ["write"]}}
    )
    assert enumerable is True
    assert granted == ["apply_patch", "edit", "read"]


def test_helper_group_fs_deny_beats_group_fs_alsoallow():
    # MUST NOT CHANGE: the "group:fs" deny short-circuit runs before grant resolution.
    granted, enumerable = _b68_fs_tools_granted(
        {"tools": {"alsoAllow": ["group:fs"], "deny": ["group:fs"]}}
    )
    assert granted == []
    assert enumerable is True


def test_helper_group_fs_in_alsoallow_grants_whole_family_minus_denied():
    # MUST NOT CHANGE: "group:fs" in alsoAllow already resolves to the whole family --
    # same answer whether reached via the explicit group token or the implicit wildcard.
    granted, enumerable = _b68_fs_tools_granted(
        {"tools": {"alsoAllow": ["group:fs"], "deny": ["write"]}}
    )
    assert enumerable is True
    assert granted == sorted({"read", "edit", "apply_patch"})


def test_helper_powerful_profile_plus_narrow_alsoallow_does_not_narrow():
    # MUST NOT CHANGE: THE subtlest hazard -- a POWERFUL profile already grants every fs
    # tool; a narrow alsoAllow must only ever WIDEN, never narrow that verdict down to
    # its own tokens. tools.profile is set here, so this is unaffected by B-411 either
    # way -- both readings already land on "every fs tool".
    granted, enumerable = _b68_fs_tools_granted(
        {"tools": {"profile": "coding", "alsoAllow": ["read"]}}
    )
    assert enumerable is True
    assert granted == sorted({"read", "write", "edit", "apply_patch"})


def test_helper_non_powerful_profile_plus_alsoallow_still_adds_narrow_grant():
    # MUST NOT CHANGE -- THE profile-guard tripwire (B-411 §7 risk #4): tools.profile is
    # set, so the unionAllow implicit-wildcard is SUPPRESSED (it is a separate,
    # non-unionAllow policy layer -- see _tool_policy_view's docstring). Without the
    # `profile is None` condition on `implicit_all`, this becomes "every fs tool" instead
    # of just "read" -- the exact false-widening the profile guard exists to prevent. Do
    # not let this assertion be "harmonised" with the alsoAllow-only tests above.
    granted, enumerable = _b68_fs_tools_granted(
        {"tools": {"profile": "minimal", "alsoAllow": ["read"]}}
    )
    assert enumerable is True
    assert granted == ["read"]
    assert _tool_policy_view({"tools": {"profile": "minimal", "alsoAllow": ["read"]}}).implicit_all is False


def test_helper_unknown_preserved_when_alsoallow_names_no_fs_tool():
    # B-411: alsoAllow-only (tools.allow absent, no profile) grants EVERY tool via the
    # implicit wildcard, regardless of which token it names -- "network_search" being
    # outside the fs family no longer matters. Retracts the pre-B-411 "stays UNKNOWN"
    # premise; the config genuinely grants read/write/edit/apply_patch.
    granted, enumerable = _b68_fs_tools_granted({"tools": {"alsoAllow": ["network_search"]}})
    assert enumerable is True
    assert granted == ["apply_patch", "edit", "read", "write"]


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


def test_helper_nonempty_junk_alsoallow_still_triggers_implicit_wildcard():
    # unionAllow's own emptiness test runs on the RAW array LENGTH, before any
    # blank/type filtering (sandbox-tool-policy-ClB7s2K0.js:10-12) -- a non-empty list
    # of junk entries still has len > 0, so it still injects the wildcard even though
    # none of its entries name a real tool. Mirrors _tool_policy_view's own comment;
    # do not "clean this up" by filtering blanks before the emptiness check.
    granted, enumerable = _b68_fs_tools_granted({"tools": {"alsoAllow": [None, None, None]}})
    assert enumerable is True
    assert granted == ["apply_patch", "edit", "read", "write"]


# =====================================================================================
# check_exec_applypatch_workspace (B68) -- end to end through the real check function
# =====================================================================================

def test_b68_check_alsoallow_only_narrow_tool_warns_on_full_family():
    # B-411: alsoAllow-only grants EVERY tool via the implicit wildcard -- WARN, not the
    # pre-B-411 UNKNOWN (this config is no longer "unenumerable", it grants everything).
    f = check_exec_applypatch_workspace(_ctx({"tools": {"alsoAllow": ["search"]}}))
    assert f.status == WARN
    granted_evidence = next(e for e in f.evidence if e.startswith("filesystem tools granted"))
    assert granted_evidence == "filesystem tools granted: apply_patch, edit, read, write"


def test_b68_check_bad_empty_allow_alsoallow_broad_fs_tool_warns():
    f = check_exec_applypatch_workspace(
        _ctx({"tools": {"allow": [], "alsoAllow": ["write"]}})
    )
    assert f.status == WARN
    granted_evidence = next(e for e in f.evidence if e.startswith("filesystem tools granted"))
    assert granted_evidence == "filesystem tools granted: apply_patch, edit, read, write"

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
    # B-411: alsoAllow-only grants everything via the implicit wildcard; deny still
    # wins over the wider base.
    f = check_exec_applypatch_workspace(
        _ctx({"tools": {"alsoAllow": ["write", "read"], "deny": ["write"]}})
    )
    assert f.status == WARN
    granted_evidence = next(e for e in f.evidence if e.startswith("filesystem tools granted"))
    assert granted_evidence == "filesystem tools granted: apply_patch, edit, read"


def test_b68_check_group_fs_deny_beats_group_fs_alsoallow():
    # MUST NOT CHANGE: "group:fs" deny short-circuit runs before grant resolution.
    f = check_exec_applypatch_workspace(
        _ctx({"tools": {"alsoAllow": ["group:fs"], "deny": ["group:fs"]}})
    )
    assert f.status == PASS


def test_b68_check_group_fs_alsoallow_grants_whole_family_minus_denied():
    # MUST NOT CHANGE: "group:fs" already resolves to the whole family either way.
    f = check_exec_applypatch_workspace(
        _ctx({"tools": {"alsoAllow": ["group:fs"], "deny": ["write"]}})
    )
    assert f.status == WARN
    granted_evidence = next(e for e in f.evidence if e.startswith("filesystem tools granted"))
    assert granted_evidence == "filesystem tools granted: apply_patch, edit, read"


def test_b68_check_powerful_profile_plus_narrow_alsoallow_keeps_full_family():
    # MUST NOT CHANGE: pinned explicitly per spec -- the narrow alsoAllow token must not
    # narrow a POWERFUL profile's "every fs tool granted" verdict down to just itself.
    # tools.profile is set, so the implicit wildcard is suppressed either way here.
    f = check_exec_applypatch_workspace(
        _ctx({"tools": {"profile": "coding", "alsoAllow": ["read"]}})
    )
    assert f.status == WARN
    granted_evidence = next(e for e in f.evidence if e.startswith("filesystem tools granted"))
    assert granted_evidence == "filesystem tools granted: apply_patch, edit, read, write"


def test_b68_check_non_powerful_profile_plus_alsoallow_stays_narrow():
    # THE profile-guard tripwire at check level (mirrors the helper-level test above):
    # tools.profile is set, so alsoAllow-only's implicit wildcard must NOT fire here.
    f = check_exec_applypatch_workspace(
        _ctx({"tools": {"profile": "minimal", "alsoAllow": ["read"]}})
    )
    assert f.status == WARN
    granted_evidence = next(e for e in f.evidence if e.startswith("filesystem tools granted"))
    assert granted_evidence == "filesystem tools granted: read"


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
    # MUST NOT CHANGE: B44 projects `view.named` only, never `grants_all` -- alsoAllow
    # granting "everything" per B-411 is irrelevant here since "search_threads" is
    # neither high-blast nor undisclosed.
    cfg = {"tools": {"alsoAllow": ["search_threads"]}}
    att = {"tools": ["search_threads"]}
    f = check_attestation_mismatch(_ctx(config=cfg, attestation=att))
    assert f.status == PASS


def test_b44_bad_alsoallow_undisclosed_high_blast_tool_warns():
    # MUST NOT CHANGE: unaffected by B-411's implicit wildcard -- B44 doesn't consume
    # grants_all, only the literal `named` tokens.
    cfg = {"tools": {"allow": [], "alsoAllow": ["send_email"]}}
    att = {"tools": ["search"]}
    f = check_attestation_mismatch(_ctx(config=cfg, attestation=att))
    assert f.status == WARN
    assert any("send_email" in e for e in f.evidence)

    # Equivalent old-or-chain-visible config: empty tools.allow, alsoAllow absent ->
    # nothing listed at all -> UNKNOWN.
    cfg_old = {"tools": {"allow": []}}
    f_old = check_attestation_mismatch(_ctx(config=cfg_old, attestation=att))
    assert f_old.status == UNKNOWN


def test_b44_dedupes_same_tool_in_allow_and_alsoallow():
    # MUST NOT CHANGE: unaffected by B-411/B-423.
    cfg = {"tools": {"allow": ["send_email"], "alsoAllow": ["send_email"]}}
    att = {"tools": ["search"]}
    f = check_attestation_mismatch(_ctx(config=cfg, attestation=att))
    assert f.status == WARN
    matches = [e for e in f.evidence if "send_email" in e]
    assert len(matches) == 1


def test_b44_gateway_allow_is_never_an_additive_grant():
    # B-423 regression test (was test_b44_alsoallow_merges_with_gateway_allow_not_or_chained,
    # which asserted the OPPOSITE of this -- that gateway.tools.allow surfaced as a grant).
    # gateway.tools.allow only de-denies OpenClaw's default HTTP tool-deny list; it is
    # NEVER an additive grant (tool-resolution-XVJDzZpY.js:49-50). "delete_forever" must
    # NOT appear -- the agent has no real access to it -- while "send_email" (a genuine
    # tools.alsoAllow grant) still does.
    cfg = {
        "tools": {"alsoAllow": ["send_email"]},
        "gateway": {"tools": {"allow": ["delete_forever"]}},
    }
    att = {"tools": ["search"]}
    f = check_attestation_mismatch(_ctx(config=cfg, attestation=att))
    assert f.status == WARN
    assert any("send_email" in e for e in f.evidence)
    assert not any("delete_forever" in e for e in f.evidence)


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


# =====================================================================================
# B-423/B-411 new coverage: the alias fix, gateway-de-denylist pin, home_vuln regression
# =====================================================================================

def test_helper_deny_alias_suppresses_canonical_grant():
    # B-423 alias half: denying "apply-patch" (the alias) must suppress a grant of
    # "apply_patch" (the canonical id) -- OpenClaw folds both sides through the same
    # TOOL_NAME_ALIASES table before matching (tool-policy-match-CgU98OQh.js:9-19).
    granted, enumerable = _b68_fs_tools_granted(
        {"tools": {"allow": ["apply_patch"], "deny": ["apply-patch"]}}
    )
    assert enumerable is True
    assert granted == []


def test_helper_bash_alias_folds_to_exec_in_named():
    view = _tool_policy_view({"tools": {"allow": ["bash"]}})
    assert view.named == ("exec",)
    # "bash"/"exec" are not fs-family tools, so the fs helper reports no fs grant.
    granted, enumerable = _b68_fs_tools_granted({"tools": {"allow": ["bash"]}})
    assert enumerable is True
    assert granted == []


def test_helper_gateway_tools_allow_alone_is_not_enumerable():
    # B-423 pin: gateway.tools.allow is a de-denylist, never an additive grant --
    # before this fix this config resolved to (["write"], True). It must now resolve
    # the same as an empty config: no tools.allow/alsoAllow/profile at all.
    granted, enumerable = _b68_fs_tools_granted({"gateway": {"tools": {"allow": ["write"]}}})
    assert granted == []
    assert enumerable is False


def test_home_vuln_fixture_gateway_no_longer_masks_the_powerful_profile():
    """B-423 blast-radius check (architect-verified): home_vuln sets BOTH
    gateway.tools.allow (a phantom pre-fix grant) AND tools.profile: "full" (a real
    grant). Before this fix, gateway.tools.allow hijacked the `listed` branch so the
    real powerful profile was never reached -- B68 wrongly PASSed. After this fix,
    gateway is dropped, the profile branch is reached, and B68 correctly WARNs. B55
    was already FAIL via the profile grant and stays FAIL -- no detection regression,
    strictly better detection."""
    ctx = collect(FIXTURES / "home_vuln")
    granted, enumerable = _b68_fs_tools_granted(ctx.config)
    assert enumerable is True
    assert granted == ["apply_patch", "edit", "read", "write"]

    f68 = check_exec_applypatch_workspace(ctx)
    assert f68.status == WARN

    f55 = check_fs_write_exposure(ctx)
    assert f55.status == FAIL


# =====================================================================================
# B-423/B-411 C-135 round 2: implicit-wildcard-only write grant downgrades FAIL -> WARN
#
# An independent adversarial review of the B-411 implicit-wildcard fix found a real
# false-positive FAIL: `tools.alsoAllow`-only (no tools.allow/tools.profile) triggers
# OpenClaw's implicit wildcard, but a NARROWER per-agent tools.profile
# (agents.list[N].tools.profile) is AND-ed into the SAME resolved policy OpenClaw's
# real resolver reads first (agent-tools.policy-YD9HuYgO.js:232) -- invisible to this
# static, global-only check. OpenClaw itself treats the implicit "*" as an artifact
# rather than confirmed operator intent (it mints IMPLICIT_ALLOW_ALL_FROM_ALSO_ALLOW
# specifically to refuse to honor it downstream where it can,
# sandbox-tool-policy-ClB7s2K0.js:7-14 / tool-policy-BHUGxE3p.js:100-103). check_fs_write_
# exposure now FAILs only when an EXPLICIT signal backs the write grant (a literal
# write/edit/apply_patch/"*"/"group:fs" token, or a powerful tools.profile) --
# implicit-wildcard-only grants stay WARN.
# =====================================================================================

def _open_unconfined(extra):
    return {**extra, "channels": {"telegram": {"dmPolicy": "open"}}}


def test_b55_alsoallow_only_nonwrite_token_open_channel_warns_not_fails():
    # C-135 scenario 1: alsoAllow names a harmless tool ("search"); the write grant is
    # PURELY the side effect of the implicit wildcard -- no explicit signal at all.
    f = check_fs_write_exposure(
        Context(home=None, config=_open_unconfined({"tools": {"alsoAllow": ["search"]}}))
    )
    assert f.status == WARN
    assert f.scored is False
    assert any("implicit" in e for e in f.evidence)


def test_b55_alsoallow_only_plus_peragent_profile_warns_not_fails():
    # C-135 scenario 2 (THE diagnosed false positive): a per-agent tools.profile this
    # check cannot see would legitimately narrow the grant away from write in real
    # OpenClaw. Must stay WARN, not the pre-fix FAIL.
    f = check_fs_write_exposure(
        Context(
            home=None,
            config=_open_unconfined(
                {
                    "tools": {"alsoAllow": ["browser"]},
                    "agents": {"list": [{"tools": {"profile": "messaging"}}]},
                }
            ),
        )
    )
    assert f.status == WARN
    assert f.scored is False


def test_b55_alsoallow_only_literal_write_token_still_fails():
    # The explicit/implicit distinction is per-TOKEN, not per-config: alsoAllow-only is
    # STILL implicit-wildcard territory (tools.allow/profile absent), but the operator
    # literally named "write" -- an unambiguous explicit signal -- so this stays FAIL.
    f = check_fs_write_exposure(
        Context(home=None, config=_open_unconfined({"tools": {"alsoAllow": ["write"]}}))
    )
    assert f.status == FAIL
    assert f.scored is True


def test_b55_alsoallow_narrow_plus_explicit_allow_still_fails():
    # tools.allow non-empty -> no implicit wildcard at all (unionAllow's own trigger
    # condition doesn't fire) -- an explicit "write" grant via alsoAllow stays FAIL.
    # (Mirrors tests/test_b55.py's pre-existing "alsoAllow" id in
    # test_new_grant_path_open_channel_unconfined_fails; pinned here too since it is
    # the direct control for the two tests above.)
    f = check_fs_write_exposure(
        Context(
            home=None,
            config=_open_unconfined({"tools": {"allow": ["read"], "alsoAllow": ["write"]}}),
        )
    )
    assert f.status == FAIL
    assert f.scored is True
