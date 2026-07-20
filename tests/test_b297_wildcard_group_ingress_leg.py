"""B-297 — the `channels.<p>.groups {"*": ...}` shape reaches the ingress leg.

Before this change the wildcard-group shape was modelled in exactly ONE place, B140
(`check_wildcard_group_ingress`), which nothing outside `checks/_agents.py` could reach.
Every ingress predicate in the package keyed on `dmPolicy`/`groupPolicy` VALUES, and the
wildcard-group shape carries neither field — so `_external_input_channels()` and
`risk.py`'s `_open_channel_labels()` both returned `[]` on the commonest real open-group
config, and RISK-01 ("Untrusted sender can reach host execution"), which gates on
`_open_channel_labels` alone, could not fire on it at all.

What is asserted here, in layers:

1. The predicate matrix (`_wildcard_group_gap`) — one definition, shared by B140 and the
   ingress leg. The FP guards are the point: an effective allowFrom from ANY of the three
   sources the dist's resolver consults suppresses it.
2. The accounts-merge semantics (`_resolved_channel_nodes`), grounded on the dist's
   `mergeAccountConfig` (account-helpers-BAtt8fRD.js:88-105). Both merge FP directions are
   pinned, because a raw `[c] + accounts.values()` read — the idiom the policy helpers use
   — would false-fire on both.
3. Both consumers (`_external_input_channels`, `_open_channel_labels`) and RISK-01/02/03.
4. **The contract that keeps this safe**: B140 stays WARN-never-FAIL and every RiskPath
   stays outside the A-F score, so a newly-firing chain cannot manufacture a FAIL for a
   community-bot operator who accepts any group deliberately.
5. Golden Rule #5 invariants on the two configs the project treats as the release gate.

Tests 1-3 were verified to FAIL against the pre-fix predicate (by stubbing
`_open_wildcard_group_channels` to `{}`), so none of them passes for an incidental reason.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck import risk as riskmod
from clawseccheck.catalog import CRITICAL, FAIL, PASS, WARN
from clawseccheck.checks import (
    _external_input_channels,
    _open_wildcard_group_channels,
    _resolved_channel_nodes,
    _untrusted_input_channels,
    _wildcard_group_gap,
    check_wildcard_group_ingress,
    run_all,
)
from clawseccheck.collector import Context, collect
from clawseccheck.risk import risk_paths
from clawseccheck.scoring import compute

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
RELIABILITY = FIXTURES / "reliability"

# A wildcard group whose only content is the real fleet config's shape.
_REAL_SHAPE = {"channels": {"telegram": {"groups": {"*": {"requireMention": True}}}}}


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def _tg(node: dict) -> dict:
    return {"channels": {"telegram": node}}


# ---------------------------------------------------------------------------
# 1. The predicate matrix — one shared definition of "effectively unrestricted"
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "node, expect_open, why",
    [
        # --- OPEN: no effective restriction anywhere ---
        ({"groups": {"*": {}}}, True, "bare wildcard group, no allowFrom at all"),
        (
            {"groups": {"*": {"requireMention": True}}},
            True,
            "the real fleet shape — requireMention gates the trigger, not the sender",
        ),
        (
            {"groups": {"*": {}}, "allowFrom": []},
            True,
            "empty allowFrom is 'no entries' and falls through (resolveGroupAllowFromSources)",
        ),
        (
            {"groups": {"*": {}}, "allowFrom": ["*"]},
            True,
            "isSenderIdAllowed short-circuits on hasWildcard — a '*' list is not a restriction",
        ),
        (
            {"groups": {"*": {"allowFrom": ["*"]}}, "allowFrom": ["123"]},
            True,
            "per-group allowFrom wins outright; its '*' beats the narrow channel list",
        ),
        (
            {"groups": {"*": {}}, "groupAllowFrom": [" * "]},
            True,
            "padded wildcard entry normalizes to '*' (String(value).trim())",
        ),
        # --- CLOSED: an effective allowFrom from each of the three sources ---
        ({"groups": {"*": {"allowFrom": ["123"]}}}, False, "per-group allowFrom"),
        ({"groups": {"*": {}}, "groupAllowFrom": ["123"]}, False, "channel groupAllowFrom"),
        ({"groups": {"*": {}}, "allowFrom": ["123"]}, False, "channel allowFrom fallback"),
        (
            {"groups": {"*": {}}, "groupAllowFrom": ["123"], "allowFrom": ["*"]},
            False,
            "groupAllowFrom wins outright — the wildcard DM list never governs groups",
        ),
        # --- NOT THE SHAPE AT ALL ---
        ({}, False, "no groups key"),
        ({"groups": {}}, False, "empty groups map"),
        ({"groups": {"engineering": {}}}, False, "named groups only, no wildcard"),
        ({"groups": "oops"}, False, "malformed groups is ignored, not assumed open"),
        (
            {"groups": {"*": "oops"}, "allowFrom": ["123"]},
            False,
            "malformed wildcard ENTRY falls through to the node-level allowFrom",
        ),
        # Present-but-malformed "*" with nothing restricting it stays open: the wildcard
        # KEY is what declares the surface, and B140 has always read it this way (the
        # `isinstance(wildcard_group, dict) else None` fallback). Pinned so the move into
        # _shared.py is provably behaviour-preserving, not quietly re-tuned.
        ({"groups": {"*": "oops"}}, True, "malformed entry, nothing restricting the node"),
    ],
)
def test_b297_predicate_matrix(node, expect_open, why):
    """`_wildcard_group_gap` is the single source of truth — assert the whole matrix."""
    gap = _wildcard_group_gap(node)
    assert bool(gap) is expect_open, f"{why}: node={node!r} gap={gap!r}"


def test_b297_gap_reasons_distinguish_absent_from_wildcard_allowfrom():
    """The two ways to be open stay reported apart (the B-266 distinction, preserved)."""
    assert _wildcard_group_gap({"groups": {"*": {}}}) == "no allowFrom configured"
    assert "'*'" in _wildcard_group_gap({"groups": {"*": {}}, "allowFrom": ["*"]})


def test_b297_gap_on_non_dict_node_is_none():
    for junk in (None, "x", 3, [], ["groups"]):
        assert _wildcard_group_gap(junk) is None


# ---------------------------------------------------------------------------
# 2. Accounts merge — grounded on the dist's mergeAccountConfig
# ---------------------------------------------------------------------------

def test_b297_account_scoped_wildcard_group_is_detected():
    """`channels.<p>.accounts.<id>.groups {"*"}` — B140's documented gap #2, now closed."""
    cfg = _tg({"accounts": {"primary": {"groups": {"*": {"requireMention": True}}}}})
    assert _open_wildcard_group_channels(cfg) == {"telegram": "no allowFrom configured"}
    assert check_wildcard_group_ingress(_ctx(cfg)).status == WARN


def test_b297_base_groups_restricted_by_account_allowfrom_is_not_open():
    """FP guard: mergeAccountConfig spreads the base under the account — the account
    inherits `groups` and supplies `allowFrom`, so the merged config IS restricted.
    A raw `[c] + accounts.values()` read would false-fire on the base node here."""
    cfg = _tg({"groups": {"*": {}}, "accounts": {"primary": {"allowFrom": ["123"]}}})
    assert _open_wildcard_group_channels(cfg) == {}
    assert check_wildcard_group_ingress(_ctx(cfg)).status == PASS
    assert _external_input_channels(cfg) == []


def test_b297_base_allowfrom_restricting_account_groups_is_not_open():
    """FP guard, mirror direction: base supplies `groupAllowFrom`, the account supplies
    `groups {"*"}` — merged, it is restricted. A raw per-node read would false-fire on
    the account node here."""
    cfg = _tg({"groupAllowFrom": ["123"], "accounts": {"primary": {"groups": {"*": {}}}}})
    assert _open_wildcard_group_channels(cfg) == {}
    assert check_wildcard_group_ingress(_ctx(cfg)).status == PASS


def test_b297_account_override_of_allowfrom_wins_key_by_key():
    """The spread is shallow and the account wins: a base allowFrom overridden by an
    account `allowFrom: ["*"]` leaves the group open."""
    cfg = _tg(
        {
            "groups": {"*": {}},
            "allowFrom": ["123"],
            "accounts": {"primary": {"allowFrom": ["*"]}},
        }
    )
    assert "telegram" in _open_wildcard_group_channels(cfg)


def test_b297_one_open_account_among_restricted_ones_is_reported():
    cfg = _tg(
        {
            "groups": {"*": {}},
            "accounts": {"a": {"allowFrom": ["123"]}, "b": {"allowFrom": []}},
        }
    )
    assert "telegram" in _open_wildcard_group_channels(cfg)


def test_b297_resolved_nodes_shape():
    """No accounts -> the channel node IS the implicit default account."""
    assert _resolved_channel_nodes({"groups": {"*": {}}}) == [{"groups": {"*": {}}}]
    # accounts present -> merged nodes only, and `accounts` itself never leaks into one
    nodes = _resolved_channel_nodes({"allowFrom": ["1"], "accounts": {"a": {"dmPolicy": "open"}}})
    assert nodes == [{"allowFrom": ["1"], "dmPolicy": "open"}]
    assert all("accounts" not in n for n in nodes)


def test_b297_malformed_accounts_do_not_crash_or_manufacture_findings():
    for accounts in ({}, {"a": None}, {"a": "x"}, [], "x", None):
        cfg = _tg({"groups": {"*": {"allowFrom": ["123"]}}, "accounts": accounts})
        assert _open_wildcard_group_channels(cfg) == {}, accounts
        assert check_wildcard_group_ingress(_ctx(cfg)).status == PASS, accounts


# ---------------------------------------------------------------------------
# 3. The two consumers the task named
# ---------------------------------------------------------------------------

def test_b297_external_input_channels_sees_the_wildcard_shape():
    """The defect, stated directly: this returned [] before B-297."""
    assert _external_input_channels(_REAL_SHAPE) == ["telegram"]


def test_b297_open_channel_labels_sees_the_wildcard_shape():
    labels = riskmod._open_channel_labels(_REAL_SHAPE)
    assert labels and "telegram" in labels[0] and "open group" in labels[0]


def test_b297_require_mention_is_surfaced_as_context_not_as_a_gate():
    """`requireMention: true` changes what triggers the bot, not who may trigger it —
    surfaced in the label, but it must not suppress the ingress leg."""
    gated = riskmod._open_channel_labels(_REAL_SHAPE)[0]
    ungated = riskmod._open_channel_labels(_tg({"groups": {"*": {}}}))[0]
    assert "mention-gated" in gated
    assert "mention-gated" not in ungated
    assert _external_input_channels(_REAL_SHAPE) == ["telegram"]


def test_b297_disabled_channel_is_not_ingress_but_b140_still_warns():
    """Caller-side scoping, deliberately different, pinned so neither drifts: a disabled
    channel ingests nothing (B-041), so it is not ingress — while B140 keeps assessing
    every configured provider regardless of `enabled`."""
    cfg = _tg({"enabled": False, "groups": {"*": {"requireMention": True}}})
    assert _open_wildcard_group_channels(cfg) == {}
    assert _external_input_channels(cfg) == []
    assert riskmod._open_channel_labels(cfg) == []
    assert check_wildcard_group_ingress(_ctx(cfg)).status == WARN


# ---------------------------------------------------------------------------
# 3b. C-135 residue: reachability. These three shapes are what the adversarial
#     pass actually found — each one made the ingress leg fire on a config that
#     cannot receive a group message at all.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "node, why",
    [
        (
            {"groupPolicy": "disabled", "groups": {"*": {}}},
            "groupPolicy 'disabled' gates every group-access resolver first and "
            "unconditionally (group-access-CyF0dAER.js:9/14/44/75)",
        ),
        (
            {"groups": {"*": {"enabled": False}}},
            "a wildcard entry's own enabled:false yields reason 'route_disabled' "
            "(channel2.runtime-Bb6oxd87.js:237)",
        ),
        (
            {"groups": {"*": {}}, "accounts": {"a": {"groupPolicy": "disabled"}}},
            "the account inherits `groups` and overrides groupPolicy to disabled",
        ),
    ],
)
def test_b297_group_ingress_switched_off_is_not_untrusted_ingress(node, why):
    """C-135 FP guard. Leaving a `groups` block in place while turning group access off
    is an ordinary way to disable it — it must not read as untrusted ingress, because
    here that would flip B41 to WARN and fire RISK-01/02/03 on a config admitting no
    group message. This is the sharpest FP guard in the file."""
    cfg = _tg(node)
    assert _open_wildcard_group_channels(cfg) == {}, why
    assert _external_input_channels(cfg) == [], why
    assert riskmod._open_channel_labels(cfg) == [], why
    assert not any(p.id == "RISK-01" for p in _paths({**cfg, "tools": {"exec": {"security": "full"}}}))


def test_b297_reachability_is_scoped_to_the_ingress_leg_not_b140():
    """Honest labelling: B140's verdict is UNCHANGED by B-297, so its documented gap #3
    (a wildcard entry on a groups-disabled channel still draws an advisory WARN) stays
    exactly as documented rather than being silently re-tuned. The reachability gate is
    caller-side, applied only where an unsound inference would drive a CRITICAL chain."""
    cfg = _tg({"groupPolicy": "disabled", "groups": {"*": {}}})
    assert check_wildcard_group_ingress(_ctx(cfg)).status == WARN
    assert _open_wildcard_group_channels(cfg) == {}


def test_b297_reachable_wildcard_group_still_fires():
    """The gate must not swallow the real case: an explicitly-enabled wildcard entry on
    an open-group channel is still ingress."""
    cfg = _tg({"groupPolicy": "open", "groups": {"*": {"enabled": True}}})
    assert "telegram" in _open_wildcard_group_channels(cfg)


def test_b297_channels_defaults_block_is_not_a_provider():
    cfg = {"channels": {"defaults": {"groups": {"*": {}}}}}
    assert _open_wildcard_group_channels(cfg) == {}
    assert riskmod._open_channel_labels(cfg) == []


def test_b297_policy_path_is_unchanged():
    """Only the wildcard leg was added — the dmPolicy/groupPolicy path must be untouched."""
    assert _external_input_channels(_tg({"dmPolicy": "open"})) == ["telegram"]
    assert _external_input_channels(_tg({"groupPolicy": "allowlist"})) == ["telegram"]
    assert _external_input_channels(_tg({"dmPolicy": "owner"})) == []
    assert _external_input_channels({"channels": {"feishu": {"groupPolicy": "allowall"}}}) == [
        "feishu"
    ]


def test_b297_untrusted_input_channels_deliberately_not_widened():
    """SCOPE PIN (honest labelling): `_untrusted_input_channels` — A1's trifecta ingress
    leg — is byte-identical in logic to `_external_input_channels` but was NOT widened
    here. Widening the CRITICAL scored trifecta leg needs its own C-135 pass (the same
    reasoning B-283 recorded when it left the absent-dmPolicy default out of scope).
    This asserts the divergence is the CHOSEN state, so it is noticed rather than
    silently inherited."""
    assert _untrusted_input_channels(_REAL_SHAPE) == []
    assert _external_input_channels(_REAL_SHAPE) == ["telegram"]


# ---------------------------------------------------------------------------
# 4. The risk chains — and the contract that keeps them safe
# ---------------------------------------------------------------------------

def _paths(cfg: dict):
    ctx = _ctx(cfg)
    return risk_paths(ctx, run_all(ctx))


def test_b297_risk01_fires_on_the_wildcard_group_shape():
    """The headline: RISK-01 gates on `_open_channel_labels` alone, so it could not fire
    on this shape at all before B-297."""
    cfg = {
        "channels": {"telegram": {"groups": {"*": {"requireMention": True}}}},
        "tools": {"exec": {"security": "full"}},
        "agents": {"defaults": {"sandbox": {"mode": "off"}}},
    }
    paths = _paths(cfg)
    r01 = next((p for p in paths if p.id == "RISK-01"), None)
    assert r01 is not None
    assert r01.severity == CRITICAL
    assert "telegram" in r01.chain[0]


def test_b297_risk01_does_not_fire_when_the_wildcard_group_is_restricted():
    """The FP guard at chain level."""
    cfg = {
        "channels": {"telegram": {"groups": {"*": {"allowFrom": ["123"]}}}},
        "tools": {"exec": {"security": "full"}},
        "agents": {"defaults": {"sandbox": {"mode": "off"}}},
    }
    assert not any(p.id == "RISK-01" for p in _paths(cfg))


def test_b297_risk01_still_needs_its_other_leg():
    """An open wildcard group with no exec/write tool is not a chain."""
    cfg = {
        "channels": {"telegram": {"groups": {"*": {}}}},
        "tools": {"profile": "minimal"},
    }
    assert not any(p.id == "RISK-01" for p in _paths(cfg))


def test_b297_wildcard_group_never_manufactures_a_fail():
    """THE governing GR#5 constraint (task trap #1): B140 is WARN-never-FAIL because a
    community bot may intentionally accept any group. Gaining a risk chain must not
    change that — for the bare shape, no check may FAIL."""
    ctx = _ctx(_REAL_SHAPE)
    findings = run_all(ctx)
    b140 = next(f for f in findings if f.id == "B140")
    assert b140.status == WARN
    assert not any(f.status == FAIL for f in findings)


def test_b297_risk_paths_are_advisory_and_never_move_the_score():
    """Why a newly-firing CRITICAL chain is safe: RiskPaths are computed from findings
    but are not findings — the A-F score is a pure function of the finding list."""
    cfg = {
        "channels": {"telegram": {"groups": {"*": {"requireMention": True}}}},
        "tools": {"exec": {"security": "full"}},
        "agents": {"defaults": {"sandbox": {"mode": "off"}}},
    }
    ctx = _ctx(cfg)
    findings = run_all(ctx)
    before = compute(findings)
    paths = risk_paths(ctx, findings)
    after = compute(findings)
    assert any(p.id == "RISK-01" for p in paths)
    assert (before.score, before.grade) == (after.score, after.grade)


# ---------------------------------------------------------------------------
# 5. Fixtures
# ---------------------------------------------------------------------------

def test_b297_fixture_account_scoped_wildcard_warns():
    ctx = collect(home=RELIABILITY / "bad_b297_wildcard_group_account_scoped")
    findings = run_all(ctx)
    assert next(f for f in findings if f.id == "B140").status == WARN
    assert _external_input_channels(ctx.config) == ["telegram"]


def test_b297_fixture_account_allowfrom_restricts_base_wildcard():
    ctx = collect(home=RELIABILITY / "clean_b297_wildcard_group_account_allowfrom")
    findings = run_all(ctx)
    assert next(f for f in findings if f.id == "B140").status == PASS
    assert _external_input_channels(ctx.config) == []


def test_b297_fixture_base_groupallowfrom_restricts_account_wildcard():
    ctx = collect(home=RELIABILITY / "clean_b297_wildcard_group_base_allowfrom_account_groups")
    findings = run_all(ctx)
    assert next(f for f in findings if f.id == "B140").status == PASS
    assert _external_input_channels(ctx.config) == []


@pytest.mark.parametrize(
    "name",
    [
        "bad_b297_wildcard_group_account_scoped",
        "clean_b297_wildcard_group_account_allowfrom",
        "clean_b297_wildcard_group_base_allowfrom_account_groups",
    ],
)
def test_b297_new_fixtures_raise_no_fail(name):
    """These fixtures exercise an advisory surface only — none may hard-FAIL."""
    findings = run_all(collect(home=RELIABILITY / name))
    assert [f.id for f in findings if f.status == FAIL] == []


# ---------------------------------------------------------------------------
# 6. Golden Rule #5 — the release gate, re-asserted where it is enforced
# ---------------------------------------------------------------------------

def test_b297_home_safe_has_no_wildcard_group_ingress_and_no_fail():
    ctx = collect(home=FIXTURES / "home_safe")
    findings = run_all(ctx)
    assert _open_wildcard_group_channels(ctx.config) == {}
    assert [f.id for f in findings if f.status == FAIL] == []
    assert risk_paths(ctx, findings) == []
