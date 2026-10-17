"""C-740: B55 on a channel whose allowlist admits exactly ONE sender id, and the RISK-12 label.

Dave's rulings (2026-10-17, recorded in the task):

* A write-capable tool reachable only by ONE declared sender (every declared, not-open channel is
  an allowlist holding a single distinct id) is WARN LOW with an honest sentence - not PASS (a
  wrong id or a shared account would make the reach wider) and not the HIGH wording whose advice
  ("narrow the channel to your own account") is already satisfied and cannot be followed.
* RISK-12's chain label must not say "no approval gate" on a config where ``tools.exec.mode``
  is set: B55's own evidence says that gate exists but is not write-specific. Text only.

Every case below that is NOT one id must keep the old WARN HIGH: the downgrade is a
loosening of a verdict, so each boundary (two ids, a wildcard, an empty or missing list,
pairing, a group policy with no list, a mixed set of channels, a per-conversation scope with
its own sender policy, a drifted ``accounts`` value) is pinned in the conservative direction.
The id itself must never appear in any output.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawseccheck.catalog import HIGH, LOW, WARN
from clawseccheck.checks import _one_id_bounded_channels, check_fs_write_exposure, run_all
from clawseccheck.collector import Context, collect
from clawseccheck.risk import risk_paths

ID = "7700112233"  # a made-up numeric id; it must never be echoed
GATED = {"profile": "full", "exec": {"mode": "ask"}}
OLD_ADVICE_HEAD = "Narrow the channel(s) to your own account"
NEW_DETAIL_HEAD = "is reachable by the ONE sender id"


def _b55(tmp_path: Path, channels: dict, tools: dict | None = None):
    (tmp_path / "openclaw.json").write_text(
        json.dumps({"tools": tools if tools is not None else GATED, "channels": channels}),
        encoding="utf-8",
    )
    (tmp_path / "openclaw.json").chmod(0o600)
    return check_fs_write_exposure(collect(tmp_path))


def _tg(**over):
    node = {"enabled": True, "dmPolicy": "allowlist", "groupPolicy": "allowlist",
            "allowFrom": [ID], "groupAllowFrom": [ID]}
    node.update(over)
    return node


def _assert_downgraded(f):
    assert f.status == WARN, (f.status, f.detail)
    assert f.severity == LOW, f.severity
    assert NEW_DETAIL_HEAD in f.detail
    assert OLD_ADVICE_HEAD not in f.fix
    blob = " ".join([f.detail, f.fix] + list(f.evidence or []))
    assert ID not in blob, "the sender id must never be echoed"


def _assert_unchanged_high(f):
    assert f.status == WARN, (f.status, f.detail)
    assert f.severity == HIGH, f.severity
    assert NEW_DETAIL_HEAD not in f.detail
    assert OLD_ADVICE_HEAD in f.fix


# --------------------------------------------------------------------- one id: downgraded
def test_the_real_shape_one_id_in_both_lists_with_a_wildcard_group_entry(tmp_path):
    """The exact shape found on the reviewed machine: allowlist for DMs and groups, one id in
    each list, and ``groups: {"*": {requireMention: ...}}`` (delivery tuning, no sender policy)."""
    f = _b55(tmp_path, {"telegram": _tg(groups={"*": {"requireMention": True}})})
    _assert_downgraded(f)


def test_dm_allowlist_of_one_id_and_group_policy_disabled(tmp_path):
    _assert_downgraded(_b55(tmp_path, {"telegram": _tg(groupPolicy="disabled")}))


def test_an_integer_id_and_its_string_form_are_one_id(tmp_path):
    _assert_downgraded(_b55(tmp_path, {"telegram": _tg(allowFrom=[int(ID)], groupAllowFrom=[ID])}))


def test_case_and_whitespace_spellings_of_one_id_are_one_id(tmp_path):
    f = _b55(tmp_path, {"telegram": _tg(allowFrom=["Owner_X"], groupAllowFrom=["  owner_x "])})
    assert f.severity == LOW and NEW_DETAIL_HEAD in f.detail


def test_two_accounts_with_the_same_single_id_under_a_root_that_states_the_policy(tmp_path):
    accounts = {"a": _tg(), "b": _tg()}
    _assert_downgraded(_b55(tmp_path, {"telegram": {**_tg(), "accounts": accounts}}))


# ----------------------------------------------------- not one id: the old HIGH wording stays
@pytest.mark.parametrize("label, node", [
    ("two ids in allowFrom", _tg(allowFrom=[ID, "9"])),
    ("a different id per list (union of two)", _tg(groupAllowFrom=["9"])),
    ("the wildcard", _tg(allowFrom=["*"], groupAllowFrom=["*"])),
    ("wildcard next to an id", _tg(allowFrom=[ID, "*"])),
    ("an empty list is not one id", _tg(allowFrom=[], groupAllowFrom=[])),
    ("allowFrom missing", {k: v for k, v in _tg().items() if k != "allowFrom"}),
    ("group policy allowlist with no groupAllowFrom (Discord/Slack shape)",
     {k: v for k, v in _tg().items() if k != "groupAllowFrom"}),
    ("pairing", _tg(dmPolicy="pairing", groupPolicy="disabled")),
    ("a dict entry in the list", _tg(allowFrom=[{"id": ID}])),
    ("a boolean entry in the list", _tg(allowFrom=[True])),
    ("a string instead of a list", _tg(allowFrom=ID)),
    ("a prefixed spelling counts as a second id", _tg(allowFrom=[ID, f"telegram:{ID}"])),
])
def test_everything_that_is_not_exactly_one_id_keeps_the_high_warn(tmp_path, label, node):
    _assert_unchanged_high(_b55(tmp_path, {"telegram": node}))


def test_a_drifted_accounts_value_is_not_provable(tmp_path):
    _assert_unchanged_high(_b55(tmp_path, {"telegram": _tg(accounts=["a", "b"])}))


def test_a_second_account_with_another_id_is_not_one_id(tmp_path):
    channels = {"telegram": {"enabled": True, "accounts": {"a": _tg(), "b": _tg(allowFrom=["9"])}}}
    _assert_unchanged_high(_b55(tmp_path, channels))


@pytest.mark.parametrize("scope_key", ["allowFrom", "groupAllowFrom", "groupPolicy", "dmPolicy",
                                       "users", "roles", "allowedUsers"])
def test_a_per_conversation_scope_with_its_own_sender_policy_is_not_bounded(tmp_path, scope_key):
    node = _tg(groups={"-100": {scope_key: ["x"] if scope_key not in ("groupPolicy", "dmPolicy")
                                else "open"}})
    _assert_unchanged_high(_b55(tmp_path, {"telegram": node}))


def test_an_account_that_inherits_the_policy_but_brings_its_own_allowfrom_is_not_one_id(tmp_path):
    """The account states no policy, so it inherits the channel's allowlist - but its own
    allowFrom admits a SECOND sender. Counting only nodes that state a policy missed this."""
    channels = {"telegram": {**_tg(), "accounts": {"b": {"allowFrom": ["9"]}}}}
    _assert_unchanged_high(_b55(tmp_path, channels))


def test_an_account_that_states_no_policies_of_its_own_is_not_proven_even_with_the_same_id(tmp_path):
    """Every enabled node must state BOTH policies (an absent one is pairing / a provider
    default). An account repeating the root's id without them stays HIGH: conservative."""
    channels = {"telegram": {**_tg(), "accounts": {"b": {"allowFrom": [ID]}}}}
    _assert_unchanged_high(_b55(tmp_path, channels))


@pytest.mark.parametrize("extra", [
    {"allowBots": True},
    {"dm": {"policy": "open"}},
    {"dm": {"allowFrom": ["9"]}},
    {"group": {"policy": "open"}},
    {"users": ["9"]},
    {"roles": ["admin"]},
    {"commands": {"allowFrom": ["9"]}},
    {"dmAllowlist": ["9"]},
])
def test_a_sender_setting_the_helper_does_not_model_is_not_bounded(tmp_path, extra):
    _assert_unchanged_high(_b55(tmp_path, {"telegram": _tg(**extra)}))


@pytest.mark.parametrize("extra", [
    {"allowBots": False},
    {"botToken": "redacted-placeholder"},
    {"requireMention": True},
    {"streaming": "off"},
])
def test_harmless_or_off_settings_do_not_block_the_downgrade(tmp_path, extra):
    _assert_downgraded(_b55(tmp_path, {"telegram": _tg(**extra)}))


def test_two_ids_in_a_list_whose_policy_is_disabled_are_still_counted(tmp_path):
    """Conservative by design: the list is there, so its ids count, policy or not."""
    _assert_unchanged_high(_b55(tmp_path, {"telegram": _tg(groupPolicy="disabled",
                                                           groupAllowFrom=[ID, "9"])}))


# ---- found by the independent adversarial review (C-135), each confirmed against the dist ----
def test_an_access_group_entry_stands_for_many_senders(tmp_path):
    """``accessGroup:<name>`` in a list expands to the group's members (OpenClaw
    allow-from / access-groups modules), so one list entry is not one id."""
    cfg_channels = {"telegram": _tg(allowFrom=["accessGroup:team"], groupPolicy="disabled",
                                    groupAllowFrom=[])}
    (tmp_path / "openclaw.json").write_text(json.dumps({
        "tools": GATED,
        "accessGroups": {"team": {"type": "message.senders", "members": {"*": ["111", "222"]}}},
        "channels": cfg_channels}), encoding="utf-8")
    (tmp_path / "openclaw.json").chmod(0o600)
    _assert_unchanged_high(check_fs_write_exposure(collect(tmp_path)))


@pytest.mark.parametrize("entry", ["accessGroup:team", "ACCESSGROUP:team", "role:admin",
                                   "group:ops", "everyone", "all", "telegram:*", "*@*", "user*"])
def test_list_entries_that_name_a_group_or_a_pattern_are_not_one_id(entry):
    cfg = {"channels": {"telegram": _tg(allowFrom=[entry], groupAllowFrom=[entry])}}
    assert _one_id_bounded_channels(cfg) == set()


def test_a_missing_dm_policy_means_pairing_not_no_dm(tmp_path):
    """OpenClaw resolves an absent dmPolicy to ``pairing`` (helpers: ``dmPolicy ?? "pairing"``),
    which admits every approved pairer. Leaving it out must not read as 'no DM ingress'."""
    node = {"enabled": True, "groupPolicy": "allowlist", "groupAllowFrom": [ID]}
    _assert_unchanged_high(_b55(tmp_path, {"telegram": node}))


def test_a_missing_group_policy_is_not_assumed_closed(tmp_path):
    """Some providers default an absent groupPolicy to open; only an explicit policy is trusted."""
    node = _tg()
    del node["groupPolicy"], node["groupAllowFrom"]
    _assert_unchanged_high(_b55(tmp_path, {"telegram": node}))


def test_a_root_without_policies_next_to_one_id_accounts_is_not_bounded(tmp_path):
    channels = {"telegram": {"enabled": True, "botToken": "x", "accounts": {"a": _tg()}}}
    _assert_unchanged_high(_b55(tmp_path, channels))


def test_another_enabled_channel_with_no_policy_written_blocks_the_downgrade(tmp_path):
    """A channel whose policies are left at their (pairing) defaults is not listed as an
    untrusted-input channel, but it IS reachable - the sentence 'the ONE sender' would be false."""
    channels = {"telegram": _tg(), "discord": {"token": "x"}}
    _assert_unchanged_high(_b55(tmp_path, channels))


def test_a_second_channel_that_is_itself_one_id_does_not_block(tmp_path):
    signal = {"enabled": True, "dmPolicy": "allowlist", "allowFrom": [ID], "groupPolicy": "disabled"}
    _assert_downgraded(_b55(tmp_path, {"telegram": _tg(), "signal": signal}))


def test_the_low_sentence_does_not_claim_other_senders_cannot_reach_the_model(tmp_path):
    f = _b55(tmp_path, {"telegram": _tg()})
    assert "B26" in f.fix, "quoted/history context from other senders is the remaining reach"


@pytest.mark.parametrize("provider", ["feishu", "imessage", "whatsapp", "signal", "line", "slack"])
def test_a_group_allowlist_is_only_trusted_as_a_sender_list_where_that_is_verified(
        tmp_path, provider):
    """Round-2 review: on Feishu a `groupAllowFrom` entry is a GROUP chat id, on iMessage a
    `chat_id:` entry admits everyone in that chat, and those runtimes are not installed to
    prove otherwise. Only Telegram's list is verified to hold sender ids."""
    node = {"enabled": True, "dmPolicy": "disabled", "groupPolicy": "allowlist",
            "groupAllowFrom": [ID]}
    assert _one_id_bounded_channels({"channels": {provider: node}}) == set()
    _assert_unchanged_high(_b55(tmp_path, {provider: node}))


def test_a_dm_only_allowlist_of_one_id_on_another_provider_still_downgrades(tmp_path):
    node = {"enabled": True, "dmPolicy": "allowlist", "allowFrom": [ID], "groupPolicy": "disabled"}
    _assert_downgraded(_b55(tmp_path, {"signal": node}))


@pytest.mark.parametrize("entry", ["chat_id:42", "chat_guid:abc", "CHAT_IDENTIFIER:x"])
def test_chat_target_entries_name_a_conversation_not_a_sender(entry):
    node = {"enabled": True, "dmPolicy": "allowlist", "allowFrom": [entry],
            "groupPolicy": "disabled"}
    assert _one_id_bounded_channels({"channels": {"imessage": node}}) == set()


@pytest.mark.parametrize("extra", [
    {"dm": {"groupEnabled": True, "groupChannels": ["*"]}},
    {"toolsBySender": {"someone": {"deny": ["write"]}}},
    {"invite": True},
    {"guestAccess": True},
    {"publicAccess": True},
    {"memberInfo": True},
])
def test_round_two_hints_close_the_group_dm_and_sender_keyed_shapes(tmp_path, extra):
    _assert_unchanged_high(_b55(tmp_path, {"telegram": _tg(**extra)}))


def test_a_malformed_conversation_container_is_not_bounded(tmp_path):
    _assert_unchanged_high(_b55(tmp_path, {"telegram": _tg(groups=["not", "a", "dict"])}))


def test_a_mixed_set_of_channels_is_decided_by_the_least_narrow_one(tmp_path):
    channels = {"telegram": _tg(),
                "slack": {"enabled": True, "dmPolicy": "pairing"}}
    _assert_unchanged_high(_b55(tmp_path, channels))


def test_a_disabled_second_channel_does_not_block_the_downgrade(tmp_path):
    channels = {"telegram": _tg(), "slack": {"enabled": False, "dmPolicy": "pairing"}}
    _assert_downgraded(_b55(tmp_path, channels))


# ------------------------------------------------------ paths that must not be touched
def test_a_proven_open_channel_keeps_the_existing_path(tmp_path):
    channels = {"telegram": _tg(), "discord": {"enabled": True, "dmPolicy": "open"}}
    f = _b55(tmp_path, channels)
    assert NEW_DETAIL_HEAD not in f.detail
    assert f.severity != LOW


def test_without_an_approval_gate_the_one_id_does_not_change_the_verdict(tmp_path):
    f = _b55(tmp_path, {"telegram": _tg()}, tools={"profile": "full"})
    assert f.status == WARN and f.severity == HIGH
    assert NEW_DETAIL_HEAD not in f.detail


def test_no_declared_channel_still_passes_when_gated(tmp_path):
    f = _b55(tmp_path, {})
    assert f.status != WARN or NEW_DETAIL_HEAD not in f.detail


# ------------------------------------------------------------------------- the helper
def test_the_helper_returns_names_only_and_never_ids():
    cfg = {"channels": {"telegram": _tg()}}
    assert _one_id_bounded_channels(cfg) == {"telegram"}


@pytest.mark.parametrize("cfg", [{}, {"channels": None}, {"channels": []}, {"channels": {"x": 3}}])
def test_the_helper_survives_odd_configs(cfg):
    assert _one_id_bounded_channels(cfg) == set()


# ---------------------------------------------------------------------------- RISK-12
def _risk12(cfg: dict):
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = cfg
    return [p for p in risk_paths(ctx, run_all(ctx)) if p.id == "RISK-12"]


def test_risk12_label_no_longer_claims_no_approval_gate_when_one_is_set():
    cfg = {"tools": GATED, "channels": {"telegram": _tg()}}
    paths = _risk12(cfg)
    assert paths, "RISK-12 must still arm (text-only change, no status change)"
    chain = " | ".join(paths[0].chain)
    assert "no approval gate" not in chain
    assert "no write-specific scoping" in chain


def test_risk12_label_is_the_same_whether_or_not_a_gate_is_set():
    open_cfg = {"tools": {"allow": ["fs_write"]}, "channels": {"telegram": {"dmPolicy": "open"}}}
    paths = _risk12(open_cfg)
    assert paths and "no approval gate" not in " | ".join(paths[0].chain)
