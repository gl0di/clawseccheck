"""B-1002: a channel's open BASE node must stay in the verdict once named ``accounts`` exist
whenever OpenClaw still runs that base node as an implicit default account.

``_channel_has_implicit_default_account`` (``checks/_shared.py``) decides that per channel.
Its old table claimed to be exhaustive and said Slack registered no trigger; x, whatsapp and
slack (and signal, irc, line, matrix, ...) were missing, so an open base account with
credentials read as a B2 PASS as soon as one restrictive named account was added. The table
was re-enumerated from all 28 channel plugins of OpenClaw 2026.10.9 (grounding comment above
``_IMPLICIT_DEFAULT_ACCOUNT_KEYS``), and a channel that is not one of them keeps its base node
instead of dropping it.

Five consumers read the predicate: ``_open_channels`` (B2/B55), ``_open_wildcard_group_channels``
(B140 / behavioral / RISK), ``_resolved_default_input_channels``, ``_b171_open_channels`` and
B372's ``_allow_bots_account_nodes``. Each is exercised below on the same twin shapes.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS
from clawseccheck.checks import (
    _IMPLICIT_DEFAULT_ACCOUNT_KEYS,
    _IMPLICIT_DEFAULT_ACCOUNT_PREDICATES,
    _SINGLE_ACCOUNT_CHANNELS,
    _channel_has_implicit_default_account,
    _open_channels,
    _open_wildcard_group_channels,
    check_gateway,
)
from clawseccheck.checks._agents import _allow_bots_account_nodes
from clawseccheck.checks._config import _b171_open_channels
from clawseccheck.checks._shared import _resolved_default_input_channels
from clawseccheck.collector import Context

# Placeholder credential values. Nothing here is secret-shaped; OpenClaw's implicit-account
# predicates only test presence, never format.
V = "placeholder"

OPEN_BASE = {"enabled": True, "dmPolicy": "open", "allowFrom": ["*"], "groupPolicy": "open"}
WORK = {"work": {"dmPolicy": "pairing", "groupPolicy": "allowlist"}}

# Base credentials that make each channel's base node a live implicit default account.
LIVE = {
    "x": {"userId": V, "clientId": V, "refreshToken": V},
    "whatsapp": {"authDir": "/srv/wa"},
    "slack-socket": {"botToken": V, "appToken": V},
    "slack-http": {"mode": "http", "botToken": V, "signingSecret": V},
    "slack-relay": {
        "mode": "relay", "botToken": V, "relay": {"url": V, "authToken": V, "gatewayId": V},
    },
    "slack-user": {"postAs": "user", "userToken": V, "appToken": V},
    "signal": {"account": "+15550000000"},
    "irc": {"host": "irc.example", "nick": "bot"},
    "line": {"channelAccessToken": V},
    "matrix": {"homeserver": "https://m.example", "accessToken": V},
    "matrix-password": {"homeserver": "https://m.example", "userId": "@b:m", "password": V},
    "mattermost": {"baseUrl": "https://mm.example", "botToken": V},
    "clickclack": {"baseUrl": "https://cc.example", "token": V, "workspace": "w"},
    "twitch": {"channel": ""},
    "tlon": {"ship": "~zod"},
    "sms": {"accountSid": V},
    "nostr": {"privateKey": V},
    "buzz": {"relayUrl": V},
    "synology-chat": {"token": V},
    # controls: grounded before B-1002, unchanged by it
    "telegram": {"botToken": V},
    "zalo": {"botToken": V},
    "googlechat": {"serviceAccountFile": "/srv/sa.json"},
    "nextcloud-talk": {"baseUrl": "https://nc.example", "botSecret": V},
}

# Base nodes that do NOT spawn an implicit account under that channel's grounded rule, so the
# base policy is vestigial once `accounts` exists (B-389's original false-positive guard).
VESTIGIAL = {
    "x": {},
    "whatsapp": {"authDir": "  "},
    "slack-socket-no-app": {"botToken": V},
    "slack-http-no-secret": {"mode": "http", "botToken": V, "appToken": V},
    "slack-relay-partial": {"mode": "relay", "botToken": V, "relay": {"url": V, "authToken": V}},
    "slack-relay-not-object": {"mode": "relay", "botToken": V, "relay": V},
    "slack-user-wrong-token": {"postAs": "user", "botToken": V, "appToken": V},
    "slack-no-identity": {"appToken": V, "signingSecret": V},
    "irc-host-only": {"host": "irc.example"},
    "matrix-no-auth": {"homeserver": "https://m.example", "userId": "@b:m"},
    "mattermost-no-url": {"botToken": V},
    "clickclack-no-workspace": {"baseUrl": "https://cc.example", "token": V},
    "twitch-non-string": {"username": 5},
    "tlon-empty": {"ship": ""},
    "sms-bad-ref": {"authToken": {"source": "env"}},
    "telegram": {},
    "nextcloud-talk-no-url": {"botSecret": V},
}


def _channel(case: str) -> str:
    for name in sorted(
        {*_IMPLICIT_DEFAULT_ACCOUNT_KEYS, *_IMPLICIT_DEFAULT_ACCOUNT_PREDICATES}, key=len,
        reverse=True,
    ):
        if case == name or case.startswith(name + "-"):
            return name
    raise AssertionError(case)


def _cfg(case: str, creds: dict, accounts: dict | None = WORK) -> dict:
    node = {**creds, **OPEN_BASE}
    if accounts is not None:
        node["accounts"] = accounts
    return {"channels": {_channel(case): node}}


def _b2(cfg: dict) -> str:
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = cfg
    return check_gateway(ctx).status


# ------------------------------------------------------------------ the predicate itself

@pytest.mark.parametrize("case", sorted(LIVE))
def test_live_base_credentials_spawn_the_implicit_account(case):
    assert _channel_has_implicit_default_account(_channel(case), LIVE[case]) is True


@pytest.mark.parametrize("case", sorted(VESTIGIAL))
def test_vestigial_base_does_not(case):
    assert _channel_has_implicit_default_account(_channel(case), VESTIGIAL[case]) is False


@pytest.mark.parametrize("name", sorted(_SINGLE_ACCOUNT_CHANNELS))
def test_single_account_channels_always_keep_the_base(name):
    """a2a / reef / msteams list exactly one account whatever `accounts` holds."""
    assert _channel_has_implicit_default_account(name, {}) is True


def test_an_ungrounded_channel_keeps_its_base_node():
    """UNKNOWN direction: a channel outside the 28 enumerated plugins is not dropped."""
    assert _channel_has_implicit_default_account("acme-chat", {}) is True


@pytest.mark.parametrize("name", ["defaults", "modelByChannel"])
def test_reserved_channel_blocks_are_not_channels(name):
    assert _channel_has_implicit_default_account(name, {"token": V}) is False


def test_an_unreadable_trim_target_keeps_the_base_node():
    """A non-string where the vendor calls `.trim()` makes its predicate throw - whether the
    account runs is undeterminable, so the base stays evaluated rather than read as clean."""
    assert _channel_has_implicit_default_account("irc", {"host": ["h"], "nick": {"n": 1}})


# ----------------------------------------------------- B2 end to end (the task's table)

@pytest.mark.parametrize("case", sorted(LIVE))
def test_b2_open_live_base_fails_with_and_without_accounts(case):
    assert _b2(_cfg(case, LIVE[case], accounts=None)) == FAIL
    assert _b2(_cfg(case, LIVE[case])) == FAIL


@pytest.mark.parametrize("case", sorted(VESTIGIAL))
def test_b2_vestigial_open_base_passes_once_accounts_override_it(case):
    assert _b2(_cfg(case, VESTIGIAL[case])) == PASS


def test_b2_ungrounded_channel_open_base_is_not_a_clean_pass():
    cfg = {"channels": {"acme-chat": {**OPEN_BASE, "token": V, "accounts": WORK}}}
    assert _b2(cfg) == FAIL


def test_b2_restricted_live_base_still_passes():
    """Clean twin: a live base account whose own policy is closed adds nothing."""
    node = {**LIVE["slack-socket"], "enabled": True, "dmPolicy": "pairing",
            "groupPolicy": "allowlist", "accounts": WORK}
    assert _b2({"channels": {"slack": node}}) == PASS


# ------------------------------------------------------------- the other four consumers

@pytest.mark.parametrize("case", ["x", "whatsapp", "slack-socket", "slack-http", "slack-relay",
                                  "slack-user", "telegram"])
def test_open_channels_and_b171_keep_the_live_base(case):
    cfg = _cfg(case, LIVE[case])
    assert _open_channels(cfg) == [_channel(case)]
    assert _b171_open_channels(cfg) == [_channel(case)]


@pytest.mark.parametrize("case", ["x", "slack-socket-no-app", "slack-http-no-secret"])
def test_open_channels_and_b171_drop_the_vestigial_base(case):
    cfg = _cfg(case, VESTIGIAL[case])
    assert _open_channels(cfg) == []
    assert _b171_open_channels(cfg) == []


@pytest.mark.parametrize("case", ["x", "whatsapp", "slack-socket", "slack-relay", "telegram"])
def test_wildcard_group_live_base_survives_a_disabled_account(case):
    """The ~3708 consumer (`_open_wildcard_group_channels`)."""
    node = {**LIVE[case], "enabled": True, "groups": {"*": {}},
            "accounts": {"retired": {"enabled": False}}}
    cfg = {"channels": {_channel(case): node}}
    assert _channel(case) in _open_wildcard_group_channels(cfg)


@pytest.mark.parametrize("case", ["x", "slack-socket-no-app"])
def test_wildcard_group_on_a_vestigial_base_is_silent(case):
    node = {**VESTIGIAL[case], "enabled": True, "groups": {"*": {}},
            "accounts": {"retired": {"enabled": False}}}
    assert _open_wildcard_group_channels({"channels": {_channel(case): node}}) == {}


@pytest.mark.parametrize("case", ["x", "whatsapp", "slack-socket", "telegram"])
def test_resolved_default_input_sees_the_live_base(case):
    """Base writes no dmPolicy, the one account disables DMs: the live base account still
    runs on the resolved default, so the channel is reported (B-619's repro-3 shape)."""
    node = {**LIVE[case], "enabled": True,
            "accounts": {"work": {"dmPolicy": "disabled"}}}
    assert _resolved_default_input_channels({"channels": {_channel(case): node}}) == [
        _channel(case)
    ]
    vestigial = {"enabled": True, "accounts": node["accounts"]}
    assert _resolved_default_input_channels({"channels": {_channel(case): vestigial}}) == []


def test_allow_bots_nodes_include_a_live_slack_base():
    base = {**LIVE["slack-socket"], "allowBots": True}
    c = {**base, "accounts": WORK}
    nodes = _allow_bots_account_nodes("slack", c)
    assert {k: v for k, v in c.items() if k != "accounts"} in nodes
    c2 = {**VESTIGIAL["slack-socket-no-app"], "allowBots": True, "accounts": WORK}
    assert len(_allow_bots_account_nodes("slack", c2)) == 1


# --------------------------------------------------------------------- mutation check

def test_reverting_the_table_reopens_the_false_pass(monkeypatch):
    """With the pre-B-1002 table and default (unlisted -> dropped), the x/whatsapp/slack
    twins read as a B2 PASS again - so the tests above genuinely depend on this change."""
    from clawseccheck.checks import _shared

    old = {
        "telegram": ("botToken", "tokenFile"), "discord": ("token",),
        "googlechat": ("serviceAccount", "serviceAccountRef", "serviceAccountFile"),
        "zalo": ("botToken", "tokenFile"), "zalouser": ("profile",),
        "imessage": ("cliPath", "dbPath"), "raft": ("profile",),
    }

    def reverted(name, raw_node):
        if not isinstance(raw_node, dict):
            return False
        return any(raw_node.get(k) is not None for k in old.get(name, ()))

    monkeypatch.setattr(_shared, "_channel_has_implicit_default_account", reverted)
    for case in ("x", "whatsapp", "slack-socket"):
        assert _b2(_cfg(case, LIVE[case])) == PASS
    assert _b2(_cfg("telegram", LIVE["telegram"])) == FAIL
