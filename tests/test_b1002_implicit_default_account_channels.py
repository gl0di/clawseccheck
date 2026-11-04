"""B-1002: a channel's open BASE node must stay in the verdict once named ``accounts`` exist
whenever OpenClaw still runs that base node as an implicit default account.

``_channel_has_implicit_default_account`` (``checks/_shared.py``) decides that per channel.
Its old table claimed to be exhaustive and said Slack registered no trigger; x, whatsapp and
slack (and signal, irc, line, matrix, ...) were missing, so an open base account with
credentials read as a B2 PASS as soon as one restrictive named account was added. The table
was re-enumerated from all 28 channel plugins of OpenClaw 2026.10.9 (grounding comment above
``_IMPLICIT_DEFAULT_ACCOUNT_KEYS``), and a channel that is not one of them keeps its base node
instead of dropping it.

The base node is re-added through ONE gate, ``_base_node_runs_unmerged`` (wrapped by
``_live_channel_nodes``), read by ``_open_channels`` (B2/B55), ``_b171_open_channels``,
``_open_wildcard_group_channels`` (behavioral arming, RISK chains, ``_capability``),
``_resolved_default_input_channels``, B372's ``_allow_bots_account_nodes``, and - since the
C-135 round 2 - B140 (``check_wildcard_group_ingress``), B371
(``check_channel_mention_gate_bypass``), ``risk._open_group_channels`` (RISK-21) and A1's
``_unpolicied_open_wildcard_group_channels``. Each is exercised below.

C-135 round 2 (BLOCKER): when a configured entry IS the default account (``default``, or a
key the vendor's account lookup normalizes to it), it and the implicit default account are one
account whose config is the merge, so the raw base must NOT be re-added - doing so read a
base policy the entry overrides as a B2 FAIL.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS
from clawseccheck.checks import (
    _IMPLICIT_DEFAULT_ACCOUNT_KEYS,
    _IMPLICIT_DEFAULT_ACCOUNT_PREDICATES,
    _SINGLE_ACCOUNT_CHANNELS,
    _base_node_runs_unmerged,
    _canonical_account_id,
    _channel_has_implicit_default_account,
    _open_channels,
    _open_wildcard_group_channels,
    check_channel_mention_gate_bypass,
    check_gateway,
    check_wildcard_group_ingress,
)
from clawseccheck.checks._agents import _allow_bots_account_nodes
from clawseccheck.checks._config import _b171_open_channels
from clawseccheck.checks._shared import (
    _resolved_default_input_channels,
    _unpolicied_open_wildcard_group_channels,
)
from clawseccheck.collector import Context
from clawseccheck.risk import _open_group_channels

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
        {*_IMPLICIT_DEFAULT_ACCOUNT_KEYS, *_IMPLICIT_DEFAULT_ACCOUNT_PREDICATES,
         *_SINGLE_ACCOUNT_CHANNELS}, key=len,
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


def _misses(cases, check):
    """Run *check* over every case; return the ids whose expectation failed. One test item
    per question keeps the collected count proportional to behaviours, not to table rows
    (the suite's test-count claim is a guarded band)."""
    bad = []
    for case in cases:
        try:
            if not check(case):
                bad.append(case)
        except AssertionError as exc:  # a helper's own assert
            bad.append(f"{case}: {exc}")
    return bad


# ------------------------------------------------------------------ the predicate itself

def test_live_base_credentials_spawn_the_implicit_account():
    assert _misses(sorted(LIVE), lambda c: _channel_has_implicit_default_account(
        _channel(c), LIVE[c]) is True) == []


def test_vestigial_base_does_not():
    assert _misses(sorted(VESTIGIAL), lambda c: _channel_has_implicit_default_account(
        _channel(c), VESTIGIAL[c]) is False) == []


def test_single_account_channels_always_keep_the_base():
    """a2a / reef / nostr list exactly one account whatever `accounts` holds."""
    assert _misses(sorted(_SINGLE_ACCOUNT_CHANNELS),
                   lambda n: _channel_has_implicit_default_account(n, {}) is True) == []


def test_an_ungrounded_channel_keeps_its_base_node():
    """UNKNOWN direction: a channel outside the 28 enumerated plugins is not dropped."""
    assert _channel_has_implicit_default_account("acme-chat", {}) is True


def test_reserved_channel_blocks_are_not_channels():
    for name in ("defaults", "modelByChannel"):
        assert _channel_has_implicit_default_account(name, {"token": V}) is False, name


def test_an_unreadable_trim_target_keeps_the_base_node():
    """A non-string where the vendor calls `.trim()` makes its predicate throw - whether the
    account runs is undeterminable, so the base stays evaluated rather than read as clean."""
    assert _channel_has_implicit_default_account("irc", {"host": ["h"], "nick": {"n": 1}})


# ----------------------------------------------------- B2 end to end (the task's table)

def test_b2_open_live_base_fails_with_and_without_accounts():
    assert _misses(sorted(LIVE), lambda c: (
        _b2(_cfg(c, LIVE[c], accounts=None)) == FAIL and _b2(_cfg(c, LIVE[c])) == FAIL
    )) == []


def test_b2_vestigial_open_base_passes_once_accounts_override_it():
    assert _misses(sorted(VESTIGIAL), lambda c: _b2(_cfg(c, VESTIGIAL[c])) == PASS) == []


def test_b2_ungrounded_channel_open_base_is_not_a_clean_pass():
    cfg = {"channels": {"acme-chat": {**OPEN_BASE, "token": V, "accounts": WORK}}}
    assert _b2(cfg) == FAIL


def test_b2_restricted_live_base_still_passes():
    """Clean twin: a live base account whose own policy is closed adds nothing."""
    node = {**LIVE["slack-socket"], "enabled": True, "dmPolicy": "pairing",
            "groupPolicy": "allowlist", "accounts": WORK}
    assert _b2({"channels": {"slack": node}}) == PASS


# ------------------------------------------------------------- the other consumers

def test_open_channels_and_b171_keep_the_live_base():
    def ok(case):
        cfg = _cfg(case, LIVE[case])
        return _open_channels(cfg) == [_channel(case)] == _b171_open_channels(cfg)
    assert _misses(["x", "whatsapp", "slack-socket", "slack-http", "slack-relay",
                    "slack-user", "telegram"], ok) == []


def test_open_channels_and_b171_drop_the_vestigial_base():
    def ok(case):
        cfg = _cfg(case, VESTIGIAL[case])
        return _open_channels(cfg) == [] == _b171_open_channels(cfg)
    assert _misses(["x", "slack-socket-no-app", "slack-http-no-secret"], ok) == []


def test_wildcard_group_follows_the_live_base_beside_a_disabled_account():
    def node(creds):
        return {**creds, "enabled": True, "groups": {"*": {}},
                "accounts": {"retired": {"enabled": False}}}
    assert _misses(["x", "whatsapp", "slack-socket", "slack-relay", "telegram"], lambda c: (
        _channel(c) in _open_wildcard_group_channels({"channels": {_channel(c): node(LIVE[c])}})
    )) == []
    assert _misses(["x", "slack-socket-no-app"], lambda c: (
        _open_wildcard_group_channels({"channels": {_channel(c): node(VESTIGIAL[c])}}) == {}
    )) == []


def test_resolved_default_input_sees_the_live_base():
    """Base writes no dmPolicy, the one account disables DMs: the live base account still
    runs on the resolved default, so the channel is reported (B-619's repro-3 shape)."""
    accounts = {"work": {"dmPolicy": "disabled"}}

    def ok(case):
        live = {**LIVE[case], "enabled": True, "accounts": accounts}
        vestigial = {"enabled": True, "accounts": accounts}
        return (_resolved_default_input_channels({"channels": {_channel(case): live}})
                == [_channel(case)]
                and _resolved_default_input_channels({"channels": {_channel(case): vestigial}})
                == [])
    assert _misses(["x", "whatsapp", "slack-socket", "telegram"], ok) == []


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

    def reverted(name, raw_node, cfg=None):
        if not isinstance(raw_node, dict):
            return False
        return any(raw_node.get(k) is not None for k in old.get(name, ()))

    monkeypatch.setattr(_shared, "_channel_has_implicit_default_account", reverted)
    for case in ("x", "whatsapp", "slack-socket"):
        assert _b2(_cfg(case, LIVE[case])) == PASS
    assert _b2(_cfg("telegram", LIVE["telegram"])) == FAIL


# ===================================================== C-135 round 2: the default account

# One live base credential set per channel: all 28 channel plugins of OpenClaw 2026.10.9,
# plus an ungrounded channel name.
EVERY = {
    "telegram": {"botToken": V}, "x": {"clientId": V}, "whatsapp": {"authDir": "/srv/wa"},
    "discord": {"token": V}, "googlechat": {"serviceAccountFile": "/srv/sa.json"},
    "zalo": {"botToken": V}, "zalouser": {"profile": V}, "imessage": {"cliPath": "/c"},
    "raft": {"profile": V}, "signal": {"account": "+1"}, "buzz": {"relayUrl": V},
    "qa-channel": {"baseUrl": V}, "synology-chat": {"token": V},
    "slack": {"botToken": V, "appToken": V},
    "matrix": {"homeserver": "https://m.example", "accessToken": V},
    "feishu": {"appId": V, "appSecret": V},
    "nextcloud-talk": {"baseUrl": "https://nc.example", "botSecret": V},
    "irc": {"host": "h", "nick": "n"}, "mattermost": {"baseUrl": V, "botToken": V},
    "clickclack": {"baseUrl": V, "token": V, "workspace": "w"},
    "line": {"channelAccessToken": V}, "tlon": {"ship": "~zod"}, "twitch": {"username": "u"},
    "sms": {"accountSid": V}, "nostr": {"privateKey": V}, "a2a": {}, "reef": {}, "msteams": {"appId": V},
    "acme-chat": {"token": V},
}
# a configured account that closes every surface it inherits from the base
CLOSED = {"dmPolicy": "pairing", "groupPolicy": "allowlist", "allowFrom": ["u1"],
          "groups": {"g1": {"requireMention": True}}}

# INDEPENDENT ORACLE, written from the vendor sources at tag v2026.10.9 (not imported from
# the code under test): which configured key is the entry the vendor reads as the default
# account, per channel class.
KEYS = ["default", "Default", " default ", "DEFAULT", "default!", "-default-", "(default)",
        "default."]
_TRIM_LOWER_MATCH = {"default", "Default", " default ", "DEFAULT"}
VENDOR_CLASS = {
    # resolveAccountKey with no normalizer: trim + lowercase (+ unknown channels, SDK default)
    **{n: "trim-lower" for n in (
        "discord", "feishu", "googlechat", "imessage", "line", "mattermost", "slack", "sms",
        "synology-chat", "whatsapp", "x", "zalo", "zalouser", "acme-chat")},
    # normalizeAccountId passed: every key above canonicalizes to "default"
    **{n: "canonical" for n in (
        "clickclack", "irc", "raft", "qa-channel", "telegram", "matrix", "nextcloud-talk",
        "twitch", "msteams")},
    "buzz": "exact",      # root.accounts?.[accountId]
    "signal": "signal",   # manifest policy: lowercase direct, canonical only with own `account`
    # the raw base is what the default (or only) account reads
    **{n: "base" for n in ("tlon", "a2a", "reef", "nostr")},
}
_MATCHES = {
    "trim-lower": _TRIM_LOWER_MATCH,
    "canonical": set(KEYS),
    "exact": {"default"},
    "signal": _TRIM_LOWER_MATCH,  # without the entry's own `account`
    "base": set(),
}


def _vendor_base_runs(name: str, key: str | None, entry=None) -> bool:
    """Does the vendor run the raw base as its own account, given one extra configured key?"""
    cls = VENDOR_CLASS[name]
    if cls == "base" or key is None or not isinstance(entry, dict):
        return True
    if cls == "signal" and isinstance(entry.get("account"), str) and entry["account"].strip():
        return False  # every KEY canonicalizes to "default" and the entry owns `account`
    return key not in _MATCHES[cls]


def test_the_oracle_covers_every_channel():
    assert set(VENDOR_CLASS) == set(EVERY)


# accounts block -> (key that may be the default entry, that entry)
SHAPES = {f"key {k!r}": ({k: dict(CLOSED)}, k, CLOSED) for k in KEYS}
SHAPES.update({
    "no default": ({"w": dict(CLOSED)}, None, None),
    "disabled default": ({"default": {"enabled": False}, "w": dict(CLOSED)}, "default",
                         {"enabled": False}),
    "non-object default": ({"default": None, "w": dict(CLOSED)}, "default", None),
    "default beside another": ({"default": dict(CLOSED), "w": dict(CLOSED)}, "default", CLOSED),
})
MATRIX = [(n, sh) for n in sorted(EVERY) for sh in sorted(SHAPES)]


def _expected_separate(name: str, shape: str) -> bool:
    _, key, entry = SHAPES[shape]
    return _vendor_base_runs(name, key, entry)


def test_the_gate_matches_the_vendor_default_account_rule():
    def ok(row):
        name, shape = row
        c = {**EVERY[name], "dmPolicy": "open", "accounts": SHAPES[shape][0]}
        return _base_node_runs_unmerged(name, c) is _expected_separate(name, shape)
    assert _misses(MATRIX, ok) == []


def test_signal_wide_keys_count_only_with_their_own_account():
    def runs(key, entry):
        c = {**EVERY["signal"], "dmPolicy": "open", "accounts": {key: entry}}
        return _base_node_runs_unmerged("signal", c)
    for key in KEYS:
        lowered = key in _TRIM_LOWER_MATCH
        assert runs(key, {"dmPolicy": "pairing"}) is not lowered, key
        assert runs(key, {"dmPolicy": "pairing", "account": "+1555"}) is False, key
        assert runs(key, {"dmPolicy": "pairing", "account": "  "}) is not lowered, key


def test_buzz_matches_the_exact_key_only():
    def runs(key):
        c = {**EVERY["buzz"], "dmPolicy": "open", "accounts": {key: dict(CLOSED)}}
        return _base_node_runs_unmerged("buzz", c)
    assert runs("default") is False
    assert runs("Default") is True and runs(" default ") is True


def test_nostr_with_accounts_still_reads_the_base():
    """nostr has no `accounts` in its schema and resolveNostrAccountBase ignores it."""
    for key in ("default", "w"):
        c = {"dmPolicy": "open", "accounts": {key: dict(CLOSED)}}
        assert _base_node_runs_unmerged("nostr", c) is True, key
    assert _b2({"channels": {"nostr": {"dmPolicy": "open", "accounts": {
        "default": {"dmPolicy": "pairing"}}}}}) == FAIL


@pytest.mark.parametrize("mutant", ["canonical everywhere", "exact only"])
def test_mutating_the_key_matcher_breaks_the_oracle(monkeypatch, mutant):
    """Mutation check: both retracted matchers disagree with the vendor table."""
    from clawseccheck.checks import _shared

    def canonical(name, key, entry):
        return isinstance(entry, dict) and _shared._canonical_account_id(key) == "default"

    def exact(name, key, entry):
        return isinstance(entry, dict) and key == "default"

    monkeypatch.setattr(_shared, "_is_default_account_entry",
                        canonical if mutant == "canonical everywhere" else exact)

    def ok(row):
        name, shape = row
        c = {**EVERY[name], "dmPolicy": "open", "accounts": SHAPES[shape][0]}
        return _base_node_runs_unmerged(name, c) is _expected_separate(name, shape)
    assert _misses(MATRIX, ok) != []


def test_the_reviewer_repro_discord_default_bang_fails_again():
    cfg = {"channels": {"discord": {"token": V, "dmPolicy": "open", "allowFrom": ["*"],
                                    "accounts": {"default!": {"dmPolicy": "pairing"}}}}}
    assert _b2(cfg) == FAIL
    cfg["channels"]["discord"]["accounts"] = {"Default": {"dmPolicy": "pairing"}}
    assert _b2(cfg) == PASS


def _consumers_agree(row) -> bool:
    name, shape = row
    accounts = SHAPES[shape][0]
    live = _expected_separate(name, shape)
    # base: open policy and an unrestricted wildcard group, no own allowFrom
    open_node = {**EVERY[name], "enabled": True, "dmPolicy": "open", "groupPolicy": "open",
                 "groups": {"*": {"requireMention": False}}, "accounts": accounts}
    cfg = {"channels": {name: open_node}}
    # the non-object default keeps the raw node through _resolved_channel_nodes' own
    # schema-drift fallback, so every consumer sees it regardless of the gate
    seen = live or shape == "non-object default"
    got = {
        "_open_channels": name in _open_channels(cfg),
        "_b171_open_channels": name in _b171_open_channels(cfg),
        "_open_wildcard_group_channels": name in _open_wildcard_group_channels(cfg),
        "risk._open_group_channels": name in _open_group_channels(cfg),
    }
    # the A1 leg reads only a node that writes no dmPolicy/groupPolicy at all
    bare = {**EVERY[name], "enabled": True, "groups": {"*": {}}, "accounts": accounts}
    got["_unpolicied_open_wildcard_group_channels"] = (
        name in _unpolicied_open_wildcard_group_channels({"channels": {name: bare}})
    )
    bad = [k for k, v in got.items() if v is not seen]
    # resolved-default: base writes no dmPolicy; every configured account declares one
    rdi_accounts = {
        # flat and nested forms: matrix/googlechat declare DM policy only as `dm.policy`
        k: ({"dmPolicy": "disabled", "dm": {"policy": "disabled"},
             **({"enabled": False} if v.get("enabled") is False else {})}
            if isinstance(v, dict) else v)
        for k, v in accounts.items()
    }
    rdi_node = {**EVERY[name], "enabled": True, "accounts": rdi_accounts}
    if (name in _resolved_default_input_channels({"channels": {name: rdi_node}})) is not live:
        bad.append("_resolved_default_input_channels")
    assert not bad, bad
    return True


def test_every_policy_consumer_follows_the_gate():
    assert _misses(MATRIX, _consumers_agree) == []


def test_allow_bots_nodes_follow_the_gate():
    def ok(row):
        name, shape = row
        c = {**EVERY[name], "accounts": SHAPES[shape][0]}
        root = {k: v for k, v in c.items() if k != "accounts"}
        return (root in _allow_bots_account_nodes(name, c)) is _expected_separate(name, shape)
    assert _misses([r for r in MATRIX if r[0] in ("discord", "slack", "tlon")], ok) == []


def test_the_c135_blocker_repro_is_a_pass_again():
    cfg = {"channels": {"slack": {"botToken": V, "appToken": V, "dmPolicy": "open",
                                  "accounts": {"default": {"dmPolicy": "pairing"}}}}}
    assert _b2(cfg) == PASS
    cfg["channels"]["slack"]["accounts"] = {"w": {"dmPolicy": "pairing"}}
    assert _b2(cfg) == FAIL


def test_tlon_default_entry_does_not_hide_the_raw_base():
    """tlon's default account reads the RAW channel node (tlon/src/types.ts:54-60)."""
    cfg = {"channels": {"tlon": {"ship": "~zod", "dmPolicy": "open",
                                 "accounts": {"default": {"dmPolicy": "pairing"}}}}}
    assert _b2(cfg) == FAIL


def test_canonical_account_id_mirrors_the_vendor():
    cases = [("default", "default"), ("Default", "default"), (" DEFAULT ", "default"),
             ("default!", "default"), ("-default-", "default"), ("work", "work"), ("", None),
             ("!!!", None), (5, None)]
    assert [(k, _canonical_account_id(k)) for k, _ in cases] == cases


# ------------------------------------------- B140 / B371 now see the live implicit account

_WILDCARD_SLACK = {"botToken": V, "appToken": V, "groupPolicy": "open",
                   "groups": {"*": {"requireMention": False}}}
_RESTRICTED_ACCOUNT = {"w": {"groupPolicy": "allowlist", "allowFrom": ["u1"],
                             "groups": {"g1": {"requireMention": True}}}}


def _status(check, cfg):
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = cfg
    return check(ctx).status


def test_live_base_wildcard_group_is_seen_by_b140_and_b371():
    live = {"channels": {"slack": {**_WILDCARD_SLACK, "accounts": _RESTRICTED_ACCOUNT}}}
    vestigial = {"channels": {"slack": {**_WILDCARD_SLACK, "appToken": None,
                                        "accounts": _RESTRICTED_ACCOUNT}}}
    merged = {"channels": {"slack": {**_WILDCARD_SLACK, "accounts": {
        "default": _RESTRICTED_ACCOUNT["w"]}}}}
    for check in (check_wildcard_group_ingress, check_channel_mention_gate_bypass):
        assert _status(check, live) != PASS, check.__name__
        assert _status(check, vestigial) == PASS, check.__name__
        assert _status(check, merged) == PASS, check.__name__


def test_risk_open_group_channels_sees_the_live_base():
    cfg = {"channels": {"slack": {**_WILDCARD_SLACK, "accounts": _RESTRICTED_ACCOUNT}}}
    assert "slack" in _open_group_channels(cfg)


# ----------------------------------------------------------------- round-2 mutation check

def test_ignoring_the_default_account_reopens_the_blocker(monkeypatch):
    """Without the default-account guard in the gate, the blocker repro FAILs again."""
    from clawseccheck.checks import _shared

    def no_guard(name, c, cfg=None):
        accounts = c.get("accounts") if isinstance(c, dict) else None
        return bool(isinstance(accounts, dict) and accounts
                    and _shared._channel_has_implicit_default_account(name, c))

    monkeypatch.setattr(_shared, "_base_node_runs_unmerged", no_guard)
    cfg = {"channels": {"slack": {"botToken": V, "appToken": V, "dmPolicy": "open",
                                  "accounts": {"default": {"dmPolicy": "pairing"}}}}}
    assert _b2(cfg) == FAIL
