"""B-274 (+ the B-283 monitor handoff): the channel drift signature was mostly blind.

``monitor._channel_sig`` collapsed a whole channel to ``dm=/grp=/auth=``, where ``auth``
was ``bool(...)`` over *field presence*. Consequences, every one of them measured against
the real helper before the fix — all four mutations below produced the byte-identical
signature ``82f888f98bca57be``:

  * ``allowFrom: ["owner"]`` -> ``["owner", "attacker-666"]``  — silent
  * ``allowFrom: ["owner"]`` -> ``["*"]``                      — silent
  * ``botToken`` swapped (the channel taken over)              — silent, because the
    package read ``token`` and Telegram's credential field is ``botToken``
  * ``groups["*"].requireMention`` true -> false               — silent, ``requireMention``
    was not read at any scope

and, carried over from B-283's deferred ``monitor.py`` hunk:

  * ``contextVisibility`` -> ``"all"`` at any scope            — silent, the field was
    absent from the signature entirely
  * Feishu's ``groupPolicy: "allowall"`` alias                 — hashed as *not* open,
    though the dist transforms it to exactly ``"open"``

Two controls behaved *oppositely* to the wildcard case: ``allowFrom -> []`` and
``dmPolicy -> open`` both alerted correctly. So the tool treated ``[]`` (alert) and
``["*"]`` (silence) as opposites, though ``allowWhenEmpty`` makes them semantically the
same in OpenClaw.

FP GUARD — the reason the signature is a dict of named sub-keys and not one hash. Widening
one opaque hash re-hashes EVERY channel, which fires "Channel 'X' openness/auth changed" on
every user's first post-upgrade run against a config nobody touched. That is the B-279
precedent (a naive widen mass-fired rug-pull RP2 HIGH on every unchanged ``npx -y <pkg>``).
``diff()`` therefore compares only sub-keys present on BOTH sides, and
``test_upgrade_from_legacy_snapshot_is_silent`` pins it.

Read-only and offline: committed fixtures and ``tmp_path`` only.
"""
import copy
import json
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.monitor import (
    _CHANNEL_SCOPE_KEYS,
    _channel_entry,
    _channel_sig,
    _h,
    diff,
    record_events,
    save_state,
    snapshot,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
CLEAN = FIXTURES / "clean_mon_channel_stable"
DRIFTED = FIXTURES / "bad_mon_channel_drifted"


class _Ctx:
    """Minimal stand-in — ``_channel_sig`` reads nothing but ``ctx.config``."""

    def __init__(self, config):
        self.config = config


def _cfg(home: Path) -> dict:
    return json.loads((home / "openclaw.json").read_text(encoding="utf-8"))


def _sig(config: dict) -> dict:
    return _channel_sig(_Ctx(config))


def _telegram(config: dict) -> dict:
    return _sig(config)["telegram"]


def _mutate(mutation) -> dict:
    """The clean fixture's telegram node with one mutation applied."""
    config = _cfg(CLEAN)
    mutation(config["channels"]["telegram"])
    return _telegram(config)


def _changed_keys(before: dict, after: dict) -> list:
    return sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))


def _channel_alerts(alerts):
    return [(lvl, msg) for lvl, msg in alerts if "openness/auth changed" in msg]


def _head_core(c: dict) -> str:
    """The pre-B-274 ``core`` formula, transcribed verbatim from HEAD.

    Deliberately duplicated rather than imported: its whole purpose is to be an
    INDEPENDENT copy of the historical value, so that a future edit to the production
    formula cannot silently drag the expectation along with it.
    """
    accounts = c.get("accounts")
    nodes = [c] + (list(accounts.values()) if isinstance(accounts, dict) else [])
    nodes = [n for n in nodes if isinstance(n, dict)]
    dm = any(n.get("dmPolicy") == "open" for n in nodes)
    grp = any(n.get("groupPolicy") == "open" for n in nodes)
    has_auth = bool(c.get("token") or c.get("auth") or c.get("allowFrom")
                    or c.get("allowlist") or c.get("allowedSenders"))
    return _h(f"dm={dm};grp={grp};auth={has_auth}")


def _legacy_snapshot(channels: dict) -> dict:
    """A pre-B-274 snapshot: one hash STRING per channel, computed by HEAD's formula."""
    return {"config_hash": "unchanged", "channels":
            {name: _head_core(node) for name, node in channels.items()}}


def _snap(home, prev=None):
    ctx, findings, score = audit(home)
    return snapshot(ctx, findings, score, prev=prev)


# --------------------------------------------------------------- clean: no drift, silent

def test_clean_fixture_unchanged_channel_produces_no_alert():
    """CLEAN: same config twice — nothing is reported."""
    first = _snap(CLEAN)
    second = _snap(CLEAN, prev=first)
    assert _channel_alerts(diff(first, second)) == []


def test_clean_fixture_signature_is_stable_across_recomputation():
    assert _telegram(_cfg(CLEAN)) == _telegram(_cfg(CLEAN))


# ------------------------------------------------- bad: end-to-end through audit+snapshot

def test_drifted_fixture_raises_a_channel_alert():
    """BAD: the drifted fixture alerts through the real audit -> snapshot -> diff path."""
    first = _snap(CLEAN)
    second = _snap(DRIFTED, prev=first)
    alerts = _channel_alerts(diff(first, second))
    assert alerts, "channel drift went unreported"
    assert all(lvl == "MEDIUM" for lvl, _ in alerts)
    assert any("telegram" in msg for _, msg in alerts)


def test_the_two_fixtures_are_indistinguishable_to_the_old_signature():
    """The defect, pinned: `core` is the pre-B-274 formula, and it CANNOT tell them apart.

    Every difference between the clean and drifted fixture lives in a dimension the old
    one-hash signature did not read. If this ever fails, the fixtures have drifted into
    testing something the old code already caught, and the regression guard is worthless.
    """
    assert _telegram(_cfg(CLEAN))["core"] == _telegram(_cfg(DRIFTED))["core"]
    assert _telegram(_cfg(CLEAN)) != _telegram(_cfg(DRIFTED))


# ------------------------------------------------------ B-274: the four silent mutations

def test_allowlist_membership_widening_is_detected():
    """`allowFrom: [owner] -> [owner, attacker]` — presence unchanged, membership is not."""
    before = _telegram(_cfg(CLEAN))
    after = _mutate(lambda t: t["allowFrom"].append("attacker-666"))
    assert _changed_keys(before, after) == ["allow"]


def test_allowlist_collapsing_to_wildcard_is_detected():
    """`allowFrom -> ["*"]`, the case that was silent while `-> []` alerted."""
    before = _telegram(_cfg(CLEAN))
    after = _mutate(lambda t: t.__setitem__("allowFrom", ["*"]))
    assert _changed_keys(before, after) == ["allow"]


def test_empty_and_wildcard_allowlists_are_no_longer_opposites():
    """Both are openness changes; neither may be silent."""
    before = _telegram(_cfg(CLEAN))
    emptied = _mutate(lambda t: t.__setitem__("allowFrom", []))
    wildcarded = _mutate(lambda t: t.__setitem__("allowFrom", ["*"]))
    assert "allow" in _changed_keys(before, emptied)
    assert "allow" in _changed_keys(before, wildcarded)
    # ...and they are not each other, either.
    assert emptied["allow"] != wildcarded["allow"]


def test_group_allowlist_wildcard_is_detected():
    """`groupAllowFrom` is a real, array-typed schema field and was entirely unread."""
    before = _telegram(_cfg(CLEAN))
    after = _mutate(lambda t: t.__setitem__("groupAllowFrom", ["*"]))
    assert _changed_keys(before, after) == ["allow"]


def test_bot_token_swap_is_detected():
    """A swapped `botToken` is the channel changing hands; the package read `token`."""
    before = _telegram(_cfg(CLEAN))
    after = _mutate(lambda t: t.__setitem__("botToken", "env:SOME_OTHER_REF"))
    assert _changed_keys(before, after) == ["secrets"]


def test_require_mention_disabled_on_wildcard_group_is_detected():
    """`groups["*"].requireMention: false` — the dist's own allowUnmentionedGroups case."""
    before = _telegram(_cfg(CLEAN))
    after = _mutate(lambda t: t["groups"]["*"].__setitem__("requireMention", False))
    assert _changed_keys(before, after) == ["gating"]


def test_require_mention_disabled_at_channel_scope_is_detected():
    before = _telegram(_cfg(CLEAN))
    after = _mutate(lambda t: t.__setitem__("requireMention", False))
    assert _changed_keys(before, after) == ["gating"]


# ---------------------------------------------------- B-283 handoff: ctxvis and allowall

def test_context_visibility_flip_at_channel_scope_is_detected():
    before = _telegram(_cfg(CLEAN))
    after = _mutate(lambda t: t.__setitem__("contextVisibility", "all"))
    assert "ctxvis" in _changed_keys(before, after)


def test_context_visibility_flip_on_an_account_is_detected():
    """Account -> channel -> defaults -> "all" is the dist's documented precedence.

    The per-account override is the exact shape B-283 (c) proved produced a lying PASS in
    the checks layer; the monitor was blind to it at every scope.
    """
    before = _telegram(_cfg(CLEAN))
    after = _mutate(lambda t: t["accounts"]["primary"].__setitem__("contextVisibility", "all"))
    assert _changed_keys(before, after) == ["ctxvis"]


def test_feishu_allowall_hashes_as_open():
    """Feishu's `groupPolicy: "allowall"` is transformed to "open" by the dist itself."""
    allowall = _sig({"channels": {"feishu": {"groupPolicy": "allowall"}}})["feishu"]
    wide_open = _sig({"channels": {"feishu": {"groupPolicy": "open"}}})["feishu"]
    assert allowall["open"] == wide_open["open"]


def test_allowall_is_not_normalized_off_feishu():
    """GROUNDING GUARD. `allowall` is accepted ONLY by Feishu.

    Checked against the installed dist rather than inferred: NO channel lists `allowall` in
    a `groupPolicy` enum. Feishu accepts it because its `groupPolicy` is
    `anyOf: [enum["open", "allowlist", "disabled"], {}]` — the empty second branch admits
    any value — and `policy-hydoYQvK.js:56` is what maps it to `"open"`. Telegram's is a
    bare enum `["open", "disabled", "allowlist"]`, so a telegram config written that way is
    rejected by OpenClaw's own validation and cannot be a config a running instance loaded.
    Normalizing it channel-agnostically would pin a schema fact that is false; an earlier
    attempt shipped exactly that on telegram.
    """
    allowall = _sig({"channels": {"telegram": {"groupPolicy": "allowall"}}})["telegram"]
    wide_open = _sig({"channels": {"telegram": {"groupPolicy": "open"}}})["telegram"]
    assert allowall["open"] != wide_open["open"]


# ------------------------------------------------------------- the mass-false-fire guard

def test_upgrade_from_legacy_snapshot_is_silent():
    """THE FP GUARD. A pre-B-274 snapshot vs an unchanged config must produce NO alert.

    This is the failure mode the sub-key shape exists to prevent: every user's first run
    after upgrading, on a config they never touched. The legacy snapshot carries only the
    old one-hash value; `diff()` compares the one sub-key both sides have (`core`) and
    stays silent on the five it cannot compare.
    """
    curr = _snap(CLEAN)
    legacy = json.loads(json.dumps(curr))
    legacy["channels"] = {
        name: _channel_entry(entry)["core"] for name, entry in curr["channels"].items()
    }
    assert all(isinstance(v, str) for v in legacy["channels"].values())
    assert _channel_alerts(diff(legacy, curr)) == []


def test_legacy_snapshot_still_detects_a_core_dimension_change():
    """The gate costs one run of sensitivity for NEW keys only — `core` still compares."""
    curr = _snap(DRIFTED)
    legacy = json.loads(json.dumps(curr))
    legacy["channels"] = {"telegram": _sig(
        {"channels": {"telegram": {"dmPolicy": "open"}}}
    )["telegram"]["core"]}
    assert _channel_alerts(diff(legacy, curr))


# ------------------------------------------------ C-135: `core` is ACTUALLY frozen
#
# The sub-key design's whole FP argument rests on `core` reproducing the stored
# pre-upgrade value. A revision of this module documented `core` as a "FROZEN historical
# formula" while quietly dropping two of its five terms (`auth`, `allowedSenders`), which
# made an UNCHANGED config alert on the first post-upgrade run. Both directions are pinned
# below: the untouched config stays silent, and a genuine core change still fires.

# CHANNEL CHOICE IS DELIBERATE — an earlier revision parametrized these over `matrix` and
# `tlon`, which OpenClaw REJECTS, so the cases asserted on configs that cannot load.
# Checked against the installed dist: `GENERATED_BUNDLED_CHANNEL_CONFIG_METADATA`
# (ids-DDdMGkAj.js:24) registers 25 channels and 23 of them refuse unknown keys, so
# `auth`/`allowedSenders` are rejected on matrix, tlon, feishu, line, zalo, irc and
# telegram alike. Exactly two channels are permissive: `synology-chat` (`.passthrough()`,
# channel-Dxc6BJwP.js:269-272) and `qqbot`. Those are the ones used below.

PERMISSIVE_CHANNELS = ["synology-chat", "qqbot"]


@pytest.mark.parametrize("channel", PERMISSIVE_CHANNELS)
@pytest.mark.parametrize("node", [
    {"auth": {"mode": "token", "value": "k"}, "enabled": True},
    {"allowedSenders": ["owner"], "enabled": True},
    {"auth": {"mode": "token", "value": "k"}, "allowedSenders": ["owner"]},
])
def test_untouched_config_with_a_legacy_core_term_is_silent_on_upgrade(channel, node):
    """FP DIRECTION. Nobody edited the config; the upgrade alone must not alert.

    On a permissive channel this is a config a running instance genuinely loads, so the
    scenario is real end to end and not merely a file-parsing artefact.
    """
    config = {"channels": {channel: node}}
    alerts = _channel_alerts(
        diff(_legacy_snapshot(config["channels"]),
             {"config_hash": "unchanged", "channels": _sig(config)}))
    assert alerts == [], f"upgrade alone alerted on an untouched {channel} config"


@pytest.mark.parametrize("channel,node", [
    ("telegram", {"botToken": "env:TG", "dmPolicy": "allowlist"}),
    ("synology-chat", {"auth": {"mode": "token", "value": "k"}}),
    ("qqbot", {"allowedSenders": ["owner"]}),
])
def test_core_reproduces_the_head_formula_bit_for_bit(channel, node):
    """The frozen claim, asserted against an independent copy of HEAD's formula.

    All three nodes are schema-valid for the channel they are attached to. `telegram` is a
    STRICT channel and is here on purpose, so the frozen formula is pinned on a validated
    channel and not only on the permissive pair — its node uses `botToken` (telegram's real
    credential field; `token` is not a telegram property at all) and a `dmPolicy` from the
    schema's own enum `["pairing", "allowlist", "open", "disabled"]`. The previous
    `{"token": ..., "dmPolicy": "restricted"}` was invalid twice over.
    """
    assert _sig({"channels": {channel: node}})[channel]["core"] == _head_core(node)


def test_core_is_reproduced_even_for_a_config_openclaw_would_reject():
    """`core` hashes BYTES ON DISK, not a loaded config — the real correctness condition.

    Separated from the cases above precisely because it is a different claim. A config file
    can hold a key OpenClaw refuses (a typo, a stale key from an older version, a
    half-finished hand edit); `matrix` with `allowedSenders` is exactly that — the dist's
    matrix schema sets `additionalProperties: false`, so it never loads. clawseccheck is a
    static file scanner, so it must still reproduce HEAD's stored hash for those bytes and
    must not alert on them. This is why the frozen terms stay regardless of what the schema
    says, and why no schema fact is load-bearing for `core`.
    """
    node = {"allowedSenders": ["owner"], "enabled": True}
    config = {"channels": {"matrix": node}}
    assert _sig(config)["matrix"]["core"] == _head_core(node)
    assert _channel_alerts(
        diff(_legacy_snapshot(config["channels"]),
             {"config_hash": "unchanged", "channels": _sig(config)})) == []


@pytest.mark.parametrize("before,after,label", [
    ({"dmPolicy": "restricted"}, {"dmPolicy": "open"}, "dmPolicy opened"),
    ({"groupPolicy": "restricted"}, {"groupPolicy": "open"}, "groupPolicy opened"),
    # Removing the only auth-ish key flips `has_auth` True -> False. Keeping the legacy
    # terms is what preserves this signal; dropping them made it silent.
    ({"auth": {"mode": "token", "value": "k"}}, {}, "auth removed"),
    ({"allowedSenders": ["owner"]}, {}, "allowedSenders removed"),
])
def test_a_genuine_core_change_still_alerts_across_the_boundary(before, after, label):
    """TP DIRECTION. Freezing `core` must not be a way of switching detection off."""
    alerts = _channel_alerts(
        diff(_legacy_snapshot({"synology-chat": before}),
             {"config_hash": "moved",
              "channels": _sig({"channels": {"synology-chat": after}})}))
    assert alerts, f"{label}: a real core change went unreported"


# ------------------------------------- C-135: the scope walk reaches the schema's depth
#
# The bound was 2 and was justified with "the schema nests at most channel -> groups ->
# topics (depth 2)". The dist says otherwise: `accounts` is the FIRST level, so
# telegram `accounts` -> `groups` -> `topics` (bundled-channel-config-schema-CkfMA6sO.js
# :323 -> :246 -> :179) is depth 3, and every per-account scope was truncated away.

def _depth3(require_mention=True, allow_from=("owner",), token=None):
    """channels.telegram.accounts.<a>.groups.<g>.topics.<t> — schema-valid at depth 3."""
    topic = {"requireMention": require_mention, "allowFrom": list(allow_from)}
    if token is not None:
        topic["botToken"] = token
    return {"channels": {"telegram": {"accounts": {"primary": {
        "groups": {"*": {"topics": {"42": topic}}}}}}}}


@pytest.mark.parametrize("mutation,expected", [
    (dict(require_mention=False), "gating"),
    (dict(allow_from=("owner", "attacker-666")), "allow"),
    (dict(allow_from=("*",)), "allow"),
    (dict(token="env:SOME_OTHER_REF"), "secrets"),
])
def test_depth_three_per_account_scope_change_is_detected(mutation, expected):
    """TP DIRECTION. `TelegramTopicSchema` carries requireMention/allowFrom — read them."""
    before = _sig(_depth3())["telegram"]
    after = _sig(_depth3(**mutation))["telegram"]
    assert expected in _changed_keys(before, after)


def test_depth_three_unchanged_config_is_still_silent():
    """FP DIRECTION. Reaching deeper must not manufacture drift where there is none."""
    assert _sig(_depth3())["telegram"] == _sig(_depth3())["telegram"]


def test_no_fixture_config_reaches_the_depth_three_level():
    """ANTI-VACUOUS-EVIDENCE PIN, and the reason the docstring says what it says.

    Raising the scope bound 2 -> 3 is INERT on every config in this repo: nothing gets
    deeper than 2, so the fixture sweeps cannot be cited as evidence that depth-3 behaviour
    is correct — only the hand-built configs above exercise it. If someone later adds a
    fixture that does nest to 3, this fails, which is the signal to re-word
    `_channel_scope_nodes`'s "NOT EXERCISED BY ANY CONFIG IN THIS REPO" note rather than to
    delete this test.
    """
    def max_scope_depth(node, depth=0):
        deepest = depth
        for key in _CHANNEL_SCOPE_KEYS:
            container = node.get(key)
            if isinstance(container, dict):
                for sub in container.values():
                    if isinstance(sub, dict):
                        deepest = max(deepest, max_scope_depth(sub, depth + 1))
        return deepest

    inspected, deepest_seen = 0, 0
    for path in sorted(FIXTURES.glob("**/*.json")):
        try:
            config = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue
        channels = config.get("channels") if isinstance(config, dict) else None
        if not isinstance(channels, dict):
            continue
        for node in channels.values():
            if isinstance(node, dict):
                inspected += 1
                deepest_seen = max(deepest_seen, max_scope_depth(node))

    # Guard the guard: a sweep that inspected nothing would "pass" while proving nothing.
    assert inspected > 100, f"sweep was vacuous — only {inspected} channel nodes inspected"
    assert deepest_seen < 3, (
        f"a fixture now nests to depth {deepest_seen}; the 'no fixture reaches depth 3' "
        "note in monitor._channel_scope_nodes is stale and must be re-worded"
    )


def test_gating_unmentioned_flag_cannot_change_a_signature():
    """Pins the REDUNDANCY the `allow_unmentioned` comment claims, so the claim stays true.

    The flag is a pure function of the `requireMention` values already inside the same
    hash, which is why it is documented as informational and kept rather than removed.

    Pinned by PARTITION, not by a determinism check: over an enumerated config space, two
    configs must produce the same `gating` hash under the shipped formula exactly when they
    produce the same one under a formula with the flag deleted. Equal partitions == the
    flag distinguishes nothing == it cannot change an outcome. If a future edit gives it
    independent signal the partitions diverge and this fails, which is the point — re-word
    the comment then; do not delete the test.
    """
    from clawseccheck.monitor import _channel_scope_nodes

    def without_flag(channel_node):
        """The `gating` formula with `allow_unmentioned` removed — the control."""
        mentions = [
            f"{path}requireMention={node['requireMention']}"
            for path, node in _channel_scope_nodes(channel_node)
            if isinstance(node.get("requireMention"), bool)
        ]
        return _h(";".join(sorted(mentions)))

    # FOUR states per slot, not three. `BARE` — a scope entry that EXISTS but carries no
    # `requireMention` — is what makes this enumeration able to fail: it varies the walked
    # structure while leaving the `mentions` list untouched. Without it the space is too
    # narrow to distinguish the flag from any structural term, and the test passes
    # vacuously (verified by mutation: a `len(scoped)` term slipped through a three-state
    # space and is caught by this one).
    BARE = "bare"
    states = (None, True, False, BARE)

    def slot(value):
        return {} if value is BARE else {"requireMention": value}

    shipped, control = {}, {}
    enumerated = 0
    for top in states:
        for star in states:
            for named in states:
                for topic in states:
                    node = dict(slot(top)) if top is not None else {}
                    groups = {}
                    if star is not None:
                        groups["*"] = slot(star)
                    if named is not None:
                        inner = slot(named)
                        if topic is not None:
                            inner["topics"] = {"42": slot(topic)}
                        groups["-100123"] = inner
                    if groups:
                        node["groups"] = groups
                    enumerated += 1
                    key = json.dumps(node, sort_keys=True)
                    shipped[key] = _sig({"channels": {"telegram": node}})["telegram"]["gating"]
                    control[key] = without_flag(node)

    assert enumerated == 256, f"enumeration changed shape — {enumerated} configs"
    # The space must contain structurally different configs with identical `mentions`,
    # or a structural term could never be caught and equal partitions prove nothing.
    by_mentions = {}
    for cfg_key, digest in control.items():
        by_mentions.setdefault(digest, set()).add(cfg_key)
    assert any(len(v) > 1 for v in by_mentions.values()), (
        "no two enumerated configs share a `mentions` list — the space cannot detect "
        "independent signal, so this test would pass vacuously"
    )

    def partition(table):
        groups = {}
        for cfg_key, digest in table.items():
            groups.setdefault(digest, set()).add(cfg_key)
        return sorted(sorted(members) for members in groups.values())

    # Non-vacuity: the space must actually contain configs that differ, or equal
    # partitions would be a tautology rather than evidence.
    assert len(set(shipped.values())) > 1
    assert partition(shipped) == partition(control), (
        "`allow_unmentioned` now distinguishes configs the requireMention values alone do "
        "not — it is no longer redundant, so monitor.py's comment saying it is must change"
    )


def test_the_walk_is_still_bounded_below_the_schema_depth():
    """The bound is RAISED, not removed — depth 4 is documented as out of reach.

    An honest pin of the residual limit rather than a claim of total coverage: the bundled
    channel schemas top out at depth 3, but two of the 25 registered channels are
    permissive (`synology-chat`, `qqbot`) and a plugin channel can register its own schema,
    so something nesting deeper would still be truncated here.
    """
    def depth4(require_mention):
        return {"channels": {"telegram": {"accounts": {"primary": {"groups": {
            "*": {"topics": {"42": {"direct": {"d": {
                "requireMention": require_mention}}}}}}}}}}}

    assert _changed_keys(_sig(depth4(True))["telegram"],
                         _sig(depth4(False))["telegram"]) == []


@pytest.mark.parametrize("corrupt", [42, None, [1, 2], {"core": 5}, {}])
def test_a_corrupted_channel_entry_degrades_to_no_comparison(corrupt):
    """UNKNOWN path: an unreadable entry yields no shared keys, hence no alert, not a crash.

    A bare *string* is deliberately excluded — that is not corruption, it is the legacy
    one-hash shape, and `test_legacy_snapshot_still_detects_a_core_dimension_change`
    covers it. Everything else degrades to `{}`: no shared keys, so no comparison, which
    is the conservative direction (`_both_dims` reasons the same way — comparing a real
    side against a coerced `{}` would report every live entry as newly appeared).
    """
    entry = _channel_entry(corrupt)
    assert isinstance(entry, dict)
    assert not any(isinstance(v, str) for v in entry.values())
    curr = _snap(CLEAN)
    legacy = json.loads(json.dumps(curr))
    legacy["channels"] = {"telegram": corrupt}
    assert _channel_alerts(diff(legacy, curr)) == []


def test_shorthand_channel_is_recorded_under_core():
    """`"telegram": true` has no policy object; it stays tracked, and stays comparable."""
    sig = _sig({"channels": {"telegram": True}})["telegram"]
    assert set(sig) == {"core"}
    assert sig != _sig({"channels": {"telegram": False}})["telegram"]


def test_absent_and_non_dict_channels_key_yield_no_channels():
    assert _sig({}) == {}
    assert _sig({"channels": "nope"}) == {}
    assert _sig({"channels": {}}) == {}


# ---------------------------------------------------------------- secrets stay at rest

def test_no_credential_value_reaches_state_or_events(tmp_path):
    """B-274 requires a DIGEST, never the value — asserted on the files actually written."""
    secret = "".join(["8102345", ":", "AA", "Fq-not-a-real-bot-credential"])
    config = _cfg(CLEAN)
    config["channels"]["telegram"]["botToken"] = secret
    sig = _sig(config)

    state = tmp_path / "state.json"
    events = tmp_path / "events.jsonl"
    save_state(state, {"channels": sig})
    record_events([("MEDIUM", "Channel 'telegram' openness/auth changed — review it.")],
                  path=events)

    assert secret not in state.read_text(encoding="utf-8")
    assert secret not in events.read_text(encoding="utf-8")
    assert secret not in json.dumps(sig)
    # ...and the digest still moved, so redaction did not cost detection.
    assert sig["telegram"]["secrets"] != _telegram(_cfg(CLEAN))["secrets"]


def test_same_value_under_two_fields_does_not_collide():
    """The field name is mixed into the digest."""
    a = _sig({"channels": {"x": {"token": "same-ref"}}})["x"]["secrets"]
    b = _sig({"channels": {"x": {"botToken": "same-ref"}}})["x"]["secrets"]
    assert a != b


# ------------------------------------------------------------------------ bounded walk

def test_scope_walk_is_bounded_and_does_not_recurse_forever():
    """A deeply self-similar config must not turn signature computation into a runaway."""
    node = {"requireMention": True}
    for _ in range(50):
        node = {"groups": {"g": node}}
    node["allowFrom"] = ["owner"]
    sig = _sig({"channels": {"telegram": node}})
    assert set(sig["telegram"]) == {"core", "open", "ctxvis", "allow", "secrets", "gating"}


def test_non_dict_scope_containers_are_skipped():
    for junk in ("oops", 7, [1, 2], None):
        config = _cfg(CLEAN)
        config["channels"]["telegram"]["groups"] = junk
        assert "gating" in _sig(config)["telegram"]


def test_accounts_of_the_wrong_type_do_not_crash_the_core_term():
    config = _cfg(CLEAN)
    config["channels"]["telegram"]["accounts"] = "not-a-dict"
    assert "core" in _sig(config)["telegram"]


def test_allowlist_scalar_and_numeric_members_are_read():
    """The schema is `array(union([string(), number()]))` — ids are commonly numeric."""
    before = _sig({"channels": {"t": {"allowFrom": [123]}}})["t"]["allow"]
    after = _sig({"channels": {"t": {"allowFrom": [456]}}})["t"]["allow"]
    assert before != after


def test_deep_copy_of_clean_config_is_signature_identical():
    assert _telegram(copy.deepcopy(_cfg(CLEAN))) == _telegram(_cfg(CLEAN))
