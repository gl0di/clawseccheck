"""The `channels` dimension — the ways your agent can be contacted.

An inbound channel is an untrusted-input surface, so the signature records not just which
channels exist but the reachability of each: who is allowed in, whether a group policy is
open, and whether a secret is present. The arm compares those, and a partially-resolved
channel is reported as partial rather than compared and passed.
"""

from __future__ import annotations
from ._shared import _h  # noqa: F401


# B-274: container keys under a channel node that hold per-scope entries. Every name is
# grounded in the installed dist's own channel schema
# (bundled-channel-config-schema-CkfMA6sO.js): `accounts` :323/:689/:878/:1032/:1272,
# `groups` :246/:997/:1117/:1261/:1501, `topics` :179/:195, `direct` :256, `dms`
# :255/:545/:824/:1000/:1121/:1236/:1400, `guilds` :579, `channels` :452/:860/:1329,
# `teams` :1402. Walked to a bounded depth so a per-group override
# (`groups["*"].requireMention`) is visible without inventing a path.
_CHANNEL_SCOPE_KEYS = ("accounts", "groups", "topics", "direct", "dms",
                       "guilds", "channels", "teams")


# B-274: credential-bearing channel fields, all `register(sensitive)` in the dist schema
# (same file): botToken :243/:811, token :530/:617, appToken :812, userToken :813,
# authToken :781, signingSecret :793/:873, webhookSecret :272, password :1090/:1107,
# appPassword :1365. `tokenFile` (:244) is a PATH, not a secret, but a swap of it
# redirects the credential just as a botToken swap does, so it is tracked the same way.
# Only a DIGEST of the value ever enters the snapshot — never the value itself.
_CHANNEL_SECRET_KEYS = ("token", "botToken", "appToken", "userToken", "authToken",
                        "signingSecret", "webhookSecret", "password", "appPassword",
                        "tokenFile")


# B-274: sender-allowlist fields. `allowFrom` (:162/:177/:193/:247/:405/…) and
# `groupAllowFrom` (:249) are both real, array-typed schema fields in the installed dist's
# channel schema (bundled-channel-config-schema-CkfMA6sO.js). `allowedSenders` is NOT — it
# has ZERO occurrences anywhere in the dist — and a bare `auth` is not a channel-config
# field either: it is a property of NONE of the 25 channel schemas (checked per-schema,
# see below). Both are therefore excluded from these GROUNDED keys, on the same reasoning
# B-283 used to scope `allowall` to Feishu.
#
# STATE THE `auth` HALF PER-SCHEMA, NEVER AS A COUNT OF DIST-WIDE GREP HITS. An earlier
# revision claimed "the only dist hits are an HTTP-route registration option,
# channel-Dxc6BJwP.js:1029, and description prose"; every part of that was false. A bare
# `auth` key is common in the dist — hundreds of occurrences — and `channel-*.js` alone
# holds four, none of them description prose: channel-BppRB2We.js:551 and
# channel-PR3XHV0V.js:2169 are entries in channel ADAPTER tables (alongside `resolver`/
# `message`/`status`), channel-B1AbNBrp.js:100 is a nostr received-message counter, and
# channel-Dxc6BJwP.js:1029 is the route-registration option. `auth` is moreover a REAL
# OpenClaw config key, just not a channel one: plugin-sdk/config-schema.d.ts:214 declares
# it (`auth.profiles`/`order`/`cooldowns`) as a top-level property of `OpenClawSchema`
# (:7). None of that bears on the question here, which is only ever "is it a property of a
# CHANNEL schema" — and there the answer is measured, not inferred: the channels type
# (types.channels-DFK41guV.d.ts) and bundled-channel-config-schema-CkfMA6sO.js each carry
# ZERO bare `auth` properties. The `allowedSenders` half above is exact as written; the
# defect was the unchecked quantifier on the `auth` half, not the method.
#
# WHAT OPENCLAW DOES WITH SUCH A KEY (measured against the installed dist, because this
# sentence has now been wrong twice and each rewrite invented a new falsehood):
#
#   * `GENERATED_BUNDLED_CHANNEL_CONFIG_METADATA` (ids-DDdMGkAj.js:24) registers **25**
#     channels, each with a JSON-Schema, and seeds the schema map at io-By0s-a_s.js:4088.
#   * Every configured channel IS validated against its registered schema
#     (io-By0s-a_s.js:4297-4304). Schema errors become config issues (:4305-4314); an
#     unrecognised channel id is an issue too (:4285-4295); only a clean result is written
#     back (:4317). Any issue makes config validation return `ok: false` (:4351-4356).
#   * **23 of the 25 reject unknown keys.** 22 carry `additionalProperties: false`
#     outright; `twitch` is strict too, via an `anyOf` of two branches that each set it —
#     so a scan of top-level `additionalProperties` alone mislabels it as permissive.
#     Exactly **two** are permissive: `synology-chat` (`.passthrough()`,
#     channel-Dxc6BJwP.js:269-272, registered :1169) and `qqbot` — both surface as
#     `additionalProperties: {}`.
#   * `auth` and `allowedSenders` are properties of NO channel schema. Checked directly:
#     feishu, line, zalo, matrix, irc and tlon all REJECT them; only synology-chat and
#     qqbot accept.
#
# So the ORIGINAL "OpenClaw would reject this" was broadly right, and the correction that
# replaced it — "only EIGHT channels ship a bundled schema, the other seven pass through
# unvalidated" — was wrong. Its root cause is worth recording so a fourth revision does not
# repeat it: `bundled-channel-config-schema-CkfMA6sO.js:1689` really does export exactly
# eight schemas (MSTeams, Telegram, IMessage, GoogleChat, Signal, Discord, Slack,
# WhatsApp), and that export list was mistaken for the whole registry. It is one bundle
# file among several; the other 17 channels' schemas live elsewhere (synology-chat's in
# channel-Dxc6BJwP.js) and are collected into the metadata above. The top-level
# `ChannelsSchema` IS `.passthrough()` (zod-schema.channels-config-ORTHga0n.js:68-76), but
# that only means the zod layer defers — the per-channel pass at :4297 is what judges keys.
#
# NONE OF THIS IS LOAD-BEARING. The `core` term below keeps `auth`/`allowedSenders` for a
# reason that does not reference the schema at all: clawseccheck hashes the config file AS
# WRITTEN, and `core`'s correctness condition is equality with the value HEAD stored, not
# groundedness. A config file may hold keys OpenClaw would refuse — a typo, a stale key
# from an older version, a half-finished hand edit — and this is a static file scanner, not
# the OpenClaw loader, so it must reproduce the old hash on whatever bytes are on disk.
# Dropping the terms from a formula advertised as frozen is what made an untouched config
# alert on the upgrade run; that is true whether or not the config would ever load.
_CHANNEL_ALLOWLIST_KEYS = ("allowFrom", "groupAllowFrom")


def _channel_scope_nodes(c: dict, depth: int = 3) -> "list[tuple[str, dict]]":
    """(path, node) for the channel node and its per-scope children, bounded depth.

    Bounded rather than an unbounded rglob-style walk: a bound is what keeps a
    hand-written or hostile config from turning a signature computation into unbounded
    work. The bound is 3 because 3 is what the dist's own schema actually needs — it was 2,
    which silently truncated every per-account scope (`accounts` is the FIRST level, not a
    free one). In bundled-channel-config-schema-CkfMA6sO.js the deepest chains are:

      * telegram  `accounts` :323 -> `groups` :246 -> `topics` :179
      * telegram  `accounts` :323 -> `direct` :256 -> `topics` :195
      * discord   `accounts` :689 -> `guilds` :579 -> `channels` :452

    all depth 3, and the leaves are exactly the nodes this signature cares about:
    `TelegramTopicSchema` :155 carries `requireMention` :156, `groupPolicy` :159 and
    `allowFrom` :162. At depth 2 a scope change inside a per-account group/topic was
    invisible to the drift signature. No bundled chain goes deeper: walking every
    `record(string(), …)` container edge in that file from each exported *ConfigSchema*
    gives a maximum of 3, and the leaf schemas hold no further containers. (Not every chain
    is `accounts`-rooted — MSTeams has no `accounts` and runs `teams` :1402 -> `channels`
    :1329, depth 2.)

    HONEST LIMIT: that enumeration bounds the channels with a BUNDLED schema. Two of the 25
    registered channels are permissive (`synology-chat`, `qqbot` — see
    `_CHANNEL_ALLOWLIST_KEYS`), and a plugin channel can register a schema of its own, so
    something could in principle nest deeper and would still be truncated here — which is
    the other half of why the bound stays rather than becoming an unbounded walk.

    NOT EXERCISED BY ANY CONFIG IN THIS REPO. Raising the bound 2 -> 3 changes **zero** of
    the 371 fixture configs and zero of the 8 real configs: measured over every channel node
    in the corpus, the depth histogram is {0: 154, 1: 23, 2: 2} and nothing reaches 3 (the
    real config is telegram at depth 1). So the fixture sweeps and the real-config runs
    establish that this change is INERT on real configs — they do NOT establish that it is
    correct at depth 3, because they never reach it. Only the hand-built configs in
    `tests/test_b274_channel_signature.py` exercise the third level. Do not cite a corpus
    sweep as evidence for depth-3 behaviour.
    """
    out = [("", c)]
    frontier = [("", c)]
    for _ in range(depth):
        nxt = []
        for prefix, node in frontier:
            for key in _CHANNEL_SCOPE_KEYS:
                container = node.get(key)
                if not isinstance(container, dict):
                    continue
                for sub_id, sub in sorted(container.items()):
                    if isinstance(sub, dict):
                        path = f"{prefix}{key}[{sub_id}]."
                        out.append((path, sub))
                        nxt.append((path, sub))
        frontier = nxt
    return out


def _channel_sig(ctx) -> dict:
    """name -> {sub-signature: hash} for a channel's openness/auth surface.

    SHAPE. This used to be ``name -> one hash string``. It is now ``name -> dict of named
    sub-signatures``, for one reason: a single opaque hash cannot be widened without
    re-hashing EVERY channel, which fires "Channel 'X' openness/auth changed" on every
    user's first post-upgrade run against a config nobody touched. That is the B-279
    precedent (a naive widen mass-fired rug-pull RP2 HIGH on every unchanged
    ``npx -y <pkg>``). With named sub-keys, ``diff()`` compares only the keys present in
    BOTH snapshots, so a key added by an upgrade stays silent until it has a same-shaped
    predecessor to be compared against. ``_channel_entry`` coerces a legacy string
    snapshot to ``{"core": <string>}`` so the historical term still compares across the
    boundary.

    ``core`` is therefore FROZEN at the historical formula and must not be re-tuned: it is
    the only term with a pre-upgrade counterpart. New signal goes in a new key. That
    includes the two ungrounded reads it carries, bare ``auth`` and ``allowedSenders``:
    they are kept HERE and excluded from every new key. An earlier revision dropped them
    because neither is a real channel-config field; that reasoning is irrelevant, not
    merely wrong. ``core`` must reproduce the hash HEAD stored for the bytes on disk, and
    this is a static file scanner — whether OpenClaw would load such a config decides
    nothing (``_CHANNEL_ALLOWLIST_KEYS`` records what the dist actually does, and why that
    question is not load-bearing). Dropping the terms turned ``core`` into a silent
    behaviour change that alerted on an untouched config.

    Freezing costs nothing in sensitivity relative to HEAD — it restores HEAD exactly. It
    declines to make ``core`` *more* sensitive, which is what "frozen" means; the grounded
    coverage lives in ``allow``/``secrets``/``gating`` below, and those cost the documented
    one run of silence on the upgrade itself (see ``diff()``).

    The remaining keys close B-274 and the monitor half of B-283:

    ``open``    B-283: openness with Feishu's ``groupPolicy: "allowall"`` alias normalized
                to the ``"open"`` it actually resolves to, via the shared
                ``_norm_group_policy``. Scoped to Feishu because Feishu is the only channel
                schema in the dist that accepts the literal at all — do not read this as
                "allowall is a general alias", it is not, and pinning that false fact on
                telegram was a mistake caught in B-283's own C-135 pass.
    ``ctxvis``  B-283: effective ``contextVisibility`` per the dist's documented
                account -> channel -> defaults -> "all" precedence
                (context-visibility-BVlvSMUZ.js:8-13). Previously absent at every scope,
                so a flip to ``"all"`` — the setting that exposes untrusted message content
                to the agent — was invisible to ``--monitor`` as well as to B26.
    ``allow``   B-274: allowlist MEMBERSHIP, not presence. The old ``has_auth`` was a
                ``bool(...)`` over field presence, so ``allowFrom: ["owner"]`` ->
                ``["owner", "attacker"]``, and even ``-> ["*"]``, hashed identically.
                Wildcard-ness is recorded explicitly because ``[]`` and ``["*"]`` were
                treated as OPPOSITES (``[]`` alerted, ``["*"]`` was silent) despite
                ``allowWhenEmpty`` making them semantically the same.
    ``secrets`` B-274: a digest per credential field. A swapped ``botToken`` — the whole
                channel taken over — was silent, because the package read ``token`` and
                Telegram's field is ``botToken``.
    ``gating``  B-274: ``requireMention`` at the channel node and at every per-scope entry.
                Turning it off in ``groups["*"]`` lets any group message address the agent
                unprompted, and was unread. The term also carries an ``unmentioned=`` flag
                that is NEITHER the dist's predicate NOR load-bearing; see the note at the
                term itself before trusting or removing it.

    NARROWS, does not close: this is a drift signature, not a policy verdict. It reports
    that an allowlist/credential/mention-gate MOVED; it does not judge whether the new
    value is safe. A config that was already wide open on day one still produces no alert,
    because nothing changed — that is the checks layer's job, not the monitor's.
    """
    from ..checks import _norm_group_policy  # noqa: PLC0415

    out, chans = {}, ctx.config.get("channels")
    if not isinstance(chans, dict):
        return out
    defaults_node = chans.get("defaults")
    global_ctxvis = (defaults_node.get("contextVisibility")
                     if isinstance(defaults_node, dict) else None)

    for name, c in chans.items():
        if not isinstance(c, dict):
            # C-135/FIX4: shorthand form (e.g. "telegram": true) enables/disables the
            # channel without a per-channel policy object to inspect. Record it as
            # PRESENT with an unknown-but-tracked shape rather than skipping it
            # outright — the old `continue` here made the channel invisible to drift
            # detection, so switching between shorthand and an explicit {} object (or
            # vice versa) made a still-live channel read as "no longer configured" in
            # diff()'s removal branch. Keying on repr(c) still detects a genuine
            # true<->false flip while never fabricating a deletion. Stored under `core`
            # so it still compares against a legacy string snapshot.
            out[name] = {"core": _h(f"shorthand={c!r}")}
            continue

        accounts = c.get("accounts")
        nodes = [c] + (list(accounts.values()) if isinstance(accounts, dict) else [])
        nodes = [n for n in nodes if isinstance(n, dict)]

        # --- core: FROZEN historical formula, the cross-upgrade comparability anchor ---
        # Every term below is here because HEAD hashed it, and for no other reason. `auth`
        # and `allowedSenders` are NOT grounded channel-config fields (see
        # `_CHANNEL_ALLOWLIST_KEYS`); they stay ONLY so this hash reproduces the stored
        # pre-upgrade value bit-for-bit. Removing them made an untouched config carrying
        # such a key alert on the first post-upgrade run. Do not "clean up" this list: its
        # correctness condition is equality with the old value, not groundedness — and not
        # whether OpenClaw would load the file either, since this reads bytes on disk, not
        # a loaded config. New signal goes in a new sub-key, where the grounded field set
        # applies.
        dm = any(n.get("dmPolicy") == "open" for n in nodes)
        grp = any(n.get("groupPolicy") == "open" for n in nodes)
        has_auth = bool(c.get("token") or c.get("auth") or c.get("allowFrom")
                        or c.get("allowlist") or c.get("allowedSenders"))
        entry = {"core": _h(f"dm={dm};grp={grp};auth={has_auth}")}

        scoped = _channel_scope_nodes(c)

        # --- open (B-283): same openness question, with the Feishu alias resolved ---
        dm_n = any(n.get("dmPolicy") == "open" for n in nodes)
        grp_n = any(_norm_group_policy(name, n.get("groupPolicy")) == "open"
                    for n in nodes)
        entry["open"] = _h(f"dm={dm_n};grp={grp_n}")

        # --- ctxvis (B-283): account -> channel -> defaults -> "all" ---
        channel_ctxvis = c.get("contextVisibility")
        vis = sorted(
            str(n.get("contextVisibility") or channel_ctxvis or global_ctxvis or "all")
            for n in nodes
        )
        entry["ctxvis"] = _h(";".join(vis))

        # --- allow (B-274): membership, with wildcard-ness explicit ---
        members, wildcard = [], False
        for path, node in scoped:
            for key in _CHANNEL_ALLOWLIST_KEYS:
                val = node.get(key)
                if isinstance(val, (list, tuple)):
                    vals = [str(v) for v in val]
                elif isinstance(val, (str, int)):
                    vals = [str(val)]
                else:
                    continue
                if "*" in vals:
                    wildcard = True
                members.extend(f"{path}{key}={v}" for v in vals)
        entry["allow"] = _h(f"wildcard={wildcard};" + ";".join(sorted(members)))

        # --- secrets (B-274): digest per field, never the value ---
        secrets = []
        for path, node in scoped:
            for key in _CHANNEL_SECRET_KEYS:
                val = node.get(key)
                if isinstance(val, (str, int)) and str(val).strip():
                    # Field name mixed into the digest so the same value under two
                    # different fields does not collide, and so the digest is not a bare
                    # hash of the credential alone.
                    secrets.append(f"{path}{key}={_h(f'{key}:{val}')}")
        entry["secrets"] = _h(";".join(sorted(secrets)))

        # --- gating (B-274): requireMention at every scope ---
        mentions, allow_unmentioned = [], False
        for path, node in scoped:
            val = node.get("requireMention")
            if isinstance(val, bool):
                mentions.append(f"{path}requireMention={val}")
                if val is False and path:
                    # REDUNDANT AND DELIBERATELY KEPT. Two facts, both measured, so nobody
                    # re-derives them:
                    #
                    # (1) It cannot change an outcome — but it DOES change the hash, and
                    #     the invariant is the VERDICT, not the digest. `allow_unmentioned`
                    #     is a pure function of `mentions`, which is already in the same
                    #     hash: it is true exactly when some non-empty path recorded False.
                    #     Enumerated over 243 configs -> 189 distinct `mentions` tuples,
                    #     zero where the same tuple yielded a different flag. Because the
                    #     flag is DETERMINED by `mentions`, two configs agree on the
                    #     prefixed hash exactly when they agree on the unprefixed one, so
                    #     `diff()` — which only ever tests two hashes for equality —
                    #     reaches the same verdict either way. It does NOT follow that the
                    #     digest is unchanged: dropping the `unmentioned=` prefix rehashes
                    #     every channel, e.g. telegram with
                    #     `groups["*"].requireMention=false` moves ab659656dd071add ->
                    #     33583c64a6298709. Measured over 243 structurally varying configs:
                    #     the digest differs on all 243, while all 29,403 config pairs agree
                    #     on equal-vs-changed (63 equivalence classes under both formulas,
                    #     zero mismatches).
                    # (2) It is NOT the dist's predicate, though an earlier comment here
                    #     said it was. The dist's `allowUnmentionedGroups`
                    #     (channel-DP5CkqKN.js:1131) is telegram-only and one level deep —
                    #     `channels.telegram[.accounts[X]].groups`, `*` or a named group.
                    #     This flag fires for ANY scope (topics, dms, direct) on ANY
                    #     channel, i.e. a strict superset.
                    #
                    # Kept because removing it is a behaviour change to a signature that
                    # has been differentially verified byte-for-byte, and (1) says it would
                    # buy exactly nothing. If you widen it, note it is not a dist predicate
                    # and do not re-label it as one.
                    allow_unmentioned = True
        entry["gating"] = _h(
            f"unmentioned={allow_unmentioned};" + ";".join(sorted(mentions))
        )

        out[name] = entry
    return out


def _channel_entry(value) -> dict:
    """A channels-dimension entry as ``{sub-key: hash}``, whatever shape it was stored in.

    Pre-B-274 snapshots stored ONE hash string per channel; that value was the historical
    ``dm=/grp=/auth=`` formula, which ``_channel_sig`` still emits verbatim under ``core``,
    so a legacy string is faithfully readable as ``{"core": <string>}``. Anything else
    (a corrupted or hand-edited dimension) degrades to ``{}`` — no shared keys, hence no
    comparison and no alert — the same self-healing direction as ``_dim``/``_both_dims``.
    """
    if isinstance(value, str):
        return {"core": value}
    if isinstance(value, dict):
        return {k: v for k, v in value.items() if isinstance(k, str) and isinstance(v, str)}
    return {}


def _diff_channels(pair, partial, alerts, compare_config) -> None:
    """C-433: the `channels` dimension's diff arm.

    Second per-dimension extraction. Four parameters, derived rather than guessed: the arm's
    free-variable set inside `diff_with_notes` was `_chan_pair`, `_chan_partial`, `alerts`
    and `compare_config`, plus the module-level `_channel_entry`.
    """
    # BOTH clauses. The original condition was `if compare_config and _pair is not None:`
    # and the extraction script rebuilt only the None half, which dropped the blind-run
    # guard: on a run recovering from an unknown baseline `compare_config` is False, so
    # this arm ran anyway and fabricated a HIGH "NEW channel appeared" about a channel the
    # baseline had simply never recorded. That is the exact class B-269 exists to prevent,
    # and the full suite caught it where a 19-case equivalence harness did not.
    if not compare_config or pair is None:
        return
    pch, cch = pair
    for name in sorted(cch.keys() - pch.keys()):
        alerts.append(("HIGH", f"NEW channel '{name}' appeared since last check — "
                       "confirm its auth / allowlist before it can reach the agent."))
    for name in sorted(pch.keys() & cch.keys()):
        # B-274: compare only the sub-signatures present on BOTH sides. A key this
        # release added has no predecessor in an older snapshot, and comparing it
        # against nothing would report drift on a config nobody touched — every
        # user, every channel, on the first post-upgrade run. Gating on
        # `shared` costs exactly one run of sensitivity for a newly added key and
        # buys silence on the upgrade itself. `_channel_entry` normalizes the
        # legacy one-string shape, so `core` still compares across the boundary.
        pe, ce = _channel_entry(pch[name]), _channel_entry(cch[name])
        shared = pe.keys() & ce.keys()
        if pe.keys() ^ ce.keys():
            partial.add(name)
        if any(pe[k] != ce[k] for k in shared):
            alerts.append(("MEDIUM", f"Channel '{name}' openness/auth changed — review it."))
    # B-275: the channels dimension had no removal branch either. INFO, not HIGH:
    # de-configuring a channel SHRINKS the agent's reachable surface, and users retire
    # channels routinely — worth recording in the journal, not worth alarming over.
    # (Unreachable on a blind run: this whole block is behind compare_config, so a
    # collapsed config can never present itself as a channel deletion.)
    for name in sorted(pch.keys() - cch.keys()):
        alerts.append(("INFO", f"Channel '{name}' is no longer configured — the agent "
                       "can no longer be reached over it."))
