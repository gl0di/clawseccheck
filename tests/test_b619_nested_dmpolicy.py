"""B-619 — a DM ingress closure written through a NESTED path (or ``dm.enabled: false``)
was read identically to a channel that declared nothing at all: A1 told an owner who
explicitly closed DM ingress that they set no policy, CRITICAL-capping the grade, and
recommended a flat `dmPolicy` key several of the affected channels' own schema rejects.

Grounded against the installed dist. Exactly 4 channels define a nested `dm` config
OBJECT anywhere in the dist (grep-verified exhaustively, not assumed — see
``_DM_POLICY_NESTED_ONLY_CHANNELS``'s comment in ``_shared.py`` for the file:line
citations): discord, slack, googlechat, matrix.

**B-720 corrected the next sentence, and this file asserted the wrong version of it while
staying green — a test pins a false claim exactly as well as a true one.** It used to say
googlechat and matrix are NESTED-ONLY because "their schema has no flat `dmPolicy` field
at all". Measured against the vendor's generated config schema across all 25 channels,
**matrix is the only channel declaring `dm.policy`, and the only one declaring no flat
`dmPolicy`.** googlechat is the opposite: `GoogleChatDmSchema = object({enabled}).strict()`
carries no `policy`, while the vendor's own validator enforces the FLAT key
(`superRefine` -> `requireOpenAllowFrom({policy: value.dmPolicy})`, whose message names
`channels.googlechat.dmPolicy="open"`). Defining a `dm` object is not the same as defining
`dm.policy` inside it, and conflating the two is how this got written.

discord and slack are FLAT-PRIMARY (flat wins over nested when
both are written), grounded via the generic ``resolveChannelDmPolicy``
(dm-access-j6yOoNfd.js:81-85, "topOnly" mode) that Discord's own
``resolveDiscordAccountDmPolicy`` (accounts-B2tNBeEr.js:39-48) calls, consumed at the real
DM dispatch gate (provider-DNXfDOia.js:3747-3754). ``dm.enabled === false`` is a separate,
higher-priority closure confirmed at a real consumer gate for exactly two channels —
googlechat (channel2.runtime-Bb6oxd87.js:325) and discord (provider-DNXfDOia.js:1222,3747)
— and deliberately NOT claimed for slack/matrix, unconfirmed within this task's grounding
budget; inventing it there would risk the false-negative direction this fix exists to
avoid, not just the false-positive one it fixes.

Two forms added: nested `dm.policy` (4 channels) and `dm.enabled: false` (2 of those 4).
Every closure form below has a paired OPEN-form test proving `_untrusted_input_channels`
(the trifecta ingress leg) still counts it — teaching A1 to recognise a closure must never
teach it to stop counting a leg.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_trifecta
from clawseccheck.checks._shared import (
    _DM_POLICY_ENABLED_GATE_CHANNELS,
    _DM_POLICY_FLAT_PRIMARY_CHANNELS,
    _DM_POLICY_NESTED_ONLY_CHANNELS,
    _declared_dm_policy,
    _resolved_default_input_channels,
    _untrusted_input_channels,
)
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(tmp_path: Path, cfg: dict):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    p = home / "openclaw.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")
    p.chmod(0o600)
    ctx = collect(home=str(home))
    assert ctx.config, "collect() did not read the fixture config"
    return ctx


# --------------------------------------------------------------- the enumeration itself


def test_the_channel_family_enumeration():
    """The deliverable: exactly which channels get which closure form, pinned so it does
    not silently rot behind the next channel shipped (the risk this fix's own grounding
    comment names explicitly)."""
    # B-720: googlechat was removed. It is the ONLY channel in the vendor's generated
    # config schema that declares a flat `dmPolicy` while declaring no `dm.policy`, and
    # this set had it backwards. matrix is the single genuinely nested channel.
    assert _DM_POLICY_NESTED_ONLY_CHANNELS == frozenset({"matrix"})
    assert _DM_POLICY_FLAT_PRIMARY_CHANNELS == frozenset({"discord", "slack"})
    assert _DM_POLICY_ENABLED_GATE_CHANNELS == frozenset({"googlechat", "discord"})
    # B-720 replaced the old invariant here. It asserted every enabled-gate channel is in
    # one of the two named sets, which only held while googlechat was wrongly in
    # nested-only: every channel not named reads the flat key by DEFAULT, so the named
    # sets never were "the channels that read a policy". The real constraint is narrower
    # and is the one that can actually fail -- `dm.enabled` needs a nested `dm` object,
    # and exactly four channels define one.
    _CHANNELS_WITH_A_DM_OBJECT = frozenset({"discord", "slack", "googlechat", "matrix"})
    assert _DM_POLICY_ENABLED_GATE_CHANNELS <= _CHANNELS_WITH_A_DM_OBJECT
    assert _DM_POLICY_NESTED_ONLY_CHANNELS <= _CHANNELS_WITH_A_DM_OBJECT


# --------------------------------------------------------------- _declared_dm_policy


def test_googlechat_reads_the_flat_key():
    """B-720. This test asserted the exact opposite until 2026-09-04, and was green the
    whole time — a test can pin a false claim as easily as a true one.

    The flat key is the one googlechat's own schema declares and the one the vendor's own
    validator enforces (`superRefine` -> `requireOpenAllowFrom({policy: value.dmPolicy})`,
    whose message names `channels.googlechat.dmPolicy="open"`). The NESTED path is the one
    that cannot exist: `GoogleChatDmSchema = object({enabled: ...}).strict()`.
    """
    assert _declared_dm_policy("googlechat", {"dmPolicy": "disabled"}) == "disabled"
    # And the nested form is not invented into a declaration: `dm` on googlechat holds
    # only `enabled`, so a `dm.policy` there is not a key any valid config can carry.
    assert _declared_dm_policy("googlechat", {"dm": {"policy": "disabled"}}) is None


def test_an_open_googlechat_dm_policy_is_no_longer_invisible():
    """The user-visible defect B-720 closed, stated as the thing that was wrong.

    `dmPolicy: "open"` on googlechat read as "nothing declared", so an open DM posture the
    vendor itself refuses to load without an `allowFrom` was silently absent from the
    ingress leg. Pinned separately from the reader test above because THIS is the finding;
    the reader is only how it happened.
    """
    assert _declared_dm_policy("googlechat", {"dmPolicy": "open"}) == "open"
    assert _declared_dm_policy("googlechat", {"dmPolicy": "allowlist"}) == "allowlist"


def test_matrix_reads_nested_only():
    assert _declared_dm_policy("matrix", {"dm": {"policy": "allowlist"}}) == "allowlist"
    assert _declared_dm_policy("matrix", {"dmPolicy": "allowlist"}) is None


def test_discord_and_slack_read_both_flat_wins():
    for name in ("discord", "slack"):
        assert _declared_dm_policy(name, {"dm": {"policy": "open"}}) == "open"
        assert _declared_dm_policy(name, {"dmPolicy": "open"}) == "open"
        # Both written: flat is canonical ("topOnly" mode), nested is the legacy fallback.
        node = {"dmPolicy": "pairing", "dm": {"policy": "open"}}
        assert _declared_dm_policy(name, node) == "pairing"


def test_telegram_never_reads_nested():
    """A flat-only channel's schema never defines `dm` at all — a stray `dm.policy` on it
    is never consulted by anything and must not be invented as a declaration."""
    assert _declared_dm_policy("telegram", {"dmPolicy": "disabled"}) == "disabled"
    assert _declared_dm_policy("telegram", {"dm": {"policy": "disabled"}}) is None


def test_dm_enabled_false_closes_googlechat_and_discord_even_with_no_policy_written():
    for name in ("googlechat", "discord"):
        assert _declared_dm_policy(name, {"dm": {"enabled": False}}) == "disabled"


def test_dm_enabled_false_is_not_claimed_for_slack_or_matrix():
    """Deliberate scope boundary — not a fixture of a wrong belief. Not independently
    confirmed at a consumer gate for these two within this task's grounding budget."""
    for name in ("slack", "matrix"):
        assert _declared_dm_policy(name, {"dm": {"enabled": False}}) is None


def test_dm_enabled_takes_priority_over_a_written_open_policy():
    node = {"dm": {"enabled": False, "policy": "open"}}
    assert _declared_dm_policy("googlechat", node) == "disabled"
    assert _declared_dm_policy("discord", node) == "disabled"


def test_declared_dm_policy_never_raises_on_schema_drift():
    assert _declared_dm_policy("googlechat", "not-a-dict") is None
    assert _declared_dm_policy("googlechat", {"dm": ["not", "a", "dict"]}) is None
    assert _declared_dm_policy("discord", {"dmPolicy": ["not", "a", "string"]}) is None
    assert _declared_dm_policy("discord", {"dmPolicy": ""}) is None


# --------------------------------------------------------- _resolved_default_input_channels


def test_repro1_nested_closure_is_not_a_resolved_default():
    """Brief reproduction 1, verbatim: the owner explicitly closed DM ingress via the
    nested form. Must not be reported as having set none."""
    cfg = {"channels": {"googlechat": {"enabled": True, "dm": {"enabled": False, "policy": "disabled"}}}}
    assert _resolved_default_input_channels(cfg) == []


def test_dm_enabled_false_alone_is_not_a_resolved_default():
    cfg = {"channels": {"googlechat": {"enabled": True, "dm": {"enabled": False}}}}
    assert _resolved_default_input_channels(cfg) == []


def test_genuinely_silent_googlechat_is_still_a_resolved_default():
    """The negative control: NOTHING written at all must still fire — this fix must not
    have swallowed the genuine-absence case while fixing the false one."""
    cfg = {"channels": {"googlechat": {"enabled": True}}}
    assert _resolved_default_input_channels(cfg) == ["googlechat"]


def test_matrix_nested_pairing_is_a_written_choice_not_a_default():
    cfg = {"channels": {"matrix": {"enabled": True, "dm": {"policy": "pairing"}}}}
    assert _resolved_default_input_channels(cfg) == []


def test_repro3_per_account_policy_with_no_live_base_account():
    """Brief reproduction 3: a flat-key-only channel (telegram) whose ONLY declared
    policy sits on its one configured account, with no channel-level credential to spawn
    an implicit default account. The base node must not be evaluated as if it were an
    independently-running, policy-less account."""
    cfg = {
        "channels": {
            "telegram": {"enabled": True, "accounts": {"primary": {"dmPolicy": "disabled"}}}
        }
    }
    assert _resolved_default_input_channels(cfg) == []


def test_repro3_counterpart_live_implicit_default_account_is_still_checked():
    """Same shape, but the base node NOW carries a credential (botToken) that spawns a
    live implicit default account alongside "primary" — grounded at
    _IMPLICIT_DEFAULT_ACCOUNT_KEYS["telegram"]. That base account genuinely runs with no
    dmPolicy of its own, so it must still be reported."""
    cfg = {
        "channels": {
            "telegram": {
                "enabled": True,
                "botToken": "x",
                "accounts": {"primary": {"dmPolicy": "disabled"}},
            }
        }
    }
    assert _resolved_default_input_channels(cfg) == ["telegram"]


# --------------------------------------------------------- _untrusted_input_channels
# Paired closed/open tests: every closure form gets a matching OPEN-form test proving the
# leg is still counted — teaching A1 a closure must never teach it to stop seeing an open.


def test_closed_matrix_nested_is_not_an_untrusted_leg():
    cfg = {"channels": {"matrix": {"enabled": True, "dm": {"policy": "disabled"}}}}
    assert _untrusted_input_channels(cfg) == []


def test_open_matrix_nested_still_counts_the_leg():
    cfg = {"channels": {"matrix": {"enabled": True, "dm": {"policy": "open"}}}}
    assert _untrusted_input_channels(cfg) == ["matrix"]


def test_open_googlechat_flat_counts_the_leg():
    """B-720's user-visible half, at the leg level rather than the reader level: before
    the fix this returned [] because the flat key was skipped for googlechat."""
    cfg = {"channels": {"googlechat": {"enabled": True, "dmPolicy": "open"}}}
    assert _untrusted_input_channels(cfg) == ["googlechat"]


def test_closed_googlechat_dm_enabled_false_is_not_an_untrusted_leg():
    cfg = {"channels": {"googlechat": {"enabled": True, "dm": {"enabled": False}}}}
    assert _untrusted_input_channels(cfg) == []


def test_closed_discord_nested_is_not_an_untrusted_leg():
    cfg = {"channels": {"discord": {"enabled": True, "dm": {"policy": "disabled"}}}}
    assert _untrusted_input_channels(cfg) == []


def test_repro2_open_discord_nested_counts_the_leg_same_as_flat():
    """Brief reproduction 2: the exact filed pair. A world-open nested policy must count
    identically to its flat spelling — status/leg must not split on spelling."""
    nested = {"channels": {"discord": {"enabled": True, "dm": {"policy": "open"}}}}
    flat = {"channels": {"discord": {"enabled": True, "dmPolicy": "open"}}}
    assert _untrusted_input_channels(nested) == ["discord"]
    assert _untrusted_input_channels(nested) == _untrusted_input_channels(flat)


def test_open_matrix_and_slack_nested_count_the_leg():
    assert _untrusted_input_channels(
        {"channels": {"matrix": {"enabled": True, "dm": {"policy": "allowlist"}}}}
    ) == ["matrix"]
    assert _untrusted_input_channels(
        {"channels": {"slack": {"enabled": True, "dm": {"policy": "pairing"}}}}
    ) == ["slack"]


def test_dm_enabled_false_suppresses_the_leg_even_with_a_written_open_policy():
    """dm.enabled has priority over the value at the SAME real gate this project already
    grounds for closure — an operator who closes the channel outright must not still be
    scored as having an active leg because a stale `policy: "open"` sits beside it."""
    cfg = {
        "channels": {"discord": {"enabled": True, "dm": {"enabled": False, "policy": "open"}}}
    }
    assert _untrusted_input_channels(cfg) == []


def test_slack_dm_enabled_false_does_not_suppress_the_leg():
    """The mirror control for the deliberate scope boundary above: since dm.enabled is
    NOT claimed for slack, a written open policy there must still count — this fix must
    not have silently widened the enabled-gate set past what is grounded."""
    cfg = {
        "channels": {"slack": {"enabled": True, "dm": {"enabled": False, "policy": "open"}}}
    }
    assert _untrusted_input_channels(cfg) == ["slack"]


# --------------------------------------------------------------------- A1 end to end


def test_repro1_a1_no_longer_claims_no_policy_was_set(tmp_path):
    cfg = {
        "channels": {
            "googlechat": {"enabled": True, "dm": {"enabled": False, "policy": "disabled"}}
        },
        "tools": {"allow": ["read_file", "web_fetch"]},
    }
    f = check_trifecta(_ctx(tmp_path, cfg))
    assert f.status == PASS, f.status
    assert "Resolved default" not in f.detail
    assert "set no dmPolicy" not in f.detail


def test_repro2_a1_status_matches_between_nested_and_flat(tmp_path):
    tools = {"allow": ["read_file", "web_fetch"]}
    nested = _ctx(tmp_path, {"channels": {"discord": {"enabled": True, "dm": {"policy": "open", "allowFrom": ["*"]}}}, "tools": tools})
    tmp2 = tmp_path / "flat"
    tmp2.mkdir()
    flat = _ctx(tmp2, {"channels": {"discord": {"enabled": True, "dmPolicy": "open", "allowFrom": ["*"]}}, "tools": tools})
    fn = check_trifecta(nested)
    ff = check_trifecta(flat)
    assert fn.status == ff.status == PASS
    assert sorted(fn.evidence or []) == sorted(ff.evidence or [])
    assert "Resolved default" not in fn.detail


def test_genuine_silence_still_warns_with_schema_correct_remediation(tmp_path):
    """The remaining genuine-absence case on the nested-only channel must recommend the
    NESTED key, never the flat one its schema does not carry."""
    cfg = {
        "channels": {"matrix": {"enabled": True}},
        "tools": {"allow": ["read_file", "web_fetch"]},
    }
    f = check_trifecta(_ctx(tmp_path, cfg))
    assert f.status == WARN, f.status
    assert "Resolved default" in f.detail
    assert 'dm.policy: "disabled"' in f.fix
    assert 'Set `dmPolicy: "disabled"` on matrix' not in f.fix


def test_googlechat_is_steered_to_the_flat_key_the_vendor_enforces(tmp_path):
    """B-720's harmful-advice half, pinned. Until 2026-09-04 a user with an open
    googlechat was told to write the nested `dm.policy` -- a key `GoogleChatDmSchema`
    (`.strict()`, `enabled` only) does not carry -- and told NOT to write the flat one,
    which is the key the vendor's own validator enforces. Following that advice would
    have left DM ingress open while the user believed they had closed it."""
    cfg = {
        "channels": {"googlechat": {"enabled": True}},
        "tools": {"allow": ["read_file", "web_fetch"]},
    }
    f = check_trifecta(_ctx(tmp_path, cfg))
    assert f.status == WARN, f.status
    assert 'Set `dmPolicy: "disabled"` on googlechat' in f.fix
    assert "dm.policy" not in f.fix


def test_mixed_flat_and_nested_only_channels_get_separate_remediation(tmp_path):
    cfg = {
        "channels": {
            "telegram": {"enabled": True},
            "matrix": {"enabled": True},
        },
        "tools": {"allow": ["read_file", "web_fetch"]},
    }
    f = check_trifecta(_ctx(tmp_path, cfg))
    assert f.status == WARN, f.status
    assert 'dmPolicy: "disabled"` on telegram' in f.fix
    assert 'dm.policy: "disabled"' in f.fix


def test_unknown_path_unreadable_config_is_not_upgraded_to_a_confident_claim(tmp_path):
    """UNKNOWN guard runs before any of this fix's branches. A truncated config with a
    nested-dm shape must not acquire a confidently-worded WARN/PASS about it."""
    home = tmp_path / "home"
    home.mkdir()
    p = home / "openclaw.json"
    p.write_text('{"channels": {"googlechat": {"dm": {"polic', encoding="utf-8")  # truncated
    p.chmod(0o600)
    ctx = collect(home=str(home))
    assert ctx.config_parse_error, "the truncated config was not detected as unparseable"
    f = check_trifecta(ctx)
    assert f.status == UNKNOWN, f.status
    assert "Resolved default" not in f.detail
    assert "dm.policy" not in f.detail


def test_unknown_path_schema_drifted_dm_does_not_raise_end_to_end(tmp_path):
    """A `dm` value that drifted to a list (not a dict) must degrade, not crash, all the
    way through the real check."""
    cfg = {
        "channels": {"googlechat": {"enabled": True, "dm": ["not", "a", "dict"]}},
        "tools": {"allow": ["read_file", "web_fetch"]},
    }
    f = check_trifecta(_ctx(tmp_path, cfg))
    assert f.status == WARN, f.status
    assert "Resolved default" in f.detail


# --------------------------------------------------------- shipped corpus fixtures
# Before this pair, `grep -rl '"dm"[[:space:]]*:' fixtures/` returned zero hits across
# the whole 680-home corpus — every corpus-wide sweep (finding-fingerprint manifest,
# the fleet FP gate) was structurally blind to a nested-dm channel, so a future edit to
# `_declared_dm_policy` could drop nested reading entirely and only this module's inline
# dicts (above) would notice. These two fixtures make the shape corpus-visible. Modelled
# byte-for-byte on fixtures/clean_b283_dm_pairing_disabled / bad_b283_dm_pairing (same
# gateway/tools/logging/models scaffolding, so no unrelated check fires) — differing only
# in the channels block.


def test_clean_fixture_nested_closed_is_not_reported_as_no_policy_set():
    """fixtures/clean_b619_nested_dm_closed — matrix closed via nested `dm.policy`
    (the one nested-only channel; see ``_DM_POLICY_NESTED_ONLY_CHANNELS``, and B-720 for
    why this fixture used to model the shape on googlechat) plus discord closed via
    `dm.enabled: false`
    (the enabled-gate form, grounded for discord). Neither must read as "no policy
    set", and the untrusted-input leg must not be counted for either channel."""
    ctx = collect(home=str(FIXTURES / "clean_b619_nested_dm_closed"))
    assert ctx.config, "collect() did not read the shipped fixture config"
    assert _untrusted_input_channels(ctx.config) == []
    assert _resolved_default_input_channels(ctx.config) == []
    f = check_trifecta(ctx)
    assert "Resolved default" not in f.detail
    assert "set no dmPolicy" not in f.detail


def test_bad_fixture_nested_open_still_counts_the_untrusted_input_leg():
    """fixtures/bad_b619_nested_dm_open — matrix opened via nested `dm.policy: "open"`
    only (the paired OPEN direction of the clean fixture above, so a nested-open
    channel is corpus-visible too). The trifecta ingress leg must still be counted —
    teaching A1 to recognise a nested closure must never teach it to stop seeing a
    nested open.

    B-720: both b619 fixtures modelled this shape on googlechat, whose `dm` object is
    `.strict()` with only `enabled` — so they encoded a config OpenClaw itself rejects.
    Re-pointed at matrix, the one channel whose schema declares `dm.policy`."""
    ctx = collect(home=str(FIXTURES / "bad_b619_nested_dm_open"))
    assert ctx.config, "collect() did not read the shipped fixture config"
    assert _untrusted_input_channels(ctx.config) == ["matrix"]
    f = check_trifecta(ctx)
    assert "untrusted input" in (f.evidence or [])
    assert "channel 'matrix' allows untrusted senders" in f.detail


# ------------------------------------------------- B-720: the flat googlechat corpus pair
# B-720 re-pointed both fixtures above from googlechat to matrix, because they encoded
# `dm.policy` on a channel whose `GoogleChatDmSchema` is `.strict()` with only `enabled` —
# a config OpenClaw itself rejects. That was the right move and it left a hole: after it,
# `grep -rl googlechat fixtures/` returned ZERO across the whole corpus. googlechat's
# coverage was not "never added", it was REMOVED, so the channel whose classification this
# task actually corrected became invisible to every corpus-wide sweep (the finding
# fingerprint manifest, the fleet FP gate). These two fixtures restore it in the FLAT form
# the vendor really enforces.
#
# `allowFrom: ["*"]` in the bad fixture is load-bearing, not decoration. The vendor's own
# validator (bundled-channel-config-schema.js, googlechat's `superRefine`) reads verbatim:
#
#     requireOpenAllowFrom({ policy: value.dmPolicy, allowFrom: value.allowFrom, ctx,
#       message: 'channels.googlechat.dmPolicy="open" requires
#                 channels.googlechat.allowFrom to include "*"' })
#
# and its shared predicate is `policy === "open" && !allow.includes("*")` ->
# "open_requires_wildcard" (`evaluateDmPolicyAllowFromDependency`, zod-schema.core-*.js).
# So an open googlechat DM policy is INSEPARABLE from a wildcard allowlist in OpenClaw:
# there is no way to write "open to a named few", and a fixture omitting the wildcard would
# repeat exactly the not-loadable-config defect B-720 was filed about.
#
# HONEST LIMIT, recorded rather than papered over: that refinement could not be EXECUTED
# against this dist. `channels.*` is passthrough in the core `OpenClawSchema` — proven with
# a bogus-key control, `{channels: {googlechat: {zzzBogus123: true}}}` and even a wholly
# invented channel both parse ACCEPTED, while a bogus TOP-LEVEL key is rejected — and the
# per-channel schemas load through a plugin facade that raises MissingPublicSurfaceError
# outside the runtime (no `config-api.js` ships in the dist at all). The claim above rests
# on the vendor's source read directly, which is why it quotes it verbatim instead of
# citing a parse result. Do not "verify" these fixtures by parsing them against the core
# schema and reading ACCEPTED as confirmation: it accepts anything under `channels`.


def test_clean_fixture_googlechat_flat_closed_is_not_counted_as_untrusted_input():
    """fixtures/clean_b720_googlechat_flat_dm_closed — googlechat closed via the FLAT
    `dmPolicy: "disabled"`, the form the vendor enforces. The ingress leg must not be
    counted, and the channel must not read as having set no policy."""
    ctx = collect(home=str(FIXTURES / "clean_b720_googlechat_flat_dm_closed"))
    assert ctx.config, "collect() did not read the shipped fixture config"
    assert _declared_dm_policy("googlechat", ctx.config["channels"]["googlechat"]) == "disabled"
    assert _untrusted_input_channels(ctx.config) == []
    assert _resolved_default_input_channels(ctx.config) == []
    f = check_trifecta(ctx)
    assert "Resolved default" not in f.detail
    assert "set no dmPolicy" not in f.detail


def test_bad_fixture_googlechat_flat_open_still_counts_the_untrusted_input_leg():
    """fixtures/bad_b720_googlechat_flat_dm_open — the paired OPEN direction, so a flat-open
    googlechat is corpus-visible too. Reading the flat key correctly must not cost the
    trifecta its ingress leg: this is the pairing that would catch a future edit which
    "fixes" the classifier by making it read nothing at all, which is the state B-720 found
    (`_declared_dm_policy` returned None for every googlechat channel however it was set)."""
    ctx = collect(home=str(FIXTURES / "bad_b720_googlechat_flat_dm_open"))
    assert ctx.config, "collect() did not read the shipped fixture config"
    assert _declared_dm_policy("googlechat", ctx.config["channels"]["googlechat"]) == "open"
    assert _untrusted_input_channels(ctx.config) == ["googlechat"]
    f = check_trifecta(ctx)
    assert "untrusted input" in (f.evidence or [])
    assert "channel 'googlechat' allows untrusted senders" in f.detail
