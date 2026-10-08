"""C-655 -- B372 (allowBots) reachability and account list.

Four gaps left after the 2026.9.7 default-flip work (``test_b372_allow_bots_default_flip.py``):

1. B372 asked the shared ``_external_input_channels``, which reads only the RAW ``dmPolicy`` /
   ``groupPolicy`` written in the config. A minimal Discord/Slack config that omits both reads
   as "no external input" there, so an UNSET allowBots (accepted by default on 2026.9.7+) and an
   explicit ``allowBots: true`` both read PASS. B372 now applies the schema defaults LOCALLY
   (dmPolicy -> "pairing", groupPolicy -> channels.defaults.groupPolicy -> "allowlist"); the
   shared helper stays raw (B-499).
2. The explicit-value scan looped over the resolved accounts only, while the unset-key walk also
   judged the implicit Discord default account. Both now loop over the same node list.
3. An implicit default account was added even when a configured account is itself named
   ``default`` -- the vendor's account-id combiner collects ids in a Set, so they are ONE account.
4. A DM-only config (``groupPolicy: "disabled"``) still WARNs on an unset key. That one is
   deliberately NOT changed: nothing in the installed docs establishes which surface a
   bot-authored message can arrive on, and the Discord/Slack resolvers ship out of tree. The
   residual is disclosed in ``fix`` (never ``detail``, which the fingerprint hashes).

Review round (same task): the defaults reading applies only to a stanza that HOLDS A
CREDENTIAL and only to the six channels whose schema declares ``allowBots``; a defaulted
allowlist counts only when a live (not ``enabled: false``) group/room/guild/channel is listed;
and a configured ``default`` account that is disabled does not drop the implicit node.

Offline and read-only: the build is injected through ``Context.installed_dist_version``.
"""
from __future__ import annotations

import pytest

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_channel_allow_bots
from clawseccheck.collector import Context

_UNSET_EVIDENCE = "allowBots (unset, defaults to true on 2026.9.7+)"

# Frozen on purpose: ``baseline.fingerprint()`` hashes ``detail``.
_EXPLICIT_WARN_DETAIL = (
    "1 channel scope(s) admit non-owner senders with allowBots enabled — messages "
    "authored by other bot accounts reach the agent as input, at whatever rate the bot "
    "account can generate them."
)
_DEFAULT_WARN_DETAIL = (
    _EXPLICIT_WARN_DETAIL
    + " On OpenClaw 2026.9.7 and later, Discord and Slack accept bot-authored messages when "
    "allowBots is unset, so an unset allowBots counts as enabled there."
)

_OPEN = {"dmPolicy": "open", "allowFrom": ["*"]}

# The two minimal shapes from the task (token plus a guild / channel map) and the bare token.
_DISCORD_GUILD = {"token": "t", "guilds": {"1": {}}}
_SLACK_CHANNEL = {"botToken": "t", "channels": {"C1": {}}}
_DISCORD_BARE = {"token": "t"}


def _ch(**channels):
    return {"channels": channels}


def _run(cfg, tmp_path, version=None):
    ctx = Context(home=tmp_path, config=cfg, config_found=True, installed_dist_version=version)
    return check_channel_allow_bots(ctx)


# ----------------------------------------------------------------------------------------
# item 1: reachability once the schema defaults are applied
class TestMinimalConfigs:
    @pytest.mark.parametrize("channel, node", [
        ("discord", _DISCORD_GUILD),
        ("slack", _SLACK_CHANNEL),
        ("discord", _DISCORD_BARE),
    ])
    def test_a_minimal_config_warns_on_the_flipped_build(self, tmp_path, channel, node):
        """THE regression: both of these read PASS ("no channel accepts bot-authored input")
        while the 2026.9.7 runtime accepts bots on an unset key."""
        f = _run(_ch(**{channel: dict(node)}), tmp_path, "2026.9.7")
        assert f.status == WARN
        assert f.evidence == [f"{channel}.{_UNSET_EVIDENCE}"]
        assert f.detail == _DEFAULT_WARN_DETAIL
        assert f"channels.{channel}.allowBots" in f.fix

    @pytest.mark.parametrize("channel, node", [
        ("discord", _DISCORD_GUILD),
        ("slack", _SLACK_CHANNEL),
        ("discord", _DISCORD_BARE),
    ])
    @pytest.mark.parametrize("version", ["2026.9.6", "2026.9.6-1", "2026.7.1-2"])
    def test_a_minimal_config_still_passes_on_a_denying_build(
            self, tmp_path, channel, node, version):
        assert _run(_ch(**{channel: dict(node)}), tmp_path, version).status == PASS

    @pytest.mark.parametrize("channel, node", [
        ("discord", _DISCORD_GUILD),
        ("slack", _SLACK_CHANNEL),
    ])
    @pytest.mark.parametrize("version", [None, "2026.9.7-beta.1", "0.0.0"])
    def test_a_minimal_config_on_an_undeterminable_build_is_unknown(
            self, tmp_path, channel, node, version):
        """UNKNOWN, never the old PASS and never a guessed WARN."""
        f = _run(_ch(**{channel: dict(node)}), tmp_path, version)
        assert f.status == UNKNOWN
        assert f.evidence == [f"{channel}.allowBots (unset)"]

    @pytest.mark.parametrize("channel, node", [
        ("discord", _DISCORD_GUILD),
        ("slack", _SLACK_CHANNEL),
        ("discord", _DISCORD_BARE),
    ])
    def test_the_stamp_route_reaches_the_minimal_config_too(self, tmp_path, channel, node):
        cfg = {**_ch(**{channel: dict(node)}), "meta": {"lastTouchedVersion": "2026.9.7"}}
        assert _run(cfg, tmp_path).status == WARN

    @pytest.mark.parametrize("channel, node", [
        ("discord", _DISCORD_GUILD),
        ("slack", _SLACK_CHANNEL),
    ])
    @pytest.mark.parametrize("version", [None, "2026.9.6", "2026.9.7"])
    def test_an_explicit_true_on_a_minimal_config_warns_on_every_build(
            self, tmp_path, channel, node, version):
        """The explicit-true shapes read PASS too: this was a gate miss, not an unset-key miss."""
        f = _run(_ch(**{channel: {**node, "allowBots": True}}), tmp_path, version)
        assert f.status == WARN
        assert f.evidence == [f"{channel}.allowBots=true"]
        assert f.detail == _EXPLICIT_WARN_DETAIL

    @pytest.mark.parametrize("channel, node", [
        ("discord", _DISCORD_GUILD),
        ("slack", _SLACK_CHANNEL),
    ])
    @pytest.mark.parametrize("version", [None, "2026.9.6", "2026.9.7"])
    def test_an_explicit_false_on_a_minimal_config_is_pass_on_every_build(
            self, tmp_path, channel, node, version):
        assert _run(_ch(**{channel: {**node, "allowBots": False}}), tmp_path,
                    version).status == PASS

    def test_an_explicit_true_on_a_minimal_schema_channel_warns(self, tmp_path):
        """The widened gate covers the six channels whose schema declares allowBots, not only
        Discord/Slack. (The unset key stays PASS there -- see the sibling test file.)"""
        f = _run(_ch(googlechat={"serviceAccount": "x", "allowBots": True}), tmp_path, "2026.9.7")
        assert f.status == WARN and f.evidence == ["googlechat.allowBots=true"]
        f = _run(_ch(matrix={"accessToken": "t", "rooms": {"r1": {"allowBots": "mentions"}}}),
                 tmp_path, "2026.9.7")
        assert f.status == WARN and f.evidence == ['matrix.rooms.r1.allowBots="mentions"']
        assert _run(_ch(matrix={"accessToken": "t", "rooms": {"r1": {}}}), tmp_path,
                    "2026.9.7").status == PASS
        f = _run(_ch(clickclack={"token": "t", "allowBots": True}), tmp_path, "2026.9.7")
        assert f.status == WARN and f.evidence == ["clickclack.allowBots=true"]
        f = _run(_ch(feishu={"appId": "i", "appSecret": "s", "allowBots": True}), tmp_path,
                 "2026.9.7")
        assert f.status == WARN and f.evidence == ["feishu.allowBots=true"]


class TestTheGateCanStillClose:
    """The positive controls: the resolved gate must be able to say "unreachable"."""

    def test_both_policies_disabled_is_unreachable(self, tmp_path):
        cfg = _ch(discord={**_DISCORD_GUILD, "dmPolicy": "disabled", "groupPolicy": "disabled"})
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS
        cfg = _ch(discord={**_DISCORD_GUILD, "dmPolicy": "disabled", "groupPolicy": "disabled",
                           "allowBots": True})
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS

    def test_a_disabled_channel_is_unreachable(self, tmp_path):
        for node in (_DISCORD_GUILD, {**_DISCORD_GUILD, "allowBots": True}):
            cfg = _ch(discord={**node, "enabled": False})
            assert _run(cfg, tmp_path, "2026.9.7").status == PASS

    def test_a_dm_disabled_config_inherits_the_group_default_so_it_is_reachable(self, tmp_path):
        """groupPolicy omitted resolves to "allowlist", which admits the allowlisted scopes."""
        cfg = _ch(discord={**_DISCORD_GUILD, "dmPolicy": "disabled"})
        assert _run(cfg, tmp_path, "2026.9.7").status == WARN

    @pytest.mark.parametrize("channel, node", [
        ("discord", {"dm": {"enabled": False}}),
        ("discord", {"token": "t", "dmPolicy": "disabled"}),
        ("slack", {"botToken": "t", "dmPolicy": "disabled"}),
        ("matrix", {"dm": {"policy": "disabled"}}),
    ])
    def test_a_dm_closed_config_with_no_group_scope_reads_as_it_did_before(
            self, tmp_path, channel, node):
        """A DEFAULTED allowlist admits only what it lists: nothing is listed, so there is no
        group surface. This is the shape the B-619 clean fixtures use; it must not turn into
        a finding merely because the group default is now read."""
        assert _run(_ch(**{channel: dict(node)}), tmp_path, "2026.9.7").status == PASS
        assert _run(_ch(**{channel: {**node, "allowBots": True}}), tmp_path,
                    "2026.9.7").status == PASS

    def test_an_open_defaults_group_policy_reaches_without_a_scope(self, tmp_path):
        cfg = {"channels": {"defaults": {"groupPolicy": "open"},
                            "discord": {"token": "t", "dmPolicy": "disabled"}}}
        assert _run(cfg, tmp_path, "2026.9.7").status == WARN

    def test_a_written_allowlist_counts_without_a_scope(self, tmp_path):
        """As the raw gate has always read it: a WRITTEN allowlist is external input."""
        cfg = _ch(discord={"token": "t", "dmPolicy": "disabled", "groupPolicy": "allowlist"})
        assert _run(cfg, tmp_path, "2026.9.7").status == WARN

    def test_channels_defaults_group_policy_is_read(self, tmp_path):
        """``channels.defaults.groupPolicy`` is the vendor's own default layer."""
        closed = {**_DISCORD_GUILD, "dmPolicy": "disabled"}
        cfg = {"channels": {"defaults": {"groupPolicy": "disabled"}, "discord": dict(closed)}}
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS
        # ... and a node's own groupPolicy still beats it
        cfg = {"channels": {"defaults": {"groupPolicy": "disabled"},
                            "discord": {**closed, "groupPolicy": "open"}}}
        assert _run(cfg, tmp_path, "2026.9.7").status == WARN
        # ... an open default reaches a node that omits its own
        cfg = {"channels": {"defaults": {"groupPolicy": "open"}, "discord": dict(closed)}}
        assert _run(cfg, tmp_path, "2026.9.7").status == WARN

    def test_a_drifted_defaults_group_policy_does_not_close_the_gate(self, tmp_path):
        """A non-string default is not a policy choice: fall back to the vendor default
        (allowlist), the reachable reading -- never to a PASS."""
        closed = {**_DISCORD_GUILD, "dmPolicy": "disabled"}
        for junk in (["disabled"], {"v": "disabled"}, 0, ""):
            cfg = {"channels": {"defaults": {"groupPolicy": junk}, "discord": dict(closed)}}
            assert _run(cfg, tmp_path, "2026.9.7").status == WARN, junk
        cfg = {"channels": {"defaults": "disabled", "discord": dict(closed)}}
        assert _run(cfg, tmp_path, "2026.9.7").status == WARN

    def test_a_nested_dm_disable_closes_the_dm_surface(self, tmp_path):
        """Discord's ``dm.enabled: false`` is read through ``_declared_dm_policy``."""
        cfg = _ch(discord={**_DISCORD_GUILD, "groupPolicy": "disabled",
                           "dm": {"enabled": False}})
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS

    def test_defaults_do_not_make_a_defaults_block_a_channel(self, tmp_path):
        cfg = {"channels": {"defaults": {"allowBots": True}}}
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS

    def test_an_account_policy_closes_only_that_account(self, tmp_path):
        """Per-node resolution on the unset walk: the closed account adds nothing, the
        account that writes no policy inherits the defaults and is reachable."""
        closed = {"dmPolicy": "disabled", "groupPolicy": "disabled"}
        cfg = _ch(slack={"botToken": "t", "accounts": {"quiet": {**closed}, "plain": {}}})
        f = _run(cfg, tmp_path, "2026.9.7")
        assert f.status == WARN and f.evidence == [f"slack.{_UNSET_EVIDENCE}"]
        cfg = _ch(slack={"botToken": "t", "accounts": {"quiet": {**closed}, "also": {**closed}}})
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS

    def test_a_disabled_account_beside_a_minimal_false_account_is_pass(self, tmp_path):
        cfg = _ch(slack={"botToken": "t", "accounts": {"live": {"allowBots": False},
                                                       "retired": {"enabled": False}}})
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS


# ----------------------------------------------------------------------------------------
# item 2: the explicit-value scan loops over the same nodes as the unset walk
class TestExplicitScanSeesTheImplicitDefaultAccount:
    _BASE = {"token": "t", **_OPEN}

    def test_root_true_beside_a_false_account_warns(self, tmp_path):
        cfg = _ch(discord={**self._BASE, "allowBots": True, "accounts": {"a": {"allowBots": False}}})
        f = _run(cfg, tmp_path, "2026.9.7")
        assert f.status == WARN
        assert f.evidence == ["discord.allowBots=true"]
        assert f.detail == _EXPLICIT_WARN_DETAIL

    @pytest.mark.parametrize("version", [None, "2026.9.6", "2026.9.7"])
    def test_root_true_is_a_warn_on_every_build(self, tmp_path, version):
        """An explicit value does not depend on the build."""
        cfg = _ch(discord={**self._BASE, "allowBots": True, "accounts": {"a": {"allowBots": False}}})
        assert _run(cfg, tmp_path, version).status == WARN

    def test_root_true_and_root_omitted_agree_on_the_flipped_build(self, tmp_path):
        """The task's own acceptance line: the same config with the key omitted WARNs, so
        the explicit ``true`` must too."""
        acc = {"a": {"allowBots": False}}
        omitted = _run(_ch(discord={**self._BASE, "accounts": dict(acc)}), tmp_path, "2026.9.7")
        explicit = _run(_ch(discord={**self._BASE, "allowBots": True, "accounts": dict(acc)}),
                        tmp_path, "2026.9.7")
        assert omitted.status == explicit.status == WARN

    def test_root_mentions_beside_a_false_account_warns(self, tmp_path):
        cfg = _ch(discord={**self._BASE, "allowBots": "mentions",
                           "accounts": {"a": {"allowBots": False}}})
        f = _run(cfg, tmp_path, "2026.9.7")
        assert f.status == WARN and f.evidence == ['discord.allowBots="mentions"']

    def test_a_drifted_root_value_beside_a_false_account_is_unknown(self, tmp_path):
        cfg = _ch(discord={**self._BASE, "allowBots": "sometimes",
                           "accounts": {"a": {"allowBots": False}}})
        f = _run(cfg, tmp_path, "2026.9.7")
        assert f.status == UNKNOWN and f.evidence == ["discord.allowBots"]

    def test_a_nested_root_scope_true_beside_an_overriding_account_warns(self, tmp_path):
        """The account's own ``guilds`` replaces the root's (shallow spread), so the root's
        ``guilds.g1.allowBots`` is only run by the implicit default account."""
        cfg = _ch(discord={**self._BASE, "allowBots": False,
                           "guilds": {"g1": {"allowBots": True}},
                           "accounts": {"a": {"guilds": {"g2": {}}}}})
        f = _run(cfg, tmp_path, "2026.9.7")
        assert f.status == WARN and f.evidence == ["discord.guilds.g1.allowBots=true"]

    def test_no_token_means_no_implicit_account_and_root_true_is_vestigial(self, tmp_path):
        """Control: without a credential the root is not a running account, so a root true
        that every account overrides is not a finding (the existing doctrine)."""
        base = dict(_OPEN)
        cfg = _ch(discord={**base, "allowBots": True, "accounts": {"a": {"allowBots": False}}})
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS

    def test_slack_has_no_implicit_account_so_root_true_is_vestigial(self, tmp_path):
        cfg = _ch(slack={**_OPEN, "botToken": "t", "allowBots": True,
                         "accounts": {"a": {"allowBots": False}}})
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS

    def test_an_account_that_inherits_the_root_true_still_warns(self, tmp_path):
        cfg = _ch(slack={**_OPEN, "allowBots": True, "accounts": {"a": {}}})
        f = _run(cfg, tmp_path, "2026.9.7")
        assert f.status == WARN and f.evidence == ["slack.allowBots=true"]


# ----------------------------------------------------------------------------------------
# item 3: a configured account named `default` is THE default account
class TestAccountNamedDefault:
    _BASE = {"token": "t", **_OPEN}

    @pytest.mark.parametrize("version", [None, "2026.9.6", "2026.9.7"])
    def test_a_false_default_account_is_pass_on_every_build(self, tmp_path, version):
        cfg = _ch(discord={**self._BASE, "accounts": {"default": {"allowBots": False}}})
        assert _run(cfg, tmp_path, version).status == PASS

    def test_an_unset_default_account_still_warns_once(self, tmp_path):
        cfg = _ch(discord={**self._BASE, "accounts": {"default": {}}})
        f = _run(cfg, tmp_path, "2026.9.7")
        assert f.status == WARN
        assert f.evidence == [f"discord.{_UNSET_EVIDENCE}"]

    def test_an_unset_sibling_account_still_warns(self, tmp_path):
        cfg = _ch(discord={**self._BASE, "accounts": {
            "default": {"allowBots": False}, "second": {}}})
        f = _run(cfg, tmp_path, "2026.9.7")
        assert f.status == WARN and f.evidence == [f"discord.{_UNSET_EVIDENCE}"]

    def test_a_false_sibling_beside_a_false_default_is_pass(self, tmp_path):
        cfg = _ch(discord={**self._BASE, "accounts": {
            "default": {"allowBots": False}, "second": {"allowBots": False}}})
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS

    def test_a_true_default_account_beside_a_false_root_warns(self, tmp_path):
        cfg = _ch(discord={**self._BASE, "allowBots": False,
                           "accounts": {"default": {"allowBots": True}}})
        f = _run(cfg, tmp_path, "2026.9.7")
        assert f.status == WARN and f.evidence == ["discord.allowBots=true"]

    def test_a_root_true_is_overridden_by_a_false_default_account(self, tmp_path):
        """The merged ``default`` account is the only default account, and it says false."""
        cfg = _ch(discord={**self._BASE, "allowBots": True,
                           "accounts": {"default": {"allowBots": False}}})
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS

    @pytest.mark.parametrize("key", ["Default", " default", "DEFAULT"])
    def test_a_case_or_space_variant_is_not_assumed_to_dedupe(self, tmp_path, key):
        """Whether the vendor normalizes a configured id before the Set dedupe is a per-
        channel option that ships out of tree. PASS is the direction a wrong guess hurts, so
        only the exact id ``default`` (identical strings in a Set, certain) drops the implicit
        account; any variant keeps it and the unset key WARNs."""
        cfg = _ch(discord={**self._BASE, "accounts": {key: {"allowBots": False}}})
        assert _run(cfg, tmp_path, "2026.9.7").status == WARN

    def test_slack_default_account_is_unchanged(self, tmp_path):
        cfg = _ch(slack={**_OPEN, "accounts": {"default": {"allowBots": False}}})
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS
        cfg = _ch(slack={**_OPEN, "accounts": {"default": {}}})
        assert _run(cfg, tmp_path, "2026.9.7").status == WARN


# ----------------------------------------------------------------------------------------
# item 4: the DM-only residual is disclosed, not silenced
class TestDmOnlyResidual:
    @pytest.mark.parametrize("channel, node", [
        ("discord", {"token": "t", "dmPolicy": "pairing", "groupPolicy": "disabled"}),
        ("slack", {"botToken": "t", "dmPolicy": "pairing", "groupPolicy": "disabled"}),
    ])
    def test_a_dm_only_config_still_warns_on_an_unset_key(self, tmp_path, channel, node):
        f = _run(_ch(**{channel: dict(node)}), tmp_path, "2026.9.7")
        assert f.status == WARN
        assert f.detail == _DEFAULT_WARN_DETAIL

    def test_the_default_warn_fix_discloses_the_surface_limit(self, tmp_path):
        """Disclosure lives in ``fix``: ``detail`` is fingerprint-hashed."""
        f = _run(_ch(discord=dict(_DISCORD_GUILD)), tmp_path, "2026.9.7")
        assert "direct-message-only" in f.fix
        assert "false" in f.fix and "channels.discord.allowBots" in f.fix
        assert "direct-message-only" not in f.detail

    def test_an_explicit_warn_fix_is_unchanged(self, tmp_path):
        f = _run(_ch(discord={**_DISCORD_GUILD, "allowBots": True}), tmp_path, "2026.9.7")
        assert "direct-message-only" not in f.fix
        assert f.fix.startswith("Set allowBots to false for any group/room/channel")


# ----------------------------------------------------------------------------------------
# review round: a stanza that cannot be running is not reachable
class TestCredentialGate:
    @pytest.mark.parametrize("cfg", [
        {"discord": {}},
        {"discord": {"token": ""}},
        {"discord": {"token": "   "}},
        {"discord": {"enabled": True}},
        {"slack": {}},
        {"slack": {"botToken": ""}},
        {"slack": {"contextVisibility": "allowlist", "channels": {"C1": {}},
                   "accounts": {"main": {"contextVisibility": "allowlist"}}}},
        {"matrix": {"homeserver": "https://h", "rooms": {"r": {"allowBots": True}}}},
        {"googlechat": {"allowBots": True}},
        {"feishu": {"appId": "i", "allowBots": True}},     # Feishu needs appId AND appSecret
        {"telegram": {}},
    ])
    @pytest.mark.parametrize("version", [None, "2026.9.6", "2026.9.7"])
    def test_a_stanza_with_no_credential_reads_as_it_did_before(self, tmp_path, cfg, version):
        """Pre-C-655 verdict for every one of these was PASS: nothing is configured to run."""
        assert _run({"channels": cfg}, tmp_path, version).status == PASS

    @pytest.mark.parametrize("channel, node", [
        ("slack", {"botToken": "t"}),
        ("slack", {"appToken": "t"}),
        ("slack", {"userToken": "t"}),
        ("discord", {"token": "t"}),
    ])
    def test_each_credential_makes_the_stanza_a_running_account(self, tmp_path, channel, node):
        f = _run(_ch(**{channel: dict(node)}), tmp_path, "2026.9.7")
        assert f.status == WARN and f.evidence == [f"{channel}.{_UNSET_EVIDENCE}"]

    @pytest.mark.parametrize("channel, node", [
        ("matrix", {"accessToken": "t"}),
        ("matrix", {"password": "p"}),
        ("clickclack", {"token": "t"}),
        ("clickclack", {"tokenFile": "/x"}),
        ("googlechat", {"serviceAccountFile": "/x"}),
    ])
    def test_each_credential_of_an_explicit_only_channel_counts(self, tmp_path, channel, node):
        f = _run(_ch(**{channel: {**node, "allowBots": True}}), tmp_path, "2026.9.7")
        assert f.status == WARN and f.evidence == [f"{channel}.allowBots=true"]

    def test_a_credential_on_the_account_alone_is_enough(self, tmp_path):
        cfg = _ch(slack={"accounts": {"a": {"botToken": "t"}}})
        f = _run(cfg, tmp_path, "2026.9.7")
        assert f.status == WARN and f.evidence == [f"slack.{_UNSET_EVIDENCE}"]

    def test_a_written_open_policy_still_counts_without_a_credential(self, tmp_path):
        """The raw gate is consulted first: a stanza that WRITES an admitting policy is what
        it always was (an unset key there already WARNed)."""
        cfg = _ch(slack={"dmPolicy": "open", "allowFrom": ["*"]})
        assert _run(cfg, tmp_path, "2026.9.7").status == WARN


class TestOnlyTheSchemaChannelsGetTheDefaultsReading:
    @pytest.mark.parametrize("channel", ["telegram", "whatsapp", "signal", "irc", "mattermost",
                                         "msteams", "line", "imessage", "nostr", "somechannel"])
    @pytest.mark.parametrize("version", [None, "2026.9.6", "2026.9.7"])
    def test_an_allowbots_key_on_a_channel_without_one_in_its_schema_keeps_the_raw_gate(
            self, tmp_path, channel, version):
        """``allowBots`` is not a vendor setting there; the pre-C-655 verdict stands: PASS
        unless the stanza WRITES an admitting policy."""
        node = {"token": "t", "botToken": "t", "allowBots": True, "groups": {"1": {}}}
        assert _run(_ch(**{channel: node}), tmp_path, version).status == PASS

    def test_a_written_policy_on_such_a_channel_still_warns(self, tmp_path):
        node = {"botToken": "t", "dmPolicy": "open", "allowFrom": ["*"], "allowBots": True}
        f = _run(_ch(telegram=node), tmp_path, "2026.9.7")
        assert f.status == WARN and f.evidence == ["telegram.allowBots=true"]


class TestGroupScopeCounting:
    _DM_CLOSED = {"token": "t", "dmPolicy": "disabled"}

    _SLACK_DM_CLOSED = {"botToken": "t", "dmPolicy": "disabled"}

    def test_a_disabled_slack_channel_entry_is_not_a_scope(self, tmp_path):
        """Slack ``channels.*`` carries an ``enabled`` key in its schema."""
        cfg = _ch(slack={**self._SLACK_DM_CLOSED, "channels": {"C1": {"enabled": False}}})
        for version in (None, "2026.9.6", "2026.9.7"):
            assert _run(cfg, tmp_path, version).status == PASS, version

    def test_one_live_slack_entry_beside_a_disabled_one_is_a_scope(self, tmp_path):
        cfg = _ch(slack={**self._SLACK_DM_CLOSED,
                         "channels": {"C1": {"enabled": False}, "C2": {}}})
        assert _run(cfg, tmp_path, "2026.9.7").status == WARN

    @pytest.mark.parametrize("channel, node, container", [
        ("matrix", {"accessToken": "t", "dm": {"policy": "disabled"}}, "rooms"),
        ("matrix", {"accessToken": "t", "dm": {"policy": "disabled"}}, "groups"),
        ("googlechat", {"serviceAccount": "x", "dmPolicy": "disabled"}, "groups"),
        ("feishu", {"appId": "i", "appSecret": "s", "dmPolicy": "disabled"}, "groups"),
    ])
    def test_the_disabled_entry_skip_covers_the_shapes_whose_schema_has_enabled(
            self, tmp_path, channel, node, container):
        off = {**node, container: {"x": {"enabled": False, "allowBots": True}}}
        assert _run(_ch(**{channel: off}), tmp_path, "2026.9.7").status == PASS
        on = {**node, container: {"x": {"allowBots": True}}}
        assert _run(_ch(**{channel: on}), tmp_path, "2026.9.7").status == WARN

    def test_a_discord_guild_entry_always_counts_its_schema_has_no_enabled_key(self, tmp_path):
        """Discord ``guilds.*`` has no ``enabled`` key (only its nested channels do), so an
        ``enabled: false`` there is not a setting this audit may rely on to close the scope."""
        cfg = _ch(discord={**self._DM_CLOSED, "guilds": {"1": {"enabled": False}}})
        assert _run(cfg, tmp_path, "2026.9.7").status == WARN

    def test_a_clickclack_group_entry_always_counts(self, tmp_path):
        cfg = _ch(clickclack={"token": "t", "groups": {"g": {"enabled": False, "allowBots": True}}})
        assert _run(cfg, tmp_path, "2026.9.7").status == WARN

    def test_one_live_discord_guild_beside_a_disabled_one_is_a_scope(self, tmp_path):
        cfg = _ch(discord={**self._DM_CLOSED,
                           "guilds": {"1": {"enabled": False}, "2": {}}})
        assert _run(cfg, tmp_path, "2026.9.7").status == WARN

    @pytest.mark.parametrize("scope", [{}, [], None, "", {"1": None}])
    def test_an_empty_or_null_container_is_handled(self, tmp_path, scope):
        cfg = _ch(discord={**self._DM_CLOSED, "guilds": scope})
        f = _run(cfg, tmp_path, "2026.9.7")
        # an entry that is not an object cannot say "disabled", so it counts as a scope
        assert f.status == (WARN if scope == {"1": None} else PASS)

    def test_a_container_in_an_unmodelled_shape_counts_as_a_scope(self, tmp_path):
        """That a non-empty list lists nothing cannot be shown: never a PASS."""
        cfg = _ch(discord={**self._DM_CLOSED, "guilds": ["1"]})
        assert _run(cfg, tmp_path, "2026.9.7").status == WARN

    def test_a_dm_closed_config_with_only_a_direct_container_has_no_group_scope(self, tmp_path):
        cfg = _ch(discord={**self._DM_CLOSED, "direct": {"1": {}}})
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS


class TestUnrecognisedGroupPolicy:
    """What an unrecognised value does, stated once and pinned: it is not an admitting
    policy and reads as closed, as the raw gate read it -- PASS on every build with both
    surfaces closed (the pre-C-655 verdict), not UNKNOWN."""

    _DM_CLOSED = {"token": "t", "dmPolicy": "disabled"}

    @pytest.mark.parametrize("junk", [5, ["disabled"], {"v": 1}, ""])
    def test_a_drifted_defaults_value_with_no_scope_is_pass(self, tmp_path, junk):
        cfg = {"channels": {"defaults": {"groupPolicy": junk}, "discord": dict(self._DM_CLOSED)}}
        for version in (None, "2026.9.6", "2026.9.7"):
            assert _run(cfg, tmp_path, version).status == PASS, (junk, version)

    @pytest.mark.parametrize("junk", [5, ["disabled"], ""])
    def test_a_drifted_defaults_value_with_a_scope_falls_back_to_allowlist(self, tmp_path, junk):
        cfg = {"channels": {"defaults": {"groupPolicy": junk},
                            "discord": {**self._DM_CLOSED, "guilds": {"1": {}}}}}
        assert _run(cfg, tmp_path, "2026.9.7").status == WARN

    def test_a_written_unrecognised_string_reads_as_closed(self, tmp_path):
        cfg = _ch(discord={**self._DM_CLOSED, "groupPolicy": "weird", "guilds": {"1": {}}})
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS


class TestDisabledDefaultAccountKeepsTheImplicitNode:
    """That a disabled configured ``default`` also takes the credential-carrying root down is
    NOT confirmed (the Set dedupe is, the disabled-root consequence is not), so the implicit
    node is kept: the verdict is the pre-C-655 one."""

    _BASE = {"token": "t", **_OPEN}

    @pytest.mark.parametrize("default_entry", [{"enabled": False}, None, "x", []])
    def test_the_implicit_node_stays_beside_a_default_that_is_not_a_live_account(
            self, tmp_path, default_entry):
        cfg = _ch(discord={**self._BASE, "accounts": {
            "default": default_entry, "b": {"allowBots": False}}})
        f = _run(cfg, tmp_path, "2026.9.7")
        assert f.status == WARN and f.evidence == [f"discord.{_UNSET_EVIDENCE}"]

    def test_a_live_default_still_drops_it(self, tmp_path):
        cfg = _ch(discord={**self._BASE, "accounts": {
            "default": {"allowBots": False}, "b": {"allowBots": False}}})
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS


class TestDefaultAccountCountChange:
    def test_a_true_default_account_is_counted_once_now(self, tmp_path):
        """DELIBERATE ``detail`` change, a correct consequence of the account-named-default
        rule: the implicit node used to be counted beside ``accounts.default`` (two scopes,
        one of them a phantom unset one); it is one account, so one scope."""
        cfg = _ch(discord={"token": "t", **_OPEN, "accounts": {"default": {"allowBots": True}}})
        f = _run(cfg, tmp_path, "2026.9.7")
        assert f.status == WARN
        assert f.detail == _EXPLICIT_WARN_DETAIL          # "1 channel scope(s) ..."
        assert f.evidence == ["discord.allowBots=true"]


class TestClickClackReadsReachableByItsDocumentedDefault:
    """ClickClack's schema has no dmPolicy/groupPolicy key; its ``allowFrom`` documents a
    ``["*"]`` default (docs/channels/clickclack.md). The reachable reading rests on that
    documentation, not on a ``pairing`` default, and not on an executed resolver."""

    @pytest.mark.parametrize("version", [None, "2026.9.6", "2026.9.7"])
    def test_a_credentialed_clickclack_with_an_explicit_true_warns(self, tmp_path, version):
        f = _run(_ch(clickclack={"token": "t", "allowBots": True}), tmp_path, version)
        assert f.status == WARN and f.evidence == ["clickclack.allowBots=true"]

    def test_an_explicit_allowfrom_still_counts_as_external_input(self, tmp_path):
        cfg = _ch(clickclack={"token": "t", "allowFrom": ["u1"], "allowBots": True})
        assert _run(cfg, tmp_path, "2026.9.7").status == WARN

    def test_an_unset_key_on_clickclack_stays_pass(self, tmp_path):
        """No flipped default is stated for it (the sibling file pins the same)."""
        for version in (None, "2026.9.6", "2026.9.7"):
            assert _run(_ch(clickclack={"token": "t"}), tmp_path, version).status == PASS


# ----------------------------------------------------------------------------------------
# disclosure: a credential supplied through the environment is not visible to this check
_ENV_NOTE = (
    "A stanza with no credential in the config is treated as not running; a credential "
    "supplied through the environment is not visible to this check."
)


class TestEnvironmentCredentialDisclosure:
    @pytest.mark.parametrize("channel, node", [
        ("slack", {"allowBots": True, "channels": {"C1": {}}}),
        ("discord", {"allowBots": True, "guilds": {"1": {}}}),
        ("discord", {"guilds": {"1": {}}}),            # unset key, flipped build
        ("slack", {}),
        ("matrix", {"rooms": {"r": {"allowBots": True}}}),
        ("clickclack", {"allowBots": True}),
    ])
    def test_a_pass_that_rests_on_a_missing_credential_says_so_in_fix_only(
            self, tmp_path, channel, node):
        f = _run(_ch(**{channel: dict(node)}), tmp_path, "2026.9.7")
        assert f.status == PASS
        assert f.fix == "Nothing to do. " + _ENV_NOTE
        assert "environment" not in f.detail
        assert f.detail == ("No externally-reachable channel accepts bot-authored input "
                            "(allowBots).")

    def test_an_unset_key_on_a_denying_build_is_not_a_credential_pass(self, tmp_path):
        """On 2026.9.6 an unset key is accepted nowhere: the missing credential is not why this
        reads PASS, so the note stays out."""
        f = _run(_ch(slack={}), tmp_path, "2026.9.6")
        assert f.status == PASS and f.fix == "Nothing to do."

    def test_a_credentialed_stanza_that_passes_has_no_note(self, tmp_path):
        for node in ({"botToken": "t", "allowBots": False, "channels": {"C1": {}}},
                     {"botToken": "t", "dmPolicy": "disabled", "groupPolicy": "disabled"}):
            f = _run(_ch(slack=dict(node)), tmp_path, "2026.9.7")
            assert f.status == PASS and f.fix == "Nothing to do."

    @pytest.mark.parametrize("channel", ["telegram", "whatsapp", "signal", "somechannel"])
    def test_a_channel_outside_the_schema_set_has_no_note(self, tmp_path, channel):
        f = _run(_ch(**{channel: {"allowBots": True, "groups": {"1": {}}}}), tmp_path, "2026.9.7")
        assert f.status == PASS and f.fix == "Nothing to do."

    def test_a_disabled_channel_has_no_note(self, tmp_path):
        f = _run(_ch(slack={"enabled": False, "allowBots": True}), tmp_path, "2026.9.7")
        assert f.status == PASS and f.fix == "Nothing to do."

    def test_nothing_configured_has_no_note(self, tmp_path):
        f = _run({"channels": {}, "gateway": {"mode": "local"}}, tmp_path, "2026.9.7")
        assert f.status == PASS and f.fix == "Nothing to do."

    def test_the_other_outcomes_are_untouched(self, tmp_path):
        """A WARN keeps its fix; the note rides only on a PASS."""
        f = _run(_ch(slack={"botToken": "t", "allowBots": True}), tmp_path, "2026.9.7")
        assert f.status == WARN and "environment" not in f.fix
