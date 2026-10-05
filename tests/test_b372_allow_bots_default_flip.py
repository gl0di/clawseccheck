"""B372 (re-grounded) -- the default of channels.discord.allowBots and channels.slack.allowBots
flipped from DENY to ACCEPT in OpenClaw 2026.9.7, with the config path, the
`boolean | "mentions"` type and the schema enum unchanged.

    2026.9.6  hint table  Discord / Slack allowBots  "(default: false)"
    2026.9.7  hint table  Discord / Slack allowBots  "(default: true)"
              CHANGELOG   "Discord and Slack: accept bot-authored messages by default when
                           `allowBots` is omitted ... (explicit `false` and "mentions" are
                           unchanged)"

Before this fix B372 PASSed an unset key on a reachable Discord/Slack channel on every build.
The resolver itself ships out-of-tree (`@openclaw/discord`, `@openclaw/slack`), so this is
grounded on the vendor hint and changelog rather than an executed resolver -- the tests below
pin the three-valued build answer (``deny`` / ``allow`` / ``unknown``), the verdict matrix it
drives, and the things that must NOT move: the explicit-value WARN and drifted-value UNKNOWN
text (``baseline.fingerprint()`` hashes ``detail``, so changing it orphans users'
``.clawseccheckignore`` entries), and the channels whose default did not flip.

Offline and read-only: no dist is read, the build is injected through
``Context.installed_dist_version`` or ``meta.lastTouchedVersion``.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

import clawseccheck
from clawseccheck.baseline import fingerprint
from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    _ALLOW_BOTS_DEFAULT_ALLOW_MIN,
    _ALLOW_BOTS_DENY_MEASURED_MIN,
    _ALLOW_BOTS_FLIPPED_CHANNELS,
    _allow_bots_default,
    check_channel_allow_bots,
)
from clawseccheck.collector import Context

# A channel admitting non-owner senders via an open dmPolicy -- the coarse reachability gate
# B372 shares with B39/B361/B362/B371.
_OPEN = {"dmPolicy": "open", "allowFrom": ["*"]}
_CLOSED = {"dmPolicy": "owner-only", "groupPolicy": "disabled"}

_UNSET_EVIDENCE = "allowBots (unset, defaults to true on 2026.9.7+)"

# The exact text a real user's .clawseccheckignore fingerprint was computed from before this
# change. Frozen here on purpose: see the module docstring.
_EXPLICIT_WARN_DETAIL = (
    "1 channel scope(s) admit non-owner senders with allowBots enabled \u2014 messages "
    "authored by other bot accounts reach the agent as input, at whatever rate the bot "
    "account can generate them."
)
_EXPLICIT_WARN_FIX = (
    "Set allowBots to false for any group/room/channel that admits non-owner senders, "
    "unless accepting bot-authored input is a deliberate integration."
)
_DRIFT_DETAIL = (
    "1 channel scope(s) set allowBots to a value this audit does not recognize, so whether "
    "bot-authored input is accepted there could not be determined."
)

# The NEW detail texts this change introduces. ``baseline.fingerprint()`` hashes ``detail``, so
# a user's ``.clawseccheckignore`` entry for one of these keys on the exact bytes below; the
# tests in TestFrozenWording pin them so a later rewording is a deliberate act (and moves the
# fingerprint manifest row in the same change). Disclosure prose belongs in ``fix`` instead.
_UNKNOWN_DETAIL = (
    "1 Discord/Slack channel scope(s) leave allowBots unset and the OpenClaw build could not "
    "be determined, so whether bot-authored input is accepted there could not be "
    "established: the OpenClaw releases read (2026.7.1-2 through 2026.9.6) ignore "
    "bot-authored messages when it is unset, 2026.9.7 and later accept them."
)
_DEFAULT_WARN_DETAIL = (
    _EXPLICIT_WARN_DETAIL
    + " On OpenClaw 2026.9.7 and later, Discord and Slack accept bot-authored messages when "
    "allowBots is unset, so an unset allowBots counts as enabled there."
)
_MANIFEST = Path(__file__).parent / "finding_fingerprint_manifest.txt"


def _ch(**channels):
    return {"channels": channels}


def _ctx(cfg, tmp_path, version=None):
    return Context(home=tmp_path, config=cfg, config_found=True,
                   installed_dist_version=version)


def _stamped(version, cfg=None):
    out = dict(cfg or {})
    out["meta"] = {"lastTouchedVersion": version}
    return out


def _run(cfg, tmp_path, version=None):
    return check_channel_allow_bots(_ctx(cfg, tmp_path, version))


# ----------------------------------------------------------------------------------------
# the build answer
class TestAllowBotsDefault:
    @pytest.mark.parametrize("installed, expected", [
        ("2026.9.6", "deny"),
        ("2026.9.6-1", "deny"),       # a correction suffix sorts BELOW the next release
        ("2026.9.5", "deny"),
        ("2026.9.3", "deny"),
        ("2026.8.1", "deny"),
        ("2026.7.1-2", "deny"),       # the oldest release whose hint was read
        ("2026.7.1", "unknown"),      # ... the plain 7.1 was not, and sorts below it
        ("2026.6.34", "unknown"),     # older than the measured series: never extrapolated
        ("2026.5.1", "unknown"),
        ("2025.12.3", "unknown"),
        ("0.0.0", "unknown"),         # not a calendar release: no confident safe verdict
        ("2026.9", "unknown"),        # ... nor is a two-part string
        ("2026.9.7", "allow"),
        ("2026.9.7-1", "allow"),      # a suffix on the threshold itself sorts at/above it
        ("2026.9.8", "allow"),
        ("2026.10.1", "allow"),       # calendar-numeric, not lexicographic
        ("2027.1.1", "allow"),
        ("2026.9.7-beta.1", "unknown"),   # a pre-release is unorderable, never assumed
        ("not a version", "unknown"),
        ("", "unknown"),
    ])
    def test_installed_version_decides_outright(self, tmp_path, installed, expected):
        assert _allow_bots_default(_ctx({}, tmp_path, installed)) == expected

    def test_an_installed_version_beats_a_contradicting_stamp(self, tmp_path):
        """The installed build's channel plugin is the one that resolves the key; the stamp
        only says which build last SAVED the config."""
        ctx = _ctx(_stamped("2026.9.7"), tmp_path, "2026.9.6")
        assert _allow_bots_default(ctx) == "deny"
        ctx = _ctx(_stamped("2026.9.6"), tmp_path, "2026.9.7")
        assert _allow_bots_default(ctx) == "allow"

    def test_a_stamp_at_or_after_the_flip_proves_allow(self, tmp_path):
        assert _allow_bots_default(_ctx(_stamped("2026.9.7"), tmp_path)) == "allow"
        assert _allow_bots_default(_ctx(_stamped("2026.10.2"), tmp_path)) == "allow"

    @pytest.mark.parametrize("stamp", ["2026.9.6", "2026.9.3", "2026.7.1-2", "", None])
    def test_a_stale_stamp_never_proves_deny(self, tmp_path, stamp):
        """The user may have upgraded five minutes ago without re-saving: a stamp BELOW the
        threshold proves nothing about what is installed now."""
        cfg = {} if stamp is None else _stamped(stamp)
        assert _allow_bots_default(_ctx(cfg, tmp_path)) == "unknown"

    def test_a_prerelease_stamp_is_unknown(self, tmp_path):
        assert _allow_bots_default(_ctx(_stamped("2026.9.7-beta.1"), tmp_path)) == "unknown"

    def test_no_version_at_all_is_unknown(self, tmp_path):
        assert _allow_bots_default(_ctx({}, tmp_path)) == "unknown"

    def test_the_thresholds_are_the_measured_releases(self):
        assert _ALLOW_BOTS_DEFAULT_ALLOW_MIN == (2026, 9, 7)
        assert _ALLOW_BOTS_DENY_MEASURED_MIN == (2026, 7, 1, 2)

    def test_only_the_two_channels_whose_hint_flipped_are_covered(self):
        assert set(_ALLOW_BOTS_FLIPPED_CHANNELS) == {"discord", "slack"}

    def test_an_unplaceable_installed_version_never_yields_a_pass(self, tmp_path):
        """'deny' is the answer that PASSes, so a version string we cannot place on the
        measured timeline must not reach it."""
        cfg = _ch(discord=dict(_OPEN))
        for version in ("0.0.0", "2026.9", "2026.6.8", "1.0.0"):
            assert _run(cfg, tmp_path, version).status == UNKNOWN, version


# ----------------------------------------------------------------------------------------
# the verdict matrix
@pytest.mark.parametrize("channel", ["discord", "slack"])
class TestUnsetKey:
    def test_unset_on_a_denying_build_is_pass(self, tmp_path, channel):
        """The bad-to-clean twin: 2026.9.6 ignores bot-authored input when unset."""
        f = _run(_ch(**{channel: dict(_OPEN)}), tmp_path, "2026.9.6")
        assert f.status == PASS

    def test_unset_on_the_flipped_build_warns(self, tmp_path, channel):
        """THE regression this task exists for: this used to PASS with "no channel accepts
        bot input" while the 9.7 runtime accepted it by default."""
        f = _run(_ch(**{channel: dict(_OPEN)}), tmp_path, "2026.9.7")
        assert f.status == WARN
        assert f.evidence == [f"{channel}.{_UNSET_EVIDENCE}"]
        assert "unset" in f.detail and "2026.9.7" in f.detail
        # the fix names the key, the value to set and WHY (the default moved)
        assert "false" in f.fix and "ACCEPT" in f.fix and f"channels.{channel}.allowBots" in f.fix
        assert "channels.*.allowBots" in f.config_field_paths

    def test_unset_on_a_correction_release_of_the_flipped_build_warns(self, tmp_path, channel):
        assert _run(_ch(**{channel: dict(_OPEN)}), tmp_path, "2026.9.7-1").status == WARN

    def test_unset_on_the_prior_line_correction_release_still_passes(self, tmp_path, channel):
        assert _run(_ch(**{channel: dict(_OPEN)}), tmp_path, "2026.9.6-1").status == PASS

    def test_unset_and_the_build_unknown_is_unknown_not_a_hedged_pass(self, tmp_path, channel):
        """The UNKNOWN path, explicit: an undeterminable build is never a PASS."""
        f = _run(_ch(**{channel: dict(_OPEN)}), tmp_path)
        assert f.status == UNKNOWN
        assert "could not be determined" in f.detail
        assert "2026.9.6" in f.detail and "2026.9.7" in f.detail
        assert f.evidence == [f"{channel}.allowBots (unset)"]
        # the fix must not name a default it cannot establish as fact
        assert "explicitly" in f.fix
        assert "channels.*.allowBots" in f.config_field_paths

    def test_a_prerelease_of_the_flipped_build_is_unknown(self, tmp_path, channel):
        f = _run(_ch(**{channel: dict(_OPEN)}), tmp_path, "2026.9.7-beta.1")
        assert f.status == UNKNOWN

    def test_a_stamp_from_the_flipped_build_warns_without_an_install(self, tmp_path, channel):
        cfg = _stamped("2026.9.7", _ch(**{channel: dict(_OPEN)}))
        assert _run(cfg, tmp_path).status == WARN

    def test_a_stale_stamp_and_no_install_is_unknown(self, tmp_path, channel):
        cfg = _stamped("2026.9.6", _ch(**{channel: dict(_OPEN)}))
        assert _run(cfg, tmp_path).status == UNKNOWN

    @pytest.mark.parametrize("version", [None, "2026.9.6", "2026.9.7", "2026.9.7-beta.1"])
    def test_explicit_false_is_pass_on_every_build(self, tmp_path, channel, version):
        f = _run(_ch(**{channel: {**_OPEN, "allowBots": False}}), tmp_path, version)
        assert f.status == PASS

    @pytest.mark.parametrize("version", [None, "2026.9.6", "2026.9.7"])
    def test_explicit_true_warns_on_every_build_with_the_original_text(
            self, tmp_path, channel, version):
        f = _run(_ch(**{channel: {**_OPEN, "allowBots": True}}), tmp_path, version)
        assert f.status == WARN
        assert f.evidence == [f"{channel}.allowBots=true"]
        assert f.detail == _EXPLICIT_WARN_DETAIL
        assert f.fix == _EXPLICIT_WARN_FIX

    @pytest.mark.parametrize("version", [None, "2026.9.6", "2026.9.7"])
    def test_explicit_mentions_warns_on_every_build(self, tmp_path, channel, version):
        f = _run(_ch(**{channel: {**_OPEN, "allowBots": "mentions"}}), tmp_path, version)
        assert f.status == WARN
        assert f.evidence == [f'{channel}.allowBots="mentions"']
        assert f.detail == _EXPLICIT_WARN_DETAIL

    @pytest.mark.parametrize("version", [None, "2026.9.6", "2026.9.7"])
    def test_a_drifted_value_is_unknown_with_the_original_text(self, tmp_path, channel, version):
        f = _run(_ch(**{channel: {**_OPEN, "allowBots": "sometimes"}}), tmp_path, version)
        assert f.status == UNKNOWN
        assert f.detail == _DRIFT_DETAIL
        assert f.evidence == [f"{channel}.allowBots"]

    @pytest.mark.parametrize("version", [None, "2026.9.6", "2026.9.7"])
    def test_an_unreachable_channel_is_pass_whatever_the_default(self, tmp_path, channel, version):
        assert _run(_ch(**{channel: dict(_CLOSED)}), tmp_path, version).status == PASS

    def test_a_disabled_channel_is_pass_whatever_the_default(self, tmp_path, channel):
        cfg = _ch(**{channel: {**_OPEN, "enabled": False}})
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS

    def test_an_allowlist_gated_channel_is_still_evaluated(self, tmp_path, channel):
        """Same reachability gate as B371/B39: allowlist counts as external input, and an
        explicit true there already WARNs -- the default must agree with it."""
        gated = {"dmPolicy": "allowlist", "groupPolicy": "allowlist"}
        assert _run(_ch(**{channel: {**gated, "allowBots": True}}), tmp_path,
                    "2026.9.7").status == WARN
        assert _run(_ch(**{channel: dict(gated)}), tmp_path, "2026.9.7").status == WARN
        assert _run(_ch(**{channel: dict(gated)}), tmp_path, "2026.9.6").status == PASS


class TestInheritanceAndScopes:
    def test_account_inherits_an_explicit_false_from_the_channel_root(self, tmp_path):
        cfg = _ch(discord={**_OPEN, "allowBots": False, "accounts": {"a1": {}}})
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS

    def test_an_account_that_sets_nothing_inherits_the_unset_default(self, tmp_path):
        cfg = _ch(discord={**_OPEN, "accounts": {"a1": {}}})
        f = _run(cfg, tmp_path, "2026.9.7")
        assert f.status == WARN
        assert f.evidence == [f"discord.{_UNSET_EVIDENCE}"]

    def test_one_unset_account_beside_an_explicit_false_account_warns(self, tmp_path):
        cfg = _ch(slack={**_OPEN, "accounts": {"a1": {"allowBots": False}, "a2": {}}})
        f = _run(cfg, tmp_path, "2026.9.7")
        assert f.status == WARN
        assert f.evidence == [f"slack.{_UNSET_EVIDENCE}"]

    def test_every_account_explicit_false_is_pass(self, tmp_path):
        cfg = _ch(slack={**_OPEN, "accounts": {
            "a1": {"allowBots": False}, "a2": {"allowBots": False}}})
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS

    def test_an_account_can_opt_in_over_a_false_root(self, tmp_path):
        cfg = _ch(discord={**_OPEN, "allowBots": False, "accounts": {"a1": {"allowBots": True}}})
        f = _run(cfg, tmp_path, "2026.9.7")
        assert f.status == WARN
        assert f.evidence == ["discord.allowBots=true"]

    def test_unset_accounts_collapse_to_one_evidence_row(self, tmp_path):
        cfg = _ch(discord={**_OPEN, "accounts": {"a1": {}, "a2": {}}})
        f = _run(cfg, tmp_path, "2026.9.7")
        assert f.evidence == [f"discord.{_UNSET_EVIDENCE}"]

    def test_nested_scopes_are_not_evaluated_for_an_unset_key(self, tmp_path):
        """The guild/channel hints state no default of their own: an unset nested scope must
        never add a finding beyond the channel root's."""
        cfg = _ch(discord={**_OPEN, "allowBots": False,
                           "guilds": {"g1": {"channels": {"c1": {}}}}})
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS
        cfg = _ch(slack={**_OPEN, "allowBots": False, "channels": {"C1": {}}})
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS

    def test_an_explicit_nested_true_still_warns_under_a_false_root(self, tmp_path):
        cfg = _ch(slack={**_OPEN, "allowBots": False, "channels": {"C1": {"allowBots": True}}})
        f = _run(cfg, tmp_path, "2026.9.7")
        assert f.status == WARN
        assert f.evidence == ["slack.channels.C1.allowBots=true"]

    def test_a_nested_false_does_not_rescue_an_unset_root(self, tmp_path):
        """Other guilds still inherit the root's default."""
        cfg = _ch(discord={**_OPEN, "guilds": {"g1": {"allowBots": False}}})
        f = _run(cfg, tmp_path, "2026.9.7")
        assert f.status == WARN
        assert f.evidence == [f"discord.{_UNSET_EVIDENCE}"]

    def test_discord_and_slack_both_unset_are_counted_together(self, tmp_path):
        cfg = _ch(discord=dict(_OPEN), slack=dict(_OPEN))
        f = _run(cfg, tmp_path, "2026.9.7")
        assert f.status == WARN
        assert f.evidence == [f"discord.{_UNSET_EVIDENCE}", f"slack.{_UNSET_EVIDENCE}"]
        assert f.detail.startswith("2 channel scope(s)")


class TestPerAccountReachability:
    """An UNSET key is judged on each account's OWN reachability. The channel-wide gate
    (any node open) is right for "is this channel reachable at all" but too coarse for
    "does THIS account inherit a default that admits bots": a closed account beside an
    open one must not add a finding of its own."""

    def _pair(self, channel, open_extra, closed_extra):
        return _ch(**{channel: {"accounts": {
            "open": {**_OPEN, **open_extra},
            "closed": {**_CLOSED, **closed_extra},
        }}})

    @pytest.mark.parametrize("channel", ["discord", "slack"])
    def test_a_closed_unset_account_beside_an_open_false_one_is_pass(self, tmp_path, channel):
        cfg = self._pair(channel, {"allowBots": False}, {})
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS

    @pytest.mark.parametrize("channel", ["discord", "slack"])
    def test_a_closed_unset_account_does_not_make_the_build_unknown(self, tmp_path, channel):
        cfg = self._pair(channel, {"allowBots": False}, {})
        assert _run(cfg, tmp_path).status == PASS

    @pytest.mark.parametrize("channel", ["discord", "slack"])
    def test_a_disabled_unset_account_beside_an_open_false_one_is_pass(self, tmp_path, channel):
        cfg = _ch(**{channel: {"accounts": {
            "live": {**_OPEN, "allowBots": False},
            "retired": {**_OPEN, "enabled": False},
        }}})
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS

    @pytest.mark.parametrize("channel", ["discord", "slack"])
    def test_the_open_unset_account_is_still_found_beside_a_closed_one(self, tmp_path, channel):
        cfg = self._pair(channel, {}, {"allowBots": False})
        f = _run(cfg, tmp_path, "2026.9.7")
        assert f.status == WARN
        assert f.evidence == [f"{channel}.{_UNSET_EVIDENCE}"]

    @pytest.mark.parametrize("channel", ["discord", "slack"])
    def test_an_account_that_closes_its_inherited_policy_is_not_reachable(self, tmp_path, channel):
        """The account overrides the root's open dmPolicy AND groupPolicy: nothing reaches
        it, so its inherited-unset key is not a finding."""
        cfg = _ch(**{channel: {**_OPEN, "groupPolicy": "open", "accounts": {
            "quiet": {"dmPolicy": "owner-only", "groupPolicy": "disabled"}}}})
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS

    def test_an_explicit_true_on_a_closed_account_is_unchanged(self, tmp_path):
        """The explicit-value path keeps its channel-wide gate: this task did not narrow it."""
        cfg = self._pair("discord", {"allowBots": False}, {"allowBots": True})
        f = _run(cfg, tmp_path, "2026.9.7")
        assert f.status == WARN and f.evidence == ["discord.allowBots=true"]


class TestImplicitDefaultAccount:
    """A Discord base node that carries a token is a live implicit default account beside
    any configured ``accounts`` (``_channel_has_implicit_default_account``), and its own
    unset allowBots is what that account inherits. Slack registers no such account."""

    def test_discord_token_root_with_only_false_accounts_warns(self, tmp_path):
        cfg = _ch(discord={**_OPEN, "token": "x" * 4, "accounts": {
            "a1": {"allowBots": False}}})
        f = _run(cfg, tmp_path, "2026.9.7")
        assert f.status == WARN
        assert f.evidence == [f"discord.{_UNSET_EVIDENCE}"]

    def test_discord_token_root_with_only_false_accounts_is_pass_on_the_prior_build(
            self, tmp_path):
        cfg = _ch(discord={**_OPEN, "token": "x" * 4, "accounts": {
            "a1": {"allowBots": False}}})
        assert _run(cfg, tmp_path, "2026.9.6").status == PASS

    def test_discord_token_root_with_only_false_accounts_is_unknown_without_a_build(
            self, tmp_path):
        cfg = _ch(discord={**_OPEN, "token": "x" * 4, "accounts": {
            "a1": {"allowBots": False}}})
        assert _run(cfg, tmp_path).status == UNKNOWN

    def test_discord_root_without_a_token_has_no_implicit_account(self, tmp_path):
        cfg = _ch(discord={**_OPEN, "accounts": {"a1": {"allowBots": False}}})
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS

    def test_discord_token_root_that_sets_false_is_pass(self, tmp_path):
        cfg = _ch(discord={**_OPEN, "token": "x" * 4, "allowBots": False, "accounts": {
            "a1": {}}})
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS

    def test_a_closed_implicit_default_account_is_not_reachable(self, tmp_path):
        """Root closed, one account open with allowBots false: the implicit default account
        carries the closed root policy, so nothing reaches it."""
        cfg = _ch(discord={**_CLOSED, "token": "x" * 4, "accounts": {
            "a1": {**_OPEN, "allowBots": False}}})
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS

    def test_slack_registers_no_implicit_default_account(self, tmp_path):
        cfg = _ch(slack={**_OPEN, "botToken": "x" * 4, "accounts": {
            "a1": {"allowBots": False}}})
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS


class TestChannelsWhoseDefaultDidNotFlip:
    @pytest.mark.parametrize("channel", ["matrix", "googlechat", "feishu", "clickclack",
                                         "whatsapp", "telegram", "mattermost"])
    @pytest.mark.parametrize("version", [None, "2026.9.6", "2026.9.7"])
    def test_an_unset_key_stays_pass_on_every_build(self, tmp_path, channel, version):
        """Matrix's hint still reads "(default: false)"; the others state no flipped
        default. None of them may inherit the Discord/Slack reading, and none may go
        UNKNOWN merely because the build is unknown."""
        f = _run(_ch(**{channel: dict(_OPEN)}), tmp_path, version)
        assert f.status == PASS

    def test_explicit_values_on_those_channels_are_unchanged(self, tmp_path):
        f = _run(_ch(googlechat={**_OPEN, "allowBots": True}), tmp_path, "2026.9.7")
        assert f.status == WARN and f.evidence == ["googlechat.allowBots=true"]
        f = _run(_ch(matrix={**_OPEN, "rooms": {"r1": {"allowBots": "mentions"}}}),
                 tmp_path, "2026.9.7")
        assert f.status == WARN and f.evidence == ['matrix.rooms.r1.allowBots="mentions"']


class TestPrecedence:
    def test_an_explicit_warn_outranks_an_undeterminable_default(self, tmp_path):
        cfg = _ch(googlechat={**_OPEN, "allowBots": True}, discord=dict(_OPEN))
        f = _run(cfg, tmp_path)
        assert f.status == WARN
        assert f.evidence == ["googlechat.allowBots=true"]
        assert f.detail == _EXPLICIT_WARN_DETAIL
        assert f.fix == _EXPLICIT_WARN_FIX

    def test_a_default_hit_beside_an_explicit_one_counts_both(self, tmp_path):
        cfg = _ch(googlechat={**_OPEN, "allowBots": True}, slack=dict(_OPEN))
        f = _run(cfg, tmp_path, "2026.9.7")
        assert f.status == WARN
        assert f.detail.startswith("2 channel scope(s)")
        assert f.evidence == ["googlechat.allowBots=true", f"slack.{_UNSET_EVIDENCE}"]

    def test_a_drifted_value_and_an_undeterminable_default_report_both(self, tmp_path):
        cfg = _ch(googlechat={**_OPEN, "allowBots": "sometimes"}, discord=dict(_OPEN))
        f = _run(cfg, tmp_path)
        assert f.status == UNKNOWN
        assert _DRIFT_DETAIL in f.detail
        assert "leave allowBots unset" in f.detail
        assert f.evidence == ["googlechat.allowBots", "discord.allowBots (unset)"]

    def test_an_undeterminable_default_beside_a_clean_channel_is_unknown(self, tmp_path):
        cfg = _ch(matrix=dict(_OPEN), slack=dict(_OPEN))
        assert _run(cfg, tmp_path).status == UNKNOWN

    def test_a_default_deny_build_with_nothing_else_is_pass(self, tmp_path):
        cfg = _ch(matrix=dict(_OPEN), slack=dict(_OPEN), discord=dict(_OPEN))
        assert _run(cfg, tmp_path, "2026.9.6").status == PASS


# ----------------------------------------------------------------------------------------
# C-135 review round: the wording of the NEW texts is exact, and the manifest row follows it
class TestFrozenWording:
    def test_the_unknown_detail_is_frozen(self, tmp_path):
        f = _run(_ch(discord=dict(_OPEN)), tmp_path)
        assert f.status == UNKNOWN
        assert f.detail == _UNKNOWN_DETAIL

    def test_the_default_warn_detail_is_frozen(self, tmp_path):
        f = _run(_ch(discord=dict(_OPEN)), tmp_path, "2026.9.7")
        assert f.status == WARN
        assert f.detail == _DEFAULT_WARN_DETAIL

    def test_the_unknown_detail_does_not_claim_the_plain_7_1_was_read(self, tmp_path):
        """Only 2026.7.1-2 was read; the plain 2026.7.1 sorts below it and was not. The
        detail is fingerprint-hashed, so this is settled before the manifest row is."""
        f = _run(_ch(discord=dict(_OPEN)), tmp_path)
        assert "2026.7.1-2 through 2026.9.6" in f.detail
        assert "(2026.7.1 through" not in f.detail

    def test_the_bad_c014_manifest_row_carries_the_current_unknown_fingerprint(self, tmp_path):
        """The reproduction of the blocking finding: the committed manifest row for
        bad_c014_egress_inventory must hold exactly the fingerprint of the UNKNOWN detail
        this check emits (that fixture is a single unset open Discord scope, no build)."""
        expected = fingerprint(_run(_ch(discord=dict(_OPEN)), tmp_path))
        rows = [ln for ln in _MANIFEST.read_text(encoding="utf-8").splitlines()
                if ln.startswith("bad_c014_egress_inventory\t")]
        assert len(rows) == 1
        entries = rows[0].split("\t", 1)[1].split(",")
        b372 = [e for e in entries if e.startswith("B372:")]
        assert b372 == [f"B372:UNKNOWN:{expected.split(':')[1]}"]

    def test_the_unknown_fix_does_not_overclaim_input_is_kept_out(self, tmp_path):
        """allowBots gates TURNS, not context: the vendor docs keep bot-authored history
        visible when it is false, so 'keeps bot-authored input out' was untrue."""
        f = _run(_ch(discord=dict(_OPEN)), tmp_path)
        assert "keeps bot-authored input out" not in f.fix
        assert "stops bot-authored messages from triggering turns" in f.fix

    def test_a_discord_only_warn_fix_does_not_name_slack(self, tmp_path):
        f = _run(_ch(discord=dict(_OPEN)), tmp_path, "2026.9.7")
        assert "channels.discord.allowBots" in f.fix
        assert "channels.slack" not in f.fix

    def test_a_slack_only_warn_fix_does_not_name_discord(self, tmp_path):
        f = _run(_ch(slack=dict(_OPEN)), tmp_path, "2026.9.7")
        assert "channels.slack.allowBots" in f.fix
        assert "channels.discord" not in f.fix

    def test_a_both_channel_warn_fix_names_both(self, tmp_path):
        f = _run(_ch(discord=dict(_OPEN), slack=dict(_OPEN)), tmp_path, "2026.9.7")
        assert "channels.discord.allowBots and channels.slack.allowBots" in f.fix

    def test_an_explicit_true_beside_an_unset_discord_names_only_discord(self, tmp_path):
        """slack is an explicit ``true`` here (not left unset), so the default-flip advice
        must not tell the user to create a channels.slack key for it."""
        cfg = _ch(discord=dict(_OPEN), slack={**_OPEN, "allowBots": True})
        f = _run(cfg, tmp_path, "2026.9.7")
        assert f.status == WARN
        assert "set channels.discord.allowBots to false" in f.fix
        assert "set channels.slack" not in f.fix


# ----------------------------------------------------------------------------------------
# the wiring, not the helper
class TestWiring:
    def _home(self, tmp_path, cfg_text):
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(cfg_text)
        os.chmod(cfg, 0o600)
        return tmp_path

    _CFG = (
        '{"channels": {"discord": {"dmPolicy": "open", "allowFrom": ["*"]},'
        ' "slack": {"dmPolicy": "open", "allowFrom": ["*"], "allowBots": false}}}'
    )

    def _b372(self, home, monkeypatch, version):
        monkeypatch.setattr(clawseccheck, "_installed_dist_version", lambda *a, **k: version)
        _ctx_, findings, _score = clawseccheck.audit(home, include_dist=True)
        return next(f for f in findings if f.id == "B372")

    def test_audit_warns_on_the_flipped_build_from_the_installed_version(
            self, tmp_path, monkeypatch):
        home = self._home(tmp_path, self._CFG)
        f = self._b372(home, monkeypatch, "2026.9.7")
        assert f.status == WARN
        assert f.evidence == [f"discord.{_UNSET_EVIDENCE}"]   # slack is explicit false

    def test_audit_passes_on_the_prior_build(self, tmp_path, monkeypatch):
        home = self._home(tmp_path, self._CFG)
        assert self._b372(home, monkeypatch, "2026.9.6").status == PASS

    def test_audit_is_unknown_when_the_build_cannot_be_found(self, tmp_path, monkeypatch):
        home = self._home(tmp_path, self._CFG)
        assert self._b372(home, monkeypatch, None).status == UNKNOWN

    def test_audit_reads_the_config_stamp_when_no_install_is_found(self, tmp_path, monkeypatch):
        cfg = self._CFG[:-1] + ', "meta": {"lastTouchedVersion": "2026.9.7"}}'
        home = self._home(tmp_path, cfg)
        assert self._b372(home, monkeypatch, None).status == WARN


# ----------------------------------------------------------------------------------------
# a control that can fail: the assertions above depend on the resolver, not on the shape
class TestTheControlCanFail:
    def test_a_resolver_that_always_says_deny_would_be_caught(self, tmp_path, monkeypatch):
        """Reverting to the pre-fix behaviour (an unset key is never enabled) must flip the
        headline assertions -- otherwise they would pass on the broken code too."""
        import clawseccheck.checks._agents as agents

        cfg = _ch(discord=dict(_OPEN))
        assert _run(cfg, tmp_path, "2026.9.7").status == WARN
        monkeypatch.setattr(agents, "_allow_bots_default", lambda _ctx: "deny")
        assert _run(cfg, tmp_path, "2026.9.7").status == PASS
        assert _run(cfg, tmp_path).status == PASS     # UNKNOWN collapsed into PASS
