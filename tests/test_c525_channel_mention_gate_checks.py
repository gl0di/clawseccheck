"""B371/B372 (CLAWSECCHECK-C-525) — per-provider requireMention/chatmode mention-gate
bypass and allowBots bot-authored-input admission.

Split out of C-411 (filed as C-525) because these three settings nest heterogeneously
per channel provider, not along one config path. Re-grounded from scratch against
openclaw@2026.9.3 by walking all 27 bundled channel plugin config JSON Schemas
programmatically (``dist/ids-*.mjs``'s ``RAW_BUNDLED_CHANNEL_CONFIG_METADATA`` —
an array of string chunks joined then ``JSON.parse``d), not by re-reading the prior
2026-09-11 grounding note in C-411's own docstring, which is INCOMPLETE against this
exhaustive source: it named requireMention nesting for mattermost/slack/googlechat/
msteams (top-level) and telegram/whatsapp/irc/imessage/signal (``.groups.*``,
telegram also ``.groups.*.topics.*``) and discord (``.guilds.*``/``.guilds.*.
channels.*``), but missed Matrix's ``.rooms.*``, Slack's OWN ``.channels.*``
container (distinct from Discord's nested one), Feishu/GoogleChat's ``.groups.*``,
and Telegram's ``.direct.*.topics.*`` — all confirmed present in the real schema
registry. See ``_mention_gate_scopes`` (``checks/_shared.py``) for the container
vocabulary this reuses and the full grounding trail.

No FAIL branch in this family (WARN/UNKNOWN tier, matching C-411's siblings) — no
C-135 gate required (CLAUDE.md §4, scoped to new FAIL-capable checks).
"""
from __future__ import annotations

from clawseccheck.catalog import BY_ID, MEDIUM, PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    CHECKS,
    check_channel_allow_bots,
    check_channel_mention_gate_bypass,
)
from clawseccheck.collector import Context

# A channel admitting non-owner senders via an open dmPolicy — the coarse
# reachability gate both checks share with B39/B361/B362.
_OPEN = {"dmPolicy": "open", "allowFrom": ["*"]}


def _ctx(cfg, tmp_path, *, found=True):
    return Context(home=tmp_path, config=cfg, config_found=found)


def _merged(*dicts):
    out = {}
    for d in dicts:
        out.update(d)
    return out


# =========================================================================== B371
class TestChannelMentionGateBypass:
    def test_top_level_require_mention_false_warns(self, tmp_path):
        cfg = {"channels": {"mattermost": _merged(_OPEN, {"requireMention": False})}}
        f = check_channel_mention_gate_bypass(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert "mattermost.requireMention=false" in f.detail or any(
            "mattermost.requireMention=false" in e for e in (f.evidence or [])
        )

    def test_mattermost_chatmode_onmessage_warns(self, tmp_path):
        cfg = {"channels": {"mattermost": _merged(_OPEN, {"chatmode": "onmessage"})}}
        f = check_channel_mention_gate_bypass(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert "chatmode" in f.detail

    def test_mattermost_chatmode_oncall_is_pass(self, tmp_path):
        cfg = {"channels": {"mattermost": _merged(_OPEN, {"chatmode": "oncall"})}}
        f = check_channel_mention_gate_bypass(_ctx(cfg, tmp_path))
        assert f.status == PASS

    def test_groups_wildcard_require_mention_false_warns(self, tmp_path):
        """feishu/googlechat/telegram/whatsapp/irc/imessage/signal all share this
        canonical groups.* shape."""
        cfg = {
            "channels": {
                "feishu": _merged(_OPEN, {"groups": {"g1": {"requireMention": False}}})
            }
        }
        f = check_channel_mention_gate_bypass(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert "feishu.groups.g1.requireMention=false" in (f.evidence or [])

    def test_telegram_groups_topics_third_level_warns(self, tmp_path):
        cfg = {
            "channels": {
                "telegram": _merged(
                    _OPEN,
                    {
                        "groups": {
                            "g1": {"topics": {"t1": {"requireMention": False}}}
                        }
                    },
                )
            }
        }
        f = check_channel_mention_gate_bypass(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert "telegram.groups.g1.topics.t1.requireMention=false" in (f.evidence or [])

    def test_discord_guild_channel_nested_bypass_warns(self, tmp_path):
        cfg = {
            "channels": {
                "discord": _merged(
                    _OPEN,
                    {
                        "guilds": {
                            "gid": {"channels": {"cid": {"requireMention": False}}}
                        }
                    },
                )
            }
        }
        f = check_channel_mention_gate_bypass(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert "discord.guilds.gid.channels.cid.requireMention=false" in (f.evidence or [])

    def test_discord_guild_level_bypass_warns(self, tmp_path):
        cfg = {
            "channels": {
                "discord": _merged(_OPEN, {"guilds": {"gid": {"requireMention": False}}})
            }
        }
        f = check_channel_mention_gate_bypass(_ctx(cfg, tmp_path))
        assert f.status == WARN

    def test_matrix_room_bypass_warns(self, tmp_path):
        cfg = {
            "channels": {
                "matrix": _merged(_OPEN, {"rooms": {"r1": {"requireMention": False}}})
            }
        }
        f = check_channel_mention_gate_bypass(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert "matrix.rooms.r1.requireMention=false" in (f.evidence or [])

    def test_slack_direct_channels_container_bypass_warns(self, tmp_path):
        """Slack's ``channels`` sits directly under the provider — distinct from
        Discord's nested guilds.*.channels.*."""
        cfg = {
            "channels": {
                "slack": _merged(_OPEN, {"channels": {"C1": {"requireMention": False}}})
            }
        }
        f = check_channel_mention_gate_bypass(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert "slack.channels.C1.requireMention=false" in (f.evidence or [])

    def test_account_level_override_bypass_warns(self, tmp_path):
        cfg = {
            "channels": {
                "telegram": _merged(
                    _OPEN,
                    {"accounts": {"acct1": {"groups": {"*": {"requireMention": False}}}}},
                )
            }
        }
        f = check_channel_mention_gate_bypass(_ctx(cfg, tmp_path))
        assert f.status == WARN

    def test_unreachable_channel_with_bypass_is_pass(self, tmp_path):
        cfg = {
            "channels": {
                "telegram": {
                    "dmPolicy": "owner-only",
                    "groupPolicy": "disabled",
                    "groups": {"*": {"requireMention": False}},
                }
            }
        }
        f = check_channel_mention_gate_bypass(_ctx(cfg, tmp_path))
        assert f.status == PASS

    def test_clean_config_is_pass(self, tmp_path):
        cfg = {
            "channels": {
                "telegram": _merged(_OPEN, {"groups": {"*": {"requireMention": True}}})
            }
        }
        f = check_channel_mention_gate_bypass(_ctx(cfg, tmp_path))
        assert f.status == PASS

    def test_no_channels_is_pass(self, tmp_path):
        f = check_channel_mention_gate_bypass(_ctx({"channels": {}}, tmp_path))
        assert f.status == PASS

    def test_stray_chatmode_inside_group_is_ignored(self, tmp_path):
        """chatmode is only ever meaningful at the channel-root/account scope for
        any of the 27 bundled schemas; a stray nested one is inert, not a bypass."""
        cfg = {
            "channels": {
                "mattermost": _merged(
                    _OPEN,
                    {
                        "requireMention": True,
                        "groups": {"g1": {"chatmode": "onmessage", "requireMention": True}},
                    },
                )
            }
        }
        f = check_channel_mention_gate_bypass(_ctx(cfg, tmp_path))
        assert f.status == PASS

    def test_channels_not_a_dict_is_unknown(self, tmp_path):
        f = check_channel_mention_gate_bypass(_ctx({"channels": "nope"}, tmp_path))
        assert f.status == UNKNOWN

    def test_malformed_channel_node_degrades_to_skip_not_unknown(self, tmp_path):
        """A single provider entry drifted to a non-dict degrades to 'no signal
        from this provider', matching _external_input_channels' own precedent —
        it does not poison the whole check."""
        cfg = {"channels": {"slack": "oops"}}
        f = check_channel_mention_gate_bypass(_ctx(cfg, tmp_path))
        assert f.status == PASS

    def test_drifted_require_mention_value_is_unknown(self, tmp_path):
        cfg = {
            "channels": {
                "telegram": _merged(_OPEN, {"groups": {"*": {"requireMention": "yes"}}})
            }
        }
        f = check_channel_mention_gate_bypass(_ctx(cfg, tmp_path))
        assert f.status == UNKNOWN

    def test_drifted_chatmode_value_is_unknown(self, tmp_path):
        cfg = {"channels": {"mattermost": _merged(_OPEN, {"chatmode": "sometimes"})}}
        f = check_channel_mention_gate_bypass(_ctx(cfg, tmp_path))
        assert f.status == UNKNOWN

    def test_bypass_takes_priority_over_drift_elsewhere(self, tmp_path):
        cfg = {
            "channels": {
                "mattermost": _merged(_OPEN, {"chatmode": "onmessage"}),
                "feishu": _merged(_OPEN, {"requireMention": "yes"}),
            }
        }
        f = check_channel_mention_gate_bypass(_ctx(cfg, tmp_path))
        assert f.status == WARN

    def test_unread_config_is_unknown(self, tmp_path):
        f = check_channel_mention_gate_bypass(_ctx({}, tmp_path, found=False))
        assert f.status == UNKNOWN

    def test_registered_and_catalog_consistent(self, tmp_path):
        assert check_channel_mention_gate_bypass in CHECKS
        meta = BY_ID["B371"]
        assert meta.severity == MEDIUM and meta.surface == "channels"
        emitted = check_channel_mention_gate_bypass(_ctx({"channels": {}}, tmp_path))
        assert emitted.id == "B371" and emitted.title == meta.title


# =========================================================================== B372
class TestChannelAllowBots:
    def test_top_level_allow_bots_true_warns(self, tmp_path):
        cfg = {"channels": {"googlechat": _merged(_OPEN, {"allowBots": True})}}
        f = check_channel_allow_bots(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert "googlechat.allowBots=true" in (f.evidence or [])

    def test_top_level_allow_bots_false_is_pass(self, tmp_path):
        cfg = {"channels": {"googlechat": _merged(_OPEN, {"allowBots": False})}}
        f = check_channel_allow_bots(_ctx(cfg, tmp_path))
        assert f.status == PASS

    def test_feishu_allow_bots_true_warns(self, tmp_path):
        cfg = {"channels": {"feishu": _merged(_OPEN, {"allowBots": True})}}
        f = check_channel_allow_bots(_ctx(cfg, tmp_path))
        assert f.status == WARN

    def test_slack_direct_channels_container_allow_bots_warns(self, tmp_path):
        cfg = {
            "channels": {
                "slack": _merged(_OPEN, {"channels": {"C1": {"allowBots": True}}})
            }
        }
        f = check_channel_allow_bots(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert "slack.channels.C1.allowBots=true" in (f.evidence or [])

    def test_matrix_room_allow_bots_mentions_warns(self, tmp_path):
        """Matrix's boolean|"mentions" union has no channel-root form at all —
        only inside groups/rooms."""
        cfg = {
            "channels": {
                "matrix": _merged(_OPEN, {"rooms": {"r1": {"allowBots": "mentions"}}})
            }
        }
        f = check_channel_allow_bots(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert 'matrix.rooms.r1.allowBots="mentions"' in (f.evidence or [])

    def test_matrix_group_allow_bots_false_is_pass(self, tmp_path):
        cfg = {
            "channels": {
                "matrix": _merged(_OPEN, {"groups": {"g1": {"allowBots": False}}})
            }
        }
        f = check_channel_allow_bots(_ctx(cfg, tmp_path))
        assert f.status == PASS

    def test_account_level_override_allow_bots_warns(self, tmp_path):
        cfg = {
            "channels": {
                "feishu": _merged(_OPEN, {"accounts": {"a1": {"allowBots": True}}})
            }
        }
        f = check_channel_allow_bots(_ctx(cfg, tmp_path))
        assert f.status == WARN

    def test_unreachable_channel_with_allow_bots_is_pass(self, tmp_path):
        cfg = {
            "channels": {
                "googlechat": {
                    "dmPolicy": "owner-only",
                    "groupPolicy": "disabled",
                    "allowBots": True,
                }
            }
        }
        f = check_channel_allow_bots(_ctx(cfg, tmp_path))
        assert f.status == PASS

    def test_provider_with_no_allow_bots_field_at_all_is_pass(self, tmp_path):
        """whatsapp never declares allowBots anywhere — must never false-positive."""
        cfg = {
            "channels": {
                "whatsapp": _merged(_OPEN, {"groups": {"g1": {"requireMention": True}}})
            }
        }
        f = check_channel_allow_bots(_ctx(cfg, tmp_path))
        assert f.status == PASS

    def test_no_channels_is_pass(self, tmp_path):
        f = check_channel_allow_bots(_ctx({"channels": {}}, tmp_path))
        assert f.status == PASS

    def test_channels_not_a_dict_is_unknown(self, tmp_path):
        f = check_channel_allow_bots(_ctx({"channels": "nope"}, tmp_path))
        assert f.status == UNKNOWN

    def test_drifted_allow_bots_value_is_unknown(self, tmp_path):
        cfg = {"channels": {"googlechat": _merged(_OPEN, {"allowBots": "sometimes"})}}
        f = check_channel_allow_bots(_ctx(cfg, tmp_path))
        assert f.status == UNKNOWN

    def test_unread_config_is_unknown(self, tmp_path):
        f = check_channel_allow_bots(_ctx({}, tmp_path, found=False))
        assert f.status == UNKNOWN

    def test_registered_and_catalog_consistent(self, tmp_path):
        assert check_channel_allow_bots in CHECKS
        meta = BY_ID["B372"]
        assert meta.severity == MEDIUM and meta.surface == "channels"
        emitted = check_channel_allow_bots(_ctx({"channels": {}}, tmp_path))
        assert emitted.id == "B372" and emitted.title == meta.title
