"""B-619 — a DM ingress closure written through a NESTED path (or ``dm.enabled: false``)
was read identically to a channel that declared nothing at all: A1 told an owner who
explicitly closed DM ingress that they set no policy, CRITICAL-capping the grade, and
recommended a flat `dmPolicy` key several of the affected channels' own schema rejects.

Grounded against the installed dist (openclaw@2026.7.1-2). Exactly 4 channels define a
nested `dm` config object anywhere in the dist (grep-verified exhaustively, not assumed —
see ``_DM_POLICY_NESTED_ONLY_CHANNELS``'s comment in ``_shared.py`` for the file:line
citations): discord, slack, googlechat, matrix. googlechat and matrix are NESTED-ONLY —
their schema has no flat `dmPolicy` field at all, and their real per-account resolver
(channel2.runtime-Bb6oxd87.js:213 for googlechat; channel-DVVz3Nzd.js:774-778 for matrix)
never falls back to it. discord and slack are FLAT-PRIMARY (flat wins over nested when
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
    assert _DM_POLICY_NESTED_ONLY_CHANNELS == frozenset({"googlechat", "matrix"})
    assert _DM_POLICY_FLAT_PRIMARY_CHANNELS == frozenset({"discord", "slack"})
    assert _DM_POLICY_ENABLED_GATE_CHANNELS == frozenset({"googlechat", "discord"})
    # Every enabled-gate channel is also one that reads a dmPolicy value at all.
    assert _DM_POLICY_ENABLED_GATE_CHANNELS <= (
        _DM_POLICY_NESTED_ONLY_CHANNELS | _DM_POLICY_FLAT_PRIMARY_CHANNELS
    )


# --------------------------------------------------------------- _declared_dm_policy


def test_googlechat_reads_nested_only():
    assert _declared_dm_policy("googlechat", {"dm": {"policy": "disabled"}}) == "disabled"
    # The flat key is UNRECOGNIZED by googlechat's own schema and never read by its real
    # runtime gate — recognising it here would be the same fabricated-fact shape B-609's
    # Feishu correction already retracted once.
    assert _declared_dm_policy("googlechat", {"dmPolicy": "disabled"}) is None


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


def test_closed_googlechat_nested_is_not_an_untrusted_leg():
    cfg = {"channels": {"googlechat": {"enabled": True, "dm": {"policy": "disabled"}}}}
    assert _untrusted_input_channels(cfg) == []


def test_open_googlechat_nested_still_counts_the_leg():
    cfg = {"channels": {"googlechat": {"enabled": True, "dm": {"policy": "open"}}}}
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
    """The remaining genuine-absence case on a nested-only channel must recommend the
    NESTED key, never the flat one its schema rejects."""
    cfg = {
        "channels": {"googlechat": {"enabled": True}},
        "tools": {"allow": ["read_file", "web_fetch"]},
    }
    f = check_trifecta(_ctx(tmp_path, cfg))
    assert f.status == WARN, f.status
    assert "Resolved default" in f.detail
    assert 'dm.policy: "disabled"' in f.fix
    assert 'Set `dmPolicy: "disabled"` on googlechat' not in f.fix


def test_mixed_flat_and_nested_only_channels_get_separate_remediation(tmp_path):
    cfg = {
        "channels": {
            "telegram": {"enabled": True},
            "googlechat": {"enabled": True},
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
