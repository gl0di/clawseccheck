"""B-609 — an unmodeled dmPolicy LITERAL is not the same as an absent one, and A1 read
them identically (both silent PASS).

Grounded against the installed dist (openclaw@2026.7.1-2), reading the RUNTIME
normalizer functions, not just the zod validation schema (loading is warn-and-continue —
validateConfigObjectRaw returns {ok:false, issues} rather than throwing, and the snapshot
path still returns runtimeConfig: coerceConfig(effectiveConfigRaw) on !validated.ok, so an
unmodeled literal reaches the runtime). Exactly two channels have a dist-confirmed
per-channel dmPolicy normalizer that falls back to "pairing" for any literal outside its
own recognized set: Feishu (normalizeFeishuDmPolicy, policy-hydoYQvK.js:52-54) and
iMessage (normalizeDmPolicy, monitor-i23HdnNo.js:1216-1218).

CORRECTION to the original filing's sharper example: `dmPolicy: "disabled"` on Feishu is
NOT the substitution case. normalizeFeishuDmPolicy explicitly whitelists "disabled" even
though Feishu's own DmPolicySchema (channel-PR3XHV0V.js:84-88) does not define it as a
schema member — the runtime normalizer and the validation schema disagree with each
other, and senderGateForDirect's `if (dmPolicy === "disabled") return
block("dm_policy_disabled")` (message-access-DucCKzfO.js:146) honors it and blocks all
DMs. So a user who writes "disabled" for Feishu gets what they asked for. The real
substitution trigger is a literal OUTSIDE {open,pairing,allowlist,disabled} entirely —
e.g. a typo, or "owner" (a value from a different, unrelated part of this project's own
vocabulary — see test_b499's own retraction of that exact literal as remediation advice).

Every other channel (the shared "core" schema family — telegram/discord/slack/signal/
msteams/whatsapp/googlechat/irc — and LINE) is deliberately left alone: checked, not
assumed. The generic ingress resolver they all go through
(resolveResolverPolicy, message-access-DucCKzfO.js:1028-1035) only substitutes "pairing"
via `??` when dmPolicy is ABSENT; a DEFINED-but-invalid string passes straight through
raw, and senderGateForDirect's fallthrough for it (line 164) is the allowlist branch, not
the pairing branch — not proven more permissive, so claiming it would be a fabricated
fact. Synology Chat's authorizeUserForDmWithIngress (channel-Dxc6BJwP.js:445) confirms the
same raw-passthrough shape on a channel outside the "core" family too, so this is the
DEFAULT for any channel without its own bespoke normalizer, not a Feishu/iMessage quirk.

WARN, not UNKNOWN, for the two grounded channels: the resolved value is a knowable fact
(the dist names it exactly), and it is more permissive than a silent PASS implies — a
config that PASSes here reads as "no untrusted input", not "we don't know". UNKNOWN would
be the honest answer for every other channel's unmodeled literal, but this project has
not grounded a runtime claim strong enough to WARN there, and inventing one to fill the
gap would be the opposite of B-499's own "do not invent a value" doctrine — so those
channels are silently excluded, same doctrine ``_norm_group_policy`` already applies to
every channel outside its own scope. No FAIL, ever: nothing is compromised by a typo, the
posture is merely not the one written (mirrors B-499's own WARN-not-FAIL call).

Same WARN-grade-signal-not-a-leg doctrine as B-499's own resolved-default WARN: `active`
and `evidence` are untouched, so the leg count a reader sees does not move.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from clawseccheck.catalog import UNKNOWN, WARN
from clawseccheck.checks import check_trifecta
from clawseccheck.checks._shared import _norm_dm_policy, _substituted_dm_policy_channels
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(tmp_path: Path, cfg, *, raw: bool = False):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    p = home / "openclaw.json"
    p.write_text(cfg if raw else json.dumps(cfg), encoding="utf-8")
    p.chmod(0o600)
    ctx = collect(home=str(home))
    if not raw:
        assert ctx.config, "collect() did not read the fixture config"
    return ctx


# --------------------------------------------------------------------------- the helpers


def test_norm_dm_policy_feishu_unmodeled_literal_becomes_pairing():
    assert _norm_dm_policy("feishu", "owner") == "pairing"


def test_norm_dm_policy_feishu_disabled_is_honored_not_substituted():
    """The corrected grounding, pinned: "disabled" is a Feishu normalizer passthrough,
    not a fallback trigger — schema-invalid but runtime-honored."""
    assert _norm_dm_policy("feishu", "disabled") == "disabled"


def test_norm_dm_policy_feishu_known_members_pass_through():
    for known in ("open", "pairing", "allowlist", "disabled"):
        assert _norm_dm_policy("feishu", known) == known


def test_norm_dm_policy_imessage_unmodeled_literal_becomes_pairing():
    assert _norm_dm_policy("imessage", "owner") == "pairing"


def test_norm_dm_policy_imessage_known_members_pass_through():
    for known in ("open", "allowlist", "disabled"):
        assert _norm_dm_policy("imessage", known) == known


def test_norm_dm_policy_core_channel_is_never_transformed():
    """The negative control this whole fix hinges on: no grounded fallback exists for
    the shared "core" schema family, so an unmodeled literal must pass through unchanged
    — never silently mapped to "pairing" the way Feishu/iMessage are."""
    for channel in ("telegram", "discord", "slack", "signal", "msteams", "irc"):
        assert _norm_dm_policy(channel, "banned") == "banned"


def test_norm_dm_policy_line_is_never_transformed():
    """LINE has its own local DmPolicySchema (open/allowlist/pairing/disabled) but no
    dist-confirmed bespoke normalizer — grounded absence, not an oversight."""
    assert _norm_dm_policy("line", "banned") == "banned"


def test_norm_dm_policy_non_string_never_raises():
    for drift in (["a"], {"x": 1}, 7, None):
        assert _norm_dm_policy("feishu", drift) == drift


# ------------------------------------------------------- _substituted_dm_policy_channels


def test_feishu_unmodeled_literal_is_reported():
    cfg = {"channels": {"feishu": {"enabled": True, "dmPolicy": "owner"}}}
    assert _substituted_dm_policy_channels(cfg) == {"feishu": ("owner", "pairing")}


def test_feishu_disabled_is_not_reported():
    """The corrected sharper case: not a substitution, so not a WARN trigger."""
    cfg = {"channels": {"feishu": {"enabled": True, "dmPolicy": "disabled"}}}
    assert _substituted_dm_policy_channels(cfg) == {}


def test_core_channel_unmodeled_literal_is_not_falsely_claimed():
    """The honesty guard: without a grounded runtime fallback, this must never invent
    one. Reporting telegram here would be exactly the fabricated-fact failure mode
    Golden Rule #4 exists to catch."""
    cfg = {"channels": {"telegram": {"enabled": True, "dmPolicy": "banned"}}}
    assert _substituted_dm_policy_channels(cfg) == {}


def test_line_unmodeled_literal_is_not_falsely_claimed():
    cfg = {"channels": {"line": {"enabled": True, "dmPolicy": "banned"}}}
    assert _substituted_dm_policy_channels(cfg) == {}


def test_a_disabled_channel_ingests_nothing():
    cfg = {"channels": {"feishu": {"enabled": False, "dmPolicy": "owner"}}}
    assert _substituted_dm_policy_channels(cfg) == {}


def test_a_channel_already_counted_as_untrusted_is_not_reported_twice():
    cfg = {"channels": {"feishu": {"enabled": True, "dmPolicy": "open"}}}
    assert _substituted_dm_policy_channels(cfg) == {}


def test_an_account_inherits_the_channels_written_policy():
    cfg = {
        "channels": {
            "feishu": {"enabled": True, "dmPolicy": "owner", "accounts": {"a": {}}},
        }
    }
    assert _substituted_dm_policy_channels(cfg) == {"feishu": ("owner", "pairing")}


def test_schema_drifted_accounts_do_not_raise():
    for drift in ("not-a-dict", ["a"], 7, None):
        cfg = {"channels": {"feishu": {"enabled": True, "dmPolicy": "owner", "accounts": drift}}}
        assert _substituted_dm_policy_channels(cfg) == {"feishu": ("owner", "pairing")}


def test_a_non_dict_channel_does_not_raise():
    cfg = {"channels": {"feishu": "not-a-dict"}}
    assert _substituted_dm_policy_channels(cfg) == {}


def test_a_non_string_dmpolicy_is_not_reported():
    for drift in (["a"], {"x": 1}, 7):
        cfg = {"channels": {"feishu": {"enabled": True, "dmPolicy": drift}}}
        assert _substituted_dm_policy_channels(cfg) == {}


# --------------------------------------------------------------------------- A1 end to end


def test_a1_warns_and_names_literal_and_resolved_value(tmp_path):
    cfg = {
        "channels": {"feishu": {"enabled": True, "dmPolicy": "owner", "appId": "x", "appSecret": "y"}},
        "tools": {"elevated": {"allowFrom": ["*"]}},
    }
    f = check_trifecta(_ctx(tmp_path, cfg))
    assert f.status == WARN, f.status
    assert "'feishu'" in f.detail
    assert "dmPolicy='owner'" in f.detail
    assert '"pairing"' in f.detail
    assert "Not counted as a leg" in f.detail


def test_a1_disabled_on_feishu_still_passes(tmp_path):
    """The reproduction the original filing got backwards, pinned so it cannot regress
    silently: "disabled" is honored, not substituted, so this must stay PASS."""
    from clawseccheck.catalog import PASS

    cfg = {
        "channels": {
            "feishu": {"enabled": True, "dmPolicy": "disabled", "appId": "x", "appSecret": "y"}
        },
        "tools": {"elevated": {"allowFrom": ["*"]}},
    }
    f = check_trifecta(_ctx(tmp_path, cfg))
    assert f.status == PASS, f.status
    assert "Unmodeled dmPolicy" not in f.detail


def test_a1_core_channel_unmodeled_literal_stays_pass(tmp_path):
    """The negative control at the check level: telegram has no grounded fallback, so
    A1 must not invent a WARN for it."""
    from clawseccheck.catalog import PASS

    cfg = {
        "channels": {"telegram": {"enabled": True, "dmPolicy": "banned"}},
        "tools": {"elevated": {"allowFrom": ["*"]}},
    }
    f = check_trifecta(_ctx(tmp_path, cfg))
    assert f.status == PASS, f.status
    assert "Unmodeled dmPolicy" not in f.detail


def test_the_leg_count_never_moves(tmp_path):
    written = check_trifecta(
        _ctx(tmp_path, {"channels": {"telegram": {"enabled": True, "dmPolicy": "banned"}},
                        "tools": {"elevated": {"allowFrom": ["*"]}}})
    )
    tmp2 = tmp_path / "two"
    tmp2.mkdir()
    substituted = check_trifecta(
        _ctx(tmp2, {"channels": {"feishu": {"enabled": True, "dmPolicy": "owner",
                                             "appId": "x", "appSecret": "y"}},
                    "tools": {"elevated": {"allowFrom": ["*"]}}})
    )
    assert sorted(written.evidence or []) == sorted(substituted.evidence or [])


def test_a_real_fail_is_not_downgraded():
    """The WARN branch sits after the >=3-leg FAIL return — a disclosure must never
    soften a genuine 3/3 verdict."""
    from clawseccheck.catalog import FAIL

    f = check_trifecta(collect(home=str(FIXTURES / "home_vuln")))
    assert f.status == FAIL, f.status


def test_an_unreadable_config_stays_unknown(tmp_path):
    """B-306's guard runs first, same as B-499's own equivalent test. An unmodeled
    dmPolicy literal inside a config the audit could not parse must not acquire a
    confidently-worded WARN from this change."""
    ctx = _ctx(
        tmp_path,
        '{"channels": {"feishu": {"enabled": true, "dmPolicy": "owner"',  # truncated
        raw=True,
    )
    assert ctx.config_parse_error, "the truncated config was not detected as unparseable"
    f = check_trifecta(ctx)
    assert f.status == UNKNOWN, f.status
    assert "Unmodeled dmPolicy" not in f.detail


def test_the_warn_branch_is_inert_when_the_helper_is_empty(tmp_path):
    """Guard against a silent no-op: with the helper forced empty (simulating the
    pre-fix code path exactly, since it is the only new call site), the same config
    must fall back to the pre-existing PASS. Found this shape of guard necessary once
    already, in B-499's own equivalent (`test_the_warn_branch_is_what_moves_the_verdict`) —
    the branch it protects here is new enough that nothing else pins its removal."""
    cfg = {
        "channels": {"feishu": {"enabled": True, "dmPolicy": "owner", "appId": "x", "appSecret": "y"}},
        "tools": {"elevated": {"allowFrom": ["*"]}},
    }
    ctx = _ctx(tmp_path, cfg)
    with patch("clawseccheck.checks._config._substituted_dm_policy_channels", return_value={}):
        f = check_trifecta(ctx)
    from clawseccheck.catalog import PASS

    assert f.status == PASS, f.status
    assert "Unmodeled dmPolicy" not in f.detail
