"""B-567 — RISK-01's why-text must not name a config field the firing config lacks.

The wildcard-group shape (`channels.<p>.groups {"*": ...}`, B-297) declares NEITHER
`dmPolicy` NOR `groupPolicy`. RISK-01 fires on that shape through
`_open_channel_labels` -> `_open_wildcard_group_channels`, but its why-text used to
hard-code "accepts messages from anyone (dmPolicy or groupPolicy is 'open')"
unconditionally -- a sentence a user could grep their own config for, find neither
key, and wrongly dismiss a correct CRITICAL as spurious.

These tests assert the why-text is grounded in the SAME predicate that gated the
rule, for both shapes that can fire it:
  1. the wildcard-group shape (no policy keys at all) -> reason names the wildcard
     shape, never the policy-value sentence
  2. the dmPolicy/groupPolicy='open' shape (the ORIGINAL case, still fires the same
     way) -> reason keeps the honest policy-value sentence, unregressed

ROUND 2 (C-135 caught this): the round-1 fix recovered the channel name by parsing it
back out of the rendered label (`label.split(" (", 1)[0]`). A channel key containing
the label's own `" ("` delimiter collides, the membership test misses, and control
falls through to the `else` branch -- restoring the EXACT round-1 bug. `channelId` is
a plain `ZodString` in the installed dist with no charset constraint found
(dist/bundled-channel-config-schema-BYKT0d_t.d.ts:987), and plugin-registered channels
are a real schema-supported shape (dist/channel-entry-contract-TASNXkep.js), so the
collision cannot be ruled out from the schema alone. Fixed by carrying the raw channel
name alongside the label (`_open_channel_entries`) instead of parsing presentation
text -- `test_risk01_wildcard_reason_survives_a_colliding_channel_name` below proves
the collision no longer reintroduces the bug.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.collector import Context
from clawseccheck.checks import run_all
from clawseccheck.risk import risk_paths


def _r01(cfg: dict):
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = cfg
    findings = run_all(ctx)
    paths = risk_paths(ctx, findings)
    return next((p for p in paths if p.id == "RISK-01"), None)


def test_risk01_wildcard_group_why_does_not_claim_absent_policy_field():
    # B-567's exact repro shape: no dmPolicy/groupPolicy anywhere in the config.
    cfg = {
        "channels": {
            "telegram": {"enabled": True, "groups": {"*": {"requireMention": True}}},
        },
        "tools": {"exec": {"security": "full"}},
        "agents": {"defaults": {"sandbox": {"mode": "off"}}},
    }
    tg = cfg["channels"]["telegram"]
    assert "dmPolicy" not in tg and "groupPolicy" not in tg  # confirms the repro shape

    r01 = _r01(cfg)
    assert r01 is not None, "RISK-01 must still fire on the wildcard-group shape (B-297)"
    assert "dmPolicy" not in r01.why and "groupPolicy" not in r01.why, (
        f"why-text names a field the config does not declare: {r01.why!r}"
    )
    assert "wildcard" in r01.why and "allowFrom" in r01.why


def test_risk01_wildcard_reason_survives_a_colliding_channel_name():
    # Adversarial channel key containing the label delimiter itself -- the round-1
    # split-based recovery would truncate this to "telegram" and miss the wildcard
    # membership test, falling through to the old, false policy-value sentence.
    cfg = {
        "channels": {
            "telegram (evil": {
                "enabled": True,
                "groups": {"*": {"requireMention": True}},
            },
        },
        "tools": {"exec": {"security": "full"}},
        "agents": {"defaults": {"sandbox": {"mode": "off"}}},
    }
    r01 = _r01(cfg)
    assert r01 is not None
    assert "dmPolicy" not in r01.why and "groupPolicy" not in r01.why, (
        f"colliding channel name restored the round-1 bug: {r01.why!r}"
    )
    assert "wildcard" in r01.why and "allowFrom" in r01.why


def test_risk01_policy_value_why_unregressed():
    # The original, still-real trigger: dmPolicy/groupPolicy actually set to 'open'.
    # Round 3: the why-text now names each field+value that actually fired (rather
    # than a single fused "dmPolicy or groupPolicy is 'open'" sentence), so this
    # config -- which declares BOTH -- names both explicitly.
    cfg = {
        "channels": {"telegram": {"groupPolicy": "open", "dmPolicy": "open"}},
        "tools": {"exec": {"security": "full"}},
        "agents": {"defaults": {"sandbox": {"mode": "off"}}},
    }
    r01 = _r01(cfg)
    assert r01 is not None
    assert "dmPolicy is 'open'" in r01.why
    assert "groupPolicy is 'open'" in r01.why


def test_risk01_dm_only_why_names_only_dm_policy():
    # Only dmPolicy is 'open' -- the why-text must not also claim groupPolicy.
    cfg = {
        "channels": {"telegram": {"dmPolicy": "open"}},
        "tools": {"exec": {"security": "full"}},
        "agents": {"defaults": {"sandbox": {"mode": "off"}}},
    }
    r01 = _r01(cfg)
    assert r01 is not None
    assert "dmPolicy is 'open'" in r01.why
    assert "groupPolicy is 'open'" not in r01.why


def test_risk01_feishu_allowall_why_names_allowall_not_literal_open():
    # C-135 round 3 residual: Feishu's groupPolicy 'allowall' alias is schema-legal
    # and reaches this rule, but is not literally 'open' -- the why-text must name
    # the value the config actually declares.
    cfg = {
        "channels": {"feishu": {"groupPolicy": "allowall"}},
        "tools": {"exec": {"security": "full"}},
        "agents": {"defaults": {"sandbox": {"mode": "off"}}},
    }
    r01 = _r01(cfg)
    assert r01 is not None
    assert "allowall" in r01.why
    assert "groupPolicy is 'open'" not in r01.why, (
        f"why-text claims a literal 'open' value the config does not declare: {r01.why!r}"
    )
