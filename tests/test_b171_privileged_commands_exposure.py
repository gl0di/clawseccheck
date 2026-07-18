"""B171 (B-235): root-level commands.* in-chat privileged-command surface.

OpenClaw's root `commands` key (`CommandsSchema`, dist `zod-schema-O9ml_nmo.js:615`)
exposes raw shell (`bash`), full config read/write (`config`), MCP-server-registry
rewrite (`mcp`), and plugin-enablement toggling (`plugins`) as IN-CHAT commands, gated
only by their own `commands.ownerAllowFrom` / `commands.allowFrom` / `commands.
useAccessGroups`. Before this check ClawSecCheck had zero references to commands.bash/
config/mcp/plugins outside `commands.ownerAllowFrom` (B48/B-231) -- a config with all four
enabled plus an open channel scored identically to the closed-channel baseline (the
2026-07-17 coverage-map differential test this task reproduces).

Grounded against the dist runtime (`command-auth-De19E7rf.js`, `resolveOwnerAuthorization
State` / `resolveCommandAuthorization`, spot-read 2026-07-18) -- see
docs/research/openclaw-schema-recon.md §18 for the full field table and gate semantics.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import CRITICAL, FAIL, HIGH, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_privileged_commands_exposure
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


# ---------------------------------------------------------------------------
# PASS: nothing privileged enabled (including the fully-empty / absent config)
# ---------------------------------------------------------------------------

def test_no_commands_block_passes():
    r = check_privileged_commands_exposure(_ctx({}))
    assert r.status == PASS


def test_empty_commands_block_passes():
    r = check_privileged_commands_exposure(_ctx({"commands": {}}))
    assert r.status == PASS


def test_bash_explicitly_false_passes():
    r = check_privileged_commands_exposure(_ctx({"commands": {"bash": False}}))
    assert r.status == PASS


def test_restart_default_true_alone_never_flagged():
    # commands.restart `.default(true)` in the dist schema -- must NOT be treated as an
    # opt-in danger signal (Golden Rule #5: would false-FAIL every default config).
    r = check_privileged_commands_exposure(_ctx({"commands": {"restart": True}}))
    assert r.status == PASS


def test_native_and_nativeskills_auto_never_flagged():
    cfg = {"commands": {"native": "auto", "nativeSkills": "auto", "restart": True}}
    r = check_privileged_commands_exposure(_ctx(cfg))
    assert r.status == PASS


# ---------------------------------------------------------------------------
# PASS: privileged command enabled, but the gate is scoped (non-wildcard)
# ---------------------------------------------------------------------------

def test_bash_enabled_scoped_owner_allow_from_passes():
    cfg = {"commands": {"bash": True, "ownerAllowFrom": ["telegram:307615315"]}}
    r = check_privileged_commands_exposure(_ctx(cfg))
    assert r.status == PASS


def test_config_enabled_scoped_allow_from_record_passes():
    cfg = {"commands": {"config": True, "allowFrom": {"telegram": ["307615315"]}}}
    r = check_privileged_commands_exposure(_ctx(cfg))
    assert r.status == PASS


def test_all_four_privileged_enabled_scoped_owner_passes():
    cfg = {
        "commands": {
            "bash": True,
            "config": True,
            "mcp": True,
            "plugins": True,
            "ownerAllowFrom": ["@dave"],
        }
    }
    r = check_privileged_commands_exposure(_ctx(cfg))
    assert r.status == PASS


# ---------------------------------------------------------------------------
# FAIL/CRITICAL: bash or config enabled + wildcard-open gate
# ---------------------------------------------------------------------------

def test_bash_enabled_wildcard_owner_allow_from_fails_critical():
    cfg = {"commands": {"bash": True, "ownerAllowFrom": ["*"]}}
    r = check_privileged_commands_exposure(_ctx(cfg))
    assert r.status == FAIL
    assert r.severity == CRITICAL
    joined = " ".join(r.evidence)
    assert "commands.bash" in joined and "ownerAllowFrom" in joined


def test_config_enabled_wildcard_allow_from_record_fails_critical():
    # commands.allowFrom is a record keyed by provider id (or "*" for "all providers") --
    # a "*" SENDER entry inside any of its lists is the same wildcard-authority gate as
    # ownerAllowFrom (dist: hasWildcardAllowFrom over the resolved list).
    cfg = {"commands": {"config": True, "allowFrom": {"telegram": ["*"]}}}
    r = check_privileged_commands_exposure(_ctx(cfg))
    assert r.status == FAIL
    assert r.severity == CRITICAL
    joined = " ".join(r.evidence)
    assert "commands.allowFrom" in joined


def test_allow_from_global_star_key_wildcard_sender_fails():
    cfg = {"commands": {"bash": True, "allowFrom": {"*": ["*"]}}}
    r = check_privileged_commands_exposure(_ctx(cfg))
    assert r.status == FAIL
    assert r.severity == CRITICAL


# ---------------------------------------------------------------------------
# FAIL/HIGH: mcp or plugins enabled + wildcard-open gate (narrower than bash/config)
# ---------------------------------------------------------------------------

def test_mcp_enabled_wildcard_owner_allow_from_fails_high_not_critical():
    cfg = {"commands": {"mcp": True, "ownerAllowFrom": ["*"]}}
    r = check_privileged_commands_exposure(_ctx(cfg))
    assert r.status == FAIL
    assert r.severity == HIGH


def test_plugins_enabled_wildcard_owner_allow_from_fails_high():
    cfg = {"commands": {"plugins": True, "ownerAllowFrom": ["*"]}}
    r = check_privileged_commands_exposure(_ctx(cfg))
    assert r.status == FAIL
    assert r.severity == HIGH


# ---------------------------------------------------------------------------
# FAIL: privileged command enabled + NO gate configured + an open channel
# ---------------------------------------------------------------------------

def test_bash_enabled_no_gate_open_dm_channel_fails_critical():
    cfg = {
        "commands": {"bash": True},
        "channels": {"telegram": {"enabled": True, "dmPolicy": "open"}},
    }
    r = check_privileged_commands_exposure(_ctx(cfg))
    assert r.status == FAIL
    assert r.severity == CRITICAL
    joined = " ".join(r.evidence)
    assert "open channel" in joined and "telegram" in joined


def test_mcp_enabled_no_gate_open_group_channel_fails_high():
    cfg = {
        "commands": {"mcp": True},
        "channels": {"discord": {"enabled": True, "groupPolicy": "open"}},
    }
    r = check_privileged_commands_exposure(_ctx(cfg))
    assert r.status == FAIL
    assert r.severity == HIGH


def test_disabled_open_channel_does_not_count_as_open():
    # B-041 precedent: enabled:false channels ingest nothing -- must not drive a FAIL.
    cfg = {
        "commands": {"bash": True},
        "channels": {"telegram": {"enabled": False, "dmPolicy": "open"}},
    }
    r = check_privileged_commands_exposure(_ctx(cfg))
    assert r.status != FAIL


# ---------------------------------------------------------------------------
# B-235 FP fix: dmPolicy/groupPolicy=='open' scoped by the channel's OWN
# non-wildcard allowFrom/groupAllowFrom is not "ANY sender" -- dm-policy-shared-*.js
# resolveOpenDmAllowlistAccess still blocks every sender not on that list at ingress, and
# resolveDmGroupAccessWithCommandGate feeds the same lists into the control-command
# authorizer for groups. WARN, not FAIL/CRITICAL -- see the _b171_open_channels()
# docstring in checks/_config.py and docs/research/openclaw-schema-recon.md §18.
# ---------------------------------------------------------------------------

def test_bash_enabled_no_gate_dmopen_scoped_allow_from_warns_not_fails():
    cfg = {
        "commands": {"bash": True, "config": True},
        "channels": {
            "telegram": {
                "enabled": True,
                "dmPolicy": "open",
                "allowFrom": ["987654321"],
                "groupPolicy": "disabled",
            }
        },
    }
    r = check_privileged_commands_exposure(_ctx(cfg))
    assert r.status == WARN
    assert r.status != FAIL


def test_bash_enabled_no_gate_dmopen_scoped_account_level_allow_from_warns():
    # Same shape, but the scoped allowFrom lives under channels.<p>.accounts.<id> rather
    # than the channel root -- both are walked by _b171_open_channels().
    cfg = {
        "commands": {"bash": True},
        "channels": {
            "telegram": {
                "enabled": True,
                "accounts": {
                    "default": {"dmPolicy": "open", "allowFrom": ["987654321"]}
                },
            }
        },
    }
    r = check_privileged_commands_exposure(_ctx(cfg))
    assert r.status == WARN


def test_mcp_enabled_no_gate_groupopen_scoped_group_allow_from_warns_not_fails():
    cfg = {
        "commands": {"mcp": True},
        "channels": {
            "telegram": {
                "enabled": True,
                "dmPolicy": "allowlist",
                "allowFrom": ["987654321"],
                "groupPolicy": "open",
                "groupAllowFrom": ["987654321"],
            }
        },
    }
    r = check_privileged_commands_exposure(_ctx(cfg))
    assert r.status == WARN
    assert r.status != FAIL


def test_bash_enabled_no_gate_dmopen_wildcard_allow_from_still_fails_critical():
    # The channel-level allowFrom carries the real "*" -- genuinely open, must still FAIL.
    cfg = {
        "commands": {"bash": True},
        "channels": {
            "telegram": {"enabled": True, "dmPolicy": "open", "allowFrom": ["*"]}
        },
    }
    r = check_privileged_commands_exposure(_ctx(cfg))
    assert r.status == FAIL
    assert r.severity == CRITICAL


def test_bash_enabled_no_gate_dmopen_empty_allow_from_still_fails_critical():
    # dmPolicy=open with NO channel-level allowFrom at all -- genuinely open (matches
    # test_bash_enabled_no_gate_open_dm_channel_fails_critical; kept as an explicit
    # regression pin for the same shape).
    cfg = {
        "commands": {"bash": True},
        "channels": {"telegram": {"enabled": True, "dmPolicy": "open", "allowFrom": []}},
    }
    r = check_privileged_commands_exposure(_ctx(cfg))
    assert r.status == FAIL
    assert r.severity == CRITICAL


def test_mcp_enabled_no_gate_groupopen_wildcard_group_allow_from_still_fails_high():
    cfg = {
        "commands": {"mcp": True},
        "channels": {
            "telegram": {
                "enabled": True,
                "groupPolicy": "open",
                "groupAllowFrom": ["*"],
            }
        },
    }
    r = check_privileged_commands_exposure(_ctx(cfg))
    assert r.status == FAIL
    assert r.severity == HIGH


# ---------------------------------------------------------------------------
# WARN: privileged command enabled + no gate, but the channel isn't open (allowlist/
# paired/pairing/disabled still constrains who reaches the command layer)
# ---------------------------------------------------------------------------

def test_bash_enabled_no_gate_allowlist_channel_warns_not_fails():
    cfg = {
        "commands": {"bash": True},
        "channels": {"telegram": {"enabled": True, "dmPolicy": "allowlist"}},
    }
    r = check_privileged_commands_exposure(_ctx(cfg))
    assert r.status == WARN


def test_debug_only_enabled_no_gate_paired_channel_warns():
    cfg = {
        "commands": {"debug": True},
        "channels": {"whatsapp": {"enabled": True, "dmPolicy": "paired"}},
    }
    r = check_privileged_commands_exposure(_ctx(cfg))
    assert r.status == WARN
    assert r.severity != CRITICAL


def test_use_access_groups_false_with_scoped_gate_warns():
    cfg = {
        "commands": {
            "bash": True,
            "ownerAllowFrom": ["telegram:1"],
            "useAccessGroups": False,
        }
    }
    r = check_privileged_commands_exposure(_ctx(cfg))
    assert r.status == WARN
    joined = " ".join(r.evidence)
    assert "useAccessGroups" in joined


# ---------------------------------------------------------------------------
# UNKNOWN: privileged command enabled, no gate, no channels configured at all --
# reachability genuinely can't be assessed (Golden Rule #4).
# ---------------------------------------------------------------------------

def test_bash_enabled_no_gate_no_channels_unknown():
    r = check_privileged_commands_exposure(_ctx({"commands": {"bash": True}}))
    assert r.status == UNKNOWN


def test_config_unreadable_returns_unknown():
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.config_parse_error = True
    r = check_privileged_commands_exposure(c)
    assert r.status == UNKNOWN


# ---------------------------------------------------------------------------
# Fixtures on disk
# ---------------------------------------------------------------------------

def test_bad_fixture_bash_wildcard_fails_critical():
    r = check_privileged_commands_exposure(collect(FIXTURES / "bad_b171_bash_wildcard"))
    assert r.status == FAIL
    assert r.severity == CRITICAL


def test_clean_fixture_scoped_owner_passes():
    r = check_privileged_commands_exposure(collect(FIXTURES / "clean_b171_scoped_owner"))
    assert r.status == PASS
