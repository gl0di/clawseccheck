"""B30 (Sender Identity Strength) and B32 (Control-Plane Mutation Reachability) tests.

Conservative philosophy: FAIL only on positive evidence; UNKNOWN when the config
cannot tell us; PASS when channels/gateway exist but no dangerous flags are set.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_control_plane_mutation, check_sender_identity
from clawseccheck.collector import Context


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


# ============================================================
# B30 — Sender Identity Strength
# ============================================================

# --- UNKNOWN when no channels ---

def test_b30_no_channels_unknown():
    assert check_sender_identity(_ctx({})).status == UNKNOWN


def test_b30_empty_channels_unknown():
    assert check_sender_identity(_ctx({"channels": {}})).status == UNKNOWN


# --- FAIL: dangerouslyAllowNameMatching == true ---

def test_b30_discord_name_matching_fails():
    cfg = {"channels": {"discord": {
        "dmPolicy": "allowlist",
        "dangerouslyAllowNameMatching": True,
    }}}
    f = check_sender_identity(_ctx(cfg))
    assert f.status == FAIL
    assert "dangerouslyAllowNameMatching" in f.detail
    assert len(f.evidence) >= 1


def test_b30_slack_name_matching_fails():
    cfg = {"channels": {"slack": {
        "groupPolicy": "allowlist",
        "dangerouslyAllowNameMatching": True,
    }}}
    f = check_sender_identity(_ctx(cfg))
    assert f.status == FAIL
    assert "slack" in f.detail


def test_b30_name_matching_false_does_not_fail():
    cfg = {"channels": {"discord": {
        "dmPolicy": "allowlist",
        "dangerouslyAllowNameMatching": False,
    }}}
    f = check_sender_identity(_ctx(cfg))
    assert f.status == PASS


def test_b30_name_matching_absent_does_not_fail():
    cfg = {"channels": {"discord": {"dmPolicy": "allowlist"}}}
    f = check_sender_identity(_ctx(cfg))
    assert f.status == PASS


# --- FAIL takes priority over WARN ---

def test_b30_fail_takes_priority_over_warn():
    cfg = {"channels": {
        "discord": {"dangerouslyAllowNameMatching": True},
        "telegram": {"includeGroupHistoryContext": "recent"},
    }}
    f = check_sender_identity(_ctx(cfg))
    assert f.status == FAIL


# --- WARN: includeGroupHistoryContext == "recent" ---

def test_b30_telegram_recent_history_warns():
    cfg = {"channels": {"telegram": {
        "dmPolicy": "allowlist",
        "includeGroupHistoryContext": "recent",
    }}}
    f = check_sender_identity(_ctx(cfg))
    assert f.status == WARN
    assert "includeGroupHistoryContext" in f.detail
    assert len(f.evidence) >= 1


def test_b30_telegram_mention_only_history_passes():
    cfg = {"channels": {"telegram": {
        "dmPolicy": "allowlist",
        "includeGroupHistoryContext": "mention-only",
    }}}
    f = check_sender_identity(_ctx(cfg))
    assert f.status == PASS


def test_b30_telegram_none_history_passes():
    cfg = {"channels": {"telegram": {
        "dmPolicy": "allowlist",
        "includeGroupHistoryContext": "none",
    }}}
    f = check_sender_identity(_ctx(cfg))
    assert f.status == PASS


def test_b30_telegram_history_absent_passes():
    cfg = {"channels": {"telegram": {"dmPolicy": "allowlist"}}}
    f = check_sender_identity(_ctx(cfg))
    assert f.status == PASS


# --- PASS: channels exist with safe settings ---

def test_b30_clean_channels_pass():
    cfg = {"channels": {
        "discord": {"dmPolicy": "allowlist"},
        "slack": {"groupPolicy": "allowlist"},
        "telegram": {"dmPolicy": "allowlist", "includeGroupHistoryContext": "none"},
    }}
    f = check_sender_identity(_ctx(cfg))
    assert f.status == PASS


# --- Evidence is populated on FAIL ---

def test_b30_fail_evidence_populated():
    cfg = {"channels": {"discord": {"dangerouslyAllowNameMatching": True}}}
    f = check_sender_identity(_ctx(cfg))
    assert f.status == FAIL
    assert f.evidence


# ============================================================
# B32 — Control-Plane Mutation Reachability
# ============================================================

# --- UNKNOWN when no gateway ---

def test_b32_no_gateway_unknown():
    assert check_control_plane_mutation(_ctx({})).status == UNKNOWN


def test_b32_empty_config_unknown():
    assert check_control_plane_mutation(_ctx({"channels": {"telegram": {}}})).status == UNKNOWN


# --- FAIL: control-plane tool in gateway.tools.allow ---

def test_b32_config_apply_in_allow_fails():
    cfg = {"gateway": {
        "bind": "127.0.0.1:8080",
        "auth": {"mode": "token", "token": "a" * 32},
        "tools": {"allow": ["config.apply"]},
    }}
    f = check_control_plane_mutation(_ctx(cfg))
    assert f.status == FAIL
    assert "config.apply" in f.detail
    assert len(f.evidence) >= 1


def test_b32_cron_in_allow_fails():
    cfg = {"gateway": {
        "bind": "127.0.0.1:8080",
        "auth": {"mode": "token"},
        "tools": {"allow": ["cron"]},
    }}
    f = check_control_plane_mutation(_ctx(cfg))
    assert f.status == FAIL
    assert "cron" in f.detail


def test_b32_sessions_spawn_in_allow_fails():
    cfg = {"gateway": {
        "bind": "loopback",
        "auth": {"mode": "token"},
        "tools": {"allow": ["sessions_spawn", "some_safe_tool"]},
    }}
    f = check_control_plane_mutation(_ctx(cfg))
    assert f.status == FAIL
    assert "sessions_spawn" in f.detail


def test_b32_gateway_tool_in_allow_fails():
    cfg = {"gateway": {
        "bind": "loopback",
        "tools": {"allow": ["gateway"]},
    }}
    f = check_control_plane_mutation(_ctx(cfg))
    assert f.status == FAIL


def test_b32_update_run_in_allow_fails():
    cfg = {"gateway": {
        "bind": "loopback",
        "tools": {"allow": ["update.run"]},
    }}
    f = check_control_plane_mutation(_ctx(cfg))
    assert f.status == FAIL


def test_b32_sessions_send_in_allow_fails():
    cfg = {"gateway": {
        "bind": "loopback",
        "tools": {"allow": ["sessions_send"]},
    }}
    f = check_control_plane_mutation(_ctx(cfg))
    assert f.status == FAIL


def test_b32_multiple_cp_tools_in_allow_fails():
    cfg = {"gateway": {
        "bind": "loopback",
        "tools": {"allow": ["config.apply", "cron", "sessions_spawn"]},
    }}
    f = check_control_plane_mutation(_ctx(cfg))
    assert f.status == FAIL
    assert len(f.evidence) >= 2


# --- Safe tools in allow do NOT fail ---

def test_b32_safe_tool_in_allow_does_not_fail():
    cfg = {"gateway": {
        "bind": "127.0.0.1:8080",
        "auth": {"mode": "token", "token": "a" * 32},
        "tools": {"allow": ["read_file", "list_dir"]},
    }}
    f = check_control_plane_mutation(_ctx(cfg))
    assert f.status != FAIL


# --- WARN: exposed gateway, control-plane not denied ---

def test_b32_exposed_gateway_no_deny_warns():
    cfg = {"gateway": {
        "bind": "0.0.0.0:8080",
        "auth": {"mode": "token", "token": "a" * 32},
    }}
    f = check_control_plane_mutation(_ctx(cfg))
    assert f.status == WARN
    assert "control-plane" in f.detail.lower() or "gateway" in f.detail.lower()


def test_b32_no_auth_gateway_no_deny_warns():
    cfg = {"gateway": {
        "bind": "127.0.0.1:8080",
        "auth": {"mode": "none"},
    }}
    f = check_control_plane_mutation(_ctx(cfg))
    assert f.status == WARN


# --- PASS: loopback, control-plane not re-enabled ---

def test_b32_loopback_no_allow_passes():
    cfg = {"gateway": {
        "bind": "127.0.0.1:8080",
        "auth": {"mode": "token", "token": "a" * 32},
    }}
    f = check_control_plane_mutation(_ctx(cfg))
    assert f.status == PASS


def test_b32_loopback_keyword_no_allow_passes():
    cfg = {"gateway": {
        "bind": "loopback",
        "auth": {"mode": "token", "token": "a" * 32},
    }}
    f = check_control_plane_mutation(_ctx(cfg))
    assert f.status == PASS


def test_b32_exposed_but_cp_tools_denied_passes():
    cfg = {"gateway": {
        "bind": "0.0.0.0:8080",
        "auth": {"mode": "token", "token": "a" * 32},
        "tools": {
            "deny": ["gateway", "cron", "sessions_spawn", "sessions_send",
                     "config.apply", "update.run"],
        },
    }}
    f = check_control_plane_mutation(_ctx(cfg))
    assert f.status == PASS


def test_b32_no_tools_section_loopback_passes():
    cfg = {"gateway": {
        "bind": "localhost:9000",
        "auth": {"mode": "token", "token": "a" * 32},
    }}
    f = check_control_plane_mutation(_ctx(cfg))
    assert f.status == PASS


# --- Evidence is populated on FAIL ---

def test_b32_fail_evidence_populated():
    cfg = {"gateway": {
        "bind": "loopback",
        "tools": {"allow": ["config.apply", "cron"]},
    }}
    f = check_control_plane_mutation(_ctx(cfg))
    assert f.status == FAIL
    assert f.evidence


# ============================================================
# B-835 — plugins (openclaw@2026.9.5 GATEWAY_CONTROL_PLANE_TOOLS), the reversed
# cron/automations alias, and normalisation (case/whitespace).
# ============================================================

def test_b32_plugins_in_allow_fails():
    """openclaw@2026.9.5 added "plugins" to GATEWAY_CONTROL_PLANE_TOOLS AND to
    DEFAULT_GATEWAY_HTTP_TOOL_DENY (dangerous-tools-D5_2xo_6.mjs:25,35-39) — the exact
    CLI-measured regression this task fixes: gateway.tools.allow:["plugins"] used to
    PASS."""
    cfg = {"gateway": {
        "bind": "loopback",
        "tools": {"allow": ["plugins"]},
    }}
    f = check_control_plane_mutation(_ctx(cfg))
    assert f.status == FAIL
    assert "plugins" in f.detail


def test_b32_canonical_automations_in_allow_fails():
    """Before this fix the set held only the legacy alias "cron", so the CANONICAL
    name "automations" (the more likely spelling in a real config) PASSED — backwards
    from the vendor's own TOOL_NAME_ALIASES direction (cron -> automations)."""
    cfg = {"gateway": {
        "bind": "loopback",
        "tools": {"allow": ["automations"]},
    }}
    f = check_control_plane_mutation(_ctx(cfg))
    assert f.status == FAIL
    assert "automations" in f.detail


def test_b32_cron_alias_still_fails_and_is_reported_as_written():
    """Regression guard for the alias fix: "cron" must still FAIL (it resolves to the
    canonical "automations"), and — since matching is now by normalised identity but
    reporting is by the operator's own spelling — the detail must say "cron", not the
    canonical form the operator never wrote."""
    cfg = {"gateway": {
        "bind": "loopback",
        "tools": {"allow": ["cron"]},
    }}
    f = check_control_plane_mutation(_ctx(cfg))
    assert f.status == FAIL
    assert "cron" in f.detail
    assert "cron" in f.evidence


def test_b32_mixed_case_and_whitespace_names_fail():
    cfg = {"gateway": {
        "bind": "loopback",
        "tools": {"allow": [" Plugins ", "AUTOMATIONS", "  CRON"]},
    }}
    f = check_control_plane_mutation(_ctx(cfg))
    assert f.status == FAIL
    # normalised-dedup: three spellings straddling two canonical tools (cron and
    # AUTOMATIONS both resolve to "automations") still report each written spelling.
    assert set(f.evidence) == {"Plugins", "AUTOMATIONS", "CRON"}


def test_b32_nodes_alone_in_allow_does_not_fail():
    """Deliberate scope decision (B-835): "nodes" ("Nodes + devices" — device control)
    is in the vendor's DEFAULT_GATEWAY_HTTP_TOOL_DENY and GATEWAY_OWNER_ONLY_CORE_TOOLS
    but NOT in GATEWAY_CONTROL_PLANE_TOOLS — the vendor itself does not call it a
    control-plane tool, and neither does this check. Locks the decision in so a future
    change does not silently widen B32's scope past what it is named for."""
    cfg = {"gateway": {
        "bind": "loopback",
        "tools": {"allow": ["nodes"]},
    }}
    f = check_control_plane_mutation(_ctx(cfg))
    assert f.status != FAIL


def test_b32_openclaw_alone_in_allow_does_not_fail():
    """Same scope decision as "nodes" above, for the "openclaw" tool ("Delegate
    OpenClaw setup and repair") — present in GATEWAY_OWNER_ONLY_CORE_TOOLS, absent
    from GATEWAY_CONTROL_PLANE_TOOLS."""
    cfg = {"gateway": {
        "bind": "loopback",
        "tools": {"allow": ["openclaw"]},
    }}
    f = check_control_plane_mutation(_ctx(cfg))
    assert f.status != FAIL


def test_b32_harmless_tool_name_does_not_fail():
    cfg = {"gateway": {
        "bind": "loopback",
        "tools": {"allow": ["weather_lookup"]},
    }}
    f = check_control_plane_mutation(_ctx(cfg))
    assert f.status != FAIL


def test_b32_non_string_allow_entry_does_not_crash():
    cfg = {"gateway": {
        "bind": "loopback",
        "tools": {"allow": [None, 42, "weather_lookup"]},
    }}
    f = check_control_plane_mutation(_ctx(cfg))
    assert f.status != FAIL


def test_b32_deny_normalises_cron_alias_to_automations():
    """gateway.tools.deny:["cron"] must be recognised as denying the canonical
    "automations" control-plane tool (an exposed gateway that denies the alias is
    just as covered as one that denies the canonical name)."""
    cfg = {"gateway": {
        "bind": "0.0.0.0:8080",
        "auth": {"mode": "token", "token": "a" * 32},
        "tools": {"deny": ["gateway", "cron", "plugins", "sessions_spawn",
                            "sessions_send", "config.apply", "update.run"]},
    }}
    f = check_control_plane_mutation(_ctx(cfg))
    assert f.status == PASS


# ============================================================
# Reliability: fixture-based end-to-end
# ============================================================

from clawseccheck import audit  # noqa: E402

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
RELIABILITY = FIXTURES / "reliability"


def test_b30_bad_fixture_fails():
    _, findings, _ = audit(RELIABILITY / "bad_b30_name_matching")
    by_id = {f.id: f for f in findings}
    assert by_id["B30"].status == FAIL


def test_b32_bad_fixture_fails():
    _, findings, _ = audit(RELIABILITY / "bad_b32_allow_control_plane")
    by_id = {f.id: f for f in findings}
    assert by_id["B32"].status == FAIL


def test_b32_bad_plugins_fixture_fails_end_to_end():
    """B-835 end-to-end: gateway.tools.allow:["plugins"] over a real audit() run."""
    _, findings, _ = audit(FIXTURES / "bad_b32_plugins_gateway_allow")
    by_id = {f.id: f for f in findings}
    assert by_id["B32"].status == FAIL
    assert "plugins" in by_id["B32"].detail


def test_b32_clean_control_plane_denied_fixture_passes_end_to_end():
    """B-835: enrolled in the zero-FAIL clean corpus (tests/test_fp_corpus.py) by the
    clean_* naming convention — a full audit() run must not FAIL B32 (or anything
    else) on a config that explicitly denies every control-plane tool this fix
    grounds, spelled out under their canonical (not alias) names."""
    _, findings, _ = audit(FIXTURES / "clean_b32_control_plane_denied")
    by_id = {f.id: f for f in findings}
    assert by_id["B32"].status == PASS
