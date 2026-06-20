"""B30 (Sender Identity Strength) and B32 (Control-Plane Mutation Reachability) tests.

Conservative philosophy: FAIL only on positive evidence; UNKNOWN when the config
cannot tell us; PASS when channels/gateway exist but no dangerous flags are set.
"""
from __future__ import annotations

from pathlib import Path

from clawcheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawcheck.checks import check_control_plane_mutation, check_sender_identity
from clawcheck.collector import Context


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
# Reliability: fixture-based end-to-end
# ============================================================

from clawcheck import audit  # noqa: E402

RELIABILITY = Path(__file__).resolve().parent.parent / "fixtures" / "reliability"


def test_b30_bad_fixture_fails():
    _, findings, _ = audit(RELIABILITY / "bad_b30_name_matching")
    by_id = {f.id: f for f in findings}
    assert by_id["B30"].status == FAIL


def test_b32_bad_fixture_fails():
    _, findings, _ = audit(RELIABILITY / "bad_b32_allow_control_plane")
    by_id = {f.id: f for f in findings}
    assert by_id["B32"].status == FAIL
