"""B38 (Browser Control / Cookie & SSRF Exposure) and
B39 (Session Visibility / Cross-user Transcript Leak) tests.

Conservative philosophy: FAIL only on positive evidence; UNKNOWN when the config
cannot tell us; PASS when browser/session is configured but no dangerous flags are set.
"""
from __future__ import annotations

from pathlib import Path

from clawcheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawcheck.checks import check_browser_ssrf, check_session_visibility
from clawcheck.collector import Context


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


# ============================================================
# B38 — Browser Control / Cookie & SSRF Exposure
# ============================================================

# --- UNKNOWN when no browser config ---

def test_b38_no_browser_config_unknown():
    assert check_browser_ssrf(_ctx({})).status == UNKNOWN


def test_b38_browser_not_dict_unknown():
    assert check_browser_ssrf(_ctx({"browser": True})).status == UNKNOWN


# --- FAIL: dangerouslyAllowPrivateNetwork == true ---

def test_b38_private_network_allowed_fails():
    cfg = {"browser": {
        "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": True},
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == FAIL
    assert "dangerouslyAllowPrivateNetwork" in f.detail
    assert len(f.evidence) >= 1


def test_b38_private_network_evidence_contains_metadata_ip():
    cfg = {"browser": {
        "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": True},
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == FAIL
    assert "169.254.169.254" in " ".join(f.evidence)


def test_b38_private_network_false_does_not_fail():
    cfg = {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": ["example.com"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == PASS


# --- FAIL: noSandbox == true ---

def test_b38_no_sandbox_fails():
    cfg = {"browser": {"noSandbox": True}}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == FAIL
    assert "noSandbox" in f.detail
    assert len(f.evidence) >= 1


def test_b38_no_sandbox_false_does_not_fail():
    cfg = {"browser": {
        "noSandbox": False,
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": ["example.com"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == PASS


# --- FAIL when both dangerous flags are set ---

def test_b38_both_dangerous_flags_fails():
    cfg = {"browser": {
        "noSandbox": True,
        "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": True},
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == FAIL
    assert len(f.evidence) == 2


# --- WARN: browser configured with no hostnameAllowlist ---

def test_b38_no_allowlist_warns():
    cfg = {"browser": {
        "headless": True,
        "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": False},
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == WARN
    assert "hostnameAllowlist" in f.detail


def test_b38_empty_allowlist_warns():
    cfg = {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": [],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == WARN


def test_b38_no_ssrf_policy_at_all_warns():
    cfg = {"browser": {"headless": True}}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == WARN


# --- PASS: sandboxed, private network blocked, allowlist present ---

def test_b38_fully_hardened_passes():
    cfg = {"browser": {
        "headless": True,
        "noSandbox": False,
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": ["example.com", "api.myservice.io"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == PASS


def test_b38_allowlist_present_no_sandbox_key_passes():
    # noSandbox absent (defaults to sandboxed) — should PASS
    cfg = {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": ["trusted.example.com"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == PASS


# --- Evidence populated on FAIL ---

def test_b38_fail_evidence_populated():
    cfg = {"browser": {"noSandbox": True}}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == FAIL
    assert f.evidence


# ============================================================
# B39 — Session Visibility / Cross-user Transcript Leak
# ============================================================

# --- UNKNOWN when no session config ---

def test_b39_no_session_config_unknown():
    assert check_session_visibility(_ctx({})).status == UNKNOWN


def test_b39_empty_config_unknown():
    assert check_session_visibility(_ctx({"gateway": {}})).status == UNKNOWN


# --- FAIL: dmScope == "main" with non-owner channels ---

def test_b39_main_scope_with_allowlist_channel_fails():
    cfg = {
        "session": {"dmScope": "main"},
        "channels": {"telegram": {"dmPolicy": "allowlist", "groupPolicy": "allowlist"}},
    }
    f = check_session_visibility(_ctx(cfg))
    assert f.status == FAIL
    assert "dmScope" in f.detail
    assert len(f.evidence) >= 1


def test_b39_main_scope_with_open_channel_fails():
    cfg = {
        "session": {"dmScope": "main"},
        "channels": {"discord": {"dmPolicy": "open"}},
    }
    f = check_session_visibility(_ctx(cfg))
    assert f.status == FAIL
    assert "main" in f.detail


def test_b39_main_scope_no_channels_does_not_fail():
    # "main" with no channels that allow non-owners -> no cross-user contamination
    cfg = {"session": {"dmScope": "main"}}
    f = check_session_visibility(_ctx(cfg))
    # Should NOT be FAIL (no non-owner channels)
    assert f.status != FAIL


# --- FAIL takes priority over WARN ---

def test_b39_fail_takes_priority_over_warn():
    cfg = {
        "session": {"dmScope": "main"},
        "channels": {"telegram": {"dmPolicy": "allowlist"}},
        "tools": {"sessions": {"visibility": "all"}},
    }
    f = check_session_visibility(_ctx(cfg))
    assert f.status == FAIL


# --- WARN: tools.sessions.visibility in ("agent", "all") ---

def test_b39_visibility_agent_warns():
    cfg = {"tools": {"sessions": {"visibility": "agent"}}}
    f = check_session_visibility(_ctx(cfg))
    assert f.status == WARN
    assert "visibility" in f.detail
    assert len(f.evidence) >= 1


def test_b39_visibility_all_warns():
    cfg = {"tools": {"sessions": {"visibility": "all"}}}
    f = check_session_visibility(_ctx(cfg))
    assert f.status == WARN
    assert "all" in f.detail


def test_b39_visibility_self_does_not_warn():
    cfg = {"tools": {"sessions": {"visibility": "self"}}}
    f = check_session_visibility(_ctx(cfg))
    assert f.status != WARN
    assert f.status != FAIL


def test_b39_visibility_tree_does_not_warn():
    cfg = {"tools": {"sessions": {"visibility": "tree"}}}
    f = check_session_visibility(_ctx(cfg))
    assert f.status != WARN
    assert f.status != FAIL


# --- PASS: safe scope + safe visibility ---

def test_b39_per_peer_scope_passes():
    cfg = {
        "session": {"dmScope": "per-peer"},
        "tools": {"sessions": {"visibility": "self"}},
    }
    f = check_session_visibility(_ctx(cfg))
    assert f.status == PASS


def test_b39_per_channel_peer_scope_passes():
    cfg = {
        "session": {"dmScope": "per-channel-peer"},
        "tools": {"sessions": {"visibility": "tree"}},
    }
    f = check_session_visibility(_ctx(cfg))
    assert f.status == PASS


def test_b39_per_account_channel_peer_scope_passes():
    cfg = {"session": {"dmScope": "per-account-channel-peer"}}
    f = check_session_visibility(_ctx(cfg))
    assert f.status == PASS


def test_b39_session_cfg_only_no_vis_passes():
    cfg = {"session": {"dmScope": "per-peer"}}
    f = check_session_visibility(_ctx(cfg))
    assert f.status == PASS


# --- Evidence populated on FAIL ---

def test_b39_fail_evidence_populated():
    cfg = {
        "session": {"dmScope": "main"},
        "channels": {"slack": {"dmPolicy": "allowlist"}},
    }
    f = check_session_visibility(_ctx(cfg))
    assert f.status == FAIL
    assert f.evidence


# ============================================================
# Reliability: fixture-based end-to-end
# ============================================================

from clawcheck import audit  # noqa: E402

RELIABILITY = Path(__file__).resolve().parent.parent / "fixtures" / "reliability"


def test_b38_bad_fixture_fails():
    _, findings, _ = audit(RELIABILITY / "bad_b38_private_network")
    by_id = {f.id: f for f in findings}
    assert by_id["B38"].status == FAIL


def test_b39_bad_fixture_fails():
    _, findings, _ = audit(RELIABILITY / "bad_b39_main_scope")
    by_id = {f.id: f for f in findings}
    assert by_id["B39"].status == FAIL
