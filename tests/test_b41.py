"""B41 — Credential blast-radius assessment tests.

Conservative philosophy: WARN only when credentials exist AND the agent has
both untrusted-ingress and outbound capability.  PASS when credentials exist
but the ingress+outbound path is absent.  UNKNOWN when no credentials found.

Privacy rule: the account/email portion of auth.profiles keys (after ":")
must NEVER appear in findings — only provider names (before ":") and counts.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_credential_blast_radius
from clawseccheck.collector import Context


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


# ---------------------------------------------------------------------------
# UNKNOWN — no credentials at all
# ---------------------------------------------------------------------------

def test_b41_no_auth_profiles_and_no_gateway_token_unknown():
    f = check_credential_blast_radius(_ctx({}))
    assert f.status == UNKNOWN


def test_b41_empty_profiles_dict_unknown():
    f = check_credential_blast_radius(_ctx({"auth": {"profiles": {}}}))
    assert f.status == UNKNOWN


# ---------------------------------------------------------------------------
# WARN — credentials + untrusted ingress + outbound tools
# ---------------------------------------------------------------------------

def test_b41_open_channel_plus_outbound_tool_warns():
    cfg = {
        "auth": {
            "profiles": {
                "google:owner@example.com": {"provider": "google", "mode": "oauth"},
                "github:owner": {"provider": "github", "mode": "oauth"},
            }
        },
        "channels": {"telegram": {"dmPolicy": "open"}},
        "tools": {"allow": ["email_send"]},
    }
    f = check_credential_blast_radius(_ctx(cfg))
    assert f.status == WARN


def test_b41_warn_detail_mentions_provider_count():
    cfg = {
        "auth": {
            "profiles": {
                "google:owner@example.com": {},
                "github:owner": {},
            }
        },
        "channels": {"telegram": {"dmPolicy": "open"}},
        "tools": {"allow": ["fs_write"]},
    }
    f = check_credential_blast_radius(_ctx(cfg))
    assert f.status == WARN
    # "2 provider credential(s)" in detail
    assert "2" in f.detail


def test_b41_warn_evidence_contains_provider_names():
    cfg = {
        "auth": {
            "profiles": {
                "google:owner@example.com": {},
                "slack:workspace-bot": {},
            }
        },
        "channels": {"telegram": {"dmPolicy": "open"}},
        "tools": {"allow": ["deploy"]},
    }
    f = check_credential_blast_radius(_ctx(cfg))
    assert f.status == WARN
    evidence_blob = " ".join(f.evidence)
    assert "google" in evidence_blob
    assert "slack" in evidence_blob


def test_b41_gateway_token_counted_and_noted():
    cfg = {
        "gateway": {"auth": {"token": "a" * 32}},
        "channels": {"telegram": {"dmPolicy": "open"}},
        "tools": {"allow": ["email_send"]},
    }
    f = check_credential_blast_radius(_ctx(cfg))
    assert f.status == WARN
    assert "gateway-token" in " ".join(f.evidence)
    assert "gateway token" in f.detail


def test_b41_input_tool_hint_counts_as_untrusted_ingress():
    # No open channel, but an email-reading tool counts as untrusted ingress.
    cfg = {
        "auth": {"profiles": {"google:user@example.com": {}}},
        "tools": {"allow": ["email", "webhook"]},
    }
    f = check_credential_blast_radius(_ctx(cfg))
    assert f.status == WARN


# ---------------------------------------------------------------------------
# PASS — credentials present but NOT reachable
# ---------------------------------------------------------------------------

def test_b41_allowlist_channel_no_outbound_passes():
    cfg = {
        "auth": {
            "profiles": {
                "google:owner@example.com": {},
                "github:owner": {},
            }
        },
        "channels": {"telegram": {"dmPolicy": "allowlist", "groupPolicy": "allowlist"}},
        "tools": {"profile": "minimal"},
    }
    f = check_credential_blast_radius(_ctx(cfg))
    assert f.status == PASS


def test_b41_open_channel_but_no_outbound_passes():
    # Untrusted ingress but no outbound capability — reachable=False.
    cfg = {
        "auth": {"profiles": {"google:owner@example.com": {}}},
        "channels": {"telegram": {"dmPolicy": "open"}},
        "tools": {"profile": "minimal"},
    }
    f = check_credential_blast_radius(_ctx(cfg))
    assert f.status == PASS


def test_b41_outbound_tool_but_no_ingress_passes():
    # Outbound capability (deploy) but no open/input ingress — reachable=False.
    # Note: "email_send" contains the substring "email" which matches INPUT_TOOL_HINTS,
    # so it counts as both ingress and outbound.  Use "deploy" (pure outbound) instead.
    cfg = {
        "auth": {"profiles": {"google:owner@example.com": {}}},
        "channels": {"telegram": {"dmPolicy": "allowlist"}},
        "tools": {"allow": ["deploy"]},
    }
    f = check_credential_blast_radius(_ctx(cfg))
    assert f.status == PASS


def test_b41_pass_detail_mentions_not_reachable():
    cfg = {
        "auth": {"profiles": {"google:owner@example.com": {}}},
        "channels": {"telegram": {"dmPolicy": "allowlist"}},
        "tools": {"profile": "minimal"},
    }
    f = check_credential_blast_radius(_ctx(cfg))
    assert f.status == PASS
    assert "reachable" in f.detail


# ---------------------------------------------------------------------------
# Privacy: email/account MUST NOT appear in finding detail or evidence
# ---------------------------------------------------------------------------

def test_b41_does_not_leak_email_pii():
    """The account part of a profile key must never appear in findings."""
    cfg = {
        "auth": {
            "profiles": {
                "google:secret-user@example.com": {"provider": "google", "mode": "oauth"},
            }
        },
        "channels": {"telegram": {"dmPolicy": "open"}},
        "tools": {"allow": ["email_send"]},
    }
    f = check_credential_blast_radius(_ctx(cfg))
    assert f.status == WARN

    # Combine all text surfaces a caller could read
    all_text = " ".join([f.detail, f.fix] + list(f.evidence))

    # The account/email portion must not appear anywhere
    assert "secret-user@example.com" not in all_text
    assert "secret-user" not in all_text

    # But the provider name MUST appear (it is what we deliberately expose)
    assert "google" in all_text


def test_b41_provider_deduplication():
    # Two profiles with the same provider should count as one provider.
    cfg = {
        "auth": {
            "profiles": {
                "google:user1@example.com": {},
                "google:user2@example.com": {},
            }
        },
        "channels": {"telegram": {"dmPolicy": "open"}},
        "tools": {"allow": ["fs_write"]},
    }
    f = check_credential_blast_radius(_ctx(cfg))
    assert f.status == WARN
    # Only 1 unique provider but the total credential count includes gateway token check
    assert "google" in f.detail
    # Should say 1 provider credential (deduplicated)
    assert "1 provider credential" in f.detail


# ---------------------------------------------------------------------------
# B41 must never produce FAIL (advisory check — WARN/PASS/UNKNOWN only)
# ---------------------------------------------------------------------------

def test_b41_never_fails_even_with_worst_case():
    cfg = {
        "auth": {
            "profiles": {
                "google:secret@example.com": {},
                "github:secret": {},
                "slack:workspace": {},
            }
        },
        "gateway": {"auth": {"token": "a" * 32}},
        "channels": {"telegram": {"dmPolicy": "open"}},
        "tools": {"allow": ["email_send", "fs_write", "exec", "deploy"]},
    }
    f = check_credential_blast_radius(_ctx(cfg))
    assert f.status != "FAIL"
