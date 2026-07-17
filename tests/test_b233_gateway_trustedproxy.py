"""B-233: trusted-proxy auth on a non-loopback bind without requiredHeaders/allowUsers is
a spoofable full auth-bypass — B2 must not affirm "loopback/authenticated" for it, and B70
must recognize a configured trusted-proxy (previously it keyed only on allowLoopback).

Grounded (dist zod-schema-O9ml_nmo.js / types.openclaw-CXjMEWAQ.d.ts):
  gateway.auth.mode='trusted-proxy'
  gateway.auth.trustedProxy.{userHeader,requiredHeaders,allowUsers,allowLoopback}

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, WARN
from clawseccheck.checks import check_gateway, check_trustedproxy_loopback
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


_BAD_CFG = {
    "gateway": {
        "bind": "0.0.0.0:8080",
        "auth": {"mode": "trusted-proxy", "trustedProxy": {"userHeader": "x-forwarded-user"}},
    }
}


# ---------------------------------------------------------------------------
# B2 — never asserts "loopback/authenticated" for a non-loopback bind; the
# unenforced trusted-proxy case is a FAIL naming the spoofable identity header.
# ---------------------------------------------------------------------------

def test_b2_trustedproxy_nonloopback_no_headers_fails():
    f = check_gateway(_ctx(_BAD_CFG))
    assert f.status == FAIL
    assert "Gateway is loopback/authenticated" not in f.detail
    assert "x-forwarded-user" in f.detail
    assert any("trusted-proxy" in e and "spoofable" in e for e in f.evidence)


def test_b2_trustedproxy_nonloopback_default_header_named():
    # userHeader unset -> the evidence still names the canonical spoofable header.
    cfg = {"gateway": {"bind": "0.0.0.0:8080", "auth": {"mode": "trusted-proxy"}}}
    f = check_gateway(_ctx(cfg))
    assert f.status == FAIL
    assert "x-forwarded-user" in f.detail


def test_b2_bad_fixture_fails_and_never_claims_loopback():
    f = check_gateway(collect(FIXTURES / "bad_b233_trustedproxy_nonloopback_no_headers"))
    assert f.status == FAIL
    assert "Gateway is loopback/authenticated" not in f.detail
    assert "authenticated" not in f.detail


def test_b2_trustedproxy_with_required_headers_passes():
    cfg = {
        "gateway": {
            "bind": "0.0.0.0:8080",
            "auth": {
                "mode": "trusted-proxy",
                "trustedProxy": {
                    "userHeader": "x-forwarded-user",
                    "requiredHeaders": ["x-forwarded-proto"],
                },
            },
        }
    }
    f = check_gateway(_ctx(cfg))
    assert f.status == PASS
    # A non-loopback PASS must not fabricate a loopback claim either.
    assert "Gateway is loopback/authenticated" not in f.detail


def test_b2_trustedproxy_with_allow_users_passes():
    cfg = {
        "gateway": {
            "bind": "0.0.0.0:8080",
            "auth": {
                "mode": "trusted-proxy",
                "trustedProxy": {
                    "userHeader": "x-forwarded-user",
                    "allowUsers": ["nick@example.com"],
                },
            },
        }
    }
    f = check_gateway(_ctx(cfg))
    assert f.status == PASS


def test_b2_trustedproxy_loopback_bind_passes():
    cfg = {
        "gateway": {
            "bind": "127.0.0.1:8080",
            "auth": {"mode": "trusted-proxy", "trustedProxy": {"userHeader": "x-forwarded-user"}},
        }
    }
    f = check_gateway(_ctx(cfg))
    assert f.status == PASS
    assert "loopback" in f.detail


def test_b2_clean_required_headers_fixture_passes():
    f = check_gateway(collect(FIXTURES / "clean_b233_trustedproxy_required_headers"))
    assert f.status == PASS


def test_b2_clean_loopback_bind_fixture_passes():
    f = check_gateway(collect(FIXTURES / "clean_b233_trustedproxy_loopback_bind"))
    assert f.status == PASS


def test_b2_clean_token_auth_fixture_still_passes():
    # C-135: token/password auth is unaffected by the trusted-proxy-only condition.
    f = check_gateway(collect(FIXTURES / "clean_b80_gateway_ratelimit"))
    assert f.status == PASS
    assert "Gateway is loopback/authenticated" not in f.detail
    assert "gateway.auth.mode=token" in f.detail


# ---------------------------------------------------------------------------
# B70 — recognizes a configured trusted-proxy (auth.mode='trusted-proxy'), not
# only the allowLoopback field.
# ---------------------------------------------------------------------------

def test_b70_trustedproxy_nonloopback_no_headers_fails():
    f = check_trustedproxy_loopback(_ctx(_BAD_CFG))
    assert f.status == FAIL
    assert "x-forwarded-user" in f.detail
    assert any("trusted-proxy" in e for e in f.evidence)


def test_b70_bad_fixture_fails():
    f = check_trustedproxy_loopback(
        collect(FIXTURES / "bad_b233_trustedproxy_nonloopback_no_headers")
    )
    assert f.status == FAIL


def test_b70_trustedproxy_with_required_headers_passes():
    cfg = {
        "gateway": {
            "bind": "0.0.0.0:8080",
            "auth": {
                "mode": "trusted-proxy",
                "trustedProxy": {
                    "userHeader": "x-forwarded-user",
                    "requiredHeaders": ["x-forwarded-proto"],
                },
            },
        }
    }
    f = check_trustedproxy_loopback(_ctx(cfg))
    assert f.status == PASS


def test_b70_trustedproxy_loopback_bind_passes_without_headers():
    cfg = {
        "gateway": {
            "bind": "127.0.0.1:8080",
            "auth": {"mode": "trusted-proxy", "trustedProxy": {"userHeader": "x-forwarded-user"}},
        }
    }
    f = check_trustedproxy_loopback(_ctx(cfg))
    assert f.status == PASS


def test_b70_clean_required_headers_fixture_passes():
    f = check_trustedproxy_loopback(collect(FIXTURES / "clean_b233_trustedproxy_required_headers"))
    assert f.status == PASS


def test_b70_clean_loopback_bind_fixture_passes():
    f = check_trustedproxy_loopback(collect(FIXTURES / "clean_b233_trustedproxy_loopback_bind"))
    assert f.status == PASS


def test_b70_token_auth_without_trustedproxy_field_stays_unknown():
    # C-135: token/password modes with no trustedProxy config at all are unaffected —
    # same UNKNOWN as before this fix (not a new FAIL).
    from clawseccheck.catalog import UNKNOWN

    f = check_trustedproxy_loopback(collect(FIXTURES / "clean_b80_gateway_ratelimit"))
    assert f.status == UNKNOWN


# ---------------------------------------------------------------------------
# Regression: B70's pre-existing allowLoopback-keyed behavior (unrelated to
# auth.mode) must be unchanged by the mode='trusted-proxy' widening.
# ---------------------------------------------------------------------------

def test_b70_legacy_allowloopback_field_still_warns_without_mode():
    f = check_trustedproxy_loopback(
        _ctx({"gateway": {"bind": "0.0.0.0:8080",
                          "auth": {"trustedProxy": {"allowLoopback": True}}}})
    )
    assert f.status == WARN
