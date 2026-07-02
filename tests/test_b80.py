"""B80 — gateway auth without rate limiting on a non-loopback bind.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks import check_gateway_rate_limit
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def test_b80_non_token_auth_is_pass():
    assert check_gateway_rate_limit(_ctx({"gateway": {"auth": {"mode": "none"}}})).status == PASS


def test_b80_loopback_bind_is_pass():
    cfg = {"gateway": {"bind": "127.0.0.1:8080", "auth": {"mode": "token"}}}
    assert check_gateway_rate_limit(_ctx(cfg)).status == PASS


def test_b80_ratelimit_present_is_pass():
    cfg = {"gateway": {"bind": "0.0.0.0:8080",
                       "auth": {"mode": "token", "rateLimit": {"maxAttempts": 5}}}}
    assert check_gateway_rate_limit(_ctx(cfg)).status == PASS


def test_b80_exposed_token_without_ratelimit_is_warn():
    cfg = {"gateway": {"bind": "0.0.0.0:8080", "auth": {"mode": "token"}}}
    assert check_gateway_rate_limit(_ctx(cfg)).status == WARN


def test_b80_clean_fixture_pass():
    assert check_gateway_rate_limit(collect(FIXTURES / "clean_b80_gateway_ratelimit")).status == PASS


def test_b80_bad_fixture_warn():
    assert check_gateway_rate_limit(collect(FIXTURES / "bad_b80_gateway_ratelimit")).status == WARN


def test_b80_registered_in_audit():
    from clawseccheck import audit

    _, findings, _ = audit(FIXTURES / "bad_b80_gateway_ratelimit", include_native=False)
    assert "B80" in {f.id for f in findings}
