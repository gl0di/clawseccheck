"""B83 — web-fetch tool allows excessive redirect following.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks import check_webfetch_redirects
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def test_b83_fetch_disabled_is_pass():
    assert check_webfetch_redirects(_ctx({"tools": {"web": {"fetch": {"enabled": False}}}})).status == PASS


def test_b83_fetch_enabled_low_redirects_is_pass():
    cfg = {"tools": {"web": {"fetch": {"enabled": True, "maxRedirects": 3}}}}
    assert check_webfetch_redirects(_ctx(cfg)).status == PASS


def test_b83_fetch_enabled_no_redirect_setting_is_pass():
    cfg = {"tools": {"web": {"fetch": {"enabled": True}}}}
    assert check_webfetch_redirects(_ctx(cfg)).status == PASS


def test_b83_fetch_enabled_high_redirects_is_warn():
    cfg = {"tools": {"web": {"fetch": {"enabled": True, "maxRedirects": 20}}}}
    assert check_webfetch_redirects(_ctx(cfg)).status == WARN


def test_b83_clean_fixture_pass():
    assert check_webfetch_redirects(collect(FIXTURES / "clean_b83_webfetch_redirects")).status == PASS


def test_b83_bad_fixture_warn():
    assert check_webfetch_redirects(collect(FIXTURES / "bad_b83_webfetch_redirects")).status == WARN


def test_b83_registered_in_audit():
    from clawseccheck import audit

    _, findings, _ = audit(FIXTURES / "bad_b83_webfetch_redirects", include_native=False)
    assert "B83" in {f.id for f in findings}
