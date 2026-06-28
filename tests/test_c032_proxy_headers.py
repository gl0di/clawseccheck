"""C032 — advisory UNKNOWN for real-IP fallback without trusted-proxy allow-list.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import re
from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN
from clawseccheck.checks import check_proxy_header_forging
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
_HEBREW = re.compile(r"[֐-׿]")


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def test_c032_real_ip_fallback_disabled_is_pass():
    assert check_proxy_header_forging(_ctx({"gateway": {"allowRealIpFallback": False}})).status == PASS


def test_c032_fallback_with_allowlist_is_pass():
    cfg = {
        "gateway": {
            "allowRealIpFallback": True,
            "trustedProxies": ["127.0.0.1", "10.0.0.0/8"],
        }
    }
    assert check_proxy_header_forging(_ctx(cfg)).status == PASS


def test_c032_fallback_without_allowlist_is_unknown():
    f = check_proxy_header_forging(_ctx({"gateway": {"allowRealIpFallback": True}}))
    assert f.status == UNKNOWN
    assert any("trusted" in line.lower() for line in f.evidence)


def test_c032_invalid_allowlist_shape_is_unknown():
    cfg = {"gateway": {"allowRealIpFallback": True, "trustedProxies": []}}
    assert check_proxy_header_forging(_ctx(cfg)).status == UNKNOWN



def test_c032_bad_fixture_unknown():
    assert check_proxy_header_forging(collect(FIXTURES / "bad_c032_proxy_headers")).status == UNKNOWN


def test_c032_clean_fixture_pass():
    assert check_proxy_header_forging(collect(FIXTURES / "clean_c032_proxy_headers")).status == PASS


def test_c032_registered_in_audit():
    from clawseccheck import audit

    _, findings, _ = audit(FIXTURES / "bad_c032_proxy_headers", include_native=False)
    ids = {f.id for f in findings}
    assert "C032" in ids, f"C032 not in audit findings: {sorted(ids)}"
