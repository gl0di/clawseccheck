"""BLK-02 regression: IPv6-aware gateway bind parsing.

The old `str(bind).split(':')[0]` mangled IPv6: '::' became '' (matched LOOPBACK,
so a publicly-bound gateway was reported safe) and '[::1]:port' became '[' (a
loopback bind was wrongly flagged exposed). `parse_bind_host` fixes both.
"""
from pathlib import Path

from clawseccheck.checks import check_gateway, parse_bind_host
from clawseccheck.collector import Context


def _ctx(cfg):
    c = Context(home=Path("/x"))
    c.config = cfg
    c.bootstrap = {}
    return c


# ---- parse_bind_host unit tests ----
def test_parse_bind_host_ipv4_host_port():
    assert parse_bind_host("127.0.0.1:8080") == "127.0.0.1"


def test_parse_bind_host_ipv6_any_bare():
    assert parse_bind_host("::") == "::"


def test_parse_bind_host_ipv6_any_bracket_with_port():
    assert parse_bind_host("[::]:8765") == "::"


def test_parse_bind_host_ipv6_loopback_bare():
    assert parse_bind_host("::1") == "::1"


def test_parse_bind_host_ipv6_loopback_bracket_with_port():
    assert parse_bind_host("[::1]:8765") == "::1"


def test_parse_bind_host_ipv4_any():
    assert parse_bind_host("0.0.0.0") == "0.0.0.0"


def test_parse_bind_host_empty():
    assert parse_bind_host("") == ""


def test_parse_bind_host_uppercase_normalized():
    assert parse_bind_host("[::1]:9000") == "::1"


# ---- integration: gateway exposure classification ----
def test_gateway_bind_ipv6_any_is_exposed():
    # '::' is the IPv6 "any" address — publicly exposed. Must FAIL (was a false PASS).
    cfg = {"gateway": {"bind": "::", "auth": {"mode": "none"}}}
    assert check_gateway(_ctx(cfg)).status == "FAIL"


def test_gateway_bind_bracket_ipv6_any_is_exposed():
    cfg = {"gateway": {"bind": "[::]:8765", "auth": {"mode": "none"}}}
    assert check_gateway(_ctx(cfg)).status == "FAIL"


def test_gateway_bind_ipv6_loopback_is_not_public():
    # '[::1]:8765' is IPv6 loopback — not public. Must NOT be flagged exposed.
    cfg = {"gateway": {"bind": "[::1]:8765", "auth": {"mode": "none"}}}
    assert check_gateway(_ctx(cfg)).status == "PASS"


def test_gateway_bind_ipv4_any_still_exposed():
    # Guard against regressing the IPv4 case.
    cfg = {"gateway": {"bind": "0.0.0.0:8765", "auth": {"mode": "none"}}}
    assert check_gateway(_ctx(cfg)).status == "FAIL"


def test_gateway_bind_ipv4_loopback_is_not_public():
    cfg = {"gateway": {"bind": "127.0.0.1:8765", "auth": {"mode": "none"}}}
    assert check_gateway(_ctx(cfg)).status == "PASS"


# ---- B11: funnel mode does not suppress TLS warning ----
def test_b11_funnel_mode_non_loopback_no_tls_warns():
    from clawseccheck.checks import check_tls
    cfg = {
        "gateway": {
            "bind": "0.0.0.0:8080",
            "tailscale": {"mode": "funnel"},
        }
    }
    ctx = _ctx(cfg)
    ctx.config_mode = 0o600
    f = check_tls(ctx)
    assert f.status == "WARN"
    assert "non-loopback" in f.detail


# ---- H5: IPv6 zone-id stripping ----
def test_parse_bind_host_ipv6_loopback_with_zone_id():
    # ::1%eth0 must parse to ::1 (the zone id is not part of the address).
    assert parse_bind_host("::1%eth0") == "::1"


def test_parse_bind_host_ipv6_loopback_bracket_zone_id():
    # [::1%eth0]:8765 bracketed form must also strip the zone.
    assert parse_bind_host("[::1%eth0]:8765") == "::1"


def test_parse_bind_host_ipv6_link_local_with_zone_id():
    # fe80::1%eth0 — link-local with zone; zone stripped, result kept as-is.
    assert parse_bind_host("fe80::1%eth0") == "fe80::1"


def test_gateway_bind_ipv6_loopback_with_zone_id_not_flagged():
    # [::1%eth0]:8765 is still IPv6 loopback — zone ID must not cause a false FAIL.
    cfg = {"gateway": {"bind": "[::1%eth0]:8765", "auth": {"mode": "none"}}}
    assert check_gateway(_ctx(cfg)).status == "PASS"
