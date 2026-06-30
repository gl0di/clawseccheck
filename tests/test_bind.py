"""BLK-02 regression: IPv6-aware gateway bind parsing.

The old `str(bind).split(':')[0]` mangled IPv6: '::' became '' (matched LOOPBACK,
so a publicly-bound gateway was reported safe) and '[::1]:port' became '[' (a
loopback bind was wrongly flagged exposed). `parse_bind_host` fixes both.
"""
from pathlib import Path

from clawseccheck.checks import check_gateway, check_tls, parse_bind_host
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


# ---- B11: additional check_tls verdict paths ----

def test_b11_loopback_bind_tight_perms_passes():
    # loopback bind + tight perms (config_mode=0o600) -> no exposure, no loose perms -> PASS
    cfg = {"gateway": {"bind": "127.0.0.1:9000"}}
    ctx = _ctx(cfg)
    ctx.config_mode = 0o600
    assert check_tls(ctx).status == "PASS"


def test_b11_no_bind_tight_perms_passes():
    # empty bind resolves to "" which is in LOOPBACK -> PASS
    ctx = _ctx({})
    ctx.config_mode = 0o600
    assert check_tls(ctx).status == "PASS"


def test_b11_non_loopback_tls_enabled_passes():
    # non-loopback bind but TLS enabled -> exposure risk mitigated -> PASS
    cfg = {"gateway": {"bind": "0.0.0.0:9000", "tls": {"enabled": True}}}
    ctx = _ctx(cfg)
    ctx.config_mode = 0o600
    assert check_tls(ctx).status == "PASS"


def test_b11_explicit_non_loopback_no_tls_warns():
    # simple non-loopback bind without TLS -> WARN (no tailscale or other mode involved)
    cfg = {"gateway": {"bind": "0.0.0.0:9000"}}
    ctx = _ctx(cfg)
    ctx.config_mode = 0o600
    f = check_tls(ctx)
    assert f.status == "WARN"
    assert "non-loopback" in f.detail


def test_b11_loose_perms_loopback_bind_warns():
    # loopback bind (no network exposure) but config file is group-readable -> WARN
    cfg = {"gateway": {"bind": "127.0.0.1:9000"}}
    ctx = _ctx(cfg)
    ctx.config_mode = 0o644   # group-readable: 0o077 & 0o644 = 0o044 != 0 -> loose
    f = check_tls(ctx)
    assert f.status == "WARN"
    assert "readable" in f.detail or "group" in f.detail or "perms" in f.detail or "openclaw.json" in f.detail


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


# ---- B-034: B11 fires on non-loopback bind without TLS ----

def test_b11_private_ip_no_tls_warns():
    """B-034: B11 WARNs on a non-loopback private IP bind without TLS configured."""
    cfg = {"gateway": {"bind": "192.168.1.10:9000"}}
    ctx = _ctx(cfg)
    ctx.config_mode = 0o600
    f = check_tls(ctx)
    assert f.status == "WARN"
    assert "non-loopback" in f.detail


def test_b11_loopback_no_tls_required_passes():
    """B-034: loopback bind is the clean control — B11 passes without TLS when bind is local."""
    cfg = {"gateway": {"bind": "127.0.0.1:9000"}}
    ctx = _ctx(cfg)
    ctx.config_mode = 0o600
    assert check_tls(ctx).status == "PASS"
