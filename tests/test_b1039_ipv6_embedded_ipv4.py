"""B-1039 follow-up -- an IPv6 literal that EMBEDS a public IPv4 (IPv4-mapped, IPv4-compatible,
6to4) used to be called local through stdlib `is_private` / `is_reserved`, whose answers also
differ across Python 3.10-3.14. That cleared B103's plaintext-transport FAIL and raw-IP FAIL.
Local is now affirmed by explicit arithmetic only: `::1`, `::`, fe80::/10, fc00::/7, or an
embedded IPv4 that `_ipv4_class` calls local/documentation. Reserved, multicast, Teredo and
global space are never local.
"""
from __future__ import annotations

import pytest

from clawseccheck.checks._content import (
    _install_entry_findings,
    _install_host_is_local,
    _install_host_is_public_ip,
)

EMBEDDED_PUBLIC = (
    "::ffff:8.8.8.8",
    "::ffff:808:808",
    "::8.8.8.8",
    "::808:808",
    "2002:808:808::1",
    "::ffff:0:8.8.8.8",
    "::ffff:100.100.100.200",  # RFC 6598 shared space is off-host, not local
)
NOT_LOCAL_OTHER = (
    "ff02::1",  # multicast
    "ff00::",
    "100::1",  # reserved/discard
    "2001:0:4136:e378:8000:63bf:3fff:fdd2",  # Teredo
    "2606:4700::1111",  # global
    "64:ff9b::808:808",  # NAT64 embedding a public v4
    "::2:0:0:0",
)
LOCAL = (
    "::1",
    "::",
    "fe80::1",
    "fe80::1%eth0",
    "fd00::1",
    "fc00::1",
    "::ffff:127.0.0.1",
    "::ffff:7f00:1",
    "::ffff:192.168.1.5",
    "::127.0.0.1",
    "2002:7f00:1::1",
    "2002:c0a8:101::1",
)


@pytest.mark.parametrize("host", EMBEDDED_PUBLIC + NOT_LOCAL_OTHER)
def test_ipv6_off_host_literal_is_not_local_and_reaches_off_host(host):
    assert not _install_host_is_local(host)
    assert not _install_host_is_local(f"[{host}]")
    assert _install_host_is_public_ip(host)


@pytest.mark.parametrize("host", LOCAL)
def test_ipv6_local_literal_is_local_and_not_public(host):
    assert _install_host_is_local(host)
    assert not _install_host_is_public_ip(host)


@pytest.mark.parametrize("host", EMBEDDED_PUBLIC)
def test_b103_fails_on_embedded_public_ipv4(host):
    for scheme in ("http", "https"):
        entry = {"id": "a", "kind": "download", "url": f"{scheme}://[{host}]/p.tar.gz"}
        fails = _install_entry_findings("s", [entry])
        assert fails, (scheme, host)


@pytest.mark.parametrize("host", ("::ffff:127.0.0.1", "::1", "fe80::1", "fd00::1"))
def test_b103_stays_quiet_for_local_ipv6_over_https(host):
    entry = {"id": "a", "kind": "download", "url": f"https://[{host}]/p.tar.gz"}
    assert not _install_entry_findings("s", [entry])
