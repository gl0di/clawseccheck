"""sockets.py — read-only /proc/net/tcp{,6} listening-socket enumeration (F-156).

All tests are offline and deterministic: they build a fake ``/proc`` root under
pytest's ``tmp_path`` and point ``scan_listening_sockets`` at it directly. Nothing
here opens a real socket, reads outside ``tmp_path``, or touches the real machine's
``/proc``.

Fixture rows are built with ``_hex_ipv4``/``_hex_ipv6`` — an INDEPENDENT encoder using
``socket.inet_aton``/``inet_pton`` (stdlib byte-swap, not this module's own decoder) —
so the tests do not just check the decoder against itself.
"""
from __future__ import annotations

import socket

from clawseccheck.sockets import (
    ListenSocket,
    SocketScanResult,
    _decode_hex_addr,
    _parse_table,
    classify_host,
    listeners_for_port,
    scan_listening_sockets,
)

HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"


def _hex_ipv4(ip: str) -> str:
    return bytes(reversed(socket.inet_aton(ip))).hex().upper()


def _hex_ipv6(ip: str) -> str:
    raw = socket.inet_pton(socket.AF_INET6, ip)
    out = bytearray()
    for i in range(0, 16, 4):
        out.extend(reversed(raw[i : i + 4]))
    return bytes(out).hex().upper()


def _local(ip: str, port: int) -> str:
    hexip = _hex_ipv6(ip) if ":" in ip else _hex_ipv4(ip)
    return f"{hexip}:{port:04X}"


def _row(local: str, rem: str = "00000000:0000", state: str = "0A", sl: int = 0, inode: int = 10000) -> str:
    return (
        f"   {sl}: {local} {rem} {state} 00000000:00000000 "
        f"00:00000000 00000000  1000        0 {inode} 1 0000000000000000 100 0 0 10 0"
    )


def _write(root, rel, lines):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# _decode_hex_addr / classify_host — pure unit tests
# ---------------------------------------------------------------------------

def test_decode_hex_addr_ipv4_loopback():
    assert _decode_hex_addr(_hex_ipv4("127.0.0.1")) == bytes([127, 0, 0, 1])


def test_decode_hex_addr_ipv4_wildcard():
    assert _decode_hex_addr(_hex_ipv4("0.0.0.0")) == bytes([0, 0, 0, 0])


def test_decode_hex_addr_ipv6_loopback():
    assert _decode_hex_addr(_hex_ipv6("::1")) == (b"\x00" * 15 + b"\x01")


def test_decode_hex_addr_rejects_bad_length():
    import pytest

    with pytest.raises(ValueError):
        _decode_hex_addr("ABC")  # not a multiple of 8


def test_decode_hex_addr_rejects_non_hex():
    import pytest

    with pytest.raises(ValueError):
        _decode_hex_addr("ZZZZZZZZ")


def test_classify_host_loopback_v4():
    assert classify_host("127.0.0.1") == "loopback"


def test_classify_host_loopback_v6():
    assert classify_host("::1") == "loopback"


def test_classify_host_wildcard_v4():
    assert classify_host("0.0.0.0") == "wildcard"


def test_classify_host_wildcard_v6():
    assert classify_host("::") == "wildcard"


def test_classify_host_specific():
    assert classify_host("192.168.1.5") == "specific"


def test_classify_host_ipv4_mapped_loopback():
    # Same reasoning as checks/_shared.py's LOOPBACK set: a v4-mapped IPv6 loopback
    # is genuinely loopback, not "specific".
    assert classify_host("::ffff:127.0.0.1") == "loopback"


def test_classify_host_unknown_on_garbage():
    assert classify_host("not-an-ip") == "unknown"


# ---------------------------------------------------------------------------
# _parse_table — row-level parsing
# ---------------------------------------------------------------------------

def test_parse_table_loopback_listener():
    text = HEADER + "\n" + _row(_local("127.0.0.1", 8765))
    out = _parse_table(text, "inet")
    assert out == [ListenSocket(host="127.0.0.1", port=8765, family="inet")]


def test_parse_table_wildcard_listener():
    text = HEADER + "\n" + _row(_local("0.0.0.0", 8765))
    out = _parse_table(text, "inet")
    assert out[0].host == "0.0.0.0"


def test_parse_table_ipv6_loopback_listener():
    text = HEADER + "\n" + _row(_local("::1", 8765))
    out = _parse_table(text, "inet6")
    assert out == [ListenSocket(host="::1", port=8765, family="inet6")]


def test_parse_table_non_listen_state_is_ignored():
    # state 01 == TCP_ESTABLISHED — must never surface as a listener.
    text = HEADER + "\n" + _row(_local("10.0.0.5", 443), state="01")
    assert _parse_table(text, "inet") == []


def test_parse_table_empty_table_returns_no_listeners():
    text = HEADER + "\n"
    assert _parse_table(text, "inet") == []


def test_parse_table_malformed_line_is_skipped_not_raised():
    # Too few fields, then a non-hex address, both mixed in with one good row —
    # neither may raise, and the good row must still come through.
    good = _row(_local("127.0.0.1", 22))
    lines = [HEADER, "garbage short line", "1: ZZZZZZZZ:0016 00000000:0000 0A 00 00 00 0 0 1 1 0 0 0 0 0", good]
    out = _parse_table("\n".join(lines), "inet")
    assert out == [ListenSocket(host="127.0.0.1", port=22, family="inet")]


def test_parse_table_dual_stack_loopback_both_present():
    # F-156's explicit requirement: 127.0.0.1 + [::1] on the same port is the benign
    # dual-stack shape, not two separate exposures.
    v4 = _parse_table(HEADER + "\n" + _row(_local("127.0.0.1", 8765)), "inet")
    v6 = _parse_table(HEADER + "\n" + _row(_local("::1", 8765)), "inet6")
    combined = tuple(v4) + tuple(v6)
    assert len(combined) == 2
    assert all(classify_host(s.host) == "loopback" for s in combined)


# ---------------------------------------------------------------------------
# Regression test naming the competitor's bug (piti/openclaw-security-dashboard)
# ---------------------------------------------------------------------------

def test_peer_column_wildcard_never_produces_a_wildcard_finding():
    """A LISTEN row's rem_address (peer) column is ALWAYS 00000000:0000 (no specific
    peer) — this module must read ONLY local_address. A loopback listener with that
    ordinary wildcard peer column must classify as loopback, never wildcard, or a
    future refactor has reintroduced the peer-column bug the competitor shipped."""
    text = HEADER + "\n" + _row(_local("127.0.0.1", 18789), rem="00000000:0000")
    out = _parse_table(text, "inet")
    assert len(out) == 1
    assert classify_host(out[0].host) == "loopback"


# ---------------------------------------------------------------------------
# scan_listening_sockets — filesystem-level (tmp_path as a fake /proc root)
# ---------------------------------------------------------------------------

def test_scan_reads_both_tables(tmp_path):
    _write(tmp_path, "net/tcp", [HEADER, _row(_local("127.0.0.1", 8765))])
    _write(tmp_path, "net/tcp6", [HEADER, _row(_local("::1", 8765))])
    res = scan_listening_sockets(proc_root=tmp_path)
    assert res.available is True
    assert len(res.listeners) == 2
    assert {s.family for s in res.listeners} == {"inet", "inet6"}


def test_scan_empty_tables_is_available_with_no_listeners(tmp_path):
    _write(tmp_path, "net/tcp", [HEADER])
    _write(tmp_path, "net/tcp6", [HEADER])
    res = scan_listening_sockets(proc_root=tmp_path)
    assert res.available is True
    assert res.listeners == ()


def test_scan_one_missing_table_does_not_fail_the_scan(tmp_path):
    # IPv6 disabled on this kernel/container: tcp6 absent must not degrade IPv4 signal.
    _write(tmp_path, "net/tcp", [HEADER, _row(_local("127.0.0.1", 8765))])
    res = scan_listening_sockets(proc_root=tmp_path)
    assert res.available is True
    assert len(res.listeners) == 1


def test_scan_both_tables_missing_is_unavailable(tmp_path):
    res = scan_listening_sockets(proc_root=tmp_path / "does-not-exist")
    assert res.available is False
    assert res.reason
    assert res.listeners == ()


def test_scan_result_reason_mentions_both_files_when_unavailable(tmp_path):
    res = scan_listening_sockets(proc_root=tmp_path)
    assert "tcp" in res.reason and "tcp6" in res.reason


# ---------------------------------------------------------------------------
# listeners_for_port
# ---------------------------------------------------------------------------

def test_listeners_for_port_filters_by_port():
    result = SocketScanResult(
        available=True,
        listeners=(
            ListenSocket(host="127.0.0.1", port=8765, family="inet"),
            ListenSocket(host="0.0.0.0", port=80, family="inet"),
        ),
    )
    got = listeners_for_port(result, 8765)
    assert got == (ListenSocket(host="127.0.0.1", port=8765, family="inet"),)


def test_listeners_for_port_empty_when_no_match():
    result = SocketScanResult(available=True, listeners=())
    assert listeners_for_port(result, 8765) == ()
