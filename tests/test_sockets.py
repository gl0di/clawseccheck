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

import os
import socket

from clawseccheck.sockets import (
    ListenSocket,
    ProcessIdentity,
    SocketScanResult,
    _decode_hex_addr,
    _parse_table,
    build_inode_index,
    classify_host,
    identify_listener_process,
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
    assert out == [ListenSocket(host="127.0.0.1", port=8765, family="inet", inode="10000")]


def test_parse_table_wildcard_listener():
    text = HEADER + "\n" + _row(_local("0.0.0.0", 8765))
    out = _parse_table(text, "inet")
    assert out[0].host == "0.0.0.0"


def test_parse_table_ipv6_loopback_listener():
    text = HEADER + "\n" + _row(_local("::1", 8765))
    out = _parse_table(text, "inet6")
    assert out == [ListenSocket(host="::1", port=8765, family="inet6", inode="10000")]


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
    assert out == [ListenSocket(host="127.0.0.1", port=22, family="inet", inode="10000")]


def test_parse_table_records_inode():
    text = HEADER + "\n" + _row(_local("127.0.0.1", 8765), inode=54321)
    out = _parse_table(text, "inet")
    assert out[0].inode == "54321"


def test_parse_table_short_row_has_no_inode():
    # A row with too few fields to reach the inode column must not raise, and must
    # leave inode "" rather than misreading a neighbouring field as the inode.
    local = _local("127.0.0.1", 8765)
    short_row = f"   0: {local} 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0"
    out = _parse_table(HEADER + "\n" + short_row, "inet")
    assert len(out) == 1
    assert out[0].inode == ""


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


# ---------------------------------------------------------------------------
# identify_listener_process — C-135 bug 1: best-effort PID/process correlation.
# Fake /proc/<pid>/fd + comm/cmdline built under tmp_path; the "socket:[inode]" fd
# symlink targets are the same magic (non-dereferenced) strings the real kernel
# exposes, so a dangling os.symlink target is realistic, not a test shortcut.
# ---------------------------------------------------------------------------

def _make_pid(
    root,
    pid: str,
    fd_targets: dict,
    comm: "str | None" = None,
    cmdline: "bytes | None" = None,
    exe: "str | None" = None,
):
    fd_dir = root / pid / "fd"
    fd_dir.mkdir(parents=True, exist_ok=True)
    for fd_num, target in fd_targets.items():
        os.symlink(target, fd_dir / str(fd_num))
    if comm is not None:
        (root / pid / "comm").write_text(comm, encoding="utf-8")
    if cmdline is not None:
        (root / pid / "cmdline").write_bytes(cmdline)
    if exe is not None:
        os.symlink(exe, root / pid / "exe")


def test_identify_listener_process_resolves_via_comm(tmp_path):
    _make_pid(tmp_path, "1234", {5: "socket:[999]"}, comm="docker-proxy\n")
    identity = identify_listener_process("999", proc_root=tmp_path)
    assert identity == ProcessIdentity(pid="1234", name="docker-proxy")


def test_identify_listener_process_falls_back_to_cmdline_when_comm_absent(tmp_path):
    _make_pid(tmp_path, "4321", {3: "socket:[555]"}, cmdline=b"/usr/sbin/nginx\x00-g\x00daemon off;\x00")
    identity = identify_listener_process("555", proc_root=tmp_path)
    assert identity == ProcessIdentity(
        pid="4321", name="nginx", cmdline="/usr/sbin/nginx -g daemon off;"
    )


def test_identify_listener_process_no_matching_inode_returns_none(tmp_path):
    _make_pid(tmp_path, "1234", {5: "socket:[999]"}, comm="docker-proxy\n")
    assert identify_listener_process("111", proc_root=tmp_path) is None


def test_identify_listener_process_empty_inode_returns_none(tmp_path):
    assert identify_listener_process("", proc_root=tmp_path) is None


def test_identify_listener_process_non_numeric_inode_returns_none(tmp_path):
    assert identify_listener_process("not-a-number", proc_root=tmp_path) is None


def test_identify_listener_process_ambiguous_names_returns_none(tmp_path):
    # Two different PIDs both appear to hold the same inode but disagree on process
    # name -- genuine ambiguity, must never be resolved by guessing.
    _make_pid(tmp_path, "111", {5: "socket:[999]"}, comm="docker-proxy\n")
    _make_pid(tmp_path, "222", {5: "socket:[999]"}, comm="nginx\n")
    assert identify_listener_process("999", proc_root=tmp_path) is None


def test_identify_listener_process_consistent_across_forked_workers(tmp_path):
    # Multiple PIDs sharing one inode (a pre-forking server's workers inheriting the
    # listening socket) that all agree on the SAME name is not ambiguous.
    _make_pid(tmp_path, "111", {5: "socket:[999]"}, comm="node\n")
    _make_pid(tmp_path, "222", {5: "socket:[999]"}, comm="node\n")
    identity = identify_listener_process("999", proc_root=tmp_path)
    assert identity is not None
    assert identity.name == "node"
    assert identity.pid in ("111", "222")


def test_identify_listener_process_unreadable_fd_dir_is_skipped_not_raised(tmp_path):
    # Simulate an inaccessible /proc/<pid>/fd (a real PermissionError reading another
    # UID's process) by making "fd" a plain file, not a directory -- iterdir() raises
    # NotADirectoryError (an OSError subclass), which must be swallowed, not propagated,
    # and must not stop the scan from finding the real match elsewhere.
    (tmp_path / "555").mkdir(parents=True)
    (tmp_path / "555" / "fd").write_text("not a directory", encoding="utf-8")
    _make_pid(tmp_path, "666", {5: "socket:[999]"}, comm="docker-proxy\n")
    identity = identify_listener_process("999", proc_root=tmp_path)
    assert identity == ProcessIdentity(pid="666", name="docker-proxy")


def test_identify_listener_process_proc_root_missing_returns_none(tmp_path):
    assert identify_listener_process("999", proc_root=tmp_path / "does-not-exist") is None


def test_identify_listener_process_pid_found_but_unnameable_returns_none(tmp_path):
    # The owning PID resolves, but neither comm nor cmdline can be read -- inconclusive.
    _make_pid(tmp_path, "777", {5: "socket:[999]"})
    assert identify_listener_process("999", proc_root=tmp_path) is None


# ---------------------------------------------------------------------------
# build_inode_index / identify_listener_process(index=...) -- B-374 follow-up
# (C-135 round 2, 2026-07-31): one /proc walk resolving several sockets' owning
# processes at once, instead of one scan per inode.
# ---------------------------------------------------------------------------

def test_build_inode_index_resolves_via_index_same_as_direct_scan(tmp_path):
    _make_pid(tmp_path, "1234", {5: "socket:[999]"}, comm="docker-proxy\n")
    index = build_inode_index(proc_root=tmp_path)
    identity = identify_listener_process("999", proc_root=tmp_path, index=index)
    assert identity == ProcessIdentity(pid="1234", name="docker-proxy", cmdline="")


def test_build_inode_index_resolves_cmdline_too(tmp_path):
    _make_pid(
        tmp_path,
        "4321",
        {3: "socket:[555]"},
        comm="node\n",
        cmdline=b"/usr/bin/node\x00/home/user/.openclaw/dist/cli.js\x00",
    )
    index = build_inode_index(proc_root=tmp_path)
    identity = identify_listener_process("555", proc_root=tmp_path, index=index)
    assert identity.pid == "4321"
    assert identity.name == "node"
    assert identity.cmdline == "/usr/bin/node /home/user/.openclaw/dist/cli.js"


def test_build_inode_index_one_pid_multiple_sockets(tmp_path):
    _make_pid(
        tmp_path, "10", {5: "socket:[100]", 6: "socket:[200]"}, comm="multi-listener\n"
    )
    index = build_inode_index(proc_root=tmp_path)
    assert index["100"] == [("10", "multi-listener")]
    assert index["200"] == [("10", "multi-listener")]


def test_build_inode_index_ambiguous_names_via_index_returns_none(tmp_path):
    _make_pid(tmp_path, "111", {5: "socket:[999]"}, comm="docker-proxy\n")
    _make_pid(tmp_path, "222", {5: "socket:[999]"}, comm="nginx\n")
    index = build_inode_index(proc_root=tmp_path)
    assert identify_listener_process("999", proc_root=tmp_path, index=index) is None


def test_build_inode_index_empty_when_no_inode_matches(tmp_path):
    _make_pid(tmp_path, "1234", {5: "socket:[999]"}, comm="docker-proxy\n")
    index = build_inode_index(proc_root=tmp_path)
    assert identify_listener_process("111", proc_root=tmp_path, index=index) is None


def test_build_inode_index_unreadable_fd_dir_is_skipped_not_raised(tmp_path):
    (tmp_path / "555").mkdir(parents=True)
    (tmp_path / "555" / "fd").write_text("not a directory", encoding="utf-8")
    _make_pid(tmp_path, "666", {5: "socket:[999]"}, comm="docker-proxy\n")
    index = build_inode_index(proc_root=tmp_path)
    assert index == {"999": [("666", "docker-proxy")]}


def test_build_inode_index_proc_root_missing_returns_empty_dict(tmp_path):
    assert build_inode_index(proc_root=tmp_path / "does-not-exist") == {}


def test_build_inode_index_skips_pid_with_unnameable_process(tmp_path):
    # The owning PID resolves, but neither comm nor cmdline can be read -- excluded
    # from the index entirely, matching identify_listener_process's own "inconclusive"
    # treatment for this shape.
    _make_pid(tmp_path, "777", {5: "socket:[999]"})
    index = build_inode_index(proc_root=tmp_path)
    assert index == {}


# ---------------------------------------------------------------------------
# B-400: ProcessIdentity.exe / _process_exe -- the resolved target of
# /proc/<pid>/exe, read via both the direct scan and the build_inode_index(index=...)
# path. Unlike comm/cmdline this is never attacker-controlled argv text -- see
# checks/_config.py's _classify_listener_identity for why that distinction matters.
# ---------------------------------------------------------------------------

def test_identify_listener_process_resolves_exe_directly(tmp_path):
    _make_pid(tmp_path, "42", {3: "socket:[7]"}, comm="node\n", exe="/usr/bin/node")
    identity = identify_listener_process("7", proc_root=tmp_path)
    assert identity is not None
    assert identity.exe == "/usr/bin/node"


def test_identify_listener_process_resolves_exe_via_index(tmp_path):
    _make_pid(tmp_path, "42", {3: "socket:[7]"}, comm="node\n", exe="/usr/bin/node")
    index = build_inode_index(proc_root=tmp_path)
    identity = identify_listener_process("7", proc_root=tmp_path, index=index)
    assert identity is not None
    assert identity.exe == "/usr/bin/node"


def test_identify_listener_process_exe_absent_leaves_it_empty(tmp_path):
    # No exe= given -- /proc/<pid>/exe does not exist in the fake root, matching a
    # process this caller has no permission to read (the common, expected case).
    _make_pid(tmp_path, "42", {3: "socket:[7]"}, comm="node\n")
    identity = identify_listener_process("7", proc_root=tmp_path)
    assert identity is not None
    assert identity.exe == ""


def test_identify_listener_process_exe_deleted_suffix_is_stripped(tmp_path):
    # Linux appends " (deleted)" to readlink(2)'s result when the executed file's
    # inode no longer exists at that path (e.g. an in-place upgrade after exec).
    fd_dir = tmp_path / "42" / "fd"
    fd_dir.mkdir(parents=True)
    os.symlink("socket:[7]", fd_dir / "3")
    (tmp_path / "42" / "comm").write_text("node\n", encoding="utf-8")
    os.symlink("/usr/bin/node (deleted)", tmp_path / "42" / "exe")
    identity = identify_listener_process("7", proc_root=tmp_path)
    assert identity is not None
    assert identity.exe == "/usr/bin/node"


def test_process_exe_missing_proc_root_returns_empty_string(tmp_path):
    from clawseccheck.sockets import _process_exe

    assert _process_exe("42", tmp_path / "does-not-exist") == ""
