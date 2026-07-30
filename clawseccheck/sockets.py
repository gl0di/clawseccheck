"""Read-only enumeration of the host's actual listening TCP sockets.

Every gateway-exposure verdict elsewhere in this package (B2, B70, ...) is
**declared-state only** — it reads ``gateway.bind`` out of the config and reasons
about that string. It never checks what the process is *actually* listening on. This
module supplies the one runtime signal that closes that gap: it enumerates real
``LISTEN``-state TCP sockets so a check can corroborate (or contradict) the declared
bind (F-156).

Doctrine (matches ``hostwatch.py``'s "no subprocess, no network"): on Linux this reads
``/proc/net/tcp`` and ``/proc/net/tcp6`` directly — plain text, world-readable, no
privileges required to read a bind address (only socket-to-PID mapping needs
``/proc/*/fd``, which nothing here touches). No subprocess is ever run. Where ``/proc``
is unavailable (macOS, Windows, a container without it mounted, or simply missing) this
degrades to an honest "unavailable" result — never a guess (B-172 doctrine). A later
revision MAY add a subprocess-based fallback (e.g. parsing ``lsof -F`` machine-readable
output under ``native.py``'s ``_untrusted_exec_reason`` guard); this module does not,
so the "no subprocess" property holds for every caller today.

**The one bug this module is designed to structurally rule out**: a competitor tool
(piti/openclaw-security-dashboard, reviewed 2026-07-29) ran ``ss -tlnp | grep :$PORT``
and regexed the WHOLE output line for ``0.0.0.0``/``*``. ``ss -tlnp``'s line shape is
``LISTEN 0 511  127.0.0.1:18789  0.0.0.0:*  users:(...)`` — the trailing ``0.0.0.0:*`` is
the **peer** address:port column (sockets in LISTEN state have no specific peer), not the
bind. Their regex matched that peer wildcard on every Linux host and reported a loopback
listener as "bound to 0.0.0.0" — a spurious CRITICAL on a correctly-hardened box. This
module never reads a peer column at all: it parses ``/proc/net/tcp{,6}``'s fixed
``local_address`` field by position, and returns only that. See
``tests/test_sockets.py``'s regression test naming this exact bug.

Injectable for tests: ``scan_listening_sockets(proc_root=...)`` lets tests point at a
fake filesystem root (pytest's ``tmp_path``) so the suite stays offline, deterministic,
and never opens a real socket or reads outside ``tmp_path``.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

# TCP_LISTEN state code in /proc/net/tcp{,6}'s `st` column (kernel net/tcp_states.h:
# TCP_LISTEN = 10 decimal = 0x0A). Any other value (ESTABLISHED, TIME_WAIT, ...) is not
# a listening socket and is ignored.
_TCP_LISTEN = "0A"

# The two proc tables this module reads, and the address family each describes.
_TABLES = (("tcp", "inet"), ("tcp6", "inet6"))


@dataclass(frozen=True)
class ListenSocket:
    """One listening TCP socket, decoded from /proc/net/tcp{,6}'s local_address field."""

    host: str  # decoded bind address, e.g. "127.0.0.1", "0.0.0.0", "::1", "::"
    port: int
    family: str  # "inet" | "inet6"


@dataclass(frozen=True)
class SocketScanResult:
    """Outcome of one enumeration attempt.

    ``available=False`` means the scan produced no usable signal at all (neither proc
    table could be read) — a caller must treat every port as genuinely unmeasured, not
    "nothing is listening". ``available=True`` with an empty ``listeners`` tuple is a
    real, positive fact: at least one table was read successfully and it listed no
    LISTEN-state sockets.
    """

    available: bool
    reason: str = ""
    listeners: tuple[ListenSocket, ...] = field(default_factory=tuple)


def _decode_hex_addr(hexstr: str) -> bytes:
    """Decode a /proc/net/tcp{,6} hex address into raw network-order bytes.

    The kernel dumps each 32-bit word of the address in host byte order; on every
    architecture this package supports that word must be byte-swapped to recover the
    address in normal (network) byte order. IPv4 addresses are one word (8 hex chars =
    4 bytes); IPv6 addresses are four words (32 hex chars = 16 bytes), each swapped
    independently and concatenated in word order — this is what makes
    ``0100007F`` decode to ``127.0.0.1`` and an all-zero word stay all zero regardless
    of byte order (so ``::`` and ``0.0.0.0`` decode correctly without special-casing).

    Raises ``ValueError`` on malformed input (wrong length, non-hex characters) —
    callers must catch this per line, so one corrupt row never aborts the whole scan.
    """
    if len(hexstr) % 8 != 0 or not hexstr:
        raise ValueError(f"hex address length {len(hexstr)} is not a positive multiple of 8")
    out = bytearray()
    for i in range(0, len(hexstr), 8):
        word_bytes = bytes.fromhex(hexstr[i : i + 8])  # raises ValueError on non-hex
        out.extend(reversed(word_bytes))
    return bytes(out)


def classify_host(host: str) -> str:
    """Classify a decoded bind address as ``loopback`` / ``wildcard`` / ``specific``.

    ``unknown`` only if *host* does not parse as an IP literal at all (should not
    happen for a value this module itself decoded, but a caller-supplied string is
    handled defensively too). An IPv4-mapped IPv6 address (``::ffff:127.0.0.1``) is
    classified by its mapped IPv4 address, matching the reasoning
    ``checks/_shared.py``'s ``LOOPBACK`` set already uses for the declared-bind side.
    """
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return "unknown"
    mapped = getattr(addr, "ipv4_mapped", None)
    effective = mapped if mapped is not None else addr
    if effective.is_loopback:
        return "loopback"
    if effective.is_unspecified:
        return "wildcard"
    return "specific"


def _parse_table(text: str, family: str) -> list[ListenSocket]:
    """Parse one /proc/net/tcp{,6}-shaped table body.

    Malformed rows (too few fields, non-hex address, unparseable port) are skipped —
    never raised — so one corrupt line degrades that one row, not the whole scan. The
    header line and any non-LISTEN-state row are silently skipped too; only the
    `local_address` field is ever read (never `rem_address`) — see the module
    docstring for exactly why that distinction matters.
    """
    out: list[ListenSocket] = []
    for line in text.splitlines()[1:]:  # [0] is the header row
        parts = line.split()
        if len(parts) < 4:
            continue
        local, st = parts[1], parts[3]
        if st.upper() != _TCP_LISTEN:
            continue
        if ":" not in local:
            continue
        hexhost, _, hexport = local.rpartition(":")
        try:
            raw = _decode_hex_addr(hexhost)
            port = int(hexport, 16)
        except ValueError:
            continue
        try:
            if family == "inet":
                if len(raw) != 4:
                    continue
                host = str(ipaddress.IPv4Address(raw))
            else:
                if len(raw) != 16:
                    continue
                host = str(ipaddress.IPv6Address(raw))
        except ValueError:
            continue
        out.append(ListenSocket(host=host, port=port, family=family))
    return out


def scan_listening_sockets(proc_root: "str | Path" = "/proc") -> SocketScanResult:
    """Enumerate LISTEN-state TCP sockets from ``<proc_root>/net/tcp`` and ``.../tcp6``.

    Read-only, stdlib-only, no subprocess, no network. Each table is read
    independently: a kernel/container with IPv6 disabled has no ``tcp6`` file at all,
    which is not evidence about IPv4 (or vice versa) — only when BOTH tables are
    unreadable does the whole scan report ``available=False``.
    """
    root = Path(proc_root)
    listeners: list[ListenSocket] = []
    read_ok = 0
    errors: list[str] = []
    for fname, family in _TABLES:
        path = root / "net" / fname
        try:
            text = path.read_text(encoding="ascii", errors="replace")
        except OSError as exc:
            errors.append(f"{fname}: {exc.strerror or exc.__class__.__name__}")
            continue
        read_ok += 1
        listeners.extend(_parse_table(text, family))
    if read_ok == 0:
        reason = "neither /proc/net/tcp nor /proc/net/tcp6 could be read"
        if errors:
            reason += " (" + "; ".join(errors) + ")"
        return SocketScanResult(available=False, reason=reason)
    return SocketScanResult(available=True, listeners=tuple(listeners))


def listeners_for_port(result: SocketScanResult, port: int) -> "tuple[ListenSocket, ...]":
    """The subset of *result*'s listeners bound to *port*, across both families."""
    return tuple(sock for sock in result.listeners if sock.port == port)
