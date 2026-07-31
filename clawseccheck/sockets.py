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

**C-135 bug-1 addendum (independent review, 2026-07-30 — live-reproduced on this very
machine)**: matching a listener to ``gateway.bind`` by PORT NUMBER ALONE has its own
false-positive-FAIL mode — an entirely unrelated process can happen to bind the exact
same port number on a different interface (reproduced live: Docker's userland proxy
bound to ``0.0.0.0:8080`` for a published container port, sharing that number with
``fixtures/home_safe``'s correctly-configured loopback-only ``gateway.bind``).
:func:`identify_listener_process` adds a best-effort, still fully read-only
process-identity correlation for exactly that case: it reads the LISTEN socket's own
``inode`` (the ``/proc/net/tcp{,6}`` column this module already parses) and scans
``/proc/*/fd/*`` for the ``socket:[inode]`` symlink that names which PID holds it, then
reads that PID's ``comm``/``cmdline``. A ``PermissionError`` reading another UID's
``/proc/<pid>/fd`` is the normal, expected case (most processes are not readable by an
unprivileged caller) and is silently skipped, never surfaced as an error — this stays
just as read-only and privilege-free as the rest of the module. This module still
names no verdict: it returns a process identity or ``None``, never "the gateway" or
"not the gateway" — that judgement belongs to the check that knows what "the gateway"
means (``checks/_config.py``'s ``check_effective_bind``).

**B-374 follow-up (C-135 round 2, 2026-07-31)**: the ORIGINAL C-135 bug-1 fix above
only ever DOWNGRADED a FAIL, and only on positive evidence of a non-gateway process —
any unresolved identity (permission denied, no matching inode, disagreeing names) kept
the FAIL, which is itself a false-positive-FAIL mode (an unproven guess in the FAIL
direction). ``check_effective_bind`` no longer treats "unattributable" as "keep
FAIL" — see its own docstring. Two additions here support that: ``ProcessIdentity``
now also carries ``cmdline`` (``comm`` alone is just ``"node"`` for every Node.js
process, which cannot positively identify OpenClaw's own gateway process among them;
the invoking script's path usually can), and :func:`build_inode_index` lets a caller
resolve several listeners' identities from ONE ``/proc`` walk instead of one scan per
socket (``identify_listener_process``'s optional *index* parameter).

Injectable for tests: ``scan_listening_sockets(proc_root=...)`` lets tests point at a
fake filesystem root (pytest's ``tmp_path``) so the suite stays offline, deterministic,
and never opens a real socket or reads outside ``tmp_path``. ``identify_listener_process``
and ``build_inode_index`` take the same ``proc_root`` for the same reason.
"""
from __future__ import annotations

import ipaddress
import os
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
    # /proc/net/tcp{,6}'s `inode` column (decimal, as text) -- "" when the row had too
    # few fields to read one, or the field was non-numeric. Feeds identify_listener_process()
    # for best-effort PID correlation (C-135 bug 1); a default so every existing caller
    # that builds a ListenSocket without one (every test predating this field) is unaffected.
    inode: str = ""


@dataclass(frozen=True)
class ProcessIdentity:
    """A best-effort PID + process-name correlation for one listening socket's inode.

    Resolved by scanning /proc/*/fd for the specific socket:[inode] symlink that names
    which PID holds THIS socket (never by listing all sockets a PID holds), then reading
    that PID's comm (preferred) or the argv[0] basename from its cmdline. Carries no
    verdict of its own -- a caller decides what a given name implies.

    ``cmdline`` (B-374 follow-up, C-135 round 2, 2026-07-31): the resolved PID's FULL
    command line, args re-joined with spaces, best-effort/lenient-decoded, empty string
    when unreadable. ``name`` (``comm``) alone is just ``"node"`` for every Node.js
    process on the box -- it cannot tell OpenClaw's own gateway process apart from any
    other Node process. The invoking script's path (argv[1], e.g.
    ``/home/user/.openclaw/dist/cli.js``) usually names the package that launched it,
    which is the signal a caller can actually use to positively identify OpenClaw
    itself (see ``checks/_config.py``'s ``_classify_listener_identity``). Defaulted so
    every existing caller that builds a ``ProcessIdentity`` without one (every test
    predating this field) is unaffected.
    """

    pid: str
    name: str
    cmdline: str = ""


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
        # inode is field index 9 (sl, local, rem, st, tx:rx, tr:tm, retrnsmt, uid,
        # timeout, inode, ...) -- decimal, unlike the hex address/port fields above.
        # Missing/non-numeric is left as "" rather than raised: one short/odd row must
        # only cost the PID-correlation feature for that row, never the whole scan.
        inode = parts[9] if len(parts) > 9 and parts[9].isdigit() else ""
        out.append(ListenSocket(host=host, port=port, family=family, inode=inode))
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


def _process_name(pid: str, root: Path) -> "str | None":
    """Best-effort name for *pid*: ``comm`` (preferred, already just the short executable
    name) falling back to the ``argv[0]`` basename from ``cmdline``. ``None`` when
    neither can be read -- a vanished process, or one this caller has no permission to
    inspect (both normal, expected outcomes, never raised as an error)."""
    try:
        name = (root / pid / "comm").read_text(encoding="utf-8", errors="replace").strip()
        if name:
            return name
    except OSError:
        pass
    try:
        raw = (root / pid / "cmdline").read_bytes()
    except OSError:
        return None
    argv0 = raw.split(b"\x00", 1)[0]
    if not argv0:
        return None
    return Path(argv0.decode("utf-8", errors="replace")).name or None


def _process_cmdline(pid: str, root: Path) -> str:
    """Best-effort FULL command line for *pid*: NUL-separated ``/proc/<pid>/cmdline``
    args re-joined with spaces, decoded leniently. Empty string when unreadable (a
    vanished process, or one this caller has no permission to inspect -- both normal,
    expected outcomes, never raised as an error). See :class:`ProcessIdentity`'s
    ``cmdline`` field for why this is read in addition to :func:`_process_name`."""
    try:
        raw = (root / pid / "cmdline").read_bytes()
    except OSError:
        return ""
    parts = [p for p in raw.split(b"\x00") if p]
    return " ".join(p.decode("utf-8", errors="replace") for p in parts)


def build_inode_index(proc_root: "str | Path" = "/proc") -> "dict[str, list[tuple[str, str]]]":
    """One ``/proc`` walk building an ``inode -> [(pid, name), ...]`` index, so a
    caller that needs to attribute MULTIPLE listening sockets in one go (e.g.
    ``check_effective_bind`` corroborating several non-loopback listeners on the same
    declared port) does the ``/proc/*/fd`` scan ONCE instead of once per socket.

    Read-only, stdlib-only, no subprocess -- identical ``OSError``/``PermissionError``
    tolerance as :func:`identify_listener_process`: a process this caller cannot read
    (most processes, normally, since ``/proc/<pid>/fd`` of another UID is not readable
    by an unprivileged caller) is silently skipped, never surfaced as an error. A PID
    that owns multiple sockets contributes to multiple inode buckets from the one fd
    listing already read for it. Pass the result to :func:`identify_listener_process`
    via its *index* parameter; omitting *index* there does its own, equivalent, one-off
    scan instead (unchanged, pre-existing behavior).
    """
    root = Path(proc_root)
    index: "dict[str, list[tuple[str, str]]]" = {}
    try:
        pid_dirs = [p for p in root.iterdir() if p.name.isdigit()]
    except OSError:
        return index
    for pid_dir in pid_dirs:
        try:
            fds = list((pid_dir / "fd").iterdir())
        except OSError:
            continue  # permission denied / vanished process -- normal, not an error
        inodes: "list[str]" = []
        for fd in fds:
            try:
                link = os.readlink(fd)
            except OSError:
                continue
            if link.startswith("socket:[") and link.endswith("]"):
                candidate = link[len("socket:[") : -1]
                if candidate.isdigit():
                    inodes.append(candidate)
        if not inodes:
            continue
        name = _process_name(pid_dir.name, root)
        if name is None:
            continue  # found the owning PID but can't name it -- inconclusive, skip
        for inode in inodes:
            index.setdefault(inode, []).append((pid_dir.name, name))
    return index


def identify_listener_process(
    inode: str,
    proc_root: "str | Path" = "/proc",
    index: "dict[str, list[tuple[str, str]]] | None" = None,
) -> "ProcessIdentity | None":
    """Best-effort PID/process-name(+cmdline) correlation for one listening socket's
    *inode*.

    Read-only, no subprocess, no elevated privileges: scans ``<proc_root>/<pid>/fd/*``
    for the ``socket:[inode]`` symlink that names which PID holds this exact socket,
    then reads that PID's name (see :func:`_process_name`) and full command line (see
    :func:`_process_cmdline`, populating :class:`ProcessIdentity`'s ``cmdline`` field).

    *index*: an optional pre-built :func:`build_inode_index` result. When given, this
    looks the inode up in that index instead of re-walking ``/proc`` -- lets a caller
    that needs to resolve several inodes in one call do the walk exactly once. Omitting
    *index* (the default, ``None``) reproduces the exact original one-off-scan
    behavior, unaffected -- every pre-existing caller/test is unaffected.

    Returns ``None`` -- "unresolved or inconclusive", never a guess -- when: *inode* is
    empty/non-numeric; the process listing itself can't be read; no ``fd`` symlink
    anywhere resolves to this inode (very commonly because the owning process belongs
    to another user and its ``/proc/<pid>/fd`` is not readable by us -- an expected
    ``PermissionError``, silently skipped, not a fault); the matched PID's name can't be
    read either; or more than one matched PID disagrees on the process name (genuine
    ambiguity -- never resolved by guessing). Multiple PIDs sharing the same inode that
    all agree on the SAME name (e.g. a pre-forking server's worker processes inheriting
    one listening socket) is NOT treated as ambiguous -- that shape is resolved to that
    one consistent identity.
    """
    if not inode or not str(inode).isdigit():
        return None
    inode = str(inode)
    root = Path(proc_root)

    if index is not None:
        entries = index.get(inode, [])
        if not entries:
            return None
        names = {name for _pid, name in entries}
        if len(names) > 1:
            return None  # different PIDs naming different processes -- genuinely ambiguous
        pid, name = entries[0]
        return ProcessIdentity(pid=pid, name=name, cmdline=_process_cmdline(pid, root))

    target = f"socket:[{inode}]"
    try:
        pid_dirs = [p for p in root.iterdir() if p.name.isdigit()]
    except OSError:
        return None
    identity: "ProcessIdentity | None" = None
    for pid_dir in pid_dirs:
        try:
            fds = list((pid_dir / "fd").iterdir())
        except OSError:
            continue  # permission denied / vanished process -- normal, not an error
        matched = False
        for fd in fds:
            try:
                link = os.readlink(fd)
            except OSError:
                continue
            if link == target:
                matched = True
                break
        if not matched:
            continue
        name = _process_name(pid_dir.name, root)
        if name is None:
            return None  # found the owning PID but can't name it -- inconclusive
        if identity is None:
            identity = ProcessIdentity(pid=pid_dir.name, name=name)
        elif name != identity.name:
            return None  # different PIDs naming different processes -- genuinely ambiguous
    if identity is None:
        return None
    return ProcessIdentity(
        pid=identity.pid, name=identity.name, cmdline=_process_cmdline(identity.pid, root)
    )
