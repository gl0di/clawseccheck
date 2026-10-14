"""Continuous file-system watch mode (C-517): inotify with a stat-poll fallback.

`--monitor` (see monitor.py / monitordims/) is a ONE-SHOT poll: snapshot vs. the stored
baseline, invoked manually or via cron. This module adds a long-running companion that
notices a relevant filesystem change itself and re-runs the identical `--monitor` check
automatically, instead of waiting for the next scheduled invocation.

It deliberately does NOT reimplement drift detection. On a debounced change it shells out
to ``python3 -m clawseccheck --monitor --verbose ...`` - the same invocation
``scripts/monitor_detection_gate.py`` already uses to drive this tool from outside the
library - so the alert format, severity mapping and the tamper-evident event journal stay
the single implementation in monitordims/. This module only decides WHEN to trigger that
re-scan (inotify-driven, debounced) and whether the watcher process itself is still alive
(a heartbeat file under the caller's own store directory).

Mechanism choice - stdlib-only, no new runtime dependency: see
docs/design/watch-mechanism.md. Short version: a real inotify wrapper via ``ctypes``
against libc (``inotify_init1``/``inotify_add_watch``/``read``), with a stat-based
polling fallback for any platform or sandbox where the inotify syscalls are unavailable.
``probe_inotify()`` makes a real attempt rather than guessing from the platform name, and
the design note records that this was verified live on Linux, not assumed.

Read-only w.r.t. the audited home (Golden Rule #2): this module never writes under
*home*. Every file it writes (the heartbeat) lives under the caller-supplied store
directory - the same boundary ``--monitor`` already respects.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import errno
import json
import math
import os
import select
import signal
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path

from . import pathprobe
from .configloader import loads_bounded
from .invocation import _shim_beside_the_package, cmd
from .monitorstore import _now_iso
from .safeio import secure_dir, secure_write_text

try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:  # pragma: no cover - exercised on POSIX CI; real gap on Windows
    fcntl = None  # type: ignore[assignment]
    _HAS_FCNTL = False

# --------------------------------------------------------------------------- inotify
#
# Flags/masks from <sys/inotify.h> (stable Linux UAPI) - ctypes cannot include a C
# header, so these are restated as constants rather than reimplemented as a syscall.

IN_CLOEXEC = 0o02000000
IN_NONBLOCK = 0o00004000

IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
IN_ISDIR = 0x40000000

#: The task's requested mask, plus DELETE_SELF/MOVE_SELF so a watched directory itself
#: disappearing (rm -rf, a rename) is noticed instead of silently going quiet.
WATCH_MASK = (IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM
              | IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF | IN_ATTRIB)

_EVENT_HDR_FMT = "iIII"
_EVENT_HDR_SIZE = struct.calcsize(_EVENT_HDR_FMT)

_libc = None


class InotifyUnavailable(OSError):
    """The inotify syscalls cannot be used here (wrong platform, or a sandbox that
    refuses the syscall itself) - the trigger for falling back to PollWatcher."""


def _get_libc():
    """Bind the three libc functions this module needs, once. Never a platform-name
    assumption beyond the first, cheap check: `sys.platform` rules out the vast
    majority of non-Linux hosts before touching ctypes at all, but the ACTUAL proof
    that inotify works is the syscall attempt in `_inotify_init`, not this function."""
    global _libc
    if _libc is not None:
        return _libc
    if sys.platform != "linux":
        raise InotifyUnavailable(f"inotify is Linux-only (platform: {sys.platform})")
    name = ctypes.util.find_library("c") or "libc.so.6"
    try:
        lib = ctypes.CDLL(name, use_errno=True)
        lib.inotify_init1.restype = ctypes.c_int
        lib.inotify_init1.argtypes = [ctypes.c_int]
        lib.inotify_add_watch.restype = ctypes.c_int
        lib.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        lib.inotify_rm_watch.restype = ctypes.c_int
        lib.inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
    except (OSError, AttributeError) as exc:
        raise InotifyUnavailable(str(exc)) from exc
    _libc = lib
    return _libc


def _inotify_init() -> int:
    libc = _get_libc()
    fd = libc.inotify_init1(IN_CLOEXEC | IN_NONBLOCK)
    if fd < 0:
        errno = ctypes.get_errno()
        raise InotifyUnavailable(os.strerror(errno) or f"errno {errno}")
    return fd


def _inotify_add_watch(fd: int, path: Path, mask: int) -> int:
    libc = _get_libc()
    wd = libc.inotify_add_watch(fd, os.fsencode(str(path)), mask)
    if wd < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno) or f"errno {errno}", str(path))
    return wd


def _parse_inotify_events(buf: bytes) -> "list[tuple[int, int, int, bytes]]":
    """Every (wd, mask, cookie, name) packed into one `read()` of the inotify fd."""
    events = []
    pos = 0
    n = len(buf)
    while pos + _EVENT_HDR_SIZE <= n:
        wd, mask, cookie, name_len = struct.unpack_from(_EVENT_HDR_FMT, buf, pos)
        pos += _EVENT_HDR_SIZE
        name = b""
        if name_len:
            name = buf[pos:pos + name_len].split(b"\x00", 1)[0]
            pos += name_len
        events.append((wd, mask, cookie, name))
    return events


def probe_inotify() -> bool:
    """True when this platform/sandbox can actually create an inotify fd right now.

    A cheap, side-effect-free real syscall attempt (opens and immediately closes one
    fd) - never a platform-name guess. `sys.platform != "linux"` is the common fast
    exit, but a restricted Linux sandbox can also refuse the syscall itself, and only
    an actual attempt can see that.
    """
    try:
        fd = _inotify_init()
    except OSError:
        return False
    try:
        os.close(fd)
    except OSError:
        pass
    return True


# ---------------------------------------------------------------- bounded dir walk

#: Generous for a real OpenClaw home, but a pathological tree must not make watch
#: setup itself unbounded - same discipline as safeio.walk_dir_safely's max_files.
DEFAULT_MAX_WATCH_DIRS = 20_000


def _is_symlink(p: Path) -> bool:
    try:
        return pathprobe.is_symlink(p)
    except OSError:
        return False


def _bounded_watch_dirs(root: Path, max_dirs: int = DEFAULT_MAX_WATCH_DIRS
                        ) -> "tuple[list[Path], bool]":
    """Every directory under *root* (root included); symlinked directories are never
    followed (no cycles, no escaping *root*).

    Returns ``(dirs, capped)`` - ``capped`` is True when the tree holds more
    directories than *max_dirs* and the walk stopped short, so a caller can disclose a
    partial watch rather than silently watching only part of the tree.
    """
    try:
        resolved = root.resolve()
    except OSError:
        return [], False
    if not pathprobe.is_dir(resolved):
        return [], False
    dirs = [resolved]
    capped = False
    for dirpath, dirnames, _files in os.walk(resolved, topdown=True, followlinks=False):
        kept = [d for d in sorted(dirnames) if not _is_symlink(Path(dirpath) / d)]
        dirnames[:] = kept
        for d in list(dirnames):
            if len(dirs) >= max_dirs:
                capped = True
                dirnames[:] = []
                break
            dirs.append(Path(dirpath) / d)
        if capped:
            break
    return dirs, capped


# ------------------------------------------------------------------- watcher classes

class Watcher:
    """Common interface both mechanisms implement - the loop in run_watch() never
    branches on which one it got."""

    mode = "abstract"
    capped = False

    def poll_for_change(self, timeout: float) -> bool:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover - interface
        pass


class InotifyWatcher(Watcher):
    """Real, event-driven watch via ctypes + libc inotify.

    Recursive by hand - Linux inotify is not natively recursive: every existing
    subdirectory gets its own watch descriptor up front (`_bounded_watch_dirs`), and a
    directory that appears later (created or moved in) is watched together with every
    directory already below it (`_watch_new_tree`): `mkdir -p a/b/c`, `cp -r` and `mv`
    deliver ONE event for the top, with everything under it already in place.
    """

    mode = "inotify"

    def __init__(self, root: Path, max_dirs: int = DEFAULT_MAX_WATCH_DIRS):
        self._root = Path(root)
        self._fd = _inotify_init()
        self._wd_to_path: dict = {}
        self._max_dirs = max_dirs
        self.unreadable = 0
        self.overflowed = False
        dirs, self.capped = _bounded_watch_dirs(self._root, max_dirs)
        self._add_dirs(dirs)

    def _add_dirs(self, dirs) -> None:
        for d in dirs:
            try:
                self._wd_to_path[_inotify_add_watch(self._fd, d, WATCH_MASK)] = d
            except OSError:
                self.unreadable += 1

    def poll_for_change(self, timeout: float) -> bool:
        try:
            r, _w, _x = select.select([self._fd], [], [], max(0.0, timeout))
        except OSError:
            return False
        if not r:
            return False
        return self._drain()

    def _drain(self) -> bool:
        changed = False
        while True:
            try:
                buf = os.read(self._fd, 65536)
            except BlockingIOError:
                break
            except OSError:
                break
            if not buf:
                break
            for wd, mask, _cookie, name in _parse_inotify_events(buf):
                if mask & IN_Q_OVERFLOW:
                    # The kernel dropped events we could not read fast enough. Treat
                    # as a change unconditionally - under-reporting here would be a
                    # silent gap in exactly the surface this module exists to watch.
                    self.overflowed = True
                    changed = True
                    continue
                if mask & IN_IGNORED:
                    # The watch itself was removed (directory deleted/unmounted).
                    self._wd_to_path.pop(wd, None)
                    continue
                changed = True
                if (mask & (IN_CREATE | IN_MOVED_TO)) and (mask & IN_ISDIR):
                    parent = self._wd_to_path.get(wd)
                    if parent is not None:
                        self._watch_new_tree(parent / os.fsdecode(name))
        return changed

    def _watch_new_tree(self, top: Path) -> None:
        """Watch *top* and every real directory below it, within the start-up cap (no
        symlink is followed; passing the cap sets ``capped``, which the heartbeat shows)."""
        if _is_symlink(top):
            return
        room = self._max_dirs - len(self._wd_to_path)
        if room <= 0:
            self.capped = True
            return
        dirs, capped = _bounded_watch_dirs(top, room)
        self.capped = self.capped or capped
        self._add_dirs(dirs)

    def close(self) -> None:
        try:
            os.close(self._fd)
        except OSError:
            pass


class PollWatcher(Watcher):
    """Fallback: bounded stat-based polling (mtime + size), for a non-Linux platform
    or a sandbox where the inotify syscalls raise. Not a guess - `make_watcher` only
    reaches this after a real `InotifyWatcher()` construction attempt failed.
    """

    mode = "poll"

    def __init__(self, root: Path, max_files: int = DEFAULT_MAX_WATCH_DIRS,
                 poll_interval_s: float = 1.0):
        self._root = Path(root)
        self._max_files = max_files
        self._poll_interval_s = max(0.05, poll_interval_s)
        self._snapshot, self.capped = self._scan()

    def _scan(self) -> "tuple[dict, bool]":
        snap: dict = {}
        try:
            resolved = self._root.resolve()
        except OSError:
            return snap, False
        for dirpath, dirnames, filenames in os.walk(resolved, topdown=True, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if not _is_symlink(Path(dirpath) / d))
            for fn in sorted(filenames):
                p = Path(dirpath) / fn
                if _is_symlink(p):
                    continue
                try:
                    st = p.stat()
                except OSError:
                    continue
                snap[str(p)] = (st.st_mtime_ns, st.st_size)
                if len(snap) >= self._max_files:
                    return snap, True
        return snap, False

    def poll_for_change(self, timeout: float) -> bool:
        time.sleep(min(max(0.0, timeout), self._poll_interval_s))
        new_snap, capped = self._scan()
        self.capped = capped
        changed = new_snap != self._snapshot
        self._snapshot = new_snap
        return changed

    def close(self) -> None:
        pass


def make_watcher(root: Path, max_dirs: int = DEFAULT_MAX_WATCH_DIRS,
                 poll_interval_s: float = 1.0) -> Watcher:
    """InotifyWatcher when the real syscall works, PollWatcher otherwise.

    Same non-guessing contract as `probe_inotify`: this is a real construction
    attempt, so a Linux sandbox that refuses the syscall degrades exactly like a
    non-Linux host would.
    """
    try:
        return InotifyWatcher(root, max_dirs=max_dirs)
    except OSError:
        return PollWatcher(root, max_files=max_dirs, poll_interval_s=poll_interval_s)


# --------------------------------------------------------------------- heartbeat

def _write_heartbeat(path: Path, **fields) -> None:
    """Best-effort: a heartbeat write failing must never take the watch down."""
    try:
        secure_dir(path.parent)
        secure_write_text(path, json.dumps(fields, ensure_ascii=True, indent=2) + "\n")
    except OSError:
        pass


#: A real heartbeat is well under 1 KB; anything past this is not one, and an unbounded
#: read of a file anyone can write into the store would be a memory hazard.
_HEARTBEAT_MAX_BYTES = 65536


def _is_int(v, lo: int, hi: int) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def _is_str(v, limit: int) -> bool:
    return isinstance(v, str) and len(v) <= limit


def _is_pos_finite(v, hi: float) -> bool:
    return (isinstance(v, (int, float)) and not isinstance(v, bool)
            and math.isfinite(v) and 0 < v <= hi)


#: field -> (required, validator). A field that is present with the wrong type or range -
#: including null where a value is expected - makes the whole record corrupt. `last_scan_*`
#: really are null before the first re-scan, so null is valid for those two only.
_HEARTBEAT_FIELDS = {
    "status": (True, lambda v: _is_str(v, 32)),
    "pid": (True, lambda v: _is_int(v, -2 ** 31, 2 ** 31 - 1)),
    "updated_at": (False, lambda v: _is_str(v, 64)),
    "heartbeat_interval_s": (False, lambda v: _is_pos_finite(v, 1e7)),
    "mode": (False, lambda v: _is_str(v, 32)),
    "cycles": (False, lambda v: _is_int(v, 0, 2 ** 53)),
    "last_scan_rc": (False, lambda v: v is None or _is_int(v, -2 ** 31, 2 ** 31 - 1)),
    "last_scan_at": (False, lambda v: v is None or _is_str(v, 64)),
}


def _heartbeat_invalid(hb) -> "str | None":
    """Name of the first heartbeat field whose type or range is wrong, else None. The
    heartbeat is a plain file in the store - anything that can write there can put any
    JSON in it - so no reader may use a value before it has passed through here."""
    if not isinstance(hb, dict):
        return "heartbeat"
    for key, (required, ok) in _HEARTBEAT_FIELDS.items():
        if key not in hb:
            if required:
                return key
            continue
        try:
            good = ok(hb[key])
        except (TypeError, ValueError, OverflowError):  # pragma: no cover - defensive
            good = False
        if not good:
            return key
    return None


def _printable(v, limit: int = 64) -> str:
    """A validated heartbeat value, safe to print: printable ASCII only, bounded."""
    text = str(v)[:limit]
    return "".join(c if " " <= c <= "~" else "?" for c in text)


#: Flags for every open of a store file in this module. A path in the store can be replaced
#: with a FIFO by anything that can write there, and an ordinary open() of a FIFO with no
#: writer waits forever - which would hang `--watch` or `--watch-status` by file write
#: alone. O_NONBLOCK makes that open return at once; the descriptor is then checked with
#: `fstat`, and only a regular file is ever used.
_NONBLOCK_OPEN = (getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
                  | getattr(os, "O_NOCTTY", 0))
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class _NotRegularFile(OSError):
    """The path exists but is a pipe, socket, device or directory."""


def _open_regular(path, flags: int, mode: int = 0o600, *, follow: bool = False) -> int:
    """``os.open`` that never blocks and returns a descriptor only for a REGULAR file
    (checked on the descriptor, so a swap between a check and the open is caught too).
    Raises `_NotRegularFile` otherwise; *follow* False adds O_NOFOLLOW."""
    fd = os.open(path, flags | _NONBLOCK_OPEN | (0 if follow else _NOFOLLOW), mode)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise _NotRegularFile(errno.EINVAL, "not a regular file", os.fspath(path))
    except BaseException:
        os.close(fd)
        raise
    return fd


def _read_bounded(path, limit: int) -> bytes:
    """At most ``limit + 1`` bytes of a regular file (one more than *limit* tells the
    caller it was too long); never blocks on a special file."""
    fd = _open_regular(path, os.O_RDONLY, follow=True)
    try:
        chunks: list = []
        total = 0
        while total <= limit:
            piece = os.read(fd, min(65536, limit + 1 - total))
            if not piece:
                break
            chunks.append(piece)
            total += len(piece)
        return b"".join(chunks)
    finally:
        os.close(fd)


def read_heartbeat_ex(path: "str | Path") -> "tuple[dict | None, str | None]":
    """``(heartbeat, problem)``. *problem* is None when the file parsed AND every field
    has a sane type and range, else one of ``"absent"`` (no such file: --watch has not
    run against this store), ``"not_regular"`` (the path is a pipe, socket, device or
    directory), ``"unreadable"`` (it exists, or is a dangling link, but cannot be read) or
    ``"corrupt"`` (it was read but is oversized, not JSON, not an object, or carries a
    field of the wrong type or range). Different facts, so a caller can name the right
    one instead of collapsing a damaged record into "never ran". Never blocks, never
    raises."""
    expanded = pathprobe.expand_user(path)
    try:
        raw = _read_bounded(expanded, _HEARTBEAT_MAX_BYTES)
    except _NotRegularFile:
        return None, "not_regular"
    except FileNotFoundError:
        # A dangling symlink also lands here; that is a planted path, not "never ran".
        return None, ("unreadable" if os.path.lexists(expanded) else "absent")
    except OSError:
        return None, "unreadable"
    if len(raw) > _HEARTBEAT_MAX_BYTES:
        return None, "corrupt"
    try:
        # The heartbeat is a plain file anything with write access to the store can write,
        # so it is read as hostile text: a nesting bound first, the same on every interpreter.
        data = loads_bounded(raw.decode("utf-8"))
    except (ValueError, RecursionError):  # UnicodeDecodeError, JSONNestingError: ValueErrors
        return None, "corrupt"
    if _heartbeat_invalid(data) is not None:
        return None, "corrupt"
    return data, None


def read_heartbeat(path: "str | Path") -> "dict | None":
    """Read back a heartbeat file for a liveness check. None if absent, unreadable,
    or not a valid heartbeat - never raises. Use `read_heartbeat_ex` to tell those apart."""
    return read_heartbeat_ex(path)[0]


# ------------------------------------------------- who owns the store (C-725)
#
# One watcher per store is decided by a LOCK, never by what the heartbeat file says: the
# heartbeat is a plain file anyone with write access to the store can plant, so a decision
# that trusted it (a live pid, a process whose argv looks like a watch) would let that
# writer switch the watcher off. The running watcher holds an exclusive advisory flock on
# <store>/watch.lock for as long as it runs; the kernel drops it when the process exits
# for ANY reason (SIGKILL included), so a crashed watcher can never wedge its store.

_LOCK_NAME = "watch.lock"
#: errno values flock() uses for "somebody else holds it".
_CONTENDED = (errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES)
#: A status probe holds a shared lock for an instant; a starting watcher retries this
#: briefly before it concludes the lock is really held.
_LOCK_TRIES = 6
_LOCK_RETRY_S = 0.05


def lock_path_for(heartbeat_path: "str | Path") -> Path:
    return pathprobe.expand_user(heartbeat_path).with_name(_LOCK_NAME)


def _open_failure_reason(exc: OSError) -> str:
    if isinstance(exc, _NotRegularFile) or exc.errno in (errno.EISDIR, errno.ENXIO):
        return "not_regular"
    if exc.errno == errno.ELOOP:
        return "symlink"
    return _printable(exc.strerror or f"errno {exc.errno}", 48)


_LOCK_WHY = {
    "not_regular": ("the lock file is not a regular file (a pipe, socket, device or "
                    "directory); this tool never creates that, so something else put it there"),
    "symlink": ("the lock path is a symbolic link; this tool never creates one and will not "
                "follow it, so something else put it there"),
    "no_fcntl": "this platform has no file locks",
}


def _lock_why(reason: "str | None") -> str:
    return _LOCK_WHY.get(reason or "") or f"the lock file cannot be used ({reason})"


def _acquire_watch_lock(lock_path: Path) -> "tuple[str, int | None, str | None]":
    """``("acquired", fd, None)`` | ``("held", None, None)`` (another watcher has it) |
    ``("no_fcntl", None, "no_fcntl")`` (this platform has no flock) |
    ``("unavailable", None, reason)`` (the lock file cannot be used: a planted symlink,
    FIFO, socket, device or directory, a read-only store, a filesystem without locks). The
    open never blocks and accepts only a regular file. The fd is non-inheritable, so the
    re-scan child never holds the watcher's lock."""
    if not _HAS_FCNTL or fcntl is None:
        return "no_fcntl", None, "no_fcntl"
    try:
        secure_dir(lock_path.parent)
        fd = _open_regular(lock_path, os.O_RDWR | os.O_CREAT)
    except OSError as exc:
        return "unavailable", None, _open_failure_reason(exc)
    contended = False
    for attempt in range(_LOCK_TRIES):
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return "acquired", fd, None
        except OSError as exc:
            if exc.errno not in _CONTENDED:
                break
            contended = True
            if attempt + 1 < _LOCK_TRIES:
                time.sleep(_LOCK_RETRY_S)
    try:
        os.close(fd)
    except OSError:
        pass
    return ("held", None, None) if contended else ("unavailable", None, "flock failed")


def _release_watch_lock(fd: "int | None") -> None:
    if fd is None:
        return
    try:
        os.close(fd)  # closing the descriptor releases the flock
    except OSError:
        pass


def probe_watch_lock_ex(lock_path: Path) -> "tuple[str | None, str | None]":
    """``(state, reason)``: state ``"held"`` (a watcher is running), ``"free"`` (none is) or
    None (cannot tell here - *reason* says why: ``"no_fcntl"``, ``"not_regular"``,
    ``"symlink"`` or an OS error text).

    Opens the lock file read-only, non-blocking and without creating it, refuses anything
    but a regular file, and takes a SHARED non-blocking lock for an instant, released by the
    close below - so a probe never leaves the lock held, never writes anything and never
    hangs on a planted pipe. An absent lock file is "free": a watcher creates it before it
    does anything else."""
    if not _HAS_FCNTL or fcntl is None:
        return None, "no_fcntl"
    try:
        fd = _open_regular(lock_path, os.O_RDONLY)
    except FileNotFoundError:
        return "free", None
    except OSError as exc:
        return None, _open_failure_reason(exc)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in _CONTENDED:
                return "held", None
            return None, _open_failure_reason(exc)
        return "free", None
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def probe_watch_lock(lock_path: Path) -> "str | None":
    """`probe_watch_lock_ex`'s state alone."""
    return probe_watch_lock_ex(lock_path)[0]


def lock_holder_pid(lock_path: Path) -> "int | None":
    """The pid ``/proc/locks`` lists as holding the exclusive flock on *lock_path*, or None
    (no procfs, no such entry, another pid namespace, any parse problem). INFORMATION for
    `--watch-status` only: nothing about starting a watcher depends on it."""
    try:
        st = os.stat(lock_path)
        with open("/proc/locks", "rb") as fh:
            text = fh.read(4_000_000).decode("ascii", "replace")
        want = f"{os.major(st.st_dev):02x}:{os.minor(st.st_dev):02x}:{st.st_ino}"
        for line in text.splitlines():
            f = line.split()
            # "1: FLOCK  ADVISORY  WRITE 12345 08:02:131075 0 EOF"
            if len(f) >= 6 and f[1] == "FLOCK" and f[3] == "WRITE" and f[5] == want:
                pid = int(f[4])
                return pid if _plausible_pid(pid) else None
    except (OSError, ValueError, OverflowError, IndexError):
        return None
    return None


def _plausible_pid(pid) -> bool:
    """A real process id a watcher could have: an int (not a bool) above 1. `os.kill(0, 0)`
    and `os.kill(-1, 0)` address a whole process group / every process and succeed, so a
    record naming them must never be read as a live watcher."""
    return isinstance(pid, int) and not isinstance(pid, bool) and 1 < pid <= 2 ** 31 - 1


def _pid_alive(pid) -> "bool | None":
    """True/False from a signal-0 probe; None when the platform cannot tell (a process
    owned by someone else, a value the OS rejects, or no such probe)."""
    if not _plausible_pid(pid):
        return None
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except (OSError, OverflowError, ValueError, TypeError):
        return None


def _cmdline_is_watcher(argv: "list[str]") -> bool:
    """True when a process's argv is a ``--watch`` invocation of THIS tool: the exact
    ``--watch`` token (never ``--watch-status``/``--watch-log``) plus one of the three
    ways the tool is started - ``-m clawseccheck``, the bundled ``audit.py`` shim, or the
    ``clawseccheck`` console script."""
    if "--watch" not in argv:
        return False
    for tok in argv:
        base = os.path.basename(tok)
        if base in ("clawseccheck", "clawseccheck.exe", "audit.py"):
            return True
        if base == "__main__.py" and os.path.basename(os.path.dirname(tok)) == "clawseccheck":
            return True
    return False


def _pid_is_watcher(pid: int) -> "bool | None":
    """Is *pid* a clawseccheck ``--watch`` process? Read from ``/proc/<pid>/cmdline`` (no
    subprocess). True / False, or None when that cannot be determined here (no procfs, or
    the file is not readable). INFORMATION only where a lock is available - a process can
    be made to look like a watcher, so this never decides to refuse a start there."""
    if not _plausible_pid(pid):
        return False
    if not pathprobe.is_dir(Path("/proc/self")):
        return None
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except (FileNotFoundError, ProcessLookupError):
        return False
    except OSError:
        return None
    argv = [a.decode("utf-8", "replace") for a in raw.split(b"\0") if a]
    return _cmdline_is_watcher(argv)


def _pid_record_state(hb, problem) -> "tuple[str, str]":
    """The PRE-LOCK way to read a record, kept only for platforms with no ``fcntl``:
    ``("none", "")`` | ``("live", why)`` (alive AND confirmed a watcher) |
    ``("unconfirmed", why)`` (alive, identity unknown) | ``("stale", why)``."""
    if hb is None:
        if problem in _BAD_HEARTBEAT:
            return "stale", f"its heartbeat file is {_PROBLEM_WORDS[problem]} and will be replaced"
        return "none", ""
    if hb.get("status") == "stopped":
        return "none", ""
    pid = hb.get("pid")
    if not _plausible_pid(pid):
        return "stale", f"it names pid {_printable(pid)}, which cannot be a watcher"
    if _pid_alive(pid) is False:
        return "stale", f"pid {pid} is gone"
    ident = _pid_is_watcher(pid)
    if ident is False:
        return "stale", f"pid {pid} is running but is not a ClawSecCheck watcher"
    if ident:
        return "live", f"pid {pid}"
    return "unconfirmed", f"pid {pid} is alive but could not be confirmed as a watcher"


#: `read_heartbeat_ex` problems that mean "a file is there but it is no heartbeat".
_BAD_HEARTBEAT = ("unreadable", "corrupt", "not_regular")
_PROBLEM_WORDS = {"unreadable": "unreadable", "corrupt": "corrupt",
                  "not_regular": "not a regular file", "absent": "missing"}


def _refusal(why: str, heartbeat_path) -> str:
    return (f"{cmd('--watch')}: refusing to start - another --watch holds this store's lock "
            f"({why}). A second watcher would overwrite its heartbeat and make --watch-status "
            f"report the wrong thing. Stop that one first, or use a different --data-dir.")


def can_start(heartbeat_path: "str | Path") -> "tuple[bool, str]":
    """Early, side-effect-free form of the single-watcher check, for the CLI to run before
    it announces a watch: ``(False, refusal)`` only when another watcher demonstrably holds
    this store's lock (or, where there is no ``fcntl``, a confirmed live watcher is
    recorded). Never refuses on a heartbeat's say-so. `run_watch` takes the lock itself."""
    lock = probe_watch_lock(lock_path_for(heartbeat_path))
    if lock == "held":
        return False, _refusal("the lock is held", heartbeat_path)
    if lock is None and not _HAS_FCNTL:
        hb, problem = read_heartbeat_ex(heartbeat_path)
        state, why = _pid_record_state(hb, problem)
        if state == "live":
            return False, _refusal(why, heartbeat_path)
    return True, ""


def _stale_note(heartbeat_path) -> str:
    """A line for a start that has the lock but finds a record claiming a watcher ran."""
    hb, problem = read_heartbeat_ex(heartbeat_path)
    if hb is None:
        if problem in _BAD_HEARTBEAT:
            return (f"{cmd('--watch')}: replacing a stale watcher record (its heartbeat file "
                    f"is {_PROBLEM_WORDS[problem]}).")
        return ""
    if hb.get("status") == "stopped":
        return ""
    return (f"{cmd('--watch')}: replacing a stale watcher record (heartbeat pid "
            f"{_printable(hb.get('pid'))}, last update {_printable(hb.get('updated_at', '?'))}): "
            f"nothing holds this store's lock, so that watcher is not running.")


# ------------------------------------------------------------------------ the loop

DEFAULT_DEBOUNCE_S = 2.0
DEFAULT_POLL_INTERVAL_S = 1.0
DEFAULT_SELECT_TIMEOUT_S = 1.0
DEFAULT_HEARTBEAT_INTERVAL_S = 30.0
#: A heartbeat older than this many multiples of its own interval reads as stale -
#: the watcher likely hung rather than merely being between two ordinary updates.
STALE_HEARTBEAT_MULTIPLE = 3


#: What identifies the bundled entry shim, as opposed to some other project's `audit.py`
#: that happens to sit beside a pip-installed package in site-packages.
_SHIM_MARKER = "from clawseccheck.cli import main"

#: `--monitor` exit codes that mean the scan RAN: 0 nothing to report, 3 drift found.
#: Anything else (1 = monitoring not established, 2 = refused/usage, a crash, a signal) is
#: a re-scan that did not complete.
_RESCAN_RAN_RC = (0, 3)

def _bundled_shim() -> "str | None":
    """Absolute path of this tool's own ``audit.py`` beside the package, or None."""
    shim = _shim_beside_the_package()
    if shim is None:
        return None
    try:
        with open(shim, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(65536)
    except OSError:
        return None
    return shim if _SHIM_MARKER in head else None


def _started_as_the_shim() -> bool:
    argv0 = sys.argv[0] if getattr(sys, "argv", None) and isinstance(sys.argv[0], str) else ""
    if os.path.basename(argv0) != "audit.py":
        return False
    shim = _bundled_shim()
    return shim is not None and os.path.realpath(argv0) == os.path.realpath(shim)


def _child_launch() -> "tuple[list, dict]":
    """``(entry argv, environment)`` that starts THIS package in a fresh interpreter,
    wherever the child's working directory is and however the parent was started (C-725).

    The old child was a bare ``python -m clawseccheck``: it found the package only if its
    cwd happened to hold it (or it was pip-installed), so a watcher started as
    ``python3 <skill-dir>/audit.py --watch`` from any other directory detected a change and
    then failed to re-scan. Two forms, chosen by how the parent itself was started:

    * the parent is the bundled ``audit.py`` shim -> the child is that same shim by absolute
      path. The shim finds its package beside itself, never consults the cwd, and runs its
      refusal of stray importable files (C-637/C-680) again, so the child is protected
      exactly like the parent.
    * anything else (``-m``, the console script) -> ``-m clawseccheck`` with this
      package's own parent directory first on ``PYTHONPATH`` (so an installed copy or a
      checkout elsewhere on the path cannot win) and ``PYTHONSAFEPATH=1`` (Python 3.11+
      then keeps the cwd off ``sys.path`` for ``-m``; on 3.10 the variable is ignored and a
      cwd that holds its own ``clawseccheck`` can still shadow the console-script case).

    The working directory is never changed, so a relative ``--home``/``--state``/... or
    ``--judged-bundle`` path means to the child what it meant to the parent.
    """
    env = dict(os.environ)
    if _started_as_the_shim():
        return [_bundled_shim()], env
    root = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    env["PYTHONPATH"] = root + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    env["PYTHONSAFEPATH"] = "1"
    return ["-m", "clawseccheck"], env


def _run_monitor_once(home: Path, state_path, events_path, history_path,
                      extra_args: "tuple[str, ...]" = ()) -> "tuple[int, str]":
    """Shell out to the EXISTING `--monitor` command. See this module's own docstring
    for why detection is never reimplemented here: the child is this package's own
    `--monitor`, the identical invocation `scripts/monitor_detection_gate.py` already
    drives this tool with from outside the library, so the alert format is guaranteed
    identical. How the child is started so that it imports THIS package is
    `_child_launch`.

    The literal argv list is inlined directly into the `subprocess.run` call (rather
    than built up in a local first) so it stays statically visible to
    `tests/test_doc_facts.py::test_the_only_program_this_package_spawns_...` - the
    same shape `native.py`'s own spawn site already uses, and the reason that test can
    name this one's argv too instead of only knowing a second spawn site exists. This
    is the package invoking ITSELF (the interpreter running this process, plus either the
    bundled shim or `-m clawseccheck`) to re-run the identical local, offline `--monitor`
    check in a fresh process - not a third-party program and not a network call, so it
    does not touch either badge figure the tests above pin; it is still a distinct spawn
    site, which is exactly what that test exists to make visible rather than let
    accumulate unnoticed.
    """
    entry, env = _child_launch()
    try:
        r = subprocess.run(
            [sys.executable, *entry, "--monitor", "--verbose",
             "--home", str(home), "--state", str(state_path),
             "--events", str(events_path), "--history", str(history_path),
             *extra_args],
            capture_output=True, text=True, errors="replace", env=env,
        )
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return 1, f"{cmd('--watch')}: could not run the re-scan: {exc}\n"
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def _failed_rescan_report(rc: int, output: str, when: str) -> str:
    """The loud block printed when the re-scan itself did not complete. The child's WHOLE
    output follows: `--monitor` exits 1 for "the comparison ran and its alerts were printed,
    but the journal or state could not be written" too, so cutting the output short would
    hide alerts, and the heading must not claim that nothing was checked."""
    body = output if (output or "").strip() else "(the re-scan printed nothing)\n"
    if not body.endswith("\n"):
        body += "\n"
    return (f"\n=== {cmd('--watch')}: RE-SCAN FAILED at {when} (rc={rc}) ===\n"
            f"A change was detected and the --monitor re-scan did not complete (exit code "
            f"{rc}). Its full output follows; if it printed a comparison, that is what it "
            f"found before it stopped.\n"
            f"{body}"
            f"=== end of the failed re-scan's output; this watcher is still watching and "
            f"will try again on the next change ===\n")


def run_watch(
    home: "str | Path",
    *,
    state_path: "str | Path",
    events_path: "str | Path",
    history_path: "str | Path",
    heartbeat_path: "str | Path",
    debounce_s: float = DEFAULT_DEBOUNCE_S,
    poll_interval_s: float = DEFAULT_POLL_INTERVAL_S,
    select_timeout_s: float = DEFAULT_SELECT_TIMEOUT_S,
    heartbeat_interval_s: float = DEFAULT_HEARTBEAT_INTERVAL_S,
    extra_monitor_args: "tuple[str, ...]" = (),
    max_cycles: "int | None" = None,
    install_signal_handlers: bool = True,
    stop_event=None,
    stream=None,
) -> int:
    """Watch *home* and re-run `--monitor` on a debounced relevant change.

    Read-only w.r.t. *home*: every write goes through the three `--monitor` paths
    (unchanged) or *heartbeat_path* - always inside the caller's own store directory
    (Golden Rule #2).

    Returns 0 on a clean stop. This function never exits the process itself, so a
    caller decides how to stop it: the CLI installs real SIGTERM/SIGINT handlers
    (`install_signal_handlers=True`, the default); a test instead passes a
    `threading.Event` as *stop_event* and/or a small `max_cycles`, and must pass
    `install_signal_handlers=False` when running this loop from a non-main thread
    (Python signal handlers can only be installed on the main thread - see
    tests/test_watch.py).
    """
    out = stream if stream is not None else sys.stdout
    home = pathprobe.expand_user(home)
    heartbeat_path = Path(heartbeat_path)

    # C-725: one watcher per store, decided by a LOCK (see the block above), never by what the
    # heartbeat file says. Refuse BEFORE anything is created or written, so the running
    # watcher's heartbeat is left exactly as it wrote it.
    lock_state, lock_fd, lock_reason = _acquire_watch_lock(lock_path_for(heartbeat_path))
    note = ""
    if lock_state == "held":
        sys.stderr.write(_refusal("the lock is held", heartbeat_path) + "\n")
        return 1
    if lock_state == "acquired":
        note = _stale_note(heartbeat_path)
    elif lock_state == "no_fcntl":
        # Today's pid check, for a platform with no flock. An unconfirmed identity is a
        # warning, not a refusal: a record anyone can plant must not stop the watcher.
        hb, problem = read_heartbeat_ex(heartbeat_path)
        state, why = _pid_record_state(hb, problem)
        if state == "live":
            sys.stderr.write(_refusal(why, heartbeat_path) + "\n")
            return 1
        if state == "unconfirmed":
            sys.stderr.write(f"{cmd('--watch')}: warning - {why}; starting anyway "
                             f"(this platform has no file lock to settle it).\n")
        elif state == "stale":
            note = f"{cmd('--watch')}: replacing a stale watcher record ({why})."
    else:
        # An unusable lock never stops the watcher: a monitor that runs unprotected beats one
        # that does not run. It says so, loudly, and `--watch-status` will not claim more.
        sys.stderr.write(f"{cmd('--watch')}: WARNING - could not take this store's lock "
                         f"({_lock_why(lock_reason)}); starting WITHOUT single-watcher "
                         f"protection, and --watch-status cannot confirm this watcher.\n")
    if note:
        out.write(note + "\n")
        if hasattr(out, "flush"):
            out.flush()

    try:
        return _run_watch_locked(
            home, state_path, events_path, history_path, heartbeat_path, debounce_s,
            poll_interval_s, select_timeout_s, heartbeat_interval_s, extra_monitor_args,
            max_cycles, install_signal_handlers, stop_event, out)
    finally:
        _release_watch_lock(lock_fd)


def _run_watch_locked(home, state_path, events_path, history_path, heartbeat_path,
                      debounce_s, poll_interval_s, select_timeout_s, heartbeat_interval_s,
                      extra_monitor_args, max_cycles, install_signal_handlers, stop_event,
                      out) -> int:
    """`run_watch`'s loop, run while it holds the store's lock (or knowingly without one)."""
    watcher = make_watcher(home, poll_interval_s=poll_interval_s)
    started_at = _now_iso()
    pid = os.getpid()

    # Installed BEFORE the first heartbeat write, deliberately: a caller (or a test)
    # that treats "the heartbeat file exists" as "the process is ready to be signalled"
    # must never observe a window where that is not yet true - Python's default
    # SIGTERM/SIGINT handling (die / raise KeyboardInterrupt) would otherwise be able
    # to win a race against this function installing its own handler.
    stop_requested = {"flag": False}
    prev_handlers: dict = {}
    if install_signal_handlers:
        def _request_stop(_signum, _frame):
            stop_requested["flag"] = True
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                prev_handlers[sig] = signal.signal(sig, _request_stop)
            except (OSError, ValueError):
                # ValueError: not the main thread. A caller embedding run_watch in a
                # worker thread already owns signal handling and must pass
                # install_signal_handlers=False; failing to install one here must
                # not take the watch down.
                pass

    def _heartbeat(status: str, cycles: int, last_scan_at=None, last_scan_rc=None) -> None:
        _write_heartbeat(
            heartbeat_path,
            pid=pid, status=status, mode=watcher.mode, home=str(home),
            started_at=started_at, updated_at=_now_iso(),
            debounce_s=debounce_s, heartbeat_interval_s=heartbeat_interval_s,
            cycles=cycles, watch_dirs_capped=bool(getattr(watcher, "capped", False)),
            last_scan_at=last_scan_at, last_scan_rc=last_scan_rc,
        )

    _heartbeat("starting", 0)

    def _should_stop() -> bool:
        return stop_requested["flag"] or (stop_event is not None and stop_event.is_set())

    cycles = 0
    last_scan_at = None
    last_scan_rc = None
    last_heartbeat_at = time.monotonic()
    try:
        while not _should_stop():
            if max_cycles is not None and cycles >= max_cycles:
                break
            changed = watcher.poll_for_change(select_timeout_s)
            now = time.monotonic()
            if now - last_heartbeat_at >= heartbeat_interval_s:
                _heartbeat("running", cycles, last_scan_at, last_scan_rc)
                last_heartbeat_at = now
            if not changed:
                continue
            # Debounce: a burst of writes must trigger ONE re-scan, not N. Keep
            # draining for a quiet window rather than waiting a fixed delay after the
            # FIRST event, so a save that touches several files in sequence (a
            # write-then-rename, an editor's backup+replace) still collapses to one.
            deadline = time.monotonic() + debounce_s
            while time.monotonic() < deadline and not _should_stop():
                remaining = deadline - time.monotonic()
                if watcher.poll_for_change(min(remaining, select_timeout_s)):
                    deadline = time.monotonic() + debounce_s
            if _should_stop():
                break
            rc, output = _run_monitor_once(home, state_path, events_path, history_path,
                                           extra_monitor_args)
            cycles += 1
            last_scan_at = _now_iso()
            last_scan_rc = rc
            if rc in _RESCAN_RAN_RC:
                out.write(f"\n=== {cmd('--watch')}: change detected, re-scanned at "
                          f"{last_scan_at} (rc={rc}) ===\n")
                out.write(output)
            else:
                out.write(_failed_rescan_report(rc, output, last_scan_at))
            if hasattr(out, "flush"):
                out.flush()
            _heartbeat("running", cycles, last_scan_at, last_scan_rc)
    finally:
        for sig, prev in prev_handlers.items():
            try:
                signal.signal(sig, prev)
            except (OSError, ValueError):
                pass
        watcher.close()
        _heartbeat("stopped", cycles, last_scan_at, last_scan_rc)
    return 0


def _heartbeat_age(updated_at, interval) -> "float | None":
    try:
        from datetime import datetime  # noqa: PLC0415 - only needed here
        # `_now_iso()` (monitorstore.py), the sole producer of `updated_at`, writes
        # NAIVE local time - no "Z", no offset. `datetime.now(upd.tzinfo)` matches
        # that: `upd.tzinfo` is None for the real (naive) case, so this compares
        # naive-to-naive like the producer intends, while still doing the right thing
        # if a future producer ever switches to an aware timestamp (the "Z" -> "+00:00"
        # rewrite below exists for exactly that case, not today's).
        upd = datetime.fromisoformat(str(updated_at).replace("Z", "+00:00"))
        return (datetime.now(upd.tzinfo) - upd).total_seconds()
    except (ValueError, TypeError, OverflowError):
        return None


def _claim(heartbeat, problem) -> str:
    """What the heartbeat file says, stated as the unverified claim it is."""
    if heartbeat is None:
        return {"absent": "there is no heartbeat file",
                "unreadable": "the heartbeat file is unreadable",
                "corrupt": "the heartbeat file is corrupt",
                "not_regular": "the heartbeat path is not a regular file"
                }.get(problem or "", "there is no usable heartbeat")
    upd = heartbeat.get("updated_at")
    return (f"status '{_printable(heartbeat.get('status'), 32)}', pid {heartbeat.get('pid')}, "
            f"last update {_printable(upd) if upd is not None else 'unknown'}")


def describe_liveness(heartbeat: "dict | None", problem: "str | None" = None,
                      lock: "str | None" = None, lock_why: "str | None" = None,
                      holder_pid: "int | None" = None) -> "tuple[str, str]":
    """(status_word, sentence) for a heartbeat dict - the `--watch-status` surface.

    *lock* is `probe_watch_lock_ex`'s state: ``"held"`` (a watcher holds the store's
    lock - the ONLY thing that says one is running), ``"free"`` (none does) or None
    (cannot be probed: *lock_why* says why). *problem* is `read_heartbeat_ex`'s second
    value; *holder_pid* is `lock_holder_pid`'s, information only.

    The heartbeat is a file anyone with write access to the store can plant, so a value of
    the wrong type or range makes the record corrupt (never an exception), and ``ALIVE`` is
    printed only when the lock is held AND the heartbeat does not contradict it. When the
    lock is held but the heartbeat disagrees the answer says both facts; when the lock
    cannot be probed the answer says so, and gives the heartbeat only as a claim. The word
    is never ``ALIVE`` on a heartbeat's say-so.
    """
    if heartbeat is not None and _heartbeat_invalid(heartbeat) is not None:
        heartbeat, problem = None, "corrupt"
    if lock is None:
        return ("UNKNOWN", f"It cannot be determined whether a watcher is running: "
                f"{_lock_why(lock_why)}. What the heartbeat claims (unverified - it is a plain "
                f"file that anything with write access to the store can write): "
                f"{_claim(heartbeat, problem)}.")
    holder = f" (lock held by pid {holder_pid})" if holder_pid is not None else ""
    if heartbeat is None:
        if lock == "held":
            return ("LOCK HELD", f"A process holds this store's lock{holder}, but the heartbeat "
                    f"does not back it: {_claim(None, problem)}, so nothing confirms what that "
                    f"process is or what it is doing. It may be a watcher that has not written "
                    f"its first heartbeat yet, a hung one, or another process holding the lock.")
        if problem in _BAD_HEARTBEAT:
            return ("UNREADABLE", f"The watch heartbeat path exists but is "
                    f"{_PROBLEM_WORDS[problem]}, so nothing can be said about a watcher "
                    f"\u2014 this is not the same as --watch never having run. "
                    f"Delete it to start clean.")
        return "NOT RUNNING", "No watch heartbeat found \u2014 --watch has not run yet."
    status = heartbeat.get("status")
    pid = heartbeat.get("pid")
    updated_at = heartbeat.get("updated_at")
    upd = _printable(updated_at) if updated_at is not None else "unknown"
    interval = heartbeat.get("heartbeat_interval_s", DEFAULT_HEARTBEAT_INTERVAL_S)
    if lock == "free":
        if status == "stopped":
            return "STOPPED", f"The watcher (pid {pid}) shut down cleanly at {upd}."
        return ("STALE RECORD", f"The heartbeat says a watcher was running (pid {pid}, last "
                f"update {upd}), but nothing holds this store's lock, so no watcher is running "
                f"\u2014 it exited or was killed without recording a clean stop.")
    # lock == "held": the heartbeat has to back it.
    tail = ""
    last_rc = heartbeat.get("last_scan_rc")
    if last_rc is not None and last_rc not in _RESCAN_RAN_RC:
        tail = (f" The last re-scan FAILED to complete (rc={last_rc}); the watcher's own "
                f"output has what it printed.")
    age_s = _heartbeat_age(updated_at, interval) if updated_at is not None else None
    if age_s is not None and age_s > interval * STALE_HEARTBEAT_MULTIPLE:
        return ("STALE", f"A process holds this store's lock{holder}, but the heartbeat "
                f"(pid {pid}) has not been updated in {int(age_s)}s (expected every "
                f"{int(interval)}s): the watcher may be hung, or another process holds the "
                f"lock." + tail)
    disagree = ""
    if status == "stopped":
        disagree = "the heartbeat says 'stopped'"
    elif not _plausible_pid(pid) or _pid_alive(pid) is False:
        disagree = f"the heartbeat names pid {pid}, which is not running"
    elif holder_pid is not None and holder_pid != pid:
        disagree = f"the heartbeat names pid {pid}, not the lock holder"
    if disagree:
        return ("LOCK HELD", f"A process holds this store's lock{holder}, but the heartbeat "
                f"does not back it: {disagree} (last update {upd}). Another process may be "
                f"holding the lock, or the watcher's pid is not visible from here." + tail)
    return "ALIVE", (f"A watcher holds this store's lock{holder} and its heartbeat agrees "
                     f"(pid {pid}, mode={_printable(heartbeat.get('mode'))}, "
                     f"{heartbeat.get('cycles', 0)} re-scan(s) so far, last update {upd})."
                     + tail)
