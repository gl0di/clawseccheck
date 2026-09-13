"""Continuous file-system watch mode (C-517): inotify with a stat-poll fallback.

`--monitor` (see monitor.py / monitordims/) is a ONE-SHOT poll: snapshot vs. the stored
baseline, invoked manually or via cron. This module adds a long-running companion that
notices a relevant filesystem change itself and re-runs the identical `--monitor` check
automatically, instead of waiting for the next scheduled invocation.

It deliberately does NOT reimplement drift detection. On a debounced change it shells out
to ``python3 -m clawseccheck --monitor --verbose ...`` — the same invocation
``scripts/monitor_detection_gate.py`` already uses to drive this tool from outside the
library — so the alert format, severity mapping and the tamper-evident event journal stay
the single implementation in monitordims/. This module only decides WHEN to trigger that
re-scan (inotify-driven, debounced) and whether the watcher process itself is still alive
(a heartbeat file under the caller's own store directory).

Mechanism choice — stdlib-only, no new runtime dependency: see
docs/design/watch-mechanism.md. Short version: a real inotify wrapper via ``ctypes``
against libc (``inotify_init1``/``inotify_add_watch``/``read``), with a stat-based
polling fallback for any platform or sandbox where the inotify syscalls are unavailable.
``probe_inotify()`` makes a real attempt rather than guessing from the platform name, and
the design note records that this was verified live on Linux, not assumed.

Read-only w.r.t. the audited home (Golden Rule #2): this module never writes under
*home*. Every file it writes (the heartbeat) lives under the caller-supplied store
directory — the same boundary ``--monitor`` already respects.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import json
import os
import select
import signal
import struct
import subprocess
import sys
import time
from pathlib import Path

from .monitorstore import _now_iso
from .safeio import secure_dir, secure_write_text

# --------------------------------------------------------------------------- inotify
#
# Flags/masks from <sys/inotify.h> (stable Linux UAPI) — ctypes cannot include a C
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
    refuses the syscall itself) — the trigger for falling back to PollWatcher."""


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
    fd) — never a platform-name guess. `sys.platform != "linux"` is the common fast
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
#: setup itself unbounded — same discipline as safeio.walk_dir_safely's max_files.
DEFAULT_MAX_WATCH_DIRS = 20_000


def _is_symlink(p: Path) -> bool:
    try:
        return p.is_symlink()
    except OSError:
        return False


def _bounded_watch_dirs(root: Path, max_dirs: int = DEFAULT_MAX_WATCH_DIRS
                        ) -> "tuple[list[Path], bool]":
    """Every directory under *root* (root included); symlinked directories are never
    followed (no cycles, no escaping *root*).

    Returns ``(dirs, capped)`` — ``capped`` is True when the tree holds more
    directories than *max_dirs* and the walk stopped short, so a caller can disclose a
    partial watch rather than silently watching only part of the tree.
    """
    try:
        resolved = root.resolve()
    except OSError:
        return [], False
    if not resolved.is_dir():
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
    """Common interface both mechanisms implement — the loop in run_watch() never
    branches on which one it got."""

    mode = "abstract"
    capped = False

    def poll_for_change(self, timeout: float) -> bool:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover - interface
        pass


class InotifyWatcher(Watcher):
    """Real, event-driven watch via ctypes + libc inotify.

    Recursive by hand — Linux inotify is not natively recursive: every existing
    subdirectory gets its own watch descriptor up front (`_bounded_watch_dirs`), and a
    newly created subdirectory is watched the moment its IN_CREATE|IN_ISDIR event is
    seen, so a directory created after start-up is not a blind spot.
    """

    mode = "inotify"

    def __init__(self, root: Path, max_dirs: int = DEFAULT_MAX_WATCH_DIRS):
        self._root = Path(root)
        self._fd = _inotify_init()
        self._wd_to_path: dict = {}
        self.unreadable = 0
        self.overflowed = False
        dirs, capped = _bounded_watch_dirs(self._root, max_dirs)
        self.capped = capped
        for d in dirs:
            try:
                wd = _inotify_add_watch(self._fd, d, WATCH_MASK)
            except OSError:
                self.unreadable += 1
                continue
            self._wd_to_path[wd] = d

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
                    # as a change unconditionally — under-reporting here would be a
                    # silent gap in exactly the surface this module exists to watch.
                    self.overflowed = True
                    changed = True
                    continue
                if mask & IN_IGNORED:
                    # The watch itself was removed (directory deleted/unmounted).
                    self._wd_to_path.pop(wd, None)
                    continue
                changed = True
                if (mask & IN_CREATE) and (mask & IN_ISDIR):
                    parent = self._wd_to_path.get(wd)
                    if parent is not None:
                        newdir = parent / os.fsdecode(name)
                        try:
                            new_wd = _inotify_add_watch(self._fd, newdir, WATCH_MASK)
                            self._wd_to_path[new_wd] = newdir
                        except OSError:
                            pass
        return changed

    def close(self) -> None:
        try:
            os.close(self._fd)
        except OSError:
            pass


class PollWatcher(Watcher):
    """Fallback: bounded stat-based polling (mtime + size), for a non-Linux platform
    or a sandbox where the inotify syscalls raise. Not a guess — `make_watcher` only
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


def read_heartbeat(path: "str | Path") -> "dict | None":
    """Read back a heartbeat file for a liveness check. None if absent, unreadable,
    or not valid JSON — never raises."""
    try:
        text = Path(path).expanduser().read_text(encoding="utf-8")
        data = json.loads(text)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


# ------------------------------------------------------------------------ the loop

DEFAULT_DEBOUNCE_S = 2.0
DEFAULT_POLL_INTERVAL_S = 1.0
DEFAULT_SELECT_TIMEOUT_S = 1.0
DEFAULT_HEARTBEAT_INTERVAL_S = 30.0
#: A heartbeat older than this many multiples of its own interval reads as stale —
#: the watcher likely hung rather than merely being between two ordinary updates.
STALE_HEARTBEAT_MULTIPLE = 3


def _run_monitor_once(home: Path, state_path, events_path, history_path,
                      extra_args: "tuple[str, ...]" = ()) -> "tuple[int, str]":
    """Shell out to the EXISTING `--monitor` command. See this module's own docstring
    for why detection is never reimplemented here: `sys.executable -m clawseccheck` is
    the identical invocation `scripts/monitor_detection_gate.py` already drives this
    tool with from outside the library, so the alert format is guaranteed identical.

    The literal argv list is inlined directly into the `subprocess.run` call (rather
    than built up in a local first) so it stays statically visible to
    `tests/test_doc_facts.py::test_the_only_program_this_package_spawns_...` — the
    same shape `native.py`'s own spawn site already uses, and the reason that test can
    name this one's argv too instead of only knowing a second spawn site exists. This
    is the package invoking ITSELF (`-m clawseccheck`, its own installed entry point)
    to re-run the identical local, offline `--monitor` check in a fresh process — not a
    third-party program and not a network call, so it does not touch either badge
    figure the tests above pin; it is still a distinct spawn site, which is exactly
    what that test exists to make visible rather than let accumulate unnoticed.
    """
    try:
        r = subprocess.run(
            [sys.executable, "-m", "clawseccheck", "--monitor", "--verbose",
             "--home", str(home), "--state", str(state_path),
             "--events", str(events_path), "--history", str(history_path),
             *extra_args],
            capture_output=True, text=True,
        )
    except OSError as exc:
        return 1, f"clawseccheck --watch: could not run the re-scan: {exc}\n"
    return r.returncode, (r.stdout or "") + (r.stderr or "")


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
    (unchanged) or *heartbeat_path* — always inside the caller's own store directory
    (Golden Rule #2).

    Returns 0 on a clean stop. This function never exits the process itself, so a
    caller decides how to stop it: the CLI installs real SIGTERM/SIGINT handlers
    (`install_signal_handlers=True`, the default); a test instead passes a
    `threading.Event` as *stop_event* and/or a small `max_cycles`, and must pass
    `install_signal_handlers=False` when running this loop from a non-main thread
    (Python signal handlers can only be installed on the main thread — see
    tests/test_watch.py).
    """
    out = stream if stream is not None else sys.stdout
    home = Path(home).expanduser()
    heartbeat_path = Path(heartbeat_path)

    watcher = make_watcher(home, poll_interval_s=poll_interval_s)
    started_at = _now_iso()
    pid = os.getpid()

    # Installed BEFORE the first heartbeat write, deliberately: a caller (or a test)
    # that treats "the heartbeat file exists" as "the process is ready to be signalled"
    # must never observe a window where that is not yet true — Python's default
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
            out.write(f"\n=== clawseccheck --watch: change detected, re-scanned at "
                      f"{last_scan_at} (rc={rc}) ===\n")
            out.write(output)
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


def describe_liveness(heartbeat: "dict | None") -> "tuple[str, str]":
    """(status_word, sentence) for a heartbeat dict — the `--watch-status` surface.

    Three outcomes, not two, for the same reason `--verify-baseline` refuses to
    collapse "no baseline" into "tampered": a watcher that never ran, one that shut
    down cleanly, and one that is either running or has silently hung are different
    facts calling for different reactions.
    """
    if heartbeat is None:
        return "NOT RUNNING", "No watch heartbeat found — --watch has not run yet."
    status = heartbeat.get("status")
    pid = heartbeat.get("pid")
    updated_at = heartbeat.get("updated_at")
    interval = heartbeat.get("heartbeat_interval_s")
    interval = interval if isinstance(interval, (int, float)) and interval > 0 \
        else DEFAULT_HEARTBEAT_INTERVAL_S
    pid_alive = None
    if isinstance(pid, int):
        try:
            os.kill(pid, 0)
            pid_alive = True
        except ProcessLookupError:
            pid_alive = False
        except (OSError, PermissionError):
            # Exists, owned by someone else, or platform can't tell — not evidence
            # either way; treated as "cannot determine" rather than "gone".
            pid_alive = None
    if status == "stopped":
        return "STOPPED", f"The watcher (pid {pid}) shut down cleanly at {updated_at}."
    if pid_alive is False:
        return ("STOPPED", f"The watcher process (pid {pid}) is gone but never recorded a "
                           f"clean shutdown — it may have crashed. Last update: {updated_at}.")
    age_s = None
    try:
        from datetime import datetime  # noqa: PLC0415 - only needed here
        # `_now_iso()` (monitorstore.py), the sole producer of `updated_at`, writes
        # NAIVE local time — no "Z", no offset. `datetime.now(upd.tzinfo)` matches
        # that: `upd.tzinfo` is None for the real (naive) case, so this compares
        # naive-to-naive like the producer intends, while still doing the right thing
        # if a future producer ever switches to an aware timestamp (the "Z" -> "+00:00"
        # rewrite below exists for exactly that case, not today's).
        upd = datetime.fromisoformat(str(updated_at).replace("Z", "+00:00"))
        age_s = (datetime.now(upd.tzinfo) - upd).total_seconds()
    except (ValueError, TypeError):
        age_s = None
    if age_s is not None and age_s > interval * STALE_HEARTBEAT_MULTIPLE:
        return ("STALE", f"The watcher (pid {pid}) has not updated its heartbeat in "
                         f"{int(age_s)}s (expected every {int(interval)}s) — it may have hung.")
    return "ALIVE", f"The watcher (pid {pid}) is running, mode={heartbeat.get('mode')}, " \
                   f"{heartbeat.get('cycles', 0)} re-scan(s) so far. Last update: {updated_at}."
