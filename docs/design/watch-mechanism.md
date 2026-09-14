# `--watch`'s mechanism: ctypes + libc inotify, with a stat-poll fallback

Design note for the continuous watch mode added alongside `--monitor` (`clawseccheck/watch.py`).
No code change is made by this document; it records why the mechanism looks the way it does and
what was actually verified, not assumed.

## 1. The constraint

ClawSecCheck ships zero runtime dependencies (Python 3.9+, stdlib only — see `pyproject.toml`'s
empty `dependencies = []` and this project's own golden rule). A real file-change notification
API on Linux is `inotify(7)`, but the Python standard library has no binding for it — the usual
third-party answer is a package like `inotify_simple` or `watchdog`, both of which are exactly
the dependency this project cannot add.

The alternative the stdlib does offer natively is polling: `os.stat()` every relevant path on a
timer and diff the result. That works everywhere, costs nothing to add, and is materially worse
for the one thing `--watch` exists to improve on `--monitor` — latency and CPU spent between
real changes.

## 2. The decision

Use the inotify syscalls directly via `ctypes` against the system's libc, and fall back to
stat-based polling only where that is not possible:

```python
libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
fd = libc.inotify_init1(IN_CLOEXEC | IN_NONBLOCK)
wd = libc.inotify_add_watch(fd, os.fsencode(str(path)), mask)
```

This is stdlib-only in the sense that matters here: `ctypes` is itself a standard-library
module, and nothing outside the base Python install is required. It is Linux-only by
construction — `inotify(7)` is a Linux kernel facility with no equivalent syscall on macOS or
Windows — so `clawseccheck/watch.py` never assumes it works and always has a working fallback
(`PollWatcher`) ready.

### Why not `ctypes` for macOS's `kqueue`/`FSEvents` too

Out of scope for this task. `PollWatcher` covers every non-Linux platform uniformly today;
adding a second real mechanism (kqueue via ctypes) is a natural follow-up but doubles the
surface this module has to get right for a platform this project has not yet measured usage on.
Filed as a known gap, not a silent one.

## 3. What was actually verified, not assumed

The rule this codebase applies everywhere else (`CLAUDE.md`'s recurring "ground the platform
claim", "execute the vendor function, don't read it") applies here too: whether the ctypes
binding actually works was tested against the real kernel on the development machine before any
fallback logic was written to depend on it, not inferred from `sys.platform == "linux"` alone.

Verified directly (Linux 6.x, glibc, no container/sandbox restriction beyond the ordinary):

```text
inotify_init1 OK fd= 3
add_watch OK wd= 1 dir= /tmp/tmpXXXXXXXX
select readable: True
event wd=1 mask=0x100 cookie=0 name=b'x.txt'   # IN_CREATE
event wd=1 mask=0x2   cookie=0 name=b'x.txt'   # IN_MODIFY
event wd=1 mask=0x8   cookie=0 name=b'x.txt'   # IN_CLOSE_WRITE
```

A single `open(...).write(...)` on a watched directory produced exactly the three events a
config-file save is expected to produce, read back through `select()` + `os.read()` + manual
`struct.unpack` of the `inotify_event` header — confirming the whole chain (syscall binding,
non-blocking read, wire-format parsing) works end to end, not just that `inotify_init1` returns
a non-negative fd.

`probe_inotify()` in `clawseccheck/watch.py` encodes this as a live check rather than a platform
guess: it performs the same `inotify_init1` call (and closes the fd immediately) every time it
is asked, so a Linux **sandbox** that blocks the syscall itself (seccomp, an unusual container
policy) degrades to the poll fallback exactly like a non-Linux host would — `make_watcher()`
never trusts `sys.platform` alone; the only thing that decides which class it returns is whether
constructing `InotifyWatcher` actually succeeded.

## 4. Recursive watching

`inotify` watches a single directory, not a subtree — there is no native recursive flag. This
module handles that by hand:

- On start, every existing subdirectory under `--home` gets its own watch descriptor
  (`_bounded_watch_dirs`, capped at `DEFAULT_MAX_WATCH_DIRS` = 20,000 directories, symlinks never
  followed — the same discipline `safeio.walk_dir_safely` already applies to file walks
  elsewhere in this codebase). A tree that would need more watches than the cap is disclosed
  (`watch_dirs_capped: true` in the heartbeat) rather than silently watching only part of it.
- A directory created *after* start-up is caught via its own `IN_CREATE | IN_ISDIR` event on its
  parent's watch, and a watch is added for it immediately — so a new subdirectory is never a
  permanent blind spot, only a brief one between its creation and the next event drain.
- `IN_Q_OVERFLOW` (the kernel dropped events because they were not read fast enough) is treated
  as "something changed" unconditionally, never silently absorbed — under-reporting here would
  reopen exactly the gap this module exists to close.

## 5. The poll fallback

`PollWatcher` walks the same directory tree (bounded the same way) and stat()s every file,
comparing `(mtime_ns, size)` against the previous pass. It is deliberately the *only* other
mechanism this module implements — no inotify-like third-party polling library, no `select()`
tricks beyond what `os.walk` already gives for free. It is slower to notice a change (bounded by
its own poll interval, default 1s) and costs real CPU/IO on a large tree every cycle, which is
exactly the tradeoff `--watch` exists to avoid when the real mechanism is available — but it is
correct, bounded, and needs nothing beyond the standard library.

## 6. Debounce sits above both mechanisms

Neither watcher class knows about debouncing. `run_watch()`'s own loop asks
`watcher.poll_for_change(timeout)` in a tight "keep draining while the quiet window has not
elapsed" cycle (`--watch-debounce`, default 2s) before triggering the re-scan — so a burst of
several inotify events (a config tool's write-then-rename is 3 events on its own, per §3) or
several poll cycles that each see a difference collapse into exactly one `--monitor --verbose`
invocation, never one per raw event. This was verified end-to-end (three writes 0.2s apart
inside a 1s debounce window; the heartbeat's `cycles` counter advanced by exactly 1).

## 7. Detection stays a single implementation

`run_watch()` never re-implements drift comparison. On a debounced change it shells out to
`python3 -m clawseccheck --monitor --verbose --home ... --state ... --events ... --history ...`
— the identical invocation `scripts/monitor_detection_gate.py` already uses to drive this tool
from outside the library — so the alert text, severity mapping and the tamper-evident event
journal are exactly what `--monitor --verbose` produces on its own. This also means `--watch`
inherits every property `--monitor` already has (baseline corruption handling, config-blind
degradation, the coverage/freshness notes) with no separate code path to keep in sync.

## 8. Liveness

A watcher that dies silently is worse than no watcher. `run_watch()` writes a heartbeat file
under the caller's store directory (`<data-dir>/watch_heartbeat.json`) on start, on every
completed re-scan, and periodically (default every 30s) while idle, recording `pid`, `mode`
(`inotify`/`poll`), `status` (`starting`/`running`/`stopped`), `cycles`, and the last re-scan's
timestamp/exit code. `--watch-status` reads it back and reports one of four states — `ALIVE`,
`STALE` (heartbeat older than three of its own intervals), `STOPPED` (a clean shutdown was
recorded, or the pid is confirmed gone), or `NOT RUNNING` (no heartbeat file at all) — the same
"don't collapse absence into a single ambiguous answer" discipline `--verify-baseline` already
applies to a missing vs. corrupt state file.
