"""B-108: advisory file locking for the hash-chained journal write-path.

history.jsonl and events.jsonl are hash-chained: an append reads the *last*
chain_hash, then appends the new line(s) computed from it. Two processes racing
that read-then-append window can each read the same "last" hash and both append,
leaving the journal with two lines that both legitimately point at the same
prev_hash — a false "chain BROKEN" from verify_chain's point of view even though
neither writer did anything wrong.

``journal_lock`` closes that race with a POSIX advisory ``flock`` (``fcntl``) on a
dedicated *sidecar* lock file (``<target>.lock``), never the data file's own fd —
append() reopens the data file's fd fresh every call (via ``os.open``) and rotation
(C-164) replaces its inode outright, so a lock tied to the data file's fd would not
serialize across either. A sidecar path is stable across both.

Degrades to a **no-op** whenever locking cannot be trusted to help: no ``fcntl``
(non-POSIX platforms — most notably Windows), or any failure acquiring/releasing
the lock. It never raises and never blocks the append from happening — worst case
without a working lock is the pre-existing (rare, already-documented) race, not a
new failure mode. A pre-existing ``.lock`` file left over from a crashed process is
NOT "held" from ``flock``'s point of view; a fresh process re-acquires it fine
(that is exactly the POSIX advisory-lock contract — locks are process-lifetime, not
filesystem-persistent).

Pure stdlib, no network.
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path

try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:  # pragma: no cover - exercised on POSIX CI; real gap on Windows
    fcntl = None  # type: ignore[assignment]
    _HAS_FCNTL = False

from .safeio import _open_owner_only, secure_dir


@contextmanager
def journal_lock(target: "str | Path"):
    """Advisory-lock the journal at *target* for the duration of the ``with`` block.

    Takes an exclusive ``flock`` on ``<target>.lock`` (created owner-only, 0600,
    symlink-safe — same primitives as the rest of the local store). Never raises:
    on any failure to prepare/acquire the lock, or when ``fcntl`` is unavailable,
    this is a no-op context manager (the critical section still runs, just without
    the extra serialization). Always releases (``LOCK_UN`` + close) in ``finally``.
    """
    if not _HAS_FCNTL:
        yield
        return

    lock_path = Path(str(target) + ".lock")
    fd = None
    locked = False
    try:
        secure_dir(lock_path.parent)
        fd = _open_owner_only(lock_path, 0)
        fcntl.flock(fd, fcntl.LOCK_EX)
        locked = True
    except OSError:
        pass  # degrade to no-op — never block/crash the append

    try:
        yield
    finally:
        if fd is not None:
            if locked:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
            try:
                os.close(fd)
            except OSError:
                pass
