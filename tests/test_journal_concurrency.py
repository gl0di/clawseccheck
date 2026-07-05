"""Tests for B-108 — advisory file locking on the hash-chained journal write-path.

Covers:
  - real multi-process concurrent appends to one shared journal keep the
    hash-chain valid and lose no lines (the actual race journal_lock closes).
  - graceful no-op degrade when fcntl is unavailable (append still works).
  - the lock sidecar file is created owner-only (0600) on POSIX.
"""
from __future__ import annotations

import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pytest

import clawseccheck.locking as locking
from clawseccheck.history import record as history_record
from clawseccheck.monitor import verify_chain

N_WORKERS = 4
N_PER_WORKER = 25


def _worker_append(path: str, worker_id: int, count: int) -> None:
    """Module-level (picklable) worker: append `count` history rows to `path`."""
    from types import SimpleNamespace

    from clawseccheck.history import record

    for i in range(count):
        score = SimpleNamespace(score=worker_id * 1000 + i, grade="C")
        record(score, path=path, when="2026-01-01")


# ---------------------------------------------------------------------------
# real multi-process concurrency
# ---------------------------------------------------------------------------

def test_interleaved_appends_keep_chain_valid(tmp_path: Path) -> None:
    if not locking._HAS_FCNTL:
        pytest.skip("flock unavailable")

    journal = tmp_path / "history.jsonl"
    path = str(journal)

    with ProcessPoolExecutor(max_workers=N_WORKERS) as ex:
        futures = [
            ex.submit(_worker_append, path, wid, N_PER_WORKER)
            for wid in range(N_WORKERS)
        ]
        for f in futures:
            f.result()

    assert journal.is_file()
    lines = [ln for ln in journal.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == N_WORKERS * N_PER_WORKER

    ok, msg = verify_chain(journal)
    assert ok is True
    assert msg == "OK"


# ---------------------------------------------------------------------------
# graceful degrade without fcntl
# ---------------------------------------------------------------------------

def test_lock_noop_without_fcntl(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(locking, "_HAS_FCNTL", False)

    from types import SimpleNamespace

    journal = tmp_path / "history.jsonl"
    history_record(SimpleNamespace(score=10, grade="D"), path=str(journal), when="2026-01-01")
    history_record(SimpleNamespace(score=20, grade="C"), path=str(journal), when="2026-01-02")

    lines = [ln for ln in journal.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 2

    ok, msg = verify_chain(journal)
    assert ok is True
    assert msg == "OK"


# ---------------------------------------------------------------------------
# lock sidecar permissions
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits not meaningful on Windows")
def test_lock_file_is_0600_posix(tmp_path: Path) -> None:
    if not locking._HAS_FCNTL:
        pytest.skip("flock unavailable")

    from types import SimpleNamespace

    journal = tmp_path / "history.jsonl"
    history_record(SimpleNamespace(score=42, grade="B"), path=str(journal), when="2026-01-01")

    lock_path = Path(str(journal) + ".lock")
    assert lock_path.exists()
    mode = lock_path.stat().st_mode & 0o777
    assert mode == 0o600
