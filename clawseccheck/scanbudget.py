"""Wall-clock budget for the full audit (C-159) — stdlib-only, platform-detected.

A byte cap bounds how much a check *reads*, but not how long a pathological
(ReDoS-class) regex *runs* over that input. This module gives ``run_all`` a time
budget so a slow/hostile check degrades to UNKNOWN instead of hanging the audit.

Two enforcement layers, because the platforms differ in what is even possible:

* **Per-check hard timeout — POSIX main thread only.** ``signal.setitimer(SIGALRM)``
  is the only stdlib mechanism that can interrupt a check *mid-match*, even inside a
  C-level ``re`` call that never yields to Python. The vast majority of users
  (Linux/macOS) get this. See :func:`check_deadline`.
* **Per-audit cooperative cap — every platform.** Between checks, ``run_all`` asks
  :func:`audit_budget_exceeded` whether the whole-audit deadline has passed and, if
  so, marks the remaining checks UNKNOWN. This bounds cumulative time and is the
  *only* bound available on Windows / a non-main thread, where a single check stuck
  in a C-level regex cannot be preempted in pure stdlib (a known limitation, tied to
  the Windows-parity task C-160).

Budgets are generous — they exist to stop pathological hangs, never to clip a
normal run (which finishes in well under a second).
"""
from __future__ import annotations

import contextlib
import signal
import threading
import time
from collections.abc import Iterator

# Generous ceilings: a real audit is sub-second; these only catch a pathological hang.
DEFAULT_CHECK_BUDGET_S = 15.0
DEFAULT_AUDIT_BUDGET_S = 120.0


class ScanBudgetExceeded(Exception):
    """Raised inside a check when its per-check wall-clock budget is exhausted."""


def _can_hard_timeout() -> bool:
    """True when a POSIX itimer-based hard deadline is available and usable here.

    ``signal.setitimer`` / ``SIGALRM`` exist only on Unix, and a signal handler can be
    installed only from the main thread — so a non-main-thread caller falls back to the
    cooperative cap.
    """
    return (
        hasattr(signal, "SIGALRM")
        and hasattr(signal, "setitimer")
        and threading.current_thread() is threading.main_thread()
    )


@contextlib.contextmanager
def check_deadline(seconds: float) -> Iterator[None]:
    """Arm a hard per-check deadline for the duration of the ``with`` block (POSIX).

    On exit the itimer is always disarmed and the previous ``SIGALRM`` handler restored,
    so this never leaves a pending alarm or clobbers a caller's handler. Where a hard
    timeout is unavailable (Windows, non-main thread, or ``seconds <= 0``) this is a
    transparent no-op and the caller relies on the cooperative per-audit cap instead.
    """
    if seconds <= 0 or not _can_hard_timeout():
        yield
        return

    def _fire(_signum, _frame):
        raise ScanBudgetExceeded

    previous = signal.signal(signal.SIGALRM, _fire)
    try:
        signal.setitimer(signal.ITIMER_REAL, seconds)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)  # disarm before restoring the handler
        signal.signal(signal.SIGALRM, previous)


def audit_deadline(audit_budget_s: float) -> float | None:
    """Return a monotonic deadline for the whole audit, or None to disable the cap."""
    if audit_budget_s and audit_budget_s > 0:
        return time.monotonic() + audit_budget_s
    return None


def audit_budget_exceeded(deadline: float | None) -> bool:
    """True once the whole-audit ``deadline`` (from :func:`audit_deadline`) has passed."""
    return deadline is not None and time.monotonic() >= deadline
