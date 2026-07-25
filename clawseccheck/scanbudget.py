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

# F-148: the same idea for the vet paths, which run the content ring outside ``run_all`` and
# were therefore unbounded.
#
# CALIBRATION — measured, and the measurement matters more than the number. Ring cost is
# driven by INPUT SIZE, super-linearly, NOT by how hostile the content is:
#
#     10KB 0.03s · 50KB 0.20s · 100KB 0.52s · 250KB 2.80s · 500KB 10.62s · 1MB 41.23s   (CPU)
#
# ``collector._MAX_BYTES_PER_SKILL`` is 1_000_000, so a perfectly BENIGN skill at the legal
# size cap already costs ~41 s, with up to another megabyte of Python source on its own axis.
# Across the 201 real scanned targets in fixtures/ the median is 3 ms and p99 is 30 ms; the
# real hostile `clawstealth` costs 7.93 s — i.e. LESS than a large benign skill. An earlier
# 60 s ceiling was calibrated on the claim that a 6.6 MB benign skill cost 0.22 s; that was an
# artifact — the skill was ClawSecCheck's own source, which `_is_own_source` short-circuits
# before scanning anything (0.01 s). At 60 s the ceiling sat ~1.5x over a legal benign skill,
# so a large-but-harmless skill would have been reported as unscanned; that is the false
# positive this scanner may not have (§2, Golden Rule #5).
#
# 300 s is ~7x the benign worst case idle. Headroom is what prevents the false positive, so
# it has to survive a loaded machine too: measured, load inflates the cost ~2.6x (and inflates
# CPU time just as much as wall — see cpu_deadline), which still leaves ~2.8x. Below roughly
# 120 s the margin stops covering that, so do not lower this without re-measuring.
DEFAULT_VET_TARGET_BUDGET_S = 300.0

# The sweep ceiling stays WALL-CLOCK on purpose: it exists so a user is not left staring at a
# hung terminal, and "how long have I waited" is wall time by definition. It is safe to keep
# load-sensitive because it never moves a verdict — it only marks the targets it did not reach
# as explicitly not-scanned.
DEFAULT_VET_ALL_BUDGET_S = 600.0


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


# F-148: the deadline pair above is not audit-specific — it is a plain monotonic clock the
# vet paths reuse to bound one target and a whole ``--vet-all`` sweep. Aliased rather than
# re-implemented so there is one cooperative-cap implementation, and named neutrally so a
# vet-side call site does not read as if it were capping an audit.
budget_deadline = audit_deadline
budget_exceeded = audit_budget_exceeded


def cpu_deadline(budget_s: float) -> float | None:
    """Return a CPU-time deadline for one scan, or None to disable the cap.

    Measures this process's own CPU rather than elapsed time, so the budget is not spent
    while blocked on I/O. That is the honest, modest reason to prefer it here; the ring is
    pure regex/AST work over content already in memory, so CPU is the closer proxy for "how
    much scanning has this target actually had".

    It is NOT a defence against machine load, and the docstring says so because the obvious
    assumption is wrong. Measured on an 8-core box, the same benign ~250KB skill through the
    real ring, idle versus 24 competing busy processes:

        idle            wall 0.49s   cpu 0.49s
        under 24x load  wall 1.29s   cpu 1.27s     (2.6x wall, 2.60x CPU)

    CPU time inflates essentially identically — cache contention and frequency scaling make
    the same instructions cost more CPU-seconds. What keeps load from deciding a verdict is
    HEADROOM, not the choice of clock: see the calibration note on
    ``DEFAULT_VET_TARGET_BUDGET_S``, where the ceiling sits ~7x over the benign worst case
    idle and still ~2.8x after that measured inflation.
    """
    if budget_s and budget_s > 0:
        return time.process_time() + budget_s
    return None


def cpu_exceeded(deadline: float | None) -> bool:
    """True once the CPU-time ``deadline`` (from :func:`cpu_deadline`) has passed."""
    return deadline is not None and time.process_time() >= deadline
