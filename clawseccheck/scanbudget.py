"""Wall-clock budget for the full audit (C-159) — stdlib-only, platform-detected.

A byte cap bounds how much a check *reads*, but not how long a pathological
(ReDoS-class) regex *runs* over that input. This module gives ``run_all`` a time
budget so a slow/hostile check degrades to UNKNOWN instead of hanging the audit.

Two enforcement layers, because the platforms differ in what is even possible:

* **Per-check hard timeout — POSIX main thread only.** ``signal.setitimer(SIGALRM)``
  is the only stdlib mechanism that can interrupt a check *mid-match*, even inside a
  C-level ``re`` call that never yields to Python. The vast majority of users
  (Linux/macOS) get this. See :func:`check_deadline`, which is **re-entrant**: nested
  blocks share the one process-wide itimer through a stack of absolute deadlines, and
  :class:`ScanBudgetExceeded` names the frame whose deadline expired.
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

import signal
import threading
import time

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
# size cap already costs ~41 s — but that single-axis figure is INCOMPLETE: a skill also has
# its OWN independent 1 MB caps on Python (`_MAX_PY_BYTES_PER_SKILL`), shell and JS source
# (`read_skill_shell`/`read_skill_js` reuse the same constant), plus the ~500-file cap
# (`_MAX_FILES_PER_SKILL`) — all FOUR axes are additive on one skill, and the number above was
# never measured against that combined worst case.
#
# Re-measured (2026-07-28) against a single skill that legally saturates all four axes AT
# ONCE — 500 files (the file cap) split evenly across `.py`/`.sh`/`.js`/`.md`, each axis's own
# collector landing just over its 1 MB cap — filled with genuinely benign, zero-finding prose
# ("these helpers are shipped with this skill", repeated; contains no destination/URL, so it
# never trips B156 or any other ring check — confirmed empty `ring findings: []`). Plain
# comment-line filler UNDERSHOOTS the real cost badly and must not be used to calibrate this:
# cost tracks MATCH DENSITY against a check's own trigger regex (e.g. B156's send-verb class
# matches the ordinary word "shipped"), not prose "naturalness" — every match then rescans the
# WHOLE blob for its defensive/heading context, so realistic technical prose is the expensive
# shape, not padding. `_run_content_ring` alone (the thing this constant bounds) on that
# skill:
#
#     Python 3.12.3 (this box):  204.0s CPU (208.5s wall)
#     Python 3.9.25 (uv, CI floor): 238.2s CPU (238.8s wall)  — ~1.17x slower than 3.12 here,
#                                    NOT the ~1.05x previously observed on other workloads;
#                                    3.9-vs-3.12 slowdown is workload-dependent — re-measure it
#                                    per workload, don't carry a prior ratio forward.
#
# (`check_installed_skills`, which vet_skill/vet_all always run before the ring and which this
# constant does NOT bound, added a further ~2.4-3.7s CPU on the same skill — small next to the
# ring, but note it is currently unbounded on this path.)
#
# benign_worst_case_s = 238.2 (the higher, 3.9, CPU figure for the ring alone — use the worse
# of the two interpreter measurements, not the average). Headroom is what prevents the false
# positive, so it has to survive a loaded machine too: load inflates CPU time ~2.6x (measured
# previously — see cpu_deadline; not independently re-measured this round, reused as-is).
# Minimum ceiling that survives that: 238.2 * 2.6 = ~619.3s. 900s leaves ~1.45x margin over
# that inflated minimum (~280.7s of absolute buffer — a larger raw
# buffer than the previous 300s ceiling had over ITS inflated minimum of 107.1s, even though
# the ratio-over-idle is smaller: idle content this size is simply much more expensive now
# that it is correctly measured). Do not lower this without re-measuring on a skill built the
# same way (all four axes + file cap, "shipped"-dense benign prose, verified zero findings).
DEFAULT_VET_TARGET_BUDGET_S = 900.0

# The sweep ceiling stays WALL-CLOCK on purpose: it exists so a user is not left staring at a
# hung terminal, and "how long have I waited" is wall time by definition. It is safe to keep
# load-sensitive because it never moves a verdict — it only marks the targets it did not reach
# as explicitly not-scanned.
#
# Raised from 600s in lock-step with DEFAULT_VET_TARGET_BUDGET_S going 300s -> 900s (see
# that constant's calibration comment above). Left at 600s, a single maximal-legal-benign
# target hitting its own new 900s per-target ceiling would alone exceed the WHOLE sweep
# budget — vet_all only checks its wall deadline BETWEEN targets, so that one target runs
# to its own ceiling uninterrupted, and every other target in the sweep would then read as
# "not reached" (honest, per the F-148 design — never silently marked safe — but a sweep
# that can be starved down to one target by the FIRST large-but-harmless skill it meets
# defeats the point of a sweep). 1800s gives room for at least one full-cost target plus
# meaningful headroom for the rest of a real fleet, whose median per-target cost is
# milliseconds (see the ring calibration above). A batch containing several simultaneous
# maximal-cost targets can still exhaust even this — that is accepted: the design already
# degrades honestly (unreached targets are reported as such, kept out of the "safe" tally,
# non-zero exit), never as a fabricated PASS.
DEFAULT_VET_ALL_BUDGET_S = 1800.0


class ScanBudgetExceeded(Exception):
    """Raised inside a check when a wall-clock budget it is running under is exhausted.

    ``owner`` says WHOSE deadline expired: the :class:`DeadlineFrame` handed out by the
    :func:`check_deadline` block that armed it, or ``None`` for the **cooperative,
    non-timer** raises the engine makes on its own (``skillast``'s reached-sinks cap).
    An unattributed raise belongs to nobody; it travels out to ``run_all``, which is its
    designated handler.

    The attribution exists so a *nested* handler can tell its own expiry from an outer
    owner's. Catching someone else's hands that owner a partial scan presented as a
    complete one — the false-PASS class C-175 fixed. Test the owner with :func:`owned_by`
    rather than by catching broadly.
    """

    def __init__(self, *args: object, owner: DeadlineFrame | None = None) -> None:
        super().__init__(*args)
        self.owner = owner


class DeadlineFrame:
    """Identity of one armed :func:`check_deadline` block — and its truncation flag.

    Handed out by the context manager, so a caller can both name itself when catching
    (``owned_by(exc, frame)``) and, under ``suppress_own``, ask afterwards whether its
    block was cut short (``frame.expired``).
    """

    __slots__ = ("armed", "deadline", "delivered", "expired")

    def __init__(self, deadline: float | None, armed: bool) -> None:
        self.deadline = deadline          # absolute time.monotonic(), None when inactive
        self.armed = armed                # False on the transparent no-op path
        self.expired = False              # set when an expiry is attributed to this frame
        # Internal: this frame's expiry has actually been RAISED into user code. An
        # expired frame's deadline is permanently the earliest one on the stack, so
        # without this it would be blamed for every later expiry too — starving every
        # nested block and re-arming the itimer at a stale tiny slice forever. A frame's
        # hard deadline fires ONCE; after that it has had its say.
        self.delivered = False

    def __repr__(self) -> str:                                    # pragma: no cover
        state = "expired" if self.expired else ("armed" if self.armed else "inactive")
        return f"<DeadlineFrame {state}>"


def owned_by(exc: ScanBudgetExceeded, frame: DeadlineFrame | None) -> bool:
    """True when ``exc`` is the expiry of ``frame``'s OWN deadline.

    False for an outer owner's deadline and false for an unattributed
    (``owner is None``) cooperative raise — both must keep travelling to their real
    handler. Written as a helper because ``exc.owner is frame`` is easy to get subtly
    wrong at a call site (``None is None`` would let any frame claim every unattributed
    raise).
    """
    return frame is not None and getattr(exc, "owner", None) is frame


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


# ── re-entrancy: one itimer, a stack of absolute deadlines ───────────────────
#
# A process has exactly ONE ``ITIMER_REAL``, so nesting has to be modelled rather than
# hoped away. The state is a stack of **absolute** monotonic deadlines with the itimer
# always pointed at the earliest one still on it. Three properties fall out of that
# representation for free:
#
#   * an inner block is implicitly clamped to min(its own budget, the outer's
#     remaining) — nobody computes the clamp, it is simply which deadline is earliest;
#   * on exit the outer is restored at its TRUE remaining time, with the wall time spent
#     inside the inner charged to it, because its deadline never moved;
#   * there is no restore arithmetic, so nesting cannot accumulate drift.
#
# The predecessor armed the itimer on entry and called ``setitimer(ITIMER_REAL, 0)``
# unconditionally on exit. Nesting it was therefore fail-OPEN, not merely imprecise: the
# inner block overwrote the outer's deadline going in and *disarmed* the timer coming
# out, so from the moment the inner returned the outer hard cap no longer existed and
# nothing could interrupt a hung check for the rest of that run. Nothing detects that
# after the fact either — ``signal.getitimer`` reports ``(0.0, 0.0)`` for "disarmed" and
# for "already expired" alike.
_STACK: list[DeadlineFrame] = []

_UNSET = object()
_PREV_HANDLER: object = _UNSET

# Re-arming an already-passed deadline uses this floor instead of its true (negative)
# remainder, because ``setitimer(..., 0)`` means DISARM — the exact fail-open above.
# Measured on Linux/CPython 3.12: ``setitimer(1e-6)`` reads back as ``(0.0, 0.0)`` (it has
# already elapsed by the time it can be read at all), whereas ``setitimer(1e-4)`` reads
# back as ~9.8e-05, i.e. it is a real, still-pending arm. So 1e-4 is the smallest slice
# that reliably means "armed" rather than "gone".
_MIN_ARM_S = 1e-4


def _arm_seconds(deadline: float, now: float) -> float:
    """Seconds to hand ``setitimer`` for an absolute monotonic ``deadline``.

    Never returns 0 or less, since that would disarm rather than fire immediately.
    """
    return max(deadline - now, _MIN_ARM_S)


def _rearm() -> None:
    """Point the itimer at the earliest deadline that has not had its say yet.

    The single choke point: every state change routes its timer update through here, so
    "an expired deadline is re-armed with a minimum positive slice, never disarmed" is one
    property of one function rather than a claim repeated at four call sites (where the
    predecessor's version of this guarantee was true in the nested case and false in the
    single-frame one).
    """
    earliest = None
    for frame in _STACK:                     # plain loop, not min()/a comprehension —
        if frame.delivered:                  # see _in_bookkeeping on why no helper code
            continue                         # objects may appear inside this module
        if earliest is None or frame.deadline < earliest:
            earliest = frame.deadline
    if earliest is None:
        signal.setitimer(signal.ITIMER_REAL, 0)
    else:
        signal.setitimer(signal.ITIMER_REAL, _arm_seconds(earliest, time.monotonic()))


# ── handing SIGALRM back: the disarm does NOT retract what the kernel already owes ──
#
# Measured: block SIGALRM, arm 1ms, spin 20ms, then setitimer(ITIMER_REAL, 0) -> sigpending()
# STILL reports SIGALRM. Disarming prevents FUTURE firings only; an expiry the kernel has
# already generated stays owed and is delivered at the next opportunity, against whatever
# disposition is installed AT THAT MOMENT.
#
# The predecessor of this function restored the caller's handler straight after the disarm
# and relied on ``signal.signal()`` clearing the "tripped" flag. That flag is CPython's, not
# the kernel's: it only covers an expiry CPython's C trampoline already received. One the
# KERNEL still owes lands afterwards, on the just-restored disposition — which for every real
# clawseccheck run is SIG_DFL, i.e. terminate. Linux happens to be immune (``do_setitimer``
# holds the same siglock the timer callback needs, so the owed signal is flushed on the
# return path of the disarm syscall itself): measured at 150,000 nested rounds under 12x
# load, and again with the window widened 1000x to 2ms — zero late deliveries either way.
# That immunity is a Linux kernel implementation property, not a POSIX guarantee, and macOS
# CI reproducibly died with "Alarm clock" (exit 142) in exactly this window.
#
# The close is POSIX, not a narrower window: setting a disposition to SIG_IGN DISCARDS any
# pending instance, blocked or not (verified). So hand back in three steps with delivery
# blocked throughout, so the swap can never be observed half-done:
#     block -> SIG_IGN (kernel discards the debt) -> the caller's handler -> restore the mask.
# ``sigpending()`` then CONFIRMS the discard before unblocking. If a platform ever refuses to
# discard, leaving SIG_IGN installed is a disclosed deviation from the restore contract and is
# strictly better than killing the user's audit; today no known platform takes that branch.
_ALRM_SET = frozenset({signal.SIGALRM}) if hasattr(signal, "SIGALRM") else frozenset()
_CAN_MASK = hasattr(signal, "pthread_sigmask") and hasattr(signal, "sigpending")
_DISCARD_PASSES = 3

# Observability only: set when a platform refused to discard an owed SIGALRM and SIG_IGN was
# left installed instead of a lethal SIG_DFL. Nothing reads it to decide anything.
_UNRESTORED_HANDLER: object = _UNSET


def _release() -> None:
    """Outermost exit: disarm, discard what the kernel still owes, hand the handler back."""
    global _PREV_HANDLER, _UNRESTORED_HANDLER
    signal.setitimer(signal.ITIMER_REAL, 0)
    previous = _PREV_HANDLER
    _PREV_HANDLER = _UNSET
    if previous is _UNSET:
        return
    if previous is None:
        # None means the prior handler was installed from C and cannot be restored from
        # Python (in practice unreachable here). SIG_DFL is the honest guess.
        previous = signal.SIG_DFL
    prev_mask = None
    if _CAN_MASK:
        try:
            prev_mask = signal.pthread_sigmask(signal.SIG_BLOCK, _ALRM_SET)
        except (OSError, ValueError):          # pragma: no cover - defensive
            prev_mask = None
    try:
        for _ in range(_DISCARD_PASSES):
            signal.signal(signal.SIGALRM, signal.SIG_IGN)
            signal.signal(signal.SIGALRM, previous)
            if prev_mask is None or signal.SIGALRM not in signal.sigpending():
                return
        signal.signal(signal.SIGALRM, signal.SIG_IGN)
        _UNRESTORED_HANDLER = previous
    finally:
        if prev_mask is not None:
            # SIG_SETMASK, not SIG_UNBLOCK: a caller who had SIGALRM blocked for their own
            # reasons must get their mask back exactly, not merely unblocked.
            signal.pthread_sigmask(signal.SIG_SETMASK, prev_mask)


def _blame() -> DeadlineFrame | None:
    """The frame whose deadline this expiry belongs to, or None if none is actually due.

    The itimer points at the earliest live deadline, so an expiry belongs to that frame —
    but "is it actually due" is not redundant. A delivery can land after the frame it
    belonged to was popped, and blaming whichever innocent frame is now earliest is worse
    than admitting we do not know. ``delivered`` frames are excluded: their deadline is
    permanently the earliest, so keeping their claim would blame them for every later
    expiry and starve every nested block.
    """
    now = time.monotonic()
    due = None
    for frame in _STACK:
        if frame.delivered:
            continue
        if frame.deadline - now > _MIN_ARM_S:
            continue                          # not due yet — an early/stray delivery
        if due is None or frame.deadline < due.deadline:
            due = frame
    return due


# ── async-signal safety: never raise into this module's own bookkeeping ──────
#
# ``_fire`` raises at an arbitrary bytecode boundary. If it lands inside the push/pop
# bookkeeping, that bookkeeping is abandoned half-done and the frame leaks — permanently,
# because the stack then never empties, the caller's SIGALRM handler is never given back,
# and every later deadline is armed at ``_MIN_ARM_S``. One leaked frame turns a whole
# subsequent audit UNKNOWN. Two guards were tried before this one; both are recorded
# because both look correct:
#
#   1. ``signal.pthread_sigmask(SIG_BLOCK, {SIGALRM})`` around the section. DOES NOT WORK.
#      ``signal.pthread_sigmask`` is a Python-level wrapper, so CPython runs pending
#      Python handlers at bytecode boundaries INSIDE the very call meant to protect the
#      section — the expiry is raised straight out of the masking call, before the ``try``
#      that would have cleaned up is even entered. Blocking at the OS level also does not
#      un-trip a signal CPython has already flagged: the C handler only sets a flag, and
#      the Python handler runs at the next bytecode boundary regardless.
#   2. A module-level "in critical section" flag set on entry. Closes the INTERIOR of the
#      section but not its entry: whatever SETS the flag can itself be interrupted first,
#      and on the pop path that is fatal (the pop is called from a ``finally`` that will
#      not be retried). No guard that must be ARMED IN ADVANCE can close this, because
#      arming it is itself interruptible.
#
# What works is to stop arming anything and answer the question at raise time instead. A
# Python signal handler is handed the **interrupted frame**, so ``_fire`` can ask "am I
# about to raise into this module's own bookkeeping?" — a predicate computed when it is
# needed, which therefore has no window at all. If the answer is yes it re-arms a minimum
# slice and returns; the expiry arrives ~100us later, by which time the bookkeeping has
# finished and the stack invariant holds.
#
# This is sound because Python handlers run only at bytecode boundaries and only on the
# main thread (which ``_can_hard_timeout`` already requires), so there is no true
# concurrency here — only re-entrancy, which is exactly what the frame check detects.
#
# The predicate walks the WHOLE ``f_back`` chain rather than testing only the innermost
# frame. That is the difference between a guard that is right and one that is right on
# the Python version it was written on: a lambda passed to ``min()`` and — before PEP 709
# inlined them in 3.12 — a list comprehension each get their OWN code object, which an
# innermost-frame-only test would not recognise as ours. Walking the chain means any such
# helper is covered by its caller, so the set below only has to name the ENTRY POINTS.
# (This module still avoids lambdas/comprehensions in the bookkeeping, belt and braces.)
# Nothing in this module ever calls user code, so a protected frame on the stack always
# means "we are inside the bookkeeping" — and while a ``with`` body runs, no frame of this
# module is on the stack at all, so a real check never has its expiry deferred.
_PROTECTED_CODE: frozenset = frozenset()


def _in_bookkeeping(interrupted: object) -> bool:
    """True when the interrupted stack has any of this module's own frames on it."""
    frame = interrupted
    while frame is not None:
        if getattr(frame, "f_code", None) in _PROTECTED_CODE:
            return True
        frame = getattr(frame, "f_back", None)
    return False


def _fire(_signum: int, interrupted: object) -> None:
    """SIGALRM handler: attribute the expiry to a frame, then raise it into the check."""
    if _in_bookkeeping(interrupted):
        # Deferral, not cancellation. Re-arming here rather than setting a "pending"
        # flag for the bookkeeping to drain is deliberate: a flag has to be drained by
        # SOMEBODY, and any code path that forgets to drain it silently loses the
        # deadline. A re-arm needs nobody's cooperation — worst case the bookkeeping's
        # own _rearm() overwrites it a moment later with the correct value.
        #
        # An EMPTY stack must disarm instead, and that asymmetry is load-bearing: the
        # bookkeeping we could be interrupting is then _release(), which is about to hand
        # the caller's SIGALRM handler back. Leaving a 100us arm behind would deliver an
        # alarm to that handler — for the default action, killing the process. With no
        # frames left there is also, by definition, no deadline worth preserving.
        signal.setitimer(signal.ITIMER_REAL, _MIN_ARM_S if _STACK else 0)
        return
    owner = _blame()
    if owner is None:
        # Nothing is actually due: an early or late delivery. Swallow it and restore the
        # real deadline — raising an unattributed exception here would turn a healthy
        # check into a spurious UNKNOWN.
        _rearm()
        return
    owner.expired = True
    owner.delivered = True
    _rearm()
    raise ScanBudgetExceeded(owner=owner)


def _index_of(frame: DeadlineFrame) -> int:
    for i in range(len(_STACK) - 1, -1, -1):
        if _STACK[i] is frame:
            return i
    return -1


def _push(frame: DeadlineFrame) -> None:
    global _PREV_HANDLER
    if not _STACK:
        _PREV_HANDLER = signal.signal(signal.SIGALRM, _fire)
    _STACK.append(frame)
    _rearm()


def _pop(frame: DeadlineFrame) -> None:
    """Normal block exit: drop ``frame`` and everything above it, then restore the timer.

    Truncating rather than removing is the self-healing half of the design. ``with``
    blocks nest lexically, so anything still above ``frame`` when ``frame`` exits is an
    inner block that has already ended and leaked — and reaping it here bounds the blast
    radius of a leak to its enclosing block instead of letting it poison the process.
    """
    idx = _index_of(frame)
    if idx >= 0:
        del _STACK[idx:]
    if _STACK:
        # An outer whose deadline passed while control was inside this block is re-armed
        # with a minimum positive slice, not cancelled. Disarming here is the fail-open:
        # it is how the outer hard cap used to disappear for good.
        _rearm()
    else:
        _release()


def _reap(frame: DeadlineFrame) -> None:
    """Finalizer path: drop just ``frame``, wherever it sits, then restore the timer.

    Deliberately NOT truncating. This runs from ``__del__``, i.e. at a moment nobody
    chose, so "everything above me has already ended" is not something it may assume —
    truncating from here could delete a live outer block's protection.
    """
    idx = _index_of(frame)
    if idx >= 0:
        del _STACK[idx]
    if _STACK:
        _rearm()
    else:
        _release()


class _DeadlineBlock:
    """The context manager :func:`check_deadline` returns. See its docstring.

    Written as an explicit class rather than ``@contextlib.contextmanager`` for one
    concrete reason: ``__enter__``/``__exit__`` then belong to THIS module, so they can
    be named in ``_PROTECTED_CODE``. With a generator-based manager the arming happens
    inside ``contextlib``'s ``__enter__``, whose code object is not ours, leaving a window
    in which an expiry raised after the push but before the ``with`` block is armed skips
    the cleanup entirely.
    """

    __slots__ = ("_closed", "_frame", "_seconds", "_suppress")

    def __init__(self, seconds: float, suppress_own: bool) -> None:
        self._seconds = seconds
        self._suppress = suppress_own
        self._frame: DeadlineFrame | None = None
        self._closed = False

    def __enter__(self) -> DeadlineFrame:
        if self._frame is not None and not self._closed:
            # Entering the SAME object twice would overwrite _frame, so the outer entry's
            # frame could never be popped by name. Nesting is supported through separate
            # check_deadline() calls, which is what every call site does; say so loudly
            # rather than leaking a frame.
            raise RuntimeError("a check_deadline() block cannot be entered re-entrantly")
        if self._seconds <= 0 or not _can_hard_timeout():
            self._frame = DeadlineFrame(None, armed=False)
            self._closed = True          # nothing to undo; __del__ must stay a no-op
            return self._frame
        self._closed = False             # a re-used object gets a fresh, poppable frame
        frame = DeadlineFrame(time.monotonic() + self._seconds, armed=True)
        # Recorded BEFORE the push, so that a frame which reaches the stack is always
        # reachable from this object — that is what makes the __del__ net total.
        self._frame = frame
        _push(frame)
        return frame

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        frame = self._frame
        if self._closed or frame is None:
            return False
        self._closed = True
        _pop(frame)                      # restore the outer BEFORE deciding to suppress
        return bool(
            self._suppress
            and exc_type is not None
            and isinstance(exc, ScanBudgetExceeded)
            and owned_by(exc, frame)
        )

    def __del__(self) -> None:
        # Last line of defence, and the reason a leak cannot outlive the block that
        # caused it. The interpreter's own with-statement setup/teardown has a handful of
        # bytecodes on either side of __enter__/__exit__ that belong to the CALLER's frame
        # and so cannot be protected by _in_bookkeeping. If an expiry lands there the
        # block is abandoned with its frame still on the stack — but this object is then
        # unreferenced, and CPython's refcounting finalizes it immediately, which reaps
        # the frame. (_pop's truncation covers the same leak for nested blocks; this
        # covers the outermost one, which has no enclosing block to reap it.)
        try:
            if self._closed or self._frame is None:
                return
            self._closed = True
            _reap(self._frame)
        except Exception:  # noqa: BLE001 — a finalizer must never raise
            pass


def check_deadline(seconds: float, *, suppress_own: bool = False) -> _DeadlineBlock:
    """Arm a hard deadline for the duration of the ``with`` block (POSIX).

    Re-entrant: a nested block is clamped to the outer's remaining time, and on exit the
    outer is restored at its true remaining time rather than cancelled. The block hands
    out its :class:`DeadlineFrame`, which names it as an owner::

        with check_deadline(15.0) as frame:
            ...
        # elsewhere, inside that block:
        except ScanBudgetExceeded as exc:
            if owned_by(exc, frame): ...        # mine — degrade this item
            raise                               # someone else's — must reach them

    With ``suppress_own=True`` the block instead swallows its OWN expiry and returns
    normally, leaving ``frame.expired`` True to report the truncation; an outer owner's
    expiry and an unattributed cooperative raise still propagate untouched. That is the
    opt-in for a loop that wants to skip an over-budget item and carry on.

    A frame's deadline fires ONCE. If the block swallows its own expiry and keeps
    working, nothing re-interrupts it — that has always been true here, and is why an
    over-broad ``except Exception`` around a scan is a bug rather than a style choice.

    At the outermost exit the itimer is disarmed and the previous ``SIGALRM`` handler
    restored, so this never leaves a pending alarm or clobbers a caller's handler. The
    handler is captured once, at the outermost entry, and given back once, at the
    outermost exit — not per nesting level. Where a hard timeout is unavailable (Windows,
    non-main thread, or ``seconds <= 0``) it is a transparent no-op — an inactive frame
    that never becomes an owner — and the caller relies on the cooperative per-audit cap
    instead.
    """
    return _DeadlineBlock(seconds, suppress_own)


# Every function that can be on the stack while this module's state is mid-change. An
# expiry raised into any of them abandons the bookkeeping in flight; ``_fire`` defers
# instead. Helpers reached FROM these (and any per-version helper code object) are
# covered by ``_in_bookkeeping``'s walk up the caller chain, so this set names entry
# points only. ``check_deadline`` itself is absent on purpose: it constructs an object
# and changes no state, so an expiry there is safe to take immediately.
_PROTECTED_CODE = frozenset({
    fn.__code__ for fn in (
        _arm_seconds, _rearm, _release, _blame, _in_bookkeeping, _fire,
        _index_of, _push, _pop, _reap,
        _DeadlineBlock.__enter__, _DeadlineBlock.__exit__, _DeadlineBlock.__del__,
    )
})


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
    ``DEFAULT_VET_TARGET_BUDGET_S``, where the ceiling still leaves ~1.45x margin (~280.7s)
    over the benign worst case AFTER applying this same measured inflation factor.
    """
    if budget_s and budget_s > 0:
        return time.process_time() + budget_s
    return None


def cpu_exceeded(deadline: float | None) -> bool:
    """True once the CPU-time ``deadline`` (from :func:`cpu_deadline`) has passed."""
    return deadline is not None and time.process_time() >= deadline
