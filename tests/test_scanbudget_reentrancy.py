"""``check_deadline`` is re-entrant: nested blocks share one itimer without fail-open.

The bug this pins: the predecessor armed the single process-wide ``ITIMER_REAL`` on
entry and called ``setitimer(ITIMER_REAL, 0)`` unconditionally in its ``finally``.
Nesting it was fail-OPEN — the inner block overwrote the outer's deadline going in and
*disarmed* the timer coming out, so the outer hard cap silently stopped existing for the
rest of the run and nothing could interrupt a hung check.

These tests are deliberately split into three layers, because a suite that only tests
the happy path is how the first attempt at this fix passed 23/23 while leaking frames:

  1. **Behaviour** — clamping, restore-on-exit, owner attribution, ``suppress_own``.
  2. **Mechanism** — the async-signal guard itself (``_in_bookkeeping`` / ``_fire``), so
     removing the guard reddens a *deterministic* test rather than only shifting the odds
     on a probabilistic one.
  3. **Stress** — many thousands of nested enter/exit cycles at sub-millisecond budgets,
     the regime where the earlier attempt leaked ~0.1% of frames. Measured on this suite:
     with the guard removed the stress test reports ~30 leaks per 30k rounds; with it,
     zero.

Speed/determinism rule followed throughout: assert through ``signal.getitimer`` wherever
the timer never has to actually fire. Where a real fire is needed the budget is >=50ms
with a self-terminating busy loop — never 1ms, which can fire inside ``__enter__`` on a
loaded runner and make the test flaky.
"""
from __future__ import annotations

import gc
import signal
import sys
import threading
import time

import pytest

import clawseccheck.scanbudget as sb
from clawseccheck.scanbudget import (
    DeadlineFrame,
    ScanBudgetExceeded,
    _can_hard_timeout,
    check_deadline,
    owned_by,
)

POSIX = _can_hard_timeout()
posix_only = pytest.mark.skipif(not POSIX, reason="hard timeout needs POSIX + main thread")


@pytest.fixture(autouse=True)
def _no_leaked_frame_or_alarm():
    """Every test in this file must leave the module exactly as it found it.

    Asserted rather than merely repaired: a leaked frame is the failure mode this whole
    change exists to prevent, so it has to redden a test, not be quietly swept up. The
    repair still runs first, so one failing test cannot poison the rest of the file.
    """
    if not POSIX:
        yield
        return
    before = signal.getsignal(signal.SIGALRM)
    yield
    leaked_frames = list(sb._STACK)
    leaked_alarm = signal.getitimer(signal.ITIMER_REAL)
    leaked_handler = signal.getsignal(signal.SIGALRM)
    # repair first, assert second. Uses the same discard-safe restore as _release() (see
    # Defect E below) rather than a bare disarm-then-restore: a leaked test could leave a
    # real alarm genuinely owed by the kernel, and handing it straight to `before` here
    # would be this fixture's own repair path crashing the very run it's meant to protect.
    del sb._STACK[:]
    signal.setitimer(signal.ITIMER_REAL, 0)
    _release_a_direct_rearm(before)
    sb._PREV_HANDLER = sb._UNSET
    assert leaked_frames == [], f"leaked deadline frame(s): {leaked_frames}"
    assert leaked_alarm[0] == 0.0, f"leaked pending alarm: {leaked_alarm}"
    assert leaked_handler is before, "SIGALRM handler was not given back"


def _busy(seconds: float) -> None:
    """Burn CPU for at most ``seconds`` — self-terminating, so a test can never hang."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        pass


def _armed() -> float:
    return signal.getitimer(signal.ITIMER_REAL)[0]


# ── 1. behaviour ──────────────────────────────────────────────────────────────

@posix_only
def test_inner_block_does_not_cancel_the_outer():
    with check_deadline(5.0):
        assert _armed() > 4.0
        with check_deadline(2.0):
            assert 0.0 < _armed() <= 2.0          # inner is the earlier deadline
        # THE regression: the old code disarmed here and the outer cap vanished.
        assert _armed() > 4.0


@posix_only
def test_inner_is_clamped_to_the_outer_remaining():
    with check_deadline(0.5):
        with check_deadline(60.0):                # asks for far more than the outer has
            assert 0.0 < _armed() <= 0.5


@posix_only
def test_outer_is_charged_for_the_wall_time_spent_inside_the_inner():
    with check_deadline(5.0):
        before = _armed()
        with check_deadline(1.0):
            time.sleep(0.12)
        after = _armed()
    # Deadlines are absolute, so the time spent inside is simply gone from the outer —
    # there is no restore arithmetic that could hand it back.
    assert before - after >= 0.10


@posix_only
def test_handler_is_captured_once_at_outermost_entry_and_restored_once_at_exit():
    original = signal.getsignal(signal.SIGALRM)
    with check_deadline(5.0):
        assert signal.getsignal(signal.SIGALRM) is sb._fire
        assert sb._PREV_HANDLER is original
        with check_deadline(5.0):
            # a nested entry must NOT re-capture: it would save _fire as "the previous
            # handler" and hand _fire back to the caller at the outermost exit.
            assert sb._PREV_HANDLER is original
        # ...and a nested exit must not restore, or the outer body runs unprotected.
        assert signal.getsignal(signal.SIGALRM) is sb._fire
    assert signal.getsignal(signal.SIGALRM) is original
    assert sb._PREV_HANDLER is sb._UNSET


@posix_only
def test_stack_unwinds_when_the_body_raises_an_unrelated_exception():
    with pytest.raises(ValueError):
        with check_deadline(5.0):
            with check_deadline(2.0):
                raise ValueError("not a budget problem")
    assert sb._STACK == []
    assert _armed() == 0.0


@posix_only
def test_zero_and_negative_are_a_transparent_noop():
    for seconds in (0, -1.0):
        with check_deadline(seconds) as frame:
            assert frame.armed is False
            assert _armed() == 0.0
            assert sb._STACK == []
        assert owned_by(ScanBudgetExceeded(), frame) is False


@posix_only
def test_entering_the_same_block_object_twice_is_refused_not_leaked():
    """Nesting goes through separate check_deadline() calls. Re-entering ONE object
    would overwrite the frame it has to pop by name, so it is rejected outright."""
    block = check_deadline(5.0)
    with block:
        with pytest.raises(RuntimeError):
            with block:
                pass
    assert sb._STACK == []


@posix_only
def test_a_block_object_can_be_used_again_after_it_has_exited():
    block = check_deadline(5.0)
    with block as first:
        pass
    with block as second:
        assert second is not first
    assert sb._STACK == []


def test_noop_path_off_the_main_thread():
    """A non-main thread cannot install a handler, so the block stays transparent."""
    seen = []

    def body():
        with check_deadline(5.0) as frame:
            seen.append(frame.armed)

    t = threading.Thread(target=body)
    t.start()
    t.join()
    assert seen == [False]


# ── 2. owner attribution ──────────────────────────────────────────────────────

@posix_only
def test_an_outer_expiry_inside_an_inner_block_is_attributed_to_the_outer():
    inner_frames: list[DeadlineFrame] = []
    with pytest.raises(ScanBudgetExceeded) as excinfo:
        with check_deadline(0.08) as outer:
            with check_deadline(5.0) as inner:     # clamped to the outer's remaining
                inner_frames.append(inner)
                _busy(3.0)                         # self-limits; the timer cuts it first
    exc = excinfo.value
    assert owned_by(exc, outer) is True
    assert owned_by(exc, inner_frames[0]) is False
    assert outer.expired is True
    assert inner_frames[0].expired is False


@posix_only
def test_an_inner_expiry_is_attributed_to_the_inner_and_the_outer_survives():
    with check_deadline(5.0) as outer:
        with pytest.raises(ScanBudgetExceeded) as excinfo:
            with check_deadline(0.08) as inner:
                _busy(3.0)
        assert owned_by(excinfo.value, inner) is True
        assert owned_by(excinfo.value, outer) is False
        assert _armed() > 0.0                      # the outer cap is still standing
    assert outer.expired is False


@posix_only
def test_a_delivered_frame_is_never_blamed_a_second_time():
    """Defect D: a stale expired frame is permanently the earliest deadline on the
    stack, so without this it is blamed for every later, unrelated expiry."""
    stale = DeadlineFrame(time.monotonic() - 1.0, armed=True)
    sb._STACK.append(stale)
    try:
        assert sb._blame() is stale                # first expiry: it is genuinely due
        stale.delivered = True
        assert sb._blame() is None                 # it has had its say
    finally:
        del sb._STACK[:]


@posix_only
def test_a_future_deadline_is_never_blamed_for_a_stray_delivery():
    live = DeadlineFrame(time.monotonic() + 30.0, armed=True)
    sb._STACK.append(live)
    try:
        assert sb._blame() is None
    finally:
        del sb._STACK[:]


def test_a_cooperative_non_timer_raise_stays_unattributed():
    """skillast.py's reached-sinks cap (B-192) raises ScanBudgetExceeded with no owner.

    It must travel out of any enclosing deadline block untouched, all the way to
    run_all's bare handler — the contract tests/test_c159_scan_budget.py already pins.
    """
    with pytest.raises(ScanBudgetExceeded) as excinfo:
        with check_deadline(5.0) as frame:
            raise ScanBudgetExceeded             # exactly skillast.py's raise shape
    assert excinfo.value.owner is None
    assert owned_by(excinfo.value, frame) is False
    # and the positional-message shape stays constructible
    assert ScanBudgetExceeded("timed out").owner is None
    assert str(ScanBudgetExceeded("timed out")) == "timed out"


# ── 3. suppress_own ───────────────────────────────────────────────────────────

@posix_only
def test_suppress_own_swallows_its_own_expiry_and_reports_the_truncation():
    with check_deadline(5.0) as outer:
        with check_deadline(0.08, suppress_own=True) as inner:
            _busy(3.0)
        assert inner.expired is True             # the block was cut short, and says so
        assert _armed() > 0.0                    # the outer is back and still armed
    assert outer.expired is False


@posix_only
def test_suppress_own_never_eats_an_outer_owners_expiry():
    with pytest.raises(ScanBudgetExceeded) as excinfo:
        with check_deadline(0.08) as outer:
            with check_deadline(5.0, suppress_own=True) as inner:
                _busy(3.0)
    assert owned_by(excinfo.value, outer) is True
    assert inner.expired is False


@posix_only
def test_suppress_own_never_eats_an_unattributed_cooperative_raise():
    with pytest.raises(ScanBudgetExceeded) as excinfo:
        with check_deadline(5.0, suppress_own=True):
            raise ScanBudgetExceeded
    assert excinfo.value.owner is None


# ── 4. the expired-deadline re-arm (Defect C: BOTH nested and single-frame) ───

def _guard_a_direct_rearm():
    """Install a no-op SIGALRM handler so a direct, unprotected ``_rearm()``/``_fire()``
    call below can arm a REAL itimer without risking a process kill.

    Every real call path only ever reaches ``_rearm()`` from inside ``_push()``'s
    installed-``_fire`` handler. A test that pokes ``_rearm()``/``_fire()`` directly
    skips that install, so a genuinely armed ``_MIN_ARM_S`` (100us) itimer sits with
    whatever the ambient default is — normally ``SIG_DFL``, whose action is to
    terminate the process. That is not theoretical: three tests in this file did
    exactly this and were confirmed, by local reproduction with injected scheduler
    jitter, to crash the interpreter with the identical signature CI hit on
    macOS (`Alarm clock`, exit 142) — reproducible on ANY platform whenever OS signal
    delivery is slower than the disarm that follows, which is a coin flip, not a bug
    isolated to the direct-manipulation test itself. Returns the previous handler;
    callers must disarm the real timer and then hand ``previous`` back through
    :func:`_release_a_direct_rearm`, not a bare ``signal.signal(SIGALRM, previous)`` —
    see Defect E below for why a naive restore reopens the same class of race this
    closes, just moved to the very end of the ``finally`` block instead of the middle.
    """
    return signal.signal(signal.SIGALRM, lambda *_: None)


def _release_a_direct_rearm(previous) -> None:
    """Hand SIGALRM back to ``previous`` without leaking a kernel-owed alarm onto it.

    Mirrors ``scanbudget._release()``'s Defect E fix: disarming a real itimer stops
    FUTURE firings only, so if this test's own real arm already fired and the kernel
    is holding an owed SIGALRM, a bare ``signal.signal(SIGALRM, previous)`` can hand
    that debt straight to ``previous`` — usually ``SIG_DFL``, i.e. a process kill, at
    the very moment this "cleanup" code runs. See the module docstring's Defect E note
    and ``scanbudget.py``'s ``_release()`` for the full mechanism and the platform
    difference (Linux flushes it inside the disarm syscall; macOS does not) that made
    this reproduce in CI but never locally.
    """
    prev_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
    try:
        for _ in range(3):
            signal.signal(signal.SIGALRM, signal.SIG_IGN)
            signal.signal(signal.SIGALRM, previous)
            if signal.SIGALRM not in signal.sigpending():
                return
        signal.signal(signal.SIGALRM, signal.SIG_IGN)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, prev_mask)


@posix_only
def test_rearm_of_an_expired_deadline_arms_a_minimum_slice_single_frame(monkeypatch):
    """The outermost/non-nested case — where the predecessor's version of this
    guarantee was simply false, because that path disarmed instead of arming.

    Calls ``_rearm()`` directly, bypassing ``_push()`` — see ``_guard_a_direct_rearm``
    for why that needs a no-op handler. Asserts on what ``_rearm()`` REQUESTED (via a
    pass-through probe) rather than only on the OS readback, because the readback
    alone is jitter-sensitive (a correctly-armed sub-millisecond alarm can already
    read back as fired-and-cleared on a loaded runner) — see
    ``test_min_arm_s_reads_back_as_a_pending_alarm_not_disarmed`` for the readback
    property itself, pinned separately with retries so it isn't coupled to this
    test's crash-safety.
    """
    expired = DeadlineFrame(time.monotonic() - 5.0, armed=True)
    sb._STACK.append(expired)
    calls: list[tuple] = []
    real_setitimer = signal.setitimer

    def probe(which, seconds, *rest):
        calls.append((which, seconds))
        return real_setitimer(which, seconds, *rest)

    previous = _guard_a_direct_rearm()
    monkeypatch.setattr(signal, "setitimer", probe)
    try:
        sb._rearm()
    finally:
        real_setitimer(signal.ITIMER_REAL, 0)   # disarm BEFORE restoring the handler
        _release_a_direct_rearm(previous)
        del sb._STACK[:]
    assert calls, "the probe never ran — this test proves nothing"
    which, seconds = calls[-1]
    assert which == signal.ITIMER_REAL
    assert seconds > 0.0, "an expired deadline was DISARMED — that is the fail-open"
    assert seconds <= sb._MIN_ARM_S


@posix_only
def test_rearm_of_an_expired_outer_arms_a_minimum_slice_nested(monkeypatch):
    """See the single-frame test above for the no-op-handler + request-probe rationale:
    this also calls ``_rearm()`` directly, unprotected by ``_push``.
    """
    expired_outer = DeadlineFrame(time.monotonic() - 5.0, armed=True)
    live_inner = DeadlineFrame(time.monotonic() + 30.0, armed=True)
    sb._STACK.extend([expired_outer, live_inner])
    calls: list[tuple] = []
    real_setitimer = signal.setitimer

    def probe(which, seconds, *rest):
        calls.append((which, seconds))
        return real_setitimer(which, seconds, *rest)

    previous = _guard_a_direct_rearm()
    monkeypatch.setattr(signal, "setitimer", probe)
    try:
        sb._rearm()
    finally:
        real_setitimer(signal.ITIMER_REAL, 0)
        _release_a_direct_rearm(previous)
        del sb._STACK[:]
    assert calls, "the probe never ran — this test proves nothing"
    which, seconds = calls[-1]
    assert which == signal.ITIMER_REAL
    assert 0.0 < seconds <= sb._MIN_ARM_S


@posix_only
def test_min_arm_s_reads_back_as_a_pending_alarm_not_disarmed():
    """The floor ``_rearm()`` relies on to avoid the fail-open (``scanbudget.py:164-169``):
    an arm of exactly ``_MIN_ARM_S`` must read back as pending, not ``(0.0, 0.0)`` — the
    same shape ``setitimer(..., 0)`` (disarm) and "already fired" both report.

    Real OS jitter can occasionally let even a correctly-armed sub-millisecond alarm
    read back as already-gone, which is exactly why the two tests above assert on the
    REQUEST rather than the readback. This test carries the readback property instead,
    with a no-op handler (a real alarm here must never be allowed to reach the process
    default action) and a best-of-N retry so a single unlucky sample can't redden it —
    it only fails if the floor reads back as disarmed on every attempt.
    """
    previous = _guard_a_direct_rearm()
    try:
        for _ in range(20):
            signal.setitimer(signal.ITIMER_REAL, sb._MIN_ARM_S)
            remaining = signal.getitimer(signal.ITIMER_REAL)[0]
            signal.setitimer(signal.ITIMER_REAL, 0)
            if remaining > 0.0:
                return
        pytest.fail(
            f"_MIN_ARM_S ({sb._MIN_ARM_S}) read back as disarmed on every one of 20 "
            "attempts — it is no longer large enough to avoid the fail-open"
        )
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        _release_a_direct_rearm(previous)


@posix_only
def test_popping_an_inner_rearms_an_already_expired_outer_rather_than_disarming():
    """The same property through the real code path, not a hand-built stack."""
    with check_deadline(0.05) as outer:
        _busy(0.0)                                # (no work — we move the clock by hand)
        outer.deadline = time.monotonic() - 1.0   # pretend the outer's time ran out
        with check_deadline(30.0):
            pass
        armed = _armed()
        assert 0.0 < armed <= sb._MIN_ARM_S, "the outer cap was cancelled, not restored"
        outer.delivered = True                    # stop it firing during teardown
        signal.setitimer(signal.ITIMER_REAL, 0)


@posix_only
def test_an_expired_leaked_frame_does_not_clobber_a_later_budget():
    """Defect B: a stale frame stays the earliest deadline forever, so every later
    re-arm gets _MIN_ARM_S instead of the caller's real budget."""
    with check_deadline(30.0):
        leaked = DeadlineFrame(time.monotonic() - 60.0, armed=True)
        leaked.expired = leaked.delivered = True
        sb._STACK.append(leaked)                  # simulate a leaked inner frame
        with check_deadline(10.0):
            assert _armed() > 1.0, "a stale frame clobbered a fresh budget"
        # ...and the enclosing block reaps it on the way out (truncating pop)
    assert sb._STACK == []


# ── 4b. Defect E: _release() must discard what the kernel still owes ──────────
#
# setitimer(ITIMER_REAL, 0) stops FUTURE firings; it does not retract a SIGALRM the
# kernel has already generated. The predecessor of _release() restored the caller's
# handler straight after disarming and relied on CPython's signal.signal() clearing its
# own "tripped" flag — which only covers an expiry CPython's C trampoline already
# received, not one the KERNEL still owes. That owed expiry lands afterwards, on
# whatever disposition _release() just restored — SIG_DFL (terminate) in every real
# clawseccheck run, since nothing else in this stdlib-only CLI ever touches SIGALRM.
# Linux happens to flush the debt inside the disarm syscall itself (an implementation
# property of do_setitimer, not a POSIX guarantee); macOS does not, and CI reproducibly
# died with an uncaught "Alarm clock" (exit 142) in exactly this window, inside
# ``test_nested_cycles_under_adversarial_signal_timing_never_leak_a_frame`` below.

@posix_only
def test_release_discards_an_alarm_the_kernel_already_owes():
    """setitimer(0) does not retract an expiry the kernel has already generated. If
    _release() hands the caller's handler back without discarding it, the next delivery
    lands on that handler — for the SIG_DFL every real run has, killing the process.
    Delivery is frozen with a mask so the race is observed, not gambled on."""
    hits: list[int] = []

    def mine(*_args):
        hits.append(1)

    original = signal.getsignal(signal.SIGALRM)
    prev_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
    signal.signal(signal.SIGALRM, mine)
    try:
        block = check_deadline(5.0)
        block.__enter__()
        signal.setitimer(signal.ITIMER_REAL, 0.001)
        _busy(0.03)                                       # the expiry is now OWED
        assert signal.SIGALRM in signal.sigpending(), "setup failed: nothing is owed"
        block.__exit__(None, None, None)                  # -> _release()
        assert signal.SIGALRM not in signal.sigpending(), (
            "_release() handed the handler back with an alarm still owed by the kernel"
        )
        assert signal.getsignal(signal.SIGALRM) is mine, "the restore contract still holds"
        assert hits == [], "the owed alarm reached the caller's handler after all"
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, signal.SIG_IGN)
        signal.pthread_sigmask(signal.SIG_SETMASK, prev_mask)
        signal.signal(signal.SIGALRM, original)
        del sb._STACK[:]
        sb._PREV_HANDLER = sb._UNSET


@posix_only
def test_release_hands_the_handler_back_through_a_sig_ign_discard(monkeypatch):
    """Mechanism-level: pins the actual sequence, so removing the SIG_IGN discard pass
    reddens a deterministic test rather than only shifting the odds on the probabilistic
    one above."""
    seen: list[object] = []
    real_signal = signal.signal
    original = signal.getsignal(signal.SIGALRM)

    def probe(sig, handler):
        seen.append(handler)
        return real_signal(sig, handler)

    with check_deadline(5.0):
        monkeypatch.setattr(signal, "signal", probe)   # patched INSIDE: _push's install
    monkeypatch.undo()                                  # isn't recorded, only _release's
    assert seen == [signal.SIG_IGN, original]
    assert signal.getsignal(signal.SIGALRM) is original


# ── 5. mechanism: the async-signal guard itself ──────────────────────────────
#
# Defect A in the rejected predecessor was that `signal.pthread_sigmask` does not make a
# Python-level critical section uninterruptible, so a frame could be pushed and never
# popped. Its own suite did not notice: a mutation that removed ALL masking still passed.
# These tests fail *deterministically* if the guard is weakened.

@posix_only
def test_in_bookkeeping_is_false_for_ordinary_caller_code():
    assert sb._in_bookkeeping(sys._getframe()) is False
    assert sb._in_bookkeeping(None) is False


@posix_only
def test_in_bookkeeping_sees_a_protected_caller_through_an_unprotected_frame(monkeypatch):
    """The guard walks the whole caller chain, not just the interrupted frame.

    That is the difference between correct and correct-on-one-Python-version: a lambda
    passed to ``min()``, or (before PEP 709 inlined them in 3.12) a comprehension, each
    get their own code object that an innermost-frame-only test would not recognise as
    ours. Here the probe's own frame stands in for such a helper: its code object belongs
    to this test, and only its CALLER is one of the module's.
    """
    seen: list[bool] = []
    real_setitimer = signal.setitimer

    def probe(which, seconds, *rest):
        seen.append(sb._in_bookkeeping(sys._getframe()))
        return real_setitimer(which, seconds, *rest)

    monkeypatch.setattr(signal, "setitimer", probe)
    with check_deadline(5.0):
        pass
    monkeypatch.undo()
    assert seen, "the probe never ran — the test proves nothing"
    assert all(seen), "an expiry raised here would abandon the push/pop bookkeeping"


@posix_only
def test_fire_defers_instead_of_raising_into_the_modules_own_bookkeeping(monkeypatch):
    """Directly: hand ``_fire`` a frame belonging to the bookkeeping and a genuinely
    due deadline. It must record nothing and raise nothing.

    The ``with check_deadline(5.0):`` block below has already exited by the time
    ``sb._fire(...)`` is called, so ``_release()`` has restored SIGALRM to whatever
    the ambient default is — this call arms a REAL ``_MIN_ARM_S`` itimer (the
    deferral branch at ``scanbudget.py:315``, since ``_STACK`` is non-empty) with no
    handler protecting it unless one is installed first. See
    ``_guard_a_direct_rearm``: confirmed by local reproduction to crash the
    interpreter with CI's exact `Alarm clock` signature otherwise.
    """
    captured: list[object] = []
    real_setitimer = signal.setitimer

    def probe(which, seconds, *rest):
        captured.append(sys._getframe(1))        # the module's own live frame
        return real_setitimer(which, seconds, *rest)

    monkeypatch.setattr(signal, "setitimer", probe)
    with check_deadline(5.0):
        pass
    monkeypatch.undo()
    assert captured

    due = DeadlineFrame(time.monotonic() - 1.0, armed=True)
    sb._STACK.append(due)
    previous = _guard_a_direct_rearm()
    try:
        sb._fire(signal.SIGALRM, captured[0])    # must NOT raise
        assert due.delivered is False, "the expiry was consumed inside the bookkeeping"
        assert _armed() > 0.0, "the deferred expiry was dropped instead of re-armed"
    finally:
        real_setitimer(signal.ITIMER_REAL, 0)    # disarm BEFORE restoring the handler
        _release_a_direct_rearm(previous)
        del sb._STACK[:]


@posix_only
def test_fire_deferred_with_an_empty_stack_disarms_rather_than_re_arming(monkeypatch):
    """The asymmetry that keeps ``_release`` safe: with no frames left there is nothing
    to protect, and a lingering 100us arm would be delivered to the CALLER's handler —
    for the default SIGALRM action, killing the process."""
    captured: list[object] = []
    real_setitimer = signal.setitimer

    def probe(which, seconds, *rest):
        captured.append(sys._getframe(1))
        return real_setitimer(which, seconds, *rest)

    monkeypatch.setattr(signal, "setitimer", probe)
    with check_deadline(5.0):
        pass
    monkeypatch.undo()

    assert sb._STACK == []
    sb._fire(signal.SIGALRM, captured[0])
    assert _armed() == 0.0


@posix_only
def test_an_abandoned_block_is_reaped_by_its_finalizer():
    """The last line of defence for the one window ``_in_bookkeeping`` cannot cover:
    the handful of interpreter bytecodes on either side of ``__enter__``/``__exit__``
    that belong to the CALLER's frame. A block abandoned there is unreferenced, and
    CPython's refcounting finalizes it — which reaps the frame."""
    original = signal.getsignal(signal.SIGALRM)
    block = check_deadline(5.0)
    frame = block.__enter__()                    # deliberately never __exit__()ed
    assert sb._STACK == [frame]
    del block
    gc.collect()
    assert sb._STACK == []
    assert _armed() == 0.0
    assert signal.getsignal(signal.SIGALRM) is original


@posix_only
def test_pop_truncates_a_leaked_inner_frame():
    """``with`` blocks nest lexically, so anything above a frame when that frame exits
    has already ended — reaping it bounds a leak to its enclosing block."""
    with check_deadline(5.0):
        sb._STACK.append(DeadlineFrame(time.monotonic() + 1.0, armed=True))
        assert len(sb._STACK) == 2
    assert sb._STACK == []


# ── 6. adversarial signal timing ─────────────────────────────────────────────

@posix_only
def test_nested_cycles_under_adversarial_signal_timing_never_leak_a_frame():
    """Many rapid nested enter/exit cycles at sub-millisecond budgets — the regime in
    which the rejected predecessor leaked ~0.1% of its frames.

    Budgets are drawn so that the great majority of rounds DO fire, and fire near the
    enter/exit boundary rather than in the middle of the body, which is exactly where a
    signal-timing race would show. Verified to be sensitive rather than vacuous: with
    ``_PROTECTED_CODE`` emptied (the mutation the predecessor's suite survived), this
    same loop leaks frames; unmutated it reports zero.

    Deadlines are drawn as a FRACTION of this host's own measured cost for the busy
    loop below, not a fixed microsecond constant. A fixed 30-400us range (this test's
    original shape) assumes a roughly constant per-iteration Python cost and itimer
    resolution across machines, which macOS CI disproved: the identical constants that
    reliably fired on Linux only fired ~9% of the time there, starving the very signal
    path this test exists to stress (a portability gap in the test's timing, not a
    correctness bug — production's _release()/_push() were independently confirmed
    fixed by the same CI run turning a process kill into this ordinary assertion).
    Scaling to a per-host measurement keeps the same RATIO of "deadline vs. likely
    work time" everywhere, regardless of CPU speed or itimer coarsening.
    """
    import random

    rng = random.Random(4321)
    original = signal.getsignal(signal.SIGALRM)
    rounds = 12000
    fires = 0
    leaks: list[int] = []

    def spin(n: int) -> None:
        x = 0
        for _ in range(n):
            x += 1

    spin_hi = 6000
    started = time.monotonic()
    spin(spin_hi)
    spin_cost_s = max(time.monotonic() - started, 1e-6)

    for i in range(rounds):
        inner_frame: DeadlineFrame | None = None
        try:
            with check_deadline(rng.uniform(0.15, 0.6) * spin_cost_s):
                try:
                    with check_deadline(rng.uniform(0.15, 0.6) * spin_cost_s) as inner_frame:
                        spin(rng.randrange(0, spin_hi))
                except ScanBudgetExceeded as exc:
                    fires += 1
                    if not owned_by(exc, inner_frame):
                        raise
                spin(rng.randrange(0, spin_hi))
        except ScanBudgetExceeded:
            fires += 1
        if sb._STACK:
            leaks.append(i)
            del sb._STACK[:]
            signal.setitimer(signal.ITIMER_REAL, 0)
            _release_a_direct_rearm(original)
            sb._PREV_HANDLER = sb._UNSET

    assert fires > rounds // 4, (
        f"only {fires} of {rounds} rounds actually hit their deadline — the loop is not "
        "exercising the signal path and proves nothing"
    )
    assert leaks == [], f"{len(leaks)} leaked deadline frame(s) at rounds {leaks[:10]}"


# ── 7. integration: the audit's own bound survives a nesting check ────────────

def _nesting_slow_check(ctx):
    """A check that arms its OWN, much larger deadline and then hangs.

    Under the predecessor this overwrote run_all's per-check itimer with 30s, so the
    audit's hard cap was simply gone.
    """
    from clawseccheck.catalog import LOW, PASS

    import clawseccheck.checks as checks_mod

    with check_deadline(30.0):
        _busy(5.0)
    return checks_mod.Finding("NEST", "nest", LOW, PASS, "", "", "test")


def _disarm_then_hang_check(ctx):
    """A check that opens and CLOSES a nested deadline, then hangs.

    Under the predecessor the nested block's ``finally`` disarmed run_all's timer, so
    everything after it ran with no hard cap at all — the fail-open in its purest form.
    """
    from clawseccheck.catalog import LOW, PASS

    import clawseccheck.checks as checks_mod

    with check_deadline(1.0):
        pass
    _busy(5.0)
    return checks_mod.Finding("DISARM", "disarm", LOW, PASS, "", "", "test")


@posix_only
@pytest.mark.parametrize("bad_check", [_nesting_slow_check, _disarm_then_hang_check])
def test_run_all_still_bounds_a_check_that_nests_a_deadline(monkeypatch, bad_check):
    import pathlib

    import clawseccheck.checks as checks_mod
    from clawseccheck.catalog import UNKNOWN
    from clawseccheck.collector import Context

    ctx = Context(home=pathlib.Path("/nonexistent"))
    ctx.config = {}
    monkeypatch.setattr(checks_mod, "CHECKS", [bad_check])

    started = time.perf_counter()
    findings = checks_mod.run_all(ctx, check_budget_s=0.3)
    elapsed = time.perf_counter() - started

    assert elapsed < 3.0, "run_all's hard cap was cancelled by the nested block"
    budget = [f for f in findings if f.id.startswith("ERR:")]
    assert len(budget) == 1
    assert budget[0].status == UNKNOWN and budget[0].scored is False
