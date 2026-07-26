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
    # repair first, assert second
    del sb._STACK[:]
    signal.setitimer(signal.ITIMER_REAL, 0)
    signal.signal(signal.SIGALRM, before)
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

@posix_only
def test_rearm_of_an_expired_deadline_arms_a_minimum_slice_single_frame():
    """The outermost/non-nested case — where the predecessor's version of this
    guarantee was simply false, because that path disarmed instead of arming."""
    expired = DeadlineFrame(time.monotonic() - 5.0, armed=True)
    sb._STACK.append(expired)
    try:
        sb._rearm()
        armed = _armed()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        del sb._STACK[:]
    assert armed > 0.0, "an expired deadline was DISARMED — that is the fail-open"
    assert armed <= sb._MIN_ARM_S


@posix_only
def test_rearm_of_an_expired_outer_arms_a_minimum_slice_nested():
    expired_outer = DeadlineFrame(time.monotonic() - 5.0, armed=True)
    live_inner = DeadlineFrame(time.monotonic() + 30.0, armed=True)
    sb._STACK.extend([expired_outer, live_inner])
    try:
        sb._rearm()
        armed = _armed()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        del sb._STACK[:]
    assert 0.0 < armed <= sb._MIN_ARM_S


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
    due deadline. It must record nothing and raise nothing."""
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
    try:
        sb._fire(signal.SIGALRM, captured[0])    # must NOT raise
        assert due.delivered is False, "the expiry was consumed inside the bookkeeping"
        assert _armed() > 0.0, "the deferred expiry was dropped instead of re-armed"
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
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
    same loop reports ~30 leaked frames per 30k rounds; unmutated it reports zero.
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

    for i in range(rounds):
        inner_frame: DeadlineFrame | None = None
        try:
            with check_deadline(rng.uniform(0.00003, 0.0004)):
                try:
                    with check_deadline(rng.uniform(0.00003, 0.0004)) as inner_frame:
                        spin(rng.randrange(0, 6000))
                except ScanBudgetExceeded as exc:
                    fires += 1
                    if not owned_by(exc, inner_frame):
                        raise
                spin(rng.randrange(0, 6000))
        except ScanBudgetExceeded:
            fires += 1
        if sb._STACK:
            leaks.append(i)
            del sb._STACK[:]
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, original)
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
