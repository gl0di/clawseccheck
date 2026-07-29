"""B-352: a check cannot swallow its own hard deadline into a lying PASS.

``scanbudget._fire`` raises :class:`ScanBudgetExceeded` at an arbitrary bytecode
boundary inside whatever the check is doing. Deep in a real call graph that is very
often inside some *unrelated* inner ``try`` — an archive read, a parse, a subprocess
guard — whose ``except Exception`` then discards the deadline and lets the check
return an ordinary verdict computed from a scan that was cut short. Measured before
the fix: a check ran 3.31s against a 0.3s budget and was reported PASS.

The fix is structural rather than site-by-site: ``ScanBudgetExceeded`` derives from
``BaseException``, so an ``except Exception`` clause literally cannot name-match it,
the same way ``KeyboardInterrupt`` is unswallowable. There are ~48 broad handlers in
this package and no hand-maintained list of them could stay correct as it grows.

These tests pin BOTH halves: the base-class decision itself (so nobody "simplifies" it
back to ``Exception``), and the end-to-end behaviour that decision buys.
"""
from __future__ import annotations

import time

import pytest

import clawseccheck.checks as checks
from clawseccheck.catalog import LOW, PASS, UNKNOWN, Finding
from clawseccheck.collector import Context
from clawseccheck.scanbudget import (
    ScanBudgetExceeded,
    _can_hard_timeout,
    check_deadline,
)

POSIX = _can_hard_timeout()
posix_only = pytest.mark.skipif(not POSIX, reason="hard timeout needs POSIX + main thread")


def _ctx() -> Context:
    from pathlib import Path
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    return c


# ── the structural property, pinned ───────────────────────────────────────────

def test_scan_budget_exceeded_is_outside_the_exception_hierarchy():
    """The base class IS the fix — pin it so a later 'cleanup' cannot quietly undo it.

    If this ever fails because someone made it an ``Exception`` again, every
    ``except Exception`` in the package silently becomes a deadline-swallower and the
    lying-PASS class of bug is reopened wholesale.
    """
    assert issubclass(ScanBudgetExceeded, BaseException)
    assert not issubclass(ScanBudgetExceeded, Exception), (
        "ScanBudgetExceeded must NOT derive from Exception (B-352): an inner "
        "`except Exception` anywhere in a check's call graph would swallow the hard "
        "deadline and let a truncated scan report a normal verdict."
    )


def test_scan_budget_exceeded_still_derives_from_baseexception_at_the_instance_level():
    exc = ScanBudgetExceeded(owner=None)
    assert isinstance(exc, BaseException)
    assert not isinstance(exc, Exception)
    assert exc.owner is None            # the C-175 ownership attribute survives the rebase


# ── a bare `except Exception` cannot catch it — proven, not asserted ──────────

def test_bare_except_exception_cannot_catch_a_scan_budget_expiry():
    """The exact buggy shape, minimal: a guard that means to catch parse errors.

    This is the shape that exists ~48 times across the package. It must let the
    deadline through untouched — including the ``owner`` attribution, since a nested
    owner further out has to be able to tell whose deadline it was.
    """
    sentinel = object()

    def guarded():
        try:
            raise ScanBudgetExceeded(owner=sentinel)
        except Exception:  # noqa: BLE001 — deliberately the buggy shape B-352 defends against
            return "swallowed"
        return "no raise"

    with pytest.raises(ScanBudgetExceeded) as ei:
        guarded()
    assert ei.value.owner is sentinel


def test_a_bare_except_exception_still_catches_ordinary_errors():
    """Guard against over-correcting: only the deadline escapes, nothing else changed.

    A check that crashes on a bug must still be caught by its own inner guard (and,
    one level up, by run_all's ``except Exception``) — otherwise this fix would have
    traded a lying PASS for an aborted audit.
    """
    def guarded():
        try:
            raise ValueError("an ordinary bug")
        except Exception:  # noqa: BLE001 — the ordinary, still-correct use of a guard
            return "swallowed"

    assert guarded() == "swallowed"


def test_finally_still_runs_when_a_deadline_unwinds_through_a_guard():
    """A BaseException still triggers ``finally``, so cleanup on the way out is intact.

    Worth pinning explicitly: several swallow sites (collector's archive handling) do
    real cleanup in ``finally`` blocks, and this fix would be unsafe if skipping the
    ``except`` also skipped those.
    """
    ran: list[str] = []

    def guarded():
        try:
            try:
                raise ScanBudgetExceeded()
            except Exception:  # noqa: BLE001 — the buggy shape again
                ran.append("except")
            finally:
                ran.append("finally")
        finally:
            ran.append("outer-finally")

    with pytest.raises(ScanBudgetExceeded):
        guarded()
    assert ran == ["finally", "outer-finally"], "the except must not run; both finallys must"


# ── end to end: the real timer, through a real inner guard ───────────────────

def _busy_behind_a_guard(seconds: float) -> None:
    """Burn wall-clock inside an inner ``except Exception``, the way real code does.

    The guard is INSIDE the loop on purpose. A frame's deadline fires exactly once
    (see ``check_deadline``), so if the first expiry is swallowed nothing ever
    re-interrupts and the loop runs to its own self-limit — which is precisely how a
    0.3s budget produced a 3.31s scan reported as PASS.
    """
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            for _ in range(20000):
                pass
        except Exception:  # noqa: BLE001 — deliberately the buggy shape B-352 defends against
            pass


@posix_only
def test_real_deadline_escapes_an_inner_guard_and_reaches_the_owner():
    t = time.perf_counter()
    with pytest.raises(ScanBudgetExceeded):
        with check_deadline(0.3):
            _busy_behind_a_guard(5.0)
    elapsed = time.perf_counter() - t
    assert elapsed < 2.0, (
        f"the deadline was swallowed by the inner guard: the block ran {elapsed:.2f}s "
        "against a 0.3s budget"
    )


def _swallowing_check(ctx) -> Finding:
    """A check with an ordinary-looking inner guard, which overruns its budget.

    Returns a confident PASS unconditionally — that is the whole point: if the
    deadline is swallowed, run_all has no way to know the scan was truncated and this
    fabricated PASS is what the user is shown.
    """
    _busy_behind_a_guard(5.0)
    return Finding("B352T", "b352 probe", LOW, PASS, "", "", "test")


@posix_only
def test_run_all_reports_unknown_not_a_fabricated_pass_when_a_check_swallows(monkeypatch):
    """The lying-PASS bug itself, end to end through the real engine.

    Before the fix this asserted-away: the check's inner ``except Exception`` ate the
    SIGALRM-raised deadline, run_all's dedicated ``except ScanBudgetExceeded`` never
    fired, and the fabricated ``B352T`` PASS landed in the findings list.
    """
    monkeypatch.setattr(checks, "CHECKS", [_swallowing_check])
    t = time.perf_counter()
    findings = checks.run_all(_ctx(), check_budget_s=0.3)
    elapsed = time.perf_counter() - t

    assert not [f for f in findings if f.id == "B352T"], (
        "a check that swallowed its own deadline was allowed to report a normal "
        "verdict — this is the B-352 lying PASS"
    )
    budget = [f for f in findings if f.id == "ERR:_swallowing_check"]
    assert len(budget) == 1, f"expected one budget finding, got {[f.id for f in findings]}"
    assert budget[0].status == UNKNOWN
    assert budget[0].scored is False
    assert elapsed < 3.0, f"the check overran its 0.3s budget by far too much ({elapsed:.2f}s)"


# ── the top-level boundary still refuses to show a raw traceback ─────────────

def test_cli_main_degrades_an_escaped_deadline_instead_of_tracebacking(monkeypatch, capsys):
    """B-101's no-raw-traceback contract must survive the move to BaseException.

    An escape this far means every designated handler failed to claim its own
    deadline, which should not happen by design — but the user still gets one clean
    line and a NON-ZERO exit, never a traceback and never a zero (clean) exit.
    """
    from clawseccheck import cli

    def _boom(argv=None):
        raise ScanBudgetExceeded()

    monkeypatch.setattr(cli, "_main", _boom)
    rc = cli.main([])
    assert rc == 1
    err = capsys.readouterr().err
    assert "cut short" in err
    assert "Traceback" not in err


def test_cli_main_reraises_an_escaped_deadline_under_debug(monkeypatch):
    """--debug keeps its meaning: the operator asked for the traceback, so give it."""
    from clawseccheck import cli

    def _boom(argv=None):
        raise ScanBudgetExceeded()

    monkeypatch.setattr(cli, "_main", _boom)
    with pytest.raises(ScanBudgetExceeded):
        cli.main(["--debug"])
