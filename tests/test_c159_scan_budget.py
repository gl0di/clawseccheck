"""C-159: the audit has a wall-clock budget so a pathological check can't hang it.

Platform-detected (see clawseccheck/scanbudget): a POSIX main thread gets a hard
per-check timeout that interrupts even a running check; every platform gets a
cooperative per-audit cap checked between checks. Tests are split accordingly.
"""
from __future__ import annotations

import signal
import time

import pytest

import clawseccheck.checks as checks
from clawseccheck.catalog import UNKNOWN
from clawseccheck.collector import Context
from clawseccheck.scanbudget import (
    ScanBudgetExceeded,
    _can_hard_timeout,
    audit_budget_exceeded,
    audit_deadline,
    check_deadline,
)

POSIX = _can_hard_timeout()
posix_only = pytest.mark.skipif(not POSIX, reason="hard timeout needs POSIX + main thread")


def _ctx() -> Context:
    c = Context(home=__import__("pathlib").Path("/nonexistent"))
    c.config = {}
    return c


# ── per-audit cooperative cap (all platforms) ─────────────────────────────────

def test_audit_deadline_helpers():
    assert audit_deadline(0) is None
    assert audit_budget_exceeded(None) is False
    assert audit_budget_exceeded(time.monotonic() - 1) is True   # already past
    assert audit_budget_exceeded(time.monotonic() + 100) is False


# ── hard per-check timeout (POSIX main thread) ────────────────────────────────

@posix_only
def test_check_deadline_interrupts_a_running_check():
    def busy():
        end = time.monotonic() + 5.0     # self-terminates so the test can never hang
        while time.monotonic() < end:
            pass

    t = time.perf_counter()
    with pytest.raises(ScanBudgetExceeded):
        with check_deadline(0.3):
            busy()
    assert time.perf_counter() - t < 2.0   # interrupted long before the 5s self-limit


@posix_only
def test_check_deadline_restores_handler_and_disarms():
    before = signal.getsignal(signal.SIGALRM)
    with check_deadline(0.5):
        pass
    assert signal.getsignal(signal.SIGALRM) is before
    # no alarm left pending
    assert signal.setitimer(signal.ITIMER_REAL, 0)[0] == 0.0


def test_check_deadline_zero_is_noop():
    with check_deadline(0):   # disabled -> transparent, no raise
        pass


# ── run_all integration ───────────────────────────────────────────────────────

def _slow_check(ctx):
    end = time.monotonic() + 5.0
    while time.monotonic() < end:
        pass
    from clawseccheck.catalog import LOW, PASS
    return checks.Finding("SLOW", "slow", LOW, PASS, "", "", "test")


@posix_only
def test_run_all_times_out_a_single_slow_check(monkeypatch):
    monkeypatch.setattr(checks, "CHECKS", list(checks.CHECKS) + [_slow_check])
    t = time.perf_counter()
    findings = checks.run_all(_ctx(), check_budget_s=0.3)
    elapsed = time.perf_counter() - t
    assert elapsed < 3.0                                   # not the 5s the check wanted
    budget = [f for f in findings if f.id.startswith("ERR:") and "_slow_check" in f.id]
    assert len(budget) == 1
    assert budget[0].status == UNKNOWN and budget[0].scored is False
    # every real check still ran
    assert len([f for f in findings if not f.id.startswith("ERR:")]) == len(checks.CHECKS) - 1


def test_run_all_normal_run_has_no_budget_findings():
    # a fast run under a generous budget must never synthesize a timeout finding
    findings = checks.run_all(_ctx())
    assert not [f for f in findings if f.id.startswith("ERR:")]


# ── C-175: ScanBudgetExceeded must propagate through simulate_effects, not be
# swallowed into a false PASS ──────────────────────────────────────────────

def test_simulate_effects_propagates_scan_budget_exceeded(monkeypatch):
    """skillast.simulate_effects() is documented 'never raises' for ordinary
    failures, but a ScanBudgetExceeded hit mid-simulation must be the one
    exception that escapes — swallowing it made a truncated, incomplete scan
    indistinguishable from 'found nothing'."""
    from clawseccheck import skillast

    class _Boom:
        def __init__(self, *a, **kw):
            pass

        def simulate(self):
            raise ScanBudgetExceeded

    monkeypatch.setattr(skillast, "EffectSimulator", _Boom)
    with pytest.raises(ScanBudgetExceeded):
        skillast.simulate_effects("x = 1\n", "f.py")


def test_simulate_effects_still_swallows_ordinary_exceptions(monkeypatch):
    """Regression guard: only ScanBudgetExceeded escapes — any other exception
    (e.g. a bug in the simulator itself) must still degrade to an empty list,
    per simulate_effects's 'never raises' contract for non-budget failures."""
    from clawseccheck import skillast

    class _Boom:
        def __init__(self, *a, **kw):
            pass

        def simulate(self):
            raise ValueError("simulator bug")

    monkeypatch.setattr(skillast, "EffectSimulator", _Boom)
    assert skillast.simulate_effects("x = 1\n", "f.py") == []


def test_check_installed_skills_degrades_to_unknown_not_false_pass_on_budget_hit(monkeypatch):
    """Integration: when the per-check deadline fires mid-simulate_effects for
    check_installed_skills (B13), run_all must convert it to the synthetic
    ERR:check_installed_skills UNKNOWN finding — not let the check fall
    through to a confident PASS with an incomplete scan."""
    import clawseccheck.checks._vet as vet_mod

    def _raise(*a, **kw):
        raise ScanBudgetExceeded

    monkeypatch.setattr(vet_mod, "_simulate_effects", _raise)
    ctx = _ctx()
    ctx.installed_skills = {"someskill": "notes"}
    ctx.installed_skill_py = {"someskill": [("run.py", "import os\nos.system('x')\n")]}

    findings = checks.run_all(ctx, check_budget_s=120.0)
    budget_hits = [f for f in findings if f.id == "ERR:check_installed_skills"]
    assert len(budget_hits) == 1, "expected check_installed_skills to hit the budget path"
    assert budget_hits[0].status == UNKNOWN
    # And critically: no B13 PASS/FAIL finding was fabricated from the truncated scan.
    assert not [f for f in findings if f.id == "B13"]
