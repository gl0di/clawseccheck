"""B-724 — closes the B-688 accepted residual in `_run_content_ring`.

B-688 (in-source comment, `checks/_vet.py`): a `ScanBudgetExceeded` attributed to the
ring's OWN deadline can land somewhere the inner `try` does not cover — the jump
instruction implementing a `continue` inside a `try` is, in CPython 3.11+'s zero-cost
exception model, covered by the ENCLOSING block's exception-table entry, not the inner
`try`'s. A signal landing there bypassed `owned_by(...)` and escaped the function
entirely instead of being absorbed into a disclosed VET-COVERAGE gap. Confirmed for
real on a full-suite run (2026-08-29), not just via synthetic injection.

The fix: a SECOND, identically `owned_by`-gated `except ScanBudgetExceeded` wrapping
the whole `for` loop (still inside the same `with check_deadline(...) as own_frame:`,
so an outer caller's own deadline is untouched). Its one real risk was knowing which
checks to report as `skipped` without double- or under-counting — this module tracks
`last_done_idx`, set as the LAST statement on every path through the loop body, so the
outer handler's slice (`SKILL_CONTENT_RING[last_done_idx + 1:]`) is correct by ordinary
source-level statement-execution order, not by reasoning about which bytecode offset a
signal happens to land on. That is what makes it correct on CPython 3.9's older
SETUP_FINALLY/POP_BLOCK exception model too, without a separate version-specific audit
(see the in-source comment for the full argument).

These tests reproduce the residual landing spot deterministically — a custom iterable
that raises `ScanBudgetExceeded` from the loop's own iterator-advance (`enumerate`'s
`__next__`), which sits outside the inner `try` exactly as the `continue` jump does —
rather than depending on real SIGALRM timing, matching this suite's own precedent
(`test_own_deadline_firing_during_loop_body_does_not_escape`,
`test_b394_scan_budget_escape.py`) for deterministic injection over timing-dependent
signal races.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import ast
import inspect

import pytest

from clawseccheck.catalog import FAIL, HIGH, PASS
from clawseccheck.checks import _custom
import clawseccheck.checks._vet as _vet_mod
from clawseccheck.collector import Context
from clawseccheck.scanbudget import ScanBudgetExceeded


def _skill_ctx(tmp_path) -> Context:
    ctx = Context(home=tmp_path)
    ctx.installed_skills = {"demo": "# Test skill\n\nDoes a thing.\n"}
    ctx.installed_skill_py = {"demo": []}
    ctx.installed_skill_shell = {"demo": []}
    ctx.installed_skill_js = {"demo": []}
    return ctx


class _CapturingBlock:
    """Wraps the real `_DeadlineBlock` so a test can read the `DeadlineFrame` the ring
    armed for itself, without depending on any internal name for it beyond what
    `check_deadline(...).__enter__()` already hands the ring."""

    def __init__(self, real_block, holder: dict):
        self._real = real_block
        self._holder = holder

    def __enter__(self):
        frame = self._real.__enter__()
        self._holder["frame"] = frame
        return frame

    def __exit__(self, *exc):
        return self._real.__exit__(*exc)


class _EscapesAfterOne(list):
    """A `SKILL_CONTENT_RING` stand-in whose SECOND `next()` call (i.e. the loop's own
    iterator-advance between the first and second checks — outside the inner `try`,
    exactly like the `continue` jump B-688 names) raises `ScanBudgetExceeded`. The
    owner is resolved lazily, at raise time, via `owner_fn()` — never eagerly at
    construction — so a test can arm `check_deadline`'s real frame (via a holder dict
    populated only once the ring actually starts) or supply a fixed sentinel owner
    without the two ever aliasing each other. The first item is yielded normally so a
    real check runs to completion first, exercising the accounting rather than the
    trivial zero-checks-done case.
    """

    def __init__(self, items, owner_fn):
        super().__init__(items)
        self._owner_fn = owner_fn

    def __iter__(self):
        n = 0
        for item in list.__iter__(self):
            n += 1
            if n > 1:
                raise ScanBudgetExceeded(owner=self._owner_fn())
            yield item


def _armed(monkeypatch):
    """Patch `check_deadline` so the test can read the frame the ring arms for
    itself, and return the holder dict it will be recorded into."""
    holder: dict = {}
    real_check_deadline = _vet_mod.check_deadline

    def _spy(seconds, **kw):
        return _CapturingBlock(real_check_deadline(seconds, **kw), holder)

    monkeypatch.setattr(_vet_mod, "check_deadline", _spy)
    return holder


def test_the_residual_landing_spot_is_absorbed_not_escaped(tmp_path, monkeypatch):
    """The core fix: a ScanBudgetExceeded owned by the ring's own frame, landing
    outside the inner try, must not escape `_run_content_ring` — it must come back as
    a normal return with a disclosed VET-COVERAGE gap, exactly like the inner
    handler's own case already does.
    """
    holder = _armed(monkeypatch)

    def _check1(ctx):
        return _custom("B13", HIGH, PASS, "check1 ran cleanly", "-")

    def _check2(ctx):
        raise AssertionError("check2 must never run: the escape lands before its turn")

    ring = _EscapesAfterOne([_check1, _check2], lambda: holder["frame"])
    monkeypatch.setattr(_vet_mod, "SKILL_CONTENT_RING", ring, raising=True)

    out = _vet_mod._run_content_ring(_skill_ctx(tmp_path))  # must return, not raise

    gaps = [f for f in out if f.id == "VET-COVERAGE"]
    assert len(gaps) == 1, f"expected exactly one coverage-gap finding, got: {out}"


def test_a_completed_check_is_not_double_counted_into_skipped(tmp_path, monkeypatch):
    """Accounting precision: the FAIL a completed check already produced must survive
    in the return value, AND that check's name must not also appear in the
    coverage-gap's `skipped` text — that would be the `[idx:]` double-count the task
    warns against, with a completed check reported as both a real finding and one
    that "did not run".
    """
    holder = _armed(monkeypatch)

    def _check1(ctx):
        return _custom("B13", HIGH, FAIL, "planted_exfil_signal_from_check1", "-")

    def _check2(ctx):
        raise AssertionError("check2 must never run: the escape lands before its turn")

    def _check3(ctx):
        raise AssertionError("check3 must never run: the escape lands before its turn")

    ring = _EscapesAfterOne([_check1, _check2, _check3], lambda: holder["frame"])
    monkeypatch.setattr(_vet_mod, "SKILL_CONTENT_RING", ring, raising=True)

    out = _vet_mod._run_content_ring(_skill_ctx(tmp_path))

    fails = [f for f in out if f.status == FAIL]
    assert len(fails) == 1 and "planted_exfil_signal_from_check1" in fails[0].detail, out

    gaps = [f for f in out if f.id == "VET-COVERAGE"]
    assert len(gaps) == 1, out
    # both never-run checks are named...
    assert "check2" in gaps[0].detail, gaps[0].detail
    assert "check3" in gaps[0].detail, gaps[0].detail
    # ...and the check that already produced a real FAIL is not re-listed as skipped
    assert "check1" not in gaps[0].detail, gaps[0].detail


def test_the_gap_is_worded_as_a_hard_deadline_not_a_cpu_budget(tmp_path, monkeypatch):
    """`own_deadline_hit` must be set True by the outer handler too, or the rendered
    reason blames the cooperative per-check CPU budget for what was actually the
    ring's own hard wall-clock deadline firing.
    """
    holder = _armed(monkeypatch)

    def _check1(ctx):
        return _custom("B13", HIGH, PASS, "ok", "-")

    def _check2(ctx):
        raise AssertionError("must never run")

    ring = _EscapesAfterOne([_check1, _check2], lambda: holder["frame"])
    monkeypatch.setattr(_vet_mod, "SKILL_CONTENT_RING", ring, raising=True)

    out = _vet_mod._run_content_ring(_skill_ctx(tmp_path))
    gaps = [f for f in out if f.id == "VET-COVERAGE"]
    assert len(gaps) == 1
    assert "hard scan deadline fired" in gaps[0].detail, gaps[0].detail
    assert "CPU scan budget" not in gaps[0].detail, gaps[0].detail


def test_outer_handler_still_reraises_an_unowned_expiry(tmp_path, monkeypatch):
    """The outer handler must be exactly as strict as the inner one: an exception not
    owned by the ring's own frame (an unattributed cooperative raise, `owner=None` —
    skillast.py's own reached-sinks cap shape) must still travel past it untouched —
    the whole point of `owned_by(...)` is that neither handler may steal an expiry
    that is not genuinely its own.
    """

    def _check1(ctx):
        return _custom("B13", HIGH, PASS, "ok", "-")

    def _check2(ctx):
        raise AssertionError("must never run")

    # owner_fn always returns None here — never the real frame `check_deadline`
    # would hand out — so this is unconditionally the unattributed shape regardless
    # of what the ring itself arms.
    ring = _EscapesAfterOne([_check1, _check2], lambda: None)
    monkeypatch.setattr(_vet_mod, "SKILL_CONTENT_RING", ring, raising=True)

    with pytest.raises(ScanBudgetExceeded) as excinfo:
        _vet_mod._run_content_ring(_skill_ctx(tmp_path))
    assert excinfo.value.owner is None


# --------------------------------------------------------------- structural guard


def _is_last_done_assign(stmt: ast.stmt) -> bool:
    return (
        isinstance(stmt, ast.Assign)
        and len(stmt.targets) == 1
        and isinstance(stmt.targets[0], ast.Name)
        and stmt.targets[0].id == "last_done_idx"
    )


def test_every_early_exit_in_the_ring_loop_updates_last_done_idx_first():
    """B-724 structural guard, so a later edit cannot silently reopen the accounting
    gap: every `continue` inside the ring's `for` loop must be immediately preceded,
    in its own statement block, by `last_done_idx = idx` -- and the loop body's final
    (non-`continue`) completion path must end with the same assignment. Without this,
    a future branch that forgets the bookkeeping makes the outer handler's
    `[last_done_idx + 1:]` slice silently over- or under-report on the very next
    residual landing, on any CPython version -- the whole point of routing the
    accounting through source-level statement order rather than bytecode offsets.
    """
    src = inspect.getsource(_vet_mod._run_content_ring)
    tree = ast.parse(src)
    fn = tree.body[0]
    assert isinstance(fn, ast.FunctionDef) and fn.name == "_run_content_ring"
    for_node = next(n for n in ast.walk(fn) if isinstance(n, ast.For))

    def _block_containing(target: ast.AST):
        for parent in ast.walk(for_node):
            for field in ("body", "orelse", "finalbody"):
                block = getattr(parent, field, None)
                if isinstance(block, list) and target in block:
                    return block
        return None

    checked_any = False
    for node in ast.walk(for_node):
        if not isinstance(node, ast.Continue):
            continue
        checked_any = True
        block = _block_containing(node)
        assert block is not None, "could not locate a `continue`'s own statement block"
        i = block.index(node)
        assert i > 0, "a `continue` with nothing before it in its block"
        assert _is_last_done_assign(block[i - 1]), (
            "a `continue` in the ring loop is not immediately preceded by "
            "`last_done_idx = idx` -- the outer ScanBudgetExceeded handler's "
            "accounting can now silently mis-report which checks ran"
        )
    assert checked_any, "no `continue` found in the ring loop -- guard is vacuous"

    last_stmt = for_node.body[-1]
    assert _is_last_done_assign(last_stmt), (
        "the ring loop's normal (non-continue) completion path does not end with "
        "`last_done_idx = idx`"
    )


def test_the_outer_except_uses_last_done_idx_plus_one_not_idx():
    """Pins the slice expression itself: `[idx:]` (the inner handler's shape) would
    double-count here, because by construction every check up to and including
    `last_done_idx` is already fully accounted for."""
    src = inspect.getsource(_vet_mod._run_content_ring)
    assert "SKILL_CONTENT_RING[last_done_idx + 1:]" in src, (
        "expected the outer handler to slice from last_done_idx + 1, not idx"
    )
