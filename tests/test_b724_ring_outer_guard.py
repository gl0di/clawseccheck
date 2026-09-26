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
checks to report as `skipped` without double- or under-counting — this module ORIGINALLY
tracked a scalar `last_done_idx`, set as the LAST statement on every path through the
loop body, so the outer handler's slice (`SKILL_CONTENT_RING[last_done_idx + 1:]`) would
be correct by ordinary source-level statement-execution order, not by reasoning about
which bytecode offset a signal happens to land on.

B-860 found that argument incomplete: everything from `if fx.status not in (FAIL, WARN):`
onward in the loop body sits OUTSIDE the per-check inner `try`, so a signal landing
between such a branch's own mutation (`out.append(fx)`, `crashed.append(name)`, a
`ring_coverage.extend(...)`) and the FOLLOWING `last_done_idx = idx` bump was not caught
by any inner handler — it reached the outer one with the bump for the just-completed
index never having run, so that index was re-listed in `skipped` even though it had
already produced a real finding (or already been filed as crashed). Confirmed by
`sys.settrace` injection immediately after each such mutation (see the `test_b860_*`
tests below), including a crashed check ending up in BOTH `VET-RING-CHECK-ERROR` and the
`VET-COVERAGE` skipped list at once.

The fix replaces the scalar with per-index dicts/set (`out_by_idx`, `coverage_by_idx`,
`crashed_by_idx`, `skip_by_idx`, `dup_idx`), each written through a SINGLE keyed
statement (`tracker[idx] = ...` / `tracker.add(idx)`) that bakes the disposition and its
index into the same statement — there is no longer a separate trailing bump statement
for a signal to land after. A reconciliation pass placed after the whole `with
check_deadline(...)` block derives `out`/`crashed`/`skipped`/`ring_coverage` from these
trackers, and fills `skip_by_idx` for any index accounted for nowhere. See the in-source
comment on `_run_content_ring` for the full argument, including why `out_by_idx[idx] =
fx` is written BEFORE `seen.add(key)`, not after (the reviewer's naive "bump earlier"
fix, rejected for B-724, would trade this over-report for a silent drop of a real FAIL).

These tests reproduce the ORIGINAL B-724 residual landing spot deterministically — a
custom iterable that raises `ScanBudgetExceeded` from the loop's own iterator-advance
(`enumerate`'s `__next__`), which sits outside the inner `try` exactly as the `continue`
jump does — rather than depending on real SIGALRM timing, matching this suite's own
precedent (`test_own_deadline_firing_during_loop_body_does_not_escape`,
`test_b394_scan_budget_escape.py`) for deterministic injection over timing-dependent
signal races. The B-860 tests reproduce the NEWER, narrower residual with `sys.settrace`
line injection instead, because that residual sits INSIDE a single loop iteration
(between two adjacent statements), a boundary the iterator-advance trick cannot reach.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import ast
import inspect
import sys

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


# ----------------------------------------------------- B-860: settrace injection


def _line_after_anchor(func, anchor: str, target_stripped: str | None = None) -> int:
    """Absolute source line number of the line right after the first line whose
    STRIPPED text starts with `anchor` -- or, with `target_stripped`, the first LATER
    line whose stripped text equals it exactly (for an anchor statement that itself
    spans several physical lines, e.g. a bracketed comprehension). Matched against the
    stripped code line, never a bare substring search, so a prose comment elsewhere in
    the function that happens to quote the same code (this module's own rationale
    comments do) can never be mistaken for the real statement.
    """
    src_lines, start = inspect.getsourcelines(func)
    hit = next(i for i, line in enumerate(src_lines) if line.strip().startswith(anchor))
    if target_stripped is None:
        return start + hit + 1
    for j in range(hit + 1, len(src_lines)):
        if src_lines[j].strip() == target_stripped:
            return start + j
    raise AssertionError(f"no line {target_stripped!r} found after {anchor!r}")


def _raise_once_before_line(target_line: int, owner_fn):
    """A `sys.settrace` global trace function that, the FIRST time execution is about
    to reach `target_line` inside `_run_content_ring`, raises
    `ScanBudgetExceeded(owner=owner_fn())` instead of letting it run -- simulating a
    signal landing exactly between the previous statement finishing and this one
    starting, deterministically and independent of real SIGALRM timing.
    """
    state = {"fired": False}

    def local_trace(frame, event, arg):
        if event == "line" and not state["fired"] and frame.f_lineno == target_line:
            state["fired"] = True
            raise ScanBudgetExceeded(owner=owner_fn())
        return local_trace

    def global_trace(frame, event, arg):
        if event == "call" and frame.f_code.co_name == "_run_content_ring":
            return local_trace
        return None

    return global_trace


def _run_traced(global_trace, func, *args, **kwargs):
    old = sys.gettrace()
    sys.settrace(global_trace)
    try:
        return func(*args, **kwargs)
    finally:
        sys.settrace(old)


def test_b860_signal_between_out_write_and_seen_add_does_not_relist_a_completed_fail(
    tmp_path, monkeypatch
):
    """The core B-860 window: `out_by_idx[idx] = fx` has already recorded check1's real
    FAIL by the time a ScanBudgetExceeded owned by the ring's own frame lands, right
    before the following `seen.add(key)` runs. The completed FAIL must survive in the
    return value, AND check1 must not also be named in the coverage-gap's `skipped`
    text -- the exact over-report `sys.settrace` injection at this boundary confirmed
    against the pre-B-860 `last_done_idx` scheme.
    """
    holder = _armed(monkeypatch)

    def _check1(ctx):
        return _custom("B13", HIGH, FAIL, "planted_exfil_signal_from_check1", "-")

    def _check2(ctx):
        return _custom("B14", HIGH, PASS, "ok", "-")

    monkeypatch.setattr(_vet_mod, "SKILL_CONTENT_RING", [_check1, _check2], raising=True)

    target = _line_after_anchor(_vet_mod._run_content_ring, "out_by_idx[idx] = fx")
    tracer = _raise_once_before_line(target, lambda: holder["frame"])
    out = _run_traced(tracer, _vet_mod._run_content_ring, _skill_ctx(tmp_path))

    fails = [f for f in out if f.status == FAIL]
    assert len(fails) == 1 and "planted_exfil_signal_from_check1" in fails[0].detail, out
    gaps = [f for f in out if f.id == "VET-COVERAGE"]
    assert len(gaps) == 1, out
    assert "check1" not in gaps[0].detail, gaps[0].detail


def test_b860_signal_between_crashed_write_and_continue_does_not_double_bucket(
    tmp_path, monkeypatch
):
    """The reproduced cross-bucket defect: a crashed check must appear in
    `VET-RING-CHECK-ERROR` exactly once and must NOT also be re-listed in the
    `VET-COVERAGE` skipped text -- the shape confirmed for the pre-B-860 scheme by
    injecting right after `crashed_by_idx[idx] = name`, before its `continue`.
    """
    holder = _armed(monkeypatch)

    def _check1(ctx):
        raise RuntimeError("boom")

    def _check2(ctx):
        return _custom("B14", HIGH, PASS, "ok", "-")

    monkeypatch.setattr(_vet_mod, "SKILL_CONTENT_RING", [_check1, _check2], raising=True)

    target = _line_after_anchor(_vet_mod._run_content_ring, "crashed_by_idx[idx] = name")
    tracer = _raise_once_before_line(target, lambda: holder["frame"])
    out = _run_traced(tracer, _vet_mod._run_content_ring, _skill_ctx(tmp_path))

    errors = [f for f in out if f.id == "VET-RING-CHECK-ERROR"]
    assert len(errors) == 1 and "check1" in errors[0].detail, out
    gaps = [f for f in out if f.id == "VET-COVERAGE"]
    assert len(gaps) == 1, out
    assert "check1" not in gaps[0].detail, (
        "check1 crashed AND was re-listed as skipped -- the B-860 double-bucket bug",
        gaps[0].detail,
    )


def test_b860_signal_between_coverage_write_and_continue_does_not_relist(
    tmp_path, monkeypatch
):
    """Same shape for the coverage-note branch (a PASS/UNKNOWN ring result): the
    disclosure it already recorded must not additionally cause it to be named in the
    `skipped` text -- injected right after the (multi-line) `coverage_by_idx[idx] =
    [...]` assignment finishes, before its `continue`.
    """
    holder = _armed(monkeypatch)

    def _check1(ctx):
        return _custom("B14", HIGH, PASS, "ok", "-")

    def _check2(ctx):
        return _custom("B15", HIGH, PASS, "ok", "-")

    monkeypatch.setattr(_vet_mod, "SKILL_CONTENT_RING", [_check1, _check2], raising=True)

    target = _line_after_anchor(
        _vet_mod._run_content_ring, "coverage_by_idx[idx] = [", target_stripped="continue"
    )
    tracer = _raise_once_before_line(target, lambda: holder["frame"])
    out = _run_traced(tracer, _vet_mod._run_content_ring, _skill_ctx(tmp_path))

    gaps = [f for f in out if f.id == "VET-COVERAGE"]
    assert len(gaps) == 1, out
    assert "check1" not in gaps[0].detail, gaps[0].detail


# --------------------------------------------------------------- structural guard


_IDX_TRACKER_DICTS = {"skip_by_idx", "crashed_by_idx", "coverage_by_idx", "out_by_idx"}


def _subscript_index(node: ast.Subscript):
    # Python 3.9 wraps a subscript's index in `ast.Index`; 3.10+ does not.
    sl = node.slice
    return sl.value if isinstance(sl, ast.Index) else sl


def _is_idx_keyed_dict_write(stmt: ast.stmt, dict_name: str | None = None) -> bool:
    if not (
        isinstance(stmt, ast.Assign)
        and len(stmt.targets) == 1
        and isinstance(stmt.targets[0], ast.Subscript)
        and isinstance(stmt.targets[0].value, ast.Name)
        and stmt.targets[0].value.id in _IDX_TRACKER_DICTS
    ):
        return False
    idx_node = _subscript_index(stmt.targets[0])
    if not (isinstance(idx_node, ast.Name) and idx_node.id == "idx"):
        return False
    return dict_name is None or stmt.targets[0].value.id == dict_name


def _is_dup_idx_add(stmt: ast.stmt) -> bool:
    return (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Call)
        and isinstance(stmt.value.func, ast.Attribute)
        and stmt.value.func.attr == "add"
        and isinstance(stmt.value.func.value, ast.Name)
        and stmt.value.func.value.id == "dup_idx"
        and len(stmt.value.args) == 1
        and isinstance(stmt.value.args[0], ast.Name)
        and stmt.value.args[0].id == "idx"
    )


def _records_idx(stmt: ast.stmt) -> bool:
    return _is_idx_keyed_dict_write(stmt) or _is_dup_idx_add(stmt)


def _main_ring_loop(fn: ast.FunctionDef) -> ast.For:
    for node in ast.walk(fn):
        if (
            isinstance(node, ast.For)
            and isinstance(node.target, ast.Tuple)
            and len(node.target.elts) == 2
            and all(isinstance(e, ast.Name) for e in node.target.elts)
            and node.target.elts[0].id == "idx"
            and node.target.elts[1].id == "check"
        ):
            return node
    raise AssertionError(
        "could not locate the main `for idx, check in enumerate(SKILL_CONTENT_RING):` loop"
    )


def test_no_last_done_idx_scalar_remains():
    """B-860 replaced the `last_done_idx` scalar with per-index trackers written
    through a single keyed statement; guard against it quietly reappearing (e.g. a
    future edit half-reverting the fix). Checked at the AST identifier level, not by
    searching the raw source text -- a comment that merely MENTIONS `last_done_idx`
    (this module's own history, or the in-source rationale) can never make this guard
    vacuous or fail it for the wrong reason.
    """
    src = inspect.getsource(_vet_mod._run_content_ring)
    tree = ast.parse(src)
    fn = tree.body[0]
    names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
    assert "last_done_idx" not in names, (
        "`last_done_idx` reappeared as a real identifier in `_run_content_ring` -- "
        "see the B-860 in-source rationale for why the scalar bump is unsound"
    )


def test_every_early_exit_in_the_ring_loop_records_idx_first():
    """B-860 structural guard, replacing the B-724 `last_done_idx` one: every
    `continue` inside the MAIN ring loop must be immediately preceded, in its own
    statement block, by a SINGLE statement that bakes `idx` into one of the per-index
    trackers (`tracker[idx] = ...` or `dup_idx.add(idx)`) -- and the loop body's
    normal (non-`continue`) completion path must write `out_by_idx[idx] = fx`
    immediately before its final `seen.add(key)`. Without this, a future branch that
    forgets the bookkeeping -- or reintroduces a separate trailing bump instead of
    folding the index into the mutation itself -- reopens the B-860 accounting gap.
    """
    src = inspect.getsource(_vet_mod._run_content_ring)
    tree = ast.parse(src)
    fn = tree.body[0]
    assert isinstance(fn, ast.FunctionDef) and fn.name == "_run_content_ring"
    for_node = _main_ring_loop(fn)

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
        assert _records_idx(block[i - 1]), (
            "a `continue` in the ring loop is not immediately preceded by a "
            "single-statement per-index tracker write -- the reconciliation pass can "
            "now silently mis-report which checks ran"
        )
    assert checked_any, "no `continue` found in the ring loop -- guard is vacuous"

    last_two = for_node.body[-2:]
    assert len(last_two) == 2 and _is_idx_keyed_dict_write(last_two[0], "out_by_idx"), (
        "the ring loop's normal completion path must write `out_by_idx[idx] = fx` as "
        "its second-to-last statement"
    )
    tail = last_two[1]
    assert (
        isinstance(tail, ast.Expr)
        and isinstance(tail.value, ast.Call)
        and isinstance(tail.value.func, ast.Attribute)
        and tail.value.func.attr == "add"
        and isinstance(tail.value.func.value, ast.Name)
        and tail.value.func.value.id == "seen"
    ), (
        "expected `out_by_idx[idx] = fx` to be immediately followed by `seen.add(key)` "
        "-- writing `seen.add(key)` FIRST would trade the B-860 over-report for a "
        "silent drop of a real FAIL (see the in-source rationale)"
    )


def test_the_outer_handler_does_no_index_arithmetic_on_the_ring():
    """B-860: the outer `except ScanBudgetExceeded` must not rebuild `skipped` from a
    slice or index of `SKILL_CONTENT_RING` keyed off any scalar cutoff -- that is
    exactly the shape that mis-reported. Every index it might need to disclose is
    filled in by the reconciliation pass placed after the whole `with` block instead.
    """
    src = inspect.getsource(_vet_mod._run_content_ring)
    tree = ast.parse(src)
    fn = tree.body[0]
    with_node = next(n for n in ast.walk(fn) if isinstance(n, ast.With))
    outer_try = with_node.body[0]
    assert isinstance(outer_try, ast.Try), "expected the `with` block's body to be a `try`"
    handlers = [
        h for h in outer_try.handlers if getattr(h.type, "id", None) == "ScanBudgetExceeded"
    ]
    assert len(handlers) == 1
    for node in ast.walk(handlers[0]):
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
            assert node.value.id != "SKILL_CONTENT_RING", (
                "the outer ScanBudgetExceeded handler indexes/slices "
                "SKILL_CONTENT_RING directly -- accounting should come from the "
                "idx-keyed trackers via the post-loop reconciliation pass instead"
            )
