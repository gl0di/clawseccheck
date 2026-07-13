"""B-192: EffectSimulator memory explosion — nested branching OOM-kills vet/audit.

State.reached_sinks used to grow ~2^depth via simulate_if/simulate_loop each
`.extend()`-ing two already-grown lists, and State.copy() re-duplicated that list at
every nesting level — a deeply-nested-but-tiny skill could drive real-world memory
into the tens of GB (empirically ~30GB on a real 782-line script) well before any
wall-clock budget fires, OOM-killing the host process. Fixed by deduping
reached_sinks on insert (by (effect, sink, guards) identity — provably
output-identical, since simulate() already collapses to that same identity
downstream) and capping distinct entries at _MAX_REACHED_SINKS, raising the existing
ScanBudgetExceeded (which run_all/_vet.py already convert to an honest UNKNOWN,
never a silent PASS) on breach.
"""
from __future__ import annotations

import time

import pytest

from clawseccheck.scanbudget import ScanBudgetExceeded
from clawseccheck.skillast import _MAX_REACHED_SINKS, State, simulate_effects


def _nested_if_source(depth: int) -> str:
    """`depth` SEQUENTIAL if/else statements, a network sink in each branch — the real
    pathological shape (linear-size source, exponential reached_sinks pre-fix): each
    if/else copies the ALREADY-accumulated reached_sinks into both its then- and
    else-branch, then merges both copies back — so N sequential pairs double the
    (duplicate-laden) count ~N times, even though every registered sink is a plain,
    non-nested statement. Source size stays O(depth), matching the bug report's real
    782-line repro (a small file, not a deep literal nesting)."""
    indent = "    "
    lines = ["def handler(user_arg):", f"{indent}import requests"]
    for i in range(depth):
        lines.append(f"{indent}if cond_{i}(user_arg):")
        lines.append(f'{indent * 2}requests.post("http://example.com/{i}t", data=user_arg)')
        lines.append(f"{indent}else:")
        lines.append(f'{indent * 2}requests.post("http://example.com/{i}e", data=user_arg)')
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Dedup correctness — the core fix, tested directly on State (fast, deterministic)
# ---------------------------------------------------------------------------


def test_register_effect_dedups_identical_sink():
    """The same (effect, sink, guards) registered many times must not grow the list —
    this is what used to explode across nested branches/loop iterations."""
    s = State()
    for _ in range(500):
        s.register_effect("network", "requests.post")
    assert len(s.reached_sinks) == 1


def test_register_effect_keeps_distinct_guard_combinations():
    """Dedup must be content-based, not a blanket collapse — an unguarded reach and a
    guarded reach of the SAME sink are distinct findings and must both survive."""
    s = State()
    s.register_effect("network", "requests.post")  # unguarded
    s.active_guards.append({"condition_type": "approval-gate", "description": "is_ok()"})
    s.register_effect("network", "requests.post")  # guarded
    assert len(s.reached_sinks) == 2


def test_merge_reached_dedups_across_branches():
    """simulate_if/simulate_loop now call merge_reached instead of .extend() — a
    branch pair reaching the identical sink must not double-count."""
    parent = State()
    branch_a = parent.copy()
    branch_a.register_effect("network", "requests.post")
    branch_b = parent.copy()
    branch_b.register_effect("network", "requests.post")

    parent.merge_reached(branch_a)
    parent.merge_reached(branch_b)
    assert len(parent.reached_sinks) == 1


def test_copy_preserves_dedup_state():
    """A copied State must not forget what it has already seen — otherwise dedup
    resets at every branch and the bug returns."""
    s = State()
    s.register_effect("network", "requests.post")
    c = s.copy()
    c.register_effect("network", "requests.post")  # same key, already seen
    assert len(c.reached_sinks) == 1


def test_register_effect_raises_on_cap_breach():
    """A pathological explosion of DISTINCT sinks (not just duplicates) must degrade
    to the existing ScanBudgetExceeded -> UNKNOWN path, never hang/OOM silently."""
    s = State()
    with pytest.raises(ScanBudgetExceeded):
        for i in range(_MAX_REACHED_SINKS + 10):
            s.active_guards = [{"condition_type": "approval-gate", "description": f"g{i}"}]
            s.register_effect("network", f"sink_{i}")


# ---------------------------------------------------------------------------
# End-to-end: the actual repro shape from the bug report stays fast and accurate
# ---------------------------------------------------------------------------


def test_deeply_nested_if_completes_fast_and_bounded():
    """The bug report's own repro: depth 24 would be ~2^24 pre-fix (structurally
    impossible to finish, let alone in-budget) — now must complete in well under a
    second, matching an ordinary skill scan."""
    src = _nested_if_source(24)
    t0 = time.monotonic()
    results = simulate_effects(src)
    elapsed = time.monotonic() - t0
    assert elapsed < 5.0, f"nested-if simulation took {elapsed:.2f}s — dedup regressed"
    assert results, "simulation must still produce a result, not silently drop everything"
    assert "network" in results[0]["reachable_effects"]


def test_shallow_nested_if_still_reports_unshielded_and_guarded_correctly():
    """Accuracy check: a mix of guarded and unguarded paths to the SAME sink must
    still both be visible after dedup — this is the exact false-negative risk the
    architect flagged (a coarse dedup key could collapse a dangerous unshielded path
    into a guarded one)."""
    src = """
def handler(user_arg, mode=False):
    import requests
    if mode:
        if is_authorized():
            requests.post("http://example.com", data=user_arg)
    else:
        requests.post("http://example.com", data=user_arg)
"""
    results = simulate_effects(src)
    assert len(results) == 1
    res = results[0]
    assert "network" in res["reachable_effects"]
    assert "network" in res["unshielded_effects"], (
        "the unguarded else-branch reach must still be visible after dedup"
    )
