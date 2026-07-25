"""C-289 (A1) — memoize `trajaudit.analyze` on `Context._trajaudit_cache`.

`trajaudit.analyze(ctx)` (`explicit_path is None` branch) used to do a full trajectory-
sidecar glob + per-file JSON parse on EVERY call, but a single audit run calls it
repeatedly with the exact same, unmutated `ctx`: `scoring.compute` reaches it (via
`trajaudit.grade_cap_signal`) once for `audit()`'s own score and again for each of
`scoring.project`'s internal what-if `compute()` calls (`--json`'s `projection` payload).

Measurement note (ground-truthed empirically, not assumed from the design doc): patching
`trajaudit.analyze` itself with `wraps=` shows the same call count before and after this
change — every logical call SITE still invokes the `analyze` name once each; caching
lives *inside* that function, invisible to a mock wrapped around the outer name. The
metric that actually demonstrates the win is the real scan work, `trajaudit._analyze_scan`
(the function `analyze()` now delegates to on a cache miss): patched with `wraps=`, it are
called once per `Context` per audit run, not once per call site.
"""
from __future__ import annotations

from pathlib import Path
from unittest import mock

from clawseccheck import audit
from clawseccheck import trajaudit
from clawseccheck.collector import collect
from clawseccheck.report import render_json
from clawseccheck.trajaudit import analyze

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def test_real_scan_runs_once_per_ctx_across_the_full_render_json_flow():
    """The perf-relevant metric: `_analyze_scan` (the real glob + per-file parse) runs
    exactly once for one `Context`, even though `analyze()` itself is still reached from
    multiple call sites (`audit()`'s own `compute()` call, plus `scoring.project`'s
    several internal `compute()` calls threaded through `render_json`'s `projection`
    payload) — call COUNT asserted, never wall-clock."""
    orig_analyze = trajaudit.analyze
    orig_scan = trajaudit._analyze_scan
    with mock.patch.object(trajaudit, "analyze", wraps=orig_analyze) as m_analyze, \
            mock.patch.object(trajaudit, "_analyze_scan", wraps=orig_scan) as m_scan:
        ctx, findings, score = audit(FIXTURES / "traj_incident_acted")
        render_json(findings, score, ctx=ctx)

    # `analyze()` is still reached from more than one call site (the fan-out this task
    # set out to collapse the REAL work for) — pinned as >= 2 rather than hardcoding the
    # exact measured 5 so this test does not chase an unrelated future change to how many
    # fixable FAILs this fixture happens to project.
    assert m_analyze.call_count >= 2, m_analyze.call_count
    # ...but the expensive real scan behind all of them ran exactly once.
    assert m_scan.call_count == 1, m_scan.call_count


def test_without_the_cache_field_the_real_scan_runs_once_per_call_site():
    """Contrast/regression pin: strip `_trajaudit_cache` off a real `Context` (simulates
    a duck-typed ctx built before this change, or any stub missing the field) and the
    same flow's real-scan count goes back up — proving the collapse above is really the
    cache field doing the work, not some other, unrelated coincidence."""
    from clawseccheck.checks import run_all
    from clawseccheck.scoring import compute

    ctx = collect(FIXTURES / "traj_incident_acted")
    del ctx._trajaudit_cache
    assert not hasattr(ctx, "_trajaudit_cache")

    findings = run_all(ctx)
    score = compute(findings, ctx)  # audit()'s own compute() call, uncached (1 real scan)

    orig_scan = trajaudit._analyze_scan
    with mock.patch.object(trajaudit, "_analyze_scan", wraps=orig_scan) as m_scan:
        render_json(findings, score, ctx=ctx)  # scoring.project's several compute() calls

    # Every one of project()'s internal compute() calls does its own real scan when the
    # cache field is absent — more than the single scan the cached path achieves above.
    assert m_scan.call_count > 1, m_scan.call_count


def test_duck_typed_ctx_without_cache_field_still_works_uncached():
    """A stub `ctx` that never had `_trajaudit_cache` at all (e.g. a hand-built object in
    another test) must keep working exactly as before this change — `analyze` reads the
    field via `getattr(ctx, "_trajaudit_cache", None)` and simply skips caching."""

    class _StubCtx:
        def __init__(self, home):
            self.home = home
            self.installed_skills = {}
            self.bootstrap = {}

    ctx = _StubCtx(FIXTURES / "traj_no_sidecar")
    r1 = analyze(ctx)
    r2 = analyze(ctx)
    assert r1 == r2
    assert r1 is not r2  # each call still returns its own dict, uncached


def test_mutating_the_returned_dict_does_not_leak_to_the_next_caller():
    """Risk mitigation for the shared-object hazard: memoization caches ONE result dict
    per `Context`, but `analyze()` hands each caller its own shallow top-level copy — so
    a caller that reassigns/adds a top-level key can never corrupt what the next caller
    in the same audit run sees."""
    ctx = collect(FIXTURES / "traj_incident_acted")

    r1 = analyze(ctx)
    assert r1["present"] is True and r1["hits"], "fixture must produce a real hit to " \
        "make this a meaningful mutation target"
    r1["hits"] = "MUTATED-BY-CALLER"
    r1["a_key_this_dict_never_had"] = "poison"

    r2 = analyze(ctx)
    assert r2["hits"] != "MUTATED-BY-CALLER"
    assert "a_key_this_dict_never_had" not in r2
    assert r1 is not r2


def test_a_fresh_context_never_shares_a_cache_with_another_context():
    """Two different `Context` objects (e.g. `report.py`'s own per-skill blast-radius
    Context) each get their own empty cache by construction — a result cached for one
    must never leak into the other."""
    ctx_a = collect(FIXTURES / "traj_incident_acted")
    ctx_b = collect(FIXTURES / "traj_present_not_acted")

    r_a = analyze(ctx_a)
    r_b = analyze(ctx_b)

    assert r_a["hits"] != r_b["hits"]
    assert ctx_a._trajaudit_cache is not ctx_b._trajaudit_cache
