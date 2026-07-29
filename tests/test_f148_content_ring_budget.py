"""The content ring runs outside run_all and used to be unbounded.

Cost tracks INPUT SIZE, super-linearly — measured (single-axis, `_MAX_BYTES_PER_SKILL`
only) 10KB 0.03s, 100KB 0.52s, 500KB 10.6s, 1MB 41.2s of CPU — so the expensive case is a
large BENIGN skill at the legal cap, not a hostile one (the real hostile fixture costs
7.93s). An earlier ceiling was calibrated the other way round, on a 6.6 MB skill that "cost
0.22s"; that skill was the scanner's own source, which short-circuits before scanning
anything. The guard test below and scanbudget.py's calibration comment re-derive the actual
ceiling against the COMBINED worst case across all four independent per-skill axes
(content/Python/shell/JS) plus the file-count cap, which the single-axis figures above
never covered on their own.

These pin the properties that make the ceiling honest rather than merely fast: a normal vet
is untouched, an exhausted budget is recorded instead of silently returning a clean scan,
truncation never reads as safer than a full scan (and never turns a malicious skill clean),
an outer owner's deadline is never swallowed by the ring's own loop, and the ceiling keeps
measured headroom over the benign worst case so a large harmless skill cannot trip it.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from clawseccheck.catalog import CATALOG, FAIL, HIGH, PASS, UNKNOWN, WARN, Finding
from clawseccheck.checks import (
    SKILL_CONTENT_RING,
    _VET_MERGE_RANK,
    _custom,
    _run_content_ring,
    check_installed_skills,
)
from clawseccheck.collector import (
    LIMIT_DOMAIN_SKILL,
    Context,
    _read_skill_text,
    limit_hits_for,
    read_skill_js,
    read_skill_python,
    read_skill_shell,
)
from clawseccheck.dossier import axis_for, build_profile
from clawseccheck.report import render_vet_dossier
from clawseccheck.scanbudget import (
    DEFAULT_VET_TARGET_BUDGET_S,
    ScanBudgetExceeded,
    _can_hard_timeout,
    budget_deadline,
    budget_exceeded,
    check_deadline,
    cpu_deadline,
    cpu_exceeded,
)

POSIX = _can_hard_timeout()
posix_only = pytest.mark.skipif(not POSIX, reason="hard timeout needs POSIX + main thread")

# A budget the ring's own hard check_deadline can reliably fire within, without being
# so short it risks firing inside __enter__ on a loaded runner (see
# tests/test_scanbudget_reentrancy.py's module docstring: >=50ms, never 1ms).
_OWN_DEADLINE_S = 0.2


def _busy(seconds: float) -> None:
    """Burn CPU for at most ``seconds`` — self-terminating, so a test can never hang."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        pass

# Positive but already elapsed by the time the loop starts. 0 is NOT usable: budget_deadline
# treats a falsy budget as "no cap" and returns None, which is the documented opt-out.
_ALREADY_EXPIRED_S = 1e-9


def _skill_ctx(tmp_path, text: str = "# Test skill\n\nDoes a thing.\n") -> Context:
    ctx = Context(home=tmp_path)
    ctx.installed_skills = {"demo": text}
    ctx.installed_skill_py = {"demo": []}
    ctx.installed_skill_shell = {"demo": []}
    ctx.installed_skill_js = {"demo": []}
    return ctx


def test_target_budget_keeps_measured_headroom_over_the_benign_worst_case():
    """The ceiling must not be lowered without re-measuring — that is how it broke once.

    The original 41.2s figure only measured ONE of the four independent
    byte/file caps a skill saturates (`collector._MAX_BYTES_PER_SKILL`); it never accounted
    for the Python/shell/JS axes (`_MAX_PY_BYTES_PER_SKILL`, reused for shell and JS) or the
    ~500-file cap (`_MAX_FILES_PER_SKILL`) being additive on ONE skill. Re-measured against a
    single skill that legally saturates all four axes AT ONCE (500 files split across
    `.py`/`.sh`/`.js`/`.md`, each axis landing just over its own 1 MB cap), filled with
    genuinely benign, zero-finding content — NOT plain comment-line filler, which undershoots
    badly: ring cost tracks MATCH DENSITY against a check's own trigger regex (e.g. B156's
    send-verb class matches the ordinary word "shipped" — realistic technical prose repeating
    it, e.g. "these helpers are shipped with this skill", is the expensive shape, since every
    match rescans the whole blob for defensive/heading context; verified `ring findings: []`
    on this fixture, so it is a true benign-but-expensive case, not a detection).

    `_run_content_ring` alone (what this constant bounds) on that skill: 204.0s CPU on Python
    3.12.3, 238.2s CPU on Python 3.9.25 (the CI floor) — the 3.9 slowdown here is ~1.17x, NOT
    the ~1.05x previously observed on other workloads, confirming that ratio does not carry
    across workloads. Headroom must also survive a loaded machine: measured inflation is
    ~2.6x (reused from the prior measurement, not re-verified this round), and it applies to
    CPU time as much as to wall time.
    """
    benign_worst_case_s = 238.2  # the higher (3.9) CPU figure for the ring alone, all 4 axes
    load_inflation = 2.6         # measured previously, 24 competing processes on an 8-core box
    assert DEFAULT_VET_TARGET_BUDGET_S >= benign_worst_case_s * load_inflation, (
        "the per-target ceiling no longer clears a legal-size benign skill under load; "
        "re-measure before changing it"
    )


def test_budget_is_cpu_time_so_blocking_does_not_spend_it():
    """A scan blocked on I/O has not used up its scanning budget.

    This is the honest reason for the CPU clock — NOT immunity to machine load, which was
    measured and disproved (CPU inflates 2.60x under contention, wall 2.6x).
    """
    cpu = cpu_deadline(0.05)
    wall = budget_deadline(0.05)
    time.sleep(0.15)  # elapsed, but costs this process no CPU
    assert not cpu_exceeded(cpu), "sleeping consumed the CPU budget"
    assert budget_exceeded(wall), "control: the wall-clock budget did elapse"


def _vet_pool(ctx):
    """Rebuild the pool exactly the way vet_skill merges it, then profile it."""
    base = check_installed_skills(ctx)
    ring = _run_content_ring(ctx, target_budget_s=_ALREADY_EXPIRED_S)
    pool = [base, *ring]
    primary = max(pool, key=lambda fx: _VET_MERGE_RANK.get(fx.status, 0))
    primary.ring_findings = [
        fx
        for fx in pool
        if fx is not primary
        and (
            fx.status in (FAIL, WARN)
            or (fx.status == UNKNOWN and "coverage is incomplete" in (fx.detail or ""))
        )
    ]
    primary.ctx = ctx
    return build_profile(primary, str(ctx.home), "skill")


def test_truncated_ring_cannot_grade_cleaner_than_a_full_scan(tmp_path):
    """The regression that motivated the finding: before it, hitting the ceiling PAID.

    Measured on a benign skill: a truncated ring graded A/100 while the same skill fully
    scanned graded B/83 — running out of budget bought a *better* verdict than actually
    being inspected. A scan that inspected less must never read as safer.
    """
    (tmp_path / "SKILL.md").write_text("---\nname: demo\n---\n\n# Demo\n\nFormats text.\n")
    truncated = _vet_pool(_skill_ctx(tmp_path))
    assert truncated.overall_grade != "A"
    assert truncated.score <= 79
    assert truncated.overall_status == WARN
    danger = [a for a in truncated.axes if a.axis == "danger"][0]
    assert danger.status == UNKNOWN


def test_truncation_never_turns_a_malicious_skill_clean():
    """Truncation may LOSE a finding; it must never manufacture a clean one.

    Measured across the bad_* fixtures, 18 of them are caught only by a ring check, so a ring
    cut short downgrades them from FAIL/D to UNKNOWN/C — the engine cannot confirm a threat it
    never scanned, and inventing the FAIL anyway would be the fabrication Golden Rule #4
    forbids. What it MUST never do is come back clean. This pins the floor.
    """
    target = Path("fixtures/bad_b61_curl_exfil_config/skills/leaker")
    if not target.is_dir():  # pragma: no cover - fixture layout guard
        pytest.skip(f"fixture missing: {target}")

    ctx = Context(home=target)
    ctx.installed_skills = {target.name: _read_skill_text(target, ctx)}
    ctx.installed_skill_py = {target.name: read_skill_python(target, ctx)}
    ctx.installed_skill_shell = {target.name: read_skill_shell(target, ctx)}
    ctx.installed_skill_js = {target.name: read_skill_js(target, ctx)}

    base = check_installed_skills(ctx)
    ring = _run_content_ring(ctx, target_budget_s=_ALREADY_EXPIRED_S)
    pool = [base, *ring]
    primary = max(pool, key=lambda fx: _VET_MERGE_RANK.get(fx.status, 0))
    primary.ring_findings = [
        fx
        for fx in pool
        if fx is not primary
        and (
            fx.status in (FAIL, WARN)
            or (fx.status == UNKNOWN and "coverage is incomplete" in (fx.detail or ""))
        )
    ]
    primary.ctx = ctx
    profile = build_profile(primary, str(target), "skill")

    assert primary.status != PASS, "a truncated scan reported a malicious skill as clean"
    assert profile.overall_grade != "A"
    assert profile.overall_status != PASS


def test_coverage_finding_maps_to_the_danger_axis(tmp_path):
    """Unmapped, the finding lands in `unmapped`, which never reaches the grade at all."""
    gap = Finding(
        "VET-COVERAGE", "t", HIGH, UNKNOWN, "coverage is incomplete", "f", "Skill Trust", False
    )
    assert axis_for(gap) == "danger"
    profile = _vet_pool(_skill_ctx(tmp_path))
    assert "VET-COVERAGE" not in getattr(profile, "unmapped", [])


def test_gap_reaches_the_rendered_dossier(tmp_path):
    """It has to be visible to a human, not just present in a dataclass."""
    assert "coverage is incomplete" in render_vet_dossier(_vet_pool(_skill_ctx(tmp_path)))


def test_coverage_id_stays_out_of_the_catalog():
    """VET-COVERAGE is a synthetic vet verdict, not a check.

    In CATALOG it would move len(CATALOG) and redden every shipped check-count claim
    (test_doc_facts pins those exactly).
    """
    assert not any(m.id == "VET-COVERAGE" for m in CATALOG)


def test_clean_skill_records_no_coverage_gap(tmp_path):
    """Default budget: a benign skill is scanned in full and nothing is noted as skipped."""
    ctx = _skill_ctx(tmp_path)
    _run_content_ring(ctx)
    assert not [h for h in limit_hits_for(ctx, LIMIT_DOMAIN_SKILL) if "content-ring" in h]


def test_exhausted_budget_is_recorded_not_silently_dropped(tmp_path):
    """An exhausted ceiling must leave a trace: a silent skip would read as a clean scan."""
    ctx = _skill_ctx(tmp_path)
    out = _run_content_ring(ctx, target_budget_s=_ALREADY_EXPIRED_S)

    # Nothing was actually inspected, so the only finding is the coverage gap itself.
    assert [f.id for f in out] == ["VET-COVERAGE"]
    assert out[0].status == UNKNOWN
    gaps = [h for h in limit_hits_for(ctx, LIMIT_DOMAIN_SKILL) if "content-ring" in h]
    assert len(gaps) == 1, f"expected exactly one coverage-gap note, got {gaps}"
    note = gaps[0]
    # "coverage is incomplete" is load-bearing wording, not prose: dossier's
    # _danger_coverage_gap matches on that exact substring.
    assert "coverage is incomplete" in note
    # The note names how much was missed, so a reader can judge the size of the hole.
    assert f"of {len(SKILL_CONTENT_RING)} content-security check(s)" in note


def test_clean_and_exhausted_differ(tmp_path):
    """The two paths must be distinguishable — otherwise the gap note proves nothing."""
    full, starved = _skill_ctx(tmp_path), _skill_ctx(tmp_path)
    _run_content_ring(full)
    _run_content_ring(starved, target_budget_s=_ALREADY_EXPIRED_S)
    assert limit_hits_for(full, LIMIT_DOMAIN_SKILL) != limit_hits_for(
        starved, LIMIT_DOMAIN_SKILL
    )


def test_unattributed_cooperative_raise_is_re_raised_not_swallowed(tmp_path, monkeypatch):
    """skillast.py's reached-sinks cap raises ScanBudgetExceeded with no owner
    (`owner=None`, not via check_deadline) — it belongs to nobody and must escape this
    loop untouched, exactly like an outer owner's expiry.

    B-347: since the ring now arms its OWN check_deadline frame around this loop,
    `owned_by(exc, own_frame)` is what has to tell "mine" from "not mine" — an
    unattributed exception must never match a real frame (owned_by is False whenever
    exc.owner is None, regardless of which frame it's compared against). Because
    ScanBudgetExceeded is a plain Exception subclass, the ring's `except Exception:
    continue` would happily eat it too and hand the caller a partially scanned skill
    dressed up as a fully scanned one — the false-PASS shape C-175 fixed inside
    check_installed_skills; this pins that the ring does not reintroduce it.
    """
    def _times_out(_ctx):
        raise ScanBudgetExceeded  # owner=None, exactly skillast.py's raise shape

    monkeypatch.setattr(
        "clawseccheck.checks._vet.SKILL_CONTENT_RING", [_times_out], raising=True
    )
    with pytest.raises(ScanBudgetExceeded) as excinfo:
        _run_content_ring(_skill_ctx(tmp_path))
    assert excinfo.value.owner is None


@posix_only
def test_outer_owner_deadline_is_re_raised_not_swallowed(tmp_path, monkeypatch):
    """A ScanBudgetExceeded from a genuinely OUTER frame's deadline must escape this
    loop, not be mistaken for the ring's own newly-armed one (B-347).

    report.py:_skill_inventory wraps `_run_content_ring` in its own `check_deadline`
    in production; this reproduces that shape with a REAL nested check_deadline (not a
    hand-set `.owner`), so the exception is exactly what `_fire()` would actually
    attribute. If the ownership gate were ever weakened to "catch any
    ScanBudgetExceeded and treat it as mine" — i.e. dropping the `owned_by()` check —
    the ring would swallow this outer expiry and return a partial list instead of
    letting it reach `pytest.raises` here, so this test would go from pass to fail on
    exactly that mutation.
    """
    def _hangs(_ctx):
        _busy(5.0)  # self-terminates; the OUTER 0.08s deadline cuts it first
        return _custom("B13", HIGH, PASS, "unreachable", "—")

    monkeypatch.setattr(
        "clawseccheck.checks._vet.SKILL_CONTENT_RING", [_hangs], raising=True
    )
    with pytest.raises(ScanBudgetExceeded):
        # The ring's own deadline (5.0s) is far longer than the outer's (0.08s), so the
        # outer's is the one that actually fires and is attributed to it.
        with check_deadline(0.08):
            _run_content_ring(_skill_ctx(tmp_path), target_budget_s=5.0)


@posix_only
def test_own_deadline_preserves_fails_found_before_it_fired(tmp_path, monkeypatch):
    """The B-347 bug: the ring's OWN hard deadline firing mid-loop must not discard a
    FAIL/WARN an earlier check in the SAME call already produced — and the truncation
    must still be disclosed via a VET-COVERAGE coverage-gap finding, not silently.

    Mutation-proof: if the fix regressed to re-raising unconditionally (the pre-B-347
    behaviour), this call would raise ScanBudgetExceeded instead of returning, and the
    assertions on `out` below would never run. If the own-deadline arming were removed
    entirely (falling back to the old cooperative-CPU-only ceiling), `_hangs` would run
    to its full 5s self-limit instead of being interrupted at ~0.2s, and the elapsed-time
    assertion would fail.
    """
    def _real_fail(_ctx):
        return _custom("B13", HIGH, FAIL, "planted exfiltration finding", "—")

    def _hangs(_ctx):
        _busy(5.0)  # self-terminates; the ring's own 0.2s deadline cuts it first
        return _custom("B13", HIGH, PASS, "unreachable", "—")

    monkeypatch.setattr(
        "clawseccheck.checks._vet.SKILL_CONTENT_RING", [_real_fail, _hangs], raising=True
    )
    ctx = _skill_ctx(tmp_path)
    started = time.perf_counter()
    out = _run_content_ring(ctx, target_budget_s=_OWN_DEADLINE_S)
    elapsed = time.perf_counter() - started

    assert elapsed < 3.0, "not interrupted by the ring's own deadline — it ran to the 5s self-limit"
    fails = [f for f in out if f.status == FAIL]
    assert len(fails) == 1
    assert fails[0].id == "B13"
    assert fails[0].detail == "planted exfiltration finding"

    gaps = [f for f in out if f.id == "VET-COVERAGE"]
    assert len(gaps) == 1, f"expected exactly one coverage-gap finding, got {out}"
    assert gaps[0].status == UNKNOWN
    assert "coverage is incomplete" in gaps[0].detail
    assert "hard scan deadline" in gaps[0].detail, (
        "the gap reason should name the ring's OWN deadline, not the cooperative "
        f"CPU-budget wording: {gaps[0].detail!r}"
    )
    # note_limit fired on the SAME ctx the call used, not merely a finding in `out`.
    gap_notes = [h for h in limit_hits_for(ctx, LIMIT_DOMAIN_SKILL) if "content-ring" in h]
    assert len(gap_notes) == 1


def test_ordinary_check_failure_is_still_contained(tmp_path, monkeypatch):
    """The re-raise above must not turn every crashing ring check into a broken vet.

    The surviving FAIL is the point: asserting only "no exception" would pass even if the
    patch never took effect, since a benign skill yields an empty ring anyway.
    """
    def _explodes(_ctx):
        raise ValueError("boom")

    def _reports(_ctx):
        return _custom("B13", HIGH, FAIL, "planted finding", "—")

    monkeypatch.setattr(
        "clawseccheck.checks._vet.SKILL_CONTENT_RING", [_explodes, _reports], raising=True
    )
    out = _run_content_ring(_skill_ctx(tmp_path))
    assert [f.detail for f in out] == ["planted finding"]
