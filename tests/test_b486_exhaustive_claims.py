"""B-486 — `--exhaustive` was sold as removing the time budget. It raised it, and still
truncated nondeterministically. This round makes the covered SET deterministic instead.

## Round 1 (docs-only, landed earlier)

`docs/USAGE.md` promised "every log/transcript sink (not cut off by the time budget)",
and B164's own skip sentence told the operator to "re-run with --exhaustive to include
them". Both promised completeness the flag did not deliver — measured on a real 135-sink
corpus, two consecutive runs: `All 135 … scanned` in 64.2s, then `5 … not scanned` in
64.8s. That round fixed the wording without touching the mechanism
(`EXHAUSTIVE_LIMITS.log_max_total_bytes` stayed unbounded, so `log_check_budget_s` was
still the sole binding constraint and the covered set still varied with machine load).

## Round 2 (this one): the mechanism

`EXHAUSTIVE_LIMITS.log_max_total_bytes` is no longer unbounded. `_plan_log_hunt_sinks`
(built for B-484/`DEFAULT_LIMITS`) is a pure function of `(kind, mtime, size, path)` — it
never reads the clock — so a finite budget makes IT the decider instead of
`log_check_budget_s`. Measured on a real ~41 MiB / 120-sink corpus (this box,
2026-08-25): the shipped 12 MiB budget admits 42/120 sinks and the real scan loop
completes them in ~32s of the 60s ceiling (0 clock-skipped, 46% headroom) — see
`scanbudget.py`'s own comment beside the constant for the full measurement table,
including why 24 MiB was rejected (it re-hit the clock, at 60s+, with 16 of 74 admitted
sinks skipped by the loop's own deadline). `check_budget_s` / `audit_budget_s` were NOT
raised — the byte plan makes that cascade unnecessary, which is the point.

**What is NOT wrong, in either round:** the code's own disclosure. When the plan (or,
rarely now, the clock backstop) leaves sinks out, `skipped_for_time > 0`, the skip
sentence prints, and F-164 SC-5's affirmative "All N … scanned" branch correctly does
not fire in its place.

**New in round 2:** the skip-sentence remedy is now conditional on `lim.exhaustive`
(`_log_hunt_budget_remedy` in `checks/_egress.py`). Before, both call sites
unconditionally said "re-run with --exhaustive" — harmless while exhaustive was
unbounded (a re-run under different load really could scan more), but once exhaustive
itself has a deterministic budget, a run already under `--exhaustive` that still has
sinks left out will skip the exact same ones on a re-run, so recommending the flag it is
already running would be a new false remedy this round would otherwise introduce.

This module pins the wording contract and the planning/execution mechanism; it does not
assert exact timings (machine-specific, would flake) beyond the specific real-corpus
regression scenario in `test_two_exhaustive_runs_on_unchanged_corpus_scan_the_same_set`.

Stdlib-only, offline, writes nothing.
"""
from __future__ import annotations

import inspect
from pathlib import Path

from clawseccheck.checks import _egress

_DOCS = Path("docs/USAGE.md")
_SKILL_MD = Path("SKILL.md")

# The phrasings that promise the flag finishes. Any of them reappearing means someone
# re-introduced the claim the measurement above disproves.
_COMPLETENESS_PROMISES = (
    "not cut off by the time budget",
    "--exhaustive to include them",
)


def _sources() -> dict:
    return {
        "docs/USAGE.md": _DOCS.read_text(encoding="utf-8"),
        "SKILL.md": _SKILL_MD.read_text(encoding="utf-8"),
        "checks/_egress.py": inspect.getsource(_egress),
    }


def test_nothing_promises_exhaustive_removes_the_budget():
    offenders = [
        f"{name}: {promise!r}"
        for name, text in _sources().items()
        for promise in _COMPLETENESS_PROMISES
        # The in-source retraction notes quote the old wording to explain it; only a
        # live claim counts, so skip lines that are comments.
        if any(promise in ln and not ln.lstrip().startswith("#")
               for ln in text.splitlines())
    ]
    assert not offenders, (
        "a completeness promise for --exhaustive is back; the flag raises the scan "
        f"budget, it does not remove it: {offenders}")


def test_the_remedy_still_points_at_exhaustive():
    """Softening the promise must not delete the advice — it is still the right remedy."""
    src = inspect.getsource(_egress)
    assert "re-run with --exhaustive" in src, (
        "the skip disclosure stopped naming --exhaustive at all; the flag genuinely does "
        "raise the budget substantially and remains what an operator should reach for")


def test_the_remedy_says_the_flag_states_its_own_coverage():
    """The honest replacement for "include them": go look at what it reports.

    Round 2 moved the phrase into one shared helper (`_log_hunt_budget_remedy`) instead
    of duplicating it at both call sites, so this now checks that BOTH call sites route
    through it, rather than counting a literal that only appears once post-refactor.
    """
    src = inspect.getsource(_egress)
    assert "its own coverage either way" in src, (
        "the non-exhaustive remedy stopped pointing at --exhaustive's own disclosure")
    call_sites = src.count("{_log_hunt_budget_remedy(lim)}")
    assert call_sites == 2, (
        "both B164 skip-disclosure call sites (the none-readable early return and the "
        "main skip note) must share the one exhaustive-aware remedy helper — found "
        f"{call_sites} call site(s) (excludes the def itself)")


def test_the_remedy_does_not_recommend_exhaustive_to_a_run_already_exhaustive():
    """B-486 round 2's actual new bug-fix: once --exhaustive is itself deterministically
    bounded, a truncated --exhaustive run re-running --exhaustive skips the same sinks.
    Recommending the flag it is already running would be a fresh false remedy.
    """
    from clawseccheck.checks._egress import _log_hunt_budget_remedy
    from clawseccheck.scanbudget import DEFAULT_LIMITS, EXHAUSTIVE_LIMITS

    default_remedy = _log_hunt_budget_remedy(DEFAULT_LIMITS)
    exhaustive_remedy = _log_hunt_budget_remedy(EXHAUSTIVE_LIMITS)

    assert "--exhaustive" in default_remedy
    assert "re-run with --exhaustive" not in exhaustive_remedy, (
        "a run already under --exhaustive must not be told to re-run with the flag it "
        f"is already running: {exhaustive_remedy!r}")
    assert exhaustive_remedy != default_remedy


def test_the_docs_describe_a_raised_budget_not_a_removed_one():
    text = _DOCS.read_text(encoding="utf-8")
    assert "raised, not removed" in text
    assert "is disclosed, never silently dropped" in text or \
           "is disclosed, not silently dropped" in text


def test_the_affirmative_completeness_branch_is_still_conditional():
    """F-164 SC-5: "All N scanned" must stay gated on actually having scanned all N.

    If this ever becomes unconditional the output starts lying in the other direction,
    which is worse than the doc claim this task fixed.
    """
    # Anchor on the sentence itself, not on the first "All " in the module — that one
    # is in a docstring, and matching it made this test assert nothing at all.
    src = inspect.getsource(_egress)
    needle = 'All {len(sinks)} log/transcript sink(s) scanned.'
    idx = src.find(needle)
    assert idx != -1, "the affirmative completeness sentence disappeared"
    window = src[max(0, idx - 800):idx]
    assert "elif lim.exhaustive" in window, (
        "the affirmative 'All N scanned' sentence is no longer gated on --exhaustive "
        "having actually reached every sink")


# ------------------------------------------------------------- round 2: the mechanism


def test_exhaustive_budget_is_finite_and_larger_than_default():
    """The structural fix: EXHAUSTIVE_LIMITS must no longer be unbounded, or every test
    below is checking a helper that production code doesn't actually reach.
    """
    from clawseccheck.scanbudget import _UNBOUNDED, DEFAULT_LIMITS, EXHAUSTIVE_LIMITS

    assert EXHAUSTIVE_LIMITS.log_max_total_bytes != _UNBOUNDED, (
        "EXHAUSTIVE_LIMITS.log_max_total_bytes is unbounded again — that hands the "
        "covered set back to the clock, which is the exact bug this task fixes")
    assert EXHAUSTIVE_LIMITS.log_max_total_bytes > DEFAULT_LIMITS.log_max_total_bytes
    # check_budget_s / audit_budget_s must NOT have moved as a side effect of this
    # change — raising them was explicitly out of scope (SIGALRM/UNKNOWN cascade).
    from clawseccheck.scanbudget import DEFAULT_AUDIT_BUDGET_S, DEFAULT_CHECK_BUDGET_S
    assert EXHAUSTIVE_LIMITS.check_budget_s == 120.0
    assert EXHAUSTIVE_LIMITS.audit_budget_s == 900.0
    assert DEFAULT_LIMITS.check_budget_s == DEFAULT_CHECK_BUDGET_S
    assert DEFAULT_LIMITS.audit_budget_s == DEFAULT_AUDIT_BUDGET_S


def test_exhaustive_plan_is_deterministic_and_genuinely_bounded():
    """Mirrors tests/test_b484_log_hunt_planning.py::test_plan_is_deterministic, but
    against the REAL production EXHAUSTIVE_LIMITS constant (not a `replace()` copy) —
    proving the shipped value, not a stand-in, is both finite and stable across calls.
    """
    from clawseccheck.checks._egress import _plan_log_hunt_sinks
    from clawseccheck.logdiscovery import LogSink
    from clawseccheck.scanbudget import EXHAUSTIVE_LIMITS

    mib = 1024 * 1024
    # 40 x 1 MiB = 40 MiB, comfortably over the shipped budget, so this actually
    # exercises truncation instead of vacuously admitting everything.
    sinks = [
        LogSink(path=f"s{i}", kind="trajectory", source="convention", size=mib,
                 mtime=float(i % 11))
        for i in range(40)
    ]
    first_admitted, first_out = _plan_log_hunt_sinks(sinks, EXHAUSTIVE_LIMITS)
    assert first_out > 0, (
        "a 40 MiB synthetic corpus was admitted in full under EXHAUSTIVE_LIMITS — the "
        "budget is not actually bounding anything")
    for _ in range(4):
        admitted, planned_out = _plan_log_hunt_sinks(sinks, EXHAUSTIVE_LIMITS)
        assert [s.path for s in admitted] == [s.path for s in first_admitted]
        assert planned_out == first_out


def test_two_exhaustive_runs_on_unchanged_corpus_scan_the_same_set(tmp_path, monkeypatch):
    """The assertion the task exists for: two `--exhaustive` runs over an unchanged
    corpus must scan the same set, even when the second run is genuinely slower.

    Before round 2, `EXHAUSTIVE_LIMITS.log_max_total_bytes` was unbounded, so the ONLY
    thing deciding how many sinks got scanned was elapsed wall-clock time against
    `log_check_budget_s` — a slower run scanned fewer sinks than a faster one over the
    identical corpus. This drives the real `check_log_threat_hunt` end-to-end, with an
    injected per-sink delay standing in for "the machine is busier this time", and
    asserts the outcome does not change.
    """
    from dataclasses import replace

    import clawseccheck.logscan as logscan_mod
    import clawseccheck.scanbudget as sb
    from clawseccheck.checks import check_log_threat_hunt
    from clawseccheck.collector import collect
    from clawseccheck.scanbudget import EXHAUSTIVE_LIMITS

    home = tmp_path / "home"
    sessions = home / "agents" / "main" / "sessions"
    sessions.mkdir(parents=True)
    (home / "openclaw.json").write_text("{}")
    for i in range(10):
        (sessions / f"s{i:03d}.trajectory.jsonl").write_text("x" * 20_000)

    # Scaled down so the test stays fast, but shaped the same as production: a finite
    # byte budget well under what the corpus would cost, real per-sink/check budgets
    # with headroom over the injected delay below.
    test_limits = replace(
        EXHAUSTIVE_LIMITS,
        log_max_total_bytes=100_000,   # ~5 of the 10 sinks
        log_check_budget_s=3.0,
        log_per_file_budget_s=1.0,
    )
    monkeypatch.setattr(sb, "limits_for", lambda _ctx: test_limits)

    ctx = collect(home)
    ctx.exhaustive = True

    real_scan = logscan_mod.scan_log_file

    def _instant_scan(sink, deadline, skill_iocs, limits=None):
        return real_scan(sink, deadline, skill_iocs, limits=limits)

    def _busier_machine_scan(sink, deadline, skill_iocs, limits=None):
        import time as _time
        _time.sleep(0.05)  # stands in for "this run happens to be slower"
        return real_scan(sink, deadline, skill_iocs, limits=limits)

    monkeypatch.setattr(logscan_mod, "scan_log_file", _instant_scan)
    fast = check_log_threat_hunt(ctx)

    monkeypatch.setattr(logscan_mod, "scan_log_file", _busier_machine_scan)
    slow = check_log_threat_hunt(ctx)

    assert fast.detail == slow.detail, (
        "two --exhaustive runs over an unchanged corpus disagreed on what they scanned "
        f"once one of them ran slower:\\nfast: {fast.detail!r}\\nslow: {slow.detail!r}")
    # And this must be a REAL assertion, not two UNKNOWNs agreeing by having scanned
    # nothing — the plan must genuinely have left some of the 10 sinks out both times.
    assert "not scanned" in fast.detail


def test_the_skip_sentence_fires_and_the_affirmative_branch_does_not_when_bounded(
    tmp_path, monkeypatch
):
    """A determinism fix that quietly made --exhaustive claim completeness it doesn't
    have would be worse than the nondeterminism it replaces. When the plan genuinely
    truncates, the skip sentence must print and the F-164 SC-5 "All N scanned" branch
    must NOT — both directions checked in one real, bounded --exhaustive run.
    """
    from dataclasses import replace

    import clawseccheck.scanbudget as sb
    from clawseccheck.checks import check_log_threat_hunt
    from clawseccheck.collector import collect
    from clawseccheck.scanbudget import EXHAUSTIVE_LIMITS

    home = tmp_path / "home"
    sessions = home / "agents" / "main" / "sessions"
    sessions.mkdir(parents=True)
    (home / "openclaw.json").write_text("{}")
    for i in range(10):
        (sessions / f"s{i:03d}.trajectory.jsonl").write_text("x" * 20_000)

    test_limits = replace(EXHAUSTIVE_LIMITS, log_max_total_bytes=50_000)
    monkeypatch.setattr(sb, "limits_for", lambda _ctx: test_limits)

    ctx = collect(home)
    ctx.exhaustive = True
    finding = check_log_threat_hunt(ctx)

    assert "not scanned" in finding.detail
    assert "All 10 log/transcript sink(s) scanned." not in finding.detail
    assert "even --exhaustive's own" in finding.detail
    assert "re-run with --exhaustive" not in finding.detail
