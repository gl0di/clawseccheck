"""B-484 — B164 must choose WHICH log sinks it scans, deterministically and by risk.

## The bug

`check_log_threat_hunt` walked `discover_log_sinks`' order until a wall clock ran out.
Two consequences, both measured on a real 132-sink corpus:

* the covered slice was **arbitrary** — discovery returns lexicographic order and session
  filenames are UUIDs, so which third of the corpus got read was effectively random. A
  threat in yesterday's session was scanned only by luck of its UUID;
* the covered slice was **unstable** — the cutoff was elapsed time, so two consecutive
  runs over an unchanged corpus scanned 38 and then 41 sinks. B164's verdict was not
  reproducible, and the skipped count embedded in its own `detail` drifted with it.

## The fix

`_plan_log_hunt_sinks` picks the set up front from `(kind, mtime, size, path)` — cheap
stat() metadata now carried on `LogSink` — inside `ScanLimits.log_max_total_bytes`. The
clock stays, as a backstop rather than as the decider.

Measured on the real 132-sink corpus, final revision (oldest-reserve, per-file-capped
costing, 9 MiB budget). Earlier drafts of this docstring quoted numbers from builds that
no longer replayed — this project treats that as a Golden Rule #4 problem, not a stale
comment, so re-measure rather than edit around it:

    default:      41/132, nondeterministic, 4.51s  ->  53/132, deterministic, 3.16s

`--exhaustive` is NOT fixed by this change and is not claimed to be. It is bound by
`EXHAUSTIVE_LIMITS.log_check_budget_s = 60.0`, not by bytes, and lands anywhere from
118/132 to 132/132 depending only on how fast the box is that minute (observed: 126/132 at
60.02s before, then 132/132 at 56.42s and 118/132 at 60.03s after). Raising that ceiling
cascades into `check_budget_s`/`audit_budget_s` and is a separate, separately-measured
task — so the exhaustive path keeps the very nondeterminism the default path just lost.

Coverage is only *partially* fixed and this file does not pretend otherwise: the byte
budget is absolute, so the covered FRACTION still falls as a fleet grows. What is fixed
is that the uncovered tail is bounded and stable rather than arbitrary, and that the set
is the same every run.

## What must NOT regress

`tests/test_b314_check_perf.py::TestLogThreatHuntCumulativeBudget` builds `LogSink(...)`
positionally with three arguments, so its sinks carry `size == 0`. The planner treats 0 as
"unknown cost, admit it" precisely so that test still exercises the clock backstop it was
written for — see `test_unknown_size_is_admitted_and_left_to_the_clock`.
"""
from __future__ import annotations

import re
from dataclasses import replace

from clawseccheck.checks._egress import (
    _LOG_HUNT_OLDEST_RESERVE,
    _LOG_SINK_KIND_RANK,
    _plan_log_hunt_sinks,
)
from clawseccheck.logdiscovery import LogSink
from clawseccheck.scanbudget import DEFAULT_LIMITS, EXHAUSTIVE_LIMITS

_MIB = 1024 * 1024


def _sink(name: str, *, kind: str = "trajectory", size: int = 0, mtime: float = 0.0) -> LogSink:
    return LogSink(path=name, kind=kind, source="convention", size=size, mtime=mtime)


def _limits(total_bytes: int):
    return replace(DEFAULT_LIMITS, log_max_total_bytes=total_bytes)


# ------------------------------------------------------------------------ determinism


def test_plan_is_deterministic():
    """The whole point: same corpus in, same set out, every time."""
    sinks = [_sink(f"s{i}", size=_MIB, mtime=float(i % 7)) for i in range(40)]
    lim = _limits(10 * _MIB)
    first = [s.path for s in _plan_log_hunt_sinks(sinks, lim)[0]]
    for _ in range(4):
        assert [s.path for s in _plan_log_hunt_sinks(sinks, lim)[0]] == first


def test_equal_mtimes_are_broken_by_path_not_by_input_order():
    """A tie must not let discovery order leak back in as the decider."""
    a = [_sink("b", size=_MIB), _sink("a", size=_MIB), _sink("c", size=_MIB)]
    b = list(reversed(a))
    lim = _limits(10 * _MIB)
    assert [s.path for s in _plan_log_hunt_sinks(a, lim)[0]] == ["a", "b", "c"]
    assert [s.path for s in _plan_log_hunt_sinks(b, lim)[0]] == ["a", "b", "c"]


# ----------------------------------------------------------------------------- order


def test_plan_orders_newest_first():
    sinks = [_sink(f"s{i}", size=_MIB, mtime=float(i)) for i in range(5)]
    admitted, _ = _plan_log_hunt_sinks(sinks, _limits(10 * _MIB))
    assert [s.path for s in admitted] == ["s4", "s3", "s2", "s1", "s0"]


def test_singleton_kinds_rank_ahead_of_trajectory():
    """The cheap, high-signal singletons must survive a corpus that exhausts the budget.

    They are one file each; a trajectory corpus is hundreds. Ranking them behind it would
    let a big enough corpus push the config-audit log out entirely.
    """
    sinks = [_sink(f"t{i}", size=4 * _MIB, mtime=99.0) for i in range(5)]
    sinks.append(_sink("audit", kind="config_audit", size=_MIB, mtime=0.0))
    admitted, _ = _plan_log_hunt_sinks(sinks, _limits(6 * _MIB))
    assert "audit" in [s.path for s in admitted]
    assert admitted[0].path == "audit"


def test_every_known_kind_has_a_rank():
    """A kind logdiscovery can emit but the rank table forgot would sort last silently."""
    documented = {
        "trajectory", "config_log", "cache_trace",
        "transcript", "config_audit", "memory", "backup",
    }
    assert documented <= set(_LOG_SINK_KIND_RANK)


def test_unknown_kind_sorts_last_and_does_not_raise():
    sinks = [_sink("weird", kind="brand_new_kind", size=_MIB), _sink("traj", size=_MIB)]
    admitted, _ = _plan_log_hunt_sinks(sinks, _limits(10 * _MIB))
    assert [s.path for s in admitted] == ["traj", "weird"]


# ---------------------------------------------------------------------------- filling


def test_oversized_old_sink_does_not_starve_small_recent_ones():
    """Skip-and-continue, not a strict prefix: one huge sink must not shut the door.

    Note what "huge" costs: a sink is billed `min(size, log_max_bytes_per_file)`, so the
    100 MiB file below is charged the 2 MiB cap and IS admitted. An earlier draft asserted
    it was excluded — that assertion encoded the old, wrong accounting, in which a big file
    was unreachable at every mtime (a C-135 finding). What matters here is that admitting
    it does not cost the five small ones their place.
    """
    sinks = [_sink("huge", size=100 * _MIB, mtime=50.0)]
    sinks += [_sink(f"small{i}", size=_MIB, mtime=float(i)) for i in range(5)]
    admitted, planned_out = _plan_log_hunt_sinks(sinks, _limits(8 * _MIB))
    paths = [s.path for s in admitted]
    assert {f"small{i}" for i in range(5)} <= set(paths)
    assert planned_out == 0


def test_a_single_giant_sink_cannot_consume_the_whole_budget():
    """The cost cap must not become a way for one file to eat everything: charged at the
    per-file cap, one sink can never cost more than that cap however large it is."""
    sinks = [_sink("giant", size=10_000 * _MIB, mtime=9999.0)]
    sinks += [_sink(f"s{i}", size=_MIB, mtime=float(i)) for i in range(6)]
    admitted, _ = _plan_log_hunt_sinks(sinks, _limits(8 * _MIB))
    assert "giant" in [s.path for s in admitted]
    assert len([s for s in admitted if s.path.startswith("s")]) >= 5


def test_planned_out_count_is_returned():
    sinks = [_sink(f"s{i}", size=4 * _MIB, mtime=float(i)) for i in range(10)]
    admitted, planned_out = _plan_log_hunt_sinks(sinks, _limits(10 * _MIB))
    assert len(admitted) + planned_out == 10
    assert planned_out > 0


def test_unknown_size_is_admitted_and_left_to_the_clock():
    """size == 0 means "not stat()ed", not "free" — planning it out would silently drop
    it. This is what keeps test_b314_check_perf's hand-built sinks working."""
    sinks = [_sink(f"s{i}") for i in range(50)]  # every size == 0
    admitted, planned_out = _plan_log_hunt_sinks(sinks, _limits(1))
    assert len(admitted) == 50
    assert planned_out == 0


def test_exhaustive_admits_everything():
    sinks = [_sink(f"s{i}", size=64 * _MIB, mtime=float(i)) for i in range(20)]
    admitted, planned_out = _plan_log_hunt_sinks(sinks, EXHAUSTIVE_LIMITS)
    assert len(admitted) == 20
    assert planned_out == 0


def test_absent_or_zero_budget_admits_everything_in_order():
    """Defensive: a limits object without the field (or with 0) must not plan everything
    out — it must degrade to "ordered, unbounded", never to "scan nothing"."""
    sinks = [_sink(f"s{i}", size=_MIB, mtime=float(i)) for i in range(4)]
    admitted, planned_out = _plan_log_hunt_sinks(sinks, _limits(0))
    assert [s.path for s in admitted] == ["s3", "s2", "s1", "s0"]
    assert planned_out == 0


# ------------------------------------------------- C-135: no safe mtime for an attacker


def _corpus_with_evidence(evidence_name: str, evidence_mtime: float) -> list:
    """20 same-sized recent decoys plus one evidence sink the attacker has positioned."""
    sinks = [_sink(f"n{i:03d}", size=_MIB, mtime=2_000_000_000.0) for i in range(20)]
    sinks.append(_sink(evidence_name, size=_MIB, mtime=evidence_mtime))
    return sinks


def test_backdating_a_sink_does_not_hide_it():
    """The C-135 finding this design round produced, pinned.

    Ordering newest-first, on its own, handed an attacker a one-call exclusion lever the
    old lexicographic order did not have: `os.utime` a sink into the past and it falls
    behind the whole corpus, out of the byte budget. Measured before the oldest-reserve
    existed: the old order read a backdated evidence sink and a pure-recency plan did not.

    The reserve is what makes every mtime unsafe to pick, so this must keep passing.
    """
    sinks = _corpus_with_evidence("evidence", 1_000_000.0)  # far in the past
    admitted, _ = _plan_log_hunt_sinks(sinks, _limits(10 * _MIB))
    assert "evidence" in [s.path for s in admitted]


def test_sorting_last_by_name_does_not_hide_it_either():
    """The filename lever survives as the mtime tiebreak, so the reserve must cover it
    too — otherwise the change would merely swap one evasion for another."""
    sinks = _corpus_with_evidence("zzz-evidence", 2_000_000_000.0)  # ties with the decoys
    admitted, _ = _plan_log_hunt_sinks(sinks, _limits(10 * _MIB))
    assert "zzz-evidence" in [s.path for s in admitted]


def test_a_sink_larger_than_the_whole_budget_is_still_admittable():
    """C-135 regression guard. The planner used to charge a sink's FULL size, while
    `scan_log_file` never reads past `log_max_bytes_per_file`. A 64 MiB sink was therefore
    billed 32x its real cost, which put every sink bigger than the total budget out of
    reach at EVERY mtime and in BOTH passes — a lever needing no corpus knowledge at all,
    just `>> logfile` until it crosses a public shipped constant.
    """
    for size_mib in (4, 8, 16, 64):
        sinks = [_sink("evidence", size=size_mib * _MIB, mtime=0.0)]
        sinks += [_sink(f"d{i}", size=_MIB, mtime=100.0 + i) for i in range(20)]
        admitted, _ = _plan_log_hunt_sinks(sinks, DEFAULT_LIMITS)
        assert "evidence" in [s.path for s in admitted], f"{size_mib} MiB sink unreachable"


def test_reserve_reaches_an_old_trajectory_past_a_wall_of_backups():
    """C-135 regression guard. The reserve pass used to walk `reversed(ordered)`, and
    `ordered` is sorted by KIND rank first — so it consumed the whole last kind before
    reaching an old sidecar. On any home with an install-backup directory the reserve was
    spent entirely on backups and the backdating lever came straight back.
    """
    sinks = [_sink("evidence", size=_MIB, mtime=0.0)]
    sinks += [_sink(f"t{i}", size=_MIB, mtime=9000.0 + i) for i in range(20)]
    sinks += [_sink(f"bak{i}", kind="backup", size=_MIB, mtime=50.0 + i) for i in range(20)]
    admitted, _ = _plan_log_hunt_sinks(sinks, DEFAULT_LIMITS)
    assert "evidence" in [s.path for s in admitted]


def test_reserve_can_always_afford_at_least_one_sink():
    """C-135 regression guard. `reserve = int(budget * fraction)` guarantees BYTES, never
    a sink: with uniformly large sinks the reserve admitted zero and the oldest-first
    guarantee silently did not hold.

    It holds today only because the reserve share is >= the per-file cap, which bounds
    what any single sink can cost. That is a relationship between two constants in
    different modules, so it is pinned here rather than left to coincidence.
    """
    reserve_bytes = int(DEFAULT_LIMITS.log_max_total_bytes * _LOG_HUNT_OLDEST_RESERVE)
    assert reserve_bytes >= DEFAULT_LIMITS.log_max_bytes_per_file

    for size_mib in (2.1, 3, 4, 6, 12, 64):
        sinks = [_sink("evidence", size=int(size_mib * _MIB), mtime=0.0)]
        sinks += [
            _sink(f"d{i}", size=int(size_mib * _MIB), mtime=9000.0 + i) for i in range(20)
        ]
        admitted, _ = _plan_log_hunt_sinks(sinks, DEFAULT_LIMITS)
        assert "evidence" in [s.path for s in admitted], f"starved at {size_mib} MiB"


def test_reserve_does_not_swallow_the_recent_pool():
    """The reserve is a minority share. If it ever grew to dominate, B164 would be reading
    the corpus an attacker is least likely to be writing to right now."""
    sinks = [_sink(f"s{i:03d}", size=_MIB, mtime=float(i)) for i in range(40)]
    admitted, _ = _plan_log_hunt_sinks(sinks, _limits(10 * _MIB))
    newest_half = {f"s{i:03d}" for i in range(20, 40)}
    from_recent = sum(1 for s in admitted if s.path in newest_half)
    assert from_recent > len(admitted) // 2


def test_admitted_order_is_newest_first_so_the_clock_cuts_the_reserve():
    """The scan loop still consumes the plan in order, and the wall clock can still fire.
    If it does, it must eat into the oldest reserve — not into the recent pool."""
    sinks = [_sink(f"s{i:03d}", size=_MIB, mtime=float(i)) for i in range(40)]
    admitted, _ = _plan_log_hunt_sinks(sinks, _limits(10 * _MIB))
    mtimes = [s.mtime for s in admitted]
    assert mtimes == sorted(mtimes, reverse=True)


# ------------------------------------------------------------------------- disclosure


def test_planned_out_sinks_are_disclosed_and_name_the_real_remedy(tmp_path, monkeypatch):
    """Golden Rule #4: no silent caps. And the remedy named must be a true one.

    The pre-B-484 sentence ended "re-run to include them", which was only true while the
    cutoff was the wall clock. Under a deterministic plan a plain re-run skips exactly the
    same sinks, so that wording would now be a lie.

    The byte budget is shrunk rather than the corpus inflated: forcing the real 12 MiB
    default to bind would mean writing and then actually scanning >12 MiB inside a unit
    test. This drives the same code path on a corpus small enough to stay fast.
    """
    import clawseccheck.scanbudget as sb
    from clawseccheck.checks import check_log_threat_hunt
    from clawseccheck.collector import collect

    home = tmp_path / "home"
    sessions = home / "agents" / "main" / "sessions"
    sessions.mkdir(parents=True)
    (home / "openclaw.json").write_text("{}")
    for i in range(10):
        (sessions / f"s{i:03d}.trajectory.jsonl").write_text("x" * 50_000)

    tiny = replace(DEFAULT_LIMITS, log_max_total_bytes=120_000)
    monkeypatch.setattr(sb, "limits_for", lambda _ctx: tiny)

    ctx = collect(home)
    finding = check_log_threat_hunt(ctx)

    assert "not scanned" in finding.detail
    assert "--exhaustive" in finding.detail
    assert "the oldest are left out first" in finding.detail
    assert "reached) — re-run to include them" not in finding.detail


def _tiny_budget_home(tmp_path, monkeypatch, *, count, content, budget):
    import clawseccheck.scanbudget as sb
    from clawseccheck.collector import collect

    home = tmp_path / "home"
    sessions = home / "agents" / "main" / "sessions"
    sessions.mkdir(parents=True)
    (home / "openclaw.json").write_text("{}")
    for i in range(count):
        (sessions / f"s{i:03d}.trajectory.jsonl").write_text(content)
    monkeypatch.setattr(
        sb, "limits_for", lambda _ctx: replace(DEFAULT_LIMITS, log_max_total_bytes=budget)
    )
    return collect(home)


def test_counts_reconcile_and_are_never_negative(tmp_path, monkeypatch):
    """C-135 regression guard: scanned + not-scanned must equal discovered.

    The first cut of this change rebound `sinks` to the ADMITTED list, while
    `skipped_for_time` counted the sinks planned OUT of the discovered set. The roll-up
    then computed `len(sinks) - skipped_for_time` across two different denominators and
    printed a literal "-2 log/transcript sink(s) scanned" to the user.
    """
    from clawseccheck.checks import check_log_threat_hunt

    ctx = _tiny_budget_home(
        tmp_path, monkeypatch, count=10,
        content='{"role":"user","content":"hi"}\n' * 800, budget=120_000,
    )
    detail = check_log_threat_hunt(ctx).detail

    scanned = re.search(r"(-?\d+) log/transcript sink\(s\) scanned", detail)
    not_scanned = re.search(r"(\d+) log/transcript sinks? not scanned", detail)
    assert scanned and not_scanned, detail
    assert int(scanned.group(1)) >= 0, f"negative scanned count: {detail}"
    assert int(scanned.group(1)) + int(not_scanned.group(1)) == 10


def test_planning_everything_out_is_disclosed_not_blamed_on_permissions(tmp_path, monkeypatch):
    """C-135 regression guard: the none-readable early return happens BEFORE the normal
    disclosure block, so it has to carry the truncation itself.

    It previously reported "0 log/transcript sink(s) found but none were readable" for a
    corpus of ten present, readable files that the byte budget had simply declined to
    offer — a lying UNKNOWN that blamed file permissions, and a silent cap.
    """
    from clawseccheck.checks import check_log_threat_hunt

    ctx = _tiny_budget_home(
        tmp_path, monkeypatch, count=10, content="x" * 50_000, budget=1000,
    )
    finding = check_log_threat_hunt(ctx)

    assert finding.status == "UNKNOWN"
    assert "10 log/transcript sink(s) found" in finding.detail
    assert "not offered to the scan" in finding.detail
    assert "--exhaustive" in finding.detail


def test_default_budget_is_calibrated_under_the_check_budget():
    """The two constants are a pair: a byte budget that cannot be scanned inside
    `log_check_budget_s` hands the set back to the clock and undoes this whole change.

    Pinned as a relationship, not as a throughput number — measured throughput is
    machine-specific and does not belong in an assertion. ~2.9 MiB/s on the reference box
    put 12 MiB at 3.82s of the 4.5s share; this guard fails if a future edit raises the
    bytes without raising the seconds.
    """
    assert DEFAULT_LIMITS.log_max_total_bytes < EXHAUSTIVE_LIMITS.log_max_total_bytes
    generous_mib_per_s = 4.0
    projected_s = (DEFAULT_LIMITS.log_max_total_bytes / _MIB) / generous_mib_per_s
    assert projected_s < DEFAULT_LIMITS.log_check_budget_s
