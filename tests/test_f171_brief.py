"""F-171 — the session-start brief: is the watch still running, and did it speak?

Two problems, one mode.

The cheapest attack on a scheduled monitor is to stop it running. The attacker never
touches the baseline or the journal — they remove the schedule — and nothing anywhere says
so. And an alert is written to the journal once, so if nobody was looking at that moment
the signal effectively never existed.

**The load-bearing property is that `--brief` writes nothing.** Not as an optimisation: it
is what lets SKILL.md have the agent run this at session start with no consent prompt. The
consent rule covers `--monitor`, which writes. If this mode ever gains a write, that
instruction becomes wrong and the user is being surprised.

**The thresholds are measured, not chosen.** On the maintainer's real history the gap
between consecutive real runs has a median near zero, a p90 of 0.07 days and a maximum of
1.90 days — so 3 days sits above every gap actually observed, and crossing it means
something stopped rather than that the schedule is sparse.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta

from clawseccheck.cli import main
from clawseccheck.report import render_brief

_NOW = datetime(2026, 8, 11, 12, 0, 0)


def _iso(days_ago: float) -> str:
    return (_NOW - timedelta(days=days_ago)).isoformat(timespec="seconds")


def _event(level: str, days_ago: float) -> dict:
    return {"level": level, "message": "something moved", "ts": _iso(days_ago)}


# ---------------------------------------------------------------- writes nothing

def test_brief_writes_nothing_at_all(tmp_path, capsys):
    """THE test. Every file's size and mtime must be unchanged and no file may appear —
    because SKILL.md tells the agent to run this without asking the user first."""
    store = tmp_path / "store"
    store.mkdir()
    (store / "state.json").write_text(json.dumps({"ts": _iso(1), "checks": {}}),
                                      encoding="utf-8")
    (store / "events.jsonl").write_text(json.dumps(_event("HIGH", 2)) + "\n",
                                        encoding="utf-8")
    (store / "history.jsonl").write_text(
        json.dumps({"ts": _iso(1), "date": "2026-08-10", "score": 90, "grade": "A",
                    "source": "audit"}) + "\n", encoding="utf-8")
    for f in store.iterdir():
        os.chmod(f, 0o600)

    def _fingerprint():
        return {p.name: (p.stat().st_size, p.stat().st_mtime_ns)
                for p in sorted(store.iterdir())}

    before = _fingerprint()
    rc = main(["--brief", "--data-dir", str(store), "--home", str(tmp_path / "nohome")])
    capsys.readouterr()
    assert rc == 0
    assert _fingerprint() == before, "a file was written, resized or touched"
    assert {p.name for p in store.iterdir()} == set(before), "a new file appeared"


def test_brief_creates_no_store_when_none_exists(tmp_path, capsys):
    """The absent-everything case must stay absent — a session-start check that creates the
    thing it is checking would report health it manufactured."""
    store = tmp_path / "nothing-here"
    main(["--brief", "--data-dir", str(store), "--home", str(tmp_path / "nohome")])
    capsys.readouterr()
    assert not store.exists()


# ---------------------------------------------------------------- liveness

def test_no_baseline_says_nothing_is_watching():
    out = render_brief(None, [], [], now=_NOW)
    assert "Nothing is watching" in out
    assert "--monitor" in out


def test_a_fresh_check_reads_as_fresh():
    out = render_brief({"ts": _iso(0.02)}, [], [], now=_NOW)
    assert "Last drift check" in out
    assert "longer than" not in out
    assert "not running" not in out


def test_silence_past_the_measured_gap_asks_about_the_schedule():
    """Three days is above the 1.90-day maximum gap observed on a real machine, so this
    tier means something stopped rather than that checks are merely infrequent."""
    out = render_brief({"ts": _iso(5)}, [], [], now=_NOW)
    assert "longer than" in out
    assert "not running" not in out, "5 days is stale, not dead"


def test_long_silence_says_monitoring_is_not_running():
    out = render_brief({"ts": _iso(20)}, [], [], now=_NOW)
    assert "effectively not running" in out
    assert "cheapest way to silence a monitor" in out


def test_the_ladder_boundaries_are_the_measured_ones():
    from clawseccheck.report import _BRIEF_DEAD_DAYS, _BRIEF_STALE_DAYS
    assert _BRIEF_STALE_DAYS == 3.0 and _BRIEF_DEAD_DAYS == 14.0
    assert "longer than" not in render_brief({"ts": _iso(2.9)}, [], [], now=_NOW)
    assert "longer than" in render_brief({"ts": _iso(3.1)}, [], [], now=_NOW)
    assert "not running" not in render_brief({"ts": _iso(13.9)}, [], [], now=_NOW)
    assert "not running" in render_brief({"ts": _iso(14.1)}, [], [], now=_NOW)


def test_a_baseline_without_a_timestamp_falls_back_to_the_file_time_and_says_so():
    """The real state of the maintainer's own machine: a baseline written before run
    timestamps existed. A file's write time is not a record of a run, and presenting it as
    one would be inventing precision this tool does not have."""
    out = render_brief({"checks": {}}, [], [], now=_NOW, state_mtime_iso=_iso(7))
    assert "file time" in out
    assert "predates run timestamps" in out


def test_a_baseline_with_neither_timestamp_nor_file_time_admits_it():
    out = render_brief({"checks": {}}, [], [], now=_NOW)
    assert "cannot be determined" in out


# ---------------------------------------------------------------- the journal

def test_serious_events_are_surfaced_with_their_age():
    out = render_brief({"ts": _iso(0.1)},
                       [_event("CRITICAL", 5), _event("HIGH", 2), _event("MEDIUM", 1)],
                       [], now=_NOW)
    assert "2 CRITICAL-or-worse event(s)" in out
    assert "oldest 5d ago" in out
    assert "--watch-log" in out


def test_it_says_recorded_rather_than_unacknowledged():
    """Whether a human read an alert is not something this tool can observe. Saying
    "unacknowledged" would be a claim about the user's attention rather than the
    evidence — the shape of overreach this whole epic has been removing."""
    out = render_brief({"ts": _iso(0.1)}, [_event("CRITICAL", 1)], [], now=_NOW)
    assert "recorded" in out
    assert "unacknowledged" not in out.lower()


def test_a_quiet_journal_is_reported_without_alarm():
    out = render_brief({"ts": _iso(0.1)}, [_event("MEDIUM", 1), _event("INFO", 1)],
                       [], now=_NOW)
    assert "none above MEDIUM" in out
    assert "CRITICAL" not in out


def test_events_survive_a_run_that_produced_none():
    """Carry-forward: the journal is cumulative, so a quiet run does not erase what an
    earlier one recorded. An alert seen once and forgotten is an alert that never
    happened."""
    out = render_brief({"ts": _iso(0.01)}, [_event("CRITICAL", 9)], [], now=_NOW)
    assert "CRITICAL-or-worse" in out


def test_an_undated_event_does_not_break_the_age_line():
    out = render_brief({"ts": _iso(0.1)}, [{"level": "HIGH", "message": "x"}], [], now=_NOW)
    assert "HIGH-or-worse event(s)" in out
    assert "oldest" not in out, "no date means no age claim"


# ---------------------------------------------------------------- history provenance

def test_a_history_of_only_test_rows_is_called_out():
    """Measured on the real file: 4,414 of 4,576 rows carry source "test". Counting those
    as evidence a check ran would report a fixture run as a live one."""
    rows = [{"ts": _iso(1), "score": 90, "grade": "A", "source": "test"}]
    out = render_brief({"ts": _iso(1)}, [], rows, now=_NOW)
    assert "only test runs" in out


def test_a_history_with_real_rows_says_nothing_about_provenance():
    rows = [{"ts": _iso(1), "score": 90, "grade": "A", "source": "test"},
            {"ts": _iso(1), "score": 90, "grade": "A", "source": "audit"}]
    assert "only test runs" not in render_brief({"ts": _iso(1)}, [], rows, now=_NOW)


# ---------------------------------------------------------------- shape

def test_it_stays_within_five_lines():
    """A session-start line the agent prints before every conversation earns its length."""
    out = render_brief({"ts": _iso(20)},
                       [_event("CRITICAL", 9), _event("HIGH", 3)],
                       [{"ts": _iso(1), "source": "test"}], now=_NOW)
    assert 1 <= len(out.strip().splitlines()) <= 5


def test_ascii_mode_leaves_no_unicode():
    render_brief({"ts": _iso(20)}, [_event("CRITICAL", 9)], [],
                 now=_NOW, ascii_only=True).encode("ascii")


def test_the_empty_world_says_so_rather_than_implying_health():
    out = render_brief(None, [], [], now=_NOW)
    assert "Nothing is watching" in out
    assert "ok" not in out.lower() and "fine" not in out.lower()
