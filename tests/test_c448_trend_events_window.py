"""CLAWSECCHECK-C-448 — `--trend` and `--watch-log` used to print the WHOLE store
unbounded (4,609 lines / 182 KB measured on a real machine) into what is usually a chat
channel. Both now default to a recency window, state what is not shown (never silently),
and keep every summary statistic (the ungraded ratio, the arrows, the pass-rate-fall
counts) computed over the FULL history regardless of the window — narrowing THOSE would
be the deleted source/grade filter (see history.render_trend's own design note)
returning under a new axis, which is the "tempting wrong fix" this task's own body
warns against.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from clawseccheck.cli import main
from clawseccheck.history import DEFAULT_TREND_WINDOW, render_trend
from clawseccheck.report import DEFAULT_EVENTS_WINDOW, render_events


def _row(i: int, *, score: int = 70) -> dict:
    return {"date": f"2026-{(i % 12) + 1:02d}-{(i % 28) + 1:02d}",
            "ts": f"2026-{(i % 12) + 1:02d}-{(i % 28) + 1:02d}T10:00:{i % 60:02d}",
            "score": score, "grade": "C", "graded": True, "source": "audit",
            "home": None, "raw_score": None, "raw_scope": None, "raw_ver": None}


def _event(i: int) -> dict:
    return {"ts": f"2026-08-{(i % 28) + 1:02d}T00:00:00", "level": "INFO",
            "message": f"event {i}"}


# --------------------------------------------------------------------------------------
# render_trend
# --------------------------------------------------------------------------------------

def test_default_window_caps_output_and_states_the_hidden_count():
    rows = [_row(i) for i in range(50)]
    out = render_trend(rows)
    shown_lines = [ln for ln in out.splitlines() if ln.startswith("2026-")]
    assert len(shown_lines) == DEFAULT_TREND_WINDOW
    assert f"Showing the last {DEFAULT_TREND_WINDOW} of 50 run(s)" in out
    assert "20 older run(s) not shown here" in out
    assert "pass --all" in out


def test_window_shows_the_most_recent_rows_not_the_oldest():
    rows = [_row(i, score=i) for i in range(50)]  # score == index, so identity is checkable
    out = render_trend(rows)
    # The newest 30 are indices 20..49 — the oldest shown score must be 20's.
    assert "  20  " in out
    assert "  19  " not in out
    assert "  49  " in out


def test_all_none_reproduces_the_unwindowed_output_byte_for_byte():
    rows = [_row(i) for i in range(50)]
    windowed_off = render_trend(rows, window=None)
    explicit_wide = render_trend(rows, window=10_000)  # wider than the row count
    assert windowed_off == explicit_wide
    assert "Showing the last" not in windowed_off
    shown_lines = [ln for ln in windowed_off.splitlines() if ln.startswith("2026-")]
    assert len(shown_lines) == 50


def test_a_history_at_or_under_the_window_gets_no_disclosure_line():
    rows = [_row(i) for i in range(DEFAULT_TREND_WINDOW)]
    out = render_trend(rows)
    assert "Showing the last" not in out
    shown_lines = [ln for ln in out.splitlines() if ln.startswith("2026-")]
    assert len(shown_lines) == DEFAULT_TREND_WINDOW


def test_a_windowed_rows_arrow_still_compares_against_a_row_outside_the_window():
    """The arrow on the FIRST visible row must reflect the true previous graded row,
    even though that row itself is never printed."""
    rows = [_row(i, score=10) for i in range(40)]  # rows 0..39, all score 10
    rows[39] = _row(39, score=99)  # only the newest row differs
    out = render_trend(rows, window=1)  # show only the single newest row
    line = next(ln for ln in out.splitlines() if ln.startswith("2026-"))
    assert "▲" in line, f"expected an up arrow comparing against the hidden prior row: {line}"


def test_the_ungraded_ratio_counts_holes_outside_the_window():
    """A hole in the OLDEST (hidden) part of the history must still be counted in the
    'N of M runs... have no grade' ratio — the window must not shrink the denominator."""
    rows = [_row(i) for i in range(40)]
    rows[0] = {**rows[0], "score": None, "grade": None, "graded": False}  # a hole, hidden
    out = render_trend(rows, window=5)  # far narrower than 40
    assert "1 of 40 runs in this history have no grade" in out


def test_pinned_and_compounded_fall_counts_are_not_narrowed_by_the_window():
    """Same principle, for the raw-pass-rate-fall counters — constructed via the public
    render_trend contract rather than reaching into its internals."""
    rows = []
    for i in range(40):
        r = _row(i, score=80)
        r["home"] = "~/.openclaw"  # _same_subject requires a real string, not None
        r["raw_score"] = 80
        r["raw_scope"] = "scope-a"
        r["raw_ver"] = "4.0.0"
        rows.append(r)
    # One hidden (old) row's raw pass-rate falls while the score is pinned (holds).
    rows[1]["raw_score"] = 40
    out = render_trend(rows, window=3)
    assert "1 run in this history kept or raised its score while the underlying " \
        "pass-rate fell" in out


# --------------------------------------------------------------------------------------
# render_events
# --------------------------------------------------------------------------------------

def test_events_default_window_caps_output_and_states_the_hidden_count():
    events = [_event(i) for i in range(80)]
    out = render_events(events)
    shown = [ln for ln in out.splitlines() if ln.startswith("ℹ️")]
    assert len(shown) == DEFAULT_EVENTS_WINDOW
    assert f"showing the last {DEFAULT_EVENTS_WINDOW} of 80 event(s)" in out
    assert "30 older event(s) not shown here" in out
    assert "pass --all" in out


def test_events_all_none_reproduces_the_unwindowed_output():
    events = [_event(i) for i in range(80)]
    windowed_off = render_events(events, window=None)
    explicit_wide = render_events(events, window=10_000)
    assert windowed_off == explicit_wide
    assert "older event(s) not shown" not in windowed_off


def test_events_window_and_retention_pruning_disclosures_coexist():
    marker = {"ts": "2026-08-01T00:00:00", "level": "INFO",
              "message": "500 older entries were pruned by retention at 2026-08-01T00:00:00.",
              "retention_pruned": 500}
    events = [marker] + [_event(i) for i in range(80)]
    out = render_events(events)
    assert "pruned by retention" in out
    assert "older event(s) not shown here" in out
    shown = [ln for ln in out.splitlines() if ln.startswith("ℹ️")]
    assert len(shown) == DEFAULT_EVENTS_WINDOW


# --------------------------------------------------------------------------------------
# CLI wiring
# --------------------------------------------------------------------------------------

def _write_history(path: Path, n: int) -> None:
    lines = [json.dumps(_row(i)) for i in range(n)]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def test_cli_trend_defaults_to_windowed(tmp_path, capsys):
    hist = tmp_path / "history.jsonl"
    _write_history(hist, 50)
    rc = main(["--trend", "--history", str(hist), "--no-native", "--no-host"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "older run(s) not shown here" in out


def test_cli_trend_all_prints_everything(tmp_path, capsys):
    hist = tmp_path / "history.jsonl"
    _write_history(hist, 50)
    rc = main(["--trend", "--all", "--history", str(hist), "--no-native", "--no-host"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "not shown here" not in out
    # 50 written + 1 "view" row --trend itself records = 51.
    shown = [ln for ln in out.splitlines() if ln.startswith("2026-")]
    assert len(shown) == 51


def test_cli_all_without_trend_or_watch_log_notes_no_effect(tmp_path, capsys):
    rc = main(["--all", "--home", str(Path(__file__).resolve().parent.parent
                                       / "fixtures" / "home_safe"),
              "--no-native", "--no-host", "--json"])
    err = capsys.readouterr().err
    assert rc == 0
    assert "--all has no effect without --trend or --watch-log" in err
