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
from clawseccheck.history import DEFAULT_TREND_WINDOW, HistoryRows, render_trend
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


def _with_subject(row: dict) -> dict:
    """B-695: `_row()`'s default home/raw_scope/raw_ver are None -- not comparable to
    anything (see `test_pinned_and_compounded_fall_counts_are_not_narrowed_by_the_window`,
    which already does this for the same reason). Tests that need a real arrow, not a
    blank one, route their rows through this."""
    return {**row, "home": "~/.openclaw", "raw_scope": "scope-a", "raw_ver": "4.0.0"}


def test_a_windowed_rows_arrow_still_compares_against_a_row_outside_the_window():
    """The arrow on the FIRST visible row must reflect the true previous graded row,
    even though that row itself is never printed."""
    rows = [_with_subject(_row(i, score=10)) for i in range(40)]  # rows 0..39, all score 10
    rows[39] = _with_subject(_row(39, score=99))  # only the newest row differs
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
# CLAWSECCHECK-B-847 — real goldens against the actual pre-C-448 output.
#
# The two "byte for byte" tests above (`test_all_none_reproduces_the_unwindowed_...`)
# compare `window=None` against `window=10_000` — both go through the SAME post-C-448
# code, so they pass even if that code drifted from what this tool printed before
# C-448 existed. It had: `render_events`' retention-marker header unconditionally
# switched " — " to "; ", which changed the --all output whenever a retention marker
# is present (the real-machine case, a rotated journal) — reproduced below against a
# golden captured by literally running the pre-C-448 code (commit b0057c8^) against
# this exact fixture. `render_trend`'s six disclosure sentences (plus the B-580
# retention notice, folded in under this same fix) were ALSO reworded, unconditionally,
# by the same commit — kept as a deliberate improvement rather than reverted (see the
# `window` note on `render_trend`), so its golden pins the NEW wording and asserts the
# OLD wording is gone, rather than asserting equality with the pre-C-448 text.
# --------------------------------------------------------------------------------------

# Captured by running clawseccheck.report.render_events from commit b0057c8^ (the
# parent of the C-448 commit) against the exact events fixture built below.
_EVENTS_PRE_C448_GOLDEN = (
    "Agent Watch journal\n" + "=" * 30 + "\n"
    "showing 20 event(s) (most recent last) — 500 older entries were pruned by "
    "retention at 2026-08-01T00:00:00.:\n\n"
    + "\n".join(
        f"ℹ️ 2026-08-{(i % 28) + 1:02d}T00:00:00  event {i}" for i in range(20)
    )
    + "\n"
)


def test_events_all_reproduces_pre_c448_output_byte_for_byte_with_retention_marker():
    """B-847 item 1+4: --all with a retention marker present (never covered before) must
    reproduce the actual pre-C-448 bytes, not just today's own window=None/10_000 pair."""
    marker = {"ts": "2026-08-01T00:00:00", "level": "INFO",
              "message": "500 older entries were pruned by retention at "
                         "2026-08-01T00:00:00.",
              "retention_pruned": 500}
    events = [marker] + [_event(i) for i in range(20)]
    out = render_events(events, window=None)  # window=None is what --all passes
    assert out == _EVENTS_PRE_C448_GOLDEN


# Captured the same way, from clawseccheck.history.render_trend on b0057c8^ -- with the
# arrow column blanked by hand for B-695 (landed after C-448, not before it): `_row()`'s
# shape carries no home/raw_scope/raw_ver, so none of these ten rows is comparable to its
# predecessor any more, and the flat glyph the pre-C-448 code printed on every one of them
# (score is 70 throughout) is exactly the claim B-695 stopped this renderer from making.
# This golden is still about C-448 -- it pins that the WINDOW change left these lines
# alone -- so it is kept in step with B-695 rather than read as contradicting it.
_TREND_PRE_C448_ROW_LINES = [
    f"2026-{(i % 12) + 1:02d}-{(i % 28) + 1:02d}T10:00:{i % 60:02d}  C  70    [audit]"
    for i in range(10)
]


def test_trend_all_row_lines_match_pre_c448_output_byte_for_byte():
    """The per-row lines themselves are untouched by C-448 (only the trailing
    lines.append() is gated on the window) — pin that against the real old output,
    adjusted for B-695's later, separate and intentional change to the arrow column."""
    rows = [_row(i) for i in range(10)]
    out = render_trend(rows, window=None)
    row_lines = [ln for ln in out.splitlines() if ln.startswith("2026-")]
    assert row_lines == _TREND_PRE_C448_ROW_LINES


def test_trend_all_does_not_revert_the_reworded_disclosure_sentences():
    """B-847 item 2+3: the six reworded sentences (plus the B-580 retention notice) are
    a deliberate, permanent correctness fix, not something --all should undo — reverting
    them under --all would make the sentences' truth depend on which flag was passed.
    This pins that they stay reworded even when window=None, and that the stale
    pre-C-448 phrasing they replaced does not reappear."""
    rows = HistoryRows(_row(i) for i in range(5))
    rows.retention_notice = ("1001 older entries were pruned by retention at "
                              "2026-08-01T00:00:00.")
    rows.retention_pruned = 1001
    out = render_trend(rows, window=None)
    # New wording present...
    assert "4 runs in this history were not compared against" in out
    assert "on those runs is not evidence" in out
    assert "already dropped some of what it recorded: 1001 older entries" in out
    # ...and the stale pre-C-448 phrasing it replaced is gone.
    assert "runs above" not in out
    assert "shown above" not in out
    assert "on those lines" not in out
    assert "Not every recorded run is above" not in out


def test_trend_retention_notice_and_window_coexist_without_the_stale_above_claim():
    """B-847 item 5: a real fleet history is windowed by default AND can carry a B-580
    retention notice at the same time. The old notice text ("Not every recorded run is
    above: N older entries...") named only the pruned count as the reason a run might
    not be on screen — false the moment a `window` is also hiding recorded (loaded)
    rows. The reworded notice must not repeat that "above" framing."""
    rows = HistoryRows(_row(i) for i in range(40))
    rows.retention_notice = ("1001 older entries were pruned by retention at "
                              "2026-08-01T00:00:00.")
    rows.retention_pruned = 1001
    out = render_trend(rows)  # default window (30), NOT --all
    assert "older run(s) not shown here" in out  # the window disclosure fires too
    assert "already dropped some of what it recorded: 1001 older entries" in out
    assert "Not every recorded run is above" not in out


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
