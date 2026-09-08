"""C-426: history.load() classifies rows into GRADED / UNGRADED instead of
KeyError-skipping, and history.render_trend() renders an ungraded row in
place (no arrow, "no grade") with a disclosure line when at least one hole
exists.

This task writes NO ungraded rows itself (record() is unchanged) — these
tests write the future on-disk row shape directly (as a later commit will)
to prove the two reader halves classify/render it correctly.

Offline; every test writes only under pytest's tmp_path.
"""
from __future__ import annotations

import json

from clawseccheck.history import load, render_trend


# ---------------------------------------------------------------------------
# load() classification
# ---------------------------------------------------------------------------

def test_ungraded_row_loads_with_none_score_and_grade(tmp_path):
    path = tmp_path / "history.jsonl"
    row = {"date": "2026-08-08", "ts": "2026-08-08T09:29:06", "home": None,
           "source": "audit", "graded": False, "_schema": 1}
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")

    rows = load(str(path))
    assert len(rows) == 1
    assert rows[0]["score"] is None
    assert rows[0]["grade"] is None
    assert rows[0]["graded"] is False


def test_graded_row_loads_exactly_as_before(tmp_path):
    path = tmp_path / "history.jsonl"
    row = {"date": "2026-08-01", "score": 81, "grade": "B", "ts": "2026-08-01T10:00:00",
           "home": "~/.openclaw", "source": "audit", "graded": True, "_schema": 1}
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")

    rows = load(str(path))
    assert len(rows) == 1
    assert rows[0]["score"] == 81
    assert rows[0]["grade"] == "B"
    assert rows[0]["graded"] is True


def test_retention_marker_shaped_row_still_skipped(tmp_path):
    """No 'date' at all — the C-250 retention marker shape."""
    path = tmp_path / "history.jsonl"
    marker = {"ts": "2026-08-01T00:00:00", "level": "INFO",
              "message": "pruned", "retention_pruned": 5, "_schema": 1}
    path.write_text(json.dumps(marker) + "\n", encoding="utf-8")

    rows = load(str(path))
    assert rows == []


def test_row_with_score_but_no_grade_still_skipped(tmp_path):
    path = tmp_path / "history.jsonl"
    path.write_text(
        json.dumps({"date": "2026-08-01", "score": 72}) + "\n"
        + json.dumps({"date": "2026-08-02", "score": 81, "grade": "B"}) + "\n",
        encoding="utf-8",
    )
    rows = load(str(path))
    assert len(rows) == 1
    assert rows[0]["date"] == "2026-08-02"


def test_row_with_grade_but_no_score_still_skipped(tmp_path):
    path = tmp_path / "history.jsonl"
    path.write_text(
        json.dumps({"date": "2026-08-01", "grade": "B"}) + "\n"
        + json.dumps({"date": "2026-08-02", "score": 81, "grade": "B"}) + "\n",
        encoding="utf-8",
    )
    rows = load(str(path))
    assert len(rows) == 1
    assert rows[0]["date"] == "2026-08-02"


def test_contradictory_graded_false_with_score_present_loads_as_ungraded(tmp_path):
    """An explicit "graded": false WINS over a present score — a contradictory
    row withholds rather than publishes."""
    path = tmp_path / "history.jsonl"
    row = {"date": "2026-08-01", "score": 90, "grade": "A", "graded": False, "_schema": 1}
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")

    rows = load(str(path))
    assert len(rows) == 1
    assert rows[0]["score"] is None
    assert rows[0]["grade"] is None
    assert rows[0]["graded"] is False


def test_legacy_row_no_graded_key_with_score_loads_as_graded(tmp_path):
    path = tmp_path / "history.jsonl"
    row = {"date": "2026-06-10", "score": 60, "grade": "D"}
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")

    rows = load(str(path))
    assert len(rows) == 1
    assert rows[0]["score"] == 60
    assert rows[0]["grade"] == "D"
    assert rows[0]["graded"] is True


def test_score_key_always_present_on_returned_rows(tmp_path):
    path = tmp_path / "history.jsonl"
    graded = {"date": "2026-08-01", "score": 72, "grade": "C"}
    ungraded = {"date": "2026-08-02", "graded": False}
    path.write_text(
        json.dumps(graded) + "\n" + json.dumps(ungraded) + "\n", encoding="utf-8",
    )
    rows = load(str(path))
    assert len(rows) == 2
    assert all("score" in r for r in rows)


# ---------------------------------------------------------------------------
# render_trend() — mixed graded/ungraded chains
# ---------------------------------------------------------------------------

def test_render_trend_mixed_chain_hole_has_no_arrow_and_next_compares_across_it():
    rows = [
        {"date": "2026-08-01", "score": 60, "grade": "D", "graded": True, "source": "audit"},
        {"date": "2026-08-02", "score": None, "grade": None, "graded": False, "source": "audit"},
        {"date": "2026-08-03", "score": 80, "grade": "B", "graded": True, "source": "audit"},
    ]
    out = render_trend(rows, ascii_only=False)

    assert "no grade" in out
    lines = out.splitlines()
    hole_line = next(ln for ln in lines if "2026-08-02" in ln)
    assert "no grade" in hole_line
    # No arrow character anywhere on the hole's own line.
    assert "▲" not in hole_line and "▼" not in hole_line and "·" not in hole_line

    # The graded row AFTER the hole (score 80) compares against the graded row
    # BEFORE it (score 60) — 80 > 60, so it must carry the "up" arrow.
    after_line = next(ln for ln in lines if "2026-08-03" in ln)
    assert "▲" in after_line


def test_render_trend_all_ungraded_does_not_crash_and_prints_no_letter():
    rows = [
        {"date": "2026-08-01", "score": None, "grade": None, "graded": False, "source": "audit"},
        {"date": "2026-08-02", "score": None, "grade": None, "graded": False, "source": "audit"},
    ]
    out = render_trend(rows, ascii_only=False)
    assert "no grade" in out
    # No single-letter grade token should appear standalone.
    for letter in ("A", "B", "C", "D", "F"):
        assert f"  {letter}  " not in out


def test_render_trend_disclosure_present_when_hole_exists():
    rows = [
        {"date": "2026-08-01", "score": 60, "grade": "D", "graded": True, "source": "audit"},
        {"date": "2026-08-02", "score": None, "grade": None, "graded": False, "source": "audit"},
    ]
    out = render_trend(rows, ascii_only=False)
    assert "1 of 2 runs have no grade" in out
    assert "five-layer check did not" in out


def test_render_trend_disclosure_absent_when_no_hole():
    rows = [
        {"date": "2026-08-01", "score": 60, "grade": "D", "graded": True, "source": "audit"},
        {"date": "2026-08-02", "score": 80, "grade": "B", "graded": True, "source": "audit"},
    ]
    out = render_trend(rows, ascii_only=False)
    assert "no grade" not in out
    assert "have no grade" not in out


def test_render_trend_ascii_only_pure_ascii_with_mixed_chain():
    rows = [
        {"date": "2026-08-01", "score": 60, "grade": "D", "graded": True, "source": "audit"},
        {"date": "2026-08-02", "score": None, "grade": None, "graded": False, "source": "audit"},
        {"date": "2026-08-03", "score": 80, "grade": "B", "graded": True, "source": "audit",
         "home": "~/.openclaw"},
    ]
    out = render_trend(rows, ascii_only=True)
    out.encode("ascii")  # raises UnicodeEncodeError if any non-ASCII char slipped in
