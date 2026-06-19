"""Tests for clawcheck/history.py — local score history (JSONL, chmod 600)."""
from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from clawcheck.history import DEFAULT_HISTORY, load, record, render_trend


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _score(score: int, grade: str) -> SimpleNamespace:
    """Minimal stand-in for ScoreResult with the two attributes record() needs."""
    return SimpleNamespace(score=score, grade=grade)


# ---------------------------------------------------------------------------
# record() + load() round-trip
# ---------------------------------------------------------------------------

def test_record_and_load_three_entries(tmp_path):
    path = str(tmp_path / "history.jsonl")

    record(_score(72, "C"), path=path, when="2026-06-15")
    record(_score(81, "B"), path=path, when="2026-06-17")
    record(_score(90, "A"), path=path, when="2026-06-19")

    rows = load(path)
    assert len(rows) == 3
    assert rows[0] == {"date": "2026-06-15", "score": 72, "grade": "C"}
    assert rows[1] == {"date": "2026-06-17", "score": 81, "grade": "B"}
    assert rows[2] == {"date": "2026-06-19", "score": 90, "grade": "A"}


def test_record_creates_parent_dir(tmp_path):
    nested = tmp_path / "deep" / "dir" / "history.jsonl"
    record(_score(50, "D"), path=str(nested), when="2026-06-15")
    assert nested.is_file()


def test_record_appends_not_overwrites(tmp_path):
    path = str(tmp_path / "history.jsonl")
    record(_score(60, "D"), path=path, when="2026-06-15")
    record(_score(70, "C"), path=path, when="2026-06-17")
    rows = load(path)
    assert len(rows) == 2


def test_file_mode_600_on_posix(tmp_path):
    if sys.platform == "win32":
        pytest.skip("chmod 600 not meaningful on Windows")
    path = tmp_path / "history.jsonl"
    record(_score(80, "B"), path=str(path), when="2026-06-15")
    mode = path.stat().st_mode & 0o777
    assert mode == 0o600


# ---------------------------------------------------------------------------
# load() edge cases
# ---------------------------------------------------------------------------

def test_load_missing_file_returns_empty(tmp_path):
    rows = load(str(tmp_path / "nonexistent.jsonl"))
    assert rows == []


def test_load_skips_blank_lines(tmp_path):
    path = tmp_path / "history.jsonl"
    path.write_text(
        '{"date":"2026-06-15","score":72,"grade":"C"}\n'
        "\n"
        '{"date":"2026-06-17","score":81,"grade":"B"}\n',
        encoding="utf-8",
    )
    rows = load(str(path))
    assert len(rows) == 2


def test_load_skips_corrupt_json_line(tmp_path):
    path = tmp_path / "history.jsonl"
    path.write_text(
        '{"date":"2026-06-15","score":72,"grade":"C"}\n'
        "NOT VALID JSON\n"
        '{"date":"2026-06-19","score":90,"grade":"A"}\n',
        encoding="utf-8",
    )
    rows = load(str(path))
    assert len(rows) == 2
    assert rows[0]["date"] == "2026-06-15"
    assert rows[1]["date"] == "2026-06-19"


def test_load_skips_line_missing_required_key(tmp_path):
    path = tmp_path / "history.jsonl"
    path.write_text(
        '{"date":"2026-06-15","score":72}\n'   # missing "grade"
        '{"date":"2026-06-17","score":81,"grade":"B"}\n',
        encoding="utf-8",
    )
    rows = load(str(path))
    assert len(rows) == 1
    assert rows[0]["grade"] == "B"


# ---------------------------------------------------------------------------
# render_trend()
# ---------------------------------------------------------------------------

def test_render_trend_empty_message():
    out = render_trend([])
    assert out == "No history yet. Run --trend again later to see your trend."


def test_render_trend_contains_header():
    rows = [{"date": "2026-06-15", "score": 72, "grade": "C"}]
    assert "ClawCheck - Score Trend" in render_trend(rows)


def test_render_trend_contains_dates_and_grades(tmp_path):
    path = str(tmp_path / "history.jsonl")
    record(_score(72, "C"), path=path, when="2026-06-15")
    record(_score(81, "B"), path=path, when="2026-06-17")
    record(_score(90, "A"), path=path, when="2026-06-19")

    out = render_trend(load(path))
    assert "2026-06-15" in out
    assert "2026-06-17" in out
    assert "2026-06-19" in out
    assert "C" in out
    assert "B" in out
    assert "A" in out


def test_render_trend_unicode_arrows():
    rows = [
        {"date": "2026-06-15", "score": 72, "grade": "C"},
        {"date": "2026-06-17", "score": 81, "grade": "B"},
        {"date": "2026-06-19", "score": 70, "grade": "C"},
    ]
    out = render_trend(rows, ascii_only=False)
    assert "▲" in out   # score went up
    assert "▼" in out   # score went down


def test_render_trend_ascii_only_no_unicode():
    rows = [
        {"date": "2026-06-15", "score": 72, "grade": "C"},
        {"date": "2026-06-17", "score": 81, "grade": "B"},
        {"date": "2026-06-19", "score": 70, "grade": "C"},
    ]
    out = render_trend(rows, ascii_only=True)
    assert "^" in out    # up
    assert "v" in out    # down
    # Must not contain unicode arrows
    assert "▲" not in out
    assert "▼" not in out
    assert "·" not in out


def test_render_trend_flat_arrow_on_equal_score():
    rows = [
        {"date": "2026-06-15", "score": 80, "grade": "B"},
        {"date": "2026-06-17", "score": 80, "grade": "B"},
    ]
    out = render_trend(rows, ascii_only=False)
    # first row uses flat arrow; second row is also flat (equal score)
    assert "·" in out


def test_render_trend_ascii_flat_arrow_on_equal_score():
    rows = [
        {"date": "2026-06-15", "score": 80, "grade": "B"},
        {"date": "2026-06-17", "score": 80, "grade": "B"},
    ]
    out = render_trend(rows, ascii_only=True)
    assert "=" in out


def test_render_trend_first_row_always_flat(tmp_path):
    """The very first entry always shows the flat arrow (no previous to compare)."""
    rows = [{"date": "2026-06-19", "score": 90, "grade": "A"}]
    out_unicode = render_trend(rows, ascii_only=False)
    out_ascii = render_trend(rows, ascii_only=True)
    assert "·" in out_unicode
    assert "=" in out_ascii


def test_render_trend_single_entry_full(tmp_path):
    path = str(tmp_path / "history.jsonl")
    record(_score(55, "D"), path=path, when="2026-06-19")
    out = render_trend(load(path))
    assert "2026-06-19" in out
    assert "55" in out
    assert "D" in out


# ---------------------------------------------------------------------------
# DEFAULT_HISTORY constant
# ---------------------------------------------------------------------------

def test_default_history_constant():
    assert DEFAULT_HISTORY == "~/.clawcheck/history.jsonl"
