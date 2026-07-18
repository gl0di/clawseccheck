"""Tests for clawseccheck/history.py — local score history (JSONL, chmod 600)."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from clawseccheck.cli import main
from clawseccheck.history import (
    DEFAULT_HISTORY, _run_source, _sanitize_home, load, record, render_trend, verify,
)


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

    record(_score(72, "C"), path=path, when="2026-06-15", source="audit")
    record(_score(81, "B"), path=path, when="2026-06-17", source="audit")
    record(_score(90, "A"), path=path, when="2026-06-19", source="audit")

    rows = load(path)
    assert len(rows) == 3
    assert rows[0] == {"date": "2026-06-15", "score": 72, "grade": "C",
                        "ts": "2026-06-15T00:00:00", "home": None, "source": "audit"}
    assert rows[1] == {"date": "2026-06-17", "score": 81, "grade": "B",
                        "ts": "2026-06-17T00:00:00", "home": None, "source": "audit"}
    assert rows[2] == {"date": "2026-06-19", "score": 90, "grade": "A",
                        "ts": "2026-06-19T00:00:00", "home": None, "source": "audit"}


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


def test_load_skips_non_utf8_byte_instead_of_wedging(tmp_path):
    """C-177: a single non-UTF-8 byte anywhere in the journal used to raise
    UnicodeDecodeError (uncaught by the JSONDecodeError guard) and permanently
    wedge every future load()/verify() call. It must now degrade that one
    (garbled) line gracefully, same as any other malformed line."""
    path = tmp_path / "history.jsonl"
    path.write_bytes(
        b'{"date":"2026-06-15","score":72,"grade":"C"}\n'
        b'\x00\x01\xff\xfe garbage not json \x00\n'
        b'{"date":"2026-06-19","score":90,"grade":"A"}\n'
    )
    rows = load(str(path))
    assert len(rows) == 2
    assert rows[0]["date"] == "2026-06-15"
    assert rows[1]["date"] == "2026-06-19"

    ok, msg = verify(str(path))
    assert ok, msg


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
    assert "ClawSecCheck · Score Trend" in render_trend(rows)


def test_render_trend_contains_dates_and_grades(tmp_path):
    path = str(tmp_path / "history.jsonl")
    record(_score(72, "C"), path=path, when="2026-06-15", source="audit")
    record(_score(81, "B"), path=path, when="2026-06-17", source="audit")
    record(_score(90, "A"), path=path, when="2026-06-19", source="audit")

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
    record(_score(55, "D"), path=path, when="2026-06-19", source="audit")
    out = render_trend(load(path))
    assert "2026-06-19" in out
    assert "55" in out
    assert "D" in out


# ---------------------------------------------------------------------------
# DEFAULT_HISTORY constant
# ---------------------------------------------------------------------------

def test_default_history_constant():
    assert DEFAULT_HISTORY == "~/.clawseccheck/history.jsonl"


# ---------------------------------------------------------------------------
# F-094: tamper-evident hash-chain
# ---------------------------------------------------------------------------

def test_record_writes_chain_hash(tmp_path):
    path = str(tmp_path / "history.jsonl")
    record(_score(72, "C"), path=path, when="2026-06-15")
    line = json.loads(Path(path).read_text(encoding="utf-8").splitlines()[0])
    assert "chain_hash" in line
    assert isinstance(line["chain_hash"], str) and len(line["chain_hash"]) == 64


def test_verify_ok_on_untampered_chain(tmp_path):
    path = str(tmp_path / "history.jsonl")
    record(_score(72, "C"), path=path, when="2026-06-15")
    record(_score(81, "B"), path=path, when="2026-06-17")
    record(_score(90, "A"), path=path, when="2026-06-19")
    ok, msg = verify(path)
    assert ok is True
    assert msg == "OK"


def test_verify_ok_on_missing_file(tmp_path):
    ok, msg = verify(str(tmp_path / "nonexistent.jsonl"))
    assert ok is True
    assert msg == "OK"


def test_verify_ok_on_empty_file(tmp_path):
    path = tmp_path / "history.jsonl"
    path.write_text("", encoding="utf-8")
    ok, msg = verify(str(path))
    assert ok is True
    assert msg == "OK"


def test_verify_ok_on_legacy_entries_without_chain_hash(tmp_path):
    path = tmp_path / "history.jsonl"
    path.write_text(
        '{"date":"2026-06-15","score":72,"grade":"C"}\n'
        '{"date":"2026-06-17","score":81,"grade":"B"}\n',
        encoding="utf-8",
    )
    ok, msg = verify(str(path))
    assert ok is True
    assert msg == "OK"


def test_verify_detects_tampered_entry(tmp_path):
    path = tmp_path / "history.jsonl"
    record(_score(72, "C"), path=str(path), when="2026-06-15")
    record(_score(81, "B"), path=str(path), when="2026-06-17")
    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["score"] = 100  # attacker rewrites the score, leaves chain_hash untouched
    lines[0] = json.dumps(tampered)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, msg = verify(str(path))
    assert ok is False
    assert "entry 0" in msg


def test_verify_detects_deleted_entry(tmp_path):
    path = tmp_path / "history.jsonl"
    record(_score(72, "C"), path=str(path), when="2026-06-15")
    record(_score(81, "B"), path=str(path), when="2026-06-17")
    record(_score(90, "A"), path=str(path), when="2026-06-19")
    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[1]  # drop the middle entry — breaks the chain for entry after it
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, msg = verify(str(path))
    assert ok is False


# ---------------------------------------------------------------------------
# F-094: CLI --verify-history integration tests
# ---------------------------------------------------------------------------

def test_cli_verify_history_exits_zero_on_untampered_chain(tmp_path, capsys):
    path = str(tmp_path / "history.jsonl")
    record(_score(72, "C"), path=path, when="2026-06-15")
    rc = main(["--verify-history", "--history", path])
    assert rc == 0
    assert "OK" in capsys.readouterr().out


def test_cli_verify_history_exits_zero_on_missing_file(tmp_path, capsys):
    path = str(tmp_path / "nonexistent.jsonl")
    rc = main(["--verify-history", "--history", path])
    assert rc == 0


def test_cli_verify_history_exits_one_on_tampered_chain(tmp_path, capsys):
    path = tmp_path / "history.jsonl"
    record(_score(72, "C"), path=str(path), when="2026-06-15")
    record(_score(81, "B"), path=str(path), when="2026-06-17")
    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["score"] = 100
    lines[0] = json.dumps(tampered)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    rc = main(["--verify-history", "--history", str(path)])
    assert rc == 1
    assert "BROKEN" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# F-128: 'ts' timestamp
# ---------------------------------------------------------------------------

def test_record_ts_defaults_to_now_iso_format(tmp_path):
    path = str(tmp_path / "history.jsonl")
    record(_score(70, "C"), path=path, source="audit")  # when=None -> real now()
    rows = load(path)
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$", rows[0]["ts"])


def test_record_when_bare_date_sets_ts_to_midnight(tmp_path):
    path = str(tmp_path / "history.jsonl")
    record(_score(70, "C"), path=path, when="2026-06-15", source="audit")
    rows = load(path)
    assert rows[0]["date"] == "2026-06-15"
    assert rows[0]["ts"] == "2026-06-15T00:00:00"


def test_record_when_accepts_full_iso_datetime(tmp_path):
    path = str(tmp_path / "history.jsonl")
    record(_score(70, "C"), path=path, when="2026-06-15T09:30:45", source="audit")
    rows = load(path)
    assert rows[0]["date"] == "2026-06-15"  # back-compat display/sort field
    assert rows[0]["ts"] == "2026-06-15T09:30:45"


# ---------------------------------------------------------------------------
# F-128: run-source tag — detection priority
# ---------------------------------------------------------------------------

def test_run_source_explicit_arg_wins_over_everything(monkeypatch):
    monkeypatch.setenv("CLAWSECCHECK_RUN_SOURCE", "dev")
    assert _run_source("ci") == "ci"


def test_run_source_env_override_wins_over_pytest_detection(monkeypatch):
    monkeypatch.setenv("CLAWSECCHECK_RUN_SOURCE", "dev")
    # PYTEST_CURRENT_TEST is set (this IS a pytest run) but the explicit env
    # override must still win.
    assert _run_source() == "dev"


def test_run_source_detects_pytest_as_test(monkeypatch):
    monkeypatch.delenv("CLAWSECCHECK_RUN_SOURCE", raising=False)
    # pytest sets PYTEST_CURRENT_TEST for the duration of every test — no
    # per-call-site plumbing needed to get "test" here.
    assert _run_source() == "test"


def test_run_source_defaults_to_audit_outside_pytest(monkeypatch):
    monkeypatch.delenv("CLAWSECCHECK_RUN_SOURCE", raising=False)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    assert _run_source() == "audit"


def test_record_source_auto_detected_as_test_under_pytest(tmp_path, monkeypatch):
    monkeypatch.delenv("CLAWSECCHECK_RUN_SOURCE", raising=False)
    path = str(tmp_path / "history.jsonl")
    record(_score(70, "C"), path=path, when="2026-06-15")  # no explicit source=
    rows = load(path)
    assert rows[0]["source"] == "test"


def test_record_source_explicit_arg(tmp_path):
    path = str(tmp_path / "history.jsonl")
    record(_score(70, "C"), path=path, when="2026-06-15", source="audit")
    rows = load(path)
    assert rows[0]["source"] == "audit"


# ---------------------------------------------------------------------------
# F-128: 'home' — sanitized audited path
# ---------------------------------------------------------------------------

def test_sanitize_home_none_stays_none():
    assert _sanitize_home(None) is None


def test_sanitize_home_empty_string_stays_empty():
    assert _sanitize_home("") == ""


def test_sanitize_home_passthrough_for_ordinary_path():
    assert _sanitize_home("~/.openclaw") == "~/.openclaw"


def test_sanitize_home_strips_control_chars():
    dirty = "~/.openclaw\x1b[31m\x00evil"
    clean = _sanitize_home(dirty)
    assert "\x1b" not in clean
    assert "\x00" not in clean


def test_record_stores_sanitized_home(tmp_path):
    path = str(tmp_path / "history.jsonl")
    record(_score(70, "C"), path=path, when="2026-06-15", home="~/.openclaw", source="audit")
    rows = load(path)
    assert rows[0]["home"] == "~/.openclaw"


def test_record_home_defaults_to_none_when_not_supplied(tmp_path):
    path = str(tmp_path / "history.jsonl")
    record(_score(70, "C"), path=path, when="2026-06-15", source="audit")
    rows = load(path)
    assert rows[0]["home"] is None


# ---------------------------------------------------------------------------
# F-128: backward compat — a pre-F-128 entry lacking ts/home/source
# ---------------------------------------------------------------------------

def test_load_legacy_entry_fills_honest_unknown_defaults(tmp_path):
    """A pre-F-128 line has no ts/home/source concept at all. load() must not
    guess — it reports the honest 'don't know' state (None/None) and tags the
    source 'legacy' (distinct from 'audit', since it predates the real-vs-dev
    distinction this task adds)."""
    path = tmp_path / "history.jsonl"
    path.write_text('{"date":"2026-06-10","score":60,"grade":"D"}\n', encoding="utf-8")
    rows = load(str(path))
    assert len(rows) == 1
    assert rows[0]["ts"] is None
    assert rows[0]["home"] is None
    assert rows[0]["source"] == "legacy"


def test_load_forward_compat_entry_with_new_fields_and_unchanged_schema(tmp_path):
    """F-128 added ts/home/source WITHOUT bumping _schema (still 1) — a build
    that predates F-128 would still accept the line (extra keys tolerated),
    and this build must read the new fields back correctly."""
    path = tmp_path / "history.jsonl"
    entry = {
        "date": "2026-07-17", "score": 55, "grade": "D",
        "ts": "2026-07-17T10:00:00", "home": "~/.openclaw", "source": "audit",
        "_schema": 1,
    }
    path.write_text(json.dumps(entry) + "\n", encoding="utf-8")
    rows = load(str(path))
    assert len(rows) == 1
    assert rows[0]["ts"] == "2026-07-17T10:00:00"
    assert rows[0]["home"] == "~/.openclaw"
    assert rows[0]["source"] == "audit"


def test_verify_ok_on_mixed_legacy_and_new_format_file(tmp_path):
    """DoD: --verify-history stays OK across the legacy/new-format boundary in
    one file — the hash-chain scheme is entry-shape-agnostic (F-094/C-162), so
    adding ts/home/source doesn't need a chain migration."""
    path = tmp_path / "history.jsonl"
    path.write_text('{"date":"2026-06-10","score":60,"grade":"D"}\n', encoding="utf-8")
    record(_score(72, "C"), path=str(path), when="2026-06-15", source="audit")
    record(_score(81, "B"), path=str(path), when="2026-06-17", source="audit")
    ok, msg = verify(str(path))
    assert ok is True
    assert msg == "OK"

    rows = load(str(path))
    assert len(rows) == 3
    assert rows[0]["source"] == "legacy"
    assert rows[1]["source"] == "audit"
    assert rows[2]["source"] == "audit"


# ---------------------------------------------------------------------------
# F-128: --trend default filter (real audits only) + include_all
# ---------------------------------------------------------------------------

def test_render_trend_hides_test_source_by_default(tmp_path):
    path = str(tmp_path / "history.jsonl")
    record(_score(72, "C"), path=path, when="2026-06-15", source="audit")
    record(_score(50, "D"), path=path, when="2026-06-16", source="test")
    out = render_trend(load(path))
    assert "2026-06-15" in out
    assert "2026-06-16" not in out


def test_render_trend_hides_dev_source_by_default(tmp_path):
    path = str(tmp_path / "history.jsonl")
    record(_score(72, "C"), path=path, when="2026-06-15", source="audit")
    record(_score(50, "D"), path=path, when="2026-06-16", source="dev")
    out = render_trend(load(path))
    assert "2026-06-15" in out
    assert "2026-06-16" not in out


def test_render_trend_legacy_rows_count_as_real(tmp_path):
    """A pre-F-128 entry predates the source concept entirely — it must not
    be hidden by the new default filter as if it were a dev/test run."""
    path = tmp_path / "history.jsonl"
    path.write_text('{"date":"2026-06-10","score":60,"grade":"D"}\n', encoding="utf-8")
    out = render_trend(load(str(path)))
    assert "2026-06-10" in out


def test_render_trend_include_all_shows_everything_with_source_tag(tmp_path):
    path = str(tmp_path / "history.jsonl")
    record(_score(72, "C"), path=path, when="2026-06-15", source="audit")
    record(_score(50, "D"), path=path, when="2026-06-16", source="test")
    out = render_trend(load(path), include_all=True)
    assert "2026-06-15" in out
    assert "2026-06-16" in out
    assert "[audit]" in out
    assert "[test]" in out


def test_render_trend_include_all_shows_home_tag(tmp_path):
    path = str(tmp_path / "history.jsonl")
    record(_score(72, "C"), path=path, when="2026-06-15", home="~/.openclaw", source="audit")
    out = render_trend(load(path), include_all=True)
    assert "~/.openclaw" in out


def test_render_trend_no_home_tag_when_include_all_false(tmp_path):
    path = str(tmp_path / "history.jsonl")
    record(_score(72, "C"), path=path, when="2026-06-15", home="~/.openclaw", source="audit")
    out = render_trend(load(path))
    assert "~/.openclaw" not in out
    assert "[audit]" not in out


def test_render_trend_all_hidden_shows_friendly_message(tmp_path):
    path = str(tmp_path / "history.jsonl")
    record(_score(50, "D"), path=path, when="2026-06-15", source="test")
    out = render_trend(load(path))
    assert "No audit runs yet" in out
    assert "1 dev/test entry hidden" in out


def test_render_trend_all_hidden_message_pluralizes_entries(tmp_path):
    path = str(tmp_path / "history.jsonl")
    record(_score(50, "D"), path=path, when="2026-06-15", source="test")
    record(_score(60, "D"), path=path, when="2026-06-16", source="dev")
    out = render_trend(load(path))
    assert "2 dev/test entries hidden" in out
