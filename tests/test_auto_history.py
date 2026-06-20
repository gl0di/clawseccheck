"""Auto-history: default audit run appends one entry; --no-history suppresses it.

All tests redirect history to a tmp_path file so the real
~/.clawseccheck/history.jsonl is never touched.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.cli import main
from clawseccheck.history import load as history_load

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
VULN = str(FIXTURES / "home_vuln")
SAFE = str(FIXTURES / "home_safe")


# ---------------------------------------------------------------------------
# Default run appends exactly one entry
# ---------------------------------------------------------------------------

def test_default_run_records_one_entry(tmp_path, capsys):
    hist = tmp_path / "history.jsonl"
    rc = main(["--home", VULN, "--no-native", "--history", str(hist)])
    assert rc == 0
    rows = history_load(str(hist))
    assert len(rows) == 1
    assert "score" in rows[0]
    assert "grade" in rows[0]
    assert "date" in rows[0]


def test_second_run_appends_second_entry(tmp_path, capsys):
    hist = tmp_path / "history.jsonl"
    main(["--home", VULN, "--no-native", "--history", str(hist)])
    main(["--home", SAFE, "--no-native", "--history", str(hist)])
    rows = history_load(str(hist))
    assert len(rows) == 2


# ---------------------------------------------------------------------------
# --no-history suppresses the write
# ---------------------------------------------------------------------------

def test_no_history_flag_writes_nothing(tmp_path, capsys):
    hist = tmp_path / "history.jsonl"
    rc = main(["--home", VULN, "--no-native", "--no-history", "--history", str(hist)])
    assert rc == 0
    assert not hist.exists()


# ---------------------------------------------------------------------------
# --json default run also records (unless --no-history)
# ---------------------------------------------------------------------------

def test_json_run_records_entry(tmp_path, capsys):
    hist = tmp_path / "history.jsonl"
    rc = main(["--home", VULN, "--no-native", "--json", "--history", str(hist)])
    assert rc == 0
    rows = history_load(str(hist))
    assert len(rows) == 1


def test_json_run_with_no_history_writes_nothing(tmp_path, capsys):
    hist = tmp_path / "history.jsonl"
    rc = main(["--home", VULN, "--no-native", "--json", "--no-history", "--history", str(hist)])
    assert rc == 0
    assert not hist.exists()


# ---------------------------------------------------------------------------
# --trend does not double-record: still one entry per run
# ---------------------------------------------------------------------------

def test_trend_does_not_double_record(tmp_path, capsys):
    hist = tmp_path / "history.jsonl"
    rc = main(["--home", VULN, "--no-native", "--trend", "--history", str(hist)])
    assert rc == 0
    lines = [ln for ln in hist.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 1


def test_trend_second_run_gives_two_entries(tmp_path, capsys):
    hist = tmp_path / "history.jsonl"
    main(["--home", VULN, "--no-native", "--trend", "--history", str(hist)])
    main(["--home", SAFE, "--no-native", "--trend", "--history", str(hist)])
    lines = [ln for ln in hist.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 2


# ---------------------------------------------------------------------------
# Entry content is well-formed JSON with required keys
# ---------------------------------------------------------------------------

def test_recorded_entry_is_valid_json(tmp_path, capsys):
    hist = tmp_path / "history.jsonl"
    main(["--home", SAFE, "--no-native", "--history", str(hist)])
    line = hist.read_text(encoding="utf-8").strip()
    obj = json.loads(line)
    assert set(obj.keys()) >= {"date", "score", "grade"}
    assert isinstance(obj["score"], int)
    assert isinstance(obj["grade"], str)
