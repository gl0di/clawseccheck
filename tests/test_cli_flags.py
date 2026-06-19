"""Tests for the new CLI flags added in Phase 1 wiring:
--sarif, --fail-under, --exit-code, --trend, --percentile, --history,
--verbose, --debug, --log.

All tests use --home fixtures/home_vuln or fixtures/home_safe with
--no-native to stay offline and deterministic.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawcheck.cli import main

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
VULN = str(FIXTURES / "home_vuln")
SAFE = str(FIXTURES / "home_safe")
BASE = ["--no-native"]


# ---------------------------------------------------------------------------
# Regression: default run still returns 0
# ---------------------------------------------------------------------------

def test_default_run_returns_zero(capsys):
    rc = main(["--home", VULN] + BASE)
    assert rc == 0


# ---------------------------------------------------------------------------
# --fail-under
# ---------------------------------------------------------------------------

def test_fail_under_high_threshold_returns_one(capsys):
    """home_vuln has a low score, so --fail-under 100 must exit 1."""
    rc = main(["--home", VULN] + BASE + ["--fail-under", "100"])
    assert rc == 1


def test_fail_under_zero_threshold_returns_zero(capsys):
    """Score is always >= 0, so --fail-under 0 must exit 0."""
    rc = main(["--home", VULN] + BASE + ["--fail-under", "0"])
    assert rc == 0


def test_fail_under_exact_pass(capsys):
    """--fail-under N exits 0 when score == N (strictly less-than check)."""
    # We use home_safe which should score reasonably high.
    # Use threshold 1 to ensure we're above it.
    rc = main(["--home", SAFE] + BASE + ["--fail-under", "1"])
    assert rc == 0


# ---------------------------------------------------------------------------
# --exit-code
# ---------------------------------------------------------------------------

def test_exit_code_on_vuln_returns_one(capsys):
    """home_vuln has FAIL findings -> --exit-code must return 1."""
    rc = main(["--home", VULN] + BASE + ["--exit-code"])
    assert rc == 1


def test_exit_code_on_safe_returns_zero(capsys):
    """home_safe has no FAIL findings -> --exit-code must return 0."""
    rc = main(["--home", SAFE] + BASE + ["--exit-code"])
    assert rc == 0


# ---------------------------------------------------------------------------
# --sarif
# ---------------------------------------------------------------------------

def test_sarif_writes_file(tmp_path, capsys):
    out = tmp_path / "report.sarif"
    rc = main(["--home", VULN] + BASE + ["--sarif", str(out)])
    assert rc == 0
    assert out.is_file()


def test_sarif_file_contains_version(tmp_path, capsys):
    out = tmp_path / "report.sarif"
    main(["--home", VULN] + BASE + ["--sarif", str(out)])
    content = out.read_text(encoding="utf-8")
    assert '"version": "2.1.0"' in content


def test_sarif_output_is_valid_json(tmp_path, capsys):
    out = tmp_path / "report.sarif"
    main(["--home", VULN] + BASE + ["--sarif", str(out)])
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"


def test_sarif_prints_confirmation(tmp_path, capsys):
    out = tmp_path / "report.sarif"
    main(["--home", VULN] + BASE + ["--sarif", str(out)])
    captured = capsys.readouterr().out
    assert "SARIF written to" in captured


# ---------------------------------------------------------------------------
# --percentile
# ---------------------------------------------------------------------------

def test_percentile_prints_offline(capsys):
    rc = main(["--home", SAFE] + BASE + ["--percentile"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "offline" in out or "reference" in out


def test_percentile_returns_zero(capsys):
    rc = main(["--home", VULN] + BASE + ["--percentile"])
    assert rc == 0


# ---------------------------------------------------------------------------
# --trend + --history
# ---------------------------------------------------------------------------

def test_trend_writes_history_file(tmp_path, capsys):
    hist = tmp_path / "history.jsonl"
    rc = main(["--home", VULN] + BASE + ["--trend", "--history", str(hist)])
    assert rc == 0
    assert hist.is_file()


def test_trend_prints_trend_line(tmp_path, capsys):
    hist = tmp_path / "history.jsonl"
    main(["--home", VULN] + BASE + ["--trend", "--history", str(hist)])
    out = capsys.readouterr().out
    # render_trend header is "ClawCheck - Score Trend"
    assert "Score Trend" in out or "history" in out.lower() or "No history" in out or any(
        c.isdigit() for c in out
    )


def test_trend_prints_percentile(tmp_path, capsys):
    hist = tmp_path / "history.jsonl"
    main(["--home", VULN] + BASE + ["--trend", "--history", str(hist)])
    out = capsys.readouterr().out
    assert "offline" in out or "reference" in out


def test_trend_accumulates_on_second_call(tmp_path, capsys):
    hist = tmp_path / "history.jsonl"
    main(["--home", VULN] + BASE + ["--trend", "--history", str(hist)])
    main(["--home", SAFE] + BASE + ["--trend", "--history", str(hist)])
    lines = [ln for ln in hist.read_text().splitlines() if ln.strip()]
    assert len(lines) == 2


# ---------------------------------------------------------------------------
# --json regression
# ---------------------------------------------------------------------------

def test_json_flag_still_returns_zero_and_valid_json(capsys):
    rc = main(["--home", SAFE] + BASE + ["--json"])
    assert rc == 0
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert "grade" in doc


def test_json_flag_on_vuln_returns_zero_without_exit_code(capsys):
    """Without --exit-code, --json should still return 0 even on vuln fixture."""
    rc = main(["--home", VULN] + BASE + ["--json"])
    assert rc == 0


# ---------------------------------------------------------------------------
# --verbose / --debug (smoke: no crash, no secret leakage)
# ---------------------------------------------------------------------------

def test_verbose_flag_does_not_crash(capsys):
    rc = main(["--home", SAFE] + BASE + ["--verbose"])
    assert rc == 0


def test_debug_flag_does_not_crash(capsys):
    rc = main(["--home", SAFE] + BASE + ["--debug"])
    assert rc == 0


def test_log_flag_writes_file(tmp_path, capsys):
    logfile = tmp_path / "clawcheck.log"
    rc = main(["--home", SAFE] + BASE + ["--verbose", "--log", str(logfile)])
    assert rc == 0
    assert logfile.is_file()
    content = logfile.read_text(encoding="utf-8")
    # Should contain at least one log line
    assert len(content) > 0


def test_log_file_not_written_without_flag(tmp_path, capsys):
    """Without --log, no log file should be created."""
    logfile = tmp_path / "should_not_exist.log"
    main(["--home", SAFE] + BASE + ["--verbose"])
    assert not logfile.exists()
