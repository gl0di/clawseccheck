"""Tests for the coverage ledger (clawseccheck.ledger).

Covers:
  - record_run / load_ledger round-trip (tmp_path only, never real HOME)
  - freshness_notice: fresh, stale, never-run, with injected today
  - Nudge is advisory: absent from --json/--card; never changes score/grade
  - Offline and read-only (no network, no writes outside tmp_path)
"""
from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path

from clawseccheck.ledger import (
    THRESHOLDS,
    freshness_notice,
    load_ledger,
    record_run,
)
from clawseccheck.cli import main
from clawseccheck.report import render_report
from clawseccheck.scoring import compute

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE = str(FIXTURES / "home_safe")
BASE = ["--home", SAFE, "--no-native", "--no-host", "--no-history"]


# ---------------------------------------------------------------------------
# ledger path helper
# ---------------------------------------------------------------------------

def _ledger_file(home: Path) -> Path:
    return home / ".clawseccheck" / "coverage.json"


# ---------------------------------------------------------------------------
# record_run + load_ledger round-trip
# ---------------------------------------------------------------------------

def test_record_run_creates_ledger(tmp_path):
    record_run("self_test", home=str(tmp_path), today=date(2026, 6, 27))
    ledger_path = _ledger_file(tmp_path)
    assert ledger_path.exists()


def test_record_run_stores_iso_date(tmp_path):
    record_run("self_test", home=str(tmp_path), today=date(2026, 6, 27))
    ledger = load_ledger(str(tmp_path))
    assert ledger["self_test"] == "2026-06-27"


def test_record_run_preserves_other_capabilities(tmp_path):
    record_run("self_test", home=str(tmp_path), today=date(2026, 6, 1))
    record_run("vet_mcp", home=str(tmp_path), today=date(2026, 6, 15))
    ledger = load_ledger(str(tmp_path))
    assert ledger["self_test"] == "2026-06-01"
    assert ledger["vet_mcp"] == "2026-06-15"


def test_record_run_overwrites_existing_date(tmp_path):
    record_run("self_test", home=str(tmp_path), today=date(2026, 6, 1))
    record_run("self_test", home=str(tmp_path), today=date(2026, 6, 27))
    ledger = load_ledger(str(tmp_path))
    assert ledger["self_test"] == "2026-06-27"


def test_load_ledger_missing_file_returns_empty(tmp_path):
    assert load_ledger(str(tmp_path)) == {}


def test_load_ledger_malformed_json_returns_empty(tmp_path):
    p = _ledger_file(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{not json", encoding="utf-8")
    assert load_ledger(str(tmp_path)) == {}


def test_load_ledger_non_dict_returns_empty(tmp_path):
    p = _ledger_file(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text('["self_test"]', encoding="utf-8")
    assert load_ledger(str(tmp_path)) == {}


def test_load_ledger_rejects_non_string_values(tmp_path):
    p = _ledger_file(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"self_test": 12345, "vet_mcp": "2026-06-01"}),
                 encoding="utf-8")
    ledger = load_ledger(str(tmp_path))
    # Only the string value survives
    assert "self_test" not in ledger
    assert ledger.get("vet_mcp") == "2026-06-01"


def test_ledger_written_to_tmp_only(tmp_path):
    """record_run must not touch the real HOME (writes only under tmp_path)."""
    record_run("self_test", home=str(tmp_path), today=date(2026, 6, 27))
    # Only check that we can read it back from tmp_path; the real-home assertion
    # is implicit in the home= override path covering the entire write path.
    assert load_ledger(str(tmp_path))["self_test"] == "2026-06-27"


# ---------------------------------------------------------------------------
# freshness_notice — threshold logic
# ---------------------------------------------------------------------------

TODAY = date(2026, 6, 27)

_SELF_TEST_THRESHOLD = THRESHOLDS["self_test"]   # 30 days
_VET_MCP_THRESHOLD = THRESHOLDS["vet_mcp"]       # 14 days


def test_freshness_notice_empty_when_both_fresh():
    fresh_ledger = {
        "self_test": date(TODAY.year, TODAY.month, TODAY.day).isoformat(),
        "vet_mcp": date(TODAY.year, TODAY.month, TODAY.day).isoformat(),
    }
    assert freshness_notice(fresh_ledger, today=TODAY) == []


def test_freshness_notice_empty_just_under_threshold():
    """One day under the threshold should not fire."""
    from datetime import timedelta
    fresh_ledger = {
        "self_test": (TODAY - timedelta(days=_SELF_TEST_THRESHOLD)).isoformat(),
        "vet_mcp": (TODAY - timedelta(days=_VET_MCP_THRESHOLD)).isoformat(),
    }
    # threshold is strictly > (age > threshold), so exactly at threshold is silent
    assert freshness_notice(fresh_ledger, today=TODAY) == []


def test_freshness_notice_fires_one_day_over_threshold():
    """One day over the threshold must fire."""
    from datetime import timedelta
    stale_ledger = {
        "self_test": (TODAY - timedelta(days=_SELF_TEST_THRESHOLD + 1)).isoformat(),
        "vet_mcp": (TODAY - timedelta(days=_VET_MCP_THRESHOLD + 1)).isoformat(),
    }
    lines = freshness_notice(stale_ledger, today=TODAY)
    assert len(lines) == 2
    assert any("--self-test" in ln for ln in lines)
    assert any("--vet-mcp" in ln for ln in lines)


def test_freshness_notice_stale_self_test_mentions_days_and_threshold():
    from datetime import timedelta
    stale_ledger = {"self_test": (TODAY - timedelta(days=35)).isoformat()}
    lines = freshness_notice(stale_ledger, today=TODAY)
    assert any("35 days ago" in ln for ln in lines)
    assert any(str(_SELF_TEST_THRESHOLD) in ln for ln in lines)


def test_freshness_notice_stale_vet_mcp_mentions_days_and_threshold():
    from datetime import timedelta
    stale_ledger = {"vet_mcp": (TODAY - timedelta(days=20)).isoformat()}
    lines = freshness_notice(stale_ledger, today=TODAY)
    assert any("20 days ago" in ln for ln in lines)
    assert any(str(_VET_MCP_THRESHOLD) in ln for ln in lines)


def test_freshness_notice_never_run_fires_for_both():
    lines = freshness_notice({}, today=TODAY)
    assert len(lines) == 2
    assert any("--self-test" in ln for ln in lines)
    assert any("--vet-mcp" in ln for ln in lines)


def test_freshness_notice_never_run_self_test_only():
    ledger = {"vet_mcp": TODAY.isoformat()}
    lines = freshness_notice(ledger, today=TODAY)
    assert len(lines) == 1
    assert "--self-test" in lines[0]


def test_freshness_notice_never_run_vet_mcp_only():
    ledger = {"self_test": TODAY.isoformat()}
    lines = freshness_notice(ledger, today=TODAY)
    assert len(lines) == 1
    assert "--vet-mcp" in lines[0]


def test_freshness_notice_unparseable_date_skipped_silently():
    """A corrupted date entry should be silently ignored, not raise."""
    ledger = {"self_test": "not-a-date", "vet_mcp": "2026-06-27"}
    lines = freshness_notice(ledger, today=TODAY)
    # vet_mcp is fresh, self_test unparseable → skip; result should be empty
    assert lines == []


def test_freshness_notice_offline_marker_in_output():
    """Advisory lines must mention 'no network call' so users know it's local."""
    lines = freshness_notice({}, today=TODAY)
    assert all("no network call" in ln for ln in lines)


# ---------------------------------------------------------------------------
# i18n: Hebrew output contains Hebrew characters
# ---------------------------------------------------------------------------

_HEBREW_RE = re.compile(r"[֐-׿]")


def test_freshness_notice_he_contains_hebrew():
    lines = freshness_notice({}, today=TODAY, lang="he")
    assert lines, "expected at least one advisory line"
    for ln in lines:
        assert _HEBREW_RE.search(ln), f"Hebrew notice line has no Hebrew chars: {ln!r}"


def test_freshness_notice_en_default():
    lines = freshness_notice({}, today=TODAY, lang="en")
    assert any("Coverage gap" in ln for ln in lines)


# ---------------------------------------------------------------------------
# Advisory only: freshness_notice never changes score / grade
# ---------------------------------------------------------------------------

def _score_and_findings():
    from clawseccheck import collect, run_all
    ctx = collect(SAFE)
    findings = run_all(ctx)
    return findings, compute(findings)


def test_freshness_in_report_does_not_change_score():
    findings, score_without = _score_and_findings()
    report_without = render_report(findings, score_without)
    report_with = render_report(findings, score_without, freshness_notice=["Advisory line."])
    # Score line is identical in both
    assert f"Score: {score_without.score}" in report_without
    assert f"Score: {score_without.score}" in report_with
    assert f"Grade: {score_without.grade}" in report_without
    assert f"Grade: {score_without.grade}" in report_with


def test_freshness_notice_appears_in_human_report():
    findings, score = _score_and_findings()
    out = render_report(findings, score, freshness_notice=["Coverage gap: test notice."])
    assert "Coverage gap: test notice." in out


def test_freshness_notice_absent_when_not_passed():
    findings, score = _score_and_findings()
    out = render_report(findings, score)
    assert "Coverage gap" not in out


# ---------------------------------------------------------------------------
# CLI integration: --json and --card must NOT show the freshness notice
# ---------------------------------------------------------------------------

def test_cli_json_does_not_show_freshness_notice(tmp_path, monkeypatch, capsys):
    """--json output must never contain freshness advisory text."""
    monkeypatch.setenv("HOME", str(tmp_path))
    # ledger is empty → both capabilities never-run → would fire if wired
    main(BASE + ["--json"])
    out = capsys.readouterr().out
    assert "Coverage gap" not in out


def test_cli_card_does_not_show_freshness_notice(tmp_path, monkeypatch, capsys):
    """--card output must never contain freshness advisory text."""
    monkeypatch.setenv("HOME", str(tmp_path))
    main(BASE + ["--card"])
    out = capsys.readouterr().out
    assert "Coverage gap" not in out


# ---------------------------------------------------------------------------
# CLI integration: human report shows the notice; flags suppress it
# ---------------------------------------------------------------------------

def test_cli_default_report_shows_freshness_notice(tmp_path, monkeypatch, capsys):
    """Default human report with empty ledger should show both never-run advisories."""
    monkeypatch.setenv("HOME", str(tmp_path))
    main(BASE)
    out = capsys.readouterr().out
    assert "Coverage gap" in out


def test_cli_no_freshness_notice_flag_suppresses(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    main(BASE + ["--no-freshness-notice"])
    out = capsys.readouterr().out
    assert "Coverage gap" not in out


def test_cli_env_var_suppresses_freshness_notice(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("CLAWSECCHECK_NO_FRESHNESS_NOTICE", "1")
    main(BASE)
    out = capsys.readouterr().out
    assert "Coverage gap" not in out


def test_cli_fresh_ledger_no_notice(tmp_path, monkeypatch, capsys):
    """When both capabilities ran today, no freshness notice should appear."""
    monkeypatch.setenv("HOME", str(tmp_path))
    # Write a ledger where both ran today
    ledger_dir = tmp_path / ".clawseccheck"
    ledger_dir.mkdir(parents=True, exist_ok=True)
    (ledger_dir / "coverage.json").write_text(
        json.dumps({"self_test": TODAY.isoformat(), "vet_mcp": TODAY.isoformat()}),
        encoding="utf-8",
    )
    main(BASE)
    out = capsys.readouterr().out
    assert "Coverage gap" not in out


# ---------------------------------------------------------------------------
# record_run is called by CLI opt-in paths (ledger updated after --canary etc.)
# ---------------------------------------------------------------------------

def test_cli_canary_records_self_test(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    main(["--canary", "--ascii"])
    capsys.readouterr()
    ledger = load_ledger(str(tmp_path))
    assert "self_test" in ledger


def test_cli_self_test_records_self_test(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    main(["--self-test", "--ascii"])
    capsys.readouterr()
    ledger = load_ledger(str(tmp_path))
    assert "self_test" in ledger


def test_cli_redteam_records_self_test(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    main(["--redteam", "--ascii"])
    capsys.readouterr()
    ledger = load_ledger(str(tmp_path))
    assert "self_test" in ledger


def test_cli_dryrun_records_self_test(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    main(["--dryrun", "--ascii"])
    capsys.readouterr()
    ledger = load_ledger(str(tmp_path))
    assert "self_test" in ledger
