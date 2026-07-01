"""Tests for the --menu capability screen (clawseccheck.menu + cli wiring).

Pure render is exercised with injected ages/staleness so it is deterministic;
the CLI path is isolated to a tmp history file so it never reads the real
~/.clawseccheck/ and makes no network call.
"""
from __future__ import annotations

from datetime import date

from clawseccheck.cli import main
from clawseccheck.menu import compute_ages, render_menu


# ── pure render ───────────────────────────────────────────────────────────────

def test_render_menu_lists_the_four_items():
    out = render_menu(version="9.9.9")
    assert "🦞 ClawSecCheck · v9.9.9" in out
    for title in ("Check everything", "Check before install", "Report & history", "Menu"):
        assert title in out
    # numbered, so "say the number" works
    for n in ("1", "2", "3", "4"):
        assert f"  {n}  " in out
    # the live-agent test is disclosed up front on item 1
    assert "⚡" in out


def test_render_menu_ascii_is_pure_ascii():
    out = render_menu(version="1.2.3", stale=True, build_age_days=90, ascii_only=True)
    # encodes cleanly as ASCII — no emoji / unicode leaks through --ascii
    out.encode("ascii")
    assert "🦞" not in out and "⚡" not in out and "·" not in out
    assert "(live)" in out
    assert "Last check:" in out
    assert "Update:" in out


def test_last_check_phrasings():
    assert "not checked yet" in render_menu(version="1.0.0", last_check_days=None)
    assert "today" in render_menu(version="1.0.0", last_check_days=0)
    assert "1 day ago" in render_menu(version="1.0.0", last_check_days=1)
    assert "3 days ago" in render_menu(version="1.0.0", last_check_days=3)


def test_update_line_always_present_louder_when_stale():
    # fresh: the affordance is still shown so "update" is discoverable, but quiet
    fresh = render_menu(version="1.0.0", stale=False, build_age_days=5)
    assert "🆙" in fresh
    assert '"update"' in fresh
    assert "days old" not in fresh  # not the loud staleness phrasing

    # stale: louder, names the build age
    stale = render_menu(version="1.0.0", stale=True, build_age_days=120)
    assert "🆙" in stale
    assert "120 days old" in stale
    assert '"update"' in stale


# ── compute_ages ──────────────────────────────────────────────────────────────

def test_compute_ages_basic():
    today = date(2026, 6, 30)
    build_age, last_days = compute_ages(
        released="2026-06-20", last_check="2026-06-27", today=today)
    assert build_age == 10
    assert last_days == 3


def test_compute_ages_handles_missing_and_garbage():
    today = date(2026, 6, 30)
    assert compute_ages(released=None, last_check=None, today=today) == (None, None)
    assert compute_ages(released="not-a-date", last_check="", today=today) == (None, None)


# ── CLI wiring (isolated, offline) ────────────────────────────────────────────

def test_cli_menu_returns_zero_and_prints(tmp_path, capsys):
    rc = main(["--menu", "--history", str(tmp_path / "history.jsonl")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "ClawSecCheck" in out
    assert "Check everything" in out
    # no prior history in the tmp file → the never-checked nudge
    assert "not checked yet" in out


def test_cli_menu_ascii(tmp_path, capsys):
    rc = main(["--menu", "--ascii", "--history", str(tmp_path / "history.jsonl")])
    assert rc == 0
    out = capsys.readouterr().out
    out.encode("ascii")  # must not raise
    assert "🦞" not in out
