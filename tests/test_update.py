"""Offline update advisory (clawseccheck.update) + its CLI wiring.

Golden rule: this feature must never make a network call. It reads only the local clock and an
optional LOCAL hint file. The hint file is untrusted, so a planted version must not inject text.
All tests are deterministic via injected `today` / `latest_path` and a monkeypatched HOME.
"""
import json
from datetime import date
from pathlib import Path

from clawseccheck.cli import main
from clawseccheck.report import render_report
from clawseccheck.scoring import compute
from clawseccheck.update import (
    AGE_NUDGE_DAYS, _clean_version, _ver_tuple, read_latest_hint, update_notice,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
NOWHERE = "/nonexistent/clawseccheck/latest.json"


# ---------------------------------------------------------------------------
# version parsing / sanitization
# ---------------------------------------------------------------------------

def test_ver_tuple_parses_semver():
    assert _ver_tuple("1.2.0") == (1, 2, 0)
    assert _ver_tuple("10.0.34") == (10, 0, 34)


def test_ver_tuple_rejects_junk():
    assert _ver_tuple("nightly") is None
    assert _ver_tuple("1.2") is None  # needs three components
    assert _ver_tuple(None) is None


def test_clean_version_strips_injection():
    # match() sees the leading semver; reconstruction from ints discards the rest.
    assert _clean_version("5.0.0; rm -rf ~ #pwn") == "5.0.0"
    assert _clean_version("\x1b[31m9.9.9") is None  # control prefix -> no leading semver


# ---------------------------------------------------------------------------
# read_latest_hint — tolerant, sanitizing, no network
# ---------------------------------------------------------------------------

def test_hint_missing_file_is_none():
    assert read_latest_hint(NOWHERE) is None


def test_hint_malformed_json_is_none(tmp_path):
    p = tmp_path / "latest.json"
    p.write_text("{not json", encoding="utf-8")
    assert read_latest_hint(str(p)) is None


def test_hint_non_dict_is_none(tmp_path):
    p = tmp_path / "latest.json"
    p.write_text('["1.2.0"]', encoding="utf-8")
    assert read_latest_hint(str(p)) is None


def test_hint_valid_returns_clean_version(tmp_path):
    p = tmp_path / "latest.json"
    p.write_text(json.dumps({"version": "2.3.4", "published": "2026-12-01"}), encoding="utf-8")
    assert read_latest_hint(str(p)) == "2.3.4"


def test_hint_injection_is_sanitized(tmp_path):
    p = tmp_path / "latest.json"
    p.write_text(json.dumps({"version": "5.0.0; rm -rf ~"}), encoding="utf-8")
    assert read_latest_hint(str(p)) == "5.0.0"


# ---------------------------------------------------------------------------
# update_notice — priority + offline behavior
# ---------------------------------------------------------------------------

def _write_hint(tmp_path, version):
    p = tmp_path / "latest.json"
    p.write_text(json.dumps({"version": version}), encoding="utf-8")
    return str(p)


def test_notice_hint_newer_is_announced(tmp_path):
    lines = update_notice("1.2.0", latest_path=_write_hint(tmp_path, "1.3.0"),
                          today=date(2026, 6, 22))
    assert lines and "newer ClawSecCheck is available: v1.3.0" in lines[0]
    assert any("no network call" in ln for ln in lines)


def test_notice_hint_same_or_older_is_silent(tmp_path):
    assert update_notice("1.2.0", latest_path=_write_hint(tmp_path, "1.2.0"),
                         today=date(2026, 6, 22)) == []
    assert update_notice("1.2.0", latest_path=_write_hint(tmp_path, "1.0.0"),
                         today=date(2026, 6, 22)) == []


def test_notice_age_nudge_when_old_and_no_hint():
    lines = update_notice("1.2.0", released="2026-01-01", latest_path=NOWHERE,
                          today=date(2026, 6, 22))
    assert lines and "172 days old" in lines[0]


def test_notice_fresh_build_is_silent():
    assert update_notice("1.2.0", released="2026-06-22", latest_path=NOWHERE,
                         today=date(2026, 6, 22)) == []


def test_notice_exactly_at_threshold_fires():
    released = date(2026, 1, 1)
    day_before = date.fromordinal(released.toordinal() + AGE_NUDGE_DAYS - 1)
    on_threshold = date.fromordinal(released.toordinal() + AGE_NUDGE_DAYS)
    assert update_notice("1.2.0", released=released.isoformat(), latest_path=NOWHERE,
                         today=day_before) == []
    fire = update_notice("1.2.0", released=released.isoformat(), latest_path=NOWHERE,
                         today=on_threshold)
    assert fire and "days old" in fire[0]


def test_notice_clock_skew_is_silent():
    # local clock earlier than release date -> negative age -> no nudge
    assert update_notice("1.2.0", released="2026-06-22", latest_path=NOWHERE,
                         today=date(2026, 1, 1)) == []


def test_notice_hint_beats_age(tmp_path):
    # a present newer hint wins even on an old build (precise > heuristic)
    lines = update_notice("1.2.0", released="2020-01-01",
                          latest_path=_write_hint(tmp_path, "1.5.0"), today=date(2026, 6, 22))
    assert "v1.5.0" in lines[0]


# ---------------------------------------------------------------------------
# render_report wiring — notice only when passed
# ---------------------------------------------------------------------------

def _score_and_findings():
    from clawseccheck import collect, run_all
    ctx = collect(str(FIXTURES / "home_safe"))
    findings = run_all(ctx)
    return findings, compute(findings)


def test_render_report_omits_notice_by_default():
    findings, score = _score_and_findings()
    assert "newer ClawSecCheck" not in render_report(findings, score)


def test_render_report_appends_notice_when_given():
    findings, score = _score_and_findings()
    out = render_report(findings, score, update_notice=["A newer ClawSecCheck is available: v9.9.9"])
    assert "A newer ClawSecCheck is available: v9.9.9" in out


# ---------------------------------------------------------------------------
# CLI wiring — HOME-scoped hint, suppression, machine-output exemption
# ---------------------------------------------------------------------------

def _home_with_hint(tmp_path, version):
    d = tmp_path / ".clawseccheck"
    d.mkdir(parents=True, exist_ok=True)
    (d / "latest.json").write_text(json.dumps({"version": version}), encoding="utf-8")


def test_cli_default_report_shows_hint(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    _home_with_hint(tmp_path, "99.0.0")
    main(["--home", str(FIXTURES / "home_safe"), "--no-native", "--no-host", "--no-history"])
    assert "A newer ClawSecCheck is available: v99.0.0" in capsys.readouterr().out


def test_cli_no_update_notice_flag_suppresses(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    _home_with_hint(tmp_path, "99.0.0")
    main(["--home", str(FIXTURES / "home_safe"), "--no-native", "--no-host", "--no-history",
          "--no-update-notice"])
    assert "newer ClawSecCheck" not in capsys.readouterr().out


def test_cli_env_var_suppresses(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("CLAWSECCHECK_NO_UPDATE_NOTICE", "1")
    _home_with_hint(tmp_path, "99.0.0")
    main(["--home", str(FIXTURES / "home_safe"), "--no-native", "--no-host", "--no-history"])
    assert "newer ClawSecCheck" not in capsys.readouterr().out


def test_cli_json_is_exempt_from_notice(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    _home_with_hint(tmp_path, "99.0.0")
    main(["--home", str(FIXTURES / "home_safe"), "--no-native", "--no-host", "--no-history",
          "--json"])
    assert "newer ClawSecCheck" not in capsys.readouterr().out


def test_b110_future_release_date_clamps_age_no_negative(tmp_path):
    """B-110: a build 'released' date in the future (backward clock skew) must not produce
    a negative age. The age is clamped at 0, so the nudge stays silent and no absurd
    negative-age line is ever emitted."""
    missing = str(tmp_path / "no-hint.json")  # hint branch must not fire
    # today is BEFORE the release date -> raw (today - rel).days is negative.
    lines = update_notice("3.19.0", released="2030-01-01",
                          today=date(2026, 7, 5), latest_path=missing)
    assert lines == [], f"expected no advisory for a future-dated build, got {lines}"
    # Defensive: even if a line were emitted, it must never carry a negative day count.
    assert not any("-" in ln and "days old" in ln for ln in lines)


def test_b110_old_build_still_nudges(tmp_path):
    """B-110 regression guard: clamping must not suppress a genuinely-old build's nudge."""
    missing = str(tmp_path / "no-hint.json")
    old = date(2026, 7, 5).replace(year=2025)  # ~1 year old > AGE_NUDGE_DAYS
    lines = update_notice("3.19.0", released=old.isoformat(),
                          today=date(2026, 7, 5), latest_path=missing)
    assert lines and any("days old" in ln for ln in lines)
