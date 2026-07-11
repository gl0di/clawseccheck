"""Tests for the pre-scan mode preference (clawseccheck.prescan) — C-103.

Covers:
  - record_mode / read_last_mode round-trip (tmp_path only, never real HOME)
  - read_last_mode fails safe to "quick" on any unusable state: absent file,
    malformed JSON, non-object payload, out-of-enum stored value
  - record_mode silently ignores an invalid mode (writes nothing / leaves
    prior state untouched)
  - Offline and read-only (no network, no writes outside tmp_path)
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.prescan import DEFAULT_MODE, MODES, read_last_mode, record_mode


def _prescan_file(home: Path) -> Path:
    return home / ".clawseccheck" / "prescan.json"


# ---------------------------------------------------------------------------
# record_mode + read_last_mode round-trip
# ---------------------------------------------------------------------------

def test_round_trip_valid_non_default_mode(tmp_path):
    assert "deeper" in MODES
    record_mode("deeper", home=str(tmp_path))
    assert read_last_mode(home=str(tmp_path)) == "deeper"


def test_round_trip_each_known_mode(tmp_path):
    for mode in MODES:
        record_mode(mode, home=str(tmp_path))
        assert read_last_mode(home=str(tmp_path)) == mode


def test_record_mode_overwrites_previous_value(tmp_path):
    record_mode("full", home=str(tmp_path))
    record_mode("whatchanged", home=str(tmp_path))
    assert read_last_mode(home=str(tmp_path)) == "whatchanged"


def test_prescan_written_to_tmp_only(tmp_path):
    """record_mode must not touch the real HOME (writes only under tmp_path)."""
    record_mode("deeper", home=str(tmp_path))
    assert _prescan_file(tmp_path).exists()
    assert read_last_mode(home=str(tmp_path)) == "deeper"


# ---------------------------------------------------------------------------
# read_last_mode fails safe to "quick" ("quick" is DEFAULT_MODE)
# ---------------------------------------------------------------------------

def test_default_mode_is_quick():
    assert DEFAULT_MODE == "quick"


def test_absent_state_returns_quick(tmp_path):
    assert not _prescan_file(tmp_path).exists()
    assert read_last_mode(home=str(tmp_path)) == "quick"


def test_malformed_json_returns_quick(tmp_path):
    p = _prescan_file(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{not json", encoding="utf-8")
    assert read_last_mode(home=str(tmp_path)) == "quick"


def test_non_object_payload_returns_quick(tmp_path):
    p = _prescan_file(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text('["quick"]', encoding="utf-8")
    assert read_last_mode(home=str(tmp_path)) == "quick"


def test_unknown_enum_value_returns_quick(tmp_path):
    p = _prescan_file(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text('{"last_mode": "turbo"}', encoding="utf-8")
    assert read_last_mode(home=str(tmp_path)) == "quick"


def test_non_string_mode_value_returns_quick(tmp_path):
    p = _prescan_file(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text('{"last_mode": 123}', encoding="utf-8")
    assert read_last_mode(home=str(tmp_path)) == "quick"


def test_missing_key_returns_quick(tmp_path):
    p = _prescan_file(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text('{"other_key": "deeper"}', encoding="utf-8")
    assert read_last_mode(home=str(tmp_path)) == "quick"


# ---------------------------------------------------------------------------
# record_mode with an invalid mode: no-op
# ---------------------------------------------------------------------------

def test_record_mode_invalid_mode_writes_nothing(tmp_path):
    record_mode("turbo", home=str(tmp_path))
    assert not _prescan_file(tmp_path).exists()
    assert read_last_mode(home=str(tmp_path)) == "quick"


def test_record_mode_invalid_mode_leaves_prior_state(tmp_path):
    record_mode("full", home=str(tmp_path))
    before = _prescan_file(tmp_path).read_text(encoding="utf-8")
    record_mode("turbo", home=str(tmp_path))
    after = _prescan_file(tmp_path).read_text(encoding="utf-8")
    assert before == after
    assert read_last_mode(home=str(tmp_path)) == "full"


# ---------------------------------------------------------------------------
# default HOME expansion (no home= override) — must not touch real ~
# ---------------------------------------------------------------------------

def test_default_home_expansion_uses_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    record_mode("deeper")
    assert read_last_mode() == "deeper"
    assert _prescan_file(tmp_path).exists()
