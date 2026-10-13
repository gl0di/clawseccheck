"""B357 (C-701) -- the supervisor restart handoff moved from a JSON file into the state DB.

On OpenClaw 2026.9.x+ the handoff lives in ``gateway_restart_handoff`` (state/openclaw.sqlite),
written and consumed through the state-DB transaction path; the dist never reads or deletes
``gateway-supervisor-restart-handoff.json``. A leftover copy of that file is therefore a
retired state file, not a crash marker, and "restart the supervisor cleanly" cannot clear it.
The real condition is a row whose own ``expires_at`` has passed.

What is pinned here:
  * the old layout (JSON only, an older or unknown build) answers byte-for-byte as before;
  * the new answer applies from 2026.10.2 on -- the one build whose dist was read -- and an
    older or unseen build keeps today's answer;
  * on a build that keeps the handoff in the table, with the table actually present in the
    state DB: a stale row WARNs with text that claims only what the dist proves (OpenClaw
    ignores an expired record; only its consume command or a one-time migration removes it),
    a live row or no row is PASS, a row expiring implausibly far ahead is UNKNOWN, a leftover
    JSON is described as a retired file and never as a crashed supervisor, a table or database
    that cannot be read (corrupt DB, a view posing as the table, a FIFO / symlink / directory
    at the DB path) is UNKNOWN and never PASS;
  * no DB or no table leaves today's answer (the new layout is not shown to be in use);
  * the reader selects one named column, bounded, oldest expiry first, and is wired into
    ``collect``.

The table DDL is read out of ``tests/state_schema_snapshot.sql`` (the vendor's own text), not
hand-written, so this fixture cannot drift from the shipped schema.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import time
from pathlib import Path

import pytest

from clawseccheck import collector as _collector
from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_restart_handoff_stale
from clawseccheck.collector import Context, _collect_restart_handoff, collect

_SNAPSHOT = Path(__file__).with_name("state_schema_snapshot.sql")
_JSON_NAME = "gateway-supervisor-restart-handoff.json"
_NEW_BUILD = "2026.10.2"
_OLD_BUILD = "2026.10.1"  # the build just below the one whose dist was read
_HOUR_MS = 3_600_000
_MIN_MS = 60_000


def _handoff_ddl() -> str:
    text = _SNAPSHOT.read_text(encoding="utf-8")
    start = "CREATE " + "TABLE IF NOT EXISTS gateway_restart_handoff"
    m = re.search(re.escape(start) + r".*?\) STRICT;", text, re.S)
    assert m, "gateway_restart_handoff is missing from tests/state_schema_snapshot.sql"
    return m.group(0)


def _now_ms() -> int:
    return int(time.time() * 1000)


def _db(home: Path) -> Path:
    state = home / "state"
    state.mkdir(parents=True, exist_ok=True)
    return state / "openclaw.sqlite"


def _make_db(home: Path, expiries=(), *, with_table: bool = True) -> Path:
    path = _db(home)
    conn = sqlite3.connect(str(path))
    try:
        if with_table:
            conn.execute(_handoff_ddl())
            for i, exp in enumerate(expiries):
                conn.execute(
                    "INSERT INTO gateway_restart_handoff (handoff_key, kind, version, "
                    "intent_id, pid, created_at, expires_at, source, restart_kind, "
                    "supervisor_mode, updated_at_ms) VALUES (?, 'gateway-supervisor-restart-"
                    "handoff', 1, ?, 4242, ?, ?, 'cli', 'graceful', 'managed', ?)",
                    (f"k{i}", f"intent-{i}", exp - 60_000, exp, exp - 60_000),
                )
        else:
            conn.execute("CREATE " + "TABLE unrelated (x INTEGER)")
        conn.commit()
    finally:
        conn.close()
    return path


def _write_json_leftover(home: Path, expires_at: int = 1782841256068) -> None:
    (home / _JSON_NAME).write_text(json.dumps({
        "kind": "gateway-supervisor-restart-handoff", "version": 1, "intentId": "abc",
        "pid": 12345, "createdAt": expires_at - 60_000, "expiresAt": expires_at,
        "reason": "config-reload", "source": "cli", "restartKind": "graceful",
        "supervisorMode": "managed",
    }))


def _run(home: Path, build: "str | None"):
    ctx = Context(home=home)
    ctx.installed_dist_version = build
    _collect_restart_handoff(home, ctx)
    return check_restart_handoff_stale(ctx), ctx


# --------------------------------------------------------------------------- old layout

_LEGACY_WARN_DETAIL = (
    "gateway-supervisor-restart-handoff.json is present and its own expiresAt "
    "(2026-06-30T"
)


@pytest.mark.parametrize("build", [
    None, "", _OLD_BUILD, "2026.8.31", "2026.9.1", "2026.9.7", "2026.10.2-beta.1", "2026.10", "garbage",
])
def test_old_or_unknown_build_json_only_keeps_todays_answer(tmp_path, build):
    _write_json_leftover(tmp_path)
    f, _ = _run(tmp_path, build)
    assert f.status == WARN
    assert f.detail.startswith(_LEGACY_WARN_DETAIL)
    assert "a crashed supervisor, most likely" in f.detail
    assert f.fix.startswith("Restart the OpenClaw gateway supervisor cleanly")


@pytest.mark.parametrize("build", [None, _OLD_BUILD])
def test_old_or_unknown_build_ignores_a_state_db_row(tmp_path, build):
    """The table is not consulted for a build that is not shown to keep the handoff there."""
    _make_db(tmp_path, [_now_ms() - _HOUR_MS])
    f, _ = _run(tmp_path, build)
    assert f.status == PASS
    assert "No gateway-supervisor-restart-handoff.json found." == f.detail


def test_old_build_no_json_no_db_is_the_old_pass(tmp_path):
    f, _ = _run(tmp_path, _OLD_BUILD)
    assert f.status == PASS
    assert f.detail == "No gateway-supervisor-restart-handoff.json found."


@pytest.mark.parametrize("build, new_answer", [
    ("2026.10.1", False),
    ("2026.10.2", True),
    ("2026.10.3", True),
    ("2026.11.0", True),
    ("2027.1.3", True),
    ("2026.9.7", False),
    ("2025.12.31", False),
    ("2026.10", False),
    ("2026.10.2-beta.1", False),
    ("not-a-version", False),
    (None, False),
])
def test_the_build_gate_boundary_is_the_build_whose_dist_was_read(tmp_path, build, new_answer):
    """The same stale row and the same leftover file: only the installed build moves the answer."""
    _make_db(tmp_path, [_now_ms() - _HOUR_MS])
    _write_json_leftover(tmp_path)
    f, _ = _run(tmp_path, build)
    assert f.status == WARN
    assert ("state database" in f.detail) is new_answer
    assert ("a crashed supervisor, most likely" in f.detail) is (not new_answer)


# --------------------------------------------------------------------------- new layout

@pytest.mark.parametrize("build", [_NEW_BUILD, "2026.10.3", "2027.1.3"])
def test_stale_row_warns_on_every_build_from_the_gate(tmp_path, build):
    _make_db(tmp_path, [_now_ms() - _HOUR_MS])
    f, ctx = _run(tmp_path, build)
    assert ctx.restart_handoff_read is True
    assert f.status == WARN
    assert "state database" in f.detail
    assert "has already passed" in f.detail


def test_stale_row_text_claims_only_what_the_dist_proves(tmp_path):
    """The dist ignores an expired record on read and removes it only through its `consume`
    command or a one-time migration: so no 'a restart clears it', no 'crashed supervisor', no
    'never completed' as fact, and no instruction to edit the database."""
    _make_db(tmp_path, [_now_ms() - _HOUR_MS])
    f, _ = _run(tmp_path, _NEW_BUILD)
    assert f.status == WARN
    text = f"{f.detail} {f.fix}".lower()
    assert "ignores" in text and "leftover" in text
    assert "restart-handoff consume" in text and "migration" in text
    for forbidden in ("clears", "crashed", "never completed", "did not complete", "delete",
                      "remove it", "restart the openclaw", "restart it", "drop "):
        assert forbidden not in text, forbidden


def test_stale_row_and_leftover_json_names_the_file_as_retired(tmp_path):
    _make_db(tmp_path, [_now_ms() - _HOUR_MS])
    _write_json_leftover(tmp_path)
    f, _ = _run(tmp_path, _NEW_BUILD)
    assert f.status == WARN
    assert "retired" in f.fix and _JSON_NAME in f.fix


def test_the_stale_row_is_judged_by_the_oldest_expiry(tmp_path):
    _make_db(tmp_path, [_now_ms() + _HOUR_MS, _now_ms() - 5 * _HOUR_MS])
    f, _ = _run(tmp_path, _NEW_BUILD)
    assert f.status == WARN


def test_live_row_is_pass_and_claims_only_that_it_has_not_expired(tmp_path):
    _make_db(tmp_path, [_now_ms() + 30_000])
    f, _ = _run(tmp_path, _NEW_BUILD)
    assert f.status == PASS
    assert "not yet expired" in f.detail
    for forbidden in ("normal", "in-progress", "in progress"):
        assert forbidden not in f.detail.lower(), forbidden


def test_a_row_expiring_implausibly_far_ahead_is_unknown(tmp_path):
    """OpenClaw's own handoff lifetime is 60 s (it rejects a longer one): a row ten minutes or
    more ahead was not written by it, so 'not yet expired' would be a false comfort."""
    _make_db(tmp_path, [_now_ms() + 9 * _MIN_MS])
    assert _run(tmp_path, _NEW_BUILD)[0].status == PASS
    for ahead in (11 * _MIN_MS, 24 * _HOUR_MS):
        sub = tmp_path / f"h{ahead}"
        sub.mkdir()
        _make_db(sub, [_now_ms() + ahead])
        f, _ = _run(sub, _NEW_BUILD)
        assert f.status == UNKNOWN, ahead
        assert "60 seconds" in f.detail


def test_table_with_no_row_and_no_file_is_pass(tmp_path):
    _make_db(tmp_path, [])
    f, ctx = _run(tmp_path, _NEW_BUILD)
    assert ctx.restart_handoff_read is True and ctx.restart_handoff_expires_at_ms == []
    assert f.status == PASS
    assert "crashed supervisor" not in f.detail


def test_leftover_json_alone_is_a_retired_file_not_a_crash_marker(tmp_path):
    """The reported bug: an expired JSON beside an empty table was a WARN 'crashed supervisor'."""
    _make_db(tmp_path, [])
    _write_json_leftover(tmp_path)  # expiresAt 2026-06-30
    f, _ = _run(tmp_path, _NEW_BUILD)
    assert f.status == PASS
    assert "retired" in f.detail and _JSON_NAME in f.detail
    assert "crashed supervisor" not in f.detail and "crashed supervisor" not in f.fix
    assert "restart" not in f.fix.lower()


def test_leftover_json_is_never_read_on_a_new_build(tmp_path):
    """Unreadable or garbage file content cannot move the verdict: the file is not consulted."""
    _make_db(tmp_path, [])
    (tmp_path / _JSON_NAME).write_text("{ not json")
    f, _ = _run(tmp_path, _NEW_BUILD)
    assert f.status == PASS


# --------------------------------------------------------------------------- cannot tell

def test_no_state_db_keeps_todays_answer(tmp_path):
    _write_json_leftover(tmp_path)
    f, ctx = _run(tmp_path, _NEW_BUILD)
    assert ctx.restart_handoff_read is False and ctx.restart_handoff_parse_error is False
    assert f.status == WARN and "a crashed supervisor, most likely" in f.detail


def test_db_without_the_table_keeps_todays_answer(tmp_path):
    """A DB that does not show the new layout in use must not retire a possibly-live file."""
    _make_db(tmp_path, with_table=False)
    _write_json_leftover(tmp_path)
    f, ctx = _run(tmp_path, _NEW_BUILD)
    assert ctx.restart_handoff_read is False and ctx.restart_handoff_parse_error is False
    assert f.status == WARN and "a crashed supervisor, most likely" in f.detail
    (tmp_path / _JSON_NAME).unlink()
    f, _ = _run(tmp_path, _NEW_BUILD)
    assert f.status == PASS and f.detail == "No gateway-supervisor-restart-handoff.json found."


@pytest.mark.parametrize("with_json", [False, True])
def test_a_corrupt_state_db_is_unknown_never_pass(tmp_path, with_json):
    _db(tmp_path).write_bytes(b"this is not a sqlite database " * 40)
    if with_json:
        _write_json_leftover(tmp_path)
    f, ctx = _run(tmp_path, _NEW_BUILD)
    assert ctx.restart_handoff_parse_error is True and ctx.restart_handoff_read is False
    assert f.status == UNKNOWN
    assert "state database" in f.detail


def test_a_view_posing_as_the_table_is_unknown_never_pass(tmp_path):
    """A crafted view of that name would otherwise answer 'live handoff' from attacker SQL."""
    path = _db(tmp_path)
    conn = sqlite3.connect(str(path))
    try:
        conn.execute(
            "CREATE " + "VIEW gateway_restart_handoff AS SELECT 99999999999999 AS expires_at"
        )
        conn.commit()
    finally:
        conn.close()
    f, ctx = _run(tmp_path, _NEW_BUILD)
    assert ctx.restart_handoff_parse_error is True
    assert f.status == UNKNOWN


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs POSIX FIFOs")
def test_a_fifo_at_the_db_path_neither_hangs_nor_passes(tmp_path):
    os.mkfifo(_db(tmp_path))
    box: dict = {}

    def target():
        box["result"] = _run(tmp_path, _NEW_BUILD)

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(15)
    assert not t.is_alive(), "reading a FIFO at state/openclaw.sqlite hung the collector"
    f, ctx = box["result"]
    assert ctx.restart_handoff_parse_error is True
    assert f.status == UNKNOWN


@pytest.mark.parametrize("bad", ["soon", True, None, 1.5e300])
def test_a_malformed_expiry_is_unknown(bad):
    ctx = Context(home=Path("/nonexistent-c701-home"))
    ctx.installed_dist_version = _NEW_BUILD
    ctx.restart_handoff_read = True
    ctx.restart_handoff_expires_at_ms = [bad]
    assert check_restart_handoff_stale(ctx).status == UNKNOWN


@pytest.mark.parametrize("with_json", [False, True])
def test_a_symlinked_state_db_is_unknown_not_the_old_answer(tmp_path, with_json):
    real = tmp_path / "relocated"
    real.mkdir()
    target = _make_db(real, [])
    home = tmp_path / "home"
    (home / "state").mkdir(parents=True)
    os.symlink(target, home / "state" / "openclaw.sqlite")
    if with_json:
        _write_json_leftover(home)
    f, ctx = _run(home, _NEW_BUILD)
    assert ctx.restart_handoff_parse_error is True and ctx.restart_handoff_read is False
    assert f.status == UNKNOWN
    assert "symlink" in " ".join(ctx.errors)


def test_a_directory_at_the_state_db_path_is_unknown(tmp_path):
    (tmp_path / "state" / "openclaw.sqlite").mkdir(parents=True)
    _write_json_leftover(tmp_path)
    f, ctx = _run(tmp_path, _NEW_BUILD)
    assert ctx.restart_handoff_parse_error is True
    assert f.status == UNKNOWN


def test_a_state_path_that_is_a_file_or_dangling_link_is_unknown(tmp_path):
    (tmp_path / "state").write_text("not a directory")
    _write_json_leftover(tmp_path)
    f, ctx = _run(tmp_path, _NEW_BUILD)
    assert ctx.restart_handoff_parse_error is True and f.status == UNKNOWN
    other = tmp_path / "other"
    other.mkdir()
    os.symlink(other / "nowhere", other / "state")
    f, ctx = _run(other, _NEW_BUILD)
    assert ctx.restart_handoff_parse_error is True and f.status == UNKNOWN


def test_a_symlinked_state_directory_holding_a_real_database_is_read_normally(tmp_path):
    """A relocated state directory (symlink to a directory) is how users move it; the database
    inside is an ordinary file and is read, not refused."""
    real = tmp_path / "relocated"
    real.mkdir()
    _make_db(real, [_now_ms() - _HOUR_MS])
    home = tmp_path / "home"
    home.mkdir()
    os.symlink(real / "state", home / "state")
    f, ctx = _run(home, _NEW_BUILD)
    assert ctx.restart_handoff_read is True and f.status == WARN


def test_a_symlinked_state_db_on_an_old_build_keeps_the_old_answer(tmp_path):
    """The new reading is gated on the build; an old build never looks at the database."""
    real = tmp_path / "relocated"
    real.mkdir()
    target = _make_db(real, [])
    home = tmp_path / "home"
    (home / "state").mkdir(parents=True)
    os.symlink(target, home / "state" / "openclaw.sqlite")
    _write_json_leftover(home)
    f, _ = _run(home, _OLD_BUILD)
    assert f.status == WARN and "a crashed supervisor, most likely" in f.detail


# --------------------------------------------------------------------------- the reader

def test_the_reader_selects_one_named_column_bounded_oldest_first(tmp_path, monkeypatch):
    """No SELECT *, only expires_at, a LIMIT: the stale row survives a padded table."""
    cap = _collector._MAX_RESTART_HANDOFF_ROWS
    future = _now_ms() + _HOUR_MS
    _make_db(tmp_path, [future + i for i in range(cap * 4)] + [_now_ms() - _HOUR_MS])

    statements: list = []
    real_connect = sqlite3.connect

    def spy(*a, **kw):
        conn = real_connect(*a, **kw)
        conn.set_trace_callback(statements.append)
        return conn

    monkeypatch.setattr(_collector.sqlite3, "connect", spy)
    f, ctx = _run(tmp_path, _NEW_BUILD)
    # The `_table_kind` schema probes read sqlite_master, not the table: only statements that
    # read the handoff table's own rows are held to the one-named-column rule.
    selects = [s for s in statements if "FROM gateway_restart_handoff" in s]
    assert selects, statements
    for s in selects:
        assert "*" not in s
        assert re.fullmatch(
            r"SELECT expires_at FROM gateway_restart_handoff ORDER BY expires_at ASC LIMIT \d+",
            s.strip(),
        )
    assert len(ctx.restart_handoff_expires_at_ms) == cap
    assert f.status == WARN  # the one stale row sorted first, inside the cap


def test_collect_fills_the_fields_end_to_end(tmp_path):
    """Wiring, not the helper: a full collect over a home reaches the reader."""
    _make_db(tmp_path, [_now_ms() - _HOUR_MS])
    ctx = collect(tmp_path)
    assert ctx.restart_handoff_read is True
    assert len(ctx.restart_handoff_expires_at_ms) == 1
    ctx.installed_dist_version = _NEW_BUILD
    assert check_restart_handoff_stale(ctx).status == WARN
