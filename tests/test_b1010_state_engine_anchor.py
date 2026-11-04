"""B-1010: a state database that OpenClaw moved to PostgreSQL is not read as if current.

Grounded in the installed OpenClaw 2026.10.10 dist (vendor code executed, not only read):

* ``database.engine`` is resolved from config only (``resolveDatabaseEngineInput``,
  ``config-*.mjs``): unset/``sqlite`` -> no engine input, ``postgres`` -> a DSN from
  ``database.postgres.connection``. No environment override exists.
* The core state store (``state/openclaw.sqlite``) does NOT move in 2026.10.10:
  ``isStatePostgres()`` is hard-wired ``return false`` and ``stateEngineInput()`` returns
  nothing, so it stays live SQLite even with ``database.engine: postgres``. The doctor
  itself says "Stores without a registered PostgreSQL schema remain on SQLite"; the only
  store that moves is the Workboard plugin's, which this audit never reads. Gating the
  state readers on the CONFIG value would therefore turn real verdicts into UNKNOWN on a
  store that is still authoritative -- the config is deliberately not used.
* The physical, per-store signal is the engine ANCHOR: when a store is moved, the vendor
  replaces its SQLite file with one holding only ``openclaw_engine_anchor``, and refuses
  to open any file carrying that table as SQLite ("This store lives in PostgreSQL schema
  ..."). It also refuses to switch a file that still holds data, so a stale-data file
  under a live PostgreSQL store is not a state the vendor produces; a file that has the
  anchor beside rows is still not live SQLite data. ``inspectStateSqlite`` counts only a
  REAL table with the exact name -- a view, a trigger or an upper-case table is not an
  anchor (checked against the vendor function on probe files), so none of those may
  blind the readers either.

Offline, stdlib only, writes only under ``tmp_path``.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from clawseccheck import trajectorystore
from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_paired_device_operator_authority, run_all
from clawseccheck.collector import _connect_state_db, collect
from test_b176_paired_devices_sqlite_migration import _make_state_db, _token

_ANCHOR_DDL = (
    "CREATE TABLE openclaw_engine_anchor (store_id TEXT NOT NULL, engine TEXT NOT NULL "
    "CHECK (engine = 'postgres'), schema TEXT NOT NULL)"
)
_RISKY_ROW = {
    "device_id": "pg-era-device",
    "platform": "linux",
    "scopes": ["operator.admin"],
    "tokens": {"operator": {"token": _token("P"), "role": "operator"}},
    "last_seen_at_ms": 1751000000000,
}
# Every check the anchor-only home moved off PASS (measured with a before/after diff of
# the whole audit; the ids that DID change nowhere else -- B188 is a file-mode check that
# never opens the database, so its PASS on the anchor file stays true).
_STATE_DERIVED = ("B138", "B168", "B172", "B176", "B396")


def _home(tmp_path: Path, config: dict | None = None) -> Path:
    home = tmp_path / "h"
    home.mkdir()
    (home / "openclaw.json").write_text(json.dumps(config or {}), encoding="utf-8")
    return home


def _add_anchor(db: Path, *, rows: bool = True) -> None:
    conn = sqlite3.connect(db)
    try:
        conn.execute(_ANCHOR_DDL)
        if rows:
            conn.execute(
                "INSERT INTO openclaw_engine_anchor VALUES ('store-uuid', 'postgres', 'openclaw')")
        conn.commit()
    finally:
        conn.close()


def _anchor_only(home: Path) -> Path:
    state = home / "state"
    state.mkdir(parents=True, exist_ok=True)
    db = state / "openclaw.sqlite"
    _add_anchor(db)
    return db


def _probe(tmp_path: Path, name: str, sql: str) -> Path:
    db = tmp_path / name
    conn = sqlite3.connect(db)
    conn.executescript(sql)
    conn.commit()
    conn.close()
    return db


# ---------------------------------------------------------------- the anchor test itself

@pytest.mark.parametrize("name,sql,expected", [
    ("anchor_row", _ANCHOR_DDL + ";INSERT INTO openclaw_engine_anchor VALUES('u','postgres','s');", True),
    ("anchor_empty", _ANCHOR_DDL + ";", True),
    ("anchor_beside_data", _ANCHOR_DDL + ";CREATE TABLE cron_jobs(x);", True),
    ("plain", "CREATE TABLE cron_jobs(x);", False),
    ("view", "CREATE TABLE cron_jobs(x); CREATE VIEW openclaw_engine_anchor AS SELECT 1 AS a;", False),
    ("upper_case", "CREATE TABLE OPENCLAW_ENGINE_ANCHOR (a TEXT); CREATE TABLE cron_jobs(x);", False),
    ("trigger", "CREATE TABLE cron_jobs(x); CREATE TRIGGER openclaw_engine_anchor AFTER INSERT "
                "ON cron_jobs BEGIN SELECT 1; END;", False),
])
def test_has_engine_anchor_mirrors_the_vendor_inspection(tmp_path, name, sql, expected):
    conn = sqlite3.connect(_probe(tmp_path, f"{name}.sqlite", sql))
    try:
        assert trajectorystore.has_engine_anchor(conn) is expected
    finally:
        conn.close()


def test_both_openers_refuse_an_anchor_with_a_plain_reason(tmp_path):
    db = _anchor_only(tmp_path)
    for opener in (_connect_state_db, trajectorystore._open_readonly):
        with pytest.raises(sqlite3.OperationalError) as exc:
            opener(db)
        message = str(exc.value)
        assert "PostgreSQL" in message and "not read" in message
        # Every reader treats "no such table" as a quiet absence; this must never match.
        assert "no such table" not in message.lower()


def test_both_openers_still_open_an_ordinary_state_db(tmp_path):
    _make_state_db(tmp_path / "state", [])
    db = tmp_path / "state" / "openclaw.sqlite"
    for opener in (_connect_state_db, trajectorystore._open_readonly):
        conn = opener(db)
        conn.close()


# ---------------------------------------------------------------- whole-audit verdicts

def test_anchor_only_state_db_is_unknown_never_pass(tmp_path):
    home = _home(tmp_path)
    _anchor_only(home)
    ctx = collect(home)
    by_id = {f.id: f for f in run_all(ctx)}
    for cid in _STATE_DERIVED:
        assert by_id[cid].status == UNKNOWN, (cid, by_id[cid].status, by_id[cid].detail)
    assert any("PostgreSQL" in e for e in ctx.errors)


def test_anchor_beside_a_risky_row_does_not_read_the_row(tmp_path):
    """The task's fixture: engine postgres, and a SQLite file whose rows are not live.
    The stale paired device must not drive a verdict either way -- UNKNOWN, not WARN."""
    home = _home(tmp_path, {"database": {"engine": "postgres"}})
    _make_state_db(home / "state", [_RISKY_ROW])
    _add_anchor(home / "state" / "openclaw.sqlite")
    finding = check_paired_device_operator_authority(collect(home))
    assert finding.status == UNKNOWN, finding.detail
    assert not any("pg-era-device" in e for e in finding.evidence)


def test_an_empty_anchor_table_still_counts(tmp_path):
    """The vendor refuses a file whose anchor table has no row too (its ``schema``
    projection wraps ``.get()`` in an array, which is always truthy)."""
    home = _home(tmp_path)
    _make_state_db(home / "state", [_RISKY_ROW])
    _add_anchor(home / "state" / "openclaw.sqlite", rows=False)
    assert check_paired_device_operator_authority(collect(home)).status == UNKNOWN


@pytest.mark.parametrize("config", [
    {},
    {"database": {"engine": "sqlite"}},
    # 2026.10.10 keeps the core state store on SQLite under engine postgres: the file is
    # authoritative, so its verdict must not be hidden behind UNKNOWN.
    {"database": {"engine": "postgres", "postgres": {"schemaPrefix": "openclaw"}}},
])
def test_without_an_anchor_the_verdict_is_unchanged_whatever_the_engine(tmp_path, config):
    home = _home(tmp_path, config)
    _make_state_db(home / "state", [_RISKY_ROW])
    assert check_paired_device_operator_authority(collect(home)).status == WARN


def test_a_planted_view_named_like_the_anchor_does_not_blind_the_readers(tmp_path):
    home = _home(tmp_path)
    _make_state_db(home / "state", [_RISKY_ROW])
    conn = sqlite3.connect(home / "state" / "openclaw.sqlite")
    conn.execute("CREATE VIEW openclaw_engine_anchor AS SELECT 'u' AS store_id")
    conn.commit()
    conn.close()
    assert check_paired_device_operator_authority(collect(home)).status == WARN


def test_clean_state_db_without_anchor_still_passes(tmp_path):
    home = _home(tmp_path)
    _make_state_db(home / "state", [])
    assert check_paired_device_operator_authority(collect(home)).status == PASS
