"""B-1013: B191 no longer calls a session divergent when its trajectory lives in SQLite.

Measured on a real OpenClaw 2026.10.10 home: no JSONL sidecars, 7 sessions in the
per-agent ``trajectory_runtime_events`` store, 41 distinct ``audit_events`` sessions. B191
reported all 41 as divergent, because it diffed ``audit_events`` against the (empty) JSONL
event set only. Now it subtracts the sessions the SQLite census found (``session_id`` only,
§8), and when that census is incomplete -- an unreadable database, a PostgreSQL engine
anchor, a read cap -- the remaining sessions are "not compared", never "divergent".

F-134 is unchanged: with trajectory genuinely off (no sidecar, no SQLite store) B191 still
fires. New explanation goes in ``fix`` only (``detail`` feeds ``baseline.fingerprint``).

Offline, stdlib only, writes only under ``tmp_path``.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from clawseccheck import trajectorystore
from clawseccheck.behavioral import analyze
from clawseccheck.catalog import PASS, WARN
from clawseccheck.collector import collect
from test_b191_audit_events import _AUDIT_EVENTS_DDL, _insert_row, _write_traj
from test_b294_cron_run_logs import _TRAJECTORY_RUNTIME_EVENTS_DDL

_ANCHOR_DDL = (
    "CREATE TABLE openclaw_engine_anchor (store_id TEXT NOT NULL, engine TEXT NOT NULL, "
    "schema TEXT NOT NULL)"
)


def _home(tmp_path: Path, audit_sessions, *, blocked: bool = False) -> Path:
    home = tmp_path / "openclaw"
    (home / "state").mkdir(parents=True)
    conn = sqlite3.connect(home / "state" / "openclaw.sqlite")
    try:
        conn.execute(_AUDIT_EVENTS_DDL)
        for i, sid in enumerate(audit_sessions):
            _insert_row(conn, i, session_id=sid)
        if blocked:
            _insert_row(conn, len(audit_sessions), session_id=audit_sessions[0],
                        status="blocked", error_code="tool_blocked")
        conn.commit()
    finally:
        conn.close()
    return home


def _agent_db(home: Path, sessions, agent: str = "main") -> Path:
    d = home / "agents" / agent / "agent"
    d.mkdir(parents=True, exist_ok=True)
    db = d / "openclaw-agent.sqlite"
    conn = sqlite3.connect(db)
    try:
        conn.execute(_TRAJECTORY_RUNTIME_EVENTS_DDL)
        for sid in sessions:
            conn.execute(
                "INSERT INTO trajectory_runtime_events (session_id, seq, run_id, event_json, "
                "created_at) VALUES (?, 1, 'r', '{}', 1)", (sid,))
        conn.commit()
    finally:
        conn.close()
    return db


def _b191(home: Path):
    return next(f for f in analyze(collect(home))["findings"] if f.id == "B191")


def test_sessions_in_sqlite_are_not_divergent_and_the_rest_still_are(tmp_path):
    home = _home(tmp_path, ["in-sqlite-a", "in-sqlite-b", "nowhere"])
    _agent_db(home, ["in-sqlite-a", "in-sqlite-b", "unrelated"])
    f = _b191(home)
    assert f.status == WARN and f.sub_signals == frozenset({"divergence"})
    assert "1 session id(s) recorded in audit_events" in f.detail
    assert [e for e in f.evidence if "divergent" in e] == ["divergent session_id: nowhere"]
    assert "2 other audit_events session(s) have their trajectory in the per-agent SQLite" in f.fix
    assert "SQLite" not in f.detail  # explanation lives in fix only


def test_every_session_in_sqlite_reads_pass_with_the_store_named(tmp_path):
    home = _home(tmp_path, ["a", "b"])
    _agent_db(home, ["a", "b"])
    f = _b191(home)
    assert f.status == PASS, f.detail
    assert "no session divergence from the trajectory sidecar" in f.detail
    assert "2 other audit_events session(s)" in f.fix


def test_sqlite_and_sidecar_sessions_combine(tmp_path):
    home = _home(tmp_path, ["jsonl-one", "sqlite-one"])
    _write_traj(home, "jsonl-one")
    _agent_db(home, ["sqlite-one"])
    assert _b191(home).status == PASS


def test_trajectory_disabled_still_fires_f134(tmp_path):
    """No sidecar, no per-agent SQLite store: a complete, empty census."""
    home = _home(tmp_path, ["orphan"])
    f = _b191(home)
    assert f.status == WARN and "divergence" in f.sub_signals
    assert "per-agent SQLite store" not in f.fix and "could not be compared" not in f.fix


def test_agent_db_without_the_trajectory_table_still_fires(tmp_path):
    home = _home(tmp_path, ["orphan"])
    d = home / "agents" / "main" / "agent"
    d.mkdir(parents=True)
    sqlite3.connect(d / "openclaw-agent.sqlite").close()
    assert "divergence" in _b191(home).sub_signals


def test_unreadable_sqlite_store_makes_the_rest_uncompared_not_divergent(tmp_path):
    home = _home(tmp_path, ["a", "b"])
    d = home / "agents" / "main" / "agent"
    d.mkdir(parents=True)
    (d / "openclaw-agent.sqlite").write_bytes(b"not a database" * 300)
    f = _b191(home)
    assert f.status == PASS
    assert "divergence" not in f.sub_signals
    assert "no session divergence" not in f.detail  # never claimed clean
    assert "2 audit_events session(s) could not be compared" in f.fix


def test_anchored_sqlite_store_is_uncompared_too(tmp_path):
    """B-1010: a per-agent store kept in PostgreSQL is not read, so not compared."""
    home = _home(tmp_path, ["a"])
    db = _agent_db(home, [])
    conn = sqlite3.connect(db)
    conn.execute(_ANCHOR_DDL)
    conn.commit()
    conn.close()
    f = _b191(home)
    assert "divergence" not in f.sub_signals
    assert "could not be compared" in f.fix


def test_one_unreadable_store_still_subtracts_what_the_readable_one_holds(tmp_path):
    home = _home(tmp_path, ["in-good", "unknown"])
    _agent_db(home, ["in-good"], agent="good")
    bad = home / "agents" / "bad" / "agent"
    bad.mkdir(parents=True)
    (bad / "openclaw-agent.sqlite").write_bytes(b"garbage" * 600)
    f = _b191(home)
    assert "divergence" not in f.sub_signals
    assert "1 other audit_events session(s) have their trajectory" in f.fix
    assert "1 audit_events session(s) could not be compared" in f.fix


def test_a_strong_signal_still_warns_beside_uncompared_sessions(tmp_path):
    home = _home(tmp_path, ["a"], blocked=True)
    d = home / "agents" / "main" / "agent"
    d.mkdir(parents=True)
    (d / "openclaw-agent.sqlite").write_bytes(b"x" * 4096)
    f = _b191(home)
    assert f.status == WARN and f.sub_signals == frozenset({"blocked"})
    assert "could not be compared" in f.fix


def test_census_reports_completeness(tmp_path):
    home = tmp_path / "h"
    home.mkdir()
    assert trajectorystore.sqlite_session_census(home) == (frozenset(), True)
    _agent_db(home, ["s1"])
    assert trajectorystore.sqlite_session_census(home) == (frozenset({"s1"}), True)
    bad = home / "agents" / "z" / "agent"
    bad.mkdir(parents=True)
    (bad / "openclaw-agent.sqlite").write_bytes(b"y" * 4096)
    assert trajectorystore.sqlite_session_census(home) == (frozenset({"s1"}), False)
    assert trajectorystore.sqlite_session_ids(home) == frozenset({"s1"})


def test_uncompared_pass_is_not_a_verified_pass(tmp_path):
    home = _home(tmp_path, ["a"])
    d = home / "agents" / "main" / "agent"
    d.mkdir(parents=True)
    (d / "openclaw-agent.sqlite").write_bytes(b"q" * 4096)
    f = _b191(home)
    assert f.status == PASS and f.pass_confidence == "no_signal"
    assert f.fix.startswith("1 audit_events session(s) could not be compared")


def test_fully_compared_pass_stays_verified(tmp_path):
    home = _home(tmp_path, ["a"])
    _agent_db(home, ["a"])
    assert _b191(home).pass_confidence == "verified"
