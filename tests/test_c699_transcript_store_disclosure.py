"""C-699: B164 and B19 must not read as covering the SQLite session-transcript store.

On current OpenClaw the live transcripts are rows of ``transcript_events`` in each agent's
``openclaw-agent.sqlite``, not files. Owner ruling: DISCLOSE ONLY - count rows and
sessions, never select a payload column, name the store in B164's text and in the run's
``not_checked``, and say in B19 where the transcripts are. The verdict is unchanged (the
B-817 trajectory precedent: a PASS keeps its disclosure, an empty sink list stays UNKNOWN).

DDL is built with an f-string on purpose: tests/test_state_schema_grounding.py's DDL census
reads plain string constants only.
"""
from __future__ import annotations

import os
import sqlite3
import threading
from pathlib import Path

import pytest

from clawseccheck import pipeline as pl
from clawseccheck import trajectorystore as ts
from clawseccheck.catalog import PASS, UNKNOWN
from clawseccheck.checks import check_data_atrest, check_log_threat_hunt
from clawseccheck.collector import Context

TABLE = ts.TRANSCRIPT_TABLE_NAME
# Assembled at run time so no contiguous secret-shaped literal exists in the source.
CANARY = "".join(("sk-", "ant-", "c699", "canary", "0123456789"))

_REAL_COLUMNS = (
    "session_id TEXT NOT NULL, seq INTEGER NOT NULL, event_json TEXT, "
    "created_at INTEGER NOT NULL, event_zstd BLOB, event_utf8_bytes INTEGER, "
    "navigation_json TEXT, PRIMARY KEY (session_id, seq)"
)


def _ctx(home: Path) -> Context:
    return Context(home=home, config={})


def _agent_db_path(home: Path, agent: str) -> Path:
    agent_dir = home / "agents" / agent / "agent"
    agent_dir.mkdir(parents=True, exist_ok=True)
    return agent_dir / "openclaw-agent.sqlite"


def _add_transcript_db(home: Path, agent: str, rows=(), *, table: str = TABLE,
                       columns: str = _REAL_COLUMNS) -> Path:
    """A per-agent database carrying the real 2026.10.2 ``transcript_events`` shape.
    *rows* are ``(session_id, seq)``; every payload column holds the canary."""
    db_path = _agent_db_path(home, agent)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(f"CREATE TABLE {table} ({columns})")
        for session_id, seq in rows:
            conn.execute(
                f"INSERT INTO {table} VALUES (?,?,?,?,?,?,?)",
                (session_id, seq, CANARY, 0, CANARY.encode(), len(CANARY), CANARY),
            )
        conn.commit()
    finally:
        conn.close()
    return db_path


def _add_log_sink(home: Path) -> None:
    logs = home / "logs"
    logs.mkdir(exist_ok=True)
    (logs / "app.log").write_text("the agent read three files and summarized them\n",
                                  encoding="utf-8")


ROWS_A = [("s1", 0), ("s1", 1), ("s1", 2), ("s2", 0)]   # 4 rows, 2 sessions
ROWS_B = [("t1", 0), ("t1", 1)]                          # 2 rows, 1 session


# ----------------------------------------------------------------------- the reader
def test_summary_counts_rows_and_sessions_across_agents(tmp_path):
    _add_transcript_db(tmp_path, "main", ROWS_A)
    _add_transcript_db(tmp_path, "other", ROWS_B)
    s = ts.transcript_store_summary(tmp_path)
    assert (s.rows, s.sessions, s.dbs_found, s.dbs_counted) == (6, 3, 2, 2)
    assert s.dbs_unexamined == 0


def test_summary_of_a_database_that_predates_the_table_is_an_honest_zero(tmp_path):
    _add_transcript_db(tmp_path, "main", ROWS_A, table="unrelated_table")
    s = ts.transcript_store_summary(tmp_path)
    assert (s.rows, s.sessions, s.dbs_counted, s.dbs_unexamined) == (0, 0, 1, 0)


def test_summary_without_a_home_or_databases_is_empty(tmp_path):
    assert ts.transcript_store_summary(None) == ts.TranscriptStoreSummary()
    assert ts.transcript_store_summary(tmp_path) == ts.TranscriptStoreSummary()


def test_the_reader_never_names_a_payload_column_and_never_changes_the_files(tmp_path, monkeypatch):
    db_path = _add_transcript_db(tmp_path, "main", ROWS_A)
    before_files = sorted(p.name for p in db_path.parent.iterdir())
    before_bytes = db_path.read_bytes()
    seen: list = []
    real_open = ts._open_readonly

    def spying_open(path):
        conn = real_open(path)
        conn.set_trace_callback(seen.append)
        return conn

    monkeypatch.setattr(ts, "_open_readonly", spying_open)
    s = ts.transcript_store_summary(tmp_path)
    assert s.rows == 4
    # positive control: the spy saw the count statement, so an empty payload list means something
    assert any(TABLE in stmt for stmt in seen), seen
    for stmt in seen:
        low = stmt.lower()
        assert "event_json" not in low and "event_zstd" not in low, stmt
        assert "navigation_json" not in low, stmt
    assert sorted(p.name for p in db_path.parent.iterdir()) == before_files
    assert db_path.read_bytes() == before_bytes


def test_a_view_named_like_the_table_is_incomplete_not_zero(tmp_path):
    db_path = _add_transcript_db(tmp_path, "main", ROWS_A, table="backing_rows")
    conn = sqlite3.connect(db_path)
    conn.execute(f"CREATE VIEW {TABLE} AS SELECT session_id, seq FROM backing_rows")
    conn.commit()
    conn.close()
    s = ts.transcript_store_summary(tmp_path)
    assert (s.rows, s.dbs_unreadable, s.dbs_unexamined) == (0, 1, 1)


def test_a_generated_column_table_is_incomplete_not_zero(tmp_path):
    cols = ("session_id TEXT NOT NULL, seq INTEGER NOT NULL, "
            "event_json TEXT GENERATED ALWAYS AS (session_id) VIRTUAL, "
            "created_at INTEGER NOT NULL")
    db_path = _agent_db_path(tmp_path, "main")
    conn = sqlite3.connect(db_path)
    conn.execute(f"CREATE TABLE {TABLE} ({cols})")
    conn.execute(f"INSERT INTO {TABLE} (session_id, seq, created_at) VALUES ('s',0,0)")
    conn.commit()
    conn.close()
    s = ts.transcript_store_summary(tmp_path)
    assert (s.rows, s.dbs_unexamined) == (0, 1)


def test_an_unreadable_database_file_is_incomplete_not_zero(tmp_path):
    _agent_db_path(tmp_path, "main").write_bytes(b"this is not a sqlite database" * 20)
    s = ts.transcript_store_summary(tmp_path)
    assert (s.rows, s.dbs_unreadable, s.dbs_unexamined) == (0, 1, 1)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs POSIX named pipes")
def test_a_fifo_in_place_of_the_database_is_refused_without_hanging(tmp_path):
    os.mkfifo(_agent_db_path(tmp_path, "main"))
    result: list = []
    worker = threading.Thread(
        target=lambda: result.append(ts.transcript_store_summary(tmp_path)), daemon=True)
    worker.start()
    worker.join(15)
    assert not worker.is_alive(), "the reader blocked on a FIFO"
    assert result[0].dbs_unexamined == 1 and result[0].rows == 0


def test_the_incognito_database_is_not_opened_or_counted(tmp_path):
    """The vendor's incognito database is an in-memory sentinel path, not an on-disk
    store (grounded against 2026.10.2); a file there is never counted."""
    main_db = _add_transcript_db(tmp_path, "main", ROWS_B)
    incognito = main_db.parent / "incognito-openclaw-agent.sqlite"
    conn = sqlite3.connect(incognito)
    conn.execute(f"CREATE TABLE {TABLE} ({_REAL_COLUMNS})")
    conn.execute(f"INSERT INTO {TABLE} VALUES ('x',0,NULL,0,NULL,NULL,NULL)")
    conn.commit()
    conn.close()
    s = ts.transcript_store_summary(tmp_path)
    assert (s.rows, s.dbs_found) == (2, 1)


# --------------------------------------------------------------------------- B164
def test_b164_sqlite_only_transcripts_pass_with_the_count_and_no_content(tmp_path):
    _add_transcript_db(tmp_path, "main", ROWS_A)
    _add_log_sink(tmp_path)          # a scanned sink, but no transcript FILE and no sidecar
    f = check_log_threat_hunt(_ctx(tmp_path))
    assert f.status == PASS
    assert "4 transcript row(s) across 2 session(s) unexamined" in f.detail
    assert "transcript_events" in f.detail
    assert "incognito-openclaw-agent.sqlite" in f.detail and "not examined" in f.detail
    assert CANARY not in f.detail and CANARY not in (f.fix or "")


def test_b164_no_sinks_stays_unknown_and_still_discloses(tmp_path):
    _add_transcript_db(tmp_path, "main", ROWS_A)
    f = check_log_threat_hunt(_ctx(tmp_path))
    assert f.status == UNKNOWN
    assert "4 transcript row(s) across 2 session(s) unexamined" in f.detail


def test_b164_names_both_sqlite_stores_when_both_are_present(tmp_path):
    db_path = _add_transcript_db(tmp_path, "main", ROWS_A)
    conn = sqlite3.connect(db_path)
    conn.execute(f"CREATE TABLE {ts.TRAJECTORY_TABLE_NAME} (session_id TEXT NOT NULL, "
                 "seq INTEGER NOT NULL, run_id TEXT, event_json TEXT NOT NULL, "
                 "created_at INTEGER NOT NULL, PRIMARY KEY (session_id, seq))")
    conn.execute(f"INSERT INTO {ts.TRAJECTORY_TABLE_NAME} VALUES ('r',0,'x','{{}}',0)")
    conn.commit()
    conn.close()
    _add_log_sink(tmp_path)
    f = check_log_threat_hunt(_ctx(tmp_path))
    assert "1 row(s) across 1 session(s) unexamined" in f.detail            # trajectory
    assert "4 transcript row(s) across 2 session(s) unexamined" in f.detail  # transcripts
    assert f.detail.index("trajectory evidence") < f.detail.index("session transcripts live")


def test_b164_table_missing_leaves_the_text_untouched(tmp_path):
    _add_transcript_db(tmp_path, "main", ROWS_A, table="unrelated_table")
    _add_log_sink(tmp_path)
    with_db = check_log_threat_hunt(_ctx(tmp_path))
    bare = tmp_path / "bare"
    bare.mkdir()
    _add_log_sink(bare)
    without_db = check_log_threat_hunt(_ctx(bare))
    assert with_db.status == without_db.status == PASS
    assert with_db.detail == without_db.detail
    for fragment in ("transcript row(s)", "transcript_events", "incognito", "per-agent database"):
        assert fragment not in with_db.detail


def test_b164_view_is_said_to_be_uncounted_not_zero(tmp_path):
    db_path = _add_transcript_db(tmp_path, "main", ROWS_A, table="backing_rows")
    conn = sqlite3.connect(db_path)
    conn.execute(f"CREATE VIEW {TABLE} AS SELECT session_id, seq FROM backing_rows")
    conn.commit()
    conn.close()
    _add_log_sink(tmp_path)
    f = check_log_threat_hunt(_ctx(tmp_path))
    assert f.status == PASS
    assert "1 per-agent database(s) could not be examined for transcripts" in f.detail
    assert "transcript row(s)" not in f.detail


def test_b164_unreadable_database_beside_a_good_one_is_a_lower_bound(tmp_path):
    _add_transcript_db(tmp_path, "main", ROWS_A)
    _agent_db_path(tmp_path, "broken").write_bytes(b"garbage" * 64)
    _add_log_sink(tmp_path)
    f = check_log_threat_hunt(_ctx(tmp_path))
    assert "4 transcript row(s) across 2 session(s) unexamined" in f.detail
    assert "1 per-agent database(s) could not be examined for transcripts" in f.detail


def test_b164_home_without_any_database_is_unchanged(tmp_path):
    _add_log_sink(tmp_path)
    f = check_log_threat_hunt(_ctx(tmp_path))
    assert f.status == PASS
    for fragment in ("transcript row(s)", "transcript_events", "incognito", "per-agent database"):
        assert fragment not in f.detail


# ---------------------------------------------------------------- run's not_checked
def test_not_checked_carries_the_transcript_rows_and_keeps_the_trajectory_ones(tmp_path):
    db_path = _add_transcript_db(tmp_path, "main", ROWS_A)
    conn = sqlite3.connect(db_path)
    conn.execute(f"CREATE TABLE {ts.TRAJECTORY_TABLE_NAME} (session_id TEXT NOT NULL, "
                 "seq INTEGER NOT NULL, run_id TEXT, event_json TEXT NOT NULL, "
                 "created_at INTEGER NOT NULL, PRIMARY KEY (session_id, seq))")
    conn.execute(f"INSERT INTO {ts.TRAJECTORY_TABLE_NAME} VALUES ('r',0,'x','{{}}',0)")
    conn.commit()
    conn.close()
    _add_log_sink(tmp_path)
    finding = check_log_threat_hunt(_ctx(tmp_path))
    out = pl._b164_not_reached([finding])
    assert out == (
        "1 SQLite trajectory row(s) across 1 session(s) unexamined "
        "(agents/*/agent/openclaw-agent.sqlite)",
        "4 SQLite transcript row(s) across 2 session(s) unexamined "
        "(agents/*/agent/openclaw-agent.sqlite)",
    )


def test_not_checked_carries_an_uncounted_database(tmp_path):
    _agent_db_path(tmp_path, "main").write_bytes(b"garbage" * 64)
    _add_log_sink(tmp_path)
    out = pl._b164_not_reached([check_log_threat_hunt(_ctx(tmp_path))])
    assert out == ("1 per-agent database(s) could not be examined for transcripts "
                   "(agents/*/agent/openclaw-agent.sqlite)",)


def test_the_two_sqlite_regexes_cannot_read_each_others_sentence():
    transcript = "4 transcript row(s) across 2 session(s) unexamined"
    trajectory = "4 row(s) across 2 session(s) unexamined"
    assert pl._B164_SQLITE_UNSCANNED_RE.search(transcript) is None
    assert pl._B164_SQLITE_TRANSCRIPT_RE.search(trajectory) is None


# ----------------------------------------------------------------------------- B19
def _tight_home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    home.chmod(0o700)
    (home / "logs").mkdir()
    (home / "logs").chmod(0o700)
    return home


@pytest.mark.skipif(os.name != "posix", reason="B19 is POSIX-only")
def test_b19_pass_says_transcripts_are_inside_the_database(tmp_path):
    home = _tight_home(tmp_path)
    _add_transcript_db(home, "main", ROWS_A)
    f = check_data_atrest(_ctx(home))
    assert f.status == PASS
    assert "4 row(s)" in f.detail and "transcript_events" in f.detail
    assert "does not judge those files' permissions" in f.detail


@pytest.mark.skipif(os.name != "posix", reason="B19 is POSIX-only")
def test_b19_without_sqlite_transcripts_keeps_its_text_byte_for_byte(tmp_path):
    home = _tight_home(tmp_path)
    f = check_data_atrest(_ctx(home))
    assert f.status == PASS
    assert f.detail == (
        "Memory/log directories, session transcripts, and install backups are not reachable "
        "and readable by other users (owner-only, or sealed inside a tight home)."
    )
    _add_transcript_db(home, "main", ROWS_A, table="unrelated_table")   # table absent
    assert check_data_atrest(_ctx(home)).detail == f.detail


# ------------------------------------------------------------------- drift-gate wiring
def test_the_drift_gate_sees_the_count_as_a_per_agent_read_of_session_id_only():
    import importlib.util

    script = Path(__file__).resolve().parent.parent / "scripts" / "state_db_drift_gate.py"
    spec = importlib.util.spec_from_file_location("_c699_drift_gate", script)
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    reader = "trajectorystore.py:_count_transcript_events"
    assert reader in gate.PER_AGENT_DB_READERS
    reads = gate.expected_reads(Path(ts.__file__).resolve().parent)
    assert [(s["table"], s["columns"]) for s in reads[reader]] == [(TABLE, {"session_id"})]


def test_the_one_executed_transcript_statement_is_a_bounded_literal_count():
    """Source-level companion to tests/test_f187's executed-SQL census (which counts the
    call sites): the transcript statement is a plain literal, names no payload column and
    no auth table, and is not interpolated."""
    source = Path(ts.__file__).read_text(encoding="utf-8")
    lines = source.splitlines()
    windows = ["\n".join(lines[i:i + 4]) for i, ln in enumerate(lines) if ".execute(" in ln]
    mine = [w for w in windows if "FROM transcript_events" in w]
    assert len(mine) == 1, mine
    assert 'conn.execute(\n            "SELECT count(*), count(DISTINCT session_id) FROM transcript_events"' in mine[0]
    for banned in ("event_json", "event_zstd", "navigation_json", "auth_profile", "SELECT *"):
        assert banned not in mine[0], mine[0]
    assert "f'" not in mine[0] and 'f"' not in mine[0]
