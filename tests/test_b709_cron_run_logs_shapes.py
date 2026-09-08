"""B-709: ``cron_run_logs`` (the cron EXECUTION trail) has TWO observed backing tables.

On the installed OpenClaw 2026.8.2 the ``cron_run_logs`` table DOES NOT EXIST AT ALL --
the old ``SELECT job_id, status, session_id, session_key, run_id, run_at_ms, ts FROM
cron_run_logs`` throws ``sqlite3.OperationalError: no such table: cron_run_logs``, so
``ctx.cron_run_logs_found`` stayed False on a real machine and B189 answered UNKNOWN over
a state DB that in fact has a live execution trail.

The live state DB carries a completed migration record whose id is literally
``state:cron-run-logs-to-task-runs:v1`` -- the vendor naming its own destination -- and
cron executions now live as rows in the generic ``task_runs`` table (``runtime = 'cron'``).
``collector._collect_cron_run_logs`` now PROBES ``sqlite_master`` for which of the two
TABLES exist once and branches on PRESENCE (never on a caught exception -- see the
collector's docstring for why), mapping the modern shape onto the SAME output dict keys
the legacy path has always produced:

    old column       task_runs successor
    ----------       --------------------
    job_id           source_id (filtered to runtime='cron')
    status           status
    run_id           run_id
    session_key      child_session_key
    run_at_ms        started_at
    ts               created_at
    session_id       NO SUCCESSOR -- left None

Offline, read-only, stdlib only -- writes only under pytest's tmp_path, never touches a
real ``~/.openclaw``.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from clawseccheck.collector import (
    LIMIT_DOMAIN_CRON,
    Context,
    _collect_cron_run_logs,
    limit_hits_for,
)

_LEGACY_DDL = (
    "CREATE TABLE cron_run_logs (store_key TEXT, job_id TEXT, seq INTEGER, ts INTEGER, "
    "status TEXT, error TEXT, summary TEXT, diagnostics_summary TEXT, "
    "delivery_status TEXT, delivery_error TEXT, delivered INTEGER, session_id TEXT, "
    "session_key TEXT, run_id TEXT, run_at_ms INTEGER, duration_ms INTEGER, "
    "next_run_at_ms INTEGER, model TEXT, provider TEXT, total_tokens INTEGER, "
    "entry_json TEXT, created_at INTEGER)"
)

_MODERN_DDL = (
    "CREATE TABLE task_runs (task_id TEXT, runtime TEXT, task_kind TEXT, source_id TEXT, "
    "requester_session_key TEXT, owner_key TEXT, scope_kind TEXT, "
    "child_session_key TEXT, parent_flow_id TEXT, parent_task_id TEXT, agent_id TEXT, "
    "requester_agent_id TEXT, run_id TEXT, label TEXT, task TEXT, status TEXT, "
    "delivery_status TEXT, notify_policy TEXT, created_at INTEGER, started_at INTEGER, "
    "ended_at INTEGER, last_event_at INTEGER, cleanup_after INTEGER, "
    "tool_use_count INTEGER, last_tool_name TEXT, error TEXT, progress_summary TEXT, "
    "terminal_summary TEXT, terminal_outcome TEXT, detail_json TEXT)"
)


def _make_state_db(tmp_path: Path) -> tuple[Path, Path]:
    home = tmp_path / "openclaw"
    state = home / "state"
    state.mkdir(parents=True)
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    db_path = state / "openclaw.sqlite"
    return home, db_path


def _run(home: Path) -> Context:
    ctx = Context(home=home)
    _collect_cron_run_logs(home, ctx)
    return ctx


def _legacy_row(job_id, status, session_id, session_key, run_id, run_at_ms, ts):
    return (
        "default", job_id, 1, ts, status, None, None, None, None, None, 1,
        session_id, session_key, run_id, run_at_ms, 500, None, "anthropic",
        "claude", 100, "{}", ts,
    )


def _modern_row(
    task_id, runtime, source_id, status, run_id, child_session_key, started_at, created_at,
    *, task_kind="automation_run",
):
    return (
        task_id, runtime, task_kind, source_id, "req-sess", "owner", "agent",
        child_session_key, None, None, "main", "main", run_id, "label", "task", status,
        "delivered", "none", created_at, started_at, created_at + 1000, created_at + 1000,
        None, 3, "bash", None, None, "summary", "success", "{}",
    )


# ---------------------------------------------------------------------------------
# 1. LEGACY cron_run_logs table -> unchanged behaviour
# ---------------------------------------------------------------------------------

def test_legacy_table_unchanged_behaviour(tmp_path):
    home, db_path = _make_state_db(tmp_path)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(_LEGACY_DDL)
        conn.execute(
            "INSERT INTO cron_run_logs VALUES ("
            + ",".join("?" for _ in range(22)) + ")",
            _legacy_row(
                "job-1", "success", "sess-1", "key-1", "run-1", 1_700_000_000_000,
                1_700_000_000_500,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    ctx = _run(home)
    assert ctx.cron_run_logs_found is True
    assert ctx.cron_run_logs_parse_error is False
    assert ctx.cron_run_logs == [{
        "job_id": "job-1",
        "status": "success",
        "session_id": "sess-1",
        "session_key": "key-1",
        "run_id": "run-1",
        "run_at_ms": 1_700_000_000_000,
        "ts": 1_700_000_000_500,
    }]


# ---------------------------------------------------------------------------------
# 2. MODERN task_runs, runtime='cron' -> mapped correctly, job_id from source_id,
#    session_id is None
# ---------------------------------------------------------------------------------

def test_modern_task_runs_cron_rows_mapped(tmp_path):
    home, db_path = _make_state_db(tmp_path)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(_MODERN_DDL)
        conn.execute(
            "INSERT INTO task_runs VALUES (" + ",".join("?" for _ in range(30)) + ")",
            _modern_row(
                "task-1", "cron", "3e6cc857-316f-4501-a46b-158659ca52ed", "success",
                "cron:3e6cc857-316f-4501-a46b-158659ca52ed:1700000000000:abc",
                "child-key-1", 1_700_000_000_000, 1_700_000_000_500,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    ctx = _run(home)
    assert ctx.cron_run_logs_found is True
    assert ctx.cron_run_logs_parse_error is False
    assert ctx.cron_run_logs == [{
        "job_id": "3e6cc857-316f-4501-a46b-158659ca52ed",
        "status": "success",
        "session_id": None,
        "session_key": "child-key-1",
        "run_id": "cron:3e6cc857-316f-4501-a46b-158659ca52ed:1700000000000:abc",
        "run_at_ms": 1_700_000_000_000,
        "ts": 1_700_000_000_500,
    }]


# ---------------------------------------------------------------------------------
# 3. MODERN task_runs with NON-cron rows -> not returned; a subagent run must not be
#    invented as a cron execution
# ---------------------------------------------------------------------------------

def test_modern_non_cron_rows_excluded(tmp_path):
    home, db_path = _make_state_db(tmp_path)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(_MODERN_DDL)
        conn.execute(
            "INSERT INTO task_runs VALUES (" + ",".join("?" for _ in range(30)) + ")",
            _modern_row(
                "task-2", "subagent", "some-parent-task-id", "success", "run-2",
                "child-key-2", 1_700_000_001_000, 1_700_000_001_500,
                task_kind="subagent_run",
            ),
        )
        conn.commit()
    finally:
        conn.close()

    ctx = _run(home)
    assert ctx.cron_run_logs_found is True
    assert ctx.cron_run_logs == []


# ---------------------------------------------------------------------------------
# 4. BOTH tables present -> legacy wins
# ---------------------------------------------------------------------------------

def test_both_tables_present_legacy_wins(tmp_path):
    home, db_path = _make_state_db(tmp_path)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(_LEGACY_DDL)
        conn.execute(
            "INSERT INTO cron_run_logs VALUES (" + ",".join("?" for _ in range(22)) + ")",
            _legacy_row(
                "legacy-job", "success", "sess-legacy", "key-legacy", "run-legacy",
                1_700_000_002_000, 1_700_000_002_500,
            ),
        )
        conn.execute(_MODERN_DDL)
        conn.execute(
            "INSERT INTO task_runs VALUES (" + ",".join("?" for _ in range(30)) + ")",
            _modern_row(
                "task-3", "cron", "modern-job", "success", "run-modern", "child-key-3",
                1_700_000_003_000, 1_700_000_003_500,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    ctx = _run(home)
    assert ctx.cron_run_logs_found is True
    assert len(ctx.cron_run_logs) == 1
    assert ctx.cron_run_logs[0]["job_id"] == "legacy-job"


# ---------------------------------------------------------------------------------
# 5. NEITHER table present -> found stays False, no crash, nothing invented
# ---------------------------------------------------------------------------------

def test_neither_table_present_found_stays_false(tmp_path):
    home, db_path = _make_state_db(tmp_path)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("CREATE TABLE unrelated_table (x TEXT)")
        conn.commit()
    finally:
        conn.close()

    ctx = _run(home)
    assert ctx.cron_run_logs_found is False
    assert ctx.cron_run_logs_parse_error is False
    assert ctx.cron_run_logs == []


def test_no_state_db_at_all_found_stays_false(tmp_path):
    home = tmp_path / "openclaw"
    home.mkdir(parents=True)
    ctx = _run(home)
    assert ctx.cron_run_logs_found is False
    assert ctx.cron_run_logs == []


# ---------------------------------------------------------------------------------
# 6. Row cap / truncation disclosure still fires on the modern path
# ---------------------------------------------------------------------------------

def test_modern_path_row_cap_truncation_disclosed(tmp_path, monkeypatch):
    import clawseccheck.collector as collector

    monkeypatch.setattr(collector, "_MAX_CRON_RUN_LOGS", 3)

    home, db_path = _make_state_db(tmp_path)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(_MODERN_DDL)
        for i in range(5):
            conn.execute(
                "INSERT INTO task_runs VALUES (" + ",".join("?" for _ in range(30)) + ")",
                _modern_row(
                    f"task-{i}", "cron", f"job-{i}", "success", f"run-{i}",
                    f"child-key-{i}", 1_700_000_000_000 + i, 1_700_000_000_000 + i,
                ),
            )
        conn.commit()
    finally:
        conn.close()

    ctx = _run(home)
    assert ctx.cron_run_logs_found is True
    assert len(ctx.cron_run_logs) == 3
    hits = limit_hits_for(ctx, LIMIT_DOMAIN_CRON)
    assert any("older run history was NOT read" in h for h in hits), hits


def test_modern_path_row_cap_not_falsely_triggered_at_exact_cap(tmp_path, monkeypatch):
    import clawseccheck.collector as collector

    monkeypatch.setattr(collector, "_MAX_CRON_RUN_LOGS", 3)

    home, db_path = _make_state_db(tmp_path)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(_MODERN_DDL)
        for i in range(3):
            conn.execute(
                "INSERT INTO task_runs VALUES (" + ",".join("?" for _ in range(30)) + ")",
                _modern_row(
                    f"task-{i}", "cron", f"job-{i}", "success", f"run-{i}",
                    f"child-key-{i}", 1_700_000_000_000 + i, 1_700_000_000_000 + i,
                ),
            )
        conn.commit()
    finally:
        conn.close()

    ctx = _run(home)
    assert len(ctx.cron_run_logs) == 3
    hits = limit_hits_for(ctx, LIMIT_DOMAIN_CRON)
    assert not any("older run history was NOT read" in h for h in hits), hits
