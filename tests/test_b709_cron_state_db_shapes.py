"""B-709: ``cron_jobs`` table has TWO observed SQLite column shapes.

On the installed OpenClaw 2026.8.2 the real ``cron_jobs`` columns are::

    store_key, job_id, declaration_key, owner_agent_id, name, description, enabled,
    agent_id, payload_kind, job_json, state_json, runtime_updated_at_ms,
    schedule_identity, sort_order, updated_at

``delete_after_run``, ``trigger_script`` and ``payload_message`` DO NOT EXIST on this
shape any more -- the OLD ``SELECT job_id, name, enabled, delete_after_run,
trigger_script, payload_kind, payload_message FROM cron_jobs`` throws
``sqlite3.OperationalError: no such column: delete_after_run``, so every real cron job on
a 2026.8.2 machine went unread and B168 answered UNKNOWN over a populated store.

``collector._collect_cron`` now PROBES ``PRAGMA table_info(cron_jobs)`` once and branches
on COLUMN PRESENCE (never on a caught exception -- see the collector's docstring for why),
mapping the modern shape per (grounded, verbatim) vendor field paths:

* ``deleteAfterRun``       job_json top-level bool, optional
                           (dist/plugin-entry-DhKN3bwq.d.ts:6380)
* ``trigger_script``       job_json.payload.script, only when payload.kind == "script"
* ``payload_message``      job_json.payload.message when payload.kind == "agentTurn";
                           job_json.payload.text when payload.kind == "systemEvent"
                           (both: dist/persisted-shape-C6m3w-m0.js:100)

Offline, read-only, stdlib only -- writes only under pytest's tmp_path, never touches a
real ``~/.openclaw``.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from clawseccheck.collector import Context, _collect_cron

# ---------------------------------------------------------------------------------
# Column lists copied verbatim from the two observed real-world DDLs so the fixtures
# cannot silently drift from what a real machine actually has.
# ---------------------------------------------------------------------------------

_MODERN_DDL = (
    "CREATE TABLE cron_jobs ("
    "store_key TEXT, job_id TEXT, declaration_key TEXT, owner_agent_id TEXT, "
    "name TEXT, description TEXT, enabled INTEGER, agent_id TEXT, payload_kind TEXT, "
    "job_json TEXT, state_json TEXT, runtime_updated_at_ms INTEGER, "
    "schedule_identity TEXT, sort_order INTEGER, updated_at INTEGER)"
)

_LEGACY_DDL = (
    "CREATE TABLE cron_jobs (job_id TEXT, name TEXT, enabled INTEGER, "
    "delete_after_run INTEGER, trigger_script TEXT, payload_kind TEXT, payload_message TEXT)"
)

_UNRELATED_DDL = "CREATE TABLE cron_jobs (foo TEXT, bar TEXT)"

_MODERN_COLUMNS = (
    "store_key", "job_id", "declaration_key", "owner_agent_id", "name", "description",
    "enabled", "agent_id", "payload_kind", "job_json", "state_json",
    "runtime_updated_at_ms", "schedule_identity", "sort_order", "updated_at",
)


def _build_home(tmp_path: Path, ddl: str, rows: list, *, insert_columns=None) -> Context:
    """Materialise a fake ~/.openclaw with a state DB holding one ``cron_jobs`` table.

    ``insert_columns`` lets a caller insert a partial row (e.g. omitting ``job_json``
    from the VALUES list is not what's wanted here -- every row supplies every column in
    ``_MODERN_COLUMNS`` order unless the caller passes an explicit column subset).
    """
    home = tmp_path / "openclaw"
    state = home / "state"
    state.mkdir(parents=True)
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    conn = sqlite3.connect(state / "openclaw.sqlite")
    try:
        conn.execute(ddl)
        cols = insert_columns or _MODERN_COLUMNS
        placeholders = ",".join("?" for _ in cols)
        for row in rows:
            conn.execute(
                f"INSERT INTO cron_jobs ({','.join(cols)}) VALUES ({placeholders})", row
            )
        conn.commit()
    finally:
        conn.close()
    ctx = Context(home=home)
    _collect_cron(home, ctx)
    return ctx


def _modern_row(job_id, name, enabled, payload_kind, job_json_obj):
    """Build one full-width modern row; unrelated columns get harmless placeholders."""
    job_json = json.dumps(job_json_obj) if job_json_obj is not None else None
    return (
        "default", job_id, f"decl-{job_id}", "main", name, "a cron job", enabled, "main",
        payload_kind, job_json, "{}", 1_700_000_000_000, "sched", 0, 1_700_000_000_000,
    )


# ---------------------------------------------------------------------------------
# 1. MODERN + payload.kind == "agentTurn" -> payload_message
# ---------------------------------------------------------------------------------

def test_modern_agent_turn_payload_message(tmp_path):
    row = _modern_row(
        "j1", "daily digest", 1, "agentTurn",
        {"payload": {"kind": "agentTurn", "message": "Summarize yesterday's tasks."}},
    )
    ctx = _build_home(tmp_path, _MODERN_DDL, [row])
    assert ctx.cron_found is True
    assert ctx.cron_parse_error is False
    assert len(ctx.cron_jobs) == 1
    job = ctx.cron_jobs[0]
    assert job["id"] == "j1"
    assert job["name"] == "daily digest"
    assert job["payload_kind"] == "agentTurn"
    assert job["payload_message"] == "Summarize yesterday's tasks."
    assert job["trigger_script"] is None


# ---------------------------------------------------------------------------------
# 2. MODERN + payload.kind == "script" -> trigger_script
# ---------------------------------------------------------------------------------

def test_modern_script_payload_trigger_script(tmp_path):
    row = _modern_row(
        "j2", "nightly backup", 1, "script",
        {"payload": {"kind": "script", "script": "tar czf /backup.tgz /data"}},
    )
    ctx = _build_home(tmp_path, _MODERN_DDL, [row])
    job = ctx.cron_jobs[0]
    assert job["payload_kind"] == "script"
    assert job["trigger_script"] == "tar czf /backup.tgz /data"
    assert job["payload_message"] is None


# ---------------------------------------------------------------------------------
# 3. MODERN + payload.kind == "systemEvent" -> payload_message (from .text)
# ---------------------------------------------------------------------------------

def test_modern_system_event_payload_message_from_text(tmp_path):
    row = _modern_row(
        "j3", "startup ping", 1, "systemEvent",
        {"payload": {"kind": "systemEvent", "text": "agent booted"}},
    )
    ctx = _build_home(tmp_path, _MODERN_DDL, [row])
    job = ctx.cron_jobs[0]
    assert job["payload_kind"] == "systemEvent"
    assert job["payload_message"] == "agent booted"
    assert job["trigger_script"] is None


# ---------------------------------------------------------------------------------
# 4. MODERN + top-level deleteAfterRun: true -> True
# ---------------------------------------------------------------------------------

def test_modern_delete_after_run_true(tmp_path):
    row = _modern_row(
        "j4", "one-shot", 1, "agentTurn",
        {"deleteAfterRun": True, "payload": {"kind": "agentTurn", "message": "hi"}},
    )
    ctx = _build_home(tmp_path, _MODERN_DDL, [row])
    job = ctx.cron_jobs[0]
    assert job["delete_after_run"] is True


# ---------------------------------------------------------------------------------
# 5. MODERN + deleteAfterRun ABSENT -> None (not False -- absent != explicitly false)
# ---------------------------------------------------------------------------------

def test_modern_delete_after_run_absent_is_none(tmp_path):
    row = _modern_row(
        "j5", "recurring", 1, "agentTurn",
        {"payload": {"kind": "agentTurn", "message": "hi"}},
    )
    ctx = _build_home(tmp_path, _MODERN_DDL, [row])
    job = ctx.cron_jobs[0]
    assert job["delete_after_run"] is None
    assert job["delete_after_run"] is not False


# ---------------------------------------------------------------------------------
# 6. LEGACY shape still works, unchanged
# ---------------------------------------------------------------------------------

def test_legacy_shape_still_works(tmp_path):
    ctx = _build_home(
        tmp_path, _LEGACY_DDL,
        [("j6", "legacy job", 1, 0, None, "agentTurn", "Send the digest.")],
        insert_columns=("job_id", "name", "enabled", "delete_after_run",
                         "trigger_script", "payload_kind", "payload_message"),
    )
    assert ctx.cron_found is True
    assert ctx.cron_parse_error is False
    job = ctx.cron_jobs[0]
    assert job == {
        "id": "j6",
        "name": "legacy job",
        "enabled": True,
        "delete_after_run": False,
        "trigger_script": None,
        "payload_kind": "agentTurn",
        "payload_message": "Send the digest.",
    }


# ---------------------------------------------------------------------------------
# 7. Neither shape recognised -> no crash, nothing invented, flag/error recorded
# ---------------------------------------------------------------------------------

def test_unrecognised_schema_no_crash_no_invented_data(tmp_path):
    ctx = _build_home(
        tmp_path, _UNRELATED_DDL, [("x", "y")], insert_columns=("foo", "bar"),
    )
    assert ctx.cron_jobs == []
    # Reuses the existing "found but could not be parsed/read" verdict rather than a
    # fake clean read -- Golden Rule #4 (no PASS-by-absence over an unreadable store).
    assert ctx.cron_found is True
    assert ctx.cron_parse_error is True
    assert any("neither the legacy" in e and "modern" in e for e in ctx.errors)
    assert any("foo" in e and "bar" in e for e in ctx.errors)


# ---------------------------------------------------------------------------------
# 8. Malformed job_json -> recorded as a parse error, no crash, no invented data
# ---------------------------------------------------------------------------------

def test_malformed_job_json_recorded_no_crash_no_invented_data(tmp_path):
    row = (
        "default", "j8", "decl-j8", "main", "broken job", "desc", 1, "main",
        "agentTurn", "{not valid json", "{}", 1_700_000_000_000, "sched", 0,
        1_700_000_000_000,
    )
    ctx = _build_home(tmp_path, _MODERN_DDL, [row])
    # The store itself WAS read -- one bad row must not blind the whole scan, so this is
    # NOT the store-level cron_parse_error (that would hide every OTHER job's payload).
    assert ctx.cron_found is True
    assert ctx.cron_parse_error is False
    assert len(ctx.cron_jobs) == 1
    job = ctx.cron_jobs[0]
    assert job["id"] == "j8"
    # Nothing invented for the fields that live inside the unparsable job_json.
    assert job["delete_after_run"] is None
    assert job["trigger_script"] is None
    assert job["payload_message"] is None
    # But the SQL-column fields (not inside job_json) are still faithfully read.
    assert job["name"] == "broken job"
    assert job["payload_kind"] == "agentTurn"
    assert any("j8" in e and "not valid JSON" in e for e in ctx.errors)
    # And the incompleteness must reach the channel a CHECK can actually see.
    # The row is still counted in ctx.cron_jobs, so B168 would otherwise render
    # "Scanned 1 cron job(s): no embedded instruction-override found" -- a
    # finished-walk claim over content it never read. No check reads ctx.errors;
    # limit_hits_for(LIMIT_DOMAIN_CRON) is what B168/B189 consult, so assert on
    # that rather than on the error string, which cannot prevent the overclaim.
    from clawseccheck.collector import LIMIT_DOMAIN_CRON, limit_hits_for
    cron_limits = limit_hits_for(ctx, LIMIT_DOMAIN_CRON)
    assert any("j8" in h and "NOT scanned" in h for h in cron_limits), cron_limits


# ---------------------------------------------------------------------------------
# Extra: a table with no rows at all (both shapes) must not crash and must be
# distinguishable from "no table" via cron_store_empty.
# ---------------------------------------------------------------------------------

def test_modern_empty_table_is_store_empty_not_missing(tmp_path):
    ctx = _build_home(tmp_path, _MODERN_DDL, [])
    assert ctx.cron_found is True
    assert ctx.cron_jobs == []
    assert ctx.cron_store_empty is True


def test_no_cron_jobs_table_at_all_leaves_found_false(tmp_path):
    home = tmp_path / "openclaw"
    state = home / "state"
    state.mkdir(parents=True)
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    conn = sqlite3.connect(state / "openclaw.sqlite")
    conn.execute("CREATE TABLE unrelated_table (x TEXT)")
    conn.commit()
    conn.close()
    ctx = Context(home=home)
    _collect_cron(home, ctx)
    assert ctx.cron_found is False
    assert ctx.cron_parse_error is False
    assert ctx.cron_jobs == []
