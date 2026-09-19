"""B-709: ``subagent_runs`` has TWO observed SQLite column shapes.

On the installed OpenClaw 2026.8.2 the real ``subagent_runs`` columns are ONLY::

    run_id, child_session_key, controller_session_key, requester_session_key,
    created_at, payload_json

so the LEGACY ``SELECT child_session_key, model, agent_dir, workspace_dir, spawn_mode,
run_timeout_seconds, task, outcome_json, ended_reason, created_at FROM subagent_runs``
threw ``sqlite3.OperationalError: no such column: model`` on every real run, and B18
reported UNKNOWN ("No subagent delegation configured.") even on a machine that had
really spawned subagents.

``collector._collect_subagent_runs`` now PROBES ``PRAGMA table_info(subagent_runs)`` once
and branches on COLUMN PRESENCE (never on a caught exception -- see the collector's
docstring for why), mapping the modern shape per the vendor's OWN canonical read of this
table (``dist/subagent-registry.store.sqlite-B_lUfEus.js:341-351``):

* ``model``               $.model
* ``run_timeout_seconds``  $.runTimeoutSeconds
* ``ended_reason``         $.endedReason
* outcome                  $.execution.outcome.status, constrained to
                           "ok" | "error" | "timeout" | "unknown" (:362)

``agent_dir``, ``workspace_dir``, ``spawn_mode`` and ``task`` appear nowhere in that
canonical read -- they are GONE, not moved, and are always ``None`` on the modern path.
A one-time LIMIT_DOMAIN_AGENTS disclosure names that loss per collection run.

Offline, read-only, stdlib only -- writes only under pytest's tmp_path, never touches a
real ``~/.openclaw``.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from clawseccheck.collector import (
    LIMIT_DOMAIN_AGENTS,
    Context,
    _MAX_SUBAGENT_RUNS,
    _collect_subagent_runs,
    limit_hits_for,
)

# ---------------------------------------------------------------------------------
# DDLs copied verbatim from the two observed real-world shapes so the fixtures cannot
# silently drift from what a real machine actually has.
# ---------------------------------------------------------------------------------

_MODERN_DDL = (
    "CREATE TABLE subagent_runs ("
    "run_id TEXT NOT NULL PRIMARY KEY, child_session_key TEXT NOT NULL, "
    "controller_session_key TEXT, requester_session_key TEXT NOT NULL, "
    "created_at INTEGER NOT NULL, "
    "payload_json TEXT NOT NULL DEFAULT '{}'"
    ")"
)

_LEGACY_DDL = (
    "CREATE TABLE subagent_runs ("
    "run_id TEXT NOT NULL PRIMARY KEY, child_session_key TEXT NOT NULL, "
    "requester_session_key TEXT NOT NULL, task TEXT NOT NULL, cleanup TEXT NOT NULL, "
    "model TEXT, agent_dir TEXT, workspace_dir TEXT, run_timeout_seconds INTEGER, "
    "spawn_mode TEXT, created_at INTEGER NOT NULL, outcome_json TEXT, ended_reason TEXT"
    ")"
)

_UNRELATED_DDL = "CREATE TABLE subagent_runs (foo TEXT, bar TEXT)"


def _build_home(tmp_path: Path, ddl: str, rows: list, *, insert_columns) -> Context:
    """Materialise a fake ~/.openclaw with a state DB holding one ``subagent_runs`` table."""
    home = tmp_path / "openclaw"
    state = home / "state"
    state.mkdir(parents=True)
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    conn = sqlite3.connect(state / "openclaw.sqlite")
    try:
        conn.execute(ddl)
        placeholders = ",".join("?" for _ in insert_columns)
        for row in rows:
            conn.execute(
                f"INSERT INTO subagent_runs ({','.join(insert_columns)}) "
                f"VALUES ({placeholders})",
                row,
            )
        conn.commit()
    finally:
        conn.close()
    ctx = Context(home=home)
    _collect_subagent_runs(home, ctx)
    return ctx


def _modern_row(run_id, child_session_key, created_at, payload_obj):
    payload_json = json.dumps(payload_obj) if payload_obj is not None else "{}"
    return (run_id, child_session_key, f"req-{run_id}", created_at, payload_json)


_MODERN_COLUMNS = (
    "run_id", "child_session_key", "requester_session_key", "created_at", "payload_json",
)

_LEGACY_COLUMNS = (
    "run_id", "child_session_key", "requester_session_key", "task", "cleanup", "model",
    "agent_dir", "workspace_dir", "run_timeout_seconds", "spawn_mode", "created_at",
    "outcome_json", "ended_reason",
)


def _legacy_row(run_id, *, child_session_key=None, model=None, agent_dir=None,
                 workspace_dir=None, spawn_mode="detached", run_timeout_seconds=None,
                 task="do the thing", outcome_json=None, ended_reason=None, created_at=1000):
    return (
        run_id, child_session_key or f"child-{run_id}", f"req-{run_id}", task, "discard",
        model, agent_dir, workspace_dir, run_timeout_seconds, spawn_mode, created_at,
        outcome_json, ended_reason,
    )


# ---------------------------------------------------------------------------------
# 1. LEGACY columns -> unchanged behaviour.
# ---------------------------------------------------------------------------------

def test_legacy_shape_unchanged(tmp_path):
    row = _legacy_row(
        "r1", child_session_key="child-1", model="claude-opus",
        agent_dir="/home/u/.openclaw/agents/a1", workspace_dir="/home/u/projects/repo",
        spawn_mode="detached", run_timeout_seconds=600, task="summarize",
        outcome_json='{"status":"ok"}', ended_reason="completed", created_at=2000,
    )
    ctx = _build_home(tmp_path, _LEGACY_DDL, [row], insert_columns=_LEGACY_COLUMNS)
    assert ctx.subagent_runs_found is True
    assert ctx.subagent_runs_parse_error is False
    assert len(ctx.subagent_runs) == 1
    run = ctx.subagent_runs[0]
    assert run == {
        "child_session_key": "child-1",
        "model": "claude-opus",
        "agent_dir": "/home/u/.openclaw/agents/a1",
        "workspace_dir": "/home/u/projects/repo",
        "spawn_mode": "detached",
        "run_timeout_seconds": 600,
        "task": "summarize",
        "outcome": {"status": "ok"},
        "ended_reason": "completed",
        "created_at": 2000,
    }
    # Legacy path never emits the modern lost-field disclosure.
    assert limit_hits_for(ctx, LIMIT_DOMAIN_AGENTS) == []


# ---------------------------------------------------------------------------------
# 2. MODERN payload_json -> model / run_timeout_seconds / ended_reason extracted; the
#    four lost fields are None.
# ---------------------------------------------------------------------------------

def test_modern_shape_extracts_named_keys_lost_fields_none(tmp_path):
    row = _modern_row(
        "r2", "child-2", 3000,
        {"model": "claude-haiku", "runTimeoutSeconds": 300, "endedReason": "completed",
         "execution": {"outcome": {"status": "ok"}}},
    )
    ctx = _build_home(tmp_path, _MODERN_DDL, [row], insert_columns=_MODERN_COLUMNS)
    assert ctx.subagent_runs_found is True
    assert ctx.subagent_runs_parse_error is False
    assert len(ctx.subagent_runs) == 1
    run = ctx.subagent_runs[0]
    assert run["child_session_key"] == "child-2"
    assert run["model"] == "claude-haiku"
    assert run["run_timeout_seconds"] == 300
    assert run["ended_reason"] == "completed"
    assert run["created_at"] == 3000
    assert run["agent_dir"] is None
    assert run["workspace_dir"] is None
    assert run["spawn_mode"] is None
    assert run["task"] is None


# ---------------------------------------------------------------------------------
# 3. MODERN outcome built from $.execution.outcome.status, matching legacy shape.
# ---------------------------------------------------------------------------------

def test_modern_outcome_matches_legacy_shape(tmp_path):
    row = _modern_row("r3", "child-3", 4000, {"execution": {"outcome": {"status": "timeout"}}})
    ctx = _build_home(tmp_path, _MODERN_DDL, [row], insert_columns=_MODERN_COLUMNS)
    run = ctx.subagent_runs[0]
    assert run["outcome"] == {"status": "timeout"}


# ---------------------------------------------------------------------------------
# 4. MODERN out-of-vocabulary status -> treated as absent, NOT surfaced.
# ---------------------------------------------------------------------------------

def test_modern_out_of_vocabulary_status_treated_as_absent(tmp_path):
    row = _modern_row("r4", "child-4", 5000, {"execution": {"outcome": {"status": "weird"}}})
    ctx = _build_home(tmp_path, _MODERN_DDL, [row], insert_columns=_MODERN_COLUMNS)
    run = ctx.subagent_runs[0]
    assert run["outcome"] is None


# ---------------------------------------------------------------------------------
# 5. MODERN still-running row (no execution.outcome) -> KEPT, not counted as corrupt.
# ---------------------------------------------------------------------------------

def test_modern_still_running_row_kept_not_corrupt(tmp_path):
    row = _modern_row("r5", "child-5", 6000, {"model": "claude-x"})
    ctx = _build_home(tmp_path, _MODERN_DDL, [row], insert_columns=_MODERN_COLUMNS)
    assert ctx.subagent_runs_parse_error is False
    assert len(ctx.subagent_runs) == 1
    run = ctx.subagent_runs[0]
    assert run["outcome"] is None
    assert run["model"] == "claude-x"


# ---------------------------------------------------------------------------------
# 6. MODERN -> the LIMIT_DOMAIN_AGENTS lost-field disclosure is present; absent on legacy.
# ---------------------------------------------------------------------------------

def test_modern_lost_field_disclosure_present_legacy_absent(tmp_path):
    row = _modern_row("r6", "child-6", 7000, {"model": "claude-x"})
    ctx = _build_home(tmp_path, _MODERN_DDL, [row], insert_columns=_MODERN_COLUMNS)
    hits = limit_hits_for(ctx, LIMIT_DOMAIN_AGENTS)
    assert any("consolidated payload schema" in h for h in hits), hits
    assert any("agent_dir" in h and "workspace_dir" in h and "spawn_mode" in h
               and "task" in h for h in hits), hits

    legacy_row = _legacy_row("r6b", model="claude-x", created_at=7001)
    legacy_ctx = _build_home(
        tmp_path / "legacy", _LEGACY_DDL, [legacy_row], insert_columns=_LEGACY_COLUMNS,
    )
    assert limit_hits_for(legacy_ctx, LIMIT_DOMAIN_AGENTS) == []


# ---------------------------------------------------------------------------------
# 7. MODERN malformed payload_json on one row -> no crash, nothing invented, other
#    rows still read.
# ---------------------------------------------------------------------------------

def test_modern_malformed_payload_json_one_row_others_still_read(tmp_path):
    good_row = _modern_row("r7a", "child-7a", 8000, {"model": "claude-good"})
    bad_row = ("r7b", "child-7b", "req-r7b", 8001, "{not valid json")
    ctx = _build_home(
        tmp_path, _MODERN_DDL, [good_row, bad_row], insert_columns=_MODERN_COLUMNS,
    )
    assert ctx.subagent_runs_found is True
    assert ctx.subagent_runs_parse_error is False
    assert len(ctx.subagent_runs) == 1
    assert ctx.subagent_runs[0]["model"] == "claude-good"


# ---------------------------------------------------------------------------------
# 8. Neither shape -> no crash, nothing invented.
# ---------------------------------------------------------------------------------

def test_unrecognised_schema_no_crash_no_invented_data(tmp_path):
    ctx = _build_home(
        tmp_path, _UNRELATED_DDL, [("x", "y")], insert_columns=("foo", "bar"),
    )
    assert ctx.subagent_runs == []
    assert ctx.subagent_runs_found is True
    assert ctx.subagent_runs_parse_error is True
    assert any("neither the legacy" in e and "modern" in e for e in ctx.errors)
    assert any("foo" in e and "bar" in e for e in ctx.errors)


def test_no_subagent_runs_table_at_all_leaves_found_false(tmp_path):
    home = tmp_path / "openclaw"
    state = home / "state"
    state.mkdir(parents=True)
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    conn = sqlite3.connect(state / "openclaw.sqlite")
    conn.execute("CREATE TABLE unrelated_table (x TEXT)")
    conn.commit()
    conn.close()
    ctx = Context(home=home)
    _collect_subagent_runs(home, ctx)
    assert ctx.subagent_runs_found is False
    assert ctx.subagent_runs_parse_error is False
    assert ctx.subagent_runs == []


# ---------------------------------------------------------------------------------
# Extra: row cap + truncation bookkeeping still works on the modern path.
# ---------------------------------------------------------------------------------

def test_modern_row_cap_truncation_flagged_and_most_recent_kept(tmp_path):
    rows = [
        _modern_row(f"r{i}", f"child-{i}", i, {"model": f"model-{i}"})
        for i in range(_MAX_SUBAGENT_RUNS + 5)
    ]
    ctx = _build_home(tmp_path, _MODERN_DDL, rows, insert_columns=_MODERN_COLUMNS)
    assert len(ctx.subagent_runs) == _MAX_SUBAGENT_RUNS
    kept_models = {r["model"] for r in ctx.subagent_runs}
    assert f"model-{_MAX_SUBAGENT_RUNS + 4}" in kept_models
    assert "model-0" not in kept_models
    hits = limit_hits_for(ctx, LIMIT_DOMAIN_AGENTS)
    assert any("row cap" in h for h in hits)
    # And the schema disclosure is present alongside the truncation note.
    assert any("consolidated payload schema" in h for h in hits)


# ---------------------------------------------------------------------------------
# C-553: 2026.9.5 wraps the payload of a "parent"-completion run in {"parentCompletion": ...}.
# Found by diffing the blob WRITER between 2026.9.4 and 2026.9.5, not by any schema oracle:
# the DDL is byte-identical, so a reader that only checked columns saw nothing move while
# model / runTimeoutSeconds / endedReason / execution.outcome silently read back as None.
# ---------------------------------------------------------------------------------

_PARENT_RECORD = {
    "completionTarget": "parent", "model": "claude-haiku", "runTimeoutSeconds": 300,
    "endedReason": "completed", "execution": {"outcome": {"status": "ok"}},
}


def test_parent_completion_wrapper_is_unwrapped_like_the_vendor_does(tmp_path):
    row = _modern_row("p1", "child-p1", 5000, {"parentCompletion": dict(_PARENT_RECORD)})
    ctx = _build_home(tmp_path, _MODERN_DDL, [row], insert_columns=_MODERN_COLUMNS)
    assert ctx.subagent_runs_found is True and ctx.subagent_runs_parse_error is False
    run = ctx.subagent_runs[0]
    assert run["model"] == "claude-haiku"
    assert run["run_timeout_seconds"] == 300
    assert run["ended_reason"] == "completed"
    assert run["outcome"] == {"status": "ok"}


def test_a_flat_and_a_wrapped_row_are_both_read_in_one_pass(tmp_path):
    flat = _modern_row("f1", "child-f1", 5001, {"model": "claude-opus", "endedReason": "done"})
    wrapped = _modern_row("w1", "child-w1", 5002, {"parentCompletion": dict(_PARENT_RECORD)})
    ctx = _build_home(tmp_path, _MODERN_DDL, [flat, wrapped], insert_columns=_MODERN_COLUMNS)
    by_key = {r["child_session_key"]: r for r in ctx.subagent_runs}
    assert len(by_key) == 2
    assert by_key["child-f1"]["model"] == "claude-opus"
    assert by_key["child-w1"]["model"] == "claude-haiku"


def test_a_flat_record_that_itself_targets_the_parent_is_read_as_flat(tmp_path):
    """`completionTarget` at the TOP level is a flat record (the 2026.9.4 shape, or a
    non-wrapped one): nothing to unwrap, and it must still parse."""
    row = _modern_row("p2", "child-p2", 5003, dict(_PARENT_RECORD))
    ctx = _build_home(tmp_path, _MODERN_DDL, [row], insert_columns=_MODERN_COLUMNS)
    assert ctx.subagent_runs[0]["model"] == "claude-haiku"


def test_a_wrapper_naming_another_target_is_left_alone_as_the_runtime_leaves_it(tmp_path):
    """The vendor unwraps only when the inner `completionTarget` is exactly "parent"; a
    wrapper that names anything else is not a parent-completion record, so its keys are NOT
    hoisted (hoisting would invent data the runtime would never read)."""
    inner = dict(_PARENT_RECORD, completionTarget="child")
    row = _modern_row("p3", "child-p3", 5004, {"parentCompletion": inner})
    ctx = _build_home(tmp_path, _MODERN_DDL, [row], insert_columns=_MODERN_COLUMNS)
    run = ctx.subagent_runs[0]
    assert run["model"] is None and run["run_timeout_seconds"] is None
    assert run["ended_reason"] is None and run["outcome"] is None


@pytest.mark.parametrize("wrapper", ["text", 7, None, ["a"], True])
def test_a_non_object_parent_completion_value_is_ignored(tmp_path, wrapper):
    row = _modern_row("p4", "child-p4", 5005, {"model": "claude-opus", "parentCompletion": wrapper})
    ctx = _build_home(tmp_path, _MODERN_DDL, [row], insert_columns=_MODERN_COLUMNS)
    assert ctx.subagent_runs[0]["model"] == "claude-opus"
    assert ctx.subagent_runs_parse_error is False
