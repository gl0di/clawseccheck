"""B-296 (DISK-5 increment 1) — B18 disk-grounded disclosure from ``subagent_runs``.

DISCLOSURE ONLY, narrowing the class, not closing it. B18's config-derived UNKNOWN ("No
subagent delegation configured.") could previously coexist with POPULATED ``subagent_runs``
rows proving spawns actually occurred — the audit was silent about a real, recorded event.
This increment surfaces that disagreement as a WARN naming the recorded spawns (model,
agent_dir, workspace_dir, spawn_mode, outcome) whenever config says no delegation exists but
the OpenClaw state DB says otherwise. It deliberately adds NO FAIL-capable predicate: a spawn
into an out-of-tree workspace_dir or with a fallback model is normal, and OpenClaw prunes
these rows well before they could serve as durable forensic history (retention is short —
see collector._collect_subagent_runs's docstring and docs/research/openclaw-schema-recon.md
§28), so a populated table proves RECENT activity, never a complete spawn history.

Schema grounded verbatim against the installed dist (openclaw-state-db-DzSsA9Ji.js:
``CREATE TABLE IF NOT EXISTS subagent_runs``), the same file B-293/294/295 already read.
"""
from __future__ import annotations

import sqlite3

import pytest

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_subagents
from clawseccheck.collector import (
    LIMIT_DOMAIN_AGENTS,
    Context,
    _MAX_SUBAGENT_RUNS,
    _MAX_SUBAGENT_TASK_CHARS,
    _collect_subagent_runs,
    limit_hits_for,
)

# Column list + types copied verbatim from the dist CREATE TABLE so the fixture cannot drift.
_SUBAGENT_RUNS_DDL = (
    "CREATE TABLE subagent_runs ("
    "run_id TEXT NOT NULL PRIMARY KEY, child_session_key TEXT NOT NULL, "
    "controller_session_key TEXT, requester_session_key TEXT NOT NULL, "
    "requester_display_key TEXT NOT NULL, requester_origin_json TEXT, "
    "task TEXT NOT NULL, task_name TEXT, cleanup TEXT NOT NULL, label TEXT, "
    "model TEXT, agent_dir TEXT, workspace_dir TEXT, run_timeout_seconds INTEGER, "
    "spawn_mode TEXT, created_at INTEGER NOT NULL, started_at INTEGER, "
    "session_started_at INTEGER, accumulated_runtime_ms INTEGER, ended_at INTEGER, "
    "outcome_json TEXT, archive_at_ms INTEGER, cleanup_completed_at INTEGER, "
    "cleanup_handled INTEGER, suppress_announce_reason TEXT, "
    "expects_completion_message INTEGER, announce_retry_count INTEGER, "
    "last_announce_retry_at INTEGER, last_announce_delivery_error TEXT, "
    "ended_reason TEXT, pause_reason TEXT, wake_on_descendant_settle INTEGER, "
    "frozen_result_text TEXT, frozen_result_captured_at INTEGER, "
    "fallback_frozen_result_text TEXT, fallback_frozen_result_captured_at INTEGER, "
    "ended_hook_emitted_at INTEGER, pending_final_delivery INTEGER, "
    "pending_final_delivery_created_at INTEGER, "
    "pending_final_delivery_last_attempt_at INTEGER, "
    "pending_final_delivery_attempt_count INTEGER, pending_final_delivery_last_error TEXT, "
    "pending_final_delivery_payload_json TEXT, completion_announced_at INTEGER, "
    "payload_json TEXT NOT NULL DEFAULT '{}'"
    ")"
)

_NO_SUBAGENTS_CFG = {"agents": {"list": [{"name": "main"}]}}
_HAS_SUBAGENTS_CFG = {"agents": {"subagents": {"maxConcurrent": 4}}}


def _insert_run(conn, *, run_id, child_session_key=None, model=None, agent_dir=None,
                 workspace_dir=None, spawn_mode="detached", task="do the thing",
                 outcome_json=None, ended_reason=None, created_at=1000):
    conn.execute(
        "INSERT INTO subagent_runs (run_id, child_session_key, requester_session_key, "
        "requester_display_key, task, cleanup, model, agent_dir, workspace_dir, "
        "spawn_mode, created_at, outcome_json, ended_reason) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            run_id, child_session_key or f"child-{run_id}", f"req-{run_id}", "main",
            task, "discard", model, agent_dir, workspace_dir, spawn_mode, created_at,
            outcome_json, ended_reason,
        ),
    )


def _ctx(tmp_path, *, cfg=None, db=True, table=True, runs=(), wal_no_checkpoint=False):
    home = tmp_path / "openclaw"
    home.mkdir(parents=True, exist_ok=True)
    if db:
        state = home / "state"
        state.mkdir(exist_ok=True)
        db_path = state / "openclaw.sqlite"
        conn = sqlite3.connect(db_path)
        try:
            if table:
                conn.execute(_SUBAGENT_RUNS_DDL)
                for run in runs:
                    _insert_run(conn, **run)
            else:
                conn.execute("CREATE TABLE unrelated (x INTEGER)")
            conn.commit()
        finally:
            conn.close()
        if wal_no_checkpoint:
            # A SEPARATE writer connection, WAL journal mode, committed but never
            # checkpointed -- simulates the "hot WAL" trap: a reader must still see this
            # committed row without needing a checkpoint.
            w = sqlite3.connect(db_path)
            try:
                w.execute("PRAGMA journal_mode=WAL")
                _insert_run(w, run_id="wal-hot", child_session_key="child-wal-hot",
                            model="claude-x", created_at=9999)
                w.commit()
            finally:
                w.close()
    ctx = Context(home=home)
    ctx.config = cfg if cfg is not None else dict(_NO_SUBAGENTS_CFG)
    _collect_subagent_runs(home, ctx)
    return ctx


# ---------------------------------------------------------------------------------------
# Never FAIL-capable — the task's own hard constraint.
# ---------------------------------------------------------------------------------------

def test_b18_disk_disclosure_never_constructs_a_fail_finding():
    """No FAIL predicate in this increment (CLAUDE.md GR#5 + the task's own hard
    constraint): statically confirm neither check_subagents nor the new disclosure helper
    ever passes FAIL to _finding."""
    import ast
    import inspect
    from clawseccheck.checks import _agents as agents_mod

    src = inspect.getsource(agents_mod.check_subagents) + inspect.getsource(
        agents_mod._disk_subagent_disclosure
    )
    tree = ast.parse(src)
    fail_calls = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call) and any(
            isinstance(a, ast.Name) and a.id == "FAIL" for a in n.args
        )
    ]
    assert fail_calls == []


# ---------------------------------------------------------------------------------------
# Clean: absence stays UNKNOWN, never an affirmative PASS.
# ---------------------------------------------------------------------------------------

def test_no_state_db_at_all_is_unknown(tmp_path):
    ctx = _ctx(tmp_path, db=False)
    assert ctx.subagent_runs_found is False
    f = check_subagents(ctx)
    assert f.status == UNKNOWN
    assert f.detail == "No subagent delegation configured."


def test_table_absent_is_unknown(tmp_path):
    ctx = _ctx(tmp_path, table=False)
    assert ctx.subagent_runs_found is False
    f = check_subagents(ctx)
    assert f.status == UNKNOWN
    assert f.detail == "No subagent delegation configured."


def test_empty_table_is_unknown_never_pass(tmp_path):
    """Real-box shape (rows=0 everywhere at filing time): table exists, zero rows."""
    ctx = _ctx(tmp_path, runs=())
    assert ctx.subagent_runs_found is True
    assert ctx.subagent_runs == []
    f = check_subagents(ctx)
    assert f.status == UNKNOWN
    assert f.detail == "No subagent delegation configured."
    assert f.status != PASS


def test_unreadable_config_never_fabricates_a_config_claim(tmp_path):
    """openclaw.json present but unparseable -> ctx.config falls back to {} for reasons that
    have nothing to do with subagent delegation. Asserting "config declares no delegation"
    over that would be a fabricated claim (GR#4) -- the disclosure must stay silent and let
    B18 fall back to its ordinary UNKNOWN, even though subagent_runs holds rows."""
    ctx = _ctx(tmp_path, runs=[{"run_id": "r1", "model": "claude-x"}])
    ctx.config_parse_error = True
    f = check_subagents(ctx)
    assert f.status == UNKNOWN
    assert f.detail == "No subagent delegation configured."


def test_config_declares_subagents_and_rows_corroborate_no_extra_finding(tmp_path):
    """Config already declares delegation -> the normal B18 logic runs unmodified; disk
    corroboration must not manufacture a second/duplicate finding shape."""
    ctx = _ctx(
        tmp_path,
        cfg=dict(_HAS_SUBAGENTS_CFG),
        runs=[{"run_id": "r1", "model": "claude-x"}],
    )
    f = check_subagents(ctx)
    # No risky tools declared in _HAS_SUBAGENTS_CFG -> unchanged "delegation risk is low"
    # UNKNOWN wording, NOT the disk-disclosure WARN wording.
    assert f.status == UNKNOWN
    assert "delegation risk is low" in f.detail
    assert "subagent_runs" not in f.detail


# ---------------------------------------------------------------------------------------
# CLAWSECCHECK-B-296 round 2 (C-135): per-agent agents.list[i].subagents must be
# recognized by _has_subagents, not only agents.subagents / agents.defaults.subagents /
# a list with more than one agent. Exact repro from the C-135 report.
# ---------------------------------------------------------------------------------------

_PER_AGENT_SUBAGENTS_SINGLE_CFG = {
    "agents": {
        "list": [
            {"id": "main", "subagents": {"delegationMode": "suggest", "allowAgents": ["main"]}}
        ]
    }
}


def test_has_subagents_recognizes_per_agent_field_single_agent_list():
    """Direct unit check on _has_subagents: a ONE-entry agents.list whose only entry
    declares agents.list[i].subagents must be recognized -- this is the exact shape B72
    (check_subagents_allow_agents) already reads via dig(agent, "subagents.allowAgents")."""
    from clawseccheck.checks._agents import _has_subagents

    assert _has_subagents(_PER_AGENT_SUBAGENTS_SINGLE_CFG) is True


def test_per_agent_subagents_single_agent_list_rows_corroborate_no_false_disk_warn(tmp_path):
    """The reported defect, reproduced end-to-end: a single-agent list declaring
    delegation PER-AGENT, plus a real subagent_runs row for that agent, must NOT produce
    the "config declares no subagent delegation ... disk disagree" WARN -- config DOES
    declare delegation here (B72 on this identical config returns PASS/WARN/UNKNOWN off
    the same field, never "not configured"). Falls through to check_subagents' normal
    (config-derived) logic instead, exactly like
    test_config_declares_subagents_and_rows_corroborate_no_extra_finding above."""
    ctx = _ctx(
        tmp_path,
        cfg=dict(_PER_AGENT_SUBAGENTS_SINGLE_CFG),
        runs=[{"run_id": "r1", "model": "claude-x"}],
    )
    f = check_subagents(ctx)
    assert "disk disagree" not in f.detail
    assert "config declares no subagent delegation" not in f.detail
    assert "subagent_runs" not in f.detail
    # And B72 on the identical config confirms delegation IS declared (control on the
    # config side, mirroring the report's own cross-check): explicit non-"*" allowAgents
    # -> PASS, never B72's own "not configured" UNKNOWN.
    from clawseccheck.checks._agents import check_subagents_allow_agents

    b72 = check_subagents_allow_agents(ctx)
    assert b72.status == PASS
    assert "is not configured" not in b72.detail


def test_has_subagents_control_two_agent_list_already_true_before_fix():
    """Control from the report: adding a second, unrelated agent entry (same per-agent
    subagents block on the first, same shape) flips _has_subagents to True via the
    pre-existing list-length path alone -- pinning that round 1's heuristic still works
    and is not what round 2 changed."""
    from clawseccheck.checks._agents import _has_subagents

    cfg = {
        "agents": {
            "list": [
                {"id": "main", "subagents": {"delegationMode": "suggest", "allowAgents": ["main"]}},
                {"id": "other"},
            ]
        }
    }
    assert _has_subagents(cfg) is True


# ---------------------------------------------------------------------------------------
# Bad (disclosure): config silent, disk proves otherwise.
# ---------------------------------------------------------------------------------------

def test_disk_disclosure_fires_when_config_silent_but_rows_exist(tmp_path):
    ctx = _ctx(
        tmp_path,
        runs=[
            {"run_id": "r1", "model": "claude-opus", "agent_dir": "/home/u/.openclaw/agents/a1",
             "workspace_dir": "/home/u/projects/repo", "spawn_mode": "detached",
             "outcome_json": '{"status":"ok"}'},
            {"run_id": "r2", "model": "claude-haiku", "agent_dir": "/home/u/.openclaw/agents/a2",
             "workspace_dir": "/home/u/projects/repo2", "spawn_mode": "session",
             "outcome_json": '{"status":"timeout"}', "created_at": 2000},
        ],
    )
    f = check_subagents(ctx)
    assert f.status == WARN
    assert "2 spawn(s)" in f.detail
    blob = " ".join(f.evidence)
    assert "model=claude-haiku" in blob  # most-recent-first (created_at DESC)
    assert "model=claude-opus" in blob
    assert "agent_dir=/home/u/.openclaw/agents/a1" in blob
    assert "workspace_dir=/home/u/projects/repo" in blob
    assert "spawn_mode=detached" in blob
    assert "outcome=ok" in blob
    assert "outcome=timeout" in blob


def test_benign_shapes_never_fail_out_of_tree_workspace_and_fallback_model(tmp_path):
    """Out-of-tree workspace_dir + a non-default/fallback model are both NORMAL shapes.
    Pinned: neither can push this above WARN."""
    ctx = _ctx(
        tmp_path,
        runs=[{
            "run_id": "r1",
            "model": "some-fallback-model-v0",
            "workspace_dir": "/completely/unrelated/tree",
            "agent_dir": "/completely/unrelated/agents",
            "spawn_mode": "detached",
        }],
    )
    f = check_subagents(ctx)
    assert f.status == WARN
    assert f.status != FAIL


def test_outcome_absent_when_run_still_in_flight(tmp_path):
    """NULL outcome_json (run not ended yet) is normal, not corruption -- disclosure still
    fires and says so plainly instead of fabricating a status."""
    ctx = _ctx(tmp_path, runs=[{"run_id": "r1", "model": "claude-x", "outcome_json": None}])
    f = check_subagents(ctx)
    assert f.status == WARN
    assert "not recorded (may still be running)" in " ".join(f.evidence)


# ---------------------------------------------------------------------------------------
# UNKNOWN: DB absent / table absent (above) / unparseable outcome_json.
# ---------------------------------------------------------------------------------------

def test_unparseable_outcome_json_is_unknown(tmp_path):
    """Every row's outcome_json fails to parse -> nothing reliable to disclose -> falls
    back to the honest UNKNOWN rather than fabricate a count from undecodable data."""
    ctx = _ctx(tmp_path, runs=[{"run_id": "r1", "outcome_json": "{not valid json"}])
    assert ctx.subagent_runs_parse_error is True
    assert ctx.subagent_runs == []
    f = check_subagents(ctx)
    assert f.status == UNKNOWN
    assert f.detail == "No subagent delegation configured."


def test_partial_bad_row_still_discloses_the_good_ones(tmp_path):
    """One corrupt outcome_json among several rows must not blind the whole disclosure to
    otherwise-trustworthy sibling rows (design choice: tolerant per-record, like
    _collect_plugin_trust already is for its own per-record JSON)."""
    ctx = _ctx(
        tmp_path,
        runs=[
            {"run_id": "r1", "model": "claude-good", "outcome_json": '{"status":"ok"}'},
            {"run_id": "r2", "model": "claude-bad", "outcome_json": "{not valid json"},
        ],
    )
    assert ctx.subagent_runs_parse_error is False
    assert len(ctx.subagent_runs) == 1
    f = check_subagents(ctx)
    assert f.status == WARN
    assert "1 spawn(s)" in f.detail
    assert "model=claude-good" in " ".join(f.evidence)


# ---------------------------------------------------------------------------------------
# WAL lag: a committed-but-uncheckpointed row must be visible, never misread as absence.
# ---------------------------------------------------------------------------------------

def test_hot_wal_row_is_visible_not_misread_as_absence(tmp_path):
    ctx = _ctx(tmp_path, runs=[], wal_no_checkpoint=True)
    assert ctx.subagent_runs_found is True
    assert len(ctx.subagent_runs) == 1
    assert ctx.subagent_runs[0]["child_session_key"] == "child-wal-hot"
    f = check_subagents(ctx)
    assert f.status == WARN  # the committed WAL row was read, not treated as "no rows"


# ---------------------------------------------------------------------------------------
# §8 — the delegated task text itself is never echoed, and is capped defensively.
# ---------------------------------------------------------------------------------------

def test_task_text_never_reaches_the_finding(tmp_path):
    marker = "SENSITIVE-TASK-MARKER-should-never-leak"
    ctx = _ctx(tmp_path, runs=[{"run_id": "r1", "model": "claude-x", "task": marker}])
    f = check_subagents(ctx)
    blob = f.detail + f.fix + " ".join(f.evidence)
    assert marker not in blob


def test_task_text_is_capped_at_collection(tmp_path):
    long_task = "x" * (_MAX_SUBAGENT_TASK_CHARS + 500)
    ctx = _ctx(tmp_path, runs=[{"run_id": "r1", "task": long_task}])
    stored = ctx.subagent_runs[0]["task"]
    assert len(stored) <= _MAX_SUBAGENT_TASK_CHARS + len("...(truncated)")
    assert stored.endswith("...(truncated)")


# ---------------------------------------------------------------------------------------
# Bounds / read-only / truncation bookkeeping.
# ---------------------------------------------------------------------------------------

def test_collector_never_writes_to_the_state_db(tmp_path):
    ctx = _ctx(tmp_path, runs=[{"run_id": "r1", "model": "claude-x"}])
    db = ctx.home / "state" / "openclaw.sqlite"
    before = db.read_bytes()
    check_subagents(ctx)
    assert db.read_bytes() == before


def test_row_cap_truncation_is_flagged_and_most_recent_kept(tmp_path):
    runs = [
        {"run_id": f"r{i}", "model": f"model-{i}", "created_at": i}
        for i in range(_MAX_SUBAGENT_RUNS + 5)
    ]
    ctx = _ctx(tmp_path, runs=runs)
    assert len(ctx.subagent_runs) == _MAX_SUBAGENT_RUNS
    # ORDER BY created_at DESC -> the highest created_at values survive the cap.
    kept_ids = {r["model"] for r in ctx.subagent_runs}
    assert f"model-{_MAX_SUBAGENT_RUNS + 4}" in kept_ids
    assert "model-0" not in kept_ids
    hits = limit_hits_for(ctx, LIMIT_DOMAIN_AGENTS)
    assert any("subagent_runs" in h for h in hits)


@pytest.mark.parametrize("bad_value", [123, 4.5, True, ["not", "a", "dict"]])
def test_outcome_json_that_parses_to_non_object_is_treated_as_no_outcome(tmp_path, bad_value):
    import json as _json

    ctx = _ctx(tmp_path, runs=[{"run_id": "r1", "model": "claude-x",
                                 "outcome_json": _json.dumps(bad_value)}])
    # Syntactically valid JSON, just not an object -> no outcome info, NOT a parse error.
    assert ctx.subagent_runs_parse_error is False
    assert ctx.subagent_runs[0]["outcome"] is None
