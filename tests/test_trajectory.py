"""Trajectory-sidecar reader (log-observed proven tool use) — read-only, name-only.

Grounded schema: docs/research/openclaw-schema-recon.md §9.1. The reader extracts the
set of tool verbs from tool.call records' data.name, gated on
traceSchema=openclaw-trajectory / schemaVersion=1, and NEVER reads call/return payloads.

Offline, stdlib only.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from clawseccheck.trajectory import find_trajectory_files, read_events, read_proven_tools


def _write_traj(home: Path, session: str, records: list[dict]) -> None:
    d = home / "agents" / "main" / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    lines = "\n".join(json.dumps(r) for r in records) + "\n"
    (d / f"{session}.trajectory.jsonl").write_text(lines, encoding="utf-8")


def _call(name: str, arguments: dict) -> dict:
    return {
        "traceSchema": "openclaw-trajectory", "schemaVersion": 1, "type": "tool.call",
        "ts": "2026-07-03T00:00:00Z", "seq": 1, "sessionId": "s",
        "data": {"name": name, "arguments": arguments, "toolCallId": "c1"},
    }


def _write_many(home: Path, agent: str, n: int) -> list[Path]:
    """Write *n* minimal, distinctly-timestamped trajectory sidecars — one per
    synthetic session — so find_trajectory_files' newest-first mtime sort has a
    deterministic order to cap against (B-245)."""
    d = home / "agents" / agent / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    base = 1_700_000_000
    paths = []
    for i in range(n):
        rec = _call(f"tool_{i}", {})
        p = d / f"s{i}.trajectory.jsonl"
        p.write_text(json.dumps(rec) + "\n", encoding="utf-8")
        os.utime(p, (base + i, base + i))
        paths.append(p)
    return paths


def test_reader_missing_home_is_empty(tmp_path):
    verbs, meta = read_proven_tools(tmp_path / "nope")
    assert verbs == set()
    assert meta["present"] is False


def test_reader_extracts_tool_call_names(tmp_path):
    _write_traj(tmp_path, "sess1", [
        {"traceSchema": "openclaw-trajectory", "schemaVersion": 1,
         "type": "session.started", "data": {}},
        _call("bash", {"command": "ls"}),
        _call("web_search", {"q": "x"}),
        {"traceSchema": "openclaw-trajectory", "schemaVersion": 1,
         "type": "tool.result", "data": {"name": "bash", "status": "completed"}},
    ])
    verbs, meta = read_proven_tools(tmp_path)
    assert verbs == {"bash", "web_search"}
    assert meta["present"] is True and meta["files_scanned"] == 1
    assert meta["unknown_version"] is False


def test_reader_never_returns_argument_payloads(tmp_path):
    # A secret-shaped value assembled from fragments so no contiguous literal exists (§2.3).
    secret = "sk-" + "live" + "".join(["A"] * 20)
    _write_traj(tmp_path, "sess1", [_call("bash", {"command": "curl -H " + secret})])
    verbs, _ = read_proven_tools(tmp_path)
    assert verbs == {"bash"}
    # The reader returns tool identities only — no payload text ever leaves data.arguments.
    assert all(secret not in v for v in verbs)


def test_reader_version_gate_rejects_unknown_schema(tmp_path):
    rec = _call("bash", {"command": "ls"})
    rec["schemaVersion"] = 2  # unrecognised format — must NOT be trusted
    _write_traj(tmp_path, "sess1", [rec])
    verbs, meta = read_proven_tools(tmp_path)
    assert verbs == set()
    assert meta["unknown_version"] is True


def test_reader_ignores_wrong_trace_schema(tmp_path):
    rec = _call("bash", {"command": "ls"})
    rec["traceSchema"] = "something-else"
    _write_traj(tmp_path, "sess1", [rec])
    verbs, _ = read_proven_tools(tmp_path)
    assert verbs == set()


def test_reader_skips_malformed_lines(tmp_path):
    d = tmp_path / "agents" / "main" / "sessions"
    d.mkdir(parents=True)
    good = json.dumps(_call("bash", {"command": "ls"}))
    (d / "s.trajectory.jsonl").write_text(
        'not json but mentions "tool.call"\n' + good + "\n", encoding="utf-8"
    )
    verbs, _ = read_proven_tools(tmp_path)
    assert verbs == {"bash"}


# ---------------------------------------------------------------------------
# read_events (F-107) — §8-safe event metadata for the behavioral engine
# ---------------------------------------------------------------------------

def _result(name: str, *, status=None, is_error=None, success=None, thread=None, turn=None):
    data = {"name": name, "toolCallId": "c1"}
    if status is not None:
        data["status"] = status
    if is_error is not None:
        data["isError"] = is_error
    if success is not None:
        data["success"] = success
    if thread is not None:
        data["threadId"] = thread
    if turn is not None:
        data["turnId"] = turn
    return {
        "traceSchema": "openclaw-trajectory", "schemaVersion": 1, "type": "tool.result",
        "ts": "2026-07-03T00:00:01Z", "seq": 2, "data": data,
    }


def test_read_events_missing_home_is_empty(tmp_path):
    events, meta = read_events(tmp_path / "nope")
    assert events == []
    assert meta["present"] is False


def test_read_events_tool_call_and_result(tmp_path):
    _write_traj(tmp_path, "sess1", [
        {**_call("bash", {"command": "ls"}), "data": {
            "name": "bash", "arguments": {"command": "ls"}, "turnId": "t1", "threadId": "th1",
        }},
        _result("bash", status="completed", thread="th1", turn="t1"),
    ])
    events, meta = read_events(tmp_path)
    assert meta["present"] is True and meta["files_scanned"] == 1
    assert len(events) == 2
    call, result = events
    assert call["type"] == "tool.call" and call["name"] == "bash"
    assert call["turnId"] == "t1" and call["threadId"] == "th1"
    assert call["outcome"] is None  # only tool.result carries an outcome
    assert result["type"] == "tool.result" and result["outcome"] == "success"


def test_read_events_outcome_classification():
    from clawseccheck.trajectory import _event_outcome
    assert _event_outcome("tool.result", {"status": "failed"}) == "failed"
    assert _event_outcome("tool.result", {"isError": True}) == "failed"
    assert _event_outcome("tool.result", {"success": False}) == "failed"
    assert _event_outcome("tool.result", {"status": "completed"}) == "success"
    assert _event_outcome("tool.result", {"success": True}) == "success"
    assert _event_outcome("tool.result", {}) is None  # ambiguous — never guessed
    assert _event_outcome("tool.call", {"status": "failed"}) is None  # wrong type


def test_read_events_never_returns_argument_or_result_payloads(tmp_path):
    secret = "sk-" + "live" + "".join(["A"] * 20)
    _write_traj(tmp_path, "sess1", [
        _call("bash", {"command": "curl -H " + secret}),
        {"traceSchema": "openclaw-trajectory", "schemaVersion": 1, "type": "tool.result",
         "ts": "t", "seq": 2, "data": {"name": "bash", "status": "completed", "output": secret}},
    ])
    events, _ = read_events(tmp_path)
    blob = json.dumps(events)
    assert secret not in blob


def test_read_events_version_gate_rejects_unknown_schema(tmp_path):
    rec = _call("bash", {"command": "ls"})
    rec["schemaVersion"] = 2
    _write_traj(tmp_path, "sess1", [rec])
    events, meta = read_events(tmp_path)
    assert events == []
    assert meta["unknown_version"] is True


def test_read_events_prompt_submitted_has_no_name(tmp_path):
    _write_traj(tmp_path, "sess1", [
        {"traceSchema": "openclaw-trajectory", "schemaVersion": 1,
         "type": "prompt.submitted", "ts": "t", "seq": 1, "data": {"turnId": "t1"}},
    ])
    events, _ = read_events(tmp_path)
    assert len(events) == 1
    assert events[0]["type"] == "prompt.submitted"
    assert events[0]["name"] is None


def test_read_events_ignores_unrecognised_event_types(tmp_path):
    _write_traj(tmp_path, "sess1", [
        {"traceSchema": "openclaw-trajectory", "schemaVersion": 1,
         "type": "model.completed", "ts": "t", "seq": 1, "data": {}},
        _call("bash", {"command": "ls"}),
    ])
    events, _ = read_events(tmp_path)
    assert len(events) == 1
    assert events[0]["type"] == "tool.call"


def test_read_events_explicit_path(tmp_path):
    _write_traj(tmp_path, "sess1", [_call("bash", {"command": "ls"})])
    path = tmp_path / "agents" / "main" / "sessions" / "sess1.trajectory.jsonl"
    events, meta = read_events(tmp_path / "unused", explicit_path=str(path))
    assert meta["present"] is True
    assert len(events) == 1


def test_read_events_explicit_path_missing_file_is_empty(tmp_path):
    events, meta = read_events(tmp_path, explicit_path=str(tmp_path / "nope.jsonl"))
    assert events == []
    assert meta["present"] is False


# ---------------------------------------------------------------------------
# B-245 — per-FILE cap (_MAX_FILES) disclosure: the per-byte cap has been
# disclosed (`truncated`, C-180) since it was added, but the per-file cap
# silently dropped the oldest sessions with no signal at all. find_trajectory_files'
# `stats` out-param and read_proven_tools/read_events' `files_total`/`files_capped`
# meta fields close that gap — mirrors safeio.walk_dir_safely's `capped` (B-244).
# ---------------------------------------------------------------------------

def test_find_trajectory_files_stats_missing_home(tmp_path):
    stats: dict = {}
    files = find_trajectory_files(tmp_path / "nope", stats=stats)
    assert files == []
    assert stats == {"files_total": 0, "files_capped": False}


def test_find_trajectory_files_stats_not_capped_at_max(tmp_path):
    _write_many(tmp_path, "main", 60)
    stats: dict = {}
    files = find_trajectory_files(tmp_path, max_files=60, stats=stats)
    assert len(files) == 60
    assert stats["files_total"] == 60
    assert stats["files_capped"] is False


def test_find_trajectory_files_stats_capped_over_max(tmp_path):
    _write_many(tmp_path, "main", 61)
    stats: dict = {}
    files = find_trajectory_files(tmp_path, max_files=60, stats=stats)
    assert len(files) == 60
    assert stats["files_total"] == 61
    assert stats["files_capped"] is True
    # newest-first: the 61 mtimes are base..base+60, so the dropped file is the
    # very oldest one (s0) — the returned set must be the 60 newest, not it.
    assert (tmp_path / "agents" / "main" / "sessions" / "s0.trajectory.jsonl") not in files


def test_find_trajectory_files_no_stats_arg_unaffected(tmp_path):
    # Default (no `stats`) must keep the original return-type/behaviour for every
    # existing caller (incident.py, logdiscovery.py, trajaudit.py, checks/_host.py).
    _write_many(tmp_path, "main", 3)
    files = find_trajectory_files(tmp_path)
    assert len(files) == 3


def test_read_proven_tools_meta_capped_over_max_files(tmp_path):
    _write_many(tmp_path, "main", 61)
    verbs, meta = read_proven_tools(tmp_path, max_files=60)
    assert meta["files_total"] == 61
    assert meta["files_capped"] is True
    assert meta["files_scanned"] == 60


def test_read_proven_tools_meta_not_capped_at_max_files(tmp_path):
    _write_many(tmp_path, "main", 60)
    verbs, meta = read_proven_tools(tmp_path, max_files=60)
    assert meta["files_total"] == 60
    assert meta["files_capped"] is False
    assert meta["files_scanned"] == 60


def test_read_proven_tools_meta_no_sidecar_is_uncapped(tmp_path):
    verbs, meta = read_proven_tools(tmp_path / "nope")
    assert meta["files_total"] == 0
    assert meta["files_capped"] is False


def test_read_events_meta_capped_over_max_files(tmp_path):
    _write_many(tmp_path, "main", 61)
    events, meta = read_events(tmp_path, max_files=60)
    assert meta["files_total"] == 61
    assert meta["files_capped"] is True
    assert meta["files_scanned"] == 60


def test_read_events_meta_not_capped_at_max_files(tmp_path):
    _write_many(tmp_path, "main", 60)
    events, meta = read_events(tmp_path, max_files=60)
    assert meta["files_total"] == 60
    assert meta["files_capped"] is False


def test_read_events_explicit_path_files_total_and_not_capped(tmp_path):
    _write_traj(tmp_path, "sess1", [_call("bash", {"command": "ls"})])
    path = tmp_path / "agents" / "main" / "sessions" / "sess1.trajectory.jsonl"
    events, meta = read_events(tmp_path / "unused", explicit_path=str(path))
    assert meta["files_total"] == 1
    assert meta["files_capped"] is False
