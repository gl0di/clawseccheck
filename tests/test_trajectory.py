"""Trajectory-sidecar reader (log-observed proven tool use) — read-only, name-only.

Grounded schema: docs/research/openclaw-schema-recon.md §9.1. The reader extracts the
set of tool verbs from tool.call records' data.name, gated on
traceSchema=openclaw-trajectory / schemaVersion=1, and NEVER reads call/return payloads.

Offline, stdlib only.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.trajectory import read_proven_tools


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
