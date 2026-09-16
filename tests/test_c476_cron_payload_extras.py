"""C-476 — cron payload surface widening: collector._cron_payload_extras() and its two
call sites (JSON-file store, modern SQLite job_json store).

The legacy trigger_script/payload_message parity model (B-709) restored exactly two
flat fields. The vendor's real payload union is four kinds wide (systemEvent /
agentTurn / command / script, plus system-owned heartbeat), and two members carry
direct execution/untrusted-content surfaces this project did not read at all:
command's argv/cwd/env, script's toolBudget, agentTurn's
allowUnsafeExternalContent/externalContentSource, and toolsAllow (present on every
payload kind via the CronPayloadToolAllow intersection type, not agentTurn-only).

Grounded against the installed OpenClaw 2026.9.4 dist's CronPayload union
(plugin-entry-C9jaZrZv.d.ts, the CronJobBase region) — see
collector._cron_payload_extras's own docstring for the full field:kind mapping.

Offline, read-only, stdlib only — writes only under pytest's tmp_path.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from clawseccheck.collector import Context, _collect_cron

_ALL_EXTRA_KEYS = (
    "payload_argv", "payload_cwd", "payload_env", "payload_input", "payload_script",
    "payload_tool_budget", "payload_allow_unsafe_external_content",
    "payload_external_content_source", "payload_tools_allow",
)


def _json_home(tmp_path: Path, payload: dict, job_id: str = "j1") -> Context:
    home = tmp_path / "home"
    (home / "cron").mkdir(parents=True, exist_ok=True)
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    (home / "cron" / "jobs.json").write_text(json.dumps({
        "version": 1,
        "jobs": [{
            "id": job_id,
            "name": "job",
            "enabled": True,
            "createdAtMs": 1,
            "updatedAtMs": 1,
            "schedule": {"kind": "cron", "expr": "0 9 * * *"},
            "sessionTarget": {"kind": "new"},
            "wakeMode": "background",
            "payload": payload,
            "state": "active",
        }],
    }), encoding="utf-8")
    ctx = Context(home=home)
    _collect_cron(home, ctx)
    return ctx


_MODERN_DDL = (
    "CREATE TABLE cron_jobs ("
    "store_key TEXT, job_id TEXT, declaration_key TEXT, owner_agent_id TEXT, "
    "name TEXT, description TEXT, enabled INTEGER, agent_id TEXT, payload_kind TEXT, "
    "job_json TEXT, state_json TEXT, runtime_updated_at_ms INTEGER, "
    "schedule_identity TEXT, sort_order INTEGER, updated_at INTEGER)"
)
_MODERN_COLUMNS = (
    "store_key", "job_id", "declaration_key", "owner_agent_id", "name", "description",
    "enabled", "agent_id", "payload_kind", "job_json", "state_json",
    "runtime_updated_at_ms", "schedule_identity", "sort_order", "updated_at",
)


def _sqlite_home(tmp_path: Path, payload: dict, job_id: str = "j1") -> Context:
    home = tmp_path / "home"
    state = home / "state"
    state.mkdir(parents=True)
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    conn = sqlite3.connect(state / "openclaw.sqlite")
    try:
        conn.execute(_MODERN_DDL)
        job_json = json.dumps({"payload": payload})
        row = (
            "default", job_id, f"decl-{job_id}", "main", "job", "a cron job", 1, "main",
            payload.get("kind"), job_json, "{}", 1_700_000_000_000, "sched", 0,
            1_700_000_000_000,
        )
        conn.execute(
            f"INSERT INTO cron_jobs ({','.join(_MODERN_COLUMNS)}) VALUES "
            f"({','.join('?' for _ in _MODERN_COLUMNS)})", row,
        )
        conn.commit()
    finally:
        conn.close()
    ctx = Context(home=home)
    _collect_cron(home, ctx)
    return ctx


# --------------------------------------------------------------------------- command


def test_json_store_extracts_command_argv_cwd_env(tmp_path):
    payload = {"kind": "command", "argv": ["curl", "http://x"], "cwd": "/tmp",
               "env": {"FOO": "bar"}, "input": "attacker payload"}
    job = _json_home(tmp_path, payload).cron_jobs[0]
    assert job["payload_argv"] == ["curl", "http://x"]
    assert job["payload_cwd"] == "/tmp"
    assert job["payload_env"] == {"FOO": "bar"}
    assert job["payload_input"] == "attacker payload"


def test_modern_sqlite_extracts_command_argv_cwd_env(tmp_path):
    payload = {"kind": "command", "argv": ["rm", "-rf", "/tmp/x"], "cwd": "/home",
               "env": {"X": "1"}, "input": "stdin body"}
    job = _sqlite_home(tmp_path, payload).cron_jobs[0]
    assert job["payload_argv"] == ["rm", "-rf", "/tmp/x"]
    assert job["payload_cwd"] == "/home"
    assert job["payload_env"] == {"X": "1"}
    assert job["payload_input"] == "stdin body"


def test_input_on_a_non_command_kind_is_not_extracted(tmp_path):
    payload = {"kind": "script", "script": "x", "input": "should not leak"}
    job = _json_home(tmp_path, payload).cron_jobs[0]
    assert job["payload_input"] is None


# --------------------------------------------------------------------------- script


def test_script_kind_extracts_script_body_and_tool_budget(tmp_path):
    payload = {"kind": "script", "script": "print(1)", "toolBudget": 5}
    job = _json_home(tmp_path, payload).cron_jobs[0]
    assert job["payload_script"] == "print(1)"
    assert job["payload_tool_budget"] == 5


def test_modern_sqlite_script_kind_extracts_script_and_tool_budget(tmp_path):
    payload = {"kind": "script", "script": "import os", "toolBudget": 3}
    job = _sqlite_home(tmp_path, payload).cron_jobs[0]
    assert job["payload_script"] == "import os"
    assert job["payload_tool_budget"] == 3


# --------------------------------------------------------------------------- agentTurn


def test_agent_turn_extracts_unsafe_external_content_fields(tmp_path):
    payload = {
        "kind": "agentTurn", "message": "hi",
        "allowUnsafeExternalContent": True, "externalContentSource": "email",
    }
    job = _json_home(tmp_path, payload).cron_jobs[0]
    assert job["payload_allow_unsafe_external_content"] is True
    assert job["payload_external_content_source"] == "email"


# --------------------------------------------------------------------------- toolsAllow


def test_tools_allow_extracted_on_every_kind(tmp_path):
    cases = [
        ("systemEvent", {"text": "x"}),
        ("agentTurn", {"message": "hi"}),
        ("command", {"argv": ["echo"]}),
        ("script", {"script": "x"}),
    ]
    for kind, extra in cases:
        payload = {"kind": kind, "toolsAllow": ["*"], **extra}
        job = _json_home(tmp_path, payload).cron_jobs[0]
        assert job["payload_tools_allow"] == ["*"], kind


# --------------------------------------------------------------------------- kind-gating
# A same-named key on the WRONG kind is never a genuine declaration (B-378 idiom): the
# vendor's payload type is a tagged union, so a stray same-named field elsewhere is not
# something any real client writes.


def test_argv_on_a_non_command_kind_is_not_extracted(tmp_path):
    payload = {"kind": "agentTurn", "message": "hi", "argv": ["should", "not", "leak"]}
    job = _json_home(tmp_path, payload).cron_jobs[0]
    assert job["payload_argv"] is None


def test_script_on_a_non_script_kind_is_not_extracted(tmp_path):
    payload = {"kind": "systemEvent", "text": "x", "script": "should not leak"}
    job = _json_home(tmp_path, payload).cron_jobs[0]
    assert job["payload_script"] is None


def test_allow_unsafe_external_content_on_non_agent_turn_is_not_extracted(tmp_path):
    payload = {"kind": "command", "argv": ["echo"], "allowUnsafeExternalContent": True}
    job = _json_home(tmp_path, payload).cron_jobs[0]
    assert job["payload_allow_unsafe_external_content"] is None


# --------------------------------------------------------------------------- absence / shape


def test_missing_fields_are_none_not_absent_keys(tmp_path):
    payload = {"kind": "systemEvent", "text": "hi"}
    job = _json_home(tmp_path, payload).cron_jobs[0]
    for key in _ALL_EXTRA_KEYS:
        assert key in job
        assert job[key] is None


def test_wrong_shaped_values_never_raise_and_degrade_to_none(tmp_path):
    """B-378 idiom: a schema-drifted value (wrong type at the right key) must degrade,
    never crash and never be passed through as if it were the real declared value."""
    payload = {
        "kind": "command", "argv": "not-a-list", "cwd": 5, "env": ["not", "a", "dict"],
        "toolsAllow": "not-a-list",
    }
    job = _json_home(tmp_path, payload).cron_jobs[0]
    assert job["payload_argv"] is None
    assert job["payload_cwd"] is None
    assert job["payload_env"] is None
    assert job["payload_tools_allow"] is None
