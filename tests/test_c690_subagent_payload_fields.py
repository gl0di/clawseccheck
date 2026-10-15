"""C-690 -- B18's subagent-run evidence on the MODERN ``subagent_runs`` shape.

Two false statements, both about OpenClaw's own data, fixed here:

1. ``agent_dir``, ``workspace_dir``, ``spawn_mode`` and ``task`` were reported as "not
   present on this state schema -- NOT read" and printed as ``?``. The vendor serializer
   (``bindSubagentRunRecord``) writes the whole canonical record into ``payload_json``, so
   they were UNREAD, not absent. The rows below use that serializer's real key names
   (``agentDir``, ``workspaceDir``, ``spawnMode``, ``task``, ``cleanup``, ``model``,
   ``runTimeoutSeconds``, ``execution.outcome.status``, ``endedReason``), flat and wrapped
   under ``parentCompletion``. ``tests/test_c690_dist_retention_grounding.py`` feeds rows
   produced by the real installed serializer through the same reader (local-only).
2. B18's WARN claimed spawns are "typically pruned within about an hour of being SPAWNED".
   Executing the vendor's ``updateSubagentArchiveAtMs`` shows the clock starts at
   COMPLETION and only for ``cleanup: "delete"`` (or collector) runs; a default ``keep`` row
   is never swept. ``detail`` no longer carries the false claim (so the B18 disk-disclosure
   fingerprints moved; they already varied with the spawn count) and ``fix`` states the rule.

The table DDL is imported from ``test_b709_subagent_runs_shapes`` (already registered with
the state-schema grounding), never re-declared here.
"""
from __future__ import annotations

import json
import sqlite3

import pytest

from clawseccheck.catalog import WARN
from clawseccheck.checks import check_subagents
from clawseccheck.collector import (
    LIMIT_DOMAIN_AGENTS,
    Context,
    _MAX_SUBAGENT_TASK_CHARS,
    _collect_subagent_runs,
    limit_hits_for,
)
from test_b709_subagent_runs_shapes import _MODERN_DDL

_COLUMNS = ("run_id", "child_session_key", "requester_session_key", "created_at", "payload_json")


def _record(**overrides) -> dict:
    """A canonical run record carrying the serializer's real key names."""
    rec = {
        "task": "summarise the inbox",
        "spawnMode": "run",
        "cleanup": "keep",
        "model": "provider/model-x",
        "runTimeoutSeconds": 120,
        "agentDir": "/home/user/.openclaw/agents/main/agent",
        "workspaceDir": "/home/user/work/project",
        "execution": {"status": "terminal", "outcome": {"status": "ok"}},
        "endedReason": "complete",
    }
    rec.update(overrides)
    return rec


def _wrapped(rec: dict) -> dict:
    """What the serializer stores when the completion target is the parent."""
    return {"parentCompletion": dict(rec, completionTarget="parent")}


def _ctx(tmp_path, payloads, *, cfg=None) -> Context:
    home = tmp_path / "openclaw"
    state = home / "state"
    state.mkdir(parents=True)
    conn = sqlite3.connect(state / "openclaw.sqlite")
    try:
        conn.execute(_MODERN_DDL)
        for i, payload in enumerate(payloads):
            conn.execute(
                f"INSERT INTO subagent_runs ({','.join(_COLUMNS)}) VALUES (?,?,?,?,?)",
                (f"r{i}", f"child-{i}", f"req-{i}", 1000 + i, json.dumps(payload)),
            )
        conn.commit()
    finally:
        conn.close()
    ctx = Context(home=home)
    ctx.config = cfg if cfg is not None else {"agents": {"list": [{"name": "main"}]}}
    _collect_subagent_runs(home, ctx)
    return ctx


_FOUR = ("agent_dir", "workspace_dir", "spawn_mode", "task")


# ----------------------------------------------------------------------- collector

@pytest.mark.parametrize("payload", [_record(), _wrapped(_record())], ids=["flat", "parent-wrapped"])
def test_the_four_fields_are_read_from_the_payload(tmp_path, payload):
    ctx = _ctx(tmp_path, [payload])
    run = ctx.subagent_runs[0]
    assert run["agent_dir"] == "/home/user/.openclaw/agents/main/agent"
    assert run["workspace_dir"] == "/home/user/work/project"
    assert run["spawn_mode"] == "run"
    assert run["task"] == "summarise the inbox"
    # ... and the fields that were already read are still read.
    assert run["model"] == "provider/model-x"
    assert run["run_timeout_seconds"] == 120
    assert run["outcome"] == {"status": "ok"}
    assert run["ended_reason"] == "complete"


def test_session_mode_and_delete_cleanup_rows_are_read(tmp_path):
    ctx = _ctx(tmp_path, [
        _record(spawnMode="session", cleanup="delete"),
        _wrapped(_record(spawnMode="run", cleanup="delete", workspaceDir="/srv/w")),
    ])
    by_key = {r["child_session_key"]: r for r in ctx.subagent_runs}
    assert by_key["child-0"]["spawn_mode"] == "session"
    assert by_key["child-1"]["spawn_mode"] == "run"
    assert by_key["child-1"]["workspace_dir"] == "/srv/w"


def test_no_not_present_note_when_the_rows_carry_the_fields(tmp_path):
    ctx = _ctx(tmp_path, [_record(), _wrapped(_record())])
    assert limit_hits_for(ctx, LIMIT_DOMAIN_AGENTS) == []


def test_a_row_that_really_lacks_them_keeps_none_and_nothing_is_invented(tmp_path):
    ctx = _ctx(tmp_path, [{"model": "provider/model-x"}])
    run = ctx.subagent_runs[0]
    assert all(run[k] is None for k in _FOUR)
    # The note survives, but it is now a statement about the ROWS, not about the schema.
    hits = limit_hits_for(ctx, LIMIT_DOMAIN_AGENTS)
    assert any("none of the 1 row(s) read carries" in h for h in hits), hits
    assert not any("not present on this state schema" in h for h in hits), hits


def test_one_row_lacking_a_field_beside_a_row_that_has_it_emits_no_note(tmp_path):
    ctx = _ctx(tmp_path, [_record(), _record(agentDir=None, workspaceDir=None)])
    assert limit_hits_for(ctx, LIMIT_DOMAIN_AGENTS) == []
    lacking = next(r for r in ctx.subagent_runs if r["child_session_key"] == "child-1")
    assert lacking["agent_dir"] is None and lacking["workspace_dir"] is None
    assert lacking["spawn_mode"] == "run"


@pytest.mark.parametrize("bad", [123, ["a"], {"a": 1}, True, "", "   "])
def test_a_wrong_typed_or_blank_value_is_none_not_coerced(tmp_path, bad):
    ctx = _ctx(tmp_path, [_record(agentDir=bad, workspaceDir=bad, spawnMode=bad, task=bad)])
    assert all(ctx.subagent_runs[0][k] is None for k in _FOUR)


def test_task_is_capped_like_the_legacy_column(tmp_path):
    ctx = _ctx(tmp_path, [_record(task="x" * (_MAX_SUBAGENT_TASK_CHARS + 400))])
    task = ctx.subagent_runs[0]["task"]
    assert task.endswith("...(truncated)")
    assert len(task) == _MAX_SUBAGENT_TASK_CHARS + len("...(truncated)")


def test_a_wrapper_naming_another_target_is_not_unwrapped_for_the_new_fields(tmp_path):
    # Same rule the vendor's reader applies (model et al. already follow it): only a
    # wrapper whose completionTarget is "parent" is unwrapped.
    payload = {"parentCompletion": dict(_record(), completionTarget="other")}
    ctx = _ctx(tmp_path, [payload])
    assert all(ctx.subagent_runs[0][k] is None for k in _FOUR)


# ----------------------------------------------------------------------- B18 text

def _b18(tmp_path, payloads):
    ctx = _ctx(tmp_path, payloads)
    return check_subagents(ctx)


def test_b18_evidence_shows_the_fields_the_row_has(tmp_path):
    f = _b18(tmp_path, [_record(), _wrapped(_record(spawnMode="session"))])
    assert f.status == WARN
    text = "\n".join(f.evidence)
    assert "agent_dir=/home/user/.openclaw/agents/main/agent" in text
    assert "workspace_dir=/home/user/work/project" in text
    assert "spawn_mode=run" in text and "spawn_mode=session" in text
    assert "agent_dir=?" not in text and "workspace_dir=?" not in text
    assert "spawn_mode=?" not in text
    # The delegated task text is free-form content: it is read, never echoed (STD-03).
    assert "summarise the inbox" not in text
    assert "summarise the inbox" not in f.detail + f.fix


def test_b18_evidence_keeps_the_question_mark_for_a_row_that_lacks_them(tmp_path):
    f = _b18(tmp_path, [{"model": "provider/model-x"}])
    assert f.status == WARN
    text = "\n".join(f.evidence)
    assert "agent_dir=?, workspace_dir=?, spawn_mode=?" in text


def test_b18_detail_makes_no_false_retention_claim_and_fix_states_the_executed_rule(tmp_path):
    f = _b18(tmp_path, [_record()])
    for gone in ("SPAWNED", "about an hour", "nearly gone", "pruned"):
        assert gone not in f.detail, (gone, f.detail)
    assert "working registry" in f.detail and "see the advice below" in f.detail
    # The corrected statement (the measurement in test_c690_dist_retention_grounding.py).
    assert "COMPLETED" in f.fix
    assert "cleanup 'delete'" in f.fix and "60 minutes" in f.fix
    assert "default cleanup 'keep'" in f.fix and "not swept" in f.fix
    assert "never proves that no subagent ever ran" in f.fix
    assert "not from the spawn" in f.fix


def test_b18_detail_does_not_depend_on_the_new_fields(tmp_path):
    """A fingerprint hashes ``detail``: it varies with the spawn count only, as before."""
    with_fields = _b18(tmp_path / "a", [_record()])
    without = _b18(tmp_path / "b", [{"model": "provider/model-x"}])
    assert with_fields.detail == without.detail
