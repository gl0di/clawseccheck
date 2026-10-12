"""C-690 -- B18's retention and payload-field statements, grounded by EXECUTING the vendor.

A grep that finds a symbol proves the citation is live, not that the prose describes what the
symbol does (``tests/_distgrounding.py``). So this file runs two vendor functions from the
INSTALLED OpenClaw dist in ``node`` and compares their answers with what the package says:

* ``updateSubagentArchiveAtMs`` -- the single place ``archiveAtMs`` (the only removal clock of
  a ``subagent_runs`` row) is assigned. Four cases plus a control:

  ================================  ==============================================
  ``cleanup: "keep"``, ended        no ``archiveAtMs`` (a default spawn is never swept)
  ``cleanup: "delete"``, ended at T T + 60 minutes (clock starts at COMPLETION)
  ``cleanup: "delete"``, in flight  no ``archiveAtMs``
  ``cleanup: "delete"``, session    no ``archiveAtMs``
  ``archiveAfterMinutes: 5`` (ctrl) T + 5 minutes (the function reads the setting)
  ================================  ==============================================

  The next change of this rule is a red test here, not a stale sentence in B18's ``fix``.
* ``bindSubagentRunRecord`` -- the serializer that writes ``payload_json``. Rows it produces
  (flat and parent-wrapped) are inserted into a modern ``subagent_runs`` table and read back
  through ``collector._collect_subagent_runs``: all four formerly "absent" fields come back.

Local-only: skipped when node or the installed dist is absent (CI). The vendor bundles are
imported as they are, but under a scratch ``$HOME`` and a minimal environment so the real
``~/.openclaw`` (which holds live tokens) is never reachable; the scratch ``$HOME`` is
asserted empty afterwards. Exported names are minified per release (``d``, ``O``), so the
functions are found by their real ``.name``, and the bundles by the line that declares them.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess

import pytest
from _distgrounding import dist_declaring, require_dist

from clawseccheck.collector import (
    LIMIT_DOMAIN_AGENTS,
    Context,
    _collect_subagent_runs,
    limit_hits_for,
)
from test_b709_subagent_runs_shapes import _MODERN_DDL

_NODE_TIMEOUT_S = 120

_HARNESS = r"""
import { pathToFileURL } from "node:url";
const spec = JSON.parse(process.argv[2]);

async function pick(file, name) {
  const mod = await import(pathToFileURL(file).href);
  const fn = Object.values(mod).find((v) => typeof v === "function" && v.name === name);
  if (!fn) throw new Error(name + " is not exported by " + file);
  return fn;
}

const out = {};
if (spec.archive) {
  const update = await pick(spec.archive.file, "updateSubagentArchiveAtMs");
  const T = spec.archive.endedAt;
  const entry = (o) => ({
    execution: { endedAt: o.ended ? T : undefined },
    cleanup: o.cleanup, spawnMode: o.spawnMode,
  });
  const cfg = (minutes) => ({
    agents: { defaults: { subagents: minutes === undefined ? {} : { archiveAfterMinutes: minutes } } },
  });
  const cases = {
    keep_ended: [entry({ cleanup: "keep", ended: true }), cfg()],
    delete_ended: [entry({ cleanup: "delete", ended: true }), cfg()],
    delete_in_flight: [entry({ cleanup: "delete", ended: false }), cfg()],
    delete_session_ended: [entry({ cleanup: "delete", ended: true, spawnMode: "session" }), cfg()],
    delete_ended_5min: [entry({ cleanup: "delete", ended: true }), cfg(5)],
  };
  out.archive = {};
  for (const [label, [e, c]] of Object.entries(cases)) {
    update(e, c);
    out.archive[label] = e.archiveAtMs === undefined ? null : e.archiveAtMs - T;
  }
}
if (spec.bind) {
  const bind = await pick(spec.bind.file, "bindSubagentRunRecord");
  out.rows = spec.bind.records.map((r) => bind(r));
}
process.stdout.write(JSON.stringify(out));
"""


def _node(tmp_path, spec: dict) -> dict:
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed -- the vendor functions are executed, not read")
    tmp_path.mkdir(parents=True, exist_ok=True)
    home = tmp_path / "home"
    home.mkdir()
    harness = tmp_path / "harness.mjs"
    harness.write_text(_HARNESS, encoding="utf-8")
    env = {"HOME": str(home), "PATH": os.environ.get("PATH", ""), "LANG": "C"}
    proc = subprocess.run(
        [node, str(harness), json.dumps(spec)], capture_output=True, text=True,
        env=env, cwd=str(tmp_path), timeout=_NODE_TIMEOUT_S,
    )
    assert proc.returncode == 0, f"node exited {proc.returncode}: {proc.stderr.strip()[-600:]}"
    assert list(home.iterdir()) == [], "importing the vendor bundle wrote into the scratch HOME"
    return json.loads(proc.stdout)


@pytest.fixture(scope="module")
def archive_file():
    require_dist()
    return dist_declaring("function updateSubagentArchiveAtMs(", symbol="updateSubagentArchiveAtMs")


@pytest.fixture(scope="module")
def bind_file():
    require_dist()
    return dist_declaring("function bindSubagentRunRecord(", symbol="bindSubagentRunRecord")


_HOUR_MS = 60 * 60_000
_ENDED_AT = 1_000_000_000_000


def test_the_removal_clock_starts_at_completion_and_only_for_delete_runs(tmp_path, archive_file):
    got = _node(tmp_path, {"archive": {"file": str(archive_file), "endedAt": _ENDED_AT}})["archive"]
    # A default ("keep") spawn is never given a removal time.
    assert got["keep_ended"] is None
    # "delete", ended at T: T + the 60-minute default -- counted from COMPLETION.
    assert got["delete_ended"] == _HOUR_MS
    # Still in flight: nothing to age out yet, however the spawn was started.
    assert got["delete_in_flight"] is None
    # Session mode never gets one (it is dropped ~5 minutes after its cleanup completes).
    assert got["delete_session_ended"] is None
    # Control: the same function honours archiveAfterMinutes, so the 60 above is not a
    # constant that merely happens to match.
    assert got["delete_ended_5min"] == 5 * 60_000


def _records() -> list:
    base = {
        "runId": "r-flat", "childSessionKey": "agent:main:subagent:flat",
        "requesterSessionKey": "agent:main:main", "createdAt": 1000,
        "task": "summarise the inbox", "spawnMode": "run", "cleanup": "keep",
        "model": "provider/model-x", "runTimeoutSeconds": 30,
        "agentDir": "/home/user/.openclaw/agents/main/agent", "workspaceDir": "/home/user/ws",
        "execution": {"status": "terminal", "endedAt": 2000, "outcome": {"status": "ok"}},
        "endedReason": "complete",
        "completion": {"required": False}, "delivery": {"status": "not_required"},
    }
    wrapped = dict(base, runId="r-parent", childSessionKey="agent:main:subagent:parent",
                   createdAt=1001, completionTarget="parent", spawnMode="session",
                   cleanup="delete", workspaceDir="/home/user/other")
    return [base, wrapped]


def test_rows_from_the_real_serializer_read_back_with_all_four_fields(tmp_path, bind_file):
    rows = _node(tmp_path / "node", {"bind": {"file": str(bind_file), "records": _records()}})["rows"]
    # The serializer wraps a parent-targeted record under "parentCompletion", flat otherwise.
    assert ["parentCompletion" in json.loads(r["payload_json"]) for r in rows] == [False, True]

    home = tmp_path / "openclaw"
    (home / "state").mkdir(parents=True)
    conn = sqlite3.connect(home / "state" / "openclaw.sqlite")
    try:
        conn.execute(_MODERN_DDL)
        for r in rows:
            conn.execute(
                "INSERT INTO subagent_runs (run_id, child_session_key, controller_session_key, "
                "requester_session_key, created_at, payload_json) VALUES (?,?,?,?,?,?)",
                (r["run_id"], r["child_session_key"], r["controller_session_key"],
                 r["requester_session_key"], r["created_at"], r["payload_json"]),
            )
        conn.commit()
    finally:
        conn.close()
    ctx = Context(home=home)
    _collect_subagent_runs(home, ctx)

    by_key = {r["child_session_key"]: r for r in ctx.subagent_runs}
    flat = by_key["agent:main:subagent:flat"]
    parent = by_key["agent:main:subagent:parent"]
    assert flat["agent_dir"] == "/home/user/.openclaw/agents/main/agent"
    assert flat["workspace_dir"] == "/home/user/ws"
    assert flat["spawn_mode"] == "run"
    assert flat["task"] == "summarise the inbox"
    assert parent["spawn_mode"] == "session"
    assert parent["workspace_dir"] == "/home/user/other"
    assert parent["agent_dir"] == "/home/user/.openclaw/agents/main/agent"
    assert parent["task"] == "summarise the inbox"
    # What was already read is still read, and the "not present" note is gone.
    assert flat["model"] == "provider/model-x" and flat["run_timeout_seconds"] == 30
    assert flat["outcome"] == {"status": "ok"} and flat["ended_reason"] == "complete"
    assert limit_hits_for(ctx, LIMIT_DOMAIN_AGENTS) == []
