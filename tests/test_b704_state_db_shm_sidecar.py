"""B-704 — the state DB's read-only opens still rewrite the -shm sidecar.

Every reader of ``~/.openclaw/state/openclaw.sqlite`` (``_collect_cron``,
``_collect_cron_run_logs``, ``_collect_plugin_trust``, ``_collect_audit_events``,
``_collect_config_machine_state``, and every other ``collector.py`` function that opens
this database) connects ``file:...?mode=ro`` plus ``PRAGMA query_only = 1`` — a read-only
open by every measure this tool controls. But SQLite's WAL mode still rewrites the
``-shm`` shared-memory index as a side effect of opening ANY WAL-mode database, even for a
connection that never executes a single write statement: the reader has to negotiate the
WAL index's shared-memory layout with any other connection, and that negotiation touches
the file. This is a property of SQLite's WAL implementation, not a bug in one collector
function, so this test pins the aggregate behaviour of a real ``collect()`` run rather than
one reader in isolation.

Golden Rule #2 ("Read-only by default... does not mutate the user's agent") is therefore
precise but not literally exhaustive — see SECURITY_MODEL.md's "Allowed behavior" section
for the documented exception this test exists to pin. ``immutable=1`` (tells SQLite the
file can never change, which is false for a database a live OpenClaw process is writing)
and copying the ~5.9MB database before every run (safe but expensive) were both considered
and rejected; the fix is documenting the behaviour precisely, which is what this regression
test guards against silently drifting (e.g. a future change that also touches ``-wal`` or
the ``.sqlite`` file itself, which would be a strictly worse outcome than today's).

Fixture note: closing a WAL-mode SQLite connection normally triggers an automatic
checkpoint that deletes the ``-wal``/``-shm`` sidecars, so a real machine only carries them
because the OpenClaw process itself holds a WAL connection open continuously. The writer
connection below is deliberately kept open (never ``.close()``d until the very end) to
reproduce that live-process shape rather than a stale/closed one.
"""
from __future__ import annotations

import hashlib
import sqlite3

from clawseccheck.collector import collect

_STATE_FILES = ("openclaw.sqlite", "openclaw.sqlite-wal", "openclaw.sqlite-shm")

# Column lists copied from tests/test_b294_cron_run_logs.py / test_f183_config_machine_state.py
# so this fixture's schema cannot silently drift from the real reader's expectations.
_CRON_JOBS_DDL = (
    "CREATE TABLE cron_jobs (job_id TEXT, name TEXT, enabled INTEGER, "
    "delete_after_run INTEGER, trigger_script TEXT, payload_kind TEXT, payload_message TEXT)"
)
_CONFIG_MACHINE_STATE_DDL = (
    "CREATE TABLE config_machine_state "
    "(state_key TEXT PRIMARY KEY, value_json TEXT, updated_at_ms INTEGER)"
)


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_collect_touches_only_the_shm_sidecar(tmp_path):
    """copy^H^H^H^Hbuild a real WAL-mode DB with sidecars, run collect(), and assert
    exactly which files under state/ may change: today that is {"openclaw.sqlite-shm"}
    and nothing else. The .sqlite file and the -wal file must stay byte-identical."""
    home = tmp_path / "openclaw"
    state = home / "state"
    state.mkdir(parents=True)
    (home / "openclaw.json").write_text("{}", encoding="utf-8")

    db_path = state / "openclaw.sqlite"
    writer = sqlite3.connect(str(db_path))
    try:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute(_CRON_JOBS_DDL)
        writer.execute(
            "INSERT INTO cron_jobs VALUES (?,?,?,?,?,?,?)",
            ("job1", "test-job", 1, 0, None, "message", "hi"),
        )
        writer.execute(_CONFIG_MACHINE_STATE_DDL)
        writer.execute(
            "INSERT INTO config_machine_state VALUES (?,?,?)",
            ("plugins.bundledDiscovery", '"allowlist"', 0),
        )
        writer.commit()

        # Sanity: the fixture actually produced real WAL sidecars, or this test would
        # pass vacuously (nothing to rewrite).
        for name in _STATE_FILES:
            assert (state / name).exists(), (
                f"fixture setup did not produce a real {name} — WAL mode may not have "
                "taken effect on this SQLite build"
            )
        assert (state / "openclaw.sqlite-shm").stat().st_size == 32768, (
            "the -shm sidecar's documented size (SECURITY_MODEL.md) is 32768 bytes on a "
            "single-page WAL index; a different size here means the fixture no longer "
            "matches what is documented"
        )

        before = {name: _sha256(state / name) for name in _STATE_FILES}

        ctx = collect(home)  # the full collector pipeline, read-only by every reader

        after = {name: _sha256(state / name) for name in _STATE_FILES}
    finally:
        writer.close()

    assert ctx.errors == [], f"collect() must not error against a well-formed state DB: {ctx.errors}"

    changed = {name for name in _STATE_FILES if before[name] != after[name]}
    assert changed == {"openclaw.sqlite-shm"}, (
        f"expected only openclaw.sqlite-shm to change from a read-only collect() run, "
        f"got {changed} (before={before}, after={after})"
    )

    assert before["openclaw.sqlite"] == after["openclaw.sqlite"], (
        "the .sqlite file itself must be byte-identical before/after collect()"
    )
    assert before["openclaw.sqlite-wal"] == after["openclaw.sqlite-wal"], (
        "the -wal file must be byte-identical before/after collect()"
    )
    assert before["openclaw.sqlite-shm"] != after["openclaw.sqlite-shm"], (
        "this is the documented exception itself — if this ever starts failing, SQLite's "
        "WAL-open behaviour (or how these readers open the file) has changed, and "
        "SECURITY_MODEL.md's note needs re-verifying, not just this assertion deleting"
    )
