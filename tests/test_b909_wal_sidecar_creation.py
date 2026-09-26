"""B-909 — a read-only open of a WAL-mode SQLite database can CREATE its -shm/-wal
sidecars from nothing, not just rewrite ones that already exist.

The sibling issue B-704 pinned that opening a WAL-mode state database that ALREADY has
live ``-shm``/``-wal`` sidecars (because OpenClaw's own process holds the WAL open)
rewrites the ``-shm`` file in place. This module pins the stronger, more visible
manifestation: when OpenClaw is NOT currently running, its last connection cleanly
checkpoints and deletes both sidecars on close -- so a machine caught between OpenClaw
runs has neither file. Opening such a database read-only, via this codebase's own
``mode=ro`` + ``PRAGMA query_only = 1`` pattern, is enough to make SQLite materialize a
fresh 32768-byte ``-shm`` and an empty ``-wal`` where a moment ago there was nothing --
a genuine filesystem write against the user's own ``~/.openclaw`` tree by ordinary
read-only audit operation, not by any opt-in feature (Golden Rule #2).

Root cause (verified directly below, not merely asserted): SQLite's WAL protocol
requires every connection -- reader or writer -- to negotiate the WAL-index shared
memory segment with any other connection, and materializing that segment IS a
filesystem write; ``mode=ro``/``query_only`` only stop this tool from issuing writing
SQL, not SQLite's own WAL bookkeeping. The only stdlib knob that suppresses it is
``immutable=1``, which this module also demonstrates is unsound here: it works by
skipping the WAL entirely and reading the main file's already-checkpointed pages
directly, so a row committed to the WAL but not yet checkpointed back becomes invisible
-- silently missing evidence during the exact case this audit exists to observe (an
agent actively writing). That is a real correctness regression, not a smaller version of
the cosmetic sidecar write, so it was tried and retracted rather than shipped (C-135
grounds: it trades a benign side effect for a real false negative). See
SECURITY_MODEL.md's "Allowed behavior" section for the full disclosure this test exists
to keep honest, and the ``B-909`` note next to ``trajectorystore._open_readonly`` /
``collector.py``'s ``_collect_plugin_trust`` docstring for the in-source pointer.
"""
from __future__ import annotations

import sqlite3

from clawseccheck.collector import collect
from clawseccheck.trajectorystore import _open_readonly

_SIDECAR_SUFFIXES = ("-shm", "-wal")


def _sidecars(db_path):
    return {suffix: db_path.with_name(db_path.name + suffix) for suffix in _SIDECAR_SUFFIXES}


def test_open_readonly_creates_shm_and_wal_sidecars_from_nothing(tmp_path):
    """The per-agent trajectory database reader: a fresh WAL-mode DB whose last writer
    closed cleanly (no live process, so no sidecars survive) gets both a -shm and a -wal
    materialized by nothing more than this codebase's own read-only open."""
    db_path = tmp_path / "openclaw-agent.sqlite"

    writer = sqlite3.connect(str(db_path))
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute(
        "CREATE TABLE trajectory_runtime_events (session_id TEXT, seq INTEGER, event_json TEXT)"
    )
    writer.execute(
        "INSERT INTO trajectory_runtime_events VALUES (?,?,?)",
        ("s1", 1, '{"type":"turn"}'),
    )
    writer.commit()
    writer.close()  # last connection closing checkpoints + deletes -wal/-shm cleanly

    sidecars = _sidecars(db_path)
    for suffix, path in sidecars.items():
        assert not path.exists(), (
            f"fixture setup left a pre-existing {suffix} sidecar -- repro invalid, "
            "this test needs to start from a state with neither file present"
        )

    conn = _open_readonly(db_path)
    try:
        rows = conn.execute("SELECT session_id, seq FROM trajectory_runtime_events").fetchall()
    finally:
        conn.close()

    assert rows == [("s1", 1)]

    assert sidecars["-shm"].exists(), (
        "expected _open_readonly's mode=ro open of a WAL-mode DB to materialize -shm "
        "from nothing -- if this now fails, either SQLite's WAL-open behaviour changed "
        "upstream or _open_readonly stopped using a plain mode=ro connection, and "
        "SECURITY_MODEL.md's B-909 note needs re-verifying, not just this test deleting"
    )
    assert sidecars["-shm"].stat().st_size == 32768, (
        "the -shm sidecar's documented size (SECURITY_MODEL.md, B-909) is 32768 bytes "
        "for a single-page WAL index"
    )
    assert sidecars["-wal"].exists(), "expected an (empty) -wal sidecar to appear too"
    assert sidecars["-wal"].stat().st_size == 0, (
        "the freshly-created -wal sidecar is documented as empty (B-909) -- a read-only "
        "connection commits no frames to it"
    )


def test_collect_also_creates_state_db_sidecars_from_nothing(tmp_path):
    """Not specific to trajectorystore's helper: collector.py's state-DB readers (ten
    call sites, same inline mode=ro pattern, canonically documented in
    _collect_plugin_trust's docstring) hit the identical SQLite WAL behaviour."""
    home = tmp_path / "openclaw"
    state = home / "state"
    state.mkdir(parents=True)
    (home / "openclaw.json").write_text("{}", encoding="utf-8")

    db_path = state / "openclaw.sqlite"
    writer = sqlite3.connect(str(db_path))
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute(
        "CREATE TABLE cron_jobs (job_id TEXT, name TEXT, enabled INTEGER, "
        "delete_after_run INTEGER, trigger_script TEXT, payload_kind TEXT, payload_message TEXT)"
    )
    writer.execute(
        "INSERT INTO cron_jobs VALUES (?,?,?,?,?,?,?)",
        ("job1", "test-job", 1, 0, None, "message", "hi"),
    )
    writer.commit()
    writer.close()  # clean shutdown -- no live OpenClaw process, no surviving sidecars

    sidecars = _sidecars(db_path)
    for suffix, path in sidecars.items():
        assert not path.exists(), f"fixture setup left a pre-existing {suffix} -- repro invalid"

    ctx = collect(home)

    assert ctx.errors == [], f"collect() must not error against a well-formed state DB: {ctx.errors}"
    assert sidecars["-shm"].exists() and sidecars["-shm"].stat().st_size == 32768
    assert sidecars["-wal"].exists() and sidecars["-wal"].stat().st_size == 0


def test_immutable_1_would_silently_hide_uncommitted_wal_rows(tmp_path):
    """Pins WHY ``immutable=1`` was investigated and rejected as the fix for the above
    (SECURITY_MODEL.md, B-909; the same reasoning trajectorystore.py's per-agent reader
    already applied at B-811/68e9b077 time): it suppresses the sidecar write by skipping
    the WAL protocol entirely, so a row committed to the WAL but not yet checkpointed
    into the main file -- the ordinary state of a live, actively-writing OpenClaw
    process -- silently disappears from an immutable=1 reader's view, while an ordinary
    mode=ro reader (this codebase's actual choice) sees it correctly. If SQLite's own
    immutable-connection semantics ever change such that this assertion starts failing,
    the B-909 tradeoff needs re-examining, not this test quietly deleted."""
    db_path = tmp_path / "live.sqlite"

    writer = sqlite3.connect(str(db_path))
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("CREATE TABLE t (x INTEGER)")
    writer.execute("INSERT INTO t VALUES (1)")
    writer.commit()
    # Deliberately kept open (never closed, never checkpointed) to reproduce a live
    # OpenClaw process holding its WAL connection open with committed-but-unchecked-
    # pointed data -- exactly the shape a real running agent leaves behind.
    try:
        ordinary_reader = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            assert ordinary_reader.execute("SELECT x FROM t").fetchall() == [(1,)], (
                "sanity: this codebase's actual mode=ro pattern must see the committed "
                "row while the WAL is still open"
            )
        finally:
            ordinary_reader.close()

        immutable_reader = sqlite3.connect(
            f"file:{db_path.as_posix()}?mode=ro&immutable=1", uri=True
        )
        try:
            raised = False
            try:
                immutable_reader.execute("SELECT x FROM t").fetchall()
            except sqlite3.OperationalError:
                raised = True
            assert raised, (
                "expected immutable=1 to fail to see the table at all (it reads only "
                "the main file's last-checkpointed state, and nothing has been "
                "checkpointed yet) -- if this now succeeds, immutable=1's semantics "
                "changed and the B-909 rejection needs re-examining"
            )
        finally:
            immutable_reader.close()
    finally:
        writer.close()
