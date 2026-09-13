"""Corroborate WHERE an agent's trajectory evidence actually lives (F-187).

OpenClaw moved from JSONL trajectory sidecar files to a SQLite-backed store around
version 9.x. ``trajectory.find_trajectory_files`` still globs only
``agents/*/sessions/*.trajectory.jsonl`` -- the pre-migration layout -- and on a current
install that glob is silently empty on every run: the runtime's own trajectory recorder
now defaults to a SQLite sink, and its "doctor" renamed the historical JSONL sidecars
away rather than leaving them in place. ``traceSchema``/``schemaVersion`` are UNCHANGED
across this move (it is not a schema change), so a build-time oracle over trajectory
files would never have caught it; this module is a RUNTIME corroborator instead.

**The core problem this exists to solve.** "Zero trajectory sidecars found" is the exact
same observation whether an agent never ran a single session, or whether it has months of
history that moved to a container this reader used to be blind to. Those are opposite
facts about the world, and collapsing them is the lying-clean Golden Rule #4 exists to
forbid. This module answers the question by reading three more containers, read-only and
bounded, and reconciling all four into one honest status -- never a bare count.

Containers read (grounded against a live install, 2026.9.x, measured first-hand -- not the
recon doc, which predates this migration):

  * live JSONL sidecars   -- ``trajectory.find_trajectory_files`` (reused, not
                              re-implemented) -- today's locator, unchanged when it finds
                              something
  * pointer files         -- ``agents/<agent>/sessions/<session>.trajectory-path.json``,
                              ``{"traceSchema": "openclaw-trajectory-pointer",
                              "schemaVersion": 1, "sessionId": ..., "runtimeFile": <abs
                              path>}``. A pointer whose named ``runtimeFile`` does NOT
                              exist is the strongest single signal this reader has: it is
                              direct, structured evidence that a session's trajectory used
                              to live at a path the classic glob no longer finds -- not
                              that nothing happened.
  * import archive        -- ``agents/<agent>/session-sqlite-import-archive/
                              <name>.imported-<epoch>`` -- the vendor doctor's own backup
                              of every sidecar/pointer it imported into SQLite. Its count
                              is BISTABLE on its own (flaps as the doctor's restore path
                              runs) and is never read as a verdict by itself -- only ever
                              as one named line in the disclosed breakdown.
  * SQLite                -- ``agents/<agent>/agent/openclaw-agent.sqlite``, table
                              ``trajectory_runtime_events`` (``session_id``, ``seq``,
                              ``run_id``, ``event_json``, ``created_at``). This is a
                              PER-AGENT database, unlike the shared
                              ``state/openclaw.sqlite`` F-183's ``config_machine_state``
                              reader already guards -- a different file, a different
                              guard, needed on its own.

**§8 -- this is a read of a genuinely new surface.** The SAME per-agent database that
holds ``trajectory_runtime_events`` also holds ``auth_profile_store`` / ``auth_profile_state``
-- LIVE OAuth tokens, measured present in both real per-agent databases on a live host
alongside this table. This reader touches ``trajectory_runtime_events`` and nothing else:
one hardcoded table name (:data:`TRAJECTORY_TABLE_NAME`), one literal, never-interpolated
SELECT statement (:data:`_SELECT_TRAJECTORY_ROWS`) naming only ``session_id``/``seq`` --
never ``event_json`` (the sensitive per-record payload), never a table built from a
variable, never ``SELECT *``. Pointer files and archive filenames are read for NAMES and
COUNTS only -- a pointer's own ``sessionId``/``runtimeFile`` fields, never anything past
that tiny envelope; an archive entry's filename, never its content.

**What this cannot catch (constraint 4, said plainly).** Every container this reader knows
about is residue of the SPECIFIC 8.1-era JSONL-to-SQLite migration: pointers, the import
archive, SQLite rows. A hypothetical FUTURE relocation that leaves none of those behind --
no pointer, no archive entry, no database row -- produces the exact same observation as an
agent that genuinely never ran: :data:`STATUS_NO_RESIDUE`. This module says so rather than
guessing, and a future migration will need its own corroborator the same way this one did.

Layer 1 leaf: stdlib plus ``trajectory.find_trajectory_files`` only (a sibling Layer-1
reader, reused rather than re-implemented -- the same relationship ``logdiscovery.py`` has
to it). Read-only, offline, bounded. Never imports ``checks/`` or anything above it.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from .trajectory import find_trajectory_files

# ---------------------------------------------------------------------------
# Bounds -- DoS guards, same spirit as every other bounded reader in this tree
# (trajectory._MAX_FILES, logdiscovery._MAX_PER_SOURCE, collector._MAX_CRON_RUN_LOGS).
# ---------------------------------------------------------------------------
_MAX_POINTER_SCAN = 500
_MAX_ARCHIVE_SCAN = 5000
_MAX_SQLITE_DBS = 50
_MAX_SQLITE_ROWS_PER_DB = 5000
# Only two tiny top-level fields are read per line here (sessionId, seq) -- far less than
# trajectory.py's own per-file cap needs to cover, since data/type are never touched.
_MAX_JSONL_BYTES_PER_FILE_FOR_DEDUP = 2_000_000

POINTER_SCHEMA = "openclaw-trajectory-pointer"

# The ONLY table this reader may ever touch. Hardcoded, reviewed, never computed --
# see the module docstring's §8 paragraph for why that matters on this exact database.
TRAJECTORY_TABLE_NAME = "trajectory_runtime_events"

# ONE literal, table-scoped SELECT. Never built by string formatting or interpolation --
# grep for "SELECT" in this module's source and this is the only line that contains one.
# Names only session_id/seq; event_json (the sensitive per-record payload) is never
# selected, and neither auth table is ever named anywhere in this module's source.
_SELECT_TRAJECTORY_ROWS = "SELECT session_id, seq FROM trajectory_runtime_events LIMIT ?"

# ---------------------------------------------------------------------------
# Reconciled status vocabulary. Three, not two: "definitely still here" (unchanged
# from today), "here, but not where the old locator looks" (the failure this module
# exists to name), and "not observed anywhere" (honest, and never "never ran" outright
# -- see the module docstring's closing paragraph).
# ---------------------------------------------------------------------------
STATUS_LIVE = "live"
STATUS_LOCATOR_STALE = "locator_stale"
STATUS_NO_RESIDUE = "no_residue"


@dataclass(frozen=True)
class TrajectoryCorroboration:
    """One honest reconciliation of every trajectory container this reader knows about.

    Every count is a field of its own -- never merged into a bare total, per this
    module's core design rule. ``evidence`` is the plain-English, ordered breakdown a
    renderer joins directly; formatting the sentence is this module's job, the same
    one-formatting-site idiom ``layers.describe_layer`` uses for the same reason.
    """

    status: str
    jsonl_files: int = 0
    pointer_files: int = 0
    pointer_files_capped: bool = False
    pointer_targets_missing: int = 0
    archive_entries: int = 0
    archive_entries_capped: bool = False
    sqlite_dbs_found: int = 0
    sqlite_dbs_read: int = 0
    sqlite_dbs_unreadable: int = 0
    sqlite_rows: int = 0
    sqlite_rows_capped: bool = False
    sqlite_sessions: int = 0
    evidence: tuple = ()

    @property
    def locator_stale(self) -> bool:
        return self.status == STATUS_LOCATOR_STALE


def _pointer_files(home: Path) -> "tuple[int, int, bool]":
    """``(pointer_files, pointer_targets_missing, capped)`` under ``agents/*/sessions/``.

    A pointer whose named ``runtimeFile`` does not exist is this reader's strongest
    signal (see the module docstring). A pointer that fails to parse, or does not match
    the grounded schema, is still counted toward ``pointer_files`` (real disk evidence
    that a session existed) but never toward ``pointer_targets_missing`` -- an unreadable
    record is an honest "we don't know", not a claim its target is gone.
    """
    try:
        it = home.glob("agents/*/sessions/*.trajectory-path.json")
    except OSError:
        return 0, 0, False
    total = 0
    missing = 0
    capped = False
    try:
        for p in it:
            if total >= _MAX_POINTER_SCAN:
                capped = True
                break
            total += 1
            try:
                rec = json.loads(p.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                continue
            if not isinstance(rec, dict) or rec.get("traceSchema") != POINTER_SCHEMA:
                continue
            target = rec.get("runtimeFile")
            if not isinstance(target, str) or not target.strip():
                continue
            try:
                if not Path(target).is_file():
                    missing += 1
            except OSError:
                continue
    except OSError:
        pass
    return total, missing, capped


def _archive_entries(home: Path) -> "tuple[int, bool]":
    """``(count, capped)`` of ``session-sqlite-import-archive/*.imported-*`` entries.

    NAMES ONLY -- an archived sidecar's filename is disk metadata (the vendor doctor's
    own restore-tier naming convention), never its content.
    """
    try:
        it = home.glob("agents/*/session-sqlite-import-archive/*")
    except OSError:
        return 0, False
    count = 0
    capped = False
    try:
        for p in it:
            if ".imported-" not in p.name:
                continue
            if count >= _MAX_ARCHIVE_SCAN:
                capped = True
                break
            count += 1
    except OSError:
        pass
    return count, capped


def _sqlite_dbs(home: Path) -> "list[Path]":
    try:
        dbs = sorted(home.glob("agents/*/agent/openclaw-agent.sqlite"))
    except OSError:
        return []
    return dbs[:_MAX_SQLITE_DBS]


def _read_sqlite_db(db_path: Path) -> "tuple[list, bool, bool]":
    """``(pairs, capped, unreadable)`` for one per-agent trajectory database.

    Opened ``mode=ro`` (never ``immutable=1`` -- that silently skips un-checkpointed WAL
    rows). Executes EXACTLY the one literal :data:`_SELECT_TRAJECTORY_ROWS` above -- this
    cannot reach ``auth_profile_store``/``auth_profile_state``, which share this exact
    database file, because their names appear nowhere in this reader's source.

    A database predating ``trajectory_runtime_events`` (``sqlite3.OperationalError: no
    such table``) is not corrupt -- the same honest "not unreadable, just absent" every
    other sqlite reader in this codebase reports (``collector._collect_cron_run_logs`` /
    ``_collect_config_machine_state``), so it is NOT counted toward ``unreadable``.
    """
    try:
        conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    except sqlite3.Error:
        return [], False, True
    try:
        conn.execute("PRAGMA query_only = 1")
        rows = conn.execute(
            _SELECT_TRAJECTORY_ROWS, (_MAX_SQLITE_ROWS_PER_DB + 1,)
        ).fetchall()
    except sqlite3.Error as exc:
        conn.close()
        if "no such table" in str(exc).lower():
            return [], False, False
        return [], False, True
    conn.close()
    capped = len(rows) > _MAX_SQLITE_ROWS_PER_DB
    pairs = [
        (r[0], r[1]) for r in rows[:_MAX_SQLITE_ROWS_PER_DB]
        if isinstance(r[0], str) and isinstance(r[1], int)
    ]
    return pairs, capped, False


def _jsonl_session_seq_pairs(files: "list[Path]") -> "set":
    """``{(sessionId, seq)}`` read from live sidecars -- ONLY these two top-level fields,
    never ``data``/``type``/anything else in the record. Exists solely so SQLite rows
    already represented by a live file are not double-counted as NEW evidence (the
    vendor's doctor can restore a JSONL sidecar from the archive while the matching
    SQLite rows are still present, which would otherwise double-count).
    """
    pairs: set = set()
    for path in files:
        try:
            read = 0
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    read += len(line)
                    if read > _MAX_JSONL_BYTES_PER_FILE_FOR_DEDUP:
                        break
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(rec, dict):
                        continue
                    sid = rec.get("sessionId")
                    seq = rec.get("seq")
                    if isinstance(sid, str) and isinstance(seq, int):
                        pairs.add((sid, seq))
        except OSError:
            continue
    return pairs


def corroborate(home) -> TrajectoryCorroboration:
    """Reconcile every trajectory container under *home* into one honest status.

    Decision rule, in order:

    1. A live ``.trajectory.jsonl`` sidecar exists -> :data:`STATUS_LIVE` -- today's
       locator's own happy path, unconditionally, regardless of what else is found. A
       machine that still has live sidecars is not blind, whatever else is true of it.
    2. No live sidecar, but a dangling pointer target, an import-archive entry, or a
       SQLite row exists -> :data:`STATUS_LOCATOR_STALE` -- real evidence the agent ran,
       stored somewhere the classic glob does not look.
    3. Nothing in any known container -> :data:`STATUS_NO_RESIDUE` -- honestly
       indistinguishable from "never ran" (see the module docstring's closing
       paragraph); never reported as a confident "this agent never ran".

    Never raises: every sub-reader swallows its own I/O errors and reports what it
    could, same contract as every other reader in this module and its siblings.
    """
    if not isinstance(home, Path):
        return TrajectoryCorroboration(status=STATUS_NO_RESIDUE)

    jsonl_files_list = find_trajectory_files(home)
    jsonl_count = len(jsonl_files_list)

    pointer_total, pointer_missing, pointer_capped = _pointer_files(home)
    archive_total, archive_capped = _archive_entries(home)

    dbs = _sqlite_dbs(home)
    sqlite_pairs: set = set()
    dbs_read = 0
    dbs_unreadable = 0
    rows_capped = False
    for db_path in dbs:
        pairs, capped, unreadable = _read_sqlite_db(db_path)
        if unreadable:
            dbs_unreadable += 1
            continue
        dbs_read += 1
        rows_capped = rows_capped or capped
        sqlite_pairs.update(pairs)

    # Dedupe file-based and DB-based records by (sessionId, seq): the vendor's doctor can
    # restore a JSONL sidecar from the archive while the matching SQLite rows are still
    # present, and a caller who read `sqlite_rows` on its own (independent of `status`)
    # must not see the SAME event counted as evidence twice. `sqlite_rows`/
    # `sqlite_sessions` below are always the DEDUPED figures — rows not already visible
    # via a live sidecar — so they stay meaningful regardless of what `status` says.
    # When jsonl_count == 0 (the common post-migration case) there is nothing to
    # subtract and this reduces to the raw SQLite figures.
    jsonl_pairs = _jsonl_session_seq_pairs(jsonl_files_list) if jsonl_count else set()
    sqlite_new_pairs = sqlite_pairs - jsonl_pairs
    sqlite_new_sessions = len({sid for sid, _ in sqlite_new_pairs})

    evidence: "list[str]" = []
    if pointer_missing:
        evidence.append(
            f"{pointer_missing} pointer file(s) name a trajectory file that no longer "
            "exists (agents/*/sessions/*.trajectory-path.json)"
        )
    if sqlite_new_pairs:
        evidence.append(
            f"{len(sqlite_new_pairs)} SQLite trajectory row(s) across "
            f"{sqlite_new_sessions} session(s) in {dbs_read} agent database(s) "
            "(agents/*/agent/openclaw-agent.sqlite, trajectory_runtime_events)"
        )
    if archive_total:
        evidence.append(
            f"{archive_total} archived trajectory sidecar(s) "
            "(agents/*/session-sqlite-import-archive/)"
        )

    if jsonl_count:
        status = STATUS_LIVE
    elif sqlite_new_pairs or pointer_missing or archive_total:
        status = STATUS_LOCATOR_STALE
    else:
        status = STATUS_NO_RESIDUE

    return TrajectoryCorroboration(
        status=status,
        jsonl_files=jsonl_count,
        pointer_files=pointer_total,
        pointer_files_capped=pointer_capped,
        pointer_targets_missing=pointer_missing,
        archive_entries=archive_total,
        archive_entries_capped=archive_capped,
        sqlite_dbs_found=len(dbs),
        sqlite_dbs_read=dbs_read,
        sqlite_dbs_unreadable=dbs_unreadable,
        sqlite_rows=len(sqlite_new_pairs),
        sqlite_rows_capped=rows_capped,
        sqlite_sessions=sqlite_new_sessions,
        evidence=tuple(evidence),
    )
