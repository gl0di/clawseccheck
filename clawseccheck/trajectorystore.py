"""Corroborate WHERE an agent's trajectory evidence actually lives (F-187).

OpenClaw moved from JSONL trajectory sidecar files to a SQLite-backed store around
version 9.x. Before B-732, ``trajectory.find_trajectory_files`` globbed only
``agents/*/sessions/*.trajectory.jsonl`` -- the pre-migration layout -- and on an
install past that migration the glob was silently empty on every run: the runtime's own
trajectory recorder now defaults to a SQLite sink, and its "doctor" renamed the
historical JSONL sidecars away rather than leaving them in place. B-732 closed PART of
that gap: ``find_trajectory_files`` now also follows a pointer file
(``*.trajectory-path.json``) to its ``runtimeFile`` when the pointer is valid, confined
to home, and the target still exists -- so ``STATUS_LIVE`` below can now be reached
via a pointer-recovered file the classic glob alone would have missed, not only via a
literal classic-glob match. ``corroborate()``'s own ``evidence`` list does not currently
distinguish "found by the classic glob" from "found only by following a pointer" for the
LIVE case (see the decision rule below) -- both fold into the same "not blind" verdict,
which is honest but loses that provenance detail; the CASES this module exists for on a
9.x install -- ``jsonl_count == 0`` and evidence living only in SQLite/the archive/a
dangling pointer -- are unaffected, since a pointer whose target is genuinely gone still
correctly falls through to ``pointer_missing``. ``traceSchema``/``schemaVersion`` are
UNCHANGED across the SQLite move (it is not a schema change), so a build-time oracle
over trajectory files would never have caught it; this module is a RUNTIME corroborator
instead.

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
alongside this table. Every function in this module touches ``trajectory_runtime_events``
and nothing else: one hardcoded table name (:data:`TRAJECTORY_TABLE_NAME`), never a table
built from a variable, never ``SELECT *``. Pointer files and archive filenames are read
for NAMES and COUNTS only -- a pointer's own ``sessionId``/``runtimeFile`` fields, never
anything past that tiny envelope; an archive entry's filename, never its content.

``corroborate()``/``sqlite_db_paths()``/``sqlite_session_ids()`` additionally never read
``event_json`` at all -- one literal, never-interpolated SELECT
(:data:`_SELECT_TRAJECTORY_ROWS`) naming only ``session_id``/``seq``. That is UNCHANGED.

**B-811 (Dave's explicit ruling, 2026-09-15): one narrow, reviewed exception.**
``read_compiled_tool_descriptions()`` below DOES read ``event_json`` -- the only function
in this module that does, and the only thing it is for. B185
(``checks/_mcp.py::check_compiled_tool_poisoning``) is otherwise permanently blind on a
SQLite-era install: it detects poisoned tool descriptions OpenClaw actually delivered to
the model, and without this, "delivered" evidence that moved to SQLite is unrecoverable.
The exception is scoped the same way :data:`_SELECT_TRAJECTORY_ROWS` already is, extended
with one more discipline the plain count readers do not need:
  * table: still only ``trajectory_runtime_events``, hardcoded, never the auth tables.
  * column: a SECOND literal SELECT (:data:`_SELECT_TRAJECTORY_EVENT_JSON`) names ONLY
    ``event_json`` -- not ``session_id``/``seq``/``run_id``/``created_at`` either; a
    separate query from ``_SELECT_TRAJECTORY_ROWS``, so the two reads can never merge
    into one that touches more than either alone does.
  * row filtering: enforced in PYTHON after fetch (``rec.get("type") ==
    "context.compiled"``), mirroring exactly how ``trajectory.read_compiled_tool_
    descriptions()`` filters JSONL lines -- not at the SQL level. SQLite's own
    ``json_extract()`` could filter server-side, but needs the JSON1 extension, not
    guaranteed present on every SQLite build this tool might run under (Golden Rule #1:
    stdlib-only, and that includes not depending on an optional SQLite compile flag);
    filtering in Python is the already-proven, portable approach.
  * field projection: only ``trajectory._compiled_tool_entry()``'s named fields ever
    leave this function -- reused verbatim from the JSONL reader, not re-derived, so the
    two containers cannot diverge on what counts as a "delivered tool definition."

Grep for ``SELECT`` in this module's source: there are now exactly four literal queries.
Two name ``trajectory_runtime_events`` (:data:`_SELECT_TRAJECTORY_ROWS`,
:data:`_SELECT_TRAJECTORY_EVENT_JSON`); the other two are :func:`_table_kind`'s own
``sqlite_master`` lookups, added in round 2 of the same B-811 review to close the
VIEW/virtual-table/rootpage-aliasing bypasses of "we never name the auth tables in our
own source" (see that function's docstring). None of the four ever names either auth
table.

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
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote as _urlquote

from .trajectory import (
    _COMPILED_EVENT_TYPE,
    _COMPILED_TOOL_FIELDS,
    _compiled_tool_entry,
    _MAX_COMPILED_LINE_LEN,
    _MAX_ROUND_ROBIN_SOURCES,
    _MAX_TOOL_DEFS_PER_SOURCE,
    _MAX_TOOL_DEFS_ROUND_QUOTA,
    _MAX_TOOL_DEFS_TOTAL,
    _MAX_TOOLS_PER_EVENT,
    _SCHEMA_VERSION,
    _TRACE_SCHEMA,
    find_trajectory_files,
)

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
# B-811: bounds for the event_json content read -- a heavier row than the plain
# session_id/seq pairs above, so capped separately. Row cap kept well below
# _MAX_SQLITE_ROWS_PER_DB (content rows cost far more to hold in memory); byte cap
# matches trajectory.py's own per-file cap order of magnitude (real events measured
# 40-61 KB there), so a single db is bounded the same way a single JSONL file already is.
_MAX_SQLITE_CONTENT_ROWS_PER_DB = 3000
_MAX_SQLITE_CONTENT_BYTES_PER_DB = 8_000_000
# A real session_id is a short identifier (UUID-shaped on every observed host); this is
# generous headroom, not a realistic size, so it never clips real data -- it exists
# purely to bound the SAME generated-column attack _MAX_COMPILED_LINE_LEN bounds for
# event_json (found in round 2 of adversarial review, B-811, 2026-09-15: session_id was
# a working substitute target once event_json alone was bounded).
_MAX_SQLITE_SESSION_ID_LEN = 4096
# The aggregate byte cap _read_sqlite_db's own rows are bounded to, mirroring
# _MAX_SQLITE_CONTENT_BYTES_PER_DB's role for the content reader -- small, since real
# session_id/seq pairs are tiny, but a real bound now that a single row can no longer
# be made arbitrarily large by the length() cap above.
_MAX_SQLITE_ROWS_BYTES_PER_DB = 2_000_000

POINTER_SCHEMA = "openclaw-trajectory-pointer"

# The ONLY table this reader may ever touch. Hardcoded, reviewed, never computed --
# see the module docstring's §8 paragraph for why that matters on this exact database.
TRAJECTORY_TABLE_NAME = "trajectory_runtime_events"

# A literal, table-scoped SELECT. Never built by string formatting or interpolation --
# grep for "SELECT" in this module's source: there are exactly four (this one,
# _SELECT_TRAJECTORY_EVENT_JSON below, and _table_kind's two sqlite_master lookups),
# none built from a variable. This one names only session_id/seq; event_json (the
# sensitive per-record payload) is never selected here, and neither auth table is ever
# named anywhere in this module's source -- see _table_kind's docstring for why a
# literal table name in OUR source is necessary but not sufficient on its own.
#
# `length(CAST(session_id AS BLOB) ) <= ?` -- see _SELECT_TRAJECTORY_EVENT_JSON's own
# comment for why the CAST matters: SQLite's `length()` on a bare TEXT value stops at
# the first embedded NUL byte (it is computed as if by `strlen()`), so a value engineered
# to start with a NUL byte reports `length() = 0`/a tiny number while still being
# arbitrarily large -- found in round 2 of adversarial review (B-811, 2026-09-15) to
# defeat the un-CAST version of this same bound for event_json; the identical trick
# applies to session_id. Casting to BLOB first makes `length()` return the true byte
# count regardless of embedded NULs.
_SELECT_TRAJECTORY_ROWS = (
    "SELECT session_id, seq FROM trajectory_runtime_events "
    "WHERE length(CAST(session_id AS BLOB)) <= ? LIMIT ?"
)

# B-811: the SECOND literal SELECT naming trajectory_runtime_events (round 2 of the
# same review added two more, scoped to sqlite_master instead -- see _table_kind).
# Names ONLY event_json, from the SAME hardcoded table, never the auth tables, never any other
# column from this table. See the module docstring's §8 paragraph for the full review.
#
# `length(CAST(event_json AS BLOB)) <= ?` is a REAL DoS bound, not a documentation
# gesture: it is a core SQLite function (no JSON1 needed) that excludes an oversized row
# AT THE ENGINE LEVEL, before its value is ever handed to this process -- found missing
# in round 1 of adversarial review (B-811, 2026-09-15), where a 200-row, 4 KB crafted
# database produced 385 MB of peak Python RSS because the only bound that existed then
# (a byte counter checked AFTER `.fetchall()` had already materialized every row) never
# had a chance to run.
#
# The CAST is load-bearing, not defensive style: round 2 of the SAME review found that
# bare `length(event_json)` on a TEXT value stops counting at the first embedded NUL
# byte (SQLite computes it the way C's `strlen()` would), so a
# `CREATE TABLE ... event_json TEXT GENERATED ALWAYS AS (CAST(zeroblob(N) AS TEXT)) `
# generated column reports `length(event_json) = 0` regardless of N -- an 8 KB database
# file drove 2.3 GB of peak process RSS through the un-CAST version of this query, WORSE
# than the original finding it was meant to fix. `CAST(... AS BLOB)` makes `length()`
# return the true byte count, embedded NULs included. The bound value is
# _MAX_COMPILED_LINE_LEN, matching the JSONL sibling's own per-record cap.
_SELECT_TRAJECTORY_EVENT_JSON = (
    "SELECT event_json FROM trajectory_runtime_events "
    "WHERE length(CAST(event_json AS BLOB)) <= ? LIMIT ?"
)

# B-811 (round 4, following round 3's adversarial review, 2026-09-15): the inverse
# COUNT of the two length-bounded SELECTs above -- how many rows the ``WHERE`` clause
# EXCLUDED, never examined at all. Round 3 found the exclusion itself was silent: an
# oversized row (a poisoned tool description padded past the cap) vanished with
# `truncated=False`, reading as a confidently complete, clean scan rather than as
# evidence not examined. These two queries are read ONLY to disclose that count, never
# to recover the excluded rows' own content -- they select nothing but ``count(*)``.
# Cheap to run because they can only be reached once `_table_kind`'s
# `PRAGMA table_xinfo` check has already refused any table with a generated/hidden
# column (see that function): on an honestly-stored TEXT/BLOB column, `length()` reads
# the value's stored size without materialising the value itself, so this is not the
# same cost `_table_kind`'s own fix exists to avoid.
_SELECT_TRAJECTORY_ROWS_EXCLUDED_COUNT = (
    "SELECT count(*) FROM trajectory_runtime_events "
    "WHERE length(CAST(session_id AS BLOB)) > ?"
)
_SELECT_TRAJECTORY_EVENT_JSON_EXCLUDED_COUNT = (
    "SELECT count(*) FROM trajectory_runtime_events "
    "WHERE length(CAST(event_json AS BLOB)) > ?"
)

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


# ---------------------------------------------------------------------------
# Hardened connection-opening, shared by every SQLite reader below.
#
# Both hardenings were found missing in adversarial review (B-811, 2026-09-15) against
# the ORIGINAL, pre-review construction every reader in this module used
# (``f"file:{db_path.as_posix()}?mode=ro"``) -- neither is new to this review's own
# addition (``_read_sqlite_event_json``); both already applied, unnoticed, to the
# pre-existing ``_read_sqlite_db`` this module shipped before B-811.
# ---------------------------------------------------------------------------


def _open_readonly(db_path: Path) -> "sqlite3.Connection":
    """One hardened way to open a per-agent trajectory database read-only.

    - URL-QUOTED path. A ``file:`` URI's query string starts at the first ``?``, and
      SQLite's own parameter parsing is first-match-wins -- an agent-controlled path
      COMPONENT (a hostile agent id under ``agents/<id>/agent/``, say) containing a
      literal ``?`` or a ``%2f`` traversal sequence could splice in its OWN parameter
      (``mode=rwc``) ahead of our trailing ``?mode=ro``, and win. Demonstrated in
      review: an agent directory named to end in ``?mode=rwc&junk=`` made this
      "read-only" auditor CREATE A FILE (Golden Rule #2). ``quote(..., safe="/")``
      keeps path separators literal while escaping everything a URI parser would
      treat specially.
    - ``text_factory`` degrades an invalid-UTF-8 TEXT value to a replacement-character
      string instead of raising ``sqlite3.OperationalError`` out of the whole
      ``fetchall()``/cursor-iteration call -- matching ``trajectory.py``'s own
      ``errors="replace"`` tolerance for the JSONL sibling reader. Without this, ONE
      malformed row (whether hostile or merely corrupt) discarded every row already
      read in the same call, not just itself -- an attacker-cheap way to blind an
      entire database's worth of real evidence.
    """
    conn = sqlite3.connect(f"file:{_urlquote(db_path.as_posix(), safe='/')}?mode=ro", uri=True)
    conn.text_factory = lambda b: b.decode("utf-8", errors="replace")
    # A short, bounded wait rather than an immediate "database is locked" error --
    # callers wrap the schema check and the real read in one BEGIN (see
    # _read_sqlite_db/_read_sqlite_event_json), which in rollback-journal mode (SQLite's
    # default) briefly holds a SHARED lock a concurrent writer's DDL/INSERT needs an
    # exclusive lock to proceed past; in WAL mode readers never block writers at all, so
    # this timeout is pure insurance for the less common journal mode.
    conn.execute("PRAGMA busy_timeout = 2000")
    return conn


def _table_kind(conn: "sqlite3.Connection", table_name: str) -> str:
    """``"table"`` / ``"absent"`` / ``"other"`` for *table_name* in *conn*'s own
    ``sqlite_master`` -- never assumed from the name alone.

    Why this exists (found in adversarial review, B-811, 2026-09-15, round 1): every
    reader in this module reasons "we never name the auth tables in OUR source, so we
    cannot reach them" -- true of the SQL TEXT this module writes, but name resolution
    in SQLite is a property of the FILE'S OWN schema, which is attacker-controlled if
    anything can write into ``agents/*/agent/``. A crafted
    ``CREATE VIEW trajectory_runtime_events AS SELECT ... FROM auth_profile_store``
    makes ``SELECT event_json FROM trajectory_runtime_events`` execute that view body
    -- arbitrary attacker SQL -- and was demonstrated to smuggle a live OAuth token
    into a ``context.compiled`` tool description the audit then reported as
    delivered-and-poisoned, token included, in ``Finding.evidence``.

    A first version of this function checked only ``sqlite_master.type == 'table'``.
    Round 2 of the SAME review demonstrated that check is necessary but NOT
    sufficient -- three further routes to the identical outcome, none of them a VIEW:

    1. **Virtual tables** (``CREATE VIRTUAL TABLE ... USING fts4(content='some_view')``,
       rtree, etc.) are recorded in ``sqlite_master`` with ``type='table'`` -- honestly
       -- and an external-content fts4/fts5 table resolves its rows from an
       attacker-named view LAZILY, at OUR query time. Demonstrated end-to-end into a
       rendered FAIL Finding.
    2. **Rootpage aliasing**: with ``PRAGMA writable_schema=ON``, a crafted row can
       claim ``type='table'`` / a legitimate-looking ``sql`` text HONESTLY, and still
       set ``rootpage`` to the SAME b-tree root page ``auth_profile_store`` itself
       uses -- so the query reads that OTHER table's data under our name. (A row that
       LIES about ``type``/``sql`` relative to its own ``CREATE`` text fails safe:
       SQLite raises "malformed database schema" opening such a file, caught by the
       surrounding ``except sqlite3.Error`` below.) A legitimate table or index NEVER
       shares a rootpage with another schema object, checked below -- but round 3
       (2026-09-15) found this check WEAKER than an earlier version of this docstring
       claimed ("a sound, general invariant... not specific to this attack shape",
       retracted): an attacker who can already forge one ``sqlite_master`` row under
       ``writable_schema=ON`` can, by the SAME mechanism, delete the rootpage's
       ORIGINAL owning row (or rewrite it to point elsewhere) -- restoring
       "uniqueness" trivially, since only the forged row claims that rootpage once its
       sibling is gone. So this check catches only an attacker who does not bother
       covering that specific track; it is not a defense against a determined one. The
       ``PRAGMA table_xinfo`` check further below does not share this weakness -- it
       does not depend on comparing rows against each other at all -- and is why round
       4 added a render-time control (``checks/_mcp.py``) that does not depend on any
       single one of these schema-level checks holding.
    3. TOCTOU between this check and the real query, if a concurrent writer can alter
       the schema in the window -- addressed by the caller wrapping both in one
       transaction (:func:`_read_sqlite_db` / :func:`_read_sqlite_event_json`), not
       here; this function only answers the schema question for whatever transaction
       state it is called within. VERIFIED, not just claimed: a background writer
       thread racing a live `_open_and_verify_table`/`_read_sqlite_event_json` call
       produced no leak in either WAL mode (the writer's commit succeeded but was
       invisible to the reader's already-open snapshot) or rollback-journal mode (the
       writer's schema-modifying DDL could not acquire its needed exclusive lock while
       the read transaction held its shared lock) -- and DID leak, in both modes, when
       the same test was re-run against a counterfactual build with the `BEGIN`
       removed. This is the one round-1/round-2 fix round 3 (below) reproduced and
       found to genuinely hold.

    **Round 3 of the SAME review (2026-09-15) found round 2's fix INSUFFICIENT --
    worse, in one respect, than round 1's own original finding -- via a FOURTH route,
    structurally different from all three above: none of them.**

    4. **A `GENERATED ALWAYS AS (...)` column added to a real, honest table.** Four
       plain DDL statements (no ``PRAGMA writable_schema``, no VIEW, no virtual table,
       no forged ``sqlite_master`` row) are enough: ``DROP TABLE
       trajectory_runtime_events`` (if present), ``ALTER TABLE auth_profile_store
       RENAME TO trajectory_runtime_events``, then ``ALTER TABLE ... ADD COLUMN
       session_id/seq/event_json ... GENERATED ALWAYS AS (<expr>) VIRTUAL`` referencing
       the renamed table's OWN real columns (e.g. its stored secret column) in the
       generated expression. The result passes every check above HONESTLY:
       ``type='table'`` (it is one), the ``sql`` text is an ordinary ``CREATE TABLE``
       (never ``CREATE VIRTUAL TABLE``), and ``rootpage`` is a real, unique b-tree root
       (it is one -- this is a real table with real storage, just with some of its
       columns computed rather than stored). Demonstrated end-to-end: a synthetic
       secret planted in a renamed ``auth_profile_store`` row reached
       ``Finding.evidence`` on a FAIL verdict, reproduced independently twice (by the
       round-3 reviewer, and again by the implementer against the reviewer's own
       written recipe, using only a fabricated, runtime-assembled secret -- never a
       real credential). The SAME primitive also reopens the round-1 DoS finding: a
       generated column computed from ``zeroblob(N)`` costs the ALLOCATION regardless
       of what any subsequent ``length()`` filter does with the result, because SQLite
       must materialise the value before it can be measured -- an 8 KB crafted file
       drove over a gigabyte of peak process RSS in the round-3 reviewer's
       measurement, through code whose byte-cap SQL was, by every other measure,
       working correctly.

       **Why no `sqlite_master`-only predicate can close this**: a generated column is
       not a schema-OBJECT-level lie (unlike a VIEW, a virtual table, or a forged
       rootpage) -- it is ordinary, honestly-declared SQL on a real table, and
       ``sqlite_master`` records nothing that distinguishes "this column is stored"
       from "this column is computed from an expression naming another column of the
       SAME table" at the ``type``/``sql``/``rootpage`` granularity this function had
       been checking. The discriminator that DOES exist lives one level down, in
       SQLite's per-column introspection, not its per-object one -- see the
       ``PRAGMA table_xinfo`` check below, added in response.

    "Never naming a table in our own source" was never the security boundary on its
    own; this function is the closest thing to one this module has, and even it is
    reviewed as a set of NAMED, falsifiable properties rather than a single claim --
    four rounds of adversarial review, four structurally different ways to make a
    ``sqlite_master`` row lie about what querying it will actually execute, is why
    :func:`check_compiled_tool_poisoning` (``checks/_mcp.py``) additionally layers a
    render-time control that does not depend on this function's verdict at all: the
    delivered tool's own ``name`` is never rendered into ``Finding.evidence`` unless it
    is shaped like an ordinary short tool identifier, regardless of how it was
    extracted or whether some future fifth route defeats this function outright. See
    that check's own module-level comment for what that control does and does not
    guarantee -- it narrows the render surface, it does not claim to close it.
    """
    # `PRAGMA table_xinfo(<name>)` below has no bound-parameter form in SQLite's own
    # grammar -- a pragma's target is a literal/identifier, not an expression -- so
    # this function's own single caller (:func:`_open_and_verify_table`) always passes
    # the hardcoded :data:`TRAJECTORY_TABLE_NAME` constant, never anything else. This
    # check is defense-in-depth against a FUTURE caller passing something else: only a
    # plain SQL identifier (letters/digits/underscore, not digit-leading) may reach the
    # f-string below, closing the interpolation off from anything that could smuggle
    # SQL syntax through the pragma target position.
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", table_name):
        return "other"
    try:
        row = conn.execute(
            "SELECT type, sql, rootpage FROM sqlite_master WHERE name = ?",
            (table_name,),
        ).fetchone()
    except sqlite3.Error:
        return "other"
    if row is None:
        return "absent"
    kind, sql_text, rootpage = row
    if kind != "table":
        return "other"
    # A CREATE VIRTUAL TABLE row ALSO has type='table' -- the sql text is the only
    # field in sqlite_master that distinguishes it. Checked as a PREFIX of the
    # uppercased text (SQLite does not case-fold the stored sql column itself), which
    # is robust to the exact table name/module arguments that follow.
    if not isinstance(sql_text, str) or sql_text.strip().upper().startswith(
        "CREATE VIRTUAL TABLE"
    ):
        return "other"
    if not isinstance(rootpage, int) or rootpage <= 0:
        return "other"
    try:
        row2 = conn.execute(
            "SELECT count(*) FROM sqlite_master WHERE rootpage = ?", (rootpage,)
        ).fetchone()
    except sqlite3.Error:
        return "other"
    if row2 is None or row2[0] != 1:
        return "other"
    # Round 3 finding #4 (above): a GENERATED ALWAYS AS column on a real table passes
    # every check so far, honestly. `PRAGMA table_xinfo` is the one SQLite
    # introspection surface that exposes this at the COLUMN level: its `hidden`
    # field is 0 for an ordinary stored column, 1 for a virtual-table-internal hidden
    # column (fts4/5's own bookkeeping columns -- a second, independent reason those
    # tables are refused here, on top of the `sql`-prefix check above), 2 for
    # `GENERATED ALWAYS AS ... VIRTUAL`, and 3 for `... STORED`. A single generated
    # column anywhere in the table is refused, not just one on a column this module
    # happens to read today -- a future reader added to this module gets the same
    # guarantee for free, without needing to enumerate which columns matter.
    try:
        cols = conn.execute(f"PRAGMA table_xinfo({table_name})").fetchall()
    except sqlite3.Error:
        return "other"
    if any(len(c) < 7 or c[6] != 0 for c in cols):
        return "other"
    return "table"


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


def sqlite_db_paths(home) -> "list[Path]":
    """Public wrapper for :func:`_sqlite_dbs` — the per-agent trajectory database PATHS
    only, never opened here. Exists for callers that need to ``stat()`` these files
    (tamper/permission checks) without reading a single row: B85 (``checks/_host.py``)
    is the first consumer, extending its existing JSONL sidecar tamper sweep to the
    container that actually holds the evidence on a SQLite-era install. Bounded and
    capped exactly like :func:`corroborate` (``_MAX_SQLITE_DBS``); returns ``[]`` for a
    non-``Path`` *home* or any glob error, same contract as every reader in this module.
    """
    if not isinstance(home, Path):
        return []
    return _sqlite_dbs(home)


def sqlite_session_ids(home) -> "frozenset[str]":
    """The set of ``session_id`` values present in every readable per-agent trajectory
    database under *home*. Reuses :func:`_read_sqlite_db` verbatim — no new SQL, no
    ``event_json`` read (see the module docstring's §8 paragraph) — so this carries
    exactly the same guarantee ``corroborate()`` already has: it can only ever learn
    that a session id EXISTS, never what it did.

    Exists for callers that need session-level PRESENCE, not the full reconciliation
    ``corroborate()`` returns — B189's cron-erasure pivot (``checks/_lifecycle.py``) is
    the first consumer: it already cross-references orphaned run-log session ids against
    on-disk evidence so its advisory can point at a transcript the user can actually
    still read, and today that cross-reference only checks JSONL sidecars. Bounded the
    same way :func:`corroborate` is; returns ``frozenset()`` for a non-``Path`` *home*,
    never raises.
    """
    if not isinstance(home, Path):
        return frozenset()
    ids: set = set()
    for db_path in _sqlite_dbs(home):
        pairs, _capped, unreadable = _read_sqlite_db(db_path)
        if unreadable:
            continue
        ids.update(sid for sid, _seq in pairs)
    return frozenset(ids)


def _open_and_verify_table(db_path: Path) -> "tuple[sqlite3.Connection | None, str, bool]":
    """Open *db_path* read-only, start a transaction, and verify
    :data:`TRAJECTORY_TABLE_NAME` resolves to a real TABLE -- the shared preamble
    every reader in this module needs (see :func:`_table_kind`'s docstring for what
    "real table" means and why "never named in our own source" is not sufficient on
    its own).

    Returns ``(conn, kind, unreadable)``:

    - ``(conn, "table", False)`` -- the connection is open, inside an explicit
      transaction, and the caller may now run its own bounded query against
      :data:`TRAJECTORY_TABLE_NAME`. The caller owns closing ``conn`` (which also ends
      the transaction; nothing to commit, this module is read-only throughout).
    - ``(None, "absent", False)`` -- the table genuinely does not exist yet; not
      unreadable, just nothing to read (``conn`` already closed).
    - ``(None, "other", True)`` -- refused: present but not a real table (the
      demonstrated VIEW/virtual-table/rootpage-aliasing attack shapes), or any I/O or
      schema error opening/starting the transaction (``conn`` already closed).

    The transaction -- an explicit ``BEGIN`` right after opening, held open across
    this check AND the caller's subsequent read -- is what closes the TOCTOU gap
    between them (found in adversarial review, B-811, 2026-09-15, round 2): a
    concurrent writer could otherwise swap the schema between the check and the read.
    Verified empirically: in WAL mode (SQLite's normal choice for a high-concurrency
    writer like OpenClaw's own agent process) a concurrent commit is invisible to an
    already-open read transaction's snapshot; in rollback-journal mode (SQLite's
    default when a file does not opt into WAL) a writer's schema-modifying DDL cannot
    even proceed while this transaction holds its read lock, so the race is prevented
    outright rather than merely detected. :func:`_open_readonly`'s ``busy_timeout``
    bounds how long a blocked writer's own retry waits, in the less common
    rollback-journal case.
    """
    try:
        conn = _open_readonly(db_path)
    except sqlite3.Error:
        return None, "other", True
    try:
        conn.execute("BEGIN")
        conn.execute("PRAGMA query_only = 1")
        kind = _table_kind(conn, TRAJECTORY_TABLE_NAME)
    except sqlite3.Error:
        conn.close()
        return None, "other", True
    if kind == "absent":
        conn.close()
        return None, "absent", False
    if kind != "table":
        # Present, but not a real table (a view/virtual-table/rootpage-aliased row is
        # the demonstrated attack shape) -- refuse. "unreadable", not "absent": we
        # will not read it, which is a different, stronger claim than "there is
        # nothing here."
        conn.close()
        return None, "other", True
    return conn, "table", False


def _read_sqlite_db(db_path: Path) -> "tuple[list, bool, bool]":
    """``(pairs, capped, unreadable)`` for one per-agent trajectory database.

    Opened and schema-verified via :func:`_open_and_verify_table` -- refuses anything
    ``trajectory_runtime_events`` does not resolve to a real TABLE, inside the one
    transaction that also closes the TOCTOU gap (see that function's own docstring).
    Executes EXACTLY the one literal :data:`_SELECT_TRAJECTORY_ROWS` once that check
    passes -- this cannot reach ``auth_profile_store``/``auth_profile_state``, which
    share this exact database file.

    Bounds now do real work on BOTH axes (found missing on this reader specifically in
    round 2 of adversarial review, B-811, 2026-09-15 -- the SAME generated-column
    trick that inflated ``event_json`` worked just as well against ``session_id`` once
    that column alone was bounded): a single row's ``session_id`` is bounded at the SQL
    level by ``length(CAST(session_id AS BLOB)) <= ?`` (see the query's own comment for
    why the CAST matters), and rows are iterated lazily (never ``.fetchall()``) so the
    aggregate :data:`_MAX_SQLITE_ROWS_BYTES_PER_DB` cap can stop reading further rows
    the moment it is exceeded rather than only noticing after everything was already
    materialized.

    A database predating ``trajectory_runtime_events`` is not corrupt -- the same honest
    "not unreadable, just absent" every other sqlite reader in this codebase reports
    (``collector._collect_cron_run_logs`` / ``_collect_config_machine_state``), so it is
    NOT counted toward ``unreadable``.

    ``capped`` ALSO covers a row the ``WHERE length(CAST(session_id AS BLOB)) <= ?``
    filter excluded at the SQL level, not just the row-count/byte-count caps below --
    found silent in round 3 of adversarial review (B-811, 2026-09-15): the filter did
    its job, but nothing disclosed that it had, so an excluded row read as a clean,
    complete scan rather than as evidence never examined.
    """
    conn, _kind, unreadable = _open_and_verify_table(db_path)
    if conn is None:
        return [], False, unreadable

    pairs: list = []
    row_count = 0
    read_bytes = 0
    capped = False
    try:
        cursor = conn.execute(
            _SELECT_TRAJECTORY_ROWS,
            (_MAX_SQLITE_SESSION_ID_LEN, _MAX_SQLITE_ROWS_PER_DB + 1),
        )
        for row in cursor:
            row_count += 1
            if row_count > _MAX_SQLITE_ROWS_PER_DB:
                capped = True
                break
            sid, seq = row[0], row[1]
            if not isinstance(sid, str) or not isinstance(seq, int):
                continue
            read_bytes += len(sid)
            if read_bytes > _MAX_SQLITE_ROWS_BYTES_PER_DB:
                capped = True
                break
            pairs.append((sid, seq))
        excluded = conn.execute(
            _SELECT_TRAJECTORY_ROWS_EXCLUDED_COUNT, (_MAX_SQLITE_SESSION_ID_LEN,)
        ).fetchone()
        if excluded and excluded[0]:
            capped = True
    except sqlite3.Error:
        conn.close()
        return pairs, True, False
    conn.close()
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

    1. ``find_trajectory_files()`` finds a live ``.trajectory.jsonl`` sidecar (via the
       classic glob OR, since B-732, a valid in-home pointer) -> :data:`STATUS_LIVE` --
       today's locator's own happy path, unconditionally, regardless of what else is
       found. A machine that still has live sidecars is not blind, whatever else is
       true of it. This does not distinguish which of the two locator paths found it.
    2. No live sidecar reachable at all, but a dangling pointer target (its own
       ``runtimeFile`` does not exist, or resolves outside home), an import-archive
       entry, or a SQLite row exists -> :data:`STATUS_LOCATOR_STALE` -- real evidence
       the agent ran, stored somewhere ``find_trajectory_files()`` still does not reach.
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


# ---------------------------------------------------------------------------
# B-811 (Option A): the ONE function in this module that reads event_json.
# See the module docstring's §8 paragraph for the full scoping review before
# touching this section.
# ---------------------------------------------------------------------------


def _read_sqlite_event_json(db_path: Path) -> "tuple[list[str], bool, bool, int]":
    """``(event_json_values, capped, unreadable, non_text_rows)`` for one per-agent
    trajectory database.

    Two DoS bounds now do real work on BOTH axes, and on the underlying byte-counting
    primitive itself -- found missing/bypassable across TWO rounds of adversarial
    review (B-811, 2026-09-15): round 1's original version bound row COUNT via
    ``LIMIT`` and checked total BYTES only after ``.fetchall()`` had already
    materialized every row into this process, so neither bound could actually stop an
    oversized read (a 200-row, 4 KB crafted database produced 385 MB of peak Python
    RSS; a REAL vendor-shaped 3,000-row database -- matching the 40-61 KB per-event
    size ``trajectory.py`` itself measured -- produced 175 MB against an 8 MB cap,
    with no attacker involved at all). Round 2, AFTER the fixes below were first
    added, found that bare ``length(event_json)`` on a TEXT value stops counting at
    the first embedded NUL byte (computed the way C's ``strlen()`` would), so a
    ``CREATE TABLE ... event_json TEXT GENERATED ALWAYS AS
    (CAST(zeroblob(N) AS TEXT)) VIRTUAL`` generated column reported
    ``length(event_json) = 0`` regardless of N -- an 8 KB database file drove 2.3 GB
    of peak RSS through the round-1 fix, WORSE than the original finding. Three fixes
    now, all load-bearing:

    1. :data:`_SELECT_TRAJECTORY_EVENT_JSON`'s own
       ``WHERE length(CAST(event_json AS BLOB)) <= ?`` bounds a SINGLE row's TRUE
       byte size AT THE SQL ENGINE, before its value is ever handed to this process --
       a row-COUNT ``LIMIT`` alone cannot do this, since one pathological row is
       enough regardless of how many rows are allowed, and the un-CAST form only
       LOOKED like it did this. Round 3 (below) found this claim ALSO depends on
       :func:`_table_kind`'s ``PRAGMA table_xinfo`` check having already run: a
       ``GENERATED ALWAYS AS`` column must be MATERIALISED before SQLite can measure
       its length at all, so the bound alone did not stop the allocation, only the
       row from being KEPT after paying for it. It is table_xinfo's refusal, not this
       WHERE clause, that keeps this claim true today.
    2. The cursor is iterated lazily here (never ``.fetchall()``), so the per-database
       BYTE cap can actually stop reading further rows the moment it is exceeded.
    3. Opened and schema-verified via :func:`_open_and_verify_table` -- refuses to
       read anything that ``trajectory_runtime_events`` does not resolve to a real
       TABLE, inside the one transaction that also closes the TOCTOU gap between that
       check and this read. See :func:`_table_kind`'s docstring for the attack shapes
       this closes SO FAR (four, as of round 3/4 -- a VIEW, an external-content
       virtual table, rootpage aliasing, and a GENERATED ALWAYS AS column) -- stated
       as "so far", deliberately, not "the full set": round 3 found a fourth shape
       after round 2 believed the first three were exhaustive, so this list is not
       claimed closed against a fifth.
    4. The excluded-row COUNT below (:data:`_SELECT_TRAJECTORY_EVENT_JSON_EXCLUDED_COUNT`)
       discloses when the WHERE clause above dropped a row, rather than letting an
       oversized (or deliberately padded-past-the-cap) poisoned record evade B185
       while this function reports a confident, complete scan -- found silently
       missing in round 3.

    ``non_text_rows`` counts rows where a column declared TEXT nonetheless stored a
    BLOB -- the one SQLite dynamic-typing shape this reader can actually observe here,
    verified directly rather than assumed: NULL can never reach this counter, because
    ``length(CAST(NULL AS BLOB)) <= ?`` evaluates to NULL and the WHERE clause already
    excludes it (folded into the SAME exclusion the count above discloses); and an
    INTEGER or REAL stored under this column's declared TEXT affinity is coerced to
    its text representation ON READ by SQLite itself, so it arrives in Python as a
    ``str`` and is never distinguishable from ordinary text at this layer. A stray
    NULL/INTEGER/REAL is real SQLite behaviour (a writer need not honour a column's
    declared type at all) but neither is something this counter can see; only a BLOB
    survives the WHERE clause as a non-``str`` Python value.

    A database predating ``trajectory_runtime_events`` is not corrupt -- same honest
    "not unreadable, just absent" as :func:`_read_sqlite_db`.

    ``capped`` ALSO covers a row ``WHERE length(CAST(event_json AS BLOB)) <= ?``
    excluded at the SQL level, not just the row-count/byte-count caps below -- the SAME
    disclosure gap :func:`_read_sqlite_db` closes, found in round 3 of adversarial
    review (B-811, 2026-09-15): the filter correctly excludes an oversized (or
    padded-past-the-cap, poisoned) row, but nothing disclosed that exclusion, so a
    padded-past-the-cap poisoned description could evade B185 entirely while this
    module reported a confident, complete, non-truncated scan.
    """
    conn, _kind, unreadable = _open_and_verify_table(db_path)
    if conn is None:
        return [], False, unreadable, 0
    try:
        cursor = conn.execute(
            _SELECT_TRAJECTORY_EVENT_JSON,
            (_MAX_COMPILED_LINE_LEN, _MAX_SQLITE_CONTENT_ROWS_PER_DB + 1),
        )
    except sqlite3.Error:
        conn.close()
        return [], False, True, 0

    values: list[str] = []
    read_bytes = 0
    row_count = 0
    non_text = 0
    capped = False
    try:
        for row in cursor:
            row_count += 1
            if row_count > _MAX_SQLITE_CONTENT_ROWS_PER_DB:
                capped = True
                break
            value = row[0]
            if not isinstance(value, str):
                non_text += 1
                continue
            read_bytes += len(value)
            if read_bytes > _MAX_SQLITE_CONTENT_BYTES_PER_DB:
                capped = True
                break
            values.append(value)
        excluded = conn.execute(
            _SELECT_TRAJECTORY_EVENT_JSON_EXCLUDED_COUNT, (_MAX_COMPILED_LINE_LEN,)
        ).fetchone()
        if excluded and excluded[0]:
            capped = True
    except sqlite3.Error:
        conn.close()
        return values, True, False, non_text
    conn.close()
    return values, capped, False, non_text


def _iter_db_tool_candidates(values: "list[str]", meta: dict):
    """Yield each candidate tool-definition dict found in *values* -- the already
    materialized ``event_json`` rows for ONE db, as returned by
    :func:`_read_sqlite_event_json`.

    Extracted from ``read_compiled_tool_descriptions`` (B-933 round 2), the SQLite
    mirror of ``trajectory._iter_source_tool_candidates`` -- same division of labor:
    this generator owns parsing/gating and ``meta[...]`` disclosure; the caller (the
    round-robin driver) owns cross-source dedup (``seen``) and both def-count caps.
    No change to :func:`_read_sqlite_event_json` itself or its own per-db byte/row
    caps -- those already ran, unconditionally, before this generator is ever
    constructed.
    """
    for raw in values:
        # Cheap pre-filter before the full JSON parse -- same idiom the JSONL reader
        # uses, so most rows (the overwhelming majority are NOT context.compiled)
        # never reach json.loads at all.
        if f'"{_COMPILED_EVENT_TYPE}"' not in raw:
            continue
        if len(raw) > _MAX_COMPILED_LINE_LEN:
            meta["truncated"] = True
            continue
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(rec, dict):
            continue
        if rec.get("traceSchema") != _TRACE_SCHEMA:
            # B-716: mirrors the JSONL reader's identical fix.
            meta["unknown_schema"] = True
            continue
        if rec.get("schemaVersion") != _SCHEMA_VERSION:
            meta["unknown_version"] = True
            continue
        if rec.get("type") != _COMPILED_EVENT_TYPE:
            continue
        data = rec.get("data")
        if not isinstance(data, dict):
            continue
        meta["events"] += 1
        # §8: ONLY the tool-definition fields are touched, same as the JSONL reader --
        # systemPrompt/prompt/messages are never referenced here either.
        for field in _COMPILED_TOOL_FIELDS:
            tools = data.get(field)
            if not isinstance(tools, list):
                continue
            if len(tools) > _MAX_TOOLS_PER_EVENT:
                meta["truncated"] = True
            for tool in tools[:_MAX_TOOLS_PER_EVENT]:
                entry = _compiled_tool_entry(tool, field)
                if entry is None:
                    continue
                yield entry


def read_compiled_tool_descriptions(home) -> "tuple[list[dict], dict]":
    """Return ``(tool_defs, meta)`` -- the tool definitions OpenClaw actually sent to the
    model, recovered from ``context.compiled`` events in the per-agent SQLite trajectory
    store. The SQLite-container sibling of ``trajectory.read_compiled_tool_descriptions()``
    (the JSONL reader); B185 (``checks/_mcp.py``) is the only caller, and only when
    :func:`corroborate` reports :data:`STATUS_LOCATOR_STALE` -- this function is never
    reached on a host whose evidence is fully covered by live JSONL sidecars, narrowing
    when the exception below actually activates, not just how it is scoped.

    Mirrors the JSONL reader's own filtering and projection EXACTLY (same
    ``traceSchema``/``schemaVersion``/type gate, same ``trajectory._compiled_tool_entry()``
    field projection, same dedup-by-content), so the two containers cannot diverge on what
    counts as a "delivered tool definition" -- proven, not just asserted, by
    ``tests/test_b185_compiled_tool_poisoning.py``'s JSONL/SQLite equivalence test.

    ``meta`` reports ``present`` (any db read), ``dbs_found``, ``dbs_read``,
    ``dbs_unreadable``, ``events`` (``context.compiled`` records parsed), ``truncated``
    (a per-db byte/row cap, an oversized row, a per-SOURCE definition cap --
    ``_MAX_TOOL_DEFS_PER_SOURCE``, reset for each db -- or the outer TOTAL definition
    ceiling -- ``_MAX_TOOL_DEFS_TOTAL``, shared across all dbs -- was hit),
    ``unknown_version`` and ``non_text_rows`` (see :func:`_read_sqlite_event_json`) --
    same vocabulary as the JSONL reader's meta where they overlap, so a caller can treat
    both uniformly for the fields both have. The two-tier cap split (B-933) mirrors the
    JSONL reader's own split EXACTLY -- see that reader's DoS-bounds comment in
    trajectory.py for the full rationale -- and
    ``tests/test_b185_compiled_tool_poisoning.py`` pins that the two readers still agree
    after a cap is hit, not just when neither is. ``dbs_read``/``dbs_unreadable`` are
    computed by an UNCONDITIONAL first pass over every db (unchanged from before B-933
    round 2); definition extraction across the readable dbs then runs through the same
    quota-bounded ROUND-ROBIN driver as the JSONL reader (B-933 round 2, see
    ``_MAX_TOOL_DEFS_ROUND_QUOTA`` in trajectory.py), so no group of decoy dbs can
    exhaust the TOTAL ceiling before a later db is ever examined.

    This is POST-HOC FORENSIC evidence, same limit as the JSONL reader: it reports what
    WAS sent to the model in sessions that already ran. It cannot pre-clear a live MCP
    server.

    §8: see the module docstring. Only ``event_json`` is ever selected from
    ``trajectory_runtime_events``; the auth tables in the same database file are never
    named anywhere in this function or module.
    """
    tool_defs: list[dict] = []
    meta = {
        "present": False, "dbs_found": 0, "dbs_read": 0, "dbs_unreadable": 0,
        "events": 0, "unknown_version": False, "unknown_schema": False,
        "truncated": False, "non_text_rows": 0,
    }
    if not isinstance(home, Path):
        return tool_defs, meta

    dbs = _sqlite_dbs(home)
    meta["dbs_found"] = len(dbs)
    if not dbs:
        return tool_defs, meta

    seen: set[tuple] = set()

    # Unconditional first pass, UNCHANGED from before B-933 round 2: every db's rows
    # are read and its own per-db byte/row caps applied regardless of what the
    # round-robin driver below goes on to keep -- `dbs_read`/`dbs_unreadable`/
    # `non_text_rows` must reflect what was actually READ, not what was extracted.
    db_values: dict = {}
    for db_path in dbs:
        values, capped, unreadable, non_text = _read_sqlite_event_json(db_path)
        if unreadable:
            meta["dbs_unreadable"] += 1
            continue
        meta["dbs_read"] += 1
        if capped:
            meta["truncated"] = True
        if non_text:
            # A row SQLite's dynamic typing stored as non-TEXT under this TEXT-affinity
            # column is content we could not examine -- disclosed as incomplete, same
            # honesty rule as every other truncation cause, never silently dropped.
            meta["non_text_rows"] += non_text
            meta["truncated"] = True
        db_values[db_path] = values

    # B-933 round 2: round-robin across the readable dbs instead of draining them
    # strictly sequentially -- mirrors trajectory.py's JSONL driver exactly (see the
    # DoS-bounds comment above `_MAX_TOOL_DEFS_ROUND_QUOTA` there).
    readable = list(db_values.keys())
    fair_group, overflow = readable[:_MAX_ROUND_ROBIN_SOURCES], readable[_MAX_ROUND_ROBIN_SOURCES:]
    gens = {s: _iter_db_tool_candidates(db_values[s], meta) for s in fair_group}
    source_new_defs = {s: 0 for s in fair_group}
    done: set = set()
    n, round_num = len(fair_group), 0
    while (gens.keys() - done) and len(tool_defs) < _MAX_TOOL_DEFS_TOTAL:
        progressed = False
        order = fair_group[round_num % n:] + fair_group[:round_num % n] if n else []
        for s in order:
            if s in done:
                continue
            if len(tool_defs) >= _MAX_TOOL_DEFS_TOTAL:
                break
            quota_used = 0
            while quota_used < _MAX_TOOL_DEFS_ROUND_QUOTA and len(tool_defs) < _MAX_TOOL_DEFS_TOTAL:
                if source_new_defs[s] >= _MAX_TOOL_DEFS_PER_SOURCE:
                    meta["truncated"] = True
                    done.add(s)
                    break
                try:
                    entry = next(gens[s])
                except StopIteration:
                    done.add(s)
                    break
                key = (
                    entry["name"], entry["description"],
                    tuple(entry["params"]), entry["field"],
                )
                if key in seen:
                    continue
                seen.add(key)
                tool_defs.append(entry)
                source_new_defs[s] += 1
                quota_used += 1
                progressed = True
        round_num += 1
        if not progressed:
            break
    if gens.keys() - done:
        meta["truncated"] = True

    # Beyond the fair-share guarantee -- structurally unreachable today since
    # `_MAX_SQLITE_DBS` (50) < `_MAX_ROUND_ROBIN_SOURCES` (200), kept only for parity
    # with the JSONL reader's own tail.
    for db_path in overflow:
        source_new_defs_overflow = 0
        for entry in _iter_db_tool_candidates(db_values[db_path], meta):
            key = (
                entry["name"], entry["description"],
                tuple(entry["params"]), entry["field"],
            )
            if key in seen:
                continue
            if (len(tool_defs) >= _MAX_TOOL_DEFS_TOTAL
                    or source_new_defs_overflow >= _MAX_TOOL_DEFS_PER_SOURCE):
                meta["truncated"] = True
                continue
            seen.add(key)
            tool_defs.append(entry)
            source_new_defs_overflow += 1

    meta["present"] = meta["dbs_read"] > 0
    return tool_defs, meta
