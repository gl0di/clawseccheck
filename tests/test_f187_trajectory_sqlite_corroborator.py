"""F-187 — corroborating WHERE an agent's trajectory evidence actually lives.

OpenClaw moved from JSONL trajectory sidecar files to a SQLite-backed store around
version 9.x. `trajectory.find_trajectory_files` still globs only
`agents/*/sessions/*.trajectory.jsonl`, so on a current install that glob is silently
empty on every run — the same observation ("zero sidecars found") that a genuinely
fresh agent that has never run a single session would also produce. This file proves
`trajectorystore.corroborate()` tells the two apart, and that it never reaches the
OAuth-bearing tables that share its one per-agent database file.
"""
import json
import sqlite3
import tempfile
from pathlib import Path

from clawseccheck.behavioral import analyze, analysis_incompleteness, render_behavioral_analysis
from clawseccheck.collector import Context
from clawseccheck.trajectorystore import (
    STATUS_LIVE,
    STATUS_LOCATOR_STALE,
    STATUS_NO_RESIDUE,
    TRAJECTORY_TABLE_NAME,
    corroborate,
)

SECRET = "oauth-refresh-token-that-must-never-be-read"


# ---------------------------------------------------------------------------
# fixture builders
# ---------------------------------------------------------------------------

def _home(tmp_root=None) -> Path:
    home = Path(tmp_root) if tmp_root else Path(tempfile.mkdtemp(prefix="f187-"))
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    return home


def _add_pointer(home: Path, agent: str, session_id: str, *, target_exists: bool,
                  schema=True) -> None:
    sessions = home / "agents" / agent / "sessions"
    sessions.mkdir(parents=True, exist_ok=True)
    target = sessions / f"{session_id}.trajectory.jsonl"
    if target_exists:
        target.write_text("", encoding="utf-8")
    record = {"sessionId": session_id, "runtimeFile": str(target)}
    if schema:
        record = {"traceSchema": "openclaw-trajectory-pointer", "schemaVersion": 1, **record}
    (sessions / f"{session_id}.trajectory-path.json").write_text(
        json.dumps(record), encoding="utf-8")


def _add_archive_entries(home: Path, agent: str, names: "list[str]") -> None:
    archive = home / "agents" / agent / "session-sqlite-import-archive"
    archive.mkdir(parents=True, exist_ok=True)
    for name in names:
        (archive / name).write_text("", encoding="utf-8")


def _add_jsonl(home: Path, agent: str, session_id: str,
                pairs: "list[tuple[str, int]] | None" = None) -> Path:
    sessions = home / "agents" / agent / "sessions"
    sessions.mkdir(parents=True, exist_ok=True)
    path = sessions / f"{session_id}.trajectory.jsonl"
    pairs = pairs if pairs is not None else [(session_id, 0)]
    lines = [json.dumps({"sessionId": sid, "seq": seq}) for sid, seq in pairs]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _add_agent_db(home: Path, agent: str, *, trajectory_rows=(), include_auth=True,
                   table=TRAJECTORY_TABLE_NAME) -> Path:
    """Build a per-agent SQLite database matching the real vendor shape closely enough
    for these tests: `trajectory_runtime_events` (session_id, seq, run_id, event_json,
    created_at) plus, by default, the two OAuth-bearing tables that share this exact
    database file on a real host (`auth_profile_store`/`auth_profile_state`).

    ``trajectory_rows`` entries are ``(session_id, seq)`` (event_json defaults to a
    harmless ``tool.call`` placeholder) or ``(session_id, seq, event_dict)`` to plant a
    real event -- B-811's ``read_compiled_tool_descriptions()`` tests need this to
    exercise real content, not just presence -- or ``(session_id, seq, event_dict,
    created_at)`` (B-852) to control this row's own ``created_at`` explicitly, for the
    ``ORDER BY rowid DESC`` reader tests. Defaults to ``0`` for every row, same as
    before this fourth element existed.
    """
    agent_dir = home / "agents" / agent / "agent"
    agent_dir.mkdir(parents=True, exist_ok=True)
    db_path = agent_dir / "openclaw-agent.sqlite"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            f"CREATE TABLE {table} (session_id TEXT NOT NULL, seq INTEGER NOT NULL, "
            "run_id TEXT, event_json TEXT NOT NULL, created_at INTEGER NOT NULL, "
            "PRIMARY KEY (session_id, seq))"
        )
        for entry in trajectory_rows:
            session_id, seq = entry[0], entry[1]
            event = entry[2] if len(entry) > 2 else {"type": "tool.call"}
            created_at = entry[3] if len(entry) > 3 else 0
            conn.execute(
                f"INSERT INTO {table} VALUES (?,?,?,?,?)",
                (session_id, seq, "run-1", json.dumps(event), created_at),
            )
        if include_auth:
            conn.execute(
                "CREATE TABLE auth_profile_store (store_key TEXT PRIMARY KEY, "
                "store_json TEXT NOT NULL, updated_at INTEGER NOT NULL)")
            conn.execute(
                "INSERT INTO auth_profile_store VALUES (?,?,?)",
                ("anthropic", json.dumps({"access_token": SECRET}), 0),
            )
            conn.execute(
                "CREATE TABLE auth_profile_state (state_key TEXT PRIMARY KEY, "
                "state_json TEXT NOT NULL, updated_at INTEGER NOT NULL)")
            conn.execute(
                "INSERT INTO auth_profile_state VALUES (?,?,?)",
                ("anthropic", json.dumps({"refresh_token": SECRET}), 0),
            )
        conn.commit()
    finally:
        conn.close()
    return db_path


def _ctx(home: Path) -> Context:
    return Context(home=home, config={})


# ---------------------------------------------------------------------------
# scenario 1 — pointer files present, all targets missing, some SQLite rows:
# "locator stale", not "never ran"
# ---------------------------------------------------------------------------

def test_dangling_pointers_and_sqlite_rows_read_as_locator_stale():
    home = _home()
    _add_pointer(home, "main", "s1", target_exists=False)
    _add_pointer(home, "main", "s2", target_exists=False)
    _add_agent_db(home, "main", trajectory_rows=[("s1", 0), ("s1", 1), ("s2", 0)])

    corro = corroborate(home)
    assert corro.status == STATUS_LOCATOR_STALE
    assert corro.locator_stale is True
    assert corro.jsonl_files == 0
    assert corro.pointer_files == 2
    assert corro.pointer_targets_missing == 2
    assert corro.sqlite_rows == 3
    assert corro.sqlite_sessions == 2
    assert any("pointer file(s)" in e for e in corro.evidence)
    assert any("SQLite trajectory row(s)" in e for e in corro.evidence)


def test_locator_stale_flows_through_analyze_and_incompleteness():
    home = _home()
    _add_pointer(home, "main", "s1", target_exists=False)
    _add_agent_db(home, "main", trajectory_rows=[("s1", 0)])

    result = analyze(_ctx(home))
    assert result["present"] is False
    assert result["trajectory_locator_stale"] is True

    reason = analysis_incompleteness(result)
    assert reason is not None
    assert "locator appears to be stale" in reason
    assert "never run" in reason  # says explicitly this is NOT that claim


def test_locator_stale_flows_through_the_rendered_report():
    home = _home()
    _add_pointer(home, "main", "s1", target_exists=False)
    _add_agent_db(home, "main", trajectory_rows=[("s1", 0)])

    out = render_behavioral_analysis(_ctx(home), ascii_only=True)
    assert "trajectory history exists elsewhere" in out
    assert "SQLite trajectory row(s)" in out
    assert "locator is stale" in out


def test_archive_alone_is_also_locator_stale_evidence():
    """The import archive on its own (no pointer, no SQLite table at all) is still real
    disk evidence — an agent that ran, whose sidecars were archived, not one that never
    started."""
    home = _home()
    _add_archive_entries(home, "main", ["session-a.trajectory.jsonl.imported-1700000000000"])

    corro = corroborate(home)
    assert corro.status == STATUS_LOCATOR_STALE
    assert corro.archive_entries == 1
    assert any("archived trajectory sidecar" in e for e in corro.evidence)


# ---------------------------------------------------------------------------
# scenario 2 — nothing anywhere: honestly "no residue", explicitly not "never ran"
# ---------------------------------------------------------------------------

def test_nothing_at_all_is_no_residue_not_a_confident_never_ran():
    home = _home()
    corro = corroborate(home)
    assert corro.status == STATUS_NO_RESIDUE
    assert corro.locator_stale is False
    assert corro.evidence == ()
    assert corro.jsonl_files == 0
    assert corro.pointer_files == 0
    assert corro.archive_entries == 0
    assert corro.sqlite_rows == 0


def test_no_residue_leaves_the_original_message_unchanged():
    """The control for the locator-stale tests above: without real evidence anywhere,
    analyze()/render_behavioral_analysis() must read exactly as they did before this
    module existed — never a stale-locator claim manufactured from nothing."""
    home = _home()
    result = analyze(_ctx(home))
    assert result["present"] is False
    assert result.get("trajectory_locator_stale") is False

    reason = analysis_incompleteness(result)
    assert reason == "no trajectory sidecar was read"

    out = render_behavioral_analysis(_ctx(home), ascii_only=True)
    assert "No trajectory sidecars found" in out
    assert "locator is stale" not in out


def test_an_empty_openclaw_sqlite_predating_the_table_is_not_unreadable():
    """A per-agent DB that exists but predates `trajectory_runtime_events` is the same
    honest "table absent" every other sqlite reader in this codebase reports — not a
    read error, and not locator-stale evidence on its own."""
    home = _home()
    _add_agent_db(home, "main", trajectory_rows=[], table="something_else")
    corro = corroborate(home)
    assert corro.status == STATUS_NO_RESIDUE
    assert corro.sqlite_dbs_found == 1
    assert corro.sqlite_dbs_read == 1
    assert corro.sqlite_dbs_unreadable == 0
    assert corro.sqlite_rows == 0


# ---------------------------------------------------------------------------
# scenario 3 — real JSONL present and valid: unchanged behavior (regression guard)
# ---------------------------------------------------------------------------

def test_live_jsonl_wins_regardless_of_other_containers():
    home = _home()
    _add_jsonl(home, "main", "s1")
    # Pile on every OTHER kind of residue too -- STATUS_LIVE must still win outright.
    _add_pointer(home, "main", "s2", target_exists=False)
    _add_archive_entries(home, "main", ["old.trajectory.jsonl.imported-1700000000000"])
    _add_agent_db(home, "main", trajectory_rows=[("s3", 0)])

    corro = corroborate(home)
    assert corro.status == STATUS_LIVE
    assert corro.locator_stale is False
    assert corro.jsonl_files == 1


def test_the_analyze_happy_path_never_even_calls_the_corroborator(monkeypatch):
    """The regression guard the task asked for, proven structurally: when a live
    sidecar is found, `analyze()` must not touch the corroborator at all, so its
    behavior for this branch is BYTE-IDENTICAL to before F-187 existed."""
    home = _home()
    _add_jsonl(home, "main", "s1")

    called = []
    import clawseccheck.behavioral as behavioral_mod
    monkeypatch.setattr(
        behavioral_mod, "corroborate_trajectory_containers",
        lambda h: called.append(h) or (_ for _ in ()).throw(AssertionError("must not be called")),
    )
    result = analyze(_ctx(home))
    assert result["present"] is True
    assert called == []
    assert "trajectory_locator_stale" not in result


def test_dedup_by_session_id_and_seq_removes_sqlite_rows_already_live():
    """The vendor's doctor can restore a JSONL sidecar from the archive while the
    matching SQLite rows are still present — the exact shape that would otherwise
    double-count the same event as two separate pieces of evidence."""
    home = _home()
    _add_jsonl(home, "main", "s1", pairs=[("s1", 0), ("s1", 1)])
    _add_agent_db(home, "main", trajectory_rows=[("s1", 0), ("s1", 1)])  # identical pairs

    corro = corroborate(home)
    assert corro.status == STATUS_LIVE  # jsonl present -> unaffected by dedup
    assert corro.sqlite_rows == 0  # every SQLite row is already covered by the live file
    assert not any("SQLite trajectory row(s)" in e for e in corro.evidence)


def test_dedup_leaves_genuinely_new_sqlite_rows_visible():
    home = _home()
    _add_jsonl(home, "main", "s1", pairs=[("s1", 0)])
    _add_agent_db(home, "main", trajectory_rows=[("s1", 0), ("s2", 0)])  # s2 is NEW

    corro = corroborate(home)
    assert corro.sqlite_rows == 1
    assert corro.sqlite_sessions == 1


# ---------------------------------------------------------------------------
# the table-name guard (F-183 _collect_config_machine_state precedent)
# ---------------------------------------------------------------------------

def test_the_allowed_table_name_is_exactly_one_constant():
    assert TRAJECTORY_TABLE_NAME == "trajectory_runtime_events"


def test_the_query_names_only_the_trajectory_table_and_binds_its_limit():
    """A source-level companion to the behavioural OAuth tests below: `SELECT *` or a
    query built from a variable would still pass a row-count assertion if someone later
    filtered in Python — and filtering after the fact means the secret was already read
    into this process first.

    Scoped to the actual `.execute(...)` call sites, not the whole file: the module's
    own docstrings NAME `auth_profile_store`/`auth_profile_state`/`event_json` in prose
    (explaining exactly why they must never be touched), so a whole-file substring
    check would fail on the very sentences documenting the guarantee. What must be
    true is narrower and stronger: no *executed* SQL statement ever names them.

    B-811 (rewritten after adversarial review, 2026-09-15): a SECOND literal SELECT
    exists (`_SELECT_TRAJECTORY_EVENT_JSON`, read_compiled_tool_descriptions()'s own
    query) — it DOES name `event_json`, by design, and that is the one and only line
    this test allows to. A THIRD query now exists too (`_table_kind`'s
    `sqlite_master` lookup, added in response to the view-based attack this same
    review demonstrated) — it must name only `sqlite_master`, never
    `trajectory_runtime_events` or either OAuth table. The invariant this test
    protects is narrower than "event_json never appears": it is "neither OAuth table
    ever appears in any executed statement, no query is built from a variable/
    `SELECT *`, and the SQLite-object-name check is not itself bypassable by a query
    naming a variable" — all three still hold for all three queries.

    Round 3/4 (2026-09-15) added three more `.execute(` call sites: `_table_kind`'s
    `PRAGMA table_xinfo(<table_name>)` generated-column check (the ONE deliberate,
    guarded exception to "never an interpolated query" below — `table_name` is
    regex-validated to a plain SQL identifier before it can reach the f-string, since
    a pragma's target has no bound-parameter form in SQLite's own grammar), and two
    `count(*)` queries (`_SELECT_TRAJECTORY_ROWS_EXCLUDED_COUNT` /
    `_SELECT_TRAJECTORY_EVENT_JSON_EXCLUDED_COUNT`) that disclose how many rows the
    length filter silently excluded — found undisclosed in round 3. Same invariant,
    six queries now: none of the six ever names an auth table, and the one
    interpolated query is checked to be exactly the guarded, identifier-validated form.
    """
    from clawseccheck.trajectorystore import (
        _SELECT_TRAJECTORY_EVENT_JSON,
        _SELECT_TRAJECTORY_EVENT_JSON_EXCLUDED_COUNT,
        _SELECT_TRAJECTORY_ROWS,
        _SELECT_TRAJECTORY_ROWS_EXCLUDED_COUNT,
    )
    assert _SELECT_TRAJECTORY_ROWS == (
        "SELECT session_id, seq FROM trajectory_runtime_events "
        "WHERE length(CAST(session_id AS BLOB)) <= ? LIMIT ?"
    )
    assert _SELECT_TRAJECTORY_EVENT_JSON == (
        # B-852: newest rows first, so a hit LIMIT reads the most recent sessions
        # rather than whichever rows the table's own storage order happened to hold.
        # `ORDER BY rowid DESC`, not `created_at` -- two independent adversarial
        # reviews found ordering by `created_at` (an un-indexed column sharing a row
        # with up to 256 KB of `event_json`) forces SQLite to materialize and sort
        # every row's full payload before returning the first one, turning the
        # bounded streaming read unbounded on a large database. `rowid` is this
        # table's own b-tree key, so ordering by it is a plain reverse index scan --
        # no sort -- and does not depend on a `created_at` column existing at all.
        "SELECT event_json FROM trajectory_runtime_events "
        "WHERE length(CAST(event_json AS BLOB)) <= ? "
        "ORDER BY rowid DESC LIMIT ?"
    )
    assert _SELECT_TRAJECTORY_ROWS_EXCLUDED_COUNT == (
        "SELECT count(*) FROM trajectory_runtime_events "
        "WHERE length(CAST(session_id AS BLOB)) > ?"
    )
    assert _SELECT_TRAJECTORY_EVENT_JSON_EXCLUDED_COUNT == (
        "SELECT count(*) FROM trajectory_runtime_events "
        "WHERE length(CAST(event_json AS BLOB)) > ?"
    )
    assert "*" not in _SELECT_TRAJECTORY_ROWS
    assert "*" not in _SELECT_TRAJECTORY_EVENT_JSON
    # The two count queries use count(*) -- an aggregate, not a row-selecting `SELECT
    # *` -- and each names only the SAME single column its non-count sibling bounds.
    assert "session_id" not in _SELECT_TRAJECTORY_EVENT_JSON_EXCLUDED_COUNT
    assert "event_json" not in _SELECT_TRAJECTORY_ROWS_EXCLUDED_COUNT
    # The two queries select disjoint column sets from the SAME table -- neither is a
    # superset of the other, so merging them into one query would read more than either
    # caller needs.
    assert "event_json" not in _SELECT_TRAJECTORY_ROWS
    assert "session_id" not in _SELECT_TRAJECTORY_EVENT_JSON

    source = (Path(__file__).resolve().parent.parent
              / "clawseccheck" / "trajectorystore.py").read_text()
    lines = source.splitlines()
    execute_line_nums = [i for i, ln in enumerate(lines) if ".execute(" in ln]
    # _table_kind now runs THREE checks after the type/sql check (a rootpage-
    # uniqueness count(*) -- round 2, closing rootpage aliasing -- and a
    # `PRAGMA table_xinfo` generated-column check -- round 3/4, closing the
    # GENERATED ALWAYS AS bypass) + _open_and_verify_table's own BEGIN + 2 PRAGMA
    # (busy_timeout, query_only) + 2 SELECT + 2 count(*) exclusion-disclosure
    # queries (round 3/4), no more. Each appears once in SOURCE even though called
    # from two places.
    assert len(execute_line_nums) == 10, [lines[i] for i in execute_line_nums]
    # Each real call (the two SELECTs, and _table_kind's own query) is wrapped across a
    # few physical lines here (`conn.execute(\n    CONST, (...)\n).fetchall()`) -- a
    # single-LINE scan would miss a table name placed on the continuation line, so each
    # call is checked as a small WINDOW (the .execute( line plus what follows), not
    # just its own line. Each window runs from its own `.execute(` line up to (but not
    # including) the NEXT one, capped at 4 lines -- a one-line PRAGMA call's window is
    # therefore just that one line (the next call starts immediately after it), while a
    # real multi-line call's window reaches its own closing paren without bleeding into
    # whatever `.execute(` call happens to follow it.
    windows = []
    for idx, start in enumerate(execute_line_nums):
        end = execute_line_nums[idx + 1] if idx + 1 < len(execute_line_nums) else len(lines)
        windows.append("\n".join(lines[start : min(end, start + 4)]))
    # Call sites reference the CONSTANT NAME, never the literal SQL string -- so this
    # searches for the identifier, not the lowercase "event_json" substring, which
    # only ever appears inside a constant's own definition line (already asserted
    # above), not at any call site. `_SELECT_TRAJECTORY_EVENT_JSON,` (with the
    # trailing comma/newline a real call site has) is distinguished from its longer
    # `..._EXCLUDED_COUNT` sibling, which the plain substring would also match.
    event_json_windows = [w for w in windows if "_SELECT_TRAJECTORY_EVENT_JSON," in w]
    assert len(event_json_windows) == 1, event_json_windows  # exactly the round-2 query
    event_json_excluded_windows = [
        w for w in windows if "_SELECT_TRAJECTORY_EVENT_JSON_EXCLUDED_COUNT" in w
    ]
    assert len(event_json_excluded_windows) == 1, event_json_excluded_windows
    rows_excluded_windows = [
        w for w in windows if "_SELECT_TRAJECTORY_ROWS_EXCLUDED_COUNT" in w
    ]
    assert len(rows_excluded_windows) == 1, rows_excluded_windows
    # _table_kind's own two sqlite_master queries: the type/sql/rootpage lookup, with
    # `table_name` passed as a BOUND parameter (the trailing `, (table_name,)`) rather
    # than interpolated into the query text itself; and the rootpage-uniqueness check,
    # with `rootpage` likewise bound -- never a value read from this file's own
    # untrusted schema spliced into SQL text.
    sqlite_master_windows = [w for w in windows if "sqlite_master" in w]
    assert len(sqlite_master_windows) == 2, sqlite_master_windows
    assert '"SELECT type, sql, rootpage FROM sqlite_master WHERE name = ?"' in (
        sqlite_master_windows[0]
    )
    assert '"SELECT count(*) FROM sqlite_master WHERE rootpage = ?", (rootpage,)' in (
        sqlite_master_windows[1]
    )
    # `table_xinfo`'s window is the ONE deliberate exception to "never an
    # interpolated query" below -- it must be EXACTLY the guarded f-string form
    # (`table_name`, already regex-validated a few lines above it in source, is the
    # only interpolated value), never a wider or differently-shaped interpolation.
    table_xinfo_windows = [w for w in windows if "table_xinfo" in w]
    assert len(table_xinfo_windows) == 1, table_xinfo_windows
    assert 'f"PRAGMA table_xinfo({table_name})"' in table_xinfo_windows[0]
    for w in windows:
        assert "auth_profile" not in w
        assert "SELECT *" not in w
        if w in table_xinfo_windows:
            continue  # the one guarded, identifier-validated exception, asserted above
        assert "f'" not in w and 'f"' not in w  # never an interpolated/dynamic query


def test_a_row_outside_the_trajectory_table_is_never_read():
    """The mutation target: widen the query to also touch auth_profile_store /
    auth_profile_state (or `SELECT *`) and this fails, because the secret would then
    reach the returned dataclass or its evidence text."""
    home = _home()
    _add_agent_db(home, "main", trajectory_rows=[("s1", 0)], include_auth=True)
    _add_pointer(home, "main", "s1", target_exists=False)

    corro = corroborate(home)
    dumped = json.dumps(
        {"evidence": corro.evidence, "status": corro.status, "rows": corro.sqlite_rows},
        default=str,
    )
    assert SECRET not in dumped


def test_corroborate_refuses_a_view_masquerading_as_the_trajectory_table():
    """The same VIEW-based attack the compiled-tool-reader test closes (adversarial
    review, B-811, 2026-09-15), against `corroborate()`'s own reader
    (`_read_sqlite_db`) -- confirms the `_table_kind` hardening protects BOTH readers
    in this module, not just the new one. A view can fabricate a `session_id` string
    containing the secret just as easily as it can fabricate `event_json`."""
    home = _home()
    agent_dir = home / "agents" / "main" / "agent"
    agent_dir.mkdir(parents=True, exist_ok=True)
    db_path = agent_dir / "openclaw-agent.sqlite"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "CREATE TABLE auth_profile_store (store_key TEXT PRIMARY KEY, "
            "value_json TEXT)"
        )
        conn.execute(
            "INSERT INTO auth_profile_store VALUES (?, ?)",
            ("gh", json.dumps({"access_token": SECRET})),
        )
        conn.execute(
            "CREATE VIEW trajectory_runtime_events AS "
            "SELECT value_json AS session_id, 0 AS seq, 'run-1' AS run_id, "
            "'{}' AS event_json, 0 AS created_at FROM auth_profile_store"
        )
        conn.commit()
    finally:
        conn.close()

    corro = corroborate(home)
    dumped = json.dumps(
        {"evidence": corro.evidence, "status": corro.status, "rows": corro.sqlite_rows},
        default=str,
    )
    assert SECRET not in dumped
    assert corro.sqlite_dbs_unreadable == 1
    assert corro.sqlite_dbs_read == 0


def _plant_generated_column_bypass(db_path, *, event_json_expr=None):
    """Build the round-3 adversarial-review bypass (B-811, 2026-09-15): rename a real
    `auth_profile_store` into `trajectory_runtime_events`'s own name, then add
    `GENERATED ALWAYS AS` columns computed from its own stored secret column. No
    `PRAGMA writable_schema`, no VIEW, no virtual table, no forged `sqlite_master`
    row -- four plain DDL statements are enough, because the result IS a real table:
    `_table_kind`'s round-1/round-2 checks (type/sql-prefix/rootpage-uniqueness) all
    pass HONESTLY. Only `PRAGMA table_xinfo`'s hidden-column check (round 3/4) can
    tell a generated column from a stored one.

    `event_json_expr`, when given, is a SQL expression string (already valid SQL) used
    verbatim for the `event_json` generated column; the default exposes `value_json`
    directly as `session_id` instead, for callers that only need the plain-string
    (non-JSON) reader.
    """
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "CREATE TABLE auth_profile_store (store_key TEXT PRIMARY KEY, "
            "value_json TEXT)"
        )
        conn.execute(
            "INSERT INTO auth_profile_store VALUES (?, ?)",
            ("gh", SECRET),
        )
        conn.execute("DROP TABLE IF EXISTS trajectory_runtime_events")
        conn.execute(
            "ALTER TABLE auth_profile_store RENAME TO trajectory_runtime_events"
        )
        if event_json_expr is None:
            conn.execute(
                "ALTER TABLE trajectory_runtime_events ADD COLUMN session_id TEXT "
                "GENERATED ALWAYS AS (value_json) VIRTUAL"
            )
            conn.execute(
                "ALTER TABLE trajectory_runtime_events ADD COLUMN seq INTEGER "
                "GENERATED ALWAYS AS (0) VIRTUAL"
            )
        else:
            conn.execute(
                "ALTER TABLE trajectory_runtime_events ADD COLUMN session_id TEXT "
                "GENERATED ALWAYS AS ('sess-1') VIRTUAL"
            )
            conn.execute(
                "ALTER TABLE trajectory_runtime_events ADD COLUMN seq INTEGER "
                "GENERATED ALWAYS AS (0) VIRTUAL"
            )
            conn.execute(
                "ALTER TABLE trajectory_runtime_events ADD COLUMN event_json TEXT "
                f"GENERATED ALWAYS AS ({event_json_expr}) VIRTUAL"
            )
        conn.execute(
            "ALTER TABLE trajectory_runtime_events ADD COLUMN run_id TEXT "
            "GENERATED ALWAYS AS ('run-1') VIRTUAL"
        )
        conn.execute(
            "ALTER TABLE trajectory_runtime_events ADD COLUMN created_at INTEGER "
            "GENERATED ALWAYS AS (0) VIRTUAL"
        )
        conn.commit()
    finally:
        conn.close()


def test_corroborate_refuses_a_table_with_a_generated_column():
    """The round-3 adversarial-review finding (B-811, 2026-09-15): a `GENERATED ALWAYS
    AS` column on a real, honestly-typed table defeats every round-1/round-2
    `_table_kind` check (type='table', sql not a virtual-table prefix, unique
    rootpage) because the object genuinely IS a table -- unlike a VIEW, a virtual
    table, or a forged rootpage, none of which this is. Only `PRAGMA table_xinfo`'s
    per-column `hidden` check (added in response) can tell a computed column from a
    stored one."""
    home = _home()
    agent_dir = home / "agents" / "main" / "agent"
    agent_dir.mkdir(parents=True, exist_ok=True)
    db_path = agent_dir / "openclaw-agent.sqlite"
    _plant_generated_column_bypass(db_path)

    corro = corroborate(home)
    dumped = json.dumps(
        {"evidence": corro.evidence, "status": corro.status, "rows": corro.sqlite_rows},
        default=str,
    )
    assert SECRET not in dumped
    assert corro.sqlite_dbs_unreadable == 1
    assert corro.sqlite_dbs_read == 0


def test_compiled_tool_reader_refuses_a_rootpage_aliased_table():
    """Round 2's rootpage-uniqueness check (`_table_kind`'s `SELECT count(*) FROM
    sqlite_master WHERE rootpage = ?`), exercised as a REAL `PRAGMA writable_schema`
    attack rather than only asserted by source text -- round 4's own adversarial
    review (2026-09-15) found this check had ZERO behavioural coverage: a mutation
    that deleted it left the whole suite green. This forges a SECOND `sqlite_master`
    row named `trajectory_runtime_events`, with an honest (non-virtual,
    non-generated-column) `CREATE TABLE` text, sharing `auth_profile_store`'s own
    rootpage -- the ORIGINAL row is kept, not deleted, so this is exactly the
    "sloppy" shape the check is documented to still catch (see `_table_kind`'s own
    docstring for the harder variant -- deleting the original row too -- that this
    check does NOT catch, a disclosed, non-blocking residual).

    Targets `read_compiled_tool_descriptions` (the event_json reader), not
    `corroborate` (the session_id/seq reader): an earlier version of this test used
    the session_id/seq reader and passed FOR THE WRONG REASON -- that reader's own
    `isinstance(seq, int)` check happens to reject a non-numeric aliased value,
    incidentally, regardless of whether the uniqueness check is doing anything. The
    event_json reader has no such incidental type gate, so a pass here is actually
    informative about the check under test."""
    from clawseccheck.trajectorystore import read_compiled_tool_descriptions

    home = _home()
    agent_dir = home / "agents" / "main" / "agent"
    agent_dir.mkdir(parents=True, exist_ok=True)
    db_path = agent_dir / "openclaw-agent.sqlite"
    secret = "SEKRIT" + "-live-oauth-0001"  # assembled at runtime -- Golden Rule #3
    event_json_value = json.dumps(_compiled_event(
        [{"name": secret, "description": "x",
          "parameters": {"type": "object", "properties": {}}}]
    ))

    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "CREATE TABLE auth_profile_store (store_key TEXT PRIMARY KEY, "
            "value_json TEXT)"
        )
        conn.execute(
            "INSERT INTO auth_profile_store VALUES (?, ?)", ("gh", event_json_value)
        )
        conn.commit()
        auth_rootpage = conn.execute(
            "SELECT rootpage FROM sqlite_master WHERE name = 'auth_profile_store'"
        ).fetchone()[0]
        conn.execute("PRAGMA writable_schema = ON")
        # Declared with `event_json` as the SECOND column -- the same physical
        # position `value_json` holds in `auth_profile_store`'s own storage. SQLite
        # stores no column NAMES in the record itself, only values in column order,
        # so the forged table's declared columns determine what a query against this
        # NAME actually reads back from the SAME physical b-tree pages
        # `auth_profile_store` already owns.
        conn.execute(
            "INSERT INTO sqlite_master (type, name, tbl_name, rootpage, sql) "
            "VALUES ('table', 'trajectory_runtime_events', "
            "'trajectory_runtime_events', ?, "
            "'CREATE TABLE trajectory_runtime_events "
            "(placeholder TEXT, event_json TEXT)')",
            (auth_rootpage,),
        )
        conn.commit()
        conn.execute("PRAGMA writable_schema = OFF")
    finally:
        conn.close()

    # Sanity: confirm the plant actually works absent any defense -- a naive read
    # through the forged name really does return the auth table's own row, proving
    # this is a live attack shape, not a no-op fixture.
    naive = sqlite3.connect(db_path)
    try:
        leaked = naive.execute(
            "SELECT event_json FROM trajectory_runtime_events"
        ).fetchall()
    finally:
        naive.close()
    assert leaked == [(event_json_value,)], "the plant itself must be a real, working leak"

    tool_defs, meta = read_compiled_tool_descriptions(home)
    dumped = json.dumps({"tool_defs": tool_defs, "meta": meta})
    assert secret not in dumped
    assert tool_defs == []
    assert meta["dbs_unreadable"] == 1
    assert meta["dbs_read"] == 0


class _RecordingCursor:
    def __init__(self, cursor, executed):
        self._cursor = cursor
        self._executed = executed

    def execute(self, sql, params=()):
        self._executed.append(sql)
        return self._cursor.execute(sql, params)

    def fetchall(self):
        return self._cursor.fetchall()

    def fetchone(self):
        return self._cursor.fetchone()

    def __iter__(self):
        return iter(self._cursor)


class _RecordingConnection:
    def __init__(self, conn, executed):
        self._conn = conn
        self._executed = executed

    def execute(self, sql, params=()):
        self._executed.append(sql)
        return _RecordingCursor(self._conn.execute(sql, params), self._executed)

    def close(self):
        self._conn.close()


def _record_executed_sql(monkeypatch) -> "list[str]":
    """Patch ``sqlite3.connect`` to record every SQL statement executed through it for
    the duration of the test, returning the (initially empty, filled as the test runs)
    list. Shared by every "prove it behaviourally, not just by grepping source" test
    below — one recording rig, reused rather than duplicated per query."""
    executed: "list[str]" = []
    real_connect = sqlite3.connect

    def _connect(*args, **kwargs):
        return _RecordingConnection(real_connect(*args, **kwargs), executed)

    monkeypatch.setattr(sqlite3, "connect", _connect)
    return executed


def test_no_oauth_table_is_ever_queried_by_the_sqlite_reader(monkeypatch):
    """Proves the guarantee BEHAVIOURALLY, not just by grepping source: every SQL
    statement this reader ever executes against the per-agent database is recorded, and
    none of them may name either OAuth-bearing table."""
    home = _home()
    _add_agent_db(home, "main", trajectory_rows=[("s1", 0)], include_auth=True)
    executed = _record_executed_sql(monkeypatch)

    corroborate(home)

    assert executed, "expected at least one SQL statement to have been executed"
    for sql in executed:
        assert "auth_profile_store" not in sql
        assert "auth_profile_state" not in sql
        assert "event_json" not in sql
        # "*" appears legitimately in two shapes that are not the dangerous
        # `SELECT *`: a PRAGMA, and _table_kind's `count(*)` rootpage-uniqueness
        # check (B-811 round 2) -- neither ever selects a row's own columns wholesale.
        assert "*" not in sql or "PRAGMA" in sql or "count(*)" in sql


def test_no_oauth_table_is_ever_queried_by_the_compiled_tool_reader(monkeypatch):
    """B-811: the SAME behavioural proof, for the one function in this module that DOES
    read event_json (read_compiled_tool_descriptions). The property under test is
    narrower here than for corroborate() above — event_json IS expected to appear, by
    design — but the OAuth tables must still never be named in any executed statement,
    and no statement may ever be `SELECT *`."""
    from clawseccheck.trajectorystore import read_compiled_tool_descriptions

    home = _home()
    _add_agent_db(
        home, "main",
        trajectory_rows=[("s1", 0)],  # placeholder tool.call event -- content irrelevant here
        include_auth=True,
    )
    executed = _record_executed_sql(monkeypatch)

    tool_defs, meta = read_compiled_tool_descriptions(home)

    assert executed, "expected at least one SQL statement to have been executed"
    event_json_statements = [sql for sql in executed if "event_json" in sql]
    assert len(event_json_statements) >= 1, executed
    for sql in executed:
        assert "auth_profile_store" not in sql
        assert "auth_profile_state" not in sql
        assert "SELECT *" not in sql
        assert (
            "trajectory_runtime_events" in sql
            or "sqlite_master" in sql
            or "PRAGMA" in sql
            or sql == "BEGIN"
        )
    # Sanity: the placeholder event has no context.compiled record, so nothing is
    # extracted -- this test is about which TABLES were touched, not what was found.
    assert tool_defs == []
    assert meta["dbs_read"] == 1


def test_compiled_tool_reader_refuses_a_view_masquerading_as_the_trajectory_table(monkeypatch):
    """The finding this test exists to close (adversarial review, B-811, 2026-09-15):
    the PREVIOUS version of `test_no_oauth_table_is_ever_queried_by_the_compiled_tool_
    reader` proved only that no EXECUTED STATEMENT names an OAuth table -- it stayed
    green against a database where `trajectory_runtime_events` is a VIEW whose body
    reads `auth_profile_store` and smuggles its content out through a column literally
    named `event_json`. That view IS the attack: `SELECT event_json FROM
    trajectory_runtime_events` is still the only SQL text this reader ever executes,
    and the secret still reaches `tool_defs` -- because SQLite resolves the name
    against the file's OWN schema, not against what our source happens to say. This
    test builds exactly that view and asserts the secret is refused, not that the SQL
    text looks clean.
    """
    from clawseccheck.trajectorystore import read_compiled_tool_descriptions

    home = _home()
    agent_dir = home / "agents" / "main" / "agent"
    agent_dir.mkdir(parents=True, exist_ok=True)
    db_path = agent_dir / "openclaw-agent.sqlite"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "CREATE TABLE auth_profile_store (store_key TEXT PRIMARY KEY, "
            "value_json TEXT)"
        )
        conn.execute(
            "INSERT INTO auth_profile_store VALUES (?, ?)",
            ("gh", json.dumps({"access_token": SECRET})),
        )
        conn.execute(
            "CREATE VIEW trajectory_runtime_events AS "
            "SELECT 'sess-1' AS session_id, 0 AS seq, 'run-1' AS run_id, "
            "'{\"traceSchema\":\"openclaw-trajectory\",\"schemaVersion\":1,"
            "\"type\":\"context.compiled\",\"data\":{\"tools\":[{\"name\":\"' "
            "|| value_json || '\",\"description\":\"x\",\"parameters\":{}}]}}' "
            "AS event_json, 0 AS created_at FROM auth_profile_store"
        )
        conn.commit()
    finally:
        conn.close()

    tool_defs, meta = read_compiled_tool_descriptions(home)

    dumped = json.dumps({"tool_defs": tool_defs, "meta": meta})
    assert SECRET not in dumped
    assert tool_defs == []
    # The view is refused outright (not silently skipped as "no such table") -- it
    # genuinely exists under this name, it is just not a table, so it counts toward
    # `dbs_unreadable`, never `dbs_read`.
    assert meta["dbs_unreadable"] == 1
    assert meta["dbs_read"] == 0


def test_compiled_tool_reader_refuses_a_table_with_a_generated_column():
    """The round-3 adversarial-review finding (B-811, 2026-09-15), reproduced
    end-to-end through `read_compiled_tool_descriptions` -- the same primitive
    `test_corroborate_refuses_a_table_with_a_generated_column` closes for the
    session_id/seq reader, but here the generated `event_json` column assembles a
    real, PARSEABLE `context.compiled` record (via SQLite's own `json_quote()`, so the
    secret is correctly JSON-escaped rather than producing malformed JSON that would
    fail to parse for an unrelated reason and pass this test for the wrong cause).
    Round 1/round 2's `_table_kind` checks all pass this table honestly; only round
    3/4's `PRAGMA table_xinfo` hidden-column check refuses it."""
    from clawseccheck.trajectorystore import read_compiled_tool_descriptions

    home = _home()
    agent_dir = home / "agents" / "main" / "agent"
    agent_dir.mkdir(parents=True, exist_ok=True)
    db_path = agent_dir / "openclaw-agent.sqlite"
    event_json_expr = (
        "'{\"traceSchema\":\"openclaw-trajectory\",\"schemaVersion\":1,"
        "\"type\":\"context.compiled\",\"data\":{\"tools\":[{\"name\":' || "
        "json_quote(value_json) || ',\"description\":\"x\",\"parameters\":{}}]}}'"
    )
    _plant_generated_column_bypass(db_path, event_json_expr=event_json_expr)

    tool_defs, meta = read_compiled_tool_descriptions(home)

    dumped = json.dumps({"tool_defs": tool_defs, "meta": meta})
    assert SECRET not in dumped
    assert tool_defs == []
    assert meta["dbs_unreadable"] == 1
    assert meta["dbs_read"] == 0


def _compiled_event(tools):
    return {
        "traceSchema": "openclaw-trajectory", "schemaVersion": 1,
        "type": "context.compiled",
        "data": {
            "systemPrompt": "You are a helpful assistant.",
            "messages": [{"role": "user", "content": "hi"}],
            "tools": tools,
        },
    }


def test_compiled_tool_reader_recovers_real_content_and_still_ignores_oauth_tables():
    """The positive case, same db file as the isolation test above: a real
    context.compiled event IS recovered (content-reading works), and the OAuth secret
    sharing the file is STILL never reachable through the result."""
    from clawseccheck.trajectorystore import read_compiled_tool_descriptions

    home = _home()
    tools = [{
        "name": "get_weather", "description": "Get the weather for a city.",
        "parameters": {"properties": {}},
    }]
    _add_agent_db(
        home, "main",
        trajectory_rows=[("s1", 0, _compiled_event(tools))],
        include_auth=True,
    )

    tool_defs, meta = read_compiled_tool_descriptions(home)

    assert len(tool_defs) == 1
    assert tool_defs[0]["name"] == "get_weather"
    assert meta["events"] == 1
    dumped = json.dumps({"tool_defs": tool_defs, "meta": meta})
    assert SECRET not in dumped


def test_an_oversized_row_is_excluded_at_the_sql_level_not_after_materializing_it():
    """The DoS finding (adversarial review, B-811, 2026-09-15): the ORIGINAL version
    bound a single row's size only AFTER `.fetchall()` had already pulled it fully into
    this process — a 200-row, 4 KB crafted database produced 385 MB of peak Python RSS
    because that bound never got a chance to run. `_SELECT_TRAJECTORY_EVENT_JSON`'s own
    `WHERE length(event_json) <= ?` now excludes an oversized row at the SQL engine,
    before this process ever sees its value. Deterministic: measures the returned
    VALUES, not process memory (which is what an RSS assertion would need, and is too
    environment-fragile for a unit test) — the property that matters is observable
    without it: the oversized row's content never reaches this process at all.
    """
    from clawseccheck.trajectorystore import (
        _MAX_COMPILED_LINE_LEN,
        _read_sqlite_event_json,
    )

    home = _home()
    agent_dir = home / "agents" / "main" / "agent"
    agent_dir.mkdir(parents=True, exist_ok=True)
    db_path = agent_dir / "openclaw-agent.sqlite"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "CREATE TABLE trajectory_runtime_events (session_id TEXT NOT NULL, "
            "seq INTEGER NOT NULL, run_id TEXT, event_json TEXT NOT NULL, "
            "created_at INTEGER NOT NULL, PRIMARY KEY (session_id, seq))"
        )
        # One row well within bounds, one deliberately oversized (bigger than SQLite
        # itself is asked to admit) -- both real strings assembled in Python, so the
        # cap is exercised on genuine TEXT content, not a synthetic shortcut.
        conn.execute(
            "INSERT INTO trajectory_runtime_events VALUES (?,?,?,?,?)",
            ("small", 0, "r", json.dumps({"type": "tool.call"}), 0),
        )
        conn.execute(
            "INSERT INTO trajectory_runtime_events VALUES (?,?,?,?,?)",
            ("huge", 0, "r", "X" * (_MAX_COMPILED_LINE_LEN + 1000), 0),
        )
        conn.commit()
    finally:
        conn.close()

    values, capped, unreadable, non_text = _read_sqlite_event_json(db_path)

    assert unreadable is False
    # The oversized row is EXCLUDED by the WHERE clause -- it never appears in
    # `values` at all, and is not counted as a "non_text" drop either (it was TEXT,
    # just too long; the SQL filter, not the Python-side type check, is what excluded
    # it -- the two are deliberately different mechanisms for different shapes).
    assert len(values) == 1
    assert all(len(v) <= _MAX_COMPILED_LINE_LEN for v in values)
    assert non_text == 0


def test_the_aggregate_byte_cap_stops_reading_further_rows_not_just_counting_them():
    """The other half of the same DoS finding: even with every individual row within
    the per-row length bound, MANY such rows must not be allowed to accumulate past
    the per-database byte cap. `capped=True` must fire, and — the property the
    original `.fetchall()`-based version could not have, since it always materialized
    every row first — the returned `values` list itself must stop growing once the
    cap is crossed, not just report a flag after the fact."""
    from clawseccheck.trajectorystore import (
        _MAX_SQLITE_CONTENT_BYTES_PER_DB,
        _read_sqlite_event_json,
    )

    home = _home()
    agent_dir = home / "agents" / "main" / "agent"
    agent_dir.mkdir(parents=True, exist_ok=True)
    db_path = agent_dir / "openclaw-agent.sqlite"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "CREATE TABLE trajectory_runtime_events (session_id TEXT NOT NULL, "
            "seq INTEGER NOT NULL, run_id TEXT, event_json TEXT NOT NULL, "
            "created_at INTEGER NOT NULL, PRIMARY KEY (session_id, seq))"
        )
        row_size = 500_000  # well under the per-row length bound, deliberately many
        row_count = (_MAX_SQLITE_CONTENT_BYTES_PER_DB // row_size) + 20  # past the cap
        for i in range(row_count):
            conn.execute(
                "INSERT INTO trajectory_runtime_events VALUES (?,?,?,?,?)",
                (f"s{i}", 0, "r", "X" * row_size, 0),
            )
        conn.commit()
    finally:
        conn.close()

    values, capped, unreadable, non_text = _read_sqlite_event_json(db_path)

    assert unreadable is False
    assert capped is True
    total_bytes = sum(len(v) for v in values)
    # The returned bytes must stay bounded near the cap, not near what was inserted --
    # this is the property `.fetchall()` could never have given, since it always
    # materializes everything before any check runs.
    assert total_bytes <= _MAX_SQLITE_CONTENT_BYTES_PER_DB + row_size
    assert len(values) < row_count  # did NOT read everything that was inserted


def test_a_non_text_row_is_disclosed_never_silently_dropped():
    """B-4b (adversarial review, B-811, 2026-09-15): SQLite's dynamic typing lets a row
    store a BLOB (or NULL/int/float) under this TEXT-affinity column regardless of the
    declared type -- the length() SQL filter cannot tell a BLOB from oversized TEXT,
    so a caller must be told this happened, not left to assume every row was examined
    when the count of REAL context.compiled records recovered stayed the same as a
    clean run would show."""
    from clawseccheck.trajectorystore import read_compiled_tool_descriptions

    home = _home()
    tools = [{
        "name": "get_weather", "description": "Get the weather for a city.",
        "parameters": {"properties": {}},
    }]
    _add_agent_db(
        home, "main",
        trajectory_rows=[("s1", 0, _compiled_event(tools))],
        include_auth=False,
    )
    # Insert a BLOB-typed row directly (bypassing the (event_id, event) tuple shape
    # _add_agent_db expects) -- same db, same table, a SECOND row storing a BLOB.
    agent_dir = home / "agents" / "main" / "agent"
    conn = sqlite3.connect(agent_dir / "openclaw-agent.sqlite")
    try:
        conn.execute(
            "INSERT INTO trajectory_runtime_events VALUES (?,?,?,?,?)",
            ("s2", 0, "r", sqlite3.Binary(b"\x00\x01binary junk"), 0),
        )
        conn.commit()
    finally:
        conn.close()

    tool_defs, meta = read_compiled_tool_descriptions(home)

    # The real event is still recovered -- one bad row does not blind the database.
    assert len(tool_defs) == 1
    assert tool_defs[0]["name"] == "get_weather"
    # But the drop is disclosed, not silent.
    assert meta["non_text_rows"] == 1
    assert meta["truncated"] is True


def test_invalid_utf8_in_one_row_no_longer_blinds_the_whole_database():
    """B-4a (adversarial review, B-811, 2026-09-15): the ORIGINAL connection had no
    custom `text_factory`, so `sqlite3` raised `OperationalError` decoding ONE
    genuinely-invalid-UTF-8 row -- and that error discarded every row `.fetchall()`
    had already read in the same call, not just the bad one. A compromised agent could
    blind the whole database's worth of real evidence by writing a single junk byte
    sequence. `_open_readonly`'s `text_factory` (``errors="replace"``, matching the
    JSONL reader's own tolerance) degrades that one row instead of raising."""
    from clawseccheck.trajectorystore import read_compiled_tool_descriptions

    home = _home()
    tools = [{
        "name": "get_weather", "description": "Get the weather for a city.",
        "parameters": {"properties": {}},
    }]
    _add_agent_db(
        home, "main",
        trajectory_rows=[("s1", 0, _compiled_event(tools))],
        include_auth=False,
    )
    agent_dir = home / "agents" / "main" / "agent"
    conn = sqlite3.connect(agent_dir / "openclaw-agent.sqlite")
    try:
        # Genuinely invalid UTF-8 bytes, bound directly so sqlite3 stores them as TEXT
        # without this process ever validating them first.
        conn.execute(
            "INSERT INTO trajectory_runtime_events VALUES (?,?,?,?,?)",
            ("s2", 0, "r", "placeholder".encode(), 0),
        )
        conn.execute(
            "UPDATE trajectory_runtime_events SET event_json = ? WHERE session_id = ?",
            (b"\xff\xfe not valid utf8 " + b"\x80" * 20, "s2"),
        )
        conn.commit()
    finally:
        conn.close()

    tool_defs, meta = read_compiled_tool_descriptions(home)

    # The real event, in a DIFFERENT row, is still recovered -- the malformed row did
    # not take the whole database down with it.
    assert len(tool_defs) == 1
    assert tool_defs[0]["name"] == "get_weather"
    assert meta["dbs_read"] == 1
    assert meta["dbs_unreadable"] == 0


def test_an_unreadable_agent_database_is_disclosed_not_silently_dropped(tmp_path):
    """A DB file that exists but cannot be opened as SQLite at all (corrupt/locked) is
    reported as unreadable, never folded into "no residue"."""
    home = _home(tmp_path)
    agent_dir = home / "agents" / "main" / "agent"
    agent_dir.mkdir(parents=True)
    (agent_dir / "openclaw-agent.sqlite").write_bytes(b"not a sqlite file at all")

    corro = corroborate(home)
    assert corro.sqlite_dbs_found == 1
    assert corro.sqlite_dbs_unreadable == 1
    assert corro.sqlite_dbs_read == 0


def test_a_pointer_that_fails_to_parse_is_counted_but_not_flagged_missing():
    """"Could not look" and "looked, target is gone" are different answers — the same
    distinction F-183's own reader draws for an unparsable config-machine-state row."""
    home = _home()
    sessions = home / "agents" / "main" / "sessions"
    sessions.mkdir(parents=True)
    (sessions / "s1.trajectory-path.json").write_text("not json at all", encoding="utf-8")

    corro = corroborate(home)
    assert corro.pointer_files == 1
    assert corro.pointer_targets_missing == 0
    # a lone unparsable pointer, no other evidence anywhere -> honestly NO_RESIDUE
    assert corro.status == STATUS_NO_RESIDUE


def test_a_pointer_whose_target_exists_is_not_counted_as_missing():
    home = _home()
    _add_pointer(home, "main", "s1", target_exists=True)
    corro = corroborate(home)
    assert corro.pointer_files == 1
    assert corro.pointer_targets_missing == 0
    # the target file itself IS a live sidecar, so the classic glob finds it too
    assert corro.status == STATUS_LIVE


# ---------------------------------------------------------------------------
# B-852 item 1 — _SELECT_TRAJECTORY_EVENT_JSON now reads newest rows first.
# ---------------------------------------------------------------------------


def test_read_sqlite_event_json_reads_newest_row_first_when_capped():
    """Before B-852, `_SELECT_TRAJECTORY_EVENT_JSON` carried a `LIMIT` with no `ORDER
    BY` at all, so on a store past the row cap SQLite returned rows in whatever order
    its own storage happened to hold them -- in practice insertion order, i.e. the
    OLDEST rows first, for a plain sequential set of INSERTs like this fixture builds.
    With `max_rows=1` forcing the cap, the single value returned must be the row with
    the LARGEST `rowid`/`created_at` ("new", inserted second), never the smallest
    ("old") -- this fails exactly the way it would have before the `ORDER BY rowid
    DESC` fix, which returned "old" here (the first-inserted row). (A first version of
    this fix used `ORDER BY created_at DESC` instead of `rowid`; two independent
    adversarial reviews found that regresses performance/correctness on a large
    database -- see `_SELECT_TRAJECTORY_EVENT_JSON`'s own comment -- so it was
    replaced with `rowid`, which this fixture's insertion order (old first, new
    second) still exercises identically.)
    """
    from clawseccheck.trajectorystore import _read_sqlite_event_json

    home = _home()
    agent_dir = home / "agents" / "main" / "agent"
    agent_dir.mkdir(parents=True, exist_ok=True)
    db_path = agent_dir / "openclaw-agent.sqlite"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "CREATE TABLE trajectory_runtime_events (session_id TEXT NOT NULL, "
            "seq INTEGER NOT NULL, run_id TEXT, event_json TEXT NOT NULL, "
            "created_at INTEGER NOT NULL, PRIMARY KEY (session_id, seq))"
        )
        # Inserted OLDEST first, exactly the shape a real long-lived agent database
        # accumulates rows in.
        conn.execute(
            "INSERT INTO trajectory_runtime_events VALUES (?,?,?,?,?)",
            ("old", 0, "r", json.dumps({"marker": "old"}), 1),
        )
        conn.execute(
            "INSERT INTO trajectory_runtime_events VALUES (?,?,?,?,?)",
            ("new", 0, "r", json.dumps({"marker": "new"}), 2),
        )
        conn.commit()
    finally:
        conn.close()

    values, capped, unreadable, non_text = _read_sqlite_event_json(db_path, max_rows=1)

    assert unreadable is False
    assert capped is True
    assert len(values) == 1
    assert json.loads(values[0])["marker"] == "new"


# ---------------------------------------------------------------------------
# B-852 follow-up — `ORDER BY created_at DESC` (the first version of the item-1 fix
# above) turned out to regress performance/correctness on a large database: two
# independent adversarial (C-135) reviews measured a single 500 MB per-agent database
# going from 0.16s to 2.6-3.0s, and 8 such databases blowing through the check's 15s
# wall-clock scan budget entirely (aborted as UNKNOWN -- meaning a poisoned newest
# record was never reported, the opposite of the intended fix). The root cause:
# `created_at` has no index, and shares a row with up to 256 KB of `event_json`, so
# SQLite must materialize and sort every row's full payload before it can return the
# first one under `LIMIT`. `ORDER BY rowid DESC` replaces it -- `rowid` is the table's
# own b-tree key, so this is a plain reverse index scan, no sort, no materialization.
# ---------------------------------------------------------------------------


def test_event_json_query_plan_has_no_sort_step():
    """A direct, deterministic proxy for the measured 500 MB/2.6-3.0s regression,
    without needing an actual large database: `EXPLAIN QUERY PLAN` on
    `_SELECT_TRAJECTORY_EVENT_JSON` must show a plain scan and NOTHING that
    materializes/sorts rows (SQLite reports that as `USE TEMP B-TREE FOR ORDER BY`).
    Run the SAME query with `ORDER BY created_at DESC` substituted back in (the
    regressed, first-attempt fix) to prove this is a real, checkable difference in
    THIS SQLite build, not a query the optimizer would have avoided sorting for
    anyway -- if that substitution ever stopped needing a sort too, this assertion
    would need re-examining, not just the `rowid` one.
    """
    from clawseccheck.trajectorystore import _MAX_COMPILED_LINE_LEN, _SELECT_TRAJECTORY_EVENT_JSON

    assert "ORDER BY rowid DESC" in _SELECT_TRAJECTORY_EVENT_JSON

    conn = sqlite3.connect(":memory:")
    try:
        conn.execute(
            "CREATE TABLE trajectory_runtime_events (session_id TEXT NOT NULL, "
            "seq INTEGER NOT NULL, run_id TEXT, event_json TEXT NOT NULL, "
            "created_at INTEGER NOT NULL, PRIMARY KEY (session_id, seq))"
        )
        for i in range(5):
            conn.execute(
                "INSERT INTO trajectory_runtime_events VALUES (?,?,?,?,?)",
                (f"s{i}", 0, "r", json.dumps({"i": i}), i),
            )
        conn.commit()

        rowid_plan = conn.execute(
            f"EXPLAIN QUERY PLAN {_SELECT_TRAJECTORY_EVENT_JSON}",
            (_MAX_COMPILED_LINE_LEN, 10),
        ).fetchall()
        rowid_plan_text = " ".join(row[-1] for row in rowid_plan)
        assert "B-TREE" not in rowid_plan_text.upper(), rowid_plan

        regressed_query = _SELECT_TRAJECTORY_EVENT_JSON.replace(
            "ORDER BY rowid DESC", "ORDER BY created_at DESC"
        )
        assert regressed_query != _SELECT_TRAJECTORY_EVENT_JSON  # substitution took
        created_at_plan = conn.execute(
            f"EXPLAIN QUERY PLAN {regressed_query}",
            (_MAX_COMPILED_LINE_LEN, 10),
        ).fetchall()
        created_at_plan_text = " ".join(row[-1] for row in created_at_plan)
        assert "USE TEMP B-TREE FOR ORDER BY" in created_at_plan_text, created_at_plan
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# B-852 item 2 — the SQLite reader's caps are now overridable, so --exhaustive can
# widen them the same way it already widens the JSONL sibling's max_files/
# max_bytes_per_file (checks/_mcp.py's own lim.sqlite_max_* plumbing).
# ---------------------------------------------------------------------------


def test_sqlite_dbs_honors_a_narrower_max_dbs_override():
    from clawseccheck.trajectorystore import _sqlite_dbs

    home = _home()
    for i in range(3):
        _add_agent_db(home, f"agent{i}", trajectory_rows=[(f"s{i}", 0)], include_auth=False)

    assert len(_sqlite_dbs(home)) == 3          # default: no cap hit
    assert len(_sqlite_dbs(home, max_dbs=1)) == 1
    assert len(_sqlite_dbs(home, max_dbs=0)) == 0


def test_read_compiled_tool_descriptions_threads_its_override_kwargs_to_the_reader():
    """`read_compiled_tool_descriptions`'s new `max_dbs` /
    `max_content_rows_per_db` / `max_content_bytes_per_db` kwargs (B-852) must
    actually reach the underlying per-database reads, not just be accepted and
    ignored. Proven the same way `test_read_sqlite_event_json_reads_newest_row_first_
    when_capped` proves the reader itself: force the row cap down to 1 via the PUBLIC
    function's own kwarg (not by reaching into `_read_sqlite_event_json` directly),
    and confirm only the newest of two events survives.
    """
    from clawseccheck.trajectorystore import read_compiled_tool_descriptions

    home = _home()
    older = [{"name": "older_tool", "description": "d", "parameters": {"properties": {}}}]
    newer = [{"name": "newer_tool", "description": "d", "parameters": {"properties": {}}}]
    _add_agent_db(
        home, "main",
        trajectory_rows=[
            ("s_old", 0, _compiled_event(older), 1),
            ("s_new", 0, _compiled_event(newer), 2),
        ],
        include_auth=False,
    )

    # Default caps: both events recovered.
    tool_defs, meta = read_compiled_tool_descriptions(home)
    assert meta["events"] == 2
    names = {d["name"] for d in tool_defs}
    assert names == {"older_tool", "newer_tool"}

    # max_content_rows_per_db=1: only the newest row is admitted.
    capped_defs, capped_meta = read_compiled_tool_descriptions(
        home, max_content_rows_per_db=1,
    )
    assert capped_meta["events"] == 1
    assert capped_meta["truncated"] is True
    assert {d["name"] for d in capped_defs} == {"newer_tool"}

    # max_dbs=0: no database is opened at all.
    empty_defs, empty_meta = read_compiled_tool_descriptions(home, max_dbs=0)
    assert empty_defs == []
    assert empty_meta["dbs_found"] == 0
    assert empty_meta["present"] is False
