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
    database file on a real host (`auth_profile_store`/`auth_profile_state`)."""
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
        for session_id, seq in trajectory_rows:
            conn.execute(
                f"INSERT INTO {table} VALUES (?,?,?,?,?)",
                (session_id, seq, "run-1", json.dumps({"type": "tool.call"}), 0),
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
    """A source-level companion to the behavioural OAuth test below: `SELECT *` or a
    query built from a variable would still pass a row-count assertion if someone later
    filtered in Python — and filtering after the fact means the secret was already read
    into this process first.

    Scoped to the actual `.execute(...)` call sites, not the whole file: the module's
    own docstrings NAME `auth_profile_store`/`auth_profile_state`/`event_json` in prose
    (explaining exactly why they must never be touched), so a whole-file substring
    check would fail on the very sentences documenting the guarantee. What must be
    true is narrower and stronger: no *executed* SQL statement ever names them.
    """
    from clawseccheck.trajectorystore import _SELECT_TRAJECTORY_ROWS
    assert _SELECT_TRAJECTORY_ROWS == (
        "SELECT session_id, seq FROM trajectory_runtime_events LIMIT ?"
    )
    assert "*" not in _SELECT_TRAJECTORY_ROWS

    source = (Path(__file__).resolve().parent.parent
              / "clawseccheck" / "trajectorystore.py").read_text()
    execute_lines = [ln for ln in source.splitlines() if ".execute(" in ln]
    assert len(execute_lines) == 2, execute_lines  # PRAGMA + the one SELECT, no more
    for ln in execute_lines:
        assert "auth_profile" not in ln
        assert "event_json" not in ln
        assert "SELECT *" not in ln
        assert "f'" not in ln and 'f"' not in ln  # never an interpolated/dynamic query


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


def test_no_oauth_table_is_ever_queried_by_the_sqlite_reader(monkeypatch):
    """Proves the guarantee BEHAVIOURALLY, not just by grepping source: every SQL
    statement this reader ever executes against the per-agent database is recorded, and
    none of them may name either OAuth-bearing table."""
    home = _home()
    _add_agent_db(home, "main", trajectory_rows=[("s1", 0)], include_auth=True)

    executed: "list[str]" = []
    real_connect = sqlite3.connect

    class _RecordingCursor:
        def __init__(self, cursor):
            self._cursor = cursor

        def execute(self, sql, params=()):
            executed.append(sql)
            return self._cursor.execute(sql, params)

        def fetchall(self):
            return self._cursor.fetchall()

        def fetchone(self):
            return self._cursor.fetchone()

    class _RecordingConnection:
        def __init__(self, conn):
            self._conn = conn

        def execute(self, sql, params=()):
            executed.append(sql)
            return _RecordingCursor(self._conn.execute(sql, params))

        def close(self):
            self._conn.close()

    def _connect(*args, **kwargs):
        return _RecordingConnection(real_connect(*args, **kwargs))

    monkeypatch.setattr(sqlite3, "connect", _connect)

    corroborate(home)

    assert executed, "expected at least one SQL statement to have been executed"
    for sql in executed:
        assert "auth_profile_store" not in sql
        assert "auth_profile_state" not in sql
        assert "event_json" not in sql
        assert "*" not in sql or "PRAGMA" in sql


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
