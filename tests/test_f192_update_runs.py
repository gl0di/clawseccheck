"""F-192 -- reading OpenClaw's own self-update ledger (`update_runs`), a new state-DB
table at 2026.9.2 (state schema `PRAGMA user_version` 15).

`trigger = 'chat'` is first-class self-modification evidence: an OpenClaw self-update
initiated FROM a conversation turn. Today `checks/_lifecycle.py` / `openclawdist.py` can
only INFER an update happened from bytes that changed on disk -- never who triggered it,
what it moved from/to, or whether it finished. A row stuck at `status = 'running'` is the
exact shape of the known "UI update leaves gateway down" failure.

The reader is field-selected, never `SELECT *`: the same database holds live OAuth tokens
under `authProfiles.store` / `auth.sharedStore`, and the seven `*_json` blob columns on
this very table may themselves carry filesystem paths -- so this reader does not read any
of them at all.
"""
import json
import os
import sqlite3
import tempfile
from pathlib import Path

from clawseccheck.collector import (
    Context,
    _collect_update_runs,
    _MAX_UPDATE_RUNS,
    collect,
)

SECRET = "oauth-token-that-must-never-be-read"

_UPDATE_RUNS_SCHEMA = """
CREATE TABLE update_runs (
  run_id TEXT PRIMARY KEY NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  trigger TEXT NOT NULL,
  phase TEXT NOT NULL,
  status TEXT NOT NULL,
  reason TEXT,
  origin_json TEXT NOT NULL,
  target_json TEXT NOT NULL,
  before_json TEXT NOT NULL,
  after_json TEXT NOT NULL,
  steps_json TEXT NOT NULL,
  verification_json TEXT NOT NULL,
  repair_json TEXT NOT NULL,
  confirmed_at_ms INTEGER,
  finished_at_ms INTEGER,
  downtime_ms INTEGER
)
"""

_ROW_DEFAULTS = dict(
    created_at_ms=1_700_000_000_000,
    updated_at_ms=1_700_000_000_000,
    reason=None,
    origin_json="{}",
    target_json="{}",
    before_json="{}",
    after_json="{}",
    steps_json="[]",
    verification_json="{}",
    repair_json="{}",
    confirmed_at_ms=None,
    finished_at_ms=None,
    downtime_ms=None,
)


def _home(rows=None, *, table="update_runs", make_db=True, extra_tables=()):
    home = Path(tempfile.mkdtemp(prefix="f192-"))
    path = home / "openclaw.json"
    path.write_text(json.dumps({}))
    os.chmod(path, 0o600)
    if make_db:
        state = home / "state"
        state.mkdir()
        con = sqlite3.connect(state / "openclaw.sqlite")
        try:
            con.execute(_UPDATE_RUNS_SCHEMA.replace("update_runs", table, 1))
            for row in (rows or []):
                merged = {**_ROW_DEFAULTS, **row}
                cols = ", ".join(merged)
                placeholders = ", ".join("?" for _ in merged)
                con.execute(
                    f"INSERT INTO {table} ({cols}) VALUES ({placeholders})",
                    list(merged.values()),
                )
            for name, ddl in extra_tables:
                con.execute(ddl)
            con.commit()
        finally:
            con.close()
    return home


def _row(run_id, trigger, phase, status, **overrides):
    return dict(run_id=run_id, trigger=trigger, phase=phase, status=status, **overrides)


# ------------------------------------------------------------------ the reader

def test_clean_empty_table_is_read_but_holds_nothing():
    """The DoD's clean fixture: table present, empty -- no self-update ever ran."""
    ctx = collect(_home([]))
    assert ctx.update_runs_read is True
    assert ctx.update_runs == []
    assert ctx.update_runs_parse_error is False


def test_a_chat_triggered_update_is_surfaced():
    """The DoD's first bad fixture: a completed self-update the agent itself kicked off."""
    ctx = collect(_home([
        _row("run-1", "chat", "finished", "succeeded", finished_at_ms=1_700_000_100_000),
    ]))
    assert ctx.update_runs_read is True
    assert len(ctx.update_runs) == 1
    entry = ctx.update_runs[0]
    assert entry["run_id"] == "run-1"
    assert entry["trigger"] == "chat"
    assert entry["status"] == "succeeded"


def test_a_stuck_running_update_is_surfaced():
    """The DoD's second bad fixture: this machine's own real state on 2026-09-06 -- a
    9.1 -> 9.2 upgrade that requested and never finished."""
    ctx = collect(_home([
        _row("4165c78d-stuck", "cli", "requested", "running"),
    ]))
    entry = next(e for e in ctx.update_runs if e["run_id"] == "4165c78d-stuck")
    assert entry["status"] == "running"
    assert entry["phase"] == "requested"
    assert entry["finished_at_ms"] is None


def test_table_absent_from_the_db_is_undetermined_not_absent():
    """The DoD's UNKNOWN fixture. A DECLARED table (`CREATE TABLE IF NOT EXISTS`) is not
    necessarily an EXISTING one -- 13 of the skill_library_* family prove that on a real
    machine (B-725). "Could not look" must never collapse into "looked, nothing there"."""
    ctx = collect(_home([], table="something_else"))
    assert ctx.update_runs_read is False
    assert ctx.update_runs == []


def test_no_state_database_at_all_is_also_undetermined():
    ctx = collect(_home([], make_db=False))
    assert ctx.update_runs_read is False
    assert ctx.update_runs == []


def test_multiple_runs_come_back_newest_first():
    ctx = collect(_home([
        _row("older", "cli", "finished", "succeeded", created_at_ms=1_000),
        _row("newer", "chat", "finished", "succeeded", created_at_ms=2_000),
    ]))
    assert [e["run_id"] for e in ctx.update_runs] == ["newer", "older"]


def test_every_declared_trigger_and_phase_round_trips():
    """Not an enum validator (sqlite has no CHECK enforcement in this fixture) -- just
    proof the reader does not silently drop a value it doesn't recognise."""
    ctx = collect(_home([
        _row("r1", "control-ui", "staging", "running"),
        _row("r2", "campaign", "repairing", "failed"),
        _row("r3", "mac-app", "verifying", "rolled-back"),
        _row("r4", "api", "activating", "skipped"),
    ]))
    triggers = {e["trigger"] for e in ctx.update_runs}
    assert triggers == {"control-ui", "campaign", "mac-app", "api"}


# ------------------------------------------------------- bound / truncation

def test_the_row_cap_is_disclosed_and_the_newest_rows_survive():
    rows = [
        _row(f"run-{i}", "cli", "finished", "succeeded", created_at_ms=i)
        for i in range(_MAX_UPDATE_RUNS + 5)
    ]
    ctx = collect(_home(rows))
    assert len(ctx.update_runs) == _MAX_UPDATE_RUNS
    assert ctx.update_runs_truncated is True
    # newest (highest created_at_ms) survive the cap
    assert ctx.update_runs[0]["run_id"] == f"run-{_MAX_UPDATE_RUNS + 4}"


def test_under_the_cap_is_not_reported_truncated():
    ctx = collect(_home([_row("only-one", "cli", "finished", "succeeded")]))
    assert ctx.update_runs_truncated is False


# ------------------------------------------------------- the key scope, proven

def test_the_blob_columns_are_never_selected():
    """The mutation target. Widen the SELECT to `origin_json`/`target_json`/etc (or to
    `SELECT *`) and this fails -- the same guarantee `config_machine_state` proves for its
    own table, on a sibling table that shares the same database."""
    ctx = collect(_home([
        _row("r1", "chat", "finished", "succeeded",
             origin_json=json.dumps({"path": f"/home/{SECRET}/install"}),
             target_json=json.dumps({"token": SECRET}),
             repair_json=json.dumps({"note": SECRET})),
    ]))
    entry = ctx.update_runs[0]
    assert set(entry) == {
        "run_id", "trigger", "phase", "status", "reason",
        "created_at_ms", "updated_at_ms", "finished_at_ms", "downtime_ms",
    }
    assert SECRET not in json.dumps(entry)


def test_the_query_binds_an_explicit_column_list_never_select_star():
    """Checked against the CODE, with the docstring's own grounding prose (which quotes the
    full CREATE TABLE, blob-column names included, for the schema record) stripped out via
    `ast` -- never a naive comment strip, which the docstring's grounding text defeats."""
    import ast
    import inspect
    from clawseccheck import collector

    source = inspect.getsource(collector._collect_update_runs)
    tree = ast.parse(source)
    fn = tree.body[0]
    docstring = ast.get_docstring(fn, clean=False)
    body_nodes = fn.body[1:] if (docstring is not None) else fn.body
    code = "\n".join(ast.get_source_segment(source, n) or "" for n in body_nodes)

    assert "SELECT *" not in code
    for blob_col in ("origin_json", "target_json", "before_json", "after_json",
                      "steps_json", "verification_json", "repair_json"):
        assert blob_col not in code, f"{blob_col} must never be selected (§8)"


def test_nothing_from_the_blob_columns_reaches_a_rendered_report():
    from clawseccheck import audit
    from clawseccheck.report import render_report
    home = _home([
        _row("r1", "chat", "finished", "succeeded",
             origin_json=json.dumps({"secret": SECRET})),
    ])
    _ctx, findings, score = audit(home)
    rendered = render_report(findings, score, ctx=_ctx, verbose=True)
    assert SECRET not in rendered
    assert SECRET not in json.dumps([f.__dict__ for f in findings], default=str)


# ------------------------------------------------------- disclosure discipline

def test_an_unreadable_store_never_reads_via_generic_exception_handling(tmp_path):
    """A state DB whose update_runs table is present but the connection itself is broken
    (simulated via a corrupt file) reports parse_error, not silent success."""
    home = tmp_path / "oc"
    state = home / "state"
    state.mkdir(parents=True)
    (state / "openclaw.sqlite").write_bytes(b"not a real sqlite file at all, corrupt")
    ctx = Context(home=home, config={}, config_path=home / "openclaw.json")
    _collect_update_runs(home, ctx)
    assert ctx.update_runs_read is True
    assert ctx.update_runs_parse_error is True


def test_a_capped_state_walk_is_disclosed_not_reported_as_no_ledger(tmp_path):
    """Same GR#4 disclosure `_collect_config_machine_state` already proves: a `walk_dir_
    safely(max_files=100)` that stops before reaching the DB must not read the same as an
    ordinary empty state dir."""
    home = tmp_path / "oc"
    state = home / "state"
    state.mkdir(parents=True)
    for n in range(150):
        (state / f"zz-{n:03d}.tmp").write_bytes(b"")
    ctx = Context(home=home, config={}, config_path=home / "openclaw.json")
    _collect_update_runs(home, ctx)
    assert ctx.update_runs_read is False
    assert any("stopped listing" in e and "openclaw.sqlite" in e for e in ctx.errors)


def test_an_ordinary_empty_state_dir_stays_quiet(tmp_path):
    home = tmp_path / "oc"
    (home / "state").mkdir(parents=True)
    ctx = Context(home=home, config={}, config_path=home / "openclaw.json")
    _collect_update_runs(home, ctx)
    assert ctx.update_runs_read is False
    assert not [e for e in ctx.errors if "stopped listing" in e]
