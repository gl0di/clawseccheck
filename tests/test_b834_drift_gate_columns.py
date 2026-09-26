"""B-834: the state-DB drift gate must read COLUMNS, not every word in a SELECT list.

`scripts/state_db_drift_gate.py` derives what our code reads from the SELECT statements
`clawseccheck/` actually issues. Its column extractor was a bare identifier regex minus a
hand-kept noise set, so each SQL function we began using was a fresh false ``BLIND``:
``SELECT LENGTH(value_json) FROM config_machine_state`` printed "config_machine_state is
missing LENGTH" against a healthy database and made the gate exit 1 on a clean baseline --
on the 2026.9.4 control as well as on 2026.9.5. A gate that is red on a clean build is a gate
people learn to ignore.

The fix is structural (a function call, an alias and a string literal are not columns), and
the two failure directions are pinned separately, because either one alone would pass a
sloppy "fix": swallowing more (a real column called ``length`` vanishing) is the false
negative the gate exists to prevent, and swallowing less is the false BLIND above.

Offline: builds a throwaway package and SQLite file under ``tmp_path``.
"""
from __future__ import annotations

import importlib.util
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
GATE_SCRIPT = REPO_ROOT / "scripts" / "state_db_drift_gate.py"


def _gate():
    spec = importlib.util.spec_from_file_location("_b834_gate", GATE_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_GATE = _gate()


@pytest.mark.parametrize("collist, expected", [
    # the reported defect
    ("LENGTH(value_json)", {"value_json"}),
    ("length(value_json)", {"value_json"}),
    # functions the noise set never listed, in every position
    ("TRIM(a), UPPER(b), ABS(c)", {"a", "b", "c"}),
    ("LENGTH(TRIM(value_json))", {"value_json"}),
    ("IFNULL(a, b)", {"a", "b"}),
    ("LENGTH (value_json)", {"value_json"}),                   # whitespace before the paren
    # the functions the old set already knew still work
    ("COUNT(*)", set()),
    ("MIN(occurred_at), MAX(occurred_at)", {"occurred_at"}),
    ("COALESCE(a, b)", {"a", "b"}),
    # a string literal is data, not schema
    ("json_extract(payload_json, '$.mode')", {"payload_json"}),
    ("json_extract(payload_json, '$.it''s')", {"payload_json"}),
    ("a, 'literal words here', b", {"a", "b"}),
    # an alias / CAST target type is not a column
    ("COUNT(*) AS n", set()),
    ("a AS renamed, b", {"a", "b"}),
    ("CAST(a AS INTEGER)", {"a"}),
    # plain lists are untouched
    ("id, name, created_at", {"id", "name", "created_at"}),
    ("DISTINCT id", {"id"}),
    ("CASE WHEN a IS NULL THEN b ELSE c END", {"a", "b", "c"}),
])
def test_column_idents_reads_columns_and_only_columns(collist, expected):
    assert _GATE._column_idents(collist) == expected


def test_a_real_column_called_length_is_still_read():
    """The reason `length` was NOT added to the noise set: that would make a genuine column
    of that name invisible, so the gate could never notice it going missing."""
    assert _GATE._column_idents("length") == {"length"}
    assert _GATE._column_idents("length, LENGTH(other)") == {"length", "other"}


def _write_package(root: Path, sql: str) -> Path:
    pkg = root / "pkg"
    pkg.mkdir()
    (pkg / "reader.py").write_text(
        "def _collect_thing(conn):\n"
        f"    return conn.execute({sql!r}).fetchall()\n",
        encoding="utf-8",
    )
    return pkg


def _write_db(root: Path, table: str, columns: str) -> Path:
    """A throwaway SQLite file holding ONE stand-in table.

    The DDL is assembled from parts on purpose. These tables mirror nothing the vendor
    ships -- they are stand-ins that let the gate's parser be driven end to end -- and
    `tests/test_state_schema_grounding.py` registers every hand-written copy of a vendor
    state table by its `file:line`. A fixed `CREATE TABLE` literal here would be a
    registration (and a stale key on the next edit above it) for a claim this file never
    makes; that guard skips f-string-built DDL for exactly this reason.
    """
    db = root / "state.sqlite"
    conn = sqlite3.connect(db)
    try:
        conn.execute(f"CREATE TABLE {table} ({columns})")
        conn.commit()
    finally:
        conn.close()
    return db


def _run_gate(pkg: Path, db: Path):
    return subprocess.run(
        [sys.executable, str(GATE_SCRIPT), "--package", str(pkg), "--db", str(db)],
        capture_output=True, text=True, timeout=120,
    )


def test_expected_reads_no_longer_reports_the_function_name_as_a_column(tmp_path):
    pkg = _write_package(tmp_path, "SELECT LENGTH(value_json) FROM thing_state")
    reads = _GATE.expected_reads(pkg)
    assert len(reads) == 1
    [statement] = next(iter(reads.values()))
    assert statement["table"] == "thing_state"
    assert statement["columns"] == {"value_json"}


def test_a_healthy_database_is_not_blind_to_a_reader_that_uses_a_function(tmp_path):
    """End to end -- the exact regression: gate exit 1 with 'is missing LENGTH'."""
    pkg = _write_package(tmp_path, "SELECT LENGTH(value_json) FROM thing_state")
    db = _write_db(tmp_path, "thing_state", "key TEXT, value_json TEXT")
    result = _run_gate(pkg, db)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "BLIND" not in result.stdout
    assert "missing LENGTH" not in result.stdout


def test_positive_control_a_genuinely_missing_column_is_still_blind(tmp_path):
    """The gate must still SEE drift: the same reader against a table that really lacks
    the column it reads. A fix that merely silenced the output would pass the test above."""
    pkg = _write_package(tmp_path, "SELECT LENGTH(value_json) FROM thing_state")
    db = _write_db(tmp_path, "thing_state", "key TEXT, other_json TEXT")
    result = _run_gate(pkg, db)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "BLIND" in result.stdout
    assert "thing_state is missing value_json" in result.stdout


def test_positive_control_a_real_length_column_going_missing_is_still_blind(tmp_path):
    pkg = _write_package(tmp_path, "SELECT length FROM widgets")
    db = _write_db(tmp_path, "widgets", "id INTEGER")
    result = _run_gate(pkg, db)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "widgets is missing length" in result.stdout


def test_positive_control_a_missing_table_is_still_blind(tmp_path):
    pkg = _write_package(tmp_path, "SELECT LENGTH(value_json) FROM gone_table")
    db = _write_db(tmp_path, "elsewhere", "x TEXT")
    result = _run_gate(pkg, db)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "table 'gone_table' does not exist" in result.stdout


def test_the_shipped_readers_yield_no_function_name_as_a_column():
    """Over the real package: none of the names below is a column of any OpenClaw state
    table, so none may appear in what our readers claim to select."""
    forbidden = {"length", "count", "min", "max", "trim", "coalesce", "json_extract", "abs"}
    reads = _GATE.expected_reads(REPO_ROOT / "clawseccheck")
    assert reads, "extractor found no state-DB SELECT at all"
    seen = {c.lower() for stmts in reads.values() for s in stmts for c in s["columns"]}
    assert not (seen & forbidden), sorted(seen & forbidden)


# ---- findings of the independent review of this change, pinned ---------------------------

def test_a_star_inside_count_no_longer_discards_the_other_columns(tmp_path):
    """The one REALISTIC finding, and older than the change: `"*" not in collist` skipped the
    parser for the whole list, so `SELECT COUNT(*), MIN(occurred_at), MAX(occurred_at) FROM
    audit_events` -- a real reader -- was read as naming NO column."""
    pkg = _write_package(
        tmp_path, "SELECT COUNT(*), MIN(occurred_at), MAX(occurred_at) FROM thing_state")
    [statement] = next(iter(_GATE.expected_reads(pkg).values()))
    assert statement["columns"] == {"occurred_at"}
    assert statement["reads_all"] is False


def test_positive_control_a_renamed_column_under_count_star_is_blind(tmp_path):
    """End to end: with the column present the gate is OK, with it renamed it must say BLIND
    (before the fix it printed OK for both)."""
    pkg = _write_package(
        tmp_path, "SELECT COUNT(*), MIN(occurred_at), MAX(occurred_at) FROM thing_state")
    ok = _run_gate(pkg, _write_db(tmp_path, "thing_state", "id INTEGER, occurred_at INTEGER"))
    assert ok.returncode == 0, ok.stdout + ok.stderr
    (tmp_path / "state.sqlite").unlink()
    bad = _run_gate(pkg, _write_db(tmp_path, "thing_state", "id INTEGER, occurred_at_renamed INTEGER"))
    assert bad.returncode == 1, bad.stdout + bad.stderr
    assert "thing_state is missing occurred_at" in bad.stdout


def test_only_a_bare_select_all_reads_every_column(tmp_path):
    pkg = _write_package(tmp_path, "SELECT * FROM thing_state")
    [statement] = next(iter(_GATE.expected_reads(pkg).values()))
    assert statement["reads_all"] is True and statement["columns"] == set()
    pkg2 = tmp_path / "pkg2"
    pkg2.mkdir()
    (pkg2 / "reader.py").write_text(
        "def _r(c):\n    return c.execute('SELECT COUNT(*) FROM thing_state').fetchall()\n",
        encoding="utf-8")
    [statement] = next(iter(_GATE.expected_reads(pkg2).values()))
    assert statement["reads_all"] is False and statement["columns"] == set()


@pytest.mark.parametrize("collist, expected", [
    # a string alias must consume the AS flag, or the NEXT column is swallowed as an alias
    ("LENGTH(a) AS 'n', name", {"a", "name"}),
    ("a AS 'x', b AS 'y', c", {"a", "b", "c"}),
    # real columns that share a name with a function the gate used to whitelist by name
    ("count, total", {"count", "total"}),
    ("min, max, sum", {"min", "max", "sum"}),
    ("coalesce, cast", {"coalesce", "cast"}),
    ("COUNT(*) AS count", set()),
    ("MAX(total), total", {"total"}),
])
def test_string_aliases_and_function_named_columns(collist, expected):
    assert _GATE._column_idents(collist) == expected
