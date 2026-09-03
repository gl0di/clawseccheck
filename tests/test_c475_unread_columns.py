"""C-475 follow-up: the state-DB gate must emit bucket C at the column level.

The gate shipped with steps 1-2 of its own spec -- "table absent" and "column
absent" -- and silently dropped step 3, the reverse difference. An independent
review caught it, and the shape is worth naming: a gate built to expose "a green
oracle is evidence only about the surface that oracle reads" was itself green
about the surface it modelled and mute about the one it did not.

The database under test is built FROM `expected_reads()` rather than from a
hand-written CREATE TABLE. That is the same rule the gate's own docstring gives
for why it parses source instead of carrying a table list: a second hand-written
copy of a schema rots, and `tests/test_b296_subagent_runs_disclosure.py` proved
it by drifting under a comment promising it could not.
"""

from __future__ import annotations

import importlib.util
import sqlite3
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DRIFT_GATE_SCRIPT = REPO_ROOT / "scripts" / "state_db_drift_gate.py"
PKG_ROOT = REPO_ROOT / "clawseccheck"


def _gate():
    spec = importlib.util.spec_from_file_location("_c475_gate", DRIFT_GATE_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tables_we_read():
    """table -> the union of columns our SELECTs name, straight from source."""
    gate = _gate()
    union: dict = {}
    for statements in gate.expected_reads(PKG_ROOT).values():
        for stmt in statements:
            union.setdefault(stmt["table"], set()).update(stmt["columns"])
    return union


# `SELECT COUNT(*) FROM x` names no columns, so the union for such a table is
# empty and sqlite cannot create a zero-column table. Give it one placeholder --
# which the gate then correctly reports as unread, because a row count really
# does read no column content.
COUNT_ONLY_PLACEHOLDER = "row_payload"


def _build_db(path: Path, extra=None):
    """A state DB that satisfies every reader, plus optional surplus columns."""
    extra = extra or {}
    conn = sqlite3.connect(path)
    try:
        for table, columns in _tables_we_read().items():
            cols = sorted(columns) or [COUNT_ONLY_PLACEHOLDER]
            cols = cols + sorted(extra.get(table, []))
            spec = ", ".join(f"{c} TEXT" for c in cols)
            conn.execute(f"CREATE TABLE {table} ({spec})")
        conn.commit()
    finally:
        conn.close()


def _run(db_path: Path):
    proc = subprocess.run(
        [sys.executable, str(DRIFT_GATE_SCRIPT), "--db", str(db_path)],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    return proc.returncode, proc.stdout + proc.stderr


def test_surplus_column_on_a_read_table_is_reported(tmp_path):
    """The step-3 case the gate used to drop entirely."""
    db = tmp_path / "state.sqlite"
    _build_db(db, extra={"cron_jobs": ["freshly_added_by_vendor"]})
    code, out = _run(db)
    assert "unread col" in out, out
    assert "freshly_added_by_vendor" in out, out
    assert "cron_jobs" in out, out


def test_surplus_column_is_advisory_not_drift(tmp_path):
    """A column we do not read has broken nothing we do read."""
    db = tmp_path / "state.sqlite"
    _build_db(db, extra={"cron_jobs": ["freshly_added_by_vendor"]})
    code, out = _run(db)
    assert code == 0, f"exit {code} -- an unread column must not redden a clean build\n{out}"
    assert "bucket C" in out, out


def test_no_surplus_column_reports_none(tmp_path):
    """Negative control: without it, the positive test proves nothing."""
    db = tmp_path / "state.sqlite"
    _build_db(db)
    code, out = _run(db)
    assert code == 0, out
    named = [t for t, c in _tables_we_read().items() if c]
    for table in named:
        assert f"unread col  {table}" not in out, f"{table} falsely reported\n{out}"


def test_a_count_only_reader_reports_its_columns_as_unread(tmp_path):
    """`SELECT COUNT(*)` reads rows, not content -- so every column is unread.

    This is the honest answer, not an artifact: `capture_events` holds host,
    path, method and body columns that no statement of ours selects.
    """
    count_only = [t for t, c in _tables_we_read().items() if not c]
    assert count_only, "expected at least one COUNT(*)-only reader"
    db = tmp_path / "state.sqlite"
    _build_db(db)
    code, out = _run(db)
    assert code == 0, out
    for table in count_only:
        assert f"unread col  {table}" in out, f"{table} not reported\n{out}"


def test_the_gate_does_not_call_the_column_new(tmp_path):
    """It holds no baseline, so 'new' would be a claim it cannot support.

    Golden Rule #4: report what was measured. Present-tense coverage is
    measurable here; "the vendor added this in this upgrade" is not.
    """
    db = tmp_path / "state.sqlite"
    _build_db(db, extra={"subagent_runs": ["surplus_col"]})
    code, out = _run(db)
    reported = [ln for ln in out.splitlines() if "surplus_col" in ln]
    assert reported, out
    assert not any("new column" in ln.lower() for ln in reported), reported


def test_every_read_table_is_eligible_for_the_reverse_difference(tmp_path):
    """Not just the one table the first test happens to pick.

    A check that fires on a single hard-coded subject would pass the tests above
    while covering one ninth of its surface.
    """
    tables = sorted(_tables_we_read())
    assert len(tables) >= 5, tables
    for table in tables:
        db = tmp_path / f"state_{table}.sqlite"
        _build_db(db, extra={table: ["surplus_col"]})
        code, out = _run(db)
        assert code == 0, out
        assert f"unread col  {table}" in out, f"{table} not reported\n{out}"


# --------------------------------------------------------------------------
# `SELECT *` vs `SELECT COUNT(*)`: identical empty column sets, OPPOSITE
# meanings for the reverse difference. These two tests are the discriminator.
# Collapsing them would make the gate announce a `SELECT *` reader's entire
# table as unread -- a false claim, emitted by the one script written to catch
# false claims of exactly that shape.
# --------------------------------------------------------------------------

def _synthetic_package(tmp_path: Path, sql: str) -> Path:
    """A one-reader package, so the gate's expectations are fully controlled."""
    pkg = tmp_path / "synthpkg"
    pkg.mkdir()
    (pkg / "reader.py").write_text(
        "import sqlite3\n"
        "def _collect_synthetic(conn):\n"
        f"    return conn.execute({sql!r}).fetchall()\n"
    )
    return pkg


def _db_with(tmp_path: Path, table: str, columns) -> Path:
    db = tmp_path / f"{table}_synth.sqlite"
    conn = sqlite3.connect(db)
    try:
        conn.execute(f"CREATE TABLE {table} ({', '.join(f'{c} TEXT' for c in columns)})")
        conn.commit()
    finally:
        conn.close()
    return db


def _run_pkg(db_path: Path, pkg: Path):
    proc = subprocess.run(
        [sys.executable, str(DRIFT_GATE_SCRIPT), "--db", str(db_path), "--package", str(pkg)],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    return proc.returncode, proc.stdout + proc.stderr


def test_select_star_reader_claims_no_unread_columns(tmp_path):
    """`SELECT *` reads every column, so nothing on that table is unread."""
    pkg = _synthetic_package(tmp_path, "SELECT * FROM cron_jobs")
    db = _db_with(tmp_path, "cron_jobs", ["id", "schedule", "surprise_col"])
    code, out = _run_pkg(db, pkg)
    assert code == 0, out
    assert "unread col" not in out, (
        "a SELECT * reader reads every column; reporting any as unread is a false "
        f"claim\n{out}"
    )


def test_count_star_reader_does_claim_unread_columns(tmp_path):
    """The positive control that gives the test above its meaning.

    Same empty column set, same table, same database -- only the statement
    differs. If this pair ever agrees, the two forms have been collapsed.
    """
    pkg = _synthetic_package(tmp_path, "SELECT COUNT(*) FROM cron_jobs")
    db = _db_with(tmp_path, "cron_jobs", ["id", "schedule", "surprise_col"])
    code, out = _run_pkg(db, pkg)
    assert code == 0, out
    assert "unread col  cron_jobs" in out, out
    assert "surprise_col" in out, out
