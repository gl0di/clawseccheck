"""C-668: the state-DB drift gate must not judge a per-agent reader against the state DB.

`scripts/state_db_drift_gate.py` is step 0b of the OpenClaw upgrade protocol ("exit 1 = drift").
Its scan collects every `.execute()` SELECT in the package, and it is not file-scoped, so
`collector.py:_collect_agent_auth_profile_store_presence` -- which reads the per-agent database
`agents/<id>/agent/openclaw-agent.sqlite`, not `state/openclaw.sqlite` -- was reported BLIND
("table 'auth_profile_store' does not exist") on a healthy build. A gate that is red on a clean
build is a gate people learn to ignore.

The fix declares the per-agent readers (by file:function, never by table name) and compares them
with a per-agent database instead. The directions are pinned separately, because either alone
would pass a sloppy "fix": silencing the declared reader without ever looking at its own
database, or exempting by table name so an undeclared reader of a missing table also goes quiet.

Offline: throwaway package and SQLite files under ``tmp_path``; ``OPENCLAW_HOME`` is pointed
at an empty directory so the real ``~/.openclaw`` is never consulted.
"""
from __future__ import annotations

import importlib.util
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
GATE_SCRIPT = REPO_ROOT / "scripts" / "state_db_drift_gate.py"

DECLARED_FILE = "collector.py"
DECLARED_FUNC = "_collect_agent_auth_profile_store_presence"
SELECT_SQL = "SELECT LENGTH(store_json) FROM auth_profile_store WHERE store_key = ?"


def _gate():
    spec = importlib.util.spec_from_file_location("_c668_gate", GATE_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_GATE = _gate()


def _write_package(root: Path, filename: str, func: str) -> Path:
    pkg = root / "pkg"
    pkg.mkdir()
    (pkg / filename).write_text(
        f"def {func}(conn):\n"
        f"    return conn.execute({SELECT_SQL!r}).fetchall()\n",
        encoding="utf-8",
    )
    return pkg


def _write_db(path: Path, table: str, columns: str) -> Path:
    # DDL assembled from parts: a stand-in table, not a copy of a vendor schema (see the
    # same note in tests/test_b834_drift_gate_columns.py).
    conn = sqlite3.connect(path)
    try:
        conn.execute(f"CREATE TABLE {table} ({columns})")
        conn.commit()
    finally:
        conn.close()
    return path


def _run_gate(tmp_path: Path, pkg: Path, state_db: Path, *extra: str):
    empty_home = tmp_path / "empty_home"
    empty_home.mkdir(exist_ok=True)
    env = dict(os.environ, OPENCLAW_HOME=str(empty_home))
    return subprocess.run(
        [sys.executable, str(GATE_SCRIPT), "--package", str(pkg), "--db", str(state_db), *extra],
        capture_output=True, text=True, timeout=120, env=env,
    )


def test_a_declared_per_agent_reader_is_not_blind_when_the_state_db_lacks_its_table(tmp_path):
    """The reported defect, end to end: exit 0, the reader named on its own line."""
    pkg = _write_package(tmp_path, DECLARED_FILE, DECLARED_FUNC)
    state = _write_db(tmp_path / "state.sqlite", "elsewhere", "x TEXT")
    result = _run_gate(tmp_path, pkg, state)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "BLIND" not in result.stdout
    assert f"{DECLARED_FILE}:{DECLARED_FUNC}" in result.stdout
    assert "per-agent database reader, not checked by this gate" in result.stdout


def test_a_declared_per_agent_reader_is_judged_against_the_per_agent_db_when_given(tmp_path):
    """Not a silencer: the same reader IS reported when the per-agent database lacks its table
    or a column it selects, and is checked (not merely skipped) when it has both."""
    pkg = _write_package(tmp_path, DECLARED_FILE, DECLARED_FUNC)
    state = _write_db(tmp_path / "state.sqlite", "elsewhere", "x TEXT")

    lacking = _write_db(tmp_path / "agent_lacking.sqlite", "other_table", "y TEXT")
    bad = _run_gate(tmp_path, pkg, state, "--agent-db", str(lacking))
    assert bad.returncode == 1, bad.stdout + bad.stderr
    assert "BLIND" in bad.stdout and DECLARED_FUNC in bad.stdout
    assert "table 'auth_profile_store' does not exist" in bad.stdout

    renamed = _write_db(tmp_path / "agent_renamed.sqlite", "auth_profile_store",
                        "store_key TEXT, store_json_renamed TEXT")
    bad_col = _run_gate(tmp_path, pkg, state, "--agent-db", str(renamed))
    assert bad_col.returncode == 1, bad_col.stdout + bad_col.stderr
    assert "auth_profile_store is missing store_json" in bad_col.stdout

    healthy = _write_db(tmp_path / "agent_ok.sqlite", "auth_profile_store",
                        "store_key TEXT, store_json TEXT")
    ok = _run_gate(tmp_path, pkg, state, "--agent-db", str(healthy))
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert "checked against agent_ok.sqlite" in ok.stdout
    assert "not checked by this gate" not in ok.stdout


@pytest.mark.parametrize("filename, func", [
    # the same TABLE as the declared reader, read by a reader nobody declared
    ("reader.py", "_collect_thing"),
    # the declared function NAME, but in a file the declaration does not name
    ("other.py", DECLARED_FUNC),
])
def test_an_undeclared_reader_of_a_missing_table_is_still_blind(tmp_path, filename, func):
    """The guard must still bite: the exemption is the declared file:function, not the table."""
    pkg = _write_package(tmp_path, filename, func)
    state = _write_db(tmp_path / "state.sqlite", "elsewhere", "x TEXT")
    result = _run_gate(tmp_path, pkg, state)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "BLIND" in result.stdout
    assert "table 'auth_profile_store' does not exist" in result.stdout


def test_a_missing_explicit_agent_db_is_could_not_compare_not_a_pass(tmp_path):
    pkg = _write_package(tmp_path, DECLARED_FILE, DECLARED_FUNC)
    state = _write_db(tmp_path / "state.sqlite", "elsewhere", "x TEXT")
    result = _run_gate(tmp_path, pkg, state, "--agent-db", str(tmp_path / "nope.sqlite"))
    assert result.returncode == 2, result.stdout + result.stderr
    assert "no per-agent database" in result.stderr


def test_every_declared_per_agent_reader_exists_in_the_shipped_package():
    """A declaration naming a function that was renamed away would exempt nothing and rot
    silently; the renamed reader would then be BLIND again, so keep the two in step."""
    reads = _GATE.expected_reads(REPO_ROOT / "clawseccheck")
    assert _GATE.PER_AGENT_DB_READERS, "no per-agent reader declared"
    assert _GATE.PER_AGENT_DB_READERS <= set(reads), sorted(
        _GATE.PER_AGENT_DB_READERS - set(reads))
