"""B-686: a path the user named is their fact, not the host's.

    $ audit.py --analyze-trajectory ~/x/typo.jsonl
    Trajectory incident analysis (post-hoc, read-only)
      ? No trajectory sidecars found (agents/*/sessions/*.trajectory.jsonl). Nothing to
        analyze — run on a host where an OpenClaw agent has produced session trajectories.
    $ echo $?
    0

The user named a file. The tool never said which file, never said it was not there, and
advised them to go and find a different machine — for a typo — while exiting 0.

`--behavioral` takes the same kind of argument and had exactly this defect; B-462 fixed it
there and left this mode alone. The two now share one predicate, moved down into
`trajectory.py` so neither owns a question that belongs to both.

B-816 extends this file: the "Nothing to analyze" / "no trajectory sidecar was found to
corroborate it" sentences above are themselves the SAME defect one layer up — they fired
unconditionally even on a SQLite-era install where `trajectorystore.corroborate()` (F-187)
can see real evidence elsewhere. The tests below cover both the top-level
`render_trajectory_analysis` message and the `self_test_corroboration` /
`render_self_test_corroboration` branch, using the same real-DDL SQLite fixture builder
`tests/test_f187_trajectory_sqlite_corroborator.py` already proved against the vendor shape.
"""

import json
import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clawseccheck.behavioral import explicit_path_problem as _via_behavioral  # noqa: E402
from clawseccheck.cli import main  # noqa: E402
from clawseccheck.trajectory import explicit_path_problem  # noqa: E402
from clawseccheck.trajectorystore import TRAJECTORY_TABLE_NAME  # noqa: E402


def _base(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    return ["--home", str(home), "--data-dir", str(tmp_path / "data")]


def _add_agent_db(home, agent, trajectory_rows):
    """Minimal per-agent SQLite trajectory database, matching
    `trajectorystore.TRAJECTORY_TABLE_NAME` / `_SELECT_TRAJECTORY_ROWS`'s column shape
    exactly (same DDL as `test_f187_trajectory_sqlite_corroborator.py::_add_agent_db`,
    trimmed to just the trajectory table — no OAuth tables needed for these tests)."""
    agent_dir = home / "agents" / agent / "agent"
    agent_dir.mkdir(parents=True, exist_ok=True)
    db_path = agent_dir / "openclaw-agent.sqlite"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            f"CREATE TABLE {TRAJECTORY_TABLE_NAME} (session_id TEXT NOT NULL, "
            "seq INTEGER NOT NULL, run_id TEXT, event_json TEXT NOT NULL, "
            "created_at INTEGER NOT NULL, PRIMARY KEY (session_id, seq))"
        )
        for session_id, seq in trajectory_rows:
            conn.execute(
                f"INSERT INTO {TRAJECTORY_TABLE_NAME} VALUES (?,?,?,?,?)",
                (session_id, seq, "run-1", json.dumps({"type": "tool.call"}), 0),
            )
        conn.commit()
    finally:
        conn.close()
    return db_path


def test_the_two_modes_share_one_predicate():
    """Pinned because two copies wording the same three cases is how they drift.

    `behavioral` re-exports the moved name, so every existing importer — cli.py and
    tests/test_b462_b464_optout_honesty.py among them — still resolves.
    """
    assert _via_behavioral is explicit_path_problem


def test_absent_path_is_named_and_the_host_is_not_blamed(tmp_path, capsys):
    ghost = tmp_path / "typo.jsonl"
    rc = main(["--analyze-trajectory", str(ghost), *_base(tmp_path)])
    out = capsys.readouterr().out
    assert str(ghost) in out
    assert "no such file or directory" in out
    assert "run on a host where" not in out
    assert rc == 1


def test_a_directory_says_so(tmp_path, capsys):
    d = tmp_path / "adir"
    d.mkdir()
    rc = main(["--analyze-trajectory", str(d), *_base(tmp_path)])
    out = capsys.readouterr().out
    assert "is a directory, not a trajectory file" in out
    assert rc == 1


@pytest.mark.skipif(os.geteuid() == 0, reason="root can stat through mode 000")
def test_an_unreadable_path_says_so(tmp_path, capsys):
    locked = tmp_path / "locked"
    (locked / "inner").mkdir(parents=True)
    locked.chmod(0o000)
    try:
        rc = main(["--analyze-trajectory", str(locked / "inner"), *_base(tmp_path)])
        out = capsys.readouterr().out
    finally:
        locked.chmod(0o755)
    assert "permission denied" in out
    assert "run on a host where" not in out
    assert rc == 1


def test_the_silence_is_qualified_in_every_case(tmp_path, capsys):
    """"Nothing was analyzed" must never read as "there was nothing to find"."""
    main(["--analyze-trajectory", str(tmp_path / "typo.jsonl"), *_base(tmp_path)])
    out = capsys.readouterr().out
    assert "not evidence that the file is empty" in out


def test_no_explicit_path_is_unchanged(tmp_path, capsys):
    """The control, and the reason the predicate is asked rather than the result inspected.

    With no path named, "run on a host where an OpenClaw agent has produced session
    trajectories" is the CORRECT message and rc=0 is the correct code. A fix that reported
    a path problem unconditionally passes every test above and fails this one.
    """
    rc = main(["--analyze-trajectory", "", *_base(tmp_path)])
    out = capsys.readouterr().out
    assert "No trajectory sidecars found" in out
    assert "run on a host where" in out
    assert rc == 0


def test_behavioral_is_unchanged(tmp_path, capsys):
    """The mode the predicate came from must answer exactly as it did before."""
    ghost = tmp_path / "typo.jsonl"
    rc = main(["--behavioral", str(ghost), *_base(tmp_path)])
    out = capsys.readouterr().out
    assert "no such file or directory" in out
    assert rc == 1


# ---------------------------------------------------------------------------
# B-816 — the "Nothing to analyze" / "no trajectory sidecar was found to
# corroborate it" sentences, one layer up: they must not fire unconditionally on a
# SQLite-era install where `trajectorystore.corroborate()` (F-187) has real evidence.
# ---------------------------------------------------------------------------


def test_sqlite_only_home_names_the_evidence_instead_of_nothing_to_analyze(tmp_path, capsys):
    """No JSONL sidecar, but real SQLite trajectory rows -> the stale-locator wording,
    not the generic "run on a host where..." sentence (reproduces the bug report exactly:
    a SQLite-only fixture with real events, --analyze-trajectory, exit 0)."""
    args = _base(tmp_path)
    home = tmp_path / "home"
    _add_agent_db(home, "main", [("s1", 0), ("s1", 1), ("s2", 0)])

    rc = main(["--analyze-trajectory", "", *args])
    out = capsys.readouterr().out

    assert "trajectory history exists elsewhere" in out
    assert "SQLite trajectory row(s)" in out
    assert "locator is stale" in out
    assert "Nothing to analyze — run on a host where" not in out
    assert rc == 0


def test_sqlite_only_home_explicit_path_problem_guard_is_untouched(tmp_path, capsys):
    """The B-686 explicit_path_problem branch fires FIRST and is about the user's own
    path — real SQLite evidence sitting elsewhere on the host must not change it or
    leak into it."""
    args = _base(tmp_path)
    home = tmp_path / "home"
    _add_agent_db(home, "main", [("s1", 0)])
    ghost = tmp_path / "typo.jsonl"

    rc = main(["--analyze-trajectory", str(ghost), *args])
    out = capsys.readouterr().out

    assert str(ghost) in out
    assert "no such file or directory" in out
    assert "not evidence that the file is empty" in out
    assert "run on a host where" not in out
    assert "trajectory history exists elsewhere" not in out
    assert rc == 1


def test_genuinely_empty_home_is_byte_identical_to_today(tmp_path, capsys):
    """No JSONL, no SQLite, no pointer/archive residue anywhere -> the original
    "Nothing to analyze" sentence, unchanged. The control for the two tests above."""
    rc = main(["--analyze-trajectory", "", *_base(tmp_path)])
    out = capsys.readouterr().out

    assert "No trajectory sidecars found" in out
    assert "Nothing to analyze — run on a host where" in out
    assert "trajectory history exists elsewhere" not in out
    assert "locator is stale" not in out
    assert rc == 0


def test_self_test_corroboration_names_sqlite_evidence(tmp_path, capsys):
    """A --canary/--multiturn ledger entry + a SQLite-only home (no JSONL) ->
    `render_self_test_corroboration` names the SQLite evidence instead of the bare
    "no trajectory sidecar was found to corroborate it" sentence.

    Built as a real CLI run: a minimal ledger fixture is written directly to
    `<data-dir>/coverage.json` (the shape `ledger.load_ledger`/`record_run` read and
    write — a plain ``{"self_test": "<iso-date>"}`` map), which reaches
    `self_test_corroboration` through the exact same `--data-dir`-derived
    `ledger_path` the CLI itself wires (`cli._coverage_path`). This turned out not to
    need the "standalone function" fallback the task allowed for.
    """
    args = _base(tmp_path)
    home = tmp_path / "home"
    _add_agent_db(home, "main", [("s1", 0)])
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "coverage.json").write_text(
        json.dumps({"self_test": "2026-09-01"}), encoding="utf-8")

    rc = main(["--analyze-trajectory", "", *args])
    out = capsys.readouterr().out

    assert "Self-test corroboration" in out
    assert "local ledger shows a self-test capability was run, but no" in out
    assert "trajectory history exists elsewhere" in out
    assert "SQLite trajectory row(s)" in out
    assert "corroboration remains UNKNOWN, not an all-clear" in out
    # The plain "no trajectory sidecar was found to corroborate it" sentence must not
    # also appear — it is REPLACED, not appended alongside, by the evidence-naming one.
    assert "no trajectory sidecar was found to corroborate it" not in out
    assert rc == 0


def test_self_test_corroboration_no_residue_is_unchanged(tmp_path, capsys):
    """Same ledger entry, but a genuinely empty home (no JSONL, no SQLite residue at
    all) -> the original UNKNOWN sentence, unchanged. The control for the test above."""
    args = _base(tmp_path)
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "coverage.json").write_text(
        json.dumps({"self_test": "2026-09-01"}), encoding="utf-8")

    rc = main(["--analyze-trajectory", "", *args])
    out = capsys.readouterr().out

    assert "Self-test corroboration" in out
    assert "no trajectory sidecar was found to corroborate it — UNKNOWN, not an " \
           "all-clear." in out
    assert "trajectory history exists elsewhere" not in out
    assert rc == 0
