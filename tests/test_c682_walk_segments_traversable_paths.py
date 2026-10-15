"""C-682: trajectory-store path expansion gives the same answer on every Python.

``Path.glob('agents/*/sessions/*.trajectory.jsonl')`` over a directory that is searchable but
not listable (a home at mode 111, ``agents/<id>`` at mode 311) finds the sidecar on 3.14 and
misses it on 3.12; over ``agents/<id>/agent`` at mode 444 it reports the SQLite store on 3.12
and nothing on 3.14. ``pathprobe.walk_segments`` expands the same patterns with ``os.lstat`` /
``os.scandir`` only: a file is FOUND whenever the path to it is traversable (execute
permission), listing is needed only for a ``*`` segment, and a directory that must be listed
but cannot be is a disclosed gap (``OSError`` / the ``errors`` list), never a silent absence.

Every permission test skips under root and restores each mode in a ``finally``.
"""
from __future__ import annotations

import contextlib
import os
from pathlib import Path

import pytest

from clawseccheck import pathprobe, trajectory, trajectorystore

pytestmark = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="permission cases need a non-root user")

_JSONL = "agents/*/sessions/*.trajectory.jsonl"
_SQLITE = "agents/*/agent/openclaw-agent.sqlite"


@contextlib.contextmanager
def _mode(path: Path, mode: int):
    old = os.stat(path).st_mode & 0o7777
    os.chmod(path, mode)
    try:
        yield
    finally:
        os.chmod(path, old)


def _touch(p: Path, text: str = "x") -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _rel(home: Path, found) -> list:
    return sorted(str(Path(p).relative_to(home)) for p in found)


def _walk(home: Path, pattern: str, **kw) -> list:
    return list(pathprobe.walk_segments(home, pattern.split("/"), **kw))


# --- the helper itself ------------------------------------------------------------------

def test_clean_home_finds_the_sidecar(tmp_path):
    f = _touch(tmp_path / "agents/main/sessions/s1.trajectory.jsonl")
    assert _rel(tmp_path, _walk(tmp_path, _JSONL)) == [str(f.relative_to(tmp_path))]


def test_absent_things_are_silent(tmp_path):
    assert _walk(tmp_path / "no-such-home", _JSONL) == []
    assert _walk(tmp_path, _JSONL) == []
    (tmp_path / "agents/main").mkdir(parents=True)
    assert _walk(tmp_path, _JSONL) == []
    _touch(tmp_path / "agents/plain-file")  # a file where an agent directory should be
    assert _walk(tmp_path, _JSONL) == []


def test_home_at_mode_111_still_finds_the_sidecar(tmp_path):
    f = _touch(tmp_path / "agents/main/sessions/s1.trajectory.jsonl")
    with _mode(tmp_path, 0o111):
        assert _rel(tmp_path, _walk(tmp_path, _JSONL)) == [str(f.relative_to(tmp_path))]


def test_agent_dir_at_mode_311_still_finds_the_sidecar(tmp_path):
    f = _touch(tmp_path / "agents/main/sessions/s1.trajectory.jsonl")
    with _mode(tmp_path / "agents/main", 0o311):
        assert _rel(tmp_path, _walk(tmp_path, _JSONL)) == [str(f.relative_to(tmp_path))]


def test_a_star_directory_that_cannot_be_listed_raises(tmp_path):
    """Control: ``agents`` at mode 311 holds a ``*`` segment, which needs a listing."""
    _touch(tmp_path / "agents/main/sessions/s1.trajectory.jsonl")
    with _mode(tmp_path / "agents", 0o311):
        with pytest.raises(PermissionError):
            _walk(tmp_path, _JSONL)
        errors: list = []
        assert _walk(tmp_path, _JSONL, errors=errors) == []
        assert len(errors) == 1 and isinstance(errors[0], OSError)


def test_one_unlistable_agent_does_not_hide_the_others(tmp_path):
    good = _touch(tmp_path / "agents/a/sessions/s1.trajectory.jsonl")
    _touch(tmp_path / "agents/b/sessions/s2.trajectory.jsonl")
    with _mode(tmp_path / "agents/b/sessions", 0o311):
        errors: list = []
        found = _walk(tmp_path, _JSONL, errors=errors)
        assert _rel(tmp_path, found) == [str(good.relative_to(tmp_path))]
        assert len(errors) == 1


def test_unreadable_agent_dir_reports_the_sqlite_candidate(tmp_path):
    """``agent`` at mode 444: the store cannot be proven absent, so it is reported and the
    consumer's open fails loudly (this is what 3.12 did; 3.14 returned nothing)."""
    db = _touch(tmp_path / "agents/main/agent/openclaw-agent.sqlite")
    with _mode(tmp_path / "agents/main/agent", 0o444):
        assert _rel(tmp_path, _walk(tmp_path, _SQLITE)) == [str(db.relative_to(tmp_path))]


def test_absent_sqlite_in_a_readable_dir_is_silent(tmp_path):
    (tmp_path / "agents/main/agent").mkdir(parents=True)
    assert _walk(tmp_path, _SQLITE) == []


def test_dangling_symlink_and_dotted_names_match_pathlib(tmp_path):
    (tmp_path / "agents/main/agent").mkdir(parents=True)
    os.symlink("nowhere", tmp_path / "agents/main/agent/openclaw-agent.sqlite")
    _touch(tmp_path / "agents/.hidden/sessions/.dot.trajectory.jsonl")
    assert len(_walk(tmp_path, _SQLITE)) == 1
    assert len(_walk(tmp_path, _JSONL)) == 1


def test_symlink_loop_directory_is_absent_not_a_crash(tmp_path):
    (tmp_path / "agents").mkdir()
    os.symlink("loop", tmp_path / "agents/loop")
    assert _walk(tmp_path, _JSONL) == []
    assert _walk(tmp_path, _SQLITE) == []


# --- the consumers -----------------------------------------------------------------------

def test_find_trajectory_files_under_mode_111_and_311(tmp_path):
    f = _touch(tmp_path / "agents/main/sessions/s1.trajectory.jsonl")
    with _mode(tmp_path, 0o111):
        stats: dict = {}
        assert trajectory.find_trajectory_files(tmp_path, stats=stats) == [f]
        assert stats["files_total"] == 1 and stats["unlistable_dirs"] == 0
    with _mode(tmp_path / "agents/main", 0o311):
        assert trajectory.find_trajectory_files(tmp_path) == [f]


def test_find_trajectory_files_discloses_an_unlistable_agents_dir(tmp_path):
    _touch(tmp_path / "agents/main/sessions/s1.trajectory.jsonl")
    with _mode(tmp_path / "agents", 0o311):
        stats: dict = {}
        assert trajectory.find_trajectory_files(tmp_path, stats=stats) == []
        assert stats["unlistable_dirs"] >= 1


def test_find_trajectory_files_clean_twin_counts_no_gap(tmp_path):
    _touch(tmp_path / "agents/main/sessions/s1.trajectory.jsonl")
    stats: dict = {}
    assert len(trajectory.find_trajectory_files(tmp_path, stats=stats)) == 1
    assert stats["unlistable_dirs"] == 0


def test_pointer_files_found_under_mode_311_and_gap_is_a_lower_bound(tmp_path):
    ptr = tmp_path / "agents/main/sessions/s1.trajectory-path.json"
    _touch(ptr, "{}")
    assert trajectorystore._pointer_files(tmp_path) == (1, 0, False)
    with _mode(tmp_path / "agents/main", 0o311):
        assert trajectorystore._pointer_files(tmp_path) == (1, 0, False)
    with _mode(tmp_path / "agents", 0o311):
        assert trajectorystore._pointer_files(tmp_path) == (0, 0, True)


def test_archive_entries_found_under_mode_311_and_gap_is_a_lower_bound(tmp_path):
    _touch(tmp_path / "agents/main/session-sqlite-import-archive/a.imported-1")
    _touch(tmp_path / "agents/main/session-sqlite-import-archive/b")
    assert trajectorystore._archive_entries(tmp_path) == (1, False)
    with _mode(tmp_path / "agents/main", 0o311):
        assert trajectorystore._archive_entries(tmp_path) == (1, False)
    with _mode(tmp_path / "agents", 0o311):
        assert trajectorystore._archive_entries(tmp_path) == (0, True)


def test_sqlite_dbs_under_mode_311_and_unreadable_agent_dir(tmp_path):
    db = _touch(tmp_path / "agents/main/agent/openclaw-agent.sqlite")
    assert trajectorystore._sqlite_dbs(tmp_path) == [db]
    with _mode(tmp_path / "agents/main", 0o311):
        assert trajectorystore._sqlite_dbs(tmp_path) == [db]
    with _mode(tmp_path / "agents/main/agent", 0o444):
        assert trajectorystore._sqlite_dbs(tmp_path) == [db]
        assert trajectorystore.sqlite_db_paths(tmp_path) == [db]
        assert trajectorystore.sqlite_db_paths_capped(tmp_path) is False
    with _mode(tmp_path / "agents", 0o311):
        stats: dict = {}
        assert trajectorystore._sqlite_dbs(tmp_path, stats=stats) == []
        assert stats["dbs_unlistable"] >= 1


def test_sqlite_dbs_clean_twin_counts_no_gap(tmp_path):
    _touch(tmp_path / "agents/main/agent/openclaw-agent.sqlite")
    stats: dict = {}
    assert len(trajectorystore._sqlite_dbs(tmp_path, stats=stats)) == 1
    assert stats["dbs_unlistable"] == 0


# --- a literal last segment is only found if it exists (C-135 round 1) ----------------------

@pytest.mark.parametrize("mode", [0o000, 0o444])
def test_phantom_sqlite_is_not_reported_when_no_store_exists(tmp_path, mode):
    """No sqlite file anywhere: an unsearchable `agent` directory must not invent one."""
    (tmp_path / "agents/main/agent").mkdir(parents=True)
    with _mode(tmp_path / "agents/main/agent", mode):
        stats: dict = {}
        assert trajectorystore._sqlite_dbs(tmp_path, stats=stats) == []
        assert trajectorystore.sqlite_db_paths(tmp_path) == []
        assert stats["dbs_total"] == 0
        # a listable parent answers (the name is not there); an unlistable one is a gap
        assert stats["dbs_unlistable"] == (1 if mode == 0o000 else 0)


def test_unsearchable_unlistable_parent_is_a_gap_not_a_found_path(tmp_path):
    (tmp_path / "agents/main/agent").mkdir(parents=True)
    with _mode(tmp_path / "agents/main/agent", 0o000):
        with pytest.raises(PermissionError):
            _walk(tmp_path, _SQLITE)
        errors: list = []
        assert _walk(tmp_path, _SQLITE, errors=errors) == []
        assert len(errors) == 1


@pytest.mark.parametrize("mode", [0o000, 0o444])
def test_phantom_homes_add_no_collector_error_and_no_b185_sentence(tmp_path, mode):
    from clawseccheck.collector import collect

    (tmp_path / "agents/main/agent").mkdir(parents=True)
    with _mode(tmp_path / "agents/main/agent", mode):
        ctx = collect(tmp_path)
    assert not [e for e in ctx.errors if "auth-profile store presence" in e]


def test_b85_unknown_says_how_many_directories_could_not_be_listed(tmp_path):
    from clawseccheck.checks import check_incident_readiness
    from clawseccheck.collector import collect

    _touch(tmp_path / "agents/main/sessions/s1.trajectory.jsonl")
    clean = check_incident_readiness(collect(tmp_path))
    with _mode(tmp_path / "agents", 0o311):
        gap = check_incident_readiness(collect(tmp_path))
    assert gap.status == "UNKNOWN"
    assert "could not be listed" in gap.fix
    assert "could not be listed" not in gap.detail
    assert "could not be listed" not in clean.fix
    # the unchanged detail: the same text a plain "no evidence" home gets
    plain = check_incident_readiness(collect(tmp_path / "nope"))
    assert gap.detail == plain.detail
