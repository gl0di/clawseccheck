"""B85 incident-readiness (C-093 / E-014 S3) — the trajectory sidecar as a tamper-resistant,
attributable tool-use record.

Filesystem-grounded (recon §9.1): B85 stat()s the trajectory sidecar files and their
sessions/ dir — it NEVER reads their contents (§8). HIGH confidence (fs facts). Offline,
writes only under tmp_path.

B-810: also covers the SQLite-store branch -- when the classic JSONL locator is empty
but trajectorystore.corroborate() finds real evidence in the per-agent SQLite database
(agents/<agent>/agent/openclaw-agent.sqlite, trajectory_runtime_events), B85 must
answer the same presence/tamper questions against that container instead of claiming
"no on-disk record" over a false negative.
"""
import json
import os
import sqlite3
from pathlib import Path

import pytest

from clawseccheck import checks
from clawseccheck.checks import check_incident_readiness
from clawseccheck.collector import Context
from clawseccheck.trajectory import find_trajectory_files
from clawseccheck.trajectorystore import TRAJECTORY_TABLE_NAME

_LINE = json.dumps({
    "traceSchema": "openclaw-trajectory", "schemaVersion": 1,
    "type": "tool.call", "data": {"name": "bash"},
}) + "\n"


def _traj(home: Path, *, agent="main", session="s", file_mode=0o600, dir_mode=0o700) -> Path:
    """Write one trajectory sidecar under home/agents/<agent>/sessions/ and pin perms."""
    d = home / "agents" / agent / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    f = d / f"{session}.trajectory.jsonl"
    f.write_text(_LINE, encoding="utf-8")
    os.chmod(f, file_mode)
    os.chmod(d, dir_mode)
    return f


def _ctx(home: Path) -> Context:
    return Context(home=home, config={})


def _sqlite_db(home: Path, *, agent="main", rows=(("s1", 0),), file_mode=0o600,
                dir_mode=0o700) -> Path:
    """Write one per-agent SQLite trajectory database under
    home/agents/<agent>/agent/openclaw-agent.sqlite and pin perms -- same column shape
    trajectorystore._read_sqlite_db()/_SELECT_TRAJECTORY_ROWS expects (session_id TEXT,
    seq INTEGER at minimum)."""
    d = home / "agents" / agent / "agent"
    d.mkdir(parents=True, exist_ok=True)
    db_path = d / "openclaw-agent.sqlite"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            f"CREATE TABLE {TRAJECTORY_TABLE_NAME} (session_id TEXT NOT NULL, "
            "seq INTEGER NOT NULL, run_id TEXT, event_json TEXT NOT NULL, "
            "created_at INTEGER NOT NULL, PRIMARY KEY (session_id, seq))"
        )
        for session_id, seq in rows:
            conn.execute(
                f"INSERT INTO {TRAJECTORY_TABLE_NAME} VALUES (?,?,?,?,?)",
                (session_id, seq, "run-1", json.dumps({"type": "tool.call"}), 0),
            )
        conn.commit()
    finally:
        conn.close()
    os.chmod(db_path, file_mode)
    os.chmod(d, dir_mode)
    return db_path


# ---- PASS: record present, perms tight ---------------------------------------------------
def test_b85_present_tight_perms_pass(tmp_path):
    _traj(tmp_path, file_mode=0o600, dir_mode=0o700)
    f = check_incident_readiness(_ctx(tmp_path))
    assert f.status == "PASS"
    assert f.confidence == "HIGH"
    assert any("present" in e for e in f.evidence)


def test_b85_group_readable_but_not_writable_still_pass(tmp_path):
    # 0o640 file / 0o750 dir: group can READ but not WRITE -> not tamperable -> PASS.
    _traj(tmp_path, file_mode=0o640, dir_mode=0o750)
    f = check_incident_readiness(_ctx(tmp_path))
    assert f.status == "PASS"


# ---- WARN: record present but tamperable -------------------------------------------------
def test_b85_group_writable_file_warns(tmp_path):
    _traj(tmp_path, file_mode=0o660, dir_mode=0o700)   # group-write on the file
    f = check_incident_readiness(_ctx(tmp_path))
    assert f.status == "WARN"
    assert f.confidence == "HIGH"
    assert any("trajectory.jsonl" in e for e in f.evidence)


def test_b85_world_writable_dir_warns(tmp_path):
    _traj(tmp_path, file_mode=0o600, dir_mode=0o707)   # world-write on the sessions/ dir
    f = check_incident_readiness(_ctx(tmp_path))
    assert f.status == "WARN"
    assert any("dir" in e for e in f.evidence)


# ---- B-127: group-writable, but group has NO other members -> WARN downgraded to LOW -----
def test_b85_group_writable_singleton_group_is_low_severity(monkeypatch, tmp_path):
    from clawseccheck.catalog import LOW
    monkeypatch.setattr(checks._shared, "_group_has_other_members", lambda gid, uid: False)
    _traj(tmp_path, file_mode=0o660, dir_mode=0o700)   # group-write on the file
    f = check_incident_readiness(_ctx(tmp_path))
    assert f.status == "WARN"
    assert f.severity == LOW
    assert "no other group members" in f.detail.lower()
    assert "destroying the evidence" not in f.detail.lower()


# ---- B-127: group-writable, group HAS other members -> unchanged MEDIUM WARN -------------
def test_b85_group_writable_multi_member_group_stays_medium_warn(monkeypatch, tmp_path):
    from clawseccheck.catalog import MEDIUM
    monkeypatch.setattr(checks._shared, "_group_has_other_members", lambda gid, uid: True)
    _traj(tmp_path, file_mode=0o660, dir_mode=0o700)
    f = check_incident_readiness(_ctx(tmp_path))
    assert f.status == "WARN"
    assert f.severity == MEDIUM
    assert "destroying the evidence" in f.detail.lower()


# ---- B-127: world-writable file always stays the active-threat WARN, even if group is
#      also a singleton (world bit alone is an active threat regardless of group membership)
def test_b85_world_writable_file_not_downgraded_even_if_group_singleton(monkeypatch, tmp_path):
    from clawseccheck.catalog import MEDIUM
    monkeypatch.setattr(checks._shared, "_group_has_other_members", lambda gid, uid: False)
    _traj(tmp_path, file_mode=0o606, dir_mode=0o700)   # world-write only on the file
    f = check_incident_readiness(_ctx(tmp_path))
    assert f.status == "WARN"
    assert f.severity == MEDIUM


# ---- B-810: SQLite-only evidence (classic JSONL locator empty, but the per-agent
#      SQLite store has real rows) -- corroborate() reports STATUS_LOCATOR_STALE and
#      B85 must answer presence/tamper against that container, not report UNKNOWN. ------
def test_b85_sqlite_only_tight_perms_pass(tmp_path):
    _sqlite_db(tmp_path, rows=(("s1", 0), ("s1", 1), ("s2", 0)), file_mode=0o600, dir_mode=0o700)
    f = check_incident_readiness(_ctx(tmp_path))
    assert f.status == "PASS"
    assert f.confidence == "HIGH"
    assert "sqlite" in f.detail.lower()
    # The old false claim must not survive onto the SQLite-evidence branch.
    assert "no on-disk record" not in f.detail.lower()


def test_b85_sqlite_only_world_writable_db_warns(tmp_path):
    _sqlite_db(tmp_path, file_mode=0o606, dir_mode=0o700)   # world-write on the db file
    f = check_incident_readiness(_ctx(tmp_path))
    assert f.status == "WARN"
    assert f.confidence == "HIGH"
    assert any("sqlite" in e.lower() for e in f.evidence)


def test_b85_sqlite_only_group_writable_singleton_group_is_low_severity(monkeypatch, tmp_path):
    from clawseccheck.catalog import LOW
    monkeypatch.setattr(checks._shared, "_group_has_other_members", lambda gid, uid: False)
    _sqlite_db(tmp_path, file_mode=0o660, dir_mode=0o700)   # group-write on the db file
    f = check_incident_readiness(_ctx(tmp_path))
    assert f.status == "WARN"
    assert f.severity == LOW
    assert "no other group members" in f.detail.lower()


# ---- UNKNOWN: nothing to reason about ----------------------------------------------------
def test_b85_absent_is_unknown(tmp_path):
    # No trajectory sidecar anywhere, in any container -> UNKNOWN, never a false FAIL/PASS.
    f = check_incident_readiness(_ctx(tmp_path))
    assert f.status == "UNKNOWN"
    assert "trajectory" in f.detail.lower()
    # The old wording asserted "no on-disk record" as a flat, unqualified fact. The
    # tightened wording keeps that consequence clause but now qualifies it against the
    # containers actually checked -- assert the new qualified phrasing is present.
    assert "no trajectory evidence was found in any known container" in f.detail.lower()
    assert "known container" in f.detail.lower()


def test_b85_non_posix_is_unknown(monkeypatch, tmp_path):
    _traj(tmp_path)   # even with a record present, NTFS ACLs are unreadable -> UNKNOWN
    monkeypatch.setattr(checks._shared, "_is_posix", lambda: False)
    f = check_incident_readiness(_ctx(tmp_path))
    assert f.status == "UNKNOWN"
    assert "acl" in f.detail.lower()


def test_b85_home_none_is_unknown():
    # A non-Path home must not crash; find_trajectory_files returns [] -> UNKNOWN.
    f = check_incident_readiness(Context(home=None, config={}))
    assert f.status == "UNKNOWN"


# ---- helper: find_trajectory_files -------------------------------------------------------
def test_find_trajectory_files_globs_the_grounded_layout(tmp_path):
    _traj(tmp_path, agent="main", session="a")
    _traj(tmp_path, agent="worker", session="b")
    found = find_trajectory_files(tmp_path)
    assert len(found) == 2
    assert all(p.name.endswith(".trajectory.jsonl") for p in found)


def test_find_trajectory_files_caps_at_max_files(tmp_path):
    for i in range(5):
        _traj(tmp_path, session=f"s{i}")
    assert len(find_trajectory_files(tmp_path, max_files=3)) == 3


def test_find_trajectory_files_non_path_returns_empty():
    assert find_trajectory_files(None) == []
    assert find_trajectory_files("agents") == []


def test_find_trajectory_files_absent_returns_empty(tmp_path):
    assert find_trajectory_files(tmp_path) == []


# ---- surface / registration integrity ----------------------------------------------------
def test_b85_is_registered_and_advisory():
    from clawseccheck.catalog import BY_ID, ast_for, owasp_for

    meta = BY_ID["B85"]
    assert meta.scored is False               # advisory: never moves the static grade
    assert meta.surface == "logs"              # F-163: audit/trajectory-trail half of monitoring
    assert ast_for("B85") == ("AST09",)       # governance / audit-trail, mirrors B50
    assert owasp_for("B85") == ()             # no clean LLM analog (like B50)
    assert check_incident_readiness in checks.CHECKS


if __name__ == "__main__":   # pragma: no cover
    pytest.main([__file__, "-q"])
