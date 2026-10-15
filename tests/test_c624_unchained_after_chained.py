"""C-624: verify-history / verify-events reported "chain OK" for an unchained row that
appears AFTER the first chained row.

``verify_chain`` skipped any row lacking ``chain_hash`` wherever it sat, without advancing
``prev_hash``, so later chained rows still validated and the only trace was a count in the
OK message. A forged row appended at the tail, inserted mid-file, or a last row whose
``chain_hash`` was stripped and whose body was then edited, all verified with rc 0.

Legacy rows (written by a build older than F-094 chaining) can only exist as a PREFIX: every
writer of these journals chains (``record_events``, ``history.record``) and
``_rotate_journal`` re-chains every survivor. An unchained row after a chained one has no
legitimate writer, so it is BROKEN. The legacy PREFIX carve-out and its count disclosure
(C-250) are unchanged - the positive controls below pin that.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from clawseccheck.history import record as history_record
from clawseccheck.history import verify as history_verify
from clawseccheck.monitor import (
    CHAIN_NO_ENTRIES,
    _chain_hash,
    _rotate_journal,
    chain_provenance_note,
    record_events,
    verify_chain,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SAFE = str(REPO_ROOT / "fixtures" / "home_safe")


class _Score:
    def __init__(self, score=50, grade="F", graded=True):
        self.score = score
        self.grade = grade
        self.graded = graded


def _run(*args: str, tmp_path: Path):
    """Own fake HOME and an explicit --home fixture (same isolation as
    tests/test_b582_viewer_chain_provenance.py's _run)."""
    fake_home = tmp_path / "home"
    fake_home.mkdir(exist_ok=True)
    home_args = [] if "--home" in args else ["--home", SAFE]
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--no-deptree", "--no-host", *home_args, *args],
        cwd=REPO_ROOT, capture_output=True, text=True,
        env={**os.environ, "HOME": str(fake_home)},
    )


def _chained_events(tmp_path: Path, n: int = 3, name: str = "events.jsonl") -> Path:
    j = tmp_path / name
    for i in range(n):
        record_events([("INFO", f"alert-{i}")], path=j, when=f"2026-01-0{i + 1}T00:00:00")
    return j


def _rows(p: Path) -> list:
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def _write_rows(p: Path, rows: list) -> None:
    p.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def _forged(msg: str = "forged") -> dict:
    return {"ts": "2026-01-09T00:00:00", "level": "INFO", "message": msg}


_NOT_LEGACY = "unchained entry {n} follows a chained entry - not legacy"


# ---------------------------------------------------------------- bad cases (were True)

def test_unchained_row_at_the_tail_is_broken(tmp_path):
    j = _chained_events(tmp_path, 3)
    rows = _rows(j)
    rows.append(_forged())
    _write_rows(j, rows)
    assert verify_chain(j) == (False, _NOT_LEGACY.format(n=3))


def test_unchained_row_inserted_mid_journal_is_broken(tmp_path):
    j = _chained_events(tmp_path, 4)
    rows = _rows(j)
    rows.insert(2, _forged())
    _write_rows(j, rows)
    assert verify_chain(j) == (False, _NOT_LEGACY.format(n=2))


def test_hash_stripped_and_edited_last_row_is_broken(tmp_path):
    j = _chained_events(tmp_path, 3)
    rows = _rows(j)
    rows[-1].pop("chain_hash")
    rows[-1]["message"] = "EDITED"
    _write_rows(j, rows)
    assert verify_chain(j) == (False, _NOT_LEGACY.format(n=2))


def test_hash_stripped_mid_row_with_rechained_successors_is_broken(tmp_path):
    """The forward-recompute actor: strips row 1's hash and re-hashes every successor so
    the chained rows all validate. The stripped row itself is still an unchained row after
    a chained one."""
    j = _chained_events(tmp_path, 4)
    rows = _rows(j)
    rows[1].pop("chain_hash")
    rows[1]["message"] = "EDITED"
    prev = rows[0]["chain_hash"]
    for r in rows[2:]:
        base = {k: v for k, v in r.items() if k != "chain_hash"}
        r["chain_hash"] = prev = _chain_hash(prev, base)
    _write_rows(j, rows)
    assert verify_chain(j) == (False, _NOT_LEGACY.format(n=1))


def test_chain_hash_null_after_chained_is_broken(tmp_path):
    j = _chained_events(tmp_path, 3)
    rows = _rows(j)
    rows[-1]["chain_hash"] = None
    rows[-1]["message"] = "EDITED"
    _write_rows(j, rows)
    assert verify_chain(j) == (False, _NOT_LEGACY.format(n=2))


def test_non_null_wrong_typed_chain_hash_still_takes_the_mismatch_path(tmp_path):
    """The carve-out keys on ``is None``, not falsiness: an empty / zero / false hash is a
    present-but-wrong hash and keeps reporting the ordinary 'broken at entry N'."""
    for bogus in ("", 0, False, []):
        j = _chained_events(tmp_path, 3, name=f"e-{type(bogus).__name__}.jsonl")
        rows = _rows(j)
        rows[-1]["chain_hash"] = bogus
        _write_rows(j, rows)
        assert verify_chain(j) == (False, "broken at entry 2"), repr(bogus)


def test_history_journal_gets_the_same_verdict(tmp_path):
    h = tmp_path / "history.jsonl"
    for i in range(3):
        assert history_record(_Score(50 + i), path=str(h), when=f"2026-01-0{i + 1}") is None
    assert history_verify(str(h)) == (True, "OK")
    rows = _rows(h)
    rows.append({"date": "2026-01-09", "score": 100, "grade": "A"})
    _write_rows(h, rows)
    assert history_verify(str(h)) == (False, _NOT_LEGACY.format(n=3))


def test_verify_events_cli_exit_1_and_names_broken(tmp_path):
    j = _chained_events(tmp_path, 3)
    rows = _rows(j)
    rows.append(_forged())
    _write_rows(j, rows)
    result = _run("--verify-events", "--events", str(j), tmp_path=tmp_path)
    assert result.returncode == 1
    assert "Events chain BROKEN" in result.stdout
    assert "unchained entry" in result.stdout


def test_watch_log_note_names_the_entry_and_stays_rc_0(tmp_path):
    note = chain_provenance_note(False, _NOT_LEGACY.format(n=4))
    assert note is not None
    assert "entry 4 onward" in note
    assert "unverified provenance" in note

    j = _chained_events(tmp_path, 3)
    rows = _rows(j)
    rows.append(_forged("forged tail row"))
    _write_rows(j, rows)
    result = _run("--watch-log", "--events", str(j), tmp_path=tmp_path)
    assert result.returncode == 0
    assert "unverified provenance" in result.stdout
    assert "entry 3 onward" in result.stdout
    assert "alert-0" in result.stdout  # rows still rendered (B-582 contract)


# ---------------------------------------------------------------- positive controls

def test_legacy_prefix_then_chained_is_still_ok_with_count(tmp_path):
    j = tmp_path / "events.jsonl"
    _write_rows(j, [_forged("legacy-a"), _forged("legacy-b")])
    record_events([("INFO", "chained-a")], path=j, when="2026-02-01T00:00:00")
    record_events([("INFO", "chained-b")], path=j, when="2026-02-02T00:00:00")
    assert verify_chain(j) == (
        True, "OK (2 entries not chain-verified (legacy, no chain_hash))")


def test_all_legacy_journal_is_still_ok_with_count(tmp_path):
    j = tmp_path / "events.jsonl"
    _write_rows(j, [_forged("legacy-a"), _forged("legacy-b")])
    assert verify_chain(j) == (
        True, "OK (2 entries not chain-verified (legacy, no chain_hash))")


def test_fully_chained_journal_is_bare_ok(tmp_path):
    assert verify_chain(_chained_events(tmp_path, 4)) == (True, "OK")


def test_rotation_never_leaves_an_unchained_row_after_a_chained_one(tmp_path):
    """Pins the claim the fix rests on: no legitimate writer produces the flagged shape.
    Rotation over a legacy prefix + chained rows re-chains EVERY survivor."""
    j = tmp_path / "events.jsonl"
    _write_rows(j, [_forged("legacy-a"), _forged("legacy-b")])
    for i in range(4):
        record_events([("INFO", f"chained-{i}")], path=j, when=f"2026-02-0{i + 1}T00:00:00")
    assert verify_chain(j)[0] is True
    _rotate_journal(j, max_lines=3, keep=2)
    rows = _rows(j)
    assert len(rows) == 3  # retention marker + 2 survivors
    assert all(r.get("chain_hash") for r in rows)
    assert verify_chain(j) == (True, "OK")


def test_unparseable_tail_line_is_disclosed_not_unchained(tmp_path):
    j = _chained_events(tmp_path, 3)
    with open(j, "a", encoding="utf-8") as fh:
        fh.write('{"ts": "2026-01-09T00:00:0')  # crash-mid-write shape, no newline
    assert verify_chain(j) == (True, "OK (1 unparseable line skipped)")


def test_blank_lines_between_rows_are_not_unchained_rows(tmp_path):
    j = _chained_events(tmp_path, 3)
    lines = j.read_text(encoding="utf-8").splitlines()
    j.write_text(lines[0] + "\n\n" + lines[1] + "\n\n" + lines[2] + "\n", encoding="utf-8")
    assert verify_chain(j) == (True, "OK")


def test_journal_of_only_an_unparseable_line_is_still_the_third_outcome(tmp_path):
    """The new branch cannot fire before a parseable chained row exists."""
    j = tmp_path / "events.jsonl"
    j.write_text("not json at all\n", encoding="utf-8")
    cause: list = []
    ok, msg = verify_chain(j, cause=cause)
    assert ok is None
    assert cause == [CHAIN_NO_ENTRIES]
    assert msg.startswith("no chain here")
