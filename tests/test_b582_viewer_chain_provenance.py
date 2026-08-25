"""B-582: `--trend` and `--watch-log` present the local stores without ever checking the
tamper-evident chain that exists for them.

Both viewers rendered whatever the file said, rc 0, no warning — while
`--verify-history`/`--verify-events` on the IDENTICAL file correctly answered BROKEN. The
chain existed and simply was not consulted on the path a human actually reads.

Two constraints on the fix, both tested here:

- Never refuse to display. A broken chain still renders every row.
- Never say "tampering". `configjournal.py` established the precedent this mirrors: a
  broken hash-chain link has ordinary benign causes (a hand edit outside the writer, two
  writes racing from a common base, log rotation) and is reported as *unverified
  provenance*, never an accusation.

**Negative-only.** An intact chain prints NOTHING extra — a standing "Chain verified" line
on every healthy run would be read as furniture within a week and would bury the one line
that matters. Silence means verified. `test_intact_history_prints_no_provenance_note` and
`test_intact_events_prints_no_provenance_note` are the positive controls: they prove the
line is genuinely absent on an intact file, not merely untested for it, so the two negative
tests below are trusted rather than accidental.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from clawseccheck.history import record as history_record
from clawseccheck.monitor import chain_provenance_note, record_events

REPO_ROOT = Path(__file__).resolve().parents[1]


class _Score:
    def __init__(self, score=50, grade="F", graded=True):
        self.score = score
        self.grade = grade
        self.graded = graded


SAFE = str(REPO_ROOT / "fixtures" / "home_safe")


def _run(*args: str, tmp_path: Path):
    """Every run gets its own fake HOME and an explicit --home fixture, so no
    subprocess here ever touches the real machine's OpenClaw config (same
    isolation as tests/test_b598_dashboard_history.py's _run helper)."""
    fake_home = tmp_path / "home"
    fake_home.mkdir(exist_ok=True)
    import os
    home_args = [] if "--home" in args else ["--home", SAFE]
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck", *home_args, *args],
        cwd=REPO_ROOT, capture_output=True, text=True,
        env={**os.environ, "HOME": str(fake_home)},
    )


def _tamper_second_line(path: Path, replace: str, with_: str) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace(replace, with_)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# --------------------------------------------------------------- unit: chain_provenance_note

def test_note_is_none_when_chain_verified():
    assert chain_provenance_note(True, "OK") is None


def test_note_is_none_when_chain_verified_with_legacy_notes():
    assert chain_provenance_note(True, "OK (2 entries not chain-verified (legacy, no chain_hash))") is None


def test_note_is_none_when_no_chain_to_check():
    assert chain_provenance_note(None, "no chain here — the file does not exist") is None


def test_note_names_the_entry_and_says_unverified_provenance_not_tampering():
    note = chain_provenance_note(False, "broken at entry 7")
    assert note is not None
    assert "entry 7" in note
    assert "unverified provenance" in note
    assert "tampering" not in note.lower() or "not evidence of tampering" in note


# --------------------------------------------------------------- --trend: positive control

def test_intact_history_prints_no_provenance_note(tmp_path):
    hist = tmp_path / "history.jsonl"
    for i in range(3):
        history_record(_Score(50 + i), path=str(hist), when=f"2026-08-1{i}T10:00:00")

    result = _run("--trend", "--history", str(hist), "--data-dir", str(tmp_path / "d"),
                  tmp_path=tmp_path)
    assert result.returncode == 0
    assert "unverified provenance" not in result.stdout
    assert "does not verify" not in result.stdout
    assert "Chain verified" not in result.stdout  # negative-only: no standing line either


# --------------------------------------------------------------- --trend: negative control

def test_tampered_history_discloses_unverified_provenance_and_still_renders_rows(tmp_path):
    hist = tmp_path / "history.jsonl"
    for i in range(3):
        history_record(_Score(50 + i), path=str(hist), when=f"2026-08-1{i}T10:00:00")
    _tamper_second_line(hist, '"score": 51', '"score": 99')

    result = _run("--trend", "--history", str(hist), "--data-dir", str(tmp_path / "d"),
                  tmp_path=tmp_path)
    assert result.returncode == 0  # a viewer never fails the run on a broken chain
    assert "unverified provenance" in result.stdout
    assert "not evidence of tampering" in result.stdout
    assert "tampering" not in result.stdout.replace("not evidence of tampering", "")
    assert "entry 1" in result.stdout
    # every row still rendered — a broken chain must never hide data (the planted
    # "99" and the two untouched rows' own scores, 50/52, all still present)
    assert "99" in result.stdout
    assert "50" in result.stdout
    assert "52" in result.stdout

    verify = _run("--verify-history", "--history", str(hist), tmp_path=tmp_path)
    assert verify.returncode == 1
    assert "entry 1" in verify.stdout  # same index both places


# --------------------------------------------------------------- --watch-log: positive control

def test_intact_events_prints_no_provenance_note(tmp_path):
    events = tmp_path / "events.jsonl"
    record_events([("INFO", "gateway.bind checked")], path=events, when="2026-08-20T10:00:00")
    record_events([("WARNING", "gateway.bind changed")], path=events, when="2026-08-20T10:05:00")

    result = _run("--watch-log", "--events", str(events), tmp_path=tmp_path)
    assert result.returncode == 0
    assert "unverified provenance" not in result.stdout
    assert "does not verify" not in result.stdout


# --------------------------------------------------------------- --watch-log: negative control

def test_tampered_events_discloses_unverified_provenance_and_still_renders_rows(tmp_path):
    events = tmp_path / "events.jsonl"
    record_events([("INFO", "gateway.bind checked")], path=events, when="2026-08-20T10:00:00")
    record_events([("WARNING", "gateway.bind changed")], path=events, when="2026-08-20T10:05:00")
    _tamper_second_line(events, "WARNING", "CRITICAL")

    result = _run("--watch-log", "--events", str(events), tmp_path=tmp_path)
    assert result.returncode == 0
    assert "unverified provenance" in result.stdout
    assert "not evidence of tampering" in result.stdout
    assert "entry 1" in result.stdout
    assert "gateway.bind changed" in result.stdout  # row still rendered

    verify = _run("--verify-events", "--events", str(events), tmp_path=tmp_path)
    assert verify.returncode == 1
    assert "entry 1" in verify.stdout
