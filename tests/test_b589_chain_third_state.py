"""B-589 — deleting the store must not pass the tamper check.

``--verify-history`` / ``--verify-events`` reported ``chain OK`` with exit 0 for a file
that was absent, empty, or unreadable. An attacker erasing the event that recorded their
own install never had to defeat the hash chain: they deleted the file and the verifier
blessed the result. The explicitly-named case was the sharpest — ``--history
/path/that/is/gone`` printed "OK" about a specific file the user believed held their
history.

The fix is the third outcome ``--verify-baseline`` (F-173) already established one branch
over, not the other half of the bool: flipping absence to BROKEN would make a genuine
first run report tampering and send the user hunting an intruder who is not there.

These tests assert the *exact* strings, not a substring of a sentence, so a regression to
the word "OK" fails here rather than passing quietly.

Offline, read-only, stdlib only; writes nothing outside ``tmp_path``.
"""
from __future__ import annotations

import json
import pathlib
from pathlib import Path

import pytest

from clawseccheck.cli import main
from clawseccheck.history import record, verify
from clawseccheck.monitor import (
    CHAIN_ABSENT,
    CHAIN_BAD_PATH,
    CHAIN_EMPTY,
    CHAIN_NO_ENTRIES,
    CHAIN_NOT_A_FILE,
    CHAIN_UNREADABLE,
    record_events,
    verify_chain,
)

_NO_CHAIN_ABSENT = "no chain here — the file does not exist"
_NO_CHAIN_EMPTY = "no chain here — the file is empty"


class _Score:
    def __init__(self, score, grade):
        self.score = score
        self.grade = grade


def _populated_events(tmp_path: Path, name: str = "events.jsonl") -> Path:
    j = tmp_path / name
    for i in range(3):
        record_events([("INFO", f"alert-{i}")], path=j, when=f"2026-01-0{i + 1}T00:00:00")
    return j


# ---------------------------------------------------------------------------
# The two outcomes that must NOT have moved
# ---------------------------------------------------------------------------

def test_intact_chain_still_verifies_ok(tmp_path, capsys):
    j = _populated_events(tmp_path)
    ok, msg = verify_chain(j)
    assert ok is True
    assert msg == "OK"

    rc = main(["--verify-events", "--events", str(j)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Events chain OK" in out


def test_tampered_chain_still_reports_broken_with_its_entry_index(tmp_path, capsys):
    j = _populated_events(tmp_path)
    rows = [json.loads(x) for x in j.read_text(encoding="utf-8").splitlines() if x.strip()]
    rows[1]["message"] = "TAMPERED"
    j.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")

    ok, msg = verify_chain(j)
    assert ok is False
    assert msg == "broken at entry 1"

    rc = main(["--verify-events", "--events", str(j)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "Events chain BROKEN" in out
    assert "entry 1" in out


def test_legacy_rows_keep_their_honest_ok(tmp_path):
    """A real chain whose rows predate chain_hash is NOT the absent case.

    It is a genuine journal with unverifiable rows, and the count is disclosed (C-250).
    Folding it into the third state would lose a distinction that already works.
    """
    j = tmp_path / "events.jsonl"
    j.write_text(
        '{"ts":"2025-01-01T00:00:00","level":"INFO","message":"old-0"}\n'
        '{"ts":"2025-01-02T00:00:00","level":"INFO","message":"old-1"}\n',
        encoding="utf-8",
    )
    ok, msg = verify_chain(j)
    assert ok is True
    assert msg == "OK (2 entries not chain-verified (legacy, no chain_hash))"


# ---------------------------------------------------------------------------
# The third outcome
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("flag,store", [("--verify-history", "--history"),
                                        ("--verify-events", "--events")])
def test_explicitly_named_missing_path_is_not_ok(tmp_path, capsys, flag, store):
    """The sharpest case: the user named a file they believe holds their journal."""
    path = str(tmp_path / "gone.jsonl")
    rc = main([flag, store, path])
    out = capsys.readouterr().out

    assert rc == 1
    assert "chain OK" not in out
    assert "BROKEN" not in out
    assert "NOT VERIFIED" in out
    assert _NO_CHAIN_ABSENT in out
    assert path in out
    # An explicitly named path is not a first-run state, and the text must say so.
    assert "You named this path" in out


def test_empty_file_is_not_ok(tmp_path, capsys):
    j = tmp_path / "events.jsonl"
    j.write_text("", encoding="utf-8")

    ok, msg = verify_chain(j)
    assert ok is None
    assert msg == _NO_CHAIN_EMPTY

    rc = main(["--verify-events", "--events", str(j)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "chain OK" not in out


def test_file_with_nothing_parseable_is_not_ok_and_says_how_many(tmp_path):
    """"Empty" and "nothing but garbage" are both "no chain here" and are different facts.

    A truncated-to-junk journal must not read as a never-written one — the count is what
    tells the user something was there.
    """
    j = tmp_path / "events.jsonl"
    j.write_text("not json at all\n{broken\n", encoding="utf-8")

    ok, msg = verify_chain(j)
    assert ok is None
    assert "OK" not in msg
    assert msg == "no chain here — the file holds no readable entry (2 unparseable lines)"


def test_unreadable_store_is_not_ok(tmp_path, monkeypatch):
    """A present-but-unreadable store used to return (True, "OK") from the bare
    ``except OSError``. Saying "OK" about a file that could not be opened is the same
    lying PASS as saying it about one that is not there (cross-ref B-581).

    Injected rather than chmod-ed so the assertion holds when the suite runs as root.
    """
    j = _populated_events(tmp_path)
    real_open = pathlib.Path.open

    def fake_open(self, *a, **kw):
        if self == j:
            raise PermissionError(13, "Permission denied", str(j))
        return real_open(self, *a, **kw)

    monkeypatch.setattr(pathlib.Path, "open", fake_open)

    ok, msg = verify_chain(j)
    assert ok is None, "the injection must actually have taken"
    assert "OK" not in msg
    assert "Permission denied" in msg


def test_a_store_that_existed_and_was_deleted_is_never_ok(tmp_path, capsys):
    """The filed reproduction, end to end: verify, delete, verify again."""
    j = _populated_events(tmp_path)
    assert main(["--verify-events", "--events", str(j)]) == 0
    assert "Events chain OK" in capsys.readouterr().out

    j.unlink()
    rc = main(["--verify-events", "--events", str(j)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "chain OK" not in out
    assert _NO_CHAIN_ABSENT in out


def test_history_verify_passes_the_third_state_through(tmp_path):
    """history.verify() is a delegation; the third outcome must survive it."""
    assert verify(str(tmp_path / "nope.jsonl"))[0] is None

    path = str(tmp_path / "history.jsonl")
    record(_Score(72, "C"), path=path, when="2026-06-15")
    assert verify(path)[0] is True


def test_a_bare_truthiness_check_would_have_read_absence_as_broken(tmp_path):
    """Why the callers must test ``is True`` / ``is False`` / ``is None``.

    ``None`` is falsy, so any surviving ``if ok:`` reads "no chain here" as BROKEN — the
    exact F-173 inversion (reporting tampering on a first run) that choosing a third value
    over ``False`` was meant to avoid. This pins the hazard so it is documented rather
    than rediscovered.
    """
    ok, _msg = verify_chain(tmp_path / "nope.jsonl")
    assert ok is None
    assert not ok          # falsy — a bare `if ok:` would take the BROKEN branch
    assert ok is not False  # ...but it is NOT the broken verdict


# ---------------------------------------------------------------------------
# --ascii keeps its contract now that these branches carry an em dash
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("argv", [
    ["--verify-history", "--history", "MISSING", "--ascii"],
    ["--verify-events", "--events", "MISSING", "--ascii"],
    ["--verify-self", "--ascii"],
])
def test_ascii_mode_emits_pure_ascii(tmp_path, capsys, argv):
    argv = [str(tmp_path / "gone.jsonl") if a == "MISSING" else a for a in argv]
    main(argv)
    out = capsys.readouterr().out
    leaked = sorted({ch for ch in out if ord(ch) > 127})
    assert not leaked, f"--ascii still emitted {leaked!r}"


# ---------------------------------------------------------------------------
# WHICH sentence follows is decided by what is there, not by whether a flag was typed
# ---------------------------------------------------------------------------

def _fake_home(tmp_path: Path) -> Path:
    store = tmp_path / "home" / ".clawseccheck"
    store.mkdir(parents=True)
    return store


def test_a_corrupted_default_store_is_not_called_normal(tmp_path, monkeypatch, capsys):
    """The blocker an independent C-135 pass found in the first version of this fix.

    The follow-on sentence branched on whether the user typed ``--history``, not on
    whether anything was there. So a default-location store holding 200 overwritten lines
    got "nothing usable has been written there yet, which is normal before the first run"
    — a sentence that contradicts the line directly above it and talks the reader out of
    the exact tampering the third outcome exists to expose. Worse, the correct sentence
    was reachable only by passing an explicit flag, i.e. unreachable on the common
    invocation.
    """
    store = _fake_home(tmp_path)
    (store / "history.jsonl").write_text("garbage line\n" * 200, encoding="utf-8")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))

    rc = main(["--verify-history"])
    out = capsys.readouterr().out

    assert rc == 1
    assert "200 unparseable lines" in out
    assert "is not a usable journal" in out
    assert "normal before the first run" not in out
    assert "nothing has been written" not in out


def test_an_unreadable_default_store_warns_against_overwriting_the_evidence(
        tmp_path, monkeypatch, capsys):
    """Same root cause as the test above, and the same posture --verify-baseline takes:
    do not send the user to re-run the thing that WRITES the file they need to inspect."""
    store = _fake_home(tmp_path)
    journal = store / "events.jsonl"
    record_events([("INFO", "x")], path=journal, when="2026-01-01T00:00:00")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))

    real_open = pathlib.Path.open

    def fake_open(self, *a, **kw):
        if self.name == "events.jsonl":
            raise PermissionError(13, "Permission denied", str(self))
        return real_open(self, *a, **kw)

    monkeypatch.setattr(pathlib.Path, "open", fake_open)

    rc = main(["--verify-events"])
    out = capsys.readouterr().out

    assert rc == 1
    assert "could not be read" in out
    assert "normal before the first run" not in out
    assert "would overwrite the evidence" in out


def test_data_dir_does_not_claim_to_be_the_default_location(tmp_path, capsys):
    """A --data-dir path is not the default path, and the text must not say it is.

    The *decision* that --data-dir counts as non-explicit is deliberate (choosing a store
    directory is not naming a journal, and a fresh data dir legitimately has none yet) —
    but the first version paired that decision with the words "This is the default
    location", which is simply false.
    """
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    rc = main(["--verify-history", "--data-dir", str(fresh)])
    out = capsys.readouterr().out

    assert rc == 1
    assert "default location" not in out
    assert "No journal has been written to this location yet" in out
    assert str(fresh) in out


def test_genuine_first_run_keeps_its_benign_wording(tmp_path, monkeypatch, capsys):
    """The other half of the same branch: nothing there really is normal, and must read
    that way. Sharpening the corrupted-store case must not have hardened this one."""
    monkeypatch.setenv("HOME", str(tmp_path))
    rc = main(["--verify-history"])
    out = capsys.readouterr().out

    assert rc == 1
    assert "chain OK" not in out
    assert "normal before the first run" in out
    assert "is not a usable journal" not in out
    assert "worth investigating" not in out
    # An unnamed path has ordinary reasons to be absent; a named one does not. Collapsing
    # them is how "no history yet" starts sounding like evidence.
    assert "You named this path" not in out


# ---------------------------------------------------------------------------
# Causes are named from evidence, not assumed
# ---------------------------------------------------------------------------

def test_a_directory_is_not_reported_as_a_missing_file(tmp_path):
    """``not p.is_file()`` is true of far more than "absent", and asserting absence about
    a directory, a FIFO or a dangling symlink repeats the mistake this task fixed:
    naming a cause the evidence does not establish."""
    d = tmp_path / "store"
    d.mkdir()
    cause: list = []
    ok, msg = verify_chain(d, cause=cause)
    assert ok is None
    assert cause == [CHAIN_NOT_A_FILE]
    assert msg == "no chain here — the path is not a regular file"


def test_a_dangling_symlink_says_so(tmp_path):
    link = tmp_path / "store.jsonl"
    link.symlink_to(tmp_path / "never_existed.jsonl")
    cause: list = []
    ok, msg = verify_chain(link, cause=cause)
    assert ok is None
    assert cause == [CHAIN_NOT_A_FILE]
    assert "symlink" in msg
    assert msg != "no chain here — the file does not exist"


@pytest.mark.parametrize("build,expected", [
    (lambda p: None, CHAIN_ABSENT),
    (lambda p: p.write_text("", encoding="utf-8"), CHAIN_EMPTY),
    (lambda p: p.write_text("nope\n{broken\n", encoding="utf-8"), CHAIN_NO_ENTRIES),
])
def test_each_third_state_reports_its_own_cause(tmp_path, build, expected):
    j = tmp_path / "events.jsonl"
    build(j)
    cause: list = []
    ok, _msg = verify_chain(j, cause=cause)
    assert ok is None
    assert cause == [expected]


def test_an_intact_chain_reports_no_cause(tmp_path):
    """The channel must stay silent on the outcomes that are not the third one, or a
    caller reading ``cause[0]`` starts describing a healthy store."""
    j = _populated_events(tmp_path)
    cause: list = []
    assert verify_chain(j, cause=cause)[0] is True
    assert cause == []


def test_unreadable_reports_its_own_cause(tmp_path, monkeypatch):
    j = _populated_events(tmp_path)
    real_open = pathlib.Path.open

    def fake_open(self, *a, **kw):
        if self == j:
            raise PermissionError(13, "Permission denied", str(j))
        return real_open(self, *a, **kw)

    monkeypatch.setattr(pathlib.Path, "open", fake_open)
    cause: list = []
    ok, _msg = verify_chain(j, cause=cause)
    assert ok is None
    assert cause == [CHAIN_UNREADABLE]


# ---------------------------------------------------------------------------
# Round 2: a malformed path is not an unreadable store
# ---------------------------------------------------------------------------

def test_an_overlong_path_is_not_an_accusation(tmp_path, capsys):
    """ENAMETOOLONG used to land in the "unreadable" bucket, which then told the user to
    check the permissions of, and investigate who locked down, a file that cannot exist.
    Exactly the round-1 defect in a new place: naming a cause the evidence does not
    establish."""
    path = str(tmp_path / ("z" * 600 + ".jsonl"))
    cause: list = []
    ok, msg = verify_chain(path, cause=cause)
    assert ok is None
    assert cause == [CHAIN_BAD_PATH]
    assert "cannot name a file" in msg

    rc = main(["--verify-events", "--events", path])
    out = capsys.readouterr().out
    assert rc == 1
    assert "check it for a typo" in out
    assert "permissions" not in out
    assert "worth investigating" not in out


def test_an_unknown_user_home_does_not_raise(tmp_path):
    """``Path.expanduser()`` raises RuntimeError for ``~nosuchuser`` and sat OUTSIDE the
    try, so the "never raises" contract in this function's own docstring was false."""
    cause: list = []
    ok, msg = verify_chain("~nosuchuser42/events.jsonl", cause=cause)
    assert ok is None
    assert cause == [CHAIN_BAD_PATH]
    assert "cannot be resolved" in msg


def test_a_symlink_loop_is_not_described_as_a_missing_target(tmp_path):
    """``exists()`` is False for a loop as well as for a dangling link, so the first
    wording ("its target does not exist") was true of only one of them — a loop's target
    exists, it is the link. Claim what was established: following it reaches no file."""
    loop = tmp_path / "loop.jsonl"
    loop.symlink_to(loop)
    cause: list = []
    ok, msg = verify_chain(loop, cause=cause)
    assert ok is None
    assert cause == [CHAIN_NOT_A_FILE]
    assert "does not resolve to a readable file" in msg
    assert "target does not exist" not in msg
