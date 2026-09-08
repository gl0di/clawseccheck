"""B-581: an unreadable ``--history``/``--events`` path is named, not read as "no data".

``--trend`` and ``--watch-log`` are the sixth and seventh call sites for the
``cli._describe_os_error`` / ``cli._path_problem_text`` family B-561/B-562 built, and the
worst of the seven: the other five empty an advisory payload, but ``history.load()`` /
``monitor.load_events()`` fed a FALSE STATEMENT about the user's own data. Measured before
the fix::

    --trend --history /nope/deep/hist.jsonl
    -> "No history yet. Run --trend again later to see your trend." · rc 0 · stderr empty

    --watch-log --events /nope/ev.jsonl
    -> "No recorded change events yet." · rc 0 · stderr empty

The real history/journal were untouched and never opened; the user had mistyped a flag.
``--trend`` also has a second failure the read-only siblings do not: ``history.record()``
swallowed the append's ``OSError`` (``except OSError: pass``), so a cron running
``--trend --history /mnt/backup/hist.jsonl`` after the mount drops loses the point
forever while printing the same cheerful "No history yet."

## Same shape as B-561/B-562, deliberately

One ``note:`` line to stderr naming the path and the reason. stdout, the artifact and the
exit code are unchanged — B-561's first attempt exited 1 and had to be retracted for
breaking a documented degradation; the same reasoning applies here with more force,
because unlike the three verdicts flags, ``--history``/``--events`` have a real DEFAULT
location, and an absent file there is a genuine first run that must stay silent
(``cli._explicit_paths`` is what tells the two apart — it is computed before argparse's
per-flag defaulting, so "the user typed this" survives to the read/write site).

The write-failure note is unconditional — not gated on ``_explicit_paths`` like the read
note — because a dropped write is never a "normal first run" state the way an absent file
is, whichever path it targets.

## Why B-561/B-562's own tests don't need touching

``cli._path_problem_text`` was widened to run its composed line through
``report._redact_home_paths`` (a real ``/home/dave/...`` in an error message is exactly
the §8 hole ``_redact_home_paths`` exists for, and it had one caller only, not a scope
limit). ``tests/test_b561_judge_payload_path.py`` and ``tests/test_b562_bundle_path.py``
both still pass unmodified — 11 and 14 green — but that is not evidence the widening is
covered: both build their unreadable paths from pytest's ``tmp_path``, which lives under
``/tmp/...`` on every machine that runs this suite, so the redaction never fires in either
file. Neither sibling puts a ``/home/...`` path in front of the helper it shares. The
redaction coverage below is this file's alone.

Offline, writes nothing outside tmp_path, stdlib only. Never ``Path.home()`` — this
module's own history/events go through ``--data-dir``/``--history``/``--events``, and the
one path meant to look like a real home directory is a SYNTHETIC ``/home/faketestuser/...``
literal, not the sandbox's own ``$HOME`` (which the suite already redirects to a tmp dir —
asserting against it would be vacuous, since it never contains ``/home/`` on this box's
real path shape after the B-519 redirect and would only prove the redirect, not the fix).
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from clawseccheck.history import render_trend

REPO_ROOT = Path(__file__).resolve().parents[1]
HOME = REPO_ROOT / "fixtures" / "home_safe"

MISSING_HISTORY = "/nope/deep/hist.jsonl"
MISSING_EVENTS = "/nope/ev.jsonl"
# A synthetic path under /home/ that is NOT this machine's real $HOME (which the suite's
# own B-519 redirect has already pointed at a tmp dir). /home itself is root-owned on a
# normal install, so this fails for real (PermissionError) without ever touching anyone's
# actual home directory.
SYNTHETIC_HOME_PATH = "/home/faketestuser/blocked/hist.jsonl"
SYNTHETIC_HOME_EVENTS = "/home/faketestuser/blocked/ev.jsonl"

# The empty-history render, called on the real function rather than guessed as a literal —
# this branch of render_trend does not touch ascii_only, so it needs no --ascii pin.
_NO_HISTORY_TEXT = render_trend([])


def _run(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--data-dir", str(tmp_path / "state"),
         "--home", str(HOME), *args],
        cwd=REPO_ROOT, capture_output=True, text=True)


# ------------------------------------------------------ unreadable named path -> note


def test_unreadable_named_history_path_is_reported_rc0(tmp_path):
    proc = _run(tmp_path, "--trend", "--history", MISSING_HISTORY)
    assert proc.returncode == 0
    assert "note: --history:" in proc.stderr
    assert "no such file or directory" in proc.stderr
    assert MISSING_HISTORY in proc.stderr
    assert proc.stdout.startswith(_NO_HISTORY_TEXT), proc.stdout[:200]
    assert "note:" not in proc.stdout


def test_unreadable_named_events_path_is_reported_rc0(tmp_path):
    proc = _run(tmp_path, "--watch-log", "--events", MISSING_EVENTS)
    assert proc.returncode == 0
    assert "note: --events:" in proc.stderr
    assert "no such file or directory" in proc.stderr
    assert MISSING_EVENTS in proc.stderr
    # B-583 moved this sentence. What this test guards is the SEPARATION — the problem
    # is noted on stderr and never on stdout, and rc stays 0 — not the exact wording of
    # the empty-journal line, which now distinguishes "never written" from "ran and
    # nothing changed" instead of collapsing both into one neutral sentence.
    assert "monitoring has not run yet" in proc.stdout, proc.stdout
    assert "note:" not in proc.stdout


# ------------------------------------------------------ genuine first run stays silent


def test_fresh_default_history_reads_as_empty_not_error(tmp_path):
    """No --history given: --data-dir alone resolves a fresh, never-before-seen default
    location. A genuine first run must stay completely silent on stderr — the note exists
    for a NAMED path, not an absent one.

    Unlike --watch-log below, --trend WRITES before it reads (that write is the whole
    point of the mode), so its own read is never literally empty here: it sees the row
    it just wrote a moment earlier, rendered as "no grade" (this sandbox has no OpenClaw
    home, so the five-layer check never completes). That is correct, expected behaviour,
    not this test's subject — the subject is that neither the write nor the read prints
    a note about a path nobody named.
    """
    proc = _run(tmp_path, "--trend")
    assert proc.returncode == 0
    assert proc.stderr == "", f"a first run must not note anything: {proc.stderr!r}"
    assert "no grade" in proc.stdout, proc.stdout[:200]


def test_fresh_default_events_reads_as_empty_not_error(tmp_path):
    proc = _run(tmp_path, "--watch-log")
    assert proc.returncode == 0
    assert proc.stderr == "", f"a first run must not note anything: {proc.stderr!r}"
    # The invariant here is the SILENCE on stderr for an absent default path. B-583
    # changed what stdout says about an empty journal: a genuine first run has neither
    # a journal nor a prior monitor run, so it now says so instead of the older neutral
    # sentence, which read identically to "monitoring ran and found nothing".
    assert "monitoring has not run yet" in proc.stdout, proc.stdout


# ------------------------------------------------------ the dropped write is reported


def test_write_failure_is_reported_and_the_point_is_not_saved(tmp_path):
    proc = _run(tmp_path, "--trend", "--history", MISSING_HISTORY)
    assert proc.returncode == 0
    assert "note: --trend:" in proc.stderr
    assert "could not be recorded" in proc.stderr
    assert "NOT saved" in proc.stderr
    # The write is reported DISTINCTLY from the read: two separate note lines, not one
    # conflated sentence.
    write_notes = [ln for ln in proc.stderr.splitlines() if "note: --trend:" in ln]
    read_notes = [ln for ln in proc.stderr.splitlines() if "note: --history:" in ln]
    assert len(write_notes) == 1, proc.stderr
    assert len(read_notes) == 1, proc.stderr
    # And the write genuinely never landed: /nope was never created (same assertion the
    # bug report itself made against the pre-fix behaviour).
    assert not Path("/nope").exists(), "the dropped write silently created its own path"


# ------------------------------------------------------ redaction: no /home/<user> leaks


def test_no_home_path_leaks_in_the_trend_notes(tmp_path):
    """Pins BOTH notes --trend can print for one bad path, not just the pair combined —
    history.record() hands back the RAW OSError text (e.g. "Permission denied:
    '/home/faketestuser'"), a separate string from _path_problem_text's composed read-note
    line, and it went through _sanitize only (not _redact_home_paths) until this task:
    a real §8 leak, found while proving this exact write note, now pinned by name so a
    future edit to the write-note f-string cannot silently drop the second redact call.
    """
    proc = _run(tmp_path, "--trend", "--history", SYNTHETIC_HOME_PATH)
    assert proc.returncode == 0
    write_notes = [ln for ln in proc.stderr.splitlines() if "note: --trend:" in ln]
    read_notes = [ln for ln in proc.stderr.splitlines() if "note: --history:" in ln]
    assert len(write_notes) == 1 and len(read_notes) == 1, proc.stderr
    assert "faketestuser" not in write_notes[0], write_notes[0]
    assert "faketestuser" not in read_notes[0], read_notes[0]
    assert "~/" in write_notes[0], "the redacted write note should still show the rest of the path"
    assert "~/" in read_notes[0], "the redacted read note should still show the rest of the path"
    assert "faketestuser" not in proc.stdout, proc.stdout


def test_no_home_path_leaks_in_the_watch_log_note(tmp_path):
    proc = _run(tmp_path, "--watch-log", "--events", SYNTHETIC_HOME_EVENTS)
    assert proc.returncode == 0
    assert "faketestuser" not in proc.stderr, proc.stderr
    assert "faketestuser" not in proc.stdout, proc.stdout
    assert "~/" in proc.stderr


# ------------------------------------------------------ hostile path stays one sanitised line


# ------------------------------------------------------ the version-sensitive predicate


def test_a_stat_inaccessible_path_is_reported_not_crashed(tmp_path):
    """The version-sensitive branch this task's design turns on: a PARENT directory with
    no execute/traverse bit makes ``Path.is_file()`` itself raise ``PermissionError``
    (verified directly against this interpreter AND 3.9 with the identical chmod, outside
    pytest: both raise identically — no divergence found, but checked rather than
    assumed). The OLD ``monitor.load_events()`` called ``is_file()`` OUTSIDE its
    ``try``/``except OSError`` block, so this exact scenario propagated UNCAUGHT
    (verified against the pre-fix source via ``git show``: it does — confirmed for
    ``history.load()`` too, same shape). Dropping that pre-check — the core of
    ``load_events_with_problem`` — is what this test pins: the same scenario must now
    degrade to a reported note, never a crash.

    ``--watch-log``, not ``--trend``: ``history.record()`` calls ``secure_dir()`` first,
    which ``chmod``s the parent back to 0700 ("tighten in case the dir pre-existed with
    looser perms") BEFORE the read ever runs — a real first attempt at this test used
    ``--trend`` and the write silently healed the very permission it was meant to test.
    ``--watch-log`` never writes, so the chmod stands until the read.
    """
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    target = blocked / "ev.jsonl"
    target.write_text("{}\n", encoding="utf-8")
    os.chmod(blocked, 0o000)
    try:
        proc = _run(tmp_path, "--watch-log", "--events", str(target))
    finally:
        os.chmod(blocked, 0o700)  # restore so tmp_path cleanup can remove it
    assert proc.returncode == 0
    assert "note: --events:" in proc.stderr, proc.stderr
    assert "permission" in proc.stderr.lower(), proc.stderr


def test_a_hostile_history_path_reaches_stderr_sanitised(tmp_path):
    # Rooted under /nope (unwritable, like MISSING_HISTORY above), not /tmp: --trend's
    # write path (unlike --judged-bundle's read-only one, which is what B-562's sibling
    # test of this shape uses) calls secure_dir(), which CREATES missing directories —
    # so a hostile name under a writable /tmp would silently succeed instead of failing.
    hostile = "/nope/ev\x1b[31mRED\x1b[0m‮il​\x07/b\nundle.jsonl"
    proc = _run(tmp_path, "--trend", "--history", hostile)
    notes = [ln for ln in proc.stderr.splitlines() if "note: --history:" in ln]
    assert len(notes) == 1, proc.stderr
    assert "\x1b" not in notes[0]
    assert "‮" not in notes[0]
