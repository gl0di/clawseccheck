"""B-562: an unreadable ``--judged-bundle`` path is named, not silently emptied.

Sibling of B-561, which fixed the same shape for the three flags that read a verdicts
JSON. ``--judged-bundle`` reads through a different module and was left out of that change
on purpose — different bound, different buckets, and a consequence the other three do not
have.

``pipeline.read_judged_bundle`` did::

    try:
        raw = Path(path).expanduser().read_text(encoding="utf-8", errors="replace")
    except OSError:
        raw = ""

Measured on the real CLI before the fix::

    --full --judged-bundle /nope/bundle.json --json
    -> rc 0 · stdout 237236 B · stderr 0 B · the path appears 0 times on either stream

## Why this one is worse than B-561's three

The bundle carries FOUR buckets — ``attestation``, ``judged``, ``vetJudged``, ``liveTest``
— and an unreadable path empties all four at once. ``liveTest`` feeds
``scoring.compute``'s ``LIVE_INJECTION_CAP``, so a lost bundle is a lost score **cap**:
the run scores HIGHER than it should, silently. None of B-561's three flags can move the
score at all. ``attestation`` is resolved before ``audit()`` so B43/B44 can see it
(B-476), so a lost bundle also quietly changes those checks' inputs.

## Same shape as B-561, deliberately

One ``note:`` line to stderr naming the path and the reason. **stdout, the artifact and
the exit code are unchanged** — B-561's first attempt exited 1 instead and had to be
retracted because it broke a documented degradation, and the same reasoning applies here
with more force: an advisory bundle must never be able to perturb the audit.

`pipeline` returns the exception rather than a sentence. Its "never raises, degrade to
inert" contract is what lets an untrusted bundle be advisory at all, and the wording
belongs to the shell (`cli._describe_os_error`), which is the one classifier all five
call sites now share.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HOME = REPO_ROOT / "fixtures" / "home_vuln"

MISSING = "/nope/bundle.json"

# `--full` reports a real wall-clock duration per phase, so two runs of it differ by a
# couple of bytes at random. Normalised rather than ignored: an artifact comparison that
# silently tolerated ANY difference would pass while the change moved something real.
_ELAPSED = re.compile(r'"elapsed_s":\s*[0-9.eE+-]+')


def _run(tmp_path: Path, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--data-dir", str(tmp_path / "state"),
         "--home", str(HOME), "--no-history", *args],
        cwd=REPO_ROOT, capture_output=True, text=True, input=stdin)


def _stable(payload: str) -> str:
    return _ELAPSED.sub('"elapsed_s": 0', payload)


def _note_lines(stderr: str) -> list[str]:
    return [ln for ln in stderr.splitlines() if "--judged-bundle:" in ln]


# ------------------------------------------------------ an unreadable path is named


def test_an_unreadable_bundle_path_is_named_on_stderr(tmp_path):
    proc = _run(tmp_path, "--next", "--judged-bundle", MISSING)
    assert "bundle.json" in proc.stderr, "the path was never named"
    assert "no such file or directory" in proc.stderr
    assert "bundle.json" not in proc.stdout, "the diagnostic reached the JSON artifact"


def test_a_directory_is_reported_as_a_directory(tmp_path):
    proc = _run(tmp_path, "--next", "--judged-bundle", str(tmp_path))
    assert "is a directory, not a bundle file" in proc.stderr, proc.stderr[:200]


def test_the_note_names_what_was_lost_not_just_that_something_was(tmp_path):
    """`liveTest` carries a score cap, so "nothing was applied" understates the loss —
    the run scores higher than it should. The buckets are named for that reason."""
    stderr = _run(tmp_path, "--next", "--judged-bundle", MISSING).stderr
    for phrase in ("attestation", "judge verdicts", "live-test signal", "score cap"):
        assert phrase in stderr, f"the note never mentions {phrase!r}: {stderr[:300]!r}"


def test_the_note_fires_once_per_run_in_every_mode_that_reads_the_bundle(tmp_path):
    """`cli._judged_bundle` memoizes per path and three separate readers consult it in one
    `--full` run (B-476). Emitting inside the cache-miss branch is what keeps one failure
    from reading as three.

    Every bundle-reading mode is checked, not just `--full`: the first C-135 pass on this
    change measured `--full` alone and left the other four `not-reached`, and "one reader
    happened to run" is not the same fact as "the cache holds".
    """
    for mode in (["--full", "--json"], ["--next"], ["--percentile"], ["--trend"],
                 ["--monitor"]):
        proc = _run(tmp_path, *mode, "--judged-bundle", MISSING)
        notes = _note_lines(proc.stderr)
        assert len(notes) == 1, f"{' '.join(mode)} emitted {len(notes)} notes: {notes}"


def test_an_empty_path_says_so_instead_of_blaming_the_current_directory(tmp_path):
    """**The C-135 break.** `Path("")` normalizes to `Path(".")`, so an empty argument
    reads the CURRENT DIRECTORY and the OS reports on that. The note read

        note: --judged-bundle: : is a directory, not a bundle file.

    naming nothing and blaming a path the user never typed. Reachable only here: an empty
    value for `--judged`/`--propose-ignore` is rejected up front by
    `_VALUE_REQUIRED_MODES`, which can do that because those two are primary MODES, while
    `--judged-bundle` modifies a run rather than being one.
    """
    proc = _run(tmp_path, "--next", "--judged-bundle", "")
    notes = _note_lines(proc.stderr)
    assert len(notes) == 1, notes
    assert "no path was given" in notes[0], notes[0]
    assert "is a directory" not in notes[0], "still blaming the current directory"
    assert "--judged-bundle: :" not in notes[0], "still rendering an empty path slot"


def test_a_hostile_bundle_path_reaches_stderr_sanitised(tmp_path):
    """The path is user-supplied and lands on a terminal. ANSI, BEL, a bidi override and a
    zero-width space must not survive, and the note must stay one line."""
    hostile = "/tmp/ev\x1b[31mRED\x1b[0m‮il​\x07/b\nundle.json"
    proc = _run(tmp_path, "--next", "--judged-bundle", hostile)
    notes = _note_lines(proc.stderr)
    assert len(notes) == 1, notes
    for name, ch in (("ESC", "\x1b"), ("BEL", "\x07"), ("U+202E", "‮"),
                     ("U+200B", "​")):
        assert ch not in proc.stderr, f"{name} survived into stderr"


# --------------------------------------- the artifact and exit code are UNCHANGED


def test_the_artifact_and_exit_code_do_not_move(tmp_path):
    """Pinned against a control bundle that exists and yields the same four empty buckets,
    so this cannot drift into a behaviour change. B-561's first attempt exited 1 and
    emitted nothing; an advisory bundle must never be able to perturb the audit."""
    control = tmp_path / "inert.json"
    control.write_text("{}", encoding="utf-8")
    missing = _run(tmp_path, "--full", "--json", "--judged-bundle", MISSING)
    baseline = _run(tmp_path, "--full", "--json", "--judged-bundle", str(control))
    assert missing.returncode == baseline.returncode
    assert _stable(missing.stdout) == _stable(baseline.stdout), (
        "an unreadable bundle changed the artifact")
    assert missing.stdout, "the run emitted nothing at all — that is the retracted shape"


# --------------------------------------------- a payload problem is a different fact


def test_a_readable_but_garbage_bundle_stays_quiet(tmp_path):
    """`split_judged_bundle` degrades any malformed payload to absent buckets and says
    nothing. That is a statement about the PAYLOAD; this task is about there being no
    payload. The path note must not leak onto it."""
    junk = tmp_path / "junk.json"
    junk.write_text("not json at all", encoding="utf-8")
    proc = _run(tmp_path, "--next", "--judged-bundle", str(junk))
    assert _note_lines(proc.stderr) == [], proc.stderr[:300]


def test_a_mode_that_never_reads_the_bundle_claims_no_path_problem(tmp_path):
    """`--json` without `--full` already says the flag has no effect, and never opens the
    file. It must not then report a problem with a path it did not touch — the note has to
    follow the read, not the flag."""
    proc = _run(tmp_path, "--json", "--judged-bundle", MISSING)
    assert _note_lines(proc.stderr) == [], proc.stderr[:300]
    assert "has no effect without --full" in proc.stderr


# --------------------------------------------- everything that already worked, unchanged


def test_a_real_bundle_still_applies(tmp_path):
    """The regression guard: the fix is on the path every successful bundle run goes
    through."""
    bundle = tmp_path / "bundle.json"
    bundle.write_text(json.dumps({"attestation": {"schema": "x"}}), encoding="utf-8")
    proc = _run(tmp_path, "--next", "--judged-bundle", str(bundle))
    assert proc.returncode == 0, proc.stderr[:300]
    assert _note_lines(proc.stderr) == []


def test_stdin_is_untouched(tmp_path):
    proc = _run(tmp_path, "--next", "--judged-bundle", "-",
                stdin=json.dumps({"attestation": {"schema": "x"}}))
    assert proc.returncode == 0, proc.stderr[:300]
    assert _note_lines(proc.stderr) == [], "reading stdin produced a path note"


def test_read_judged_bundle_keeps_its_signature_and_its_result(tmp_path):
    """The public reader is unchanged and now delegates. Asserted directly because
    `tests/test_f153_pipeline.py` pins its contract and a silent signature change there
    would be a library-level break, not just a CLI one."""
    from clawseccheck import pipeline as pl

    good = tmp_path / "b.json"
    good.write_text(json.dumps({"judged": {"a": 1}}), encoding="utf-8")
    assert pl.read_judged_bundle(str(good))["judged"] == {"a": 1}

    bundle, problem = pl.read_judged_bundle_with_problem(str(good))
    assert problem is None
    assert bundle == pl.read_judged_bundle(str(good))

    bundle, problem = pl.read_judged_bundle_with_problem(str(tmp_path / "nope.json"))
    assert isinstance(problem, OSError), "the reason for the failed read was discarded"
    assert bundle == pl.read_judged_bundle(str(tmp_path / "nope.json"))


# ------------------------------------------------------- --apply-ignore-proposals


def test_apply_ignore_proposals_names_the_path(tmp_path):
    """It always reported and exited 1, so it was never silent — but it printed only the
    exception CLASS ("could not read proposals file (FileNotFoundError)"), so the user
    could not tell WHICH path failed, which is the half of B-561 that mattered."""
    proc = _run(tmp_path, "--apply-ignore-proposals", "/nope/props.json")
    combined = proc.stdout + proc.stderr
    assert "/nope/props.json" in combined, combined[:300]
    assert "no such file or directory" in combined
    assert "FileNotFoundError" not in combined, "still leaking the exception class name"
    assert proc.returncode == 1


def test_apply_ignore_proposals_keeps_its_other_diagnostics(tmp_path):
    """The path message must not swallow the payload ones — same separation B-561 kept."""
    bad = tmp_path / "props.json"
    bad.write_text("not json", encoding="utf-8")
    proc = _run(tmp_path, "--apply-ignore-proposals", str(bad))
    assert "not valid JSON" in proc.stdout + proc.stderr
    assert proc.returncode == 1
