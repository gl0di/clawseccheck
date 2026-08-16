"""B-561: a judge-verdicts path that could not be read is named, not silently emptied.

Three flags take a user-supplied path to a judge-verdicts JSON, and all three did::

    try:
        verdicts_raw = Path(args.X).expanduser().read_text(encoding="utf-8")
    except OSError:
        verdicts_raw = ""

so a typo produced an empty payload and **the path was never named** — not on stdout, not
on stderr, not once, in any of the three.

## What this fix does NOT do, and why that matters

It does not change stdout, the artifact, or the exit code. `docs/OUTPUT_SCHEMA.md` §13
promises that an unreadable PATH "stays quiet: those genuinely are 'no verdicts
submitted'", `adjudication._payload_carries_content` says the same in code, and three
tests assert the resulting behaviour by name
(`test_cli_judged_flag_missing_file_still_renders_report`,
`test_cli_vet_judged_missing_file_leaves_verdict_unchanged`, and two in `test_risk.py`).

The first attempt at B-561 refused to run and exited 1. It broke all three of those and
would have destroyed the `--vet` verdict the user also asked for — a documented
degradation traded away for a diagnostic that fits on stderr. Retracted.

## What survives, and why it is still a real defect

The doc's own justification names the distinction it is drawing: the existing `note:`
exists to tell "0 of N applied" apart from "no verdicts submitted". An unreadable path is
a **third** case that dichotomy has no room for. An empty payload is a statement — the
judge submitted nothing. An unreadable path is the ABSENCE of one: nothing at all is known
about what the judge decided, and the user believes they said something.

`adjudication` cannot draw that line — by the time it sees `""` the reason is gone. The
CLI can, because it did the read. So the split lives there, and the parser's contract is
untouched.

`--vet-judged` is why it is worth drawing at all. Measured on the real CLI, its output on
an unreadable path is **byte-identical** to a run with no `--vet-judged` at all AND to one
with an explicit `"verdicts": []` — zero keys anywhere name the judge. Since it is
escalate-only, what goes missing is an escalation, so the verdict shown is too LENIENT for
a skill the user is deciding whether to install. `--judged` is the mild case by contrast:
its artifact self-describes, annotating all 87 items "not yet reviewed by a judge".

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "fixtures"
HOME = FIXTURES / "home_vuln"
VET_TARGET = FIXTURES / "bad_b61_curl_exfil_config" / "skills" / "leaker"

MISSING = "/nope/typo.json"


def _run(tmp_path: Path, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--data-dir", str(tmp_path / "state"),
         *args],
        cwd=REPO_ROOT, capture_output=True, text=True, input=stdin)


def _audit(tmp_path: Path, *args: str, **kw) -> subprocess.CompletedProcess:
    return _run(tmp_path, "--home", str(HOME), "--no-history", *args, **kw)


def _vet(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    return _run(tmp_path, "--vet-skill", str(VET_TARGET), "--json", *args)


def _flags_reading_a_verdicts_path() -> list[str]:
    """Derived from the call sites, not hard-coded: a later reader wired through the same
    helper is covered by these tests without this file being edited.

    **Not exhaustive, and deliberately so — read this before trusting it.** It enumerates
    what goes through `_verdicts_with_note`, which is not the same question as "every flag
    that reads a user-named judge file". Two siblings are knowingly outside it:

    * `--judged-bundle` reads through `pipeline.read_judged_bundle`, which has the same
      `except OSError: raw = ""` shape. Measured: an unreadable path yields rc 0, 237 KB
      of stdout and a byte-empty stderr, with all four buckets (`judged`, `vetJudged`,
      `attestation`, `liveTest`) silently empty — and `liveTest` feeds `scoring.compute`'s
      cap. A separate module, a separate bound, and a score consequence these three do not
      have, so it is a separate task rather than an append to this one.
    * `--apply-ignore-proposals` already reports and exits 1, but prints only the exception
      CLASS (`could not read proposals file (FileNotFoundError)`) and never the path.

    Recorded here because this helper returning three flags could otherwise be read as
    proof that three is all there are.
    """
    source = (REPO_ROOT / "clawseccheck" / "cli.py").read_text(encoding="utf-8")
    found = re.findall(r'_verdicts_with_note\([^,]+,\s*"(--[a-z-]+)"\)', source)
    assert found, "no _verdicts_with_note call sites found — did the helper get renamed?"
    return sorted(set(found))


def _invoke(tmp_path: Path, flag: str, value: str) -> subprocess.CompletedProcess:
    """The one invocation shape each flag needs, so the tests below can loop over the
    derived flag list instead of naming three call shapes each time."""
    if flag == "--vet-judged":
        return _vet(tmp_path, flag, value)
    return _audit(tmp_path, flag, value)


def _packet_verdicts(tmp_path: Path, limit: int = 3) -> dict:
    """A correctly-shaped payload built from a real packet: a dict with a top-level
    `verdicts` array, which is what `_parse_verdicts` accepts. A bare list is silently
    unusable — that is the payload-shape case, not this task's."""
    proc = _audit(tmp_path, "--judge-packet")
    doc = json.loads(proc.stdout)
    packet = doc["judgePacket"] if isinstance(doc, dict) else doc
    items = packet if isinstance(packet, list) else packet.get("items", [])
    return {"verdicts": [
        {"finding_id": i["finding_id"], "target": i["target"], "verdict": "SAFE",
         "reason": "reviewed"} for i in items[:limit]]}


# --------------------------------------------------- an unreadable path is named, on stderr


def test_every_verdicts_flag_names_a_path_it_could_not_read(tmp_path):
    for flag in _flags_reading_a_verdicts_path():
        proc = _invoke(tmp_path, flag, MISSING)
        assert "typo.json" in proc.stderr, f"{flag} never named the path it could not read"
        assert flag in proc.stderr, f"{flag}'s note does not say which flag it came from"
        assert "typo.json" not in proc.stdout, (
            f"{flag} put the diagnostic on stdout, which carries the JSON artifact")


def test_a_directory_is_reported_as_a_directory(tmp_path):
    """Distinguished from "no such file" because it is a different mistake."""
    proc = _audit(tmp_path, "--judged", str(tmp_path))
    assert "is a directory" in proc.stderr, proc.stderr[:200]


def test_the_loud_failures_stay_loud(tmp_path):
    """**The C-135 break, and the correction it forced.**

    Two path shapes miss the `except OSError` family: a `~user` prefix naming no such
    user raises `RuntimeError`, and an existing file holding invalid UTF-8 raises
    `UnicodeDecodeError`. A draft of this fix caught the first one so the note could
    cover it. Measured against HEAD, that turned `rc 1` / 0 B of stdout into `rc 0` and a
    185 KB report — a LOUD failure made quiet, which is the reverse of what B-561 is for,
    and it moved the two things the narrowed fix promises not to move.

    So they stay loud, and this pins that rather than the nicer-sounding alternative. The
    path is not named in either, which is a real limitation of the crash handler and a
    separate change.
    """
    bad_bytes = tmp_path / "bad-encoding.json"
    bad_bytes.write_bytes(b'{"verdicts": [\xff\xfe]}')
    for value in ("~nosuchuser42/x.json", str(bad_bytes)):
        proc = _audit(tmp_path, "--judged", value)
        assert proc.returncode != 0, f"{value!r} degraded into a successful run"
        assert proc.stdout == "", (
            f"{value!r} emitted an artifact for input it could not read: "
            f"{len(proc.stdout)} B")
        assert "Traceback" not in proc.stderr


# ------------------------------------- the documented quiet cases STAY quiet (the retraction)


def test_a_genuinely_empty_payload_stays_quiet(tmp_path):
    """OUTPUT_SCHEMA §13: an empty payload genuinely IS "no verdicts submitted". The note
    added by this task must not leak onto it — that would destroy the very distinction the
    diagnostic exists to draw."""
    empty = tmp_path / "empty.json"
    empty.write_text("", encoding="utf-8")
    proc = _audit(tmp_path, "--judged", str(empty))
    assert proc.stderr == "", f"an empty payload became loud: {proc.stderr[:200]!r}"


def test_an_explicitly_empty_verdicts_array_stays_quiet(tmp_path):
    payload = tmp_path / "none.json"
    payload.write_text(json.dumps({"verdicts": []}), encoding="utf-8")
    for flag in ("--judged", "--propose-ignore"):
        proc = _audit(tmp_path, flag, str(payload))
        assert proc.stderr == "", f'{flag}: "verdicts": [] became loud: {proc.stderr[:200]!r}'


def test_vet_judged_is_the_documented_exception_to_that(tmp_path):
    """`--vet-judged` rejects any payload whose `targetFingerprint` is missing (§15), so
    even `{"verdicts": []}` is reported there. Pinned because the §13 paragraph this task
    edited claimed the quiet rule covered all three consumers — it never did, in this tree
    or before it, and editing the paragraph without checking would have left a false half
    sitting next to a corrected one."""
    payload = tmp_path / "none.json"
    payload.write_text(json.dumps({"verdicts": []}), encoding="utf-8")
    stderr = _vet(tmp_path, "--vet-judged", str(payload)).stderr
    assert "targetFingerprint" in stderr, stderr[:300]
    assert "no such file" not in stderr, "the path note fired for a payload that WAS read"


def test_the_payload_shape_note_is_a_different_note(tmp_path):
    """A non-empty but unusable payload keeps B-330's own diagnostic. The two are separate
    facts — "what you sent was rejected" vs "nothing arrived" — and must not collapse into
    one message."""
    bad = tmp_path / "bad.json"
    bad.write_text("not json at all", encoding="utf-8")
    shape = _audit(tmp_path, "--judged", str(bad)).stderr
    path = _audit(tmp_path, "--judged", MISSING).stderr
    assert "produced no usable entries" in shape, shape[:300]
    assert "produced no usable entries" not in path, path[:300]
    assert "no such file" in path and "no such file" not in shape


# ------------------------- stdout / exit code / artifact are UNCHANGED (this is the point)


def test_the_artifact_and_exit_code_do_not_move(tmp_path):
    """The retracted first attempt exited 1 and emitted nothing. Pinned against a control
    run so this cannot drift back into a behaviour change: for every flag, an unreadable
    path must produce the SAME stdout and rc as the documented "no verdicts submitted"
    baseline it degrades to."""
    control = tmp_path / "none.json"
    control.write_text(json.dumps({"verdicts": []}), encoding="utf-8")
    for flag in _flags_reading_a_verdicts_path():
        missing = _invoke(tmp_path, flag, MISSING)
        baseline = _invoke(tmp_path, flag, str(control))
        assert missing.returncode == baseline.returncode, (
            f"{flag} changed its exit code for an unreadable path "
            f"({missing.returncode} vs {baseline.returncode})")
        assert missing.stdout == baseline.stdout, (
            f"{flag} changed its stdout artifact for an unreadable path")
        assert missing.stdout, f"{flag} emitted nothing at all — that is the retracted fix"


# --------------------------------------------- everything that already worked, unchanged


def test_a_valid_payload_still_applies(tmp_path):
    """The regression guard: the helper is on the path every successful judging run
    goes through."""
    payload = tmp_path / "verdicts.json"
    payload.write_text(json.dumps(_packet_verdicts(tmp_path)), encoding="utf-8")
    proc = _audit(tmp_path, "--judged", str(payload))
    assert proc.returncode == 0, proc.stderr[:300]
    assert proc.stdout.count('"judge_verdict": "SAFE"') == 3, (
        "a correctly-shaped payload stopped applying")


def test_stdin_is_untouched(tmp_path):
    payload = json.dumps(_packet_verdicts(tmp_path))
    proc = _audit(tmp_path, "--judged", "-", stdin=payload)
    assert proc.returncode == 0, proc.stderr[:300]
    assert proc.stdout.count('"judge_verdict": "SAFE"') == 3
    assert proc.stderr == "", "reading stdin produced a path note"


def test_vet_judged_still_reaches_its_verdict(tmp_path):
    """`--vet-judged` is escalate-only, so what an unreadable path loses is an ESCALATION
    — the too-lenient direction. Its verdict must still be rendered either way."""
    proc = _vet(tmp_path, "--vet-judged", MISSING)
    assert json.loads(proc.stdout)["verdict"] == "DO-NOT-INSTALL", proc.stdout[:300]
