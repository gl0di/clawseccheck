"""B-595: the attach note left a host that cannot attach with no compliant move.

B-468 found a host agent answering "attach this file" with a link — twice — and fixed it by
moving the instruction off stdout, on the theory that it had been swept along in text the
agent was told to reproduce verbatim. Driving the live agent on 2026-08-20 showed the theory
was incomplete. The note was on stderr, both hosts read it, and:

* GPT-5.6 Luna wrote ``Full report: report.pdf`` — rendered ``<a href="/report.pdf">``. The
  Control UI's SPA catch-all answers that with its own index page: ``200 text/html``, 14 406
  bytes. A link to nothing, standing in for the artifact the whole ``--full`` pipeline exists
  to produce.
* GPT-5.6 Sol obeyed the note instead — said the interface could not attach, and gave the
  user nothing to open, because the note forbade naming the path too.

Both are the same defect seen from either side: the note said *"Do not paste its path, do not
send a link"*, and for a channel with no file attachment those are the only two moves there
are. Told it may say neither, one host invented the more helpful-looking one.

It was also stricter than the guidance it implements. `SKILL.md` bans pasting the path "as if
it were the deliverable" and says what to do instead; the note flattened that to an absolute
ban and dropped the fallback — and because B-468 put it at the moment of the decision, the
flattened version is the one that won.

So this file pins the PROPERTY, not the prose: on every branch the host has exactly one
correct thing it may do, and a link is never it.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
VULN = str(REPO_ROOT / "fixtures" / "home_vuln")


def _run(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", VULN,
         "--data-dir", str(tmp_path / "state"), "--no-history", *args],
        cwd=REPO_ROOT, capture_output=True, text=True)


def _note(tmp_path: Path, dest: Path, *extra: str) -> str:
    """The note is emitted from the `--dashboard` branch only — a standalone `--pdf` keeps
    its pre-existing, byte-identical behaviour (B-530), so it is `--dashboard --pdf` that
    puts the instruction in front of a host agent."""
    proc = _run(tmp_path, "--dashboard", *extra, "--pdf", str(dest))
    assert dest.exists(), proc.stderr[:300]
    hits = [blk for blk in proc.stderr.split("note: ") if "attach this PDF file itself" in blk]
    assert len(hits) == 1, proc.stderr
    return hits[0]


# --------------------------------------------------------------- the missing branch

def test_a_host_that_cannot_attach_is_told_what_it_may_do(tmp_path):
    """The whole defect: before this, the note answered "then what?" with silence."""
    note = _note(tmp_path, tmp_path / "r.pdf")
    assert "cannot attach files" in note
    assert "name the path" in note


def test_the_path_is_absolute_and_present(tmp_path):
    """A relative name is what became `href="/report.pdf"`. The fallback is only usable if
    what the host is invited to name is openable."""
    dest = tmp_path / "r2.pdf"
    note = _note(tmp_path, dest)
    assert str(dest) in note
    assert Path(str(dest)).is_absolute()


def test_attaching_is_still_first(tmp_path):
    """C-135's trap here: offering a fallback must not demote the primary. If a host reads
    "name the path" before "attach the file", the fix trades a broken link for a lazier
    answer on channels that could have attached."""
    note = _note(tmp_path, tmp_path / "r3.pdf")
    assert note.index("attach this PDF file itself") < note.index("name the path")
    assert "that is the deliverable" in note


def test_the_fallback_is_conditional_not_an_alternative(tmp_path):
    """It must read as "only if you cannot", never as a free choice — a path is useless to
    someone reading from a phone, which is why the absolute ban existed in the first place
    (see references/cli-flags.md)."""
    note = _note(tmp_path, tmp_path / "r4.pdf")
    fallback = note[note.index("cannot attach files"):]
    assert "just never as the deliverable" in fallback


# ------------------------------------------------------- the half that was always right

def test_links_are_still_forbidden_and_now_say_why(tmp_path):
    """"there is none" did not stop either host from writing one. The note now states the
    consequence, which is the part a model can check its own output against."""
    note = _note(tmp_path, tmp_path / "r5.pdf")
    assert "Never write a link or a URL" in note
    assert "broken" in note


def test_the_note_never_contains_a_url_shaped_string(tmp_path):
    """Belt and braces: the instruction that bans links must not itself model one."""
    note = _note(tmp_path, tmp_path / "r6.pdf")
    assert not re.search(r"https?://", note), note


def test_re_rendering_is_still_forbidden(tmp_path):
    """The card is the chat-sized overview; the PDF is the detail. C-374 sized them that way
    deliberately, so "paste the whole report instead" is not an accepted fallback."""
    note = _note(tmp_path, tmp_path / "r7.pdf")
    # Case-insensitive on purpose: this clause is UNCHANGED by B-595 and the pre-fix note
    # carried it too. Keying on the capitalisation would make this assert my wording rather
    # than the rule, and it would then "catch" a reversion for the wrong reason.
    assert "do not re-render" in note.lower()


# ---------------------------------------------------- B-468's guarantee is not weakened

def test_the_instruction_stays_off_stdout(tmp_path):
    """B-468's actual fix, which remains necessary even though it was not sufficient:
    stdout is pasted verbatim, so an instruction addressed to the agent must not be in it."""
    dest = tmp_path / "r8.pdf"
    proc = _run(tmp_path, "--dashboard", "--pdf", str(dest))
    assert "attach this PDF file itself" not in proc.stdout
    assert "attach this PDF file itself" in proc.stderr


def test_stdout_is_byte_identical_with_and_without_the_note(tmp_path):
    """The note grew from one line to four. If any of it had leaked into stdout, the card a
    host pastes would have changed — which is the failure B-468 was filed for."""
    a = _run(tmp_path, "--dashboard", "--pdf", str(tmp_path / "a.pdf")).stdout
    b = _run(tmp_path, "--dashboard", "--pdf", str(tmp_path / "b.pdf")).stdout
    assert a == b
    assert "note:" not in a


# ------------------------------------------------------ the shipped docs say the same

def test_skill_md_and_the_note_agree_about_the_fallback():
    """The note was stricter than `SKILL.md` and dropped its fallback; that mismatch is the
    root cause, so it is asserted rather than left to the next reader to notice."""
    skill = (REPO_ROOT / "SKILL.md").read_text(encoding="utf-8")
    flat = " ".join(skill.split())          # the source is hard-wrapped
    assert "name the path so the user can open it themselves" in flat
    assert "any link you write will simply be broken" in flat


def test_no_shipped_doc_still_bans_the_path_outright():
    """`docs/USAGE.md` and `references/cli-flags.md` both carried the absolute form. If one
    reverts, a host reading that doc is back to having no compliant move."""
    for rel in ("docs/USAGE.md", "references/cli-flags.md"):
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        assert "don't paste the path" not in text, rel
        assert "never\n  paste its path" not in text, rel


def test_all_three_invocation_shapes_emit_the_same_note(tmp_path):
    """`_emit_attach_instruction` has three call sites — the deferred rider path, plain
    `--dashboard`, and `--dashboard --full`. B-530 exists because one of them once wrote
    the file and said nothing. A four-line note is only a fix on the paths that print it."""
    seen = set()
    for i, extra in enumerate(([], ["--full"], ["--trend"])):
        note = _note(tmp_path, tmp_path / f"m{i}.pdf", *extra)
        seen.add(note.split("—", 1)[1].strip())     # everything after the path
    assert len(seen) == 1, seen
