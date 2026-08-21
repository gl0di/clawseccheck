"""B-606: the PDF path was relayed as a markdown link, so it rendered as a dead link.

Dave clicked the PDF in the Control UI and nothing happened. DOM inspection of session
`csc-b605-d` showed an `<a>` with **no href attribute at all** -- styled as a link, inviting
a click, doing nothing. The host had written a markdown link around a LOCAL PATH:

    Full report: [clawseccheck-report.pdf](/…/clawseccheck-report.pdf)

and the client correctly refuses to give a local filesystem path an href, leaving the anchor
inert. The host's behaviour is right; ours was not.

`_emit_attach_instruction` already said "Never write a link or a URL". What was written has
no scheme and no host, so an agent reading "URL" as `scheme://host/…` need not have seen
either -- the clause named the category and never the syntax.

Why this is expected to work where B-605's eight attempts did not: measured across seven
live runs, four hosts wrote the path as inline code and three wrote a markdown link. The
agent is choosing between two forms with no stated preference and getting it right about
half the time. That is a gap in the instruction, not a refusal of it.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
VULN = str(REPO_ROOT / "fixtures" / "home_vuln")


def _note(tmp_path: Path, store: str = "state") -> str:
    fake_home = tmp_path / "home"
    fake_home.mkdir(exist_ok=True)
    proc = subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", VULN, "--no-history",
         "--data-dir", str(tmp_path / store), "--dashboard",
         "--pdf", str(tmp_path / f"{store}.pdf")],
        cwd=REPO_ROOT, capture_output=True, text=True,
        env={**os.environ, "HOME": str(fake_home)})
    return proc.stderr


# ------------------------------------------------------------ it names the syntax, not a category

def test_the_note_names_markdown_link_syntax(tmp_path):
    """The whole defect. "A link or a URL" is a category; `[name](path)` is what was
    actually written, and an agent classifying "URL" as scheme://host need not read a bare
    local path inside brackets as either."""
    note = _note(tmp_path)
    assert "Markdown link syntax counts as a link" in note, note[:600]
    assert "[report.pdf](path)" in note, note[:600]


def test_the_note_names_the_form_that_works(tmp_path):
    """Naming only what is forbidden leaves the agent to invent the alternative -- and one
    of the two forms it invents is the broken one. Four of seven live runs used inline code
    and it renders correctly, so the note says so rather than leaving it to chance."""
    note = _note(tmp_path, store="s2")
    assert "plain text or inline code" in note
    assert "never as a link" in note


def test_the_note_explains_why_the_link_dies(tmp_path):
    """B-595's own lesson: "there is none" did not stop two hosts from writing one. A rule
    with its mechanism attached is checkable by the reader; a bare prohibition is not."""
    note = _note(tmp_path, store="s3")
    assert "strips the href" in note
    assert "local path" in note


# ---------------------------------------------------------------- it does not weaken B-595

def test_b595_pinned_phrases_all_survive(tmp_path):
    """The extension sits beside the existing clause and must not displace it. These are the
    exact strings `test_b595_attach_fallback.py` pins; a regression here would be silent."""
    note = _note(tmp_path, store="s4")
    for phrase in ("attach this PDF file itself", "that is the deliverable",
                   "cannot attach files", "name the path",
                   "just never as the deliverable",
                   "Never write a link or a URL", "broken"):
        assert phrase in note, phrase
    assert "do not re-render" in note.lower()


def test_the_note_still_contains_no_url_of_its_own(tmp_path):
    """The note argues that no URL exists; one appearing inside it would be self-refuting,
    and the illustrative example is deliberately `[report.pdf](path)` with no real path."""
    note = _note(tmp_path, store="s5")
    assert not re.search(r"https?://", note), note[:400]
    assert "file://" not in note


def test_the_note_stays_on_stderr(tmp_path):
    """Agent-directed advice must not land in the card the user is shown."""
    fake_home = tmp_path / "home"
    fake_home.mkdir(exist_ok=True)
    proc = subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", VULN, "--no-history",
         "--data-dir", str(tmp_path / "s6"), "--dashboard", "--pdf", str(tmp_path / "o.pdf")],
        cwd=REPO_ROOT, capture_output=True, text=True,
        env={**os.environ, "HOME": str(fake_home)})
    assert "Markdown link syntax" not in proc.stdout


# ------------------------------------------------------------------------ the docs agree

def test_skill_md_names_the_syntax_too():
    """C-125. The doc carried the same category-only wording, so it had the same gap."""
    flat = " ".join((REPO_ROOT / "SKILL.md").read_text(encoding="utf-8").split())
    assert "Markdown link syntax counts" in flat
    assert "[report.pdf](path)" in flat


def test_cli_flags_reference_names_the_syntax_too():
    flat = " ".join((REPO_ROOT / "references" / "cli-flags.md").read_text(encoding="utf-8").split())
    assert "Markdown link syntax counts as a link" in flat
    assert "plain text or inline code" in flat
