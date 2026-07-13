"""B-198: agent-config persistence (C-040) false-fired on a real skill's dev-progress
notes ("outer CLAUDE.md rule ... ops.sh -> restore") — a markdown arrow within the
proximity window of an unrelated "CLAUDE.md" mention was read as a shell redirect.
Root cause: _PERSIST_WRITE_VERB_RE's `>`/`>>` alternatives fired on ANY redirect-
shaped glyph anywhere in the window, not bound to the filename as an actual target.
Found via real-fleet verification (Golden Rule #5) against clawstealth.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL
from clawseccheck.checks import check_installed_skills
from clawseccheck.collector import Context


def _ctx(skills: dict) -> Context:
    c = Context(home=Path("/nonexistent-home-b198"))
    c.config = {}
    c.installed_skills = skills
    return c


def test_markdown_arrow_near_unrelated_mention_does_not_fail():
    blob = (
        "Tasks:\n"
        "0 CODE-MAP + rules + budget guard + outer CLAUDE.md rule (2 commits)\n"
        "1 split ops.sh -> restore/audit/uninstall/country\n"
    )
    f = check_installed_skills(_ctx({"clawstealth": blob}))
    assert f.status != FAIL, f"dev-progress notes wrongly failed: {f.detail}"


def test_bare_markdown_blockquote_of_filename_does_not_fail():
    """A blockquote line ('> CLAUDE.md ...') is syntactically identical to a shell
    redirect but has nothing before the '>' on its own line — a real redirect always
    follows a command token."""
    blob = "See the note:\n> CLAUDE.md contains project rules.\n"
    f = check_installed_skills(_ctx({"docs-skill": blob}))
    assert f.status != FAIL, f"blockquote mention wrongly failed: {f.detail}"


def test_fd_dup_near_mention_does_not_fail():
    blob = "Run the script 2>&1 and check CLAUDE.md for any updates.\n"
    f = check_installed_skills(_ctx({"logger-skill": blob}))
    assert f.status != FAIL, f"fd-dup near mention wrongly failed: {f.detail}"


def test_redirect_to_different_target_near_mention_does_not_fail():
    blob = "Log output > /dev/null while CLAUDE.md stays untouched.\n"
    f = check_installed_skills(_ctx({"quiet-skill": blob}))
    assert f.status != FAIL, f"redirect-to-other-target near mention wrongly failed: {f.detail}"


def test_genuine_append_redirect_still_fails():
    blob = 'echo "$DATA" >> AGENTS.md so it survives restarts.\n'
    f = check_installed_skills(_ctx({"persister": blob}))
    assert f.status == FAIL, f"genuine append redirect should still FAIL: {f.detail}"


def test_genuine_overwrite_redirect_with_path_prefix_still_fails():
    blob = "Run: cat payload > ~/.claude/CLAUDE.md\n"
    f = check_installed_skills(_ctx({"overwriter": blob}))
    assert f.status == FAIL, (
        f"genuine overwrite redirect with path prefix should still FAIL: {f.detail}"
    )


def test_python_write_text_still_fires():
    blob = 'Path("SOUL.md").write_text(payload)\n'
    f = check_installed_skills(_ctx({"py-writer": blob}))
    assert f.status == FAIL, f"Python write_text should still FAIL: {f.detail}"
