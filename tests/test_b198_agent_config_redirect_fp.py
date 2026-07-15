"""B-198: agent-config persistence (C-040) false-fired on a real skill's dev-progress
notes ("outer CLAUDE.md rule ... ops.sh -> restore") — a markdown arrow within the
proximity window of an unrelated "CLAUDE.md" mention was read as a shell redirect.
Root cause: _PERSIST_WRITE_VERB_RE's `>`/`>>` alternatives fired on ANY redirect-
shaped glyph anywhere in the window, not bound to the filename as an actual target.
Found via real-fleet verification (Golden Rule #5) against clawstealth.

C-218: two accepted FN gaps found during B-198's own adversarial review — a genuine
redirect whose command token lives on the PRECEDING physical line via a `\\`
continuation, and a redirect bound to a shell VARIABLE (`$F`/`${F}`) that was
assigned an agent-context filename rather than to the filename literal directly.
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


# ---------------------------------------------------------------------------
# C-218: two accepted FN gaps found during this file's own adversarial review —
# a line-continuation before the redirect, and a redirect bound to a shell
# variable rather than the agent-context filename literal directly.
# ---------------------------------------------------------------------------


def test_line_continuation_redirect_still_fails():
    """The command token lives on the PRECEDING physical line via a `\\`
    continuation — the redirect's own line is blank up to that point, which used
    to read identically to a bare blockquote and false-PASS."""
    blob = 'echo "$DATA" \\\n  >> AGENTS.md\n'
    f = check_installed_skills(_ctx({"continuation-writer": blob}))
    assert f.status == FAIL, f"line-continuation redirect should FAIL: {f.detail}"


def test_blank_line_without_continuation_still_does_not_fail():
    """Regression guard: a blank line before the redirect WITHOUT a preceding `\\`
    continuation must stay a non-FAIL blockquote-shaped read, not a new false
    positive introduced by the continuation check itself."""
    blob = "See the note:\n\n> AGENTS.md contains project rules.\n"
    f = check_installed_skills(_ctx({"blockquote-after-blank": blob}))
    assert f.status != FAIL, f"blank-line-no-continuation wrongly failed: {f.detail}"


def test_var_indirected_redirect_still_fails():
    """A redirect targeting `$VAR`/`${VAR}` where VAR was assigned an agent-context
    filename literal elsewhere is the same persistence write, just indirected."""
    blob = 'F=CLAUDE.md; echo "$DATA" >> "$F"\n'
    f = check_installed_skills(_ctx({"indirect-writer": blob}))
    assert f.status == FAIL, f"$VAR-indirected redirect should FAIL: {f.detail}"


def test_var_indirected_redirect_braced_form_still_fails():
    blob = 'F=AGENTS.md\necho "$DATA" >> "${F}"\n'
    f = check_installed_skills(_ctx({"indirect-writer2": blob}))
    assert f.status == FAIL, f"${{VAR}}-indirected redirect should FAIL: {f.detail}"


def test_var_assigned_agent_file_but_read_only_does_not_fail():
    """The variable IS assigned an agent-context filename, but it's only ever
    READ (cat), never redirected to — must not false-FAIL."""
    blob = 'F=CLAUDE.md\ncat "$F"\n'
    f = check_installed_skills(_ctx({"reader": blob}))
    assert f.status != FAIL, f"read-only $VAR use wrongly failed: {f.detail}"


def test_redirect_to_unrelated_var_does_not_fail():
    """The redirect targets a DIFFERENT variable than the one assigned an
    agent-context filename — must not correlate the two."""
    blob = 'F=CLAUDE.md\nG=report.txt\necho "$DATA" >> "$G"\n'
    f = check_installed_skills(_ctx({"unrelated-var": blob}))
    assert f.status != FAIL, f"unrelated-variable redirect wrongly failed: {f.detail}"
