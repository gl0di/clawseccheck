"""B-680: a --vet target that is not there is a usage error, not a verdict.

The bug arrived from using the tool: `--vet <workspace>/skills/browser-automation`, a
name the audit's own inventory had just listed under "2 clean". Those skills are bundled
inside a plugin, so that standalone path does not exist -- and the tool answered with
"RISK DOSSIER - skill 'browser-automation'  CAUTION" over five UNKNOWN axes, at rc=1.

Two separate defects in that one line:

  * CAUTION is a word about software. Spending it on a path with no software at all
    makes a typo indistinguishable, to a reader, from a real caveat.
  * rc=1 is what a genuine CAUTION returns, so a CI job or an agent branching on `$?`
    could not tell "you gave me a bad path" from "this skill is risky".

What must NOT change is the neighbouring case: a target that EXISTS but yields nothing
analysable is genuinely UNKNOWN, and the five-axis dossier is the right answer there.
Half of this file exists to hold that line -- collapsing the two would trade one lying
verdict for another.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clawseccheck.cli import main  # noqa: E402

_PATH_MODES = ["--vet", "--vet-skill", "--vet-plugin"]


# ---------------------------------------------------------------------------
# The four unassessable shapes: rc=2, a reason on stderr, nothing on stdout
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("flag", _PATH_MODES)
def test_absent_target_is_rc2_with_no_dossier(tmp_path, capsys, flag):
    rc = main([flag, str(tmp_path / "not-a-thing")])
    captured = capsys.readouterr()
    assert rc == 2
    assert captured.out.strip() == ""
    assert "no such file or directory" in captured.err
    # The two words the bug was about must not appear anywhere.
    assert "RISK DOSSIER" not in captured.err
    assert "CAUTION" not in captured.err


@pytest.mark.parametrize("flag", _PATH_MODES)
def test_dangling_symlink_is_not_reported_as_absent(tmp_path, capsys, flag):
    """A link IS there -- saying "no such file" about it would be a second wrong answer.

    lstat succeeds and stat does not, which is exactly what separates the two, so the
    message names the link rather than denying the path.
    """
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "gone")
    rc = main([flag, str(link)])
    captured = capsys.readouterr()
    assert rc == 2
    assert captured.out.strip() == ""
    assert "symlink" in captured.err
    assert "no such file or directory" not in captured.err


@pytest.mark.skipif(os.geteuid() == 0, reason="root can stat through mode 000")
@pytest.mark.parametrize("flag", _PATH_MODES)
def test_unreadable_target_is_a_usage_error_not_an_internal_error(tmp_path, capsys, flag):
    """Before B-680 this crashed.

    `resolve_skill_target` calls `Path.is_file()`, which does not swallow EACCES, so an
    unreadable parent reached the top-level handler and printed "unexpected internal
    error (PermissionError) ... open an issue" -- the tool asking to be bug-reported for
    the user's own directory mode.
    """
    locked = tmp_path / "locked"
    (locked / "inner").mkdir(parents=True)
    locked.chmod(0o000)
    try:
        rc = main([flag, str(locked / "inner")])
        captured = capsys.readouterr()
    finally:
        locked.chmod(0o755)
    assert rc == 2
    assert captured.out.strip() == ""
    assert "permission denied" in captured.err
    assert "internal error" not in captured.err


@pytest.mark.parametrize("flag", _PATH_MODES)
def test_absent_target_stays_a_usage_error_under_json(tmp_path, capsys, flag):
    """--json must not turn a usage error into a machine-readable verdict.

    This is the half that mattered to the reporter: stdout is the channel a pipeline
    parses, and a dossier there says a subject was examined.
    """
    rc = main([flag, str(tmp_path / "not-a-thing"), "--json"])
    captured = capsys.readouterr()
    assert rc == 2
    assert captured.out.strip() == ""


def test_skill_hint_is_tied_to_the_reason(tmp_path, capsys):
    """The plugin-bundling hint answers "no such path"; it is noise on the other two."""
    main(["--vet", str(tmp_path / "not-a-thing")])
    assert "bundled inside a plugin" in capsys.readouterr().err

    link = tmp_path / "link"
    link.symlink_to(tmp_path / "gone")
    main(["--vet", str(link)])
    assert "bundled inside a plugin" not in capsys.readouterr().err


# ---------------------------------------------------------------------------
# The line that must hold: a target that EXISTS keeps its dossier
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("flag", _PATH_MODES)
def test_existing_but_unanalysable_target_still_gets_the_dossier(tmp_path, capsys, flag):
    """Genuinely UNKNOWN: there IS something here and it could not be assessed.

    If this ever starts returning 2, the fix collapsed "you mistyped" into "I looked and
    could not tell" -- the exact conflation B-680 was filed against, pointed the other
    way.
    """
    empty = tmp_path / "empty"
    empty.mkdir()
    rc = main([flag, str(empty)])
    captured = capsys.readouterr()
    assert rc == 0
    assert "RISK DOSSIER" in captured.out
    assert "UNKNOWN" in captured.out


def test_a_real_skill_still_renders_and_returns_its_own_code(tmp_path, capsys):
    skill = tmp_path / "greeter"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: greeter\ndescription: says hello\n---\n\nSay hello to the user.\n",
        encoding="utf-8",
    )
    rc = main(["--vet", str(skill)])
    captured = capsys.readouterr()
    assert rc == 0
    assert "RISK DOSSIER" in captured.out


def test_a_configured_mcp_name_still_routes_to_the_mcp_engine(tmp_path, capsys):
    """The route boundary, pinned.

    `--vet` autodetects, and a configured MCP server NAME is not a path -- `os.stat` on
    it raises FileNotFoundError like any typo would. If the guard ever moves above
    `detect_vet_type`, or stops asking which engine the target routed to, every named
    MCP server starts failing as "no such file or directory". That break would be
    silent: the failure looks exactly like the bug being fixed here, correctly applied.
    """
    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text(
        '{"mcp": {"servers": {"weather": {"command": "npx", "args": ["-y", "weather-mcp"]}}}}',
        encoding="utf-8",
    )
    rc = main(["--vet", "weather", "--home", str(home)])
    captured = capsys.readouterr()
    assert "detected type: mcp" in captured.err
    assert "RISK DOSSIER" in captured.out
    assert rc != 2


def test_an_unconfigured_name_that_is_also_not_a_path_is_a_usage_error(tmp_path, capsys):
    """The other side of the same boundary: nothing anywhere answers to this name."""
    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    rc = main(["--vet", "no-such-server", "--home", str(home)])
    captured = capsys.readouterr()
    assert rc == 2
    assert captured.out.strip() == ""


def test_side_artifact_flags_do_not_produce_an_artifact_for_a_missing_target(
    tmp_path, capsys
):
    """--emit-manifest and --vet-judge-packet write their own stdout artifact.

    Each used to render one for a path that was never there -- a permission manifest,
    or a judge packet, describing a skill that does not exist. The guard runs before
    both, so there is nothing to hand a downstream reader.
    """
    absent = str(tmp_path / "not-a-thing")
    for extra in ("--emit-manifest", "--vet-judge-packet"):
        rc = main(["--vet", absent, extra])
        captured = capsys.readouterr()
        assert rc == 2, extra
        assert captured.out.strip() == "", extra


def test_vet_source_is_not_in_scope(capsys):
    """--vet-source judges an IDENTITY, not a path.

    A slug that is not on disk is its normal input, so the absent-path guard must not
    reach it -- the three path-taking modes are the whole surface.
    """
    rc = main(["--vet-source", "some-slug-that-is-not-a-path"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "RISK DOSSIER" in captured.out
