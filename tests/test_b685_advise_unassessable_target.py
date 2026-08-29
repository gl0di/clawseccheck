"""B-685: --advise on a target that cannot be assessed is a usage error, not a decision.

B-680's shape in the one mode it did not cover, failing the worse way — toward the clean
exit code, like B-681:

    $ audit.py --advise ~/x/no-such-skill
    ⚠️  CAUTION — skill 'no-such-skill'
    Reasons: assessment is inconclusive (UNKNOWN) — not enough signal to say INSTALL;
             review manually before trusting this source.
    $ echo $?
    0

Nothing at that path was examined. The output named a skill that does not exist, spent
CAUTION — a word about software — on a path with no software, told the reader to review a
thing that is not there, and returned the code a clean assessment returns. --advise is the
surface whose entire job is the install decision, which is what makes that worse here.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clawseccheck.cli import main  # noqa: E402


def _home(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text('{"mcp": {"servers": {}}}', encoding="utf-8")
    return ["--home", str(home), "--data-dir", str(tmp_path / "data")]


def test_absent_target_is_a_usage_error(tmp_path, capsys):
    rc = main(["--advise", str(tmp_path / "no-such-skill"), *_home(tmp_path)])
    captured = capsys.readouterr()
    assert rc == 2
    assert captured.out.strip() == ""
    assert "no such file or directory" in captured.err
    for word in ("CAUTION", "INSTALL", "DO-NOT-INSTALL"):
        assert word not in captured.out


def test_dangling_symlink_is_named_as_one(tmp_path, capsys):
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "gone")
    rc = main(["--advise", str(link), *_home(tmp_path)])
    captured = capsys.readouterr()
    assert rc == 2
    assert "symlink" in captured.err


@pytest.mark.skipif(os.geteuid() == 0, reason="root can stat through mode 000")
def test_unreadable_target_is_not_an_internal_error(tmp_path, capsys):
    locked = tmp_path / "locked"
    (locked / "inner").mkdir(parents=True)
    locked.chmod(0o000)
    try:
        rc = main(["--advise", str(locked / "inner"), *_home(tmp_path)])
        captured = capsys.readouterr()
    finally:
        locked.chmod(0o755)
    assert rc == 2
    assert "permission denied" in captured.err
    assert "internal error" not in captured.err


def test_an_existing_but_unanalysable_target_keeps_its_decision(tmp_path, capsys):
    """The line that must NOT move.

    There really is something there and it could not be assessed — a genuine UNKNOWN, and
    CAUTION is the right word for it. Collapsing this into the usage error would trade one
    lying answer for another.
    """
    empty = tmp_path / "empty"
    empty.mkdir()
    rc = main(["--advise", str(empty), *_home(tmp_path)])
    captured = capsys.readouterr()
    assert rc != 2
    assert "CAUTION" in captured.out


def test_a_real_skill_still_gets_its_decision(tmp_path, capsys):
    skill = tmp_path / "greeter"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: greeter\ndescription: says hello\n---\n\nSay hello to the user.\n",
        encoding="utf-8",
    )
    rc = main(["--advise", str(skill), *_home(tmp_path)])
    captured = capsys.readouterr()
    assert rc != 2
    assert captured.out.strip() != ""


def test_a_configured_mcp_name_is_not_treated_as_a_missing_path(tmp_path, capsys):
    """A name is not a path, and `os.stat` on it raises like any typo would.

    --advise routes an MCP-detected target to the skill engine, which is pre-existing and
    left alone; what must not happen is the guard reporting a configured server as "no
    such file or directory".
    """
    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text(
        '{"mcp": {"servers": {"weather": {"command": "npx", "args": ["-y", "w"]}}}}',
        encoding="utf-8",
    )
    rc = main(["--advise", "weather", "--home", str(home),
               "--data-dir", str(tmp_path / "data")])
    captured = capsys.readouterr()
    assert rc != 2
    assert "no such file or directory" not in captured.err


def test_the_quarantine_next_step_still_prints(tmp_path, capsys):
    """Pinned because it was briefly mistaken for this bug, and it is not one.

    `report.py`'s advise renderer ends with `rm -rf <target>  # remove the quarantine copy
    — do this either way` when `_looks_like_quarantine(target)`. Measuring it with a
    fixture under the system temp dir made it look like a destructive instruction emitted
    about an unexamined subject; outside the temp dir the same renderer prints "this does
    not look like a quarantine copy … if this is your real installed skill, do NOT delete
    it". The guard is correct and this test exists so a later reader does not re-open it as
    a finding, or weaken it while fixing something else.

    `tmp_path` IS under the system temp dir, which is what makes it the right fixture here
    and the wrong one for every other test in this file.
    """
    target = tmp_path / "quarantined"
    target.mkdir()
    main(["--advise", str(target), *_home(tmp_path)])
    out = capsys.readouterr().out
    assert "rm -rf" in out
    assert "quarantine copy" in out
