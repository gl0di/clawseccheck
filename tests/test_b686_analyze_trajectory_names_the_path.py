"""B-686: a path the user named is their fact, not the host's.

    $ audit.py --analyze-trajectory ~/x/typo.jsonl
    Trajectory incident analysis (post-hoc, read-only)
      ? No trajectory sidecars found (agents/*/sessions/*.trajectory.jsonl). Nothing to
        analyze — run on a host where an OpenClaw agent has produced session trajectories.
    $ echo $?
    0

The user named a file. The tool never said which file, never said it was not there, and
advised them to go and find a different machine — for a typo — while exiting 0.

`--behavioral` takes the same kind of argument and had exactly this defect; B-462 fixed it
there and left this mode alone. The two now share one predicate, moved down into
`trajectory.py` so neither owns a question that belongs to both.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clawseccheck.behavioral import explicit_path_problem as _via_behavioral  # noqa: E402
from clawseccheck.cli import main  # noqa: E402
from clawseccheck.trajectory import explicit_path_problem  # noqa: E402


def _base(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    return ["--home", str(home), "--data-dir", str(tmp_path / "data")]


def test_the_two_modes_share_one_predicate():
    """Pinned because two copies wording the same three cases is how they drift.

    `behavioral` re-exports the moved name, so every existing importer — cli.py and
    tests/test_b462_b464_optout_honesty.py among them — still resolves.
    """
    assert _via_behavioral is explicit_path_problem


def test_absent_path_is_named_and_the_host_is_not_blamed(tmp_path, capsys):
    ghost = tmp_path / "typo.jsonl"
    rc = main(["--analyze-trajectory", str(ghost), *_base(tmp_path)])
    out = capsys.readouterr().out
    assert str(ghost) in out
    assert "no such file or directory" in out
    assert "run on a host where" not in out
    assert rc == 1


def test_a_directory_says_so(tmp_path, capsys):
    d = tmp_path / "adir"
    d.mkdir()
    rc = main(["--analyze-trajectory", str(d), *_base(tmp_path)])
    out = capsys.readouterr().out
    assert "is a directory, not a trajectory file" in out
    assert rc == 1


@pytest.mark.skipif(os.geteuid() == 0, reason="root can stat through mode 000")
def test_an_unreadable_path_says_so(tmp_path, capsys):
    locked = tmp_path / "locked"
    (locked / "inner").mkdir(parents=True)
    locked.chmod(0o000)
    try:
        rc = main(["--analyze-trajectory", str(locked / "inner"), *_base(tmp_path)])
        out = capsys.readouterr().out
    finally:
        locked.chmod(0o755)
    assert "permission denied" in out
    assert "run on a host where" not in out
    assert rc == 1


def test_the_silence_is_qualified_in_every_case(tmp_path, capsys):
    """"Nothing was analyzed" must never read as "there was nothing to find"."""
    main(["--analyze-trajectory", str(tmp_path / "typo.jsonl"), *_base(tmp_path)])
    out = capsys.readouterr().out
    assert "not evidence that the file is empty" in out


def test_no_explicit_path_is_unchanged(tmp_path, capsys):
    """The control, and the reason the predicate is asked rather than the result inspected.

    With no path named, "run on a host where an OpenClaw agent has produced session
    trajectories" is the CORRECT message and rc=0 is the correct code. A fix that reported
    a path problem unconditionally passes every test above and fails this one.
    """
    rc = main(["--analyze-trajectory", "", *_base(tmp_path)])
    out = capsys.readouterr().out
    assert "No trajectory sidecars found" in out
    assert "run on a host where" in out
    assert rc == 0


def test_behavioral_is_unchanged(tmp_path, capsys):
    """The mode the predicate came from must answer exactly as it did before."""
    ghost = tmp_path / "typo.jsonl"
    rc = main(["--behavioral", str(ghost), *_base(tmp_path)])
    out = capsys.readouterr().out
    assert "no such file or directory" in out
    assert rc == 1
