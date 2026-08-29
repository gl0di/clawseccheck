"""B-683: a directory mode is not a defect in this tool.

Four modes handed the user the internal-error banner — the one that asks them to file a
bug — when the only thing wrong was a directory they could not read:

    clawseccheck: unexpected internal error (PermissionError); re-run with --debug …
    open an issue: https://github.com/gl0di/clawseccheck/issues

`--advise`, `--behavioral`, `--analyze-trajectory`, `--vet-mcp`. The cause is one habit,
not four sites: `Path.exists()` / `is_file()` / `is_dir()` swallow ENOENT, ENOTDIR, EBADF
and ELOOP and **not EACCES**, so each of them raises on a path whose parent cannot be
stat'd, and every call site treated them as total functions.

Two things this file is careful about, both learned by getting them wrong first:

* **Catching the exception is half the fix.** Falling back to an empty file list leaves
  `present` False, which renders as "No trajectory sidecars found … run on a host where an
  OpenClaw agent has produced session trajectories" — the host blamed for the caller's own
  directory mode. The first version of the fix printed exactly that.
* **The disclosure has to be where execution reaches.** It was first placed beside the
  existing `unreadable` arm, which sits *after* the not-present branch returns, so it was
  unreachable in precisely the case it was written for. A unit test on the helper alone
  passes in both worlds; only driving the renderer tells them apart.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clawseccheck.checks import vet_mcp  # noqa: E402
from clawseccheck.cli import main  # noqa: E402
from clawseccheck.trajectory import resolve_explicit_file  # noqa: E402

pytestmark = pytest.mark.skipif(os.geteuid() == 0, reason="root can stat through mode 000")

_MODES = ["--advise", "--behavioral", "--analyze-trajectory", "--vet-mcp"]


def _base(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text('{"mcp": {"servers": {}}}', encoding="utf-8")
    return ["--home", str(home), "--data-dir", str(tmp_path / "data")]


def _locked(tmp_path):
    locked = tmp_path / "locked"
    (locked / "inner").mkdir(parents=True)
    return locked, locked / "inner"


@pytest.mark.parametrize("flag", _MODES)
def test_no_mode_reports_a_directory_mode_as_a_tool_defect(tmp_path, capsys, flag):
    locked, inner = _locked(tmp_path)
    locked.chmod(0o000)
    try:
        main([flag, str(inner), *_base(tmp_path)])
        captured = capsys.readouterr()
    finally:
        locked.chmod(0o755)
    assert "unexpected internal error" not in captured.err
    assert "open an issue" not in captured.err


# ---------------------------------------------------------------------------
# The helper the four sites now share
# ---------------------------------------------------------------------------

def test_resolve_explicit_file_separates_absent_from_unreadable(tmp_path):
    """Four copies of `files = [p] if p.is_file() else []` became one implementation.

    The second return value is the whole point: without it, "there is nothing here" and
    "I could not look" are the same empty list.
    """
    real = tmp_path / "t.jsonl"
    real.write_text("{}\n", encoding="utf-8")
    assert resolve_explicit_file(str(real)) == ([real], False)
    assert resolve_explicit_file(str(tmp_path / "gone")) == ([], False)

    locked, inner = _locked(tmp_path)
    locked.chmod(0o000)
    try:
        files, unreadable = resolve_explicit_file(str(inner))
    finally:
        locked.chmod(0o755)
    assert files == []
    assert unreadable is True


# ---------------------------------------------------------------------------
# The wiring: does what the user SEES distinguish the two?
# ---------------------------------------------------------------------------

def test_analyze_trajectory_does_not_blame_the_host_for_a_directory_mode(tmp_path, capsys):
    locked, inner = _locked(tmp_path)
    locked.chmod(0o000)
    try:
        main(["--analyze-trajectory", str(inner), *_base(tmp_path)])
        out = capsys.readouterr().out
    finally:
        locked.chmod(0o755)
    assert "could not be read" in out
    assert "NOT evidence that the file is empty" in out
    # The exact sentence the first version of this fix produced instead.
    assert "run on a host where" not in out


def test_analyze_trajectory_still_says_nothing_found_when_nothing_is_there(tmp_path, capsys):
    """The control. A fix that printed the unreadable line unconditionally passes the test
    above and is wrong; this is what fails it."""
    main(["--analyze-trajectory", str(tmp_path / "gone"), *_base(tmp_path)])
    out = capsys.readouterr().out
    assert "No trajectory sidecars found" in out
    assert "could not be read" not in out


def test_behavioral_names_the_permission_problem(tmp_path, capsys):
    locked, inner = _locked(tmp_path)
    locked.chmod(0o000)
    try:
        main(["--behavioral", str(inner), *_base(tmp_path)])
        out = capsys.readouterr().out
    finally:
        locked.chmod(0o755)
    assert "permission denied" in out


def test_behavioral_still_names_an_absent_path(tmp_path, capsys):
    main(["--behavioral", str(tmp_path / "gone"), *_base(tmp_path)])
    assert "no such file or directory" in capsys.readouterr().out


def test_vet_mcp_does_not_call_an_unreadable_path_a_typo(tmp_path):
    """UNKNOWN, and NOT `subject_absent`.

    B-681 turns `subject_absent` into "you named something that does not exist", at rc=2.
    Whether an unreadable path is a server or a spec file is exactly what could not be
    established, so claiming it is a typo would be the same over-claim B-681 itself had to
    retract for an unreadable config.
    """
    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text('{"mcp": {"servers": {}}}', encoding="utf-8")
    locked, inner = _locked(tmp_path)
    locked.chmod(0o000)
    try:
        findings = vet_mcp(target=str(inner), home=str(home))
    finally:
        locked.chmod(0o755)
    assert len(findings) == 1
    assert findings[0].status == "UNKNOWN"
    assert findings[0].subject_absent is False
    assert "could not read" in findings[0].detail.lower()
