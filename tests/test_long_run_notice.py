"""A long run announces itself on STDERR before it collects anything.

Evidence (a live OpenClaw chat run through a Codex ``exec_command`` with a 30 s yield
window): the audit prints nothing until it finishes, so the tool returned an empty result
at 30 s, the agent saw the process alive and still told the user the audit "exited without
producing any output". Codex merges stderr into the output, so one early stderr line is
what the early return carries. The line is stderr-only: stdout (the report / the JSON)
must stay byte-identical, and ``CLAWSECCHECK_NO_PROGRESS`` silences it.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SAFE = str(REPO_ROOT / "fixtures" / "home_safe")
MARK = "ClawSecCheck: "
STILL = "still running"
WAIT = "wait for it to exit"


def _run(tmp_path: Path, *args: str, quiet: bool = False,
         home: bool = True) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.pop("CLAWSECCHECK_NO_PROGRESS", None)  # the suite-wide default silences the line
    if quiet:
        env["CLAWSECCHECK_NO_PROGRESS"] = "1"
    cmd = [sys.executable, "-m", "clawseccheck"]
    if home:
        cmd += ["--home", SAFE]
    cmd += ["--data-dir", str(tmp_path / "state"), "--no-history", "--no-deptree",
            "--no-host", "--no-native", "--no-sockets", "--no-update-notice", *args]
    return subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, env=env)


def _notice_lines(stderr: str) -> list[str]:
    return [ln for ln in stderr.splitlines() if ln.startswith(MARK)]


@pytest.mark.parametrize("extra", [[], ["--json"], ["--card"]])
def test_the_default_audit_announces_itself_on_stderr(tmp_path, extra):
    proc = _run(tmp_path, *extra)
    assert proc.returncode in (0, 1), proc.stderr[:300]
    lines = _notice_lines(proc.stderr)
    assert len(lines) == 1, proc.stderr[:400]
    line = lines[0]
    assert STILL in line and WAIT in line
    assert line.isascii()
    assert MARK not in proc.stdout


def test_the_line_comes_first_on_stderr(tmp_path):
    proc = _run(tmp_path, "--json")
    assert proc.stderr.splitlines()[0].startswith(MARK + "auditing "), proc.stderr[:300]


def test_the_home_is_shown_with_a_tilde_not_the_os_user_directory(monkeypatch, capsys):
    from types import SimpleNamespace

    from clawseccheck.cli import _announce_long_run

    monkeypatch.delenv("CLAWSECCHECK_NO_PROGRESS", raising=False)
    _announce_long_run(SimpleNamespace(home="/home/someone/.openclaw"), None)
    captured = capsys.readouterr()
    assert "someone" not in captured.err, captured.err
    assert "auditing ~/.openclaw" in captured.err, captured.err
    assert captured.out == ""


@pytest.mark.parametrize("extra", [[], ["--json"]])
def test_stdout_is_byte_identical_with_and_without_the_line(tmp_path, extra):
    loud = _run(tmp_path, *extra)
    quiet = _run(tmp_path, *extra, quiet=True)
    assert _notice_lines(loud.stderr) and not _notice_lines(quiet.stderr)
    assert loud.returncode == quiet.returncode
    assert loud.stdout == quiet.stdout


@pytest.mark.parametrize("extra", [[], ["--json"], ["--full", "--quiet", "--fast"],
                                   ["--trend"]])
def test_the_escape_variable_silences_it(tmp_path, extra):
    proc = _run(tmp_path, *extra, quiet=True)
    assert not _notice_lines(proc.stderr), proc.stderr[:300]


def test_full_quiet_still_announces(tmp_path):
    """--quiet is a --full output modifier, not the escape: `--full --quiet` is exactly
    the long run the line exists for."""
    proc = _run(tmp_path, "--full", "--quiet", "--fast")
    assert len(_notice_lines(proc.stderr)) == 1, proc.stderr[:400]


@pytest.mark.parametrize("flag", [["--version"], ["--menu"], ["--brief"], ["--help"],
                                  ["--explain", "B1"], ["--verify-self"],
                                  ["--cron-recipe"]])
def test_fast_modes_do_not_announce(tmp_path, flag):
    proc = _run(tmp_path, *flag)
    assert not _notice_lines(proc.stderr), (flag, proc.stderr[:300])


def test_a_vet_run_announces_without_naming_the_audit_home(tmp_path):
    target = REPO_ROOT / "fixtures" / "clean_b100_pinned_install"
    proc = _run(tmp_path, "--vet", str(target), home=False)
    lines = _notice_lines(proc.stderr)
    assert len(lines) == 1, proc.stderr[:400]
    assert lines[0].startswith(MARK + "vetting"), lines[0]
    assert STILL in lines[0] and WAIT in lines[0]


def test_a_first_run_onboarding_screen_is_not_announced(tmp_path):
    empty = tmp_path / "nothing-here"
    env = dict(os.environ)
    env.pop("CLAWSECCHECK_NO_PROGRESS", None)
    proc = subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", str(empty), "--data-dir",
         str(tmp_path / "state"), "--no-update-notice", "--no-deptree", "--no-host"],
        cwd=REPO_ROOT, capture_output=True, text=True, env=env)
    assert not _notice_lines(proc.stderr), proc.stderr[:300]
