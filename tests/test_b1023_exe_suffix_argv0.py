"""B-1023: a Windows `.exe` spelling of a shell / re-exec wrapper classifies like the bare name.

`subprocess.run(["sh.exe", "-c", q])` read as TT5_ARG_INJECTION (info) while
`["sh", "-c", q]` is TT5_CMD_INJECTION (crit): argv[0] was lowercased and stripped of its
directory but not of a trailing `.exe`. One shared helper now normalises it.

Offline, stdlib only, no files written.
"""
from __future__ import annotations

import pytest

from clawseccheck import skillast


def _tt5(src: str) -> list:
    return sorted(f.rule + ":" + f.severity for f in skillast.analyze_python(src)
                  if f.rule.startswith("TT5"))


ARG = ["TT5_ARG_INJECTION:info"]
CMD = ["TT5_CMD_INJECTION:crit"]
_HEAD = "import sys, subprocess\nq = sys.argv[1]\n"


@pytest.mark.parametrize("argv", [
    '["sh.exe", "-c", q]',
    '["bash.exe", "-c", q]',
    '["BASH.EXE", "-c", q]',
    '["C:\\\\Windows\\\\System32\\\\cmd.exe", "/c", q]',
    '["powershell.exe", "-Command", q]',
    '["timeout.exe", "5", "sh", "-c", q]',
    '["timeout", "5", "sh.exe", "-c", q]',  # inner shell is not classified; wrapper is
    '["env.exe", q]',
    '["/usr/bin/sh.exe", "-c", q]',
    # Windows name normalisation: trailing dots/spaces dropped, other PATHEXT suffixes,
    # stacked suffixes
    '["sh.exe.", "-c", q]',
    '["sh.exe ", "-c", q]',
    '["sh.exe. .", "-c", q]',
    '["bash.com", "-c", q]',
    '["sh.exe.exe", "-c", q]',
    '["sh.cmd", "-c", q]',
    '["bash.bat", "-c", q]',
    '["sh.exe.com", "-c", q]',
    '["timeout.exe.", "5", "sh", "-c", q]',
    '["env.com", q]',
    '["C:\\\\bin\\\\SH.EXE.", "-c", q]',
    '["cmd.exe.", "/c", q]',
])
def test_exe_suffix_shell_or_wrapper_is_command_injection(argv):
    assert _tt5(_HEAD + f"subprocess.run({argv})\n") == CMD


@pytest.mark.parametrize("argv", [
    '["git.exe", "log", q]',
    '["python.exe", "-m", "mod", q]',
    '["sh.exe", "script.sh", q]',  # shell without an eval flag: ordinary program call
    '["tool.exe", q]',
    '[".exe", q]',  # degenerate: bare suffix is not stripped to an empty name
])
def test_exe_suffix_ordinary_program_stays_argument_injection(argv):
    assert _tt5(_HEAD + f"subprocess.run({argv})\n") == ARG


def test_exe_suffix_same_as_bare_name_through_binding():
    src = _HEAD + "a = ['bash.exe', '-c', q]\nsubprocess.run(a)\n"
    assert _tt5(src) == CMD


def test_helper_unparseable_or_non_literal_argv0_is_unchanged():
    # non-literal argv0 (tainted program word) is crit regardless of name handling
    assert _tt5(_HEAD + "subprocess.run([q, 'x'])\n") == CMD
    # unparseable / dynamic list: must not raise
    assert isinstance(_tt5(_HEAD + "subprocess.run(list(q))\n"), list)


def test_basename_helper():
    f = skillast._argv0_basename
    assert f("sh.exe") == "sh"
    assert f("C:\\x\\Bash.EXE") == "bash"
    assert f("/usr/bin/sh") == "sh"
    assert f("cmd.exe") == "cmd"
    assert f(".exe") == ".exe"
    assert f("a.exe.exe") == "a"
    assert f("sh.exe.") == "sh"
    assert f("sh.exe ") == "sh"
    assert f("bash.com") == "bash"
    assert f("sh.exe.exe") == "sh"
    assert f("...") == ""
    assert f("") == ""
