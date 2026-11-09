"""B-1021: TT5 false negative on programs that re-exec the rest of their argv.

`subprocess.run(["timeout", "5", "sh", "-c", q])` with a tainted `q` read as
TT5_ARG_INJECTION (info) because `timeout` was not a known re-exec wrapper, while the
same list without the `timeout 5` prefix was TT5_CMD_INJECTION (crit). The wrappers are
matched on argv[0] alone, without parsing their options (fail-closed, like env/sudo);
`find` counts only with a literal -exec/-execdir/-ok/-okdir action.

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
    '["timeout", "5", "sh", "-c", q]',
    '["gtimeout", "-k", "2", "5", "bash", "-c", q]',
    '["nice", "-n", "10", "bash", "-c", q]',
    '["ionice", "-c", "3", "sh", "-c", q]',
    '["stdbuf", "-oL", "sh", "-c", q]',
    '["setsid", "sh", "-c", q]',
    '["xargs", "sh", "-c", q]',
    '["busybox", "sh", "-c", q]',
    '["chroot", "/srv", "sh", "-c", q]',
    '["taskset", "0x3", "sh", "-c", q]',
    '["flock", "/tmp/l", "-c", q]',
    '["chrt", "10", "sh", "-c", q]',
    '["unshare", "-n", "sh", "-c", q]',
    '["nsenter", "-t", "1", "sh", "-c", q]',
    '["runuser", "-u", "nobody", "--", "sh", "-c", q]',
    '["setpriv", "--reuid", "1000", "sh", "-c", q]',
    '["prlimit", "--nofile=64", "sh", "-c", q]',
    '["pkexec", "sh", "-c", q]',
    '["su", "nobody", "-c", q]',
    '["time", "sh", "-c", q]',
    '["watch", q]',
    '["/usr/bin/timeout", "5", "sh", "-c", q]',
    '["find", ".", "-exec", "sh", "-c", q, ";"]',
    '["find", ".", "-execdir", q, ";"]',
    '["timeout", "5", q]',  # tainted program word behind the wrapper
    '["nice", "timeout", "5", "sh", "-c", q]',  # nested wrappers
])
def test_wrapped_tainted_command_is_command_injection(argv):
    assert _tt5(_HEAD + f"subprocess.run({argv})\n") == CMD


@pytest.mark.parametrize("argv", [
    '["timeout", "5", "sh", "-c", "echo hi"]',
    '["nice", "-n", "10", "make"]',
    '["find", ".", "-name", "*.py"]',
])
def test_wrapped_literal_command_has_no_tt5(argv):
    assert _tt5(_HEAD + f"subprocess.run({argv})\n") == []


def test_find_without_an_exec_action_stays_argument_injection():
    assert _tt5(_HEAD + 'subprocess.run(["find", ".", "-name", q])\n') == ARG


@pytest.mark.parametrize("argv", [
    '["git", "log", q]',
    '["sh", "script.sh", q]',
    '["python3", "-m", "pytest", q]',
])
def test_unwrapped_program_argument_stays_argument_injection(argv):
    # control: the wrapper set must not change ordinary program calls
    assert _tt5(_HEAD + f"subprocess.run({argv})\n") == ARG


def test_wrapper_list_plus_param_is_command_injection():
    src = "import subprocess\ndef w(args):\n    return subprocess.run(['timeout', '5'] + args)\n"
    assert _tt5(src) == CMD


def test_find_list_extended_with_exec_through_a_wrapper_is_command_injection():
    src = (
        "import os, subprocess\n"
        "def sh(cmd):\n    subprocess.run(cmd)\n"
        "def main():\n"
        "    c = ['find', '.']\n"
        "    c.extend(['-exec', 'sh', '-c', os.environ['P'], ';'])\n"
        "    sh(c)\n"
    )
    assert _tt5(src) == CMD


def test_overapproximation_is_pinned():
    """Fail-closed by design (same as env/sudo): the wrapper's options are not parsed,
    so a tainted ARGUMENT of the wrapped program also counts as command position."""
    assert _tt5(_HEAD + 'subprocess.run(["timeout", "30", "git", "clone", q])\n') == CMD
