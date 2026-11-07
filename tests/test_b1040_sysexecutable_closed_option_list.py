"""B-1040: `sys.executable` heads with a closed option list are argument injection.

`os.execv(sys.executable, [sys.executable, 'tool.py'] + rest)` and `os.execl(sys.executable,
sys.executable, 'tool.py', *rest)` were TT5_CMD_INJECTION although, once a script path (or
`-m mod`) ends the interpreter's own option list, everything after it is the script's
argv. The current interpreter now reads as `python3` for the B-1018 closed-option-list
test, in the `[...] + rest` flattening, the starred-tail rule and the subprocess
concatenation. An open list (`[sys.executable] + rest`, `-c`) keeps the crit verdict.

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
_HEAD = "import sys, os, subprocess\nq = sys.argv[1]\nrest = sys.argv[2:]\n"


@pytest.mark.parametrize("body", [
    "os.execv(sys.executable, [sys.executable, 'tool.py'] + rest)\n",
    "os.execv(sys.executable, [sys.executable, '-m', 'mod'] + rest)\n",
    "os.execv(sys.executable, ['python3', 'tool.py'] + rest)\n",
    "os.execl(sys.executable, sys.executable, 'tool.py', *rest)\n",
    "os.execv(sys.executable, [sys.executable, 'tool.py', *rest])\n",
    "os.spawnl(os.P_WAIT, sys.executable, sys.executable, 'tool.py', *rest)\n",
    "os.execl('/usr/bin/git', 'git', 'log', *rest)\n",
    "os.execv(sys.executable, [sys.executable, 'tool.py'] + [q])\n",
    # a name bound once to sys.executable reads as it
    "py = sys.executable\nos.execv(py, [py, 'tool.py'] + rest)\n",
    "subprocess.run([sys.executable, 'tool.py'] + rest)\n",
    "subprocess.run([sys.executable, '-m', 'mod'] + rest)\n",
    "py = sys.executable\nsubprocess.run([py, 'tool.py'] + rest)\n",
])
def test_closed_option_list_is_argument_injection(body):
    assert _tt5(_HEAD + body) == ARG


@pytest.mark.parametrize("body", [
    "os.execv(sys.executable, [sys.executable] + rest)\n",
    "os.execv(sys.executable, [sys.executable, '-c'] + rest)\n",
    "os.execv(sys.executable, [sys.executable, '-m'] + rest)\n",
    "os.execv(sys.executable, [sys.executable, '-u', 'tool.py'] + rest)\n",  # option before script
    "os.execv(sys.executable, [sys.executable, *rest])\n",
    "os.execl(sys.executable, sys.executable, *rest)\n",
    "os.execl(sys.executable, sys.executable, '-c', *rest)\n",
    "os.execl(sys.executable, sys.executable, *['tool.py'], q)\n",
    "os.execv(sys.executable, [q, 'tool.py'] + rest)\n",                    # tainted head
    "os.execv('/bin/sh', [sys.executable, 'tool.py'] + rest)\n",            # program is a shell
    "os.execl('/bin/sh', 'sh', 'tool.py', *rest)\n",
    "os.execl('/bin/sh', 'sh', '-c', *rest)\n",
    "os.execle('/usr/bin/git', 'git', *rest, os.environ)\n",               # env form stays opaque
    "os.execl(sys.executable, *rest)\n",                                    # starred argv[0]
    "sys = get()\nos.execv(sys.executable, [sys.executable, 'tool.py'] + rest)\n",  # sys shadowed
    "py = sys.executable\npy = get()\nos.execv(py, [py, 'tool.py'] + rest)\n",     # rebound name
    "subprocess.run([sys.executable] + rest)\n",
    "subprocess.run([sys.executable, '-c'] + rest)\n",
    "subprocess.run([sys.executable, '-u', 'tool.py'] + rest)\n",
    "sys = get()\nsubprocess.run([sys.executable, 'tool.py'] + rest)\n",
])
def test_open_option_list_or_unproven_head_stays_command_injection(body):
    assert _tt5(_HEAD + body) == CMD


@pytest.mark.parametrize("body", [
    "os.execv(sys.executable, [sys.executable, 'tool.py'] + ['a'])\n",
    "os.execl(sys.executable, sys.executable, 'tool.py', *['a'])\n",
    "subprocess.run([sys.executable, 'tool.py'] + ['a'])\n",
    "os.execl('/bin/ls', 'ls', '-l', *rest)\n",  # nothing tainted: `rest` is argv data only
])
def test_untainted_shapes_yield_nothing_or_only_what_they_did(body):
    got = _tt5(_HEAD.replace("q = sys.argv[1]", "q = 'x'").replace("rest = sys.argv[2:]", "rest = ['y']") + body)
    assert got == []
