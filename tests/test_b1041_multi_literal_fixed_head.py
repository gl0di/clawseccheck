"""B-1041: a command list rebound among literals that all start with a fixed, non-shell
program is argument injection, not command injection.

`cmd = ['git', 'diff']; if staged: cmd = ['git', 'diff', '--cached']; cmd.append(p);
subprocess.run(cmd)` was TT5_CMD_INJECTION: the name has two assignments, so it was never
resolved to one literal and the unresolved argv defaulted to crit. When EVERY assignment
of the name in the scope is a list literal (or `name + [...]` / `[...] + ...`) headed by a
fixed program that `_prog_name_could_become_shell_indirect` clears, nothing can change the
program, so the head is known safe. Any other assignment, a shell/wrapper head, a
parameter, an index assignment or an argv[0]-invalidating mutator keeps the crit default.

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
_HEAD = "import sys, os, subprocess\nq = sys.argv[1]\nstaged = len(sys.argv) > 2\n"


@pytest.mark.parametrize("body", [
    "cmd = ['git', 'diff']\nif staged:\n    cmd = ['git', 'diff', '--cached']\ncmd.append(q)\nsubprocess.run(cmd)\n",
    "cmd = ['git', 'diff']\nif staged:\n    cmd = ['git', 'diff', '--cached']\ncmd += [q]\nsubprocess.run(cmd)\n",
    "cmd = ['git', 'diff']\ncmd = cmd + [q]\nsubprocess.run(cmd)\n",
    "cmd = ['git', 'diff']\nif staged:\n    cmd = cmd + ['--cached']\ncmd = cmd + [q]\nsubprocess.run(cmd)\n",
    "cmd = ('git', 'diff')\nif staged:\n    cmd = ['git', 'log']\ncmd.append(q)\nsubprocess.run(cmd)\n",
    "cmd = ['git', 'diff']\nif staged:\n    cmd = ['git'] + ['log']\ncmd.extend([q])\nsubprocess.run(cmd)\n",
    # inside a function
    "def f(p):\n    cmd = ['git', 'diff']\n    if staged:\n        cmd = ['git', 'diff', '--cached']\n    cmd.append(p)\n    subprocess.run(cmd)\nf(q)\n",
    # a closed python option list is not a shell either
    "cmd = ['python3', 'a.py']\nif staged:\n    cmd = ['python3', '-m', 'mod']\ncmd.append(q)\nsubprocess.run(cmd)\n",
])
def test_every_assignment_has_a_fixed_non_shell_head(body):
    assert _tt5(_HEAD + body) == ARG


@pytest.mark.parametrize("body", [
    # a shell / wrapper / open interpreter head in any assignment
    "cmd = ['git', 'diff']\nif staged:\n    cmd = ['sh', '-c']\ncmd.append(q)\nsubprocess.run(cmd)\n",
    "cmd = ['sh', '-c']\nif staged:\n    cmd = ['git', 'diff']\ncmd.append(q)\nsubprocess.run(cmd)\n",
    "cmd = ['git', 'diff']\nif staged:\n    cmd = ['env']\ncmd.append(q)\nsubprocess.run(cmd)\n",
    "cmd = ['git', 'diff']\nif staged:\n    cmd = ['python3']\ncmd.append(q)\nsubprocess.run(cmd)\n",
    # a non-literal assignment
    "cmd = ['git', 'diff']\nif staged:\n    cmd = get()\ncmd.append(q)\nsubprocess.run(cmd)\n",
    "cmd = ['git', 'diff']\nif staged:\n    cmd = [q, 'diff']\ncmd.append(q)\nsubprocess.run(cmd)\n",
    "cmd = ['git', 'diff']\nif staged:\n    cmd = [get(), 'diff']\ncmd.append(q)\nsubprocess.run(cmd)\n",
    "cmd = ['git', 'diff']\nif staged:\n    cmd = q.split()\ncmd.append(q)\nsubprocess.run(cmd)\n",
    "cmd = ['git', 'diff']\nif staged:\n    cmd = q + cmd\ncmd.append(q)\nsubprocess.run(cmd)\n",
    "cmd = ['git', 'diff']\nif staged:\n    cmd = [q] + cmd\ncmd.append(q)\nsubprocess.run(cmd)\n",
    # unpack / loop / with / walrus / aug-assign binds
    "cmd = ['git', 'diff']\nif staged:\n    cmd = ['git', 'log']\nif q:\n    cmd, x = get()\ncmd.append(q)\nsubprocess.run(cmd)\n",
    "cmd = ['git', 'diff']\nif staged:\n    cmd = ['git', 'log']\nfor cmd in get():\n    pass\ncmd.append(q)\nsubprocess.run(cmd)\n",
    "cmd = ['git', 'diff']\nif staged:\n    cmd = ['git', 'log']\nif q:\n    cmd *= 2\ncmd.append(q)\nsubprocess.run(cmd)\n",
    "cmd = ['git', 'diff']\nif staged:\n    cmd = ['git', 'log']\ncmd[0] = q\ncmd.append(q)\nsubprocess.run(cmd)\n",
    "cmd = ['git', 'diff']\nif staged:\n    cmd = ['git', 'log']\ncmd.insert(0, q)\ncmd.append(q)\nsubprocess.run(cmd)\n",
    "cmd = ['git', 'diff']\nif staged:\n    cmd = ['git', 'log']\ncmd.pop(0)\ncmd.append(q)\nsubprocess.run(cmd)\n",
    # a nested function that mutates the head
    "cmd = ['git', 'diff']\nif staged:\n    cmd = ['git', 'log']\ndef g():\n    cmd.insert(0, 'sh')\ncmd.append(q)\nsubprocess.run(cmd)\n",
    # global / nonlocal rebinding
    "def f(p):\n    global cmd\n    cmd = ['git', 'diff']\n    if staged:\n        cmd = ['git', 'log']\n    cmd.append(p)\n    subprocess.run(cmd)\nf(q)\n",
    # a parameter may carry anything
    "def f(cmd, p):\n    if staged:\n        cmd = ['git', 'diff']\n    cmd.append(p)\n    subprocess.run(cmd)\nf(get(), q)\n",
    # a name assigned only through a star-import / never assigned in this scope
    "from os import *\nif staged:\n    cmd = ['git', 'diff']\ncmd.append(q)\nsubprocess.run(cmd)\n",
    # a concatenation as the sink argument is not resolved through the name (unchanged)
    "cmd = ['git', 'diff']\nif staged:\n    cmd = ['hg', 'diff']\nsubprocess.check_output(cmd + [q])\n",
    # shell=True is never an argv list
    "cmd = ['git', 'diff']\nif staged:\n    cmd = ['git', 'log']\ncmd.append(q)\nsubprocess.run(cmd, shell=True)\n",
])
def test_any_other_binding_or_shell_head_keeps_command_injection(body):
    assert _tt5(_HEAD + body) == CMD


def test_untainted_multi_literal_command_yields_nothing():
    src = ("import subprocess, sys\nstaged = len(sys.argv) > 2\n"
           "cmd = ['git', 'diff']\nif staged:\n    cmd = ['git', 'diff', '--cached']\n"
           "cmd.append('x')\nsubprocess.run(cmd)\n")
    assert _tt5(src) == []


def test_single_literal_binding_verdict_is_unchanged():
    assert _tt5(_HEAD + "cmd = ['git', 'diff']\ncmd.append(q)\nsubprocess.run(cmd)\n") == ARG
    assert _tt5(_HEAD + "cmd = ['sh', '-c']\ncmd.append(q)\nsubprocess.run(cmd)\n") == CMD


_TWO = "cmd = ['git', 'diff']\nif staged:\n    cmd = ['git', 'log']\n"


@pytest.mark.parametrize("body", [
    # aliasing / indirect mutation of the head
    _TWO + "x = cmd\nx.insert(0, 'sh')\ncmd.append(q)\nsubprocess.run(cmd)\n",
    _TWO + "x = cmd\nx[0] = 'sh'\ncmd.append(q)\nsubprocess.run(cmd)\n",
    _TWO + "box = [cmd]\nbox[0][0] = 'sh'\ncmd.append(q)\nsubprocess.run(cmd)\n",
    _TWO + "mutate(cmd)\ncmd.append(q)\nsubprocess.run(cmd)\n",
    _TWO + "import operator\noperator.setitem(cmd, 0, 'sh')\ncmd.append(q)\nsubprocess.run(cmd)\n",
    _TWO + "cmd.__setitem__(0, 'sh')\ncmd.append(q)\nsubprocess.run(cmd)\n",
    _TWO + "cmd.__delitem__(0)\ncmd.append(q)\nsubprocess.run(cmd)\n",
    _TWO + "cmd[0:1] = ['sh', '-c']\ncmd.append(q)\nsubprocess.run(cmd)\n",
    _TWO + "del cmd[0]\ncmd.append(q)\nsubprocess.run(cmd)\n",
    _TWO + "del cmd\ncmd = ['git']\ncmd.append(q)\nsubprocess.run(cmd)\n",
    _TWO + "y = cmd.copy()\ncmd.append(q)\nsubprocess.run(cmd)\n",
    _TWO + "for _ in cmd:\n    pass\ncmd.append(q)\nsubprocess.run(cmd)\n",
    _TWO + "n = len(cmd)\ncmd.append(q)\nsubprocess.run(cmd)\n",
    _TWO + "cmd.append(cmd)\ncmd.append(q)\nsubprocess.run(cmd)\n",
    _TWO + "cmd.append(q)\nsubprocess.run(cmd)\ndef g():\n    cmd.insert(0, 'sh')\n",
    _TWO + "cmd.append(q)\nsubprocess.run(cmd)\ndef g(x):\n    x[0] = 'sh'\ng(cmd)\n",
    # scope confusion: the sink is not directly in the scope holding the assignments
    _TWO + "cmd.append(q)\nrun = lambda: subprocess.run(cmd)\nrun()\n",
    _TWO + "cmd.append(q)\nr = [subprocess.run(cmd) for _ in (1,)]\n",
    _TWO + "cmd.append(q)\nclass K:\n    subprocess.run(cmd)\n",
    _TWO + "cmd.append(q)\ndef g(cmd):\n    subprocess.run(cmd)\ng(get())\n",
    # another function rebinds the module-level name through `global`
    _TWO + "cmd.append(q)\nsubprocess.run(cmd)\ndef g():\n    global cmd\n    cmd = get()\n",
])
def test_aliasing_or_scope_confusion_keeps_command_injection(body):
    assert _tt5(_HEAD + body) == CMD


def test_the_original_benign_twin_is_still_argument_injection():
    body = ("cmd = ['git', 'diff']\nif staged:\n    cmd = ['git', 'diff', '--cached']\n"
            "cmd.append(q)\nsubprocess.run(cmd)\n")
    assert _tt5(_HEAD + body) == ARG
    fn = ("def f(p):\n    cmd = ['git', 'diff']\n    if staged:\n"
          "        cmd = ['git', 'diff', '--cached']\n    cmd.append(p)\n    subprocess.run(cmd)\nf(q)\n")
    assert _tt5(_HEAD + fn) == ARG


@pytest.mark.parametrize("body", [
    _TWO + "def g():\n    cmd.append(q)\n    subprocess.run(cmd)\ng()\n",
    "def f():\n    cmd = ['git', 'diff']\n    if staged:\n        cmd = ['git', 'log']\n"
    "    def g():\n        cmd.append(q)\n        subprocess.run(cmd)\n    g()\nf()\n",
    "def f():\n    cmd = ['git', 'diff']\n    if staged:\n        cmd = ['git', 'log']\n"
    "    cmd.append(q)\n    def g(x=subprocess.run(cmd)):\n        pass\n    g()\nf()\n",
])
def test_closure_or_default_sinks_are_never_downgraded(body):
    # the sink is in a nested function / a default argument, not in the scope that holds the
    # literal assignments: no shortcut (today these report nothing at all -- never ARG)
    assert _tt5(_HEAD + body) != ARG
