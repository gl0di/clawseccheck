"""B-1022: TT5 false negative on a literal argv list mutated by .append()/.extend() and
handed DIRECTLY to subprocess.*.

`a = ['sh']; a.extend(['-c', q]); subprocess.run(a)` produced no TT5 at all: taint
propagation never marks the receiver of `.append(tainted)` tainted, so the sink call had
no tainted Name in it. The same list through a one-parameter wrapper was crit. The sink
now also counts a same-scope `.append()`/`.extend()` of tainted data on the bound Name;
the existing classifier then decides crit (shell / re-exec-wrapper head, B-953 drops the
binding) vs TT5_ARG_INJECTION (ordinary head).

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
_HEAD = "import sys, os, subprocess\nq = sys.argv[1]\n"


@pytest.mark.parametrize("body", [
    "a = ['sh']\na.extend(['-c', q])\nsubprocess.run(a)\n",
    "a = ['sh', '-c']\na.append(q)\nsubprocess.run(a)\n",
    "a = ['bash']\na.append('-c')\na.append(q)\nsubprocess.run(a)\n",
    "a = ['env']\na.append(q)\nsubprocess.run(a)\n",
    "a = ['timeout', '5']\na.append(q)\nsubprocess.run(a)\n",
    "a = ['find', '.']\na.extend(['-exec', 'sh', '-c', q, ';'])\nsubprocess.run(a)\n",
    "a = ['sh']\na.extend(['-c', q])\nsubprocess.Popen(a)\n",
    "c = ['sh']\nc.extend(['-c', q])\nsubprocess.check_output(c)\n",
    "a = ['sh']\na.extend(['-c', q])\nsubprocess.run(list(a))\n",
    "a = ['sh']\na.extend(['-c', q])\nsubprocess.run(a, shell=False)\n",
    "a = ['sh.exe']\na.extend(['-c', q])\nsubprocess.run(a)\n",
    # the keyword spelling of the same slot
    "a = ['sh']\na.extend(['-c', q])\nsubprocess.run(args=a)\n",
    "a = ['env']\na.append(q)\nsubprocess.Popen(args=a)\n",
    # inline source in the mutation argument, no named taint at all
    "a = ['sh']\na.extend(['-c', sys.argv[1]])\nsubprocess.run(a)\n",
    "a = ['sh']\na.extend(['-c', os.environ['P']])\nsubprocess.run(a)\n",
    # inside a function
    "def f():\n    a = ['sh']\n    a.extend(['-c', sys.argv[1]])\n    subprocess.run(a)\nf()\n",
    "def f(x):\n    a = ['sh']\n    a.extend(['-c', x])\n    subprocess.run(a)\nf(q)\n",
])
def test_mutated_shell_or_wrapper_argv_direct_sink_is_command_injection(body):
    assert _tt5(_HEAD + body) == CMD


@pytest.mark.parametrize("body", [
    "cmd = ['git', 'log']\ncmd.append(q)\nsubprocess.run(cmd)\n",
    "cmd = ['git', 'log']\ncmd.extend(['--', q])\nsubprocess.run(cmd)\n",
    "cmd = ['ls']\ncmd.append(os.environ['P'])\nsubprocess.run(cmd)\n",
    "cmd = ['python3', '-m', 'mod']\ncmd.append(q)\nsubprocess.run(cmd)\n",
    "cmd = ['git']\ncmd += [q]\nsubprocess.run(cmd)\n",
])
def test_mutated_ordinary_program_argv_stays_argument_injection(body):
    assert _tt5(_HEAD + body) == ARG


@pytest.mark.parametrize("body", [
    # untainted mutation
    "a = ['sh']\na.extend(['-c', 'ls'])\nsubprocess.run(a)\n",
    "cmd = ['git', 'log']\ncmd.append('-x')\nsubprocess.run(cmd)\n",
    # tainted value appended to a DIFFERENT list
    "a = ['sh', '-c', 'ls']\nb = ['x']\nb.append(q)\nsubprocess.run(a)\n",
    # mutation in a different scope than the sink
    "a = ['sh']\ndef g():\n    a.append(q)\nsubprocess.run(a)\n",
    # not a literal-list binding: built from a call
    "import shlex\na = shlex.split('ls')\na.append(q)\nsubprocess.run(a)\n",
    # an unrelated, fully literal sink next to an untainted list
    "a = ['x']\na.append('y')\nsubprocess.run(['echo', 'hi'])\n",
])
def test_no_finding_when_nothing_tainted_reaches_this_argv(body):
    assert _tt5(_HEAD + body) == []


def test_args_keyword_without_taint_is_quiet():
    assert _tt5(_HEAD + "a = ['sh']\na.extend(['-c', 'ls'])\nsubprocess.run(args=a)\n") == []


def test_unparseable_and_dynamic_shapes_do_not_raise():
    for body in (
        "a = ['sh']\na.extend(['-c', q]\nsubprocess.run(a)\n",  # syntax error
        "a = ['sh']\ngetattr(a, 'extend')(['-c', q])\nsubprocess.run(a)\n",  # dynamic mutator
        "a = ['sh']\na.extend(*[q])\nsubprocess.run(a)\n",
        "subprocess.run()\n",
    ):
        assert isinstance(_tt5(_HEAD + body), list)


def test_wrapper_twin_still_crit():
    src = _HEAD + (
        "def sh(c):\n    subprocess.run(c)\n"
        "c = ['bash']\nc.extend(['-c', q])\nsh(c)\n"
    )
    assert _tt5(src) == CMD
