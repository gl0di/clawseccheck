"""B-1042: four argv shapes the TT5 classifier read as harmless (false negatives).

(a) `a = []; a.append('sh'); a.append('-c'); a.append(q)` -- an empty literal whose head
    arrives through `.append`. The literal prefix is rebuilt from the first same-scope
    mutation when it is a straight-line statement; with uncertain flow it fails closed
    only when a shell / wrapper literal is appended.
(b) `flag = '-c'; ['sh', flag, q]` -- a single-literal binding is resolved in flag
    positions; an unresolved element at the first non-option position after a shell head
    with a tainted later element is command injection.
(c) `os.posix_spawn` / `os.posix_spawnp(path, argv, env)` -- same verdict as os.execv.
(d) a module-level list mutated inside a function and passed to a sink there is a known,
    documented limit (not asserted here beyond not raising).

Offline, stdlib only, no files written.
"""
from __future__ import annotations

import ast as _ast

import pytest

from clawseccheck import skillast


def _tt5(src: str) -> list:
    return sorted(f.rule + ":" + f.severity for f in skillast.analyze_python(src)
                  if f.rule.startswith("TT5"))


ARG = ["TT5_ARG_INJECTION:info"]
CMD = ["TT5_CMD_INJECTION:crit"]
_HEAD = "import sys, os, subprocess\nq = sys.argv[1]\n"


# --- (a) head arrives through .append -------------------------------------------------

@pytest.mark.parametrize("body", [
    "a = []\na.append('sh')\na.append('-c')\na.append(q)\nsubprocess.run(a)\n",
    "a = []\na.append('bash')\na.append('-c')\na.append(q)\nsubprocess.check_output(a)\n",
    "a = []\na.extend(['sh', '-c'])\na.append(q)\nsubprocess.run(a)\n",
    "a = []\na += ['sh', '-c']\na += [q]\nsubprocess.run(a)\n",
    "a = []\na.append('env')\na.append(q)\nsubprocess.run(a)\n",
    "a = []\na.append('timeout')\na.append('5')\na.append(q)\nsubprocess.run(a)\n",
    "a = []\na.append('sh')\na.append('-c')\na.append(q)\nos.execvp('sh', a)\n",
    "a = []\na.append('x')\na.append('-c')\na.append(q)\nos.execv('/bin/sh', a)\n",
    # uncertain flow, shell literal appended: fail closed
    "a = []\nif q:\n    a.append('sh')\n    a.append('-c')\na.append(q)\nsubprocess.run(a)\n",
    "a = []\nfor x in 'ab':\n    a.append('sh')\na.append('-c')\na.append(q)\nsubprocess.run(a)\n",
    "a = []\nif q:\n    a.append('git')\na.append('sh')\na.append(q)\nsubprocess.run(a)\n",
    "def g():\n    a.append('sh')\na = []\ng()\na.append('-c')\na.append(q)\nsubprocess.run(a)\n",
])
def test_shell_head_appended_to_an_empty_literal_is_command_injection(body):
    assert _tt5(_HEAD + body) == CMD


@pytest.mark.parametrize("body", [
    "a = []\na.append('git')\na.append('log')\na.append(q)\nsubprocess.run(a)\n",
    "a = []\na.append('git')\na.append(q)\nsubprocess.run(a)\n",
    "a = []\na.extend(['git', 'log'])\na.append(q)\nsubprocess.run(a)\n",
    "a = []\na += ['git', 'log']\na += [q]\nsubprocess.run(a)\n",
    "a = []\na.append('python3')\na.append('tool.py')\na.append(q)\nsubprocess.run(a)\n",
    "a = []\na.append('git')\na.append(q)\nos.execv('/usr/bin/git', a)\n",
    # a shell literal appended later is data behind a safe head, not the head
    "a = []\na.append('git')\nif q:\n    a.append('sh')\na.append(q)\nsubprocess.run(a)\n",
    # uncertain flow but no shell literal appended: unchanged
    "a = []\nif q:\n    a.append('git')\na.append('log')\na.append(q)\nsubprocess.run(a)\n",
])
def test_benign_head_appended_to_an_empty_literal_stays_argument_injection(body):
    assert _tt5(_HEAD + body) == ARG


@pytest.mark.parametrize("body", [
    "a = []\na.append('sh')\na.append('-c')\na.append('ls')\nsubprocess.run(a)\n",  # untainted
    "a = []\na.append('git')\na.append('log')\nsubprocess.run(a)\n",
])
def test_untainted_appended_head_yields_nothing(body):
    assert _tt5(_HEAD + body) == []


# --- (b) eval flag held in a variable -------------------------------------------------

@pytest.mark.parametrize("body", [
    "flag = '-c'\nsubprocess.run(['sh', flag, q])\n",
    "flag = '-c'\nsubprocess.run(['bash', flag, q])\n",
    "flag = '-c'\nsubprocess.run(['python3', flag, q])\n",
    "flag = '-c'\nos.execvp('sh', ['sh', flag, q])\n",
    "flag = '-c'\nos.execv('/bin/sh', ['x', flag, q])\n",
    "def f():\n    flag = '-c'\n    subprocess.run(['sh', flag, q])\nf()\n",
    # unresolved flag at the first non-option position, tainted later element
    "flag = get()\nsubprocess.run(['sh', flag, q])\n",
    "def f(flag):\n    subprocess.run(['sh', flag, q])\nf('-c')\n",
    "flag = '-c'\nflag = get()\nsubprocess.run(['sh', flag, q])\n",
    "subprocess.run(['sh', get(), q])\n",
    "subprocess.run(['sh', '-l', get(), q])\n",
    "subprocess.run(['sh', *get(), q])\n",
    "flag = get()\nos.execvp('sh', ['sh', flag, q])\n",
    "flag = get()\nos.execv('/bin/sh', ['x', flag, q])\n",
])
def test_eval_flag_in_a_variable_is_command_injection(body):
    assert _tt5(_HEAD + body) == CMD


@pytest.mark.parametrize("body", [
    "flag = '-x'\nsubprocess.run(['sh', flag, q])\n",
    "script = 'run.sh'\nsubprocess.run(['sh', script, q])\n",
    "subprocess.run(['sh', get()])\nsubprocess.run(['sh', q])\n",
    "subprocess.run(['sh', q])\n",                         # the tainted element IS the opaque slot
    "subprocess.run(['git', get(), q])\n",                 # not a shell
    "subprocess.run(['python3', get(), q])\n",             # an interpreter, not a shell: unchanged
    "flag = '-x'\nos.execvp('sh', ['sh', flag, q])\n",
])
def test_resolved_non_eval_flag_or_non_opaque_shape_stays_argument_injection(body):
    got = _tt5(_HEAD + body)
    assert got == ARG


@pytest.mark.parametrize("body", [
    "flag = '-c'\nsubprocess.run(['sh', flag, 'ls'])\n",
    "flag = get()\nsubprocess.run(['sh', flag, 'ls'])\n",
])
def test_eval_flag_variable_without_taint_yields_nothing(body):
    assert _tt5(_HEAD + body) == []


# --- (c) posix_spawn / posix_spawnp ---------------------------------------------------

@pytest.mark.parametrize("call", [
    "os.posix_spawn('/bin/sh', ['sh', '-c', q], os.environ)",
    "os.posix_spawnp('sh', ['sh', '-c', q], os.environ)",
    "os.posix_spawn('/bin/sh', ['x', '-c', q], os.environ)",
    "os.posix_spawn(q, ['x'], os.environ)",
    "os.posix_spawnp('sh', ['sh', '-c', q], os.environ, setsid=True)",
    "os.posix_spawn(path='/bin/sh', argv=['sh', '-c', q], env=os.environ)",
    "os.posix_spawn('/bin/sh', build(q), os.environ)",
    "os.posix_spawn('/bin/sh', ['sh', '-c', q], os.environ, bogus=1)",
    "os.posix_spawn(*q)",
])
def test_posix_spawn_shell_is_command_injection(call):
    assert _tt5(_HEAD + call + "\n") == CMD


@pytest.mark.parametrize("call", [
    "os.posix_spawn('/usr/bin/git', ['git', 'log', q], os.environ)",
    "os.posix_spawnp('git', ['git', 'log', q], os.environ, setsid=True)",
    "os.posix_spawnp('git', ['git', 'log', q], os.environ, file_actions=None)",
])
def test_posix_spawn_ordinary_program_is_argument_injection(call):
    assert _tt5(_HEAD + call + "\n") == ARG


@pytest.mark.parametrize("call", [
    "os.posix_spawn('/bin/sh', ['sh', '-c', 'ls'], os.environ)",
    "os.posix_spawnp('git', ['git', 'log'], os.environ)",
    "os.posix_spawn('/bin/ls')",           # too few arguments: unparseable, no raise
])
def test_posix_spawn_untainted_yields_nothing(call):
    assert _tt5(_HEAD + call + "\n") == []


# --- (d) documented limit -------------------------------------------------------------

def test_module_level_list_mutated_in_a_function_is_a_documented_limit():
    src = _HEAD + "a = ['git']\ndef f():\n    a.append(q)\n    subprocess.run(a)\nf()\n"
    assert isinstance(skillast.analyze_python(src), list)


# --- hardening round: shell option grammar is not modelled -------------------------------

@pytest.mark.parametrize("body", [
    "subprocess.run(['sh', 'run.sh', get(), q])\n",
    "subprocess.run(['sh', '-l', 'run.sh', get(), q])\n",
    "subprocess.run(['sh', '-o', 'pipefail', get(), q])\n",
    "subprocess.run(['bash', '--rcfile', 'x', get(), q])\n",
    "subprocess.run(['sh', get(), 'x', q])\n",
    "subprocess.run(['sh', 'a', 'b', 'c', get(), 'd', q])\n",
    "subprocess.run(['cmd.exe', '/k', get(), q])\n",
    "subprocess.run(['cmd', '/q', '/d', get(), q])\n",
    "subprocess.run(['powershell', '-NoProfile', get(), q])\n",
    "os.execvp('sh', ['sh', 'run.sh', get(), q])\n",
    "os.execv('/bin/sh', ['x', '-o', 'pipefail', get(), q])\n",
])
def test_unreadable_element_after_a_shell_head_with_a_tainted_later_element_is_crit(body):
    assert _tt5(_HEAD + body) == CMD


@pytest.mark.parametrize("body", [
    "subprocess.run(['sh', 'run.sh', q, 'x'])\n",          # the first unreadable element IS the tainted one
    "subprocess.run(['sh', 'run.sh', 'a', q])\n",           # nothing unreadable
    "subprocess.run(['sh', '-l', 'run.sh', get()])\nsubprocess.run(['sh', q])\n",
    "subprocess.run(['python3', 'run.py', get(), q])\n",    # an interpreter, not a shell
])
def test_shell_head_benign_twins_are_unchanged(body):
    assert _tt5(_HEAD + body) == ARG


# --- hardening round: closure / invalidating mutation never yields a rebuilt head ----------

def _appended_head(src: str, name: str = "a") -> str:
    return skillast._b1042_appended_head(_ast.parse(src), name)[0]


@pytest.mark.parametrize("src", [
    "a = []\na.append('git')\ndef g():\n    a.insert(0, 'sh')\n",
    "a = []\na.append('git')\ndef g():\n    a.append('sh')\n",
    "a = []\na.append('git')\nf = lambda: a.append('sh')\n",
    "a = []\na.append('git')\n[a.append(x) for x in 'ab']\n",
    "a = []\na.append('git')\nclass K:\n    a.extend(['x'])\n",
    "a = []\na.append('git')\na.clear()\n",
    "a = []\na.append('git')\na.insert(0, 'sh')\n",
    "a = []\na.append('git')\na.pop(0)\n",
    "a = []\na.append('git')\na.remove('git')\n",
    "a = []\na.append('git')\na.reverse()\n",
    "a = []\na.append('git')\na.sort()\n",
    "a = []\na.append('git')\na[0:1] = ['sh']\n",
    "a = []\na.append('git')\na[0] = 'sh'\n",
    "a = []\na.append('git')\ndel a[0]\n",
    "a = []\na.append('git')\na.__setitem__(0, 'sh')\n",
    "a = []\na.append('git')\nlist.insert(a, 0, 'sh')\n",
    "def g():\n    del a[0]\na = []\na.append('git')\n",
])
def test_rebuilt_head_is_never_claimed_with_closure_or_invalidating_writes(src):
    assert _appended_head(src) != "lit"


def test_plain_straight_line_appends_still_rebuild_the_head():
    assert _appended_head("a = []\na.append('git')\na.append('x')\n") == "lit"


@pytest.mark.parametrize("body", [
    "a = []\na.append('git')\ndef g():\n    a.insert(0, 'sh')\na.append(q)\nsubprocess.run(a)\n",
    "a = []\na.append('git')\nf = lambda: a.append('sh')\na.append(q)\nsubprocess.run(a)\n",
    "a = []\na.append('git')\na[0] = 'sh'\na.append(q)\nsubprocess.run(a)\n",
])
def test_those_shapes_are_never_weaker_than_before(body):
    assert _tt5(_HEAD + body) in (ARG, CMD)


# --- hardening round: further head-changing spellings drop the binding ----------------------

@pytest.mark.parametrize("body", [
    "cmd = ['git', 'diff']\ndel cmd[0]\ncmd.append(q)\nsubprocess.run(cmd)\n",
    "cmd = ['git', 'diff']\ndel cmd[0:1]\ncmd.append(q)\nsubprocess.run(cmd)\n",
    "cmd = ['git', 'diff']\nlist.insert(cmd, 0, 'sh')\ncmd.append(q)\nsubprocess.run(cmd)\n",
    "cmd = ['git', 'diff']\nlist.__setitem__(cmd, 0, 'sh')\ncmd.append(q)\nsubprocess.run(cmd)\n",
    "cmd = ['git', 'diff']\ncmd.__setitem__(0, 'sh')\ncmd.append(q)\nsubprocess.run(cmd)\n",
    "cmd = ['git', 'diff']\ncmd.__delitem__(0)\ncmd.append(q)\nsubprocess.run(cmd)\n",
    "cmd = ['git', 'diff']\ncmd.__iadd__(['x'])\ncmd.append(q)\nsubprocess.run(cmd)\n",
    "cmd = ['git', 'diff']\ncmd.__imul__(2)\ncmd.append(q)\nsubprocess.run(cmd)\n",
    "import operator\ncmd = ['git', 'diff']\noperator.setitem(cmd, 0, 'sh')\ncmd.append(q)\nsubprocess.run(cmd)\n",
    "cmd = ['git', 'diff']\ncmd[0] += 'x'\ncmd.append(q)\nsubprocess.run(cmd)\n",
])
def test_head_changing_spellings_keep_command_injection(body):
    assert _tt5(_HEAD + body) == CMD
