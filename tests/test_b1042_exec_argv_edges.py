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
    "subprocess.run(['sh', 'run.sh', get(), q])\n",       # a literal script ended the options
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
