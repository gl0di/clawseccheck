"""B-1024: TT5 false negative on os.exec* / os.spawn*.

They got only DANGEROUS_SINK (info) however tainted the program or argv was, while the
same argv through subprocess.* is TT5_CMD_INJECTION (shell / re-exec-wrapper head) or
TT5_ARG_INJECTION. The program is a separate argument (`file`/`path`; `spawn*` has the
mode first); the existing shell-indirect classification now applies to both the program
argument and the argv. os.system / os.popen were already TT5 sinks and are untouched.

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
_HEAD = "import sys, os\nq = sys.argv[1]\n"


@pytest.mark.parametrize("call", [
    "os.execvp('sh', ['sh', '-c', q])",
    "os.execv('/bin/sh', ['sh', '-c', q])",
    "os.execve('/bin/sh', ['sh', '-c', q], os.environ)",
    "os.execvpe('sh', ['sh', '-c', q], os.environ)",
    "os.spawnvp(os.P_WAIT, 'sh', ['sh', '-c', q])",
    "os.spawnv(os.P_NOWAIT, '/bin/bash', ['bash', '-c', q])",
    "os.spawnve(os.P_WAIT, '/bin/sh', ['sh', '-c', q], os.environ)",
    "os.spawnvpe(os.P_WAIT, 'sh', ['sh', '-c', q], os.environ)",
    "os.execl('/bin/sh', 'sh', '-c', q)",
    "os.execlp('sh', 'sh', '-c', q)",
    "os.execle('/bin/sh', 'sh', '-c', q, os.environ)",
    "os.execlpe('sh', 'sh', '-c', q, os.environ)",
    "os.spawnl(os.P_WAIT, '/bin/sh', 'sh', '-c', q)",
    "os.spawnlp(os.P_WAIT, 'sh', 'sh', '-c', q)",
    "os.spawnle(os.P_WAIT, '/bin/sh', 'sh', '-c', q, os.environ)",
    "os.spawnlpe(os.P_WAIT, 'sh', 'sh', '-c', q, os.environ)",
    # re-exec wrapper head, B-1021 / B-1023 vocabulary
    "os.execvp('timeout', ['timeout', '5', 'sh', '-c', q])",
    "os.execvp('env', ['env', q])",
    "os.execvp('timeout.exe', ['timeout.exe', '5', 'sh', '-c', q])",
    "os.execvp('find', ['find', '.', '-exec', q, ';'])",
    # argv[0] is arbitrary: the PROGRAM argument is the shell
    "os.execv('/bin/sh', ['x', '-c', q])",
    "os.spawnv(os.P_WAIT, '/bin/sh', ['x', '-c', q])",
    # tainted program path / tainted argv[0]
    "os.execv(q, [q])",
    "os.execvp(q, ['x'])",
    "os.spawnv(os.P_WAIT, q, ['x'])",
    "os.execvp('ls', [q, '-l'])",
    "os.execl(q, 'x')",
    # inline sources
    "os.execvp('sh', ['sh', '-c', sys.argv[1]])",
    "os.execvpe('sh', ['sh', '-c', os.environ['P']], os.environ)",
    # unresolvable argv that is tainted fails closed
    "os.execvp('sh', list(q))",
    "os.execvp('sh', build(q))",
    "os.execvp('sh', q)",
])
def test_tainted_shell_or_program_is_command_injection(call):
    assert _tt5(_HEAD + call + "\n") == CMD


@pytest.mark.parametrize("body", [
    "a = ['sh']\na.extend(['-c', q])\nos.execvp('sh', a)\n",
    "a = ['bash', '-c']\na.append(q)\nos.spawnvp(os.P_WAIT, 'bash', a)\n",
    "a = ['sh', '-c', q]\nos.execvp('sh', a)\n",
    "def f(x):\n    os.execvp('sh', ['sh', '-c', x])\nf(q)\n",
])
def test_bound_or_wrapped_argv_is_command_injection(body):
    assert _tt5(_HEAD + body) == CMD


@pytest.mark.parametrize("call", [
    "os.execvp('git', ['git', 'log', q])",
    "os.execv('/usr/bin/git', ['git', 'log', q])",
    "os.spawnvp(os.P_WAIT, 'git', ['git', 'log', q])",
    "os.execlp('git', 'git', 'log', q)",
    "os.execvp('sh', ['sh', 'script.sh', q])",  # shell without an eval flag
    "os.execvp('python3', ['python3', '-m', 'mod', q])",
])
def test_tainted_non_program_element_is_argument_injection(call):
    assert _tt5(_HEAD + call + "\n") == ARG


def test_mutated_ordinary_argv_is_argument_injection():
    assert _tt5(_HEAD + "a = ['git']\na.append(q)\nos.execvp('git', a)\n") == ARG


@pytest.mark.parametrize("call", [
    "os.execvp('git', ['git', 'log'])",
    "os.execv(sys.executable, [sys.executable, 'a.py'])",
    # the self-restart idiom stays quiet
    "os.execv(sys.executable, [sys.executable] + sys.argv)",
    "os.execv(sys.executable, ['python'] + sys.argv)",
    "os.execle('/bin/ls', 'ls', '-l', {'A': q})",  # taint only in the environment mapping
    "os.spawnl(os.P_WAIT, '/bin/ls', 'ls', 'x')",
    "os.execvp('sh', ['sh', '-c', 'ls'])",
])
def test_nothing_tainted_reaches_the_argv_no_tt5(call):
    assert _tt5(_HEAD + call + "\n") == []


def test_dangerous_sink_info_is_still_emitted():
    src = _HEAD + "os.execvp('sh', ['sh', '-c', q])\n"
    rules = {f.rule for f in skillast.analyze_python(src)}
    assert {"DANGEROUS_SINK", "TT5_CMD_INJECTION"} <= rules


def test_os_system_and_popen_unchanged():
    assert _tt5(_HEAD + "os.system(q)\n") == CMD
    assert _tt5(_HEAD + "os.popen(q)\n") == CMD


@pytest.mark.parametrize("call", [
    "os.execvp('sh')",            # too few arguments
    "os.spawnv(os.P_WAIT)",       # mode only
    "os.execl()",
    "os.execvp('sh', [])",        # empty argv
    "os.execv_unknown(q, [q])",   # not an os.exec* name
])
def test_unparseable_or_unclaimed_shapes_yield_no_tt5_and_do_not_raise(call):
    assert _tt5(_HEAD + call + "\n") == []


def test_syntax_error_source_does_not_raise():
    assert isinstance(skillast.analyze_python(_HEAD + "os.execvp('sh', ['sh', '-c', q]\n"), list)


# --- follow-up: security review bypasses (program-as-head, keywords, starred tails) ---

@pytest.mark.parametrize("body", [
    # 1. the PROGRAM is the shell; argv is stale / partial / unreadable
    "a = ['x']\na.append('-c')\na.append(q)\nos.execv('/bin/sh', a)\n",
    "a = ['x']\na.extend(['-c', q])\nos.execv('/bin/sh', a)\n",
    "a = ['x']\na.extend(['-c', q])\nos.spawnv(os.P_WAIT, '/bin/sh', a)\n",
    "os.execv('/bin/sh', ['x'] + ['-c', q])\n",
    "os.execv('/bin/sh', ['x'] + [q])\n",
    "os.execv('/bin/sh', ['x', '-c'] + [q])\n",
    "def f(a):\n    os.execv('/bin/sh', a)\nf(q)\n",
    "def f(rest):\n    os.execv('/bin/sh', ['sh'] + rest)\nf(q)\n",
    "os.execvp('timeout', ['x'] + [q])\n",
    "a = ['x']\na.append(q)\nos.execv('/usr/bin/python3', a)\n",
    "os.execv('/usr/bin/python3', ['python3'] + [q])\n",
    # non-literal program is never folded with a concatenation
    "def f(prog, rest):\n    os.execv(prog, ['x'] + rest)\nf('sh', q)\n",
    # 2. keywords map onto the slots; anything unmappable fails closed
    "os.execvp(file='sh', args=['sh', '-c', q])\n",
    "os.execve(path='/bin/sh', argv=['sh', '-c', q], env={})\n",
    "os.spawnv(mode=os.P_WAIT, file='sh', args=['sh', '-c', q])\n",
    "os.spawnvp(os.P_WAIT, 'sh', args=['sh', '-c', q])\n",
    "os.execvp(file=q, args=['x'])\n",
    "os.execvp(bogus='sh', args=['sh', '-c', q])\n",       # unknown keyword
    "os.execvp('sh', ['sh'], args=['sh', '-c', q])\n",    # slot given twice
    "os.execvp('sh', **{'args': ['sh', '-c', q]})\n",     # **kwargs
    "os.execl('/bin/sh', 'sh', '-c', q, mode=1)\n",       # keyword on an l form
    "os.execvp(*q)\n",                                    # starred positional
    # 3. starred tails: argv is unreadable, the env strip must not apply
    "rest = [q]\nos.execl('/bin/sh', 'sh', '-c', *rest)\n",
    "os.execle('/bin/sh', 'sh', '-c', q, *e)\n",
    "os.execle('/bin/sh', 'sh', '-c', *[q])\n",
    "os.execle('/bin/ls', 'ls', *['x'], {'A': q})\n",
    "os.spawnl(os.P_WAIT, '/bin/sh', 'sh', *[q])\n",
    "os.execv('/bin/sh', *[q])\n",
])
def test_review_bypasses_are_command_injection(body):
    assert _tt5(_HEAD + body) == CMD


@pytest.mark.parametrize("body", [
    # benign twins stay info
    "a = ['git']\na.append(q)\nos.execv('/usr/bin/git', a)\n",
    "a = ['python3', '-m', 'mod']\na.append(q)\nos.execv('/usr/bin/python3', a)\n",
    "os.execv('/usr/bin/git', ['git'] + [q])\n",
    "os.execv('/usr/bin/git', ['git', 'log'] + [q])\n",
    "os.execv('/usr/bin/python3', ['python3', '-m', 'mod'] + [q])\n",
    "os.execvp(file='git', args=['git', 'log', q])\n",
    "os.spawnv(mode=os.P_WAIT, file='git', args=['git', q])\n",
    "os.execvp('git', ['git', *['log'], q])\n",
])
def test_review_bypass_benign_twins_stay_argument_injection(body):
    assert _tt5(_HEAD + body) == ARG


@pytest.mark.parametrize("body", [
    "os.execvp(file='git', args=['git', 'log'])\n",
    "os.execle('/bin/ls', 'ls', '-l', *e)\n",             # starred, nothing tainted
    "os.execle('/bin/ls', 'ls', '-l', {'A': q})\n",       # env mapping still stripped
    "os.execv('/bin/sh', ['x'] + ['-c', 'ls'])\n",        # untainted concatenation
    "a = ['x']\na.append('-c')\nos.execv('/bin/sh', a)\n",  # untainted mutation
])
def test_review_bypass_shapes_without_taint_yield_nothing(body):
    assert _tt5(_HEAD + body) == []


# --- last hardening round: stale + unresolved program, `+=`, starred list element ---

@pytest.mark.parametrize("body", [
    # 1. stale argv + a program that is not a literal and does not resolve to one
    "a = ['x']\na.append(q)\nprog = get()\nos.execv(prog, a)\n",
    "def f(prog):\n    a = ['x']\n    a.append(q)\n    os.execv(prog, a)\nf('sh')\n",
    "a = ['x']\na += [q]\nos.execv(sys.executable, a)\n",
    "os.execv(sys.executable, ['x', *q])\n",
    # a name rebound later is not a single binding
    "prog = '/usr/bin/git'\nprog = get()\na = ['git']\na.append(q)\nos.execv(prog, a)\n",
    # 2. `+=` on the argv name
    "a = ['x']\na += [q]\nos.execv('/bin/sh', a)\n",
    "a = ['x']\na += ['-c', q]\nos.execv('/bin/sh', a)\n",
    "a = ['x']\na += [q]\nos.spawnv(os.P_WAIT, '/bin/sh', a)\n",
    "a = ['x']\na += [q]\nos.execv('/usr/bin/python3', a)\n",
    # 3. a starred element inside a v-form argv list literal
    "os.execv('/bin/sh', ['x', *q])\n",
    "os.execv('/bin/sh', ['x', *['-c', q]])\n",
    "os.execv('/usr/bin/python3', ['python3', *q])\n",
    "a = ['x', *q]\nos.execv('/bin/sh', a)\n",
    "os.spawnv(os.P_WAIT, '/bin/sh', ['x', *q])\n",
])
def test_last_round_bypasses_are_command_injection(body):
    assert _tt5(_HEAD + body) == CMD


@pytest.mark.parametrize("body", [
    "a = ['git']\na += [q]\nos.execv('/usr/bin/git', a)\n",
    "a = ['python3', '-m', 'mod']\na += [q]\nos.execv('/usr/bin/python3', a)\n",
    "os.execv('/usr/bin/git', ['git', *q])\n",
    "os.execv('/usr/bin/python3', ['python3', '-m', 'mod', *q])\n",
    "os.execvp('git', ['git', *['log'], q])\n",
    # a program bound once to a string literal reads as that literal
    "prog = '/usr/bin/git'\nos.execv(prog, ['git'] + [q])\n",
    "prog = '/usr/bin/git'\na = ['git']\na.append(q)\nos.execv(prog, a)\n",
])
def test_last_round_benign_twins_stay_argument_injection(body):
    assert _tt5(_HEAD + body) == ARG


@pytest.mark.parametrize("body", [
    "a = ['x']\na += ['y']\nos.execv('/bin/sh', a)\n",
    "os.execv('/bin/sh', ['x', *['-c', 'ls']])\n",
    "os.execvp('git', ['git', *['log'], 'x'])\n",
    "prog = get()\nos.execv(prog, ['x', *['y']])\n",
])
def test_last_round_untainted_shapes_yield_nothing(body):
    assert _tt5(_HEAD + body) == []


def test_resolved_shell_program_binding_is_judged_as_the_shell():
    assert _tt5(_HEAD + "prog = '/bin/sh'\nos.execv(prog, ['x', '-c', q])\n") == CMD


def test_plus_equals_through_subprocess_keeps_its_verdicts():
    # ordinary head: argument injection; shell head: crit (binding dropped by B-953)
    assert _tt5(_HEAD + "a = ['git']\na += [q]\nsubprocess.run(a)\n") == ARG
    assert _tt5(_HEAD + "a = ['sh']\na += ['-c', q]\nsubprocess.run(a)\n") == CMD
