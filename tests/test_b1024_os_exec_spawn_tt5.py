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
    "os.execvp(*q)",              # starred positional
    "os.spawnv(os.P_WAIT)",       # mode only
    "os.execl()",
    "os.execvp('sh', [])",        # empty argv
    "os.execv_unknown(q, [q])",   # not an os.exec* name
])
def test_unparseable_or_unclaimed_shapes_yield_no_tt5_and_do_not_raise(call):
    assert _tt5(_HEAD + call + "\n") == []


def test_syntax_error_source_does_not_raise():
    assert isinstance(skillast.analyze_python(_HEAD + "os.execvp('sh', ['sh', '-c', q]\n"), list)
