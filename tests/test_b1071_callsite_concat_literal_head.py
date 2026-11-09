"""B-1071: a literal-headed ``+`` chain at a wrapper's CALL SITE is a fixed argv.

Real false positive (B13 FAIL CRITICAL, DO-NOT-INSTALL under --vet): a wrapper
``def run(cmd): subprocess.run(cmd)`` called as ``run(["kubectl", "exec", pod] +
["ls"])``. ``+`` on a list never changes index 0, so argv[0] is the head literal's
first element; the tainted ``pod`` is only an argument. The call-site resolver used
to treat any non-literal call-site expression as unresolvable, i.e. crit. B-1018 had
already taught the SINK side the same rule.

Fail-closed: the head program must be a plain string that cannot become a shell /
interpreter / re-exec wrapper, and a call site whose program is an inline
``sys.argv``/``argv``/``input()`` read stays crit. That second guard also closes a
pre-existing miss (``run([sys.argv[1]])``) that a crit concat sibling used to mask.
Offline, stdlib only, no files written.
"""
from __future__ import annotations

import pytest

from clawseccheck import skillast


def _tt5(src: str) -> list:
    return sorted({f.rule + ":" + f.severity for f in skillast.analyze_python(src)
                   if f.rule.startswith("TT5")})


CMD = "TT5_CMD_INJECTION:crit"

_WRAP = "import subprocess, sys, os\ndef run(cmd):\n    return subprocess.run(cmd)\n"
_ARG = "import argparse\np = argparse.ArgumentParser(); p.add_argument('--pod'); a = p.parse_args()\n"


@pytest.mark.parametrize("call", [
    "run(['kubectl', 'exec', a.pod] + ['ls'])",
    "run(['git', '-C', a.pod] + ['log'] + ['--oneline'])",
    "run(('kubectl', 'exec', a.pod) + ('ls',))",
])
def test_literal_headed_concat_at_call_site_is_not_command_injection(call):
    assert CMD not in _tt5(_WRAP + _ARG + call + "\n")


@pytest.mark.parametrize("call", [
    "run(['bash', '-c'] + [sys.argv[1]])",      # shell head
    "run(['bash'] + ['-c', sys.argv[1]])",      # shell head, flag in the tail
    "run(['env'] + [sys.argv[1]])",             # re-exec wrapper head
    "run(['find', '.'] + [sys.argv[1]])",       # find can gain -exec
    "run([sys.argv[1]] + ['x'])",               # tainted head
    "run(sys.argv[1:] + ['x'])",                # tainted left operand
    "run(['ls'] * 1 + [sys.argv[1]])",          # non-literal head (BinOp Mult)
    "run([*sys.argv[1:]] + ['x'])",             # starred head
    "run(['ls'] + sys.argv[1:])",               # non-display right operand
    "run(['ls'] + E())",                        # __radd__ object could rewrite argv[0]
    "run(['docker', 'exec', 'c'] + ['sh', '-c', sys.argv[1]])",   # C-135: exec-family head
    "run(['kubectl', 'exec', 'p', '--'] + ['sh', '-c', sys.argv[1]])",
    "run(['python3.12'] + ['-c', sys.argv[1]])",                  # versioned interpreter
    "run(['git', '-c'] + [sys.argv[1], 'status'])",               # git -c core.sshCommand
])
def test_malicious_twins_stay_command_injection(call):
    evil_cls = (
        "class E(list):\n"
        "    def __radd__(self, other):\n"
        "        return ['sh', '-c', sys.argv[1]]\n"
    )
    assert CMD in _tt5(_WRAP + evil_cls + call + "\n")


@pytest.mark.parametrize("second", [
    "run([sys.argv[1]])",
    "run(['sh', '-c', sys.argv[1]])",
    "run(['bash', '-c', input()])",
    "run([input()])",
    "run([os.environ['X']])",
])
def test_a_tainted_sibling_call_site_still_convicts(second):
    src = _WRAP + "run(['ls'] + ['-l'])\n" + second + "\n"
    assert CMD in _tt5(src)


def test_from_sys_import_argv_program_stays_crit():
    src = (
        "import subprocess\nfrom sys import argv\n"
        "def run(cmd):\n    return subprocess.run(cmd)\n"
        "run(['ls'] + ['-l'])\nrun([argv[1], 'x'])\n"
    )
    assert CMD in _tt5(src)


def test_shell_true_wrapper_stays_crit():
    src = (
        "import subprocess, sys\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n"
        "run(['ls'] + [sys.argv[1]])\n"
    )
    assert CMD in _tt5(src)
