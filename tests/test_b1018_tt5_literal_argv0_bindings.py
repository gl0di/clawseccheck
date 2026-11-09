"""B-1018: TT5_CMD_INJECTION on literal-argv0 command lists the binding resolver dropped.

Real fleet false positives (B13 FAIL CRITICAL, DO-NOT-INSTALL under --vet), measured
2026-11-04 on Anthropic's docx/pptx/xlsx/skill-creator skill copies and a local
qa-expert skill:

1. ``cmd = ["claude", "-p", query, ...]`` bound inside a ``try:`` body, then
   ``Popen(cmd)`` in the same body. B-952 rejects any binding reached only
   conditionally; now a binding is still applied to a call that the assignment
   DOMINATES (same statement list, earlier), never to code after or outside it.
2. ``subprocess.run(["soffice"] + args)``: ``+`` never changes index 0, so a literal,
   non-shell-indirect left-hand argv[0] is the program.
3. ``cmd = ["python", "-m", "pytest", path]; cmd.extend([...])``: CPython ends its own
   option list at ``-m <module>`` (or the first script path), so a later append cannot
   become ``python -c``. B-953 still disqualifies an extend after a bare interpreter.

Each fix is pinned against a malicious twin that must stay CMD_INJECTION. Offline,
stdlib only, no files written.
"""
from __future__ import annotations

import pytest

from clawseccheck import skillast


def _tt5(src: str) -> list:
    return sorted(f.rule + ":" + f.severity for f in skillast.analyze_python(src)
                  if f.rule.startswith("TT5"))


ARG = ["TT5_ARG_INJECTION:info"]
CMD = ["TT5_CMD_INJECTION:crit"]

_WRAP = "import os, subprocess, sys\ndef sh(cmd):\n    subprocess.run(cmd)\n"


# ---------------------------------------------------------------- row 1: try block

def test_row1_try_body_binding_is_resolved():
    src = (
        "import sys, subprocess\n"
        "def f(model):\n"
        "    q = sys.argv[1]\n"
        "    try:\n"
        "        cmd = ['claude', '-p', q, '--verbose']\n"
        "        if model:\n"
        "            cmd.extend(['--model', model])\n"
        "        p = subprocess.Popen(cmd)\n"
        "    except Exception:\n"
        "        pass\n"
    )
    assert _tt5(src) == ARG


def test_row1_twin_try_bash_extend_through_wrapper_stays_crit():
    src = _WRAP + (
        "def main():\n"
        "    try:\n"
        "        c = ['bash']\n"
        "        c.extend(['-c', os.environ['P']])\n"
        "        sh(c)\n"
        "    except Exception:\n"
        "        pass\n"
    )
    assert _tt5(src) == CMD


def test_row1_twin_tainted_argv0_in_try_stays_crit():
    src = (
        "import sys, subprocess\n"
        "try:\n"
        "    cmd = [sys.argv[1], 'x']\n"
        "    subprocess.run(cmd)\n"
        "except Exception:\n"
        "    pass\n"
    )
    assert _tt5(src) == CMD


@pytest.mark.parametrize("src", [
    # assigned in the try body, used in the handler: the assign may not have run
    "import sys, subprocess\ncmd = sys.argv[1:]\ntry:\n    cmd = ['ls']\n"
    "except Exception:\n    subprocess.run(cmd)\n",
    # B-952 itself: assigned in a branch, used after it
    "import sys, subprocess\ndef f(d):\n    args = sys.argv[1:]\n    if d:\n"
    "        args = ['echo']\n    subprocess.run(args)\n",
    # the sink BEFORE the assignment in the same loop body
    "import sys, subprocess\ncmd = sys.argv[1:]\nfor i in range(2):\n"
    "    subprocess.run(cmd)\n    if i:\n        cmd = ['ls']\n",
])
def test_row1_non_dominating_binding_stays_crit(src):
    assert _tt5(src) == CMD


# ---------------------------------------------------------------- row 2: literal + args

def test_row2_literal_program_plus_param_is_argument_injection():
    src = (
        "import subprocess\n"
        "def run_soffice(args, **kw):\n"
        "    args = list(args)\n"
        "    return subprocess.run(['soffice'] + args, **kw)\n"
    )
    assert _tt5(src) == ARG


@pytest.mark.parametrize("left", ["['bash']", "['/bin/sh']", "['python3']", "['env']",
                                  "['sudo']"])
def test_row2_twin_shell_indirect_program_plus_param_stays_crit(left):
    src = f"import subprocess\ndef w(args):\n    return subprocess.run({left} + args)\n"
    assert _tt5(src) == CMD


def test_row2_twin_param_as_argv0_stays_crit():
    src = "import subprocess\ndef w(p, args):\n    return subprocess.run([p] + args)\n"
    assert _tt5(src) == CMD


def test_row2_twin_tainted_argv0_stays_crit():
    assert _tt5("import sys, subprocess\nsubprocess.run([sys.argv[1]] + ['x'])\n") == CMD


# ---------------------------------------------------------------- row 3: python -m

@pytest.mark.parametrize("mutation", ["cmd.extend(['-k', t])", "cmd.append('-v')",
                                      "cmd += ['-v']"])
def test_row3_python_m_module_then_append_is_argument_injection(mutation):
    src = (
        "import sys, subprocess\n"
        "t = sys.argv[1]\n"
        "cmd = ['python', '-m', 'pytest', t, '-v']\n"
        f"{mutation}\n"
        "subprocess.run(cmd)\n"
    )
    assert _tt5(src) == ARG


@pytest.mark.parametrize("head", ["['python']", "['python', '-u']", "['python3', '-mpytest']",
                                  "['python', '-m']", "['python', '-']"])
def test_row3_twin_open_interpreter_option_list_extend_stays_crit(head):
    src = _WRAP + (
        "def main():\n"
        f"    c = {head}\n"
        "    c.extend(['-c', os.environ['P']])\n"
        "    sh(c)\n"
    )
    assert _tt5(src) == CMD


def test_row3_closed_option_list_helper():
    import ast

    def elts(src):
        return ast.parse(src, mode="eval").body.elts

    closed = skillast._python_option_list_closed
    assert closed(elts("['python', '-m', 'pytest']"))
    assert closed(elts("['python3', 'script.py', '-c']"))
    assert not closed(elts("['python']"))
    assert not closed(elts("['python', '-m']"))
    assert not closed(elts("['python', '-u', '-m', 'x']"))
    assert not closed(elts("['python', '-m', x]"))
    assert not closed(elts("['python', '-']"))


@pytest.mark.parametrize("rebind", [
    "cmd, x = [q], 1",
    "(cmd, x) = ([q], 1)",
    "cmd, = [[q]]",
    "[cmd] = [[q]]",
    "del cmd\n        cmd2 = 1",
    "import cmd",
])
def test_row1_other_rebinding_in_the_try_body_stays_crit(rebind):
    """C-135 round 1: tuple/list unpacking (and every other store of the name) used to
    slip past the B-1018 re-check."""
    src = (
        "import sys, subprocess\n"
        "def f():\n"
        "    q = sys.argv[1]\n"
        "    try:\n"
        "        cmd = ['ls']\n"
        f"        {rebind}\n"
        "        subprocess.run(cmd)\n"
        "    except Exception:\n"
        "        pass\n"
    )
    assert _tt5(src) != ARG


def test_row1_global_rebind_from_another_function_stays_crit():
    src = (
        "import sys, subprocess\n"
        "def g():\n"
        "    global cmd\n"
        "    cmd = sys.argv[1:]\n"
        "try:\n"
        "    cmd = ['ls']\n"
        "    g()\n"
        "    subprocess.run(cmd)\n"
        "except Exception:\n"
        "    pass\n"
    )
    assert _tt5(src) == CMD


@pytest.mark.parametrize("pattern", ["[*cmd]", "[_, *cmd]", "_ as cmd", "{**cmd}"])
def test_row1_match_capture_rebinding_stays_crit(pattern):
    # Python 3.9 cannot parse `match` (AST_UNANALYZABLE, never ARG), so no skip needed.
    src = (
        "import sys, subprocess\n"
        "def f():\n"
        "    try:\n"
        "        cmd = ['ls']\n"
        "        match sys.argv[1:]:\n"
        f"            case {pattern}:\n"
        "                pass\n"
        "        subprocess.run(cmd)\n"
        "    except Exception:\n"
        "        pass\n"
    )
    assert _tt5(src) != ARG
