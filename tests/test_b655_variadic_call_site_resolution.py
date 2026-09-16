"""CLAWSECCHECK-B-655: TT5 (B-413 layer 2) call-site resolution had two independent
gaps for the variadic subprocess-wrapper idiom (`def sh(*args): check_output(list(args))`),
so it stayed crit even when every intra-file call site passed a fully-literal argv —
while the ordinary, non-variadic form of the identical wrapper was already cleared:

  1a. The layer-2 gate at the sink call site checked only
      `fn.args.posonlyargs/args/kwonlyargs` for a name match, excluding
      `fn.args.vararg` — so layer 2 never even attempted to run for a vararg param.
  1b. `_param_argv_call_sites` bailed unconditionally whenever `fn` had `*args`/
      `**kwargs` in its OWN signature (`if args.vararg or args.kwarg: return None`).
      Sound for an ORDINARY parameter sharing a function with a vararg (the
      parameter's position could depend on unpacking), unsound as a reason to refuse
      the vararg itself: its binding at every call site is exactly "every positional
      argument from index len(positional_names) onward".
  1c. `check_output(list(args))` — the sink's first argument is an `ast.Call`
      (`list(...)`), not a bare `ast.Name`, so neither the literal-List/Tuple branch
      nor the bare-Name/layer-2 branch was ever reached at all, independently of 1a/1b.

Fix (clawseccheck/skillast.py): 1c unwraps a single-argument `list(x)`/`tuple(x)`
call around a bare Name to that Name. 1a widens the gate to also match the vararg
name. 1b lets `_param_argv_call_sites` proceed when the resolved param IS the
vararg, synthesizing one `ast.List` per call site out of
`call.args[len(positional_names):]` and handing it to the EXISTING
`_all_call_sites_bind_fixed_argv` unchanged — same literal-argv / argv0-shell-
indirect-exec rules a non-vararg wrapper already gets, including the
retracted-and-narrowed "sh -c <tainted>" case (B-413 layer 2's own C-135 history).

A self-caught defect during this task's own implementation, worth naming here since
it is exactly the shape the task's gates existed to catch: the FIRST synthesis wrote
`ast.List(elts=list(call.args[vararg_start:]), ctx=ast.Load())` and appended it
directly to `bound_exprs` without registering it in `owner_map`.
`_all_call_sites_bind_fixed_argv` resolves taint VISIBILITY via `owner_map.get(expr)`
on that synthetic node — an unregistered node reads as module scope only, silently
DROPPING a caller-local tainted variable and wrongly clearing the exact "sh -c
<tainted>" case this task's gates require to stay crit
(test_retracted_sh_dash_c_case_stays_crit below reproduced it failing before the
`owner_map[synthetic] = owner_map.get(call)` line was added). Caught by this file's
own tests before any external review, not by one.

A SECOND defect, caught by an independent C-135 adversarial pass (not self-caught):
the 1c unwrap trusted that a bare-name call to `list`/`tuple` really meant the
builtin, with no check for a file that shadows the name (`def list(x): return
["sh", "-c", tainted]`). That shape silently cleared TT5_CMD_INJECTION for BOTH the
new vararg path and the pre-existing ordinary (non-vararg) B-413 layer-2 path, since
1c's unwrap runs before either branches. Fixed with `_name_rebound_anywhere` — a
whole-file, not-scope-precise "is this name rebound ANYWHERE" check that only ever
makes the unwrap MORE conservative when uncertain (see
test_shadowed_list_builtin_defeats_nothing_vararg_case /
test_shadowed_list_builtin_defeats_nothing_non_variadic_case below).

Offline, deterministic. No network calls, no writes outside tmp_path.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import PASS
from clawseccheck.skillast import analyze_python

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _rules(src: str) -> dict:
    return {f.rule: f for f in analyze_python(src, "t.py")}


def _b13(home: Path):
    _, findings, _ = audit(home, include_native=False)
    return {f.id: f for f in findings}["B13"]


# --------------------------------------------------------------------------------- 1
# Gap 1: the primary case -- a variadic wrapper, every call site literal, must clear.


def test_variadic_wrapper_all_literal_call_sites_clears():
    src = (
        "import subprocess\n"
        "\n"
        "def sh(*args):\n"
        "    return subprocess.check_output(list(args), text=True).strip()\n"
        "\n"
        "def main():\n"
        "    print(sh('git', 'describe', '--tags'))\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r, r.get("TT5_CMD_INJECTION")


def test_variadic_wrapper_with_tuple_call_clears_too():
    """1c must handle both list(...) and tuple(...) around the vararg."""
    src = (
        "import subprocess\n"
        "\n"
        "def sh(*args):\n"
        "    return subprocess.check_output(tuple(args), text=True).strip()\n"
        "\n"
        "def main():\n"
        "    print(sh('git', 'describe'))\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r


def test_variadic_wrapper_with_leading_positional_param_clears():
    """1b's slicing must correctly skip the wrapper's own leading positional params
    before collecting the vararg-bound call arguments."""
    src = (
        "import subprocess\n"
        "\n"
        "def sh(label, *args):\n"
        "    return subprocess.check_output(list(args), text=True).strip()\n"
        "\n"
        "def main():\n"
        "    print(sh('note:', 'git', 'status'))\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r


def test_shadowed_list_builtin_defeats_nothing_vararg_case():
    """C-135: a file that shadows `list` with its own def must not let the 1c unwrap
    treat that call as the trusted builtin -- the shadow could return anything,
    including a hardcoded sh -c <tainted> argv unrelated to the literal call-site
    arguments. Caught during this task's own adversarial review; verified this exact
    shape was silently cleared before `_name_rebound_anywhere` was added."""
    src = (
        "import os\n"
        "import subprocess\n"
        "\n"
        "def list(x):\n"
        "    return ['sh', '-c', os.environ['WEBHOOK_PAYLOAD']]\n"
        "\n"
        "def sh(*args):\n"
        "    return subprocess.check_output(list(args))\n"
        "\n"
        "def main():\n"
        "    print(sh('git', 'status'))\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r, "regression: a shadowed list() builtin defeated the unwrap"
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_shadowed_list_builtin_defeats_nothing_non_variadic_case():
    """Same shadowing concern, but through the ORDINARY (non-vararg) B-413 layer-2
    path -- the 1c unwrap runs for both, so the shadow check must too."""
    src = (
        "import os\n"
        "import subprocess\n"
        "\n"
        "def list(x):\n"
        "    return ['sh', '-c', os.environ['WEBHOOK_PAYLOAD']]\n"
        "\n"
        "def run(cmd):\n"
        "    subprocess.check_output(list(cmd))\n"
        "\n"
        "def main():\n"
        "    run(['git', 'status'])\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_unshadowed_list_builtin_still_unwraps_correctly():
    """Control: no shadowing anywhere in the file -- the 1c unwrap must still work,
    proving the shadow check is not simply refusing every unwrap unconditionally."""
    src = (
        "import subprocess\n"
        "\n"
        "def sh(*args):\n"
        "    return subprocess.check_output(list(args))\n"
        "\n"
        "def main():\n"
        "    print(sh('git', 'status'))\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r


def test_variadic_wrapper_with_kwarg_in_signature_still_clears():
    """The function having **kwargs alongside *args must not itself force a bail --
    only a **unpack AT A CALL SITE should (see the starred/kwarg-unpack tests
    below)."""
    src = (
        "import subprocess\n"
        "\n"
        "def sh(*args, **kwargs):\n"
        "    return subprocess.check_output(list(args), text=True).strip()\n"
        "\n"
        "def main():\n"
        "    print(sh('git', 'status'))\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r


# --------------------------------------------------------------------------------- 2
# The gate: the retracted "sh -c <tainted>" case must survive the synthesis unchanged.
# This is the task's own explicit reason to prefer the synthesis shape, and the exact
# case that caught this task's own self-introduced owner_map bug.


def test_retracted_sh_dash_c_case_stays_crit():
    """sh("sh", "-c", <tainted>) -- argv0 is a shell taking -c, so every OTHER argv
    element must also be checked for taint, not just argv0. Must stay crit through
    the vararg synthesis exactly as it already does through the non-variadic path."""
    src = (
        "import os\n"
        "import subprocess\n"
        "\n"
        "def sh(*args):\n"
        "    return subprocess.check_output(list(args), text=True).strip()\n"
        "\n"
        "def main():\n"
        "    payload = os.environ['WEBHOOK_PAYLOAD']\n"
        "    print(sh('sh', '-c', payload))\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r, "regression: the retracted sh -c <tainted> case was wrongly cleared"
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_tainted_program_name_via_vararg_stays_crit():
    """argv[0] itself tainted, reached only through the vararg synthesis path."""
    src = (
        "import os\n"
        "import subprocess\n"
        "\n"
        "def sh(*args):\n"
        "    return subprocess.check_output(list(args), text=True).strip()\n"
        "\n"
        "def main():\n"
        "    prog = os.environ['PROG']\n"
        "    print(sh(prog, 'status'))\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


# --------------------------------------------------------------------------------- 3
# Every existing bail must still apply to the vararg path.


def test_zero_call_sites_stays_crit():
    """Load-bearing: a helper with no intra-file caller is unknown from outside the
    file and MUST stay crit."""
    src = (
        "import subprocess\n"
        "\n"
        "def sh(*args):\n"
        "    return subprocess.check_output(list(args), text=True).strip()\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_starred_unpack_at_call_site_stays_crit():
    """*extra at a call site defeats positional resolution -- must bail, not guess."""
    src = (
        "import subprocess\n"
        "\n"
        "def sh(*args):\n"
        "    return subprocess.check_output(list(args), text=True).strip()\n"
        "\n"
        "def main():\n"
        "    extra = ['status']\n"
        "    print(sh('git', *extra))\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_kwargs_unpack_at_call_site_stays_crit():
    """**extra at a call site -- must bail."""
    src = (
        "import subprocess\n"
        "\n"
        "def sh(*args):\n"
        "    return subprocess.check_output(list(args), text=True).strip()\n"
        "\n"
        "def main():\n"
        "    extra = {}\n"
        "    print(sh('git', 'status', **extra))\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_wrapper_name_used_as_value_stays_crit():
    """The wrapper's bare name referenced somewhere other than Call.func (e.g.
    reassigned) is an indirect call this walk cannot see -- must bail."""
    src = (
        "import subprocess\n"
        "\n"
        "def sh(*args):\n"
        "    return subprocess.check_output(list(args), text=True).strip()\n"
        "\n"
        "def main():\n"
        "    f = sh\n"
        "    print(sh('git', 'status'))\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


# --------------------------------------------------------------------------------- 4
# Regression guard: the ordinary (non-variadic) B-413 layer-2 path this task
# deliberately reuses (_all_call_sites_bind_fixed_argv, unchanged) must keep behaving
# exactly as before.


def test_non_variadic_wrapper_still_clears():
    src = (
        "import subprocess\n"
        "\n"
        "def run(cmd):\n"
        "    subprocess.check_call(cmd)\n"
        "\n"
        "def main():\n"
        "    run(['git', 'status'])\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r


def test_non_variadic_sh_dash_c_tainted_still_stays_crit():
    src = (
        "import os\n"
        "import subprocess\n"
        "\n"
        "def run(cmd):\n"
        "    subprocess.check_call(cmd)\n"
        "\n"
        "def main():\n"
        "    payload = os.environ['X']\n"
        "    run(['sh', '-c', payload])\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


# --------------------------------------------------------------------------------- 5
# The neighbouring FP (migration runner) named in the task must NOT be "fixed" -- the
# task's own C-135 measurement proved a call-site-anchoring exemption for exec()
# defeatable in 4 lines from a second file in the same skill. This diff only touches
# subprocess argv call-site resolution, never exec()'s own taint detection, so the
# migration-runner shape must fire EXACTLY as before: unchanged, still crit.


def test_migration_runner_exec_shape_is_unaffected_by_this_fix():
    src = (
        "import pathlib\n"
        "\n"
        "MIG = pathlib.Path(__file__).with_name('migrations')\n"
        "\n"
        "def load_migration(path):\n"
        "    ns = {}\n"
        "    exec(compile(path.read_text(encoding='utf-8'), str(path), 'exec'), ns)\n"
        "    return ns\n"
    )
    r = _rules(src)
    # This is the task's OWN named false positive, and the task's own point is that
    # it must NOT be "fixed" (proven unfixable by sound static means -- a
    # __file__-anchored-call-site exemption is defeatable in 4 lines from a second
    # file in the same skill, per the task's own C-135 measurement). It fires via
    # exec()'s own taint detection, which this fix never touches (only subprocess
    # argv call-site resolution) -- still crit, unchanged, on purpose.
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


# --------------------------------------------------------------------------------- 6
# The existing fixed-argv fixture suite must be untouched by this change.


def test_clean_b13_fixed_argv_subprocess_fixture_still_passes():
    f = _b13(FIXTURES / "clean_b13_fixed_argv_subprocess")
    assert f.status == PASS, (f.status, f.detail)
