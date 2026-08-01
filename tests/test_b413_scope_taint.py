"""Regression tests for CLAWSECCHECK-B-413: scope/binding-aware taint for
TT5_CMD_INJECTION (clawseccheck/skillast.py, `_external_tainted_names` /
`_subprocess_taint_is_command_injection`).

Two independent bugs, fixed independently:

Layer 1 -- scope-bucketed external taint. The old `_collect_func_params` seeded EVERY
function's parameter names into one flat `set[str]`, and `_external_tainted_names`
resolved taint by pure identifier-name matching across the whole file, with no scope
awareness. That let a parameter in one function taint an unrelated same-named local in
a totally different function (SkillTrustBench case_00374), or let a generic name
(`missing`/`data`/`result`) reused across sibling functions collide (case_01948).
Fixed by `_func_param_taint_by_scope` (per-function taint buckets) +
`_external_tainted_names` resolving sourced-ness against `_tainted_names_visible` at
each assignment's own lexical position -- the same scope/binding model already used
for the decode->exec taint rule (`_tainted_names`).

Layer 2 -- call-site argv resolution for wrapper functions. The ordinary, encouraged
`def run(cmd): subprocess.check_call(cmd, ...)` idiom is NOT fixed by layer 1 alone:
`cmd` really is tainted from `run`'s own scope (that part of layer 1 is correct). Only
inspecting every intra-file call site to `run` can prove every real invocation passes
a fully-hardcoded, untainted-program argv list. Fixed by `_param_argv_call_sites` +
`_all_call_sites_bind_fixed_argv`, wired into `_subprocess_taint_is_command_injection`
strictly AFTER the existing `shell=` gate and only for the `subprocess.*` branch --
never for `os.system`/`eval`/`exec`, and never when any call site is unresolvable or
passes a tainted program name.

Offline, deterministic. No network calls, no writes outside tmp_path.
"""

from __future__ import annotations

import ast
from pathlib import Path

import clawseccheck.skillast as skillast_mod
from clawseccheck.catalog import FAIL, PASS
from clawseccheck.checks import vet_skill
from clawseccheck.skillast import analyze_python

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _rules(src: str) -> dict[str, object]:
    return {f.rule: f for f in analyze_python(src, "t.py")}


def _findings(src: str) -> list:
    return list(analyze_python(src, "t.py"))


def _toplevel_funcs(tree: ast.AST) -> list:
    return [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


# ---------------------------------------------------------------------------
# Layer 1: scope-bucketed external taint
# ---------------------------------------------------------------------------


def test_cross_scope_param_collision_not_falsely_tainted():
    """case_00374 shape: a helper's own parameter must not taint an unrelated
    same-named, deterministic local in a completely different function."""
    src = (
        "import subprocess\n"
        "from pathlib import Path\n"
        "\n"
        "\n"
        "def _resolve_python(venv_dir):\n"
        "    return venv_dir / 'bin' / 'python'\n"
        "\n"
        "\n"
        "def main():\n"
        "    root = Path(__file__).resolve().parent\n"
        "    venv_dir = root / '.venv'\n"
        "    interpreter = _resolve_python(venv_dir)\n"
        "    subprocess.check_call([str(interpreter), '-m', 'pip', 'install', '-U', 'pip'])\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r
    assert "TT5_ARG_INJECTION" not in r


def test_generic_name_reused_across_sibling_functions_not_conflated():
    """case_01948 shape: a generic local name (`missing`) reused in two unrelated
    sibling functions must not let one function's sourcing taint the other's."""
    src = (
        "import subprocess\n"
        "\n"
        "\n"
        "def _ensure_deps():\n"
        "    missing = []\n"
        "    missing.append('pandas')\n"
        "    subprocess.check_call(['pip', 'install'] + missing)\n"
        "\n"
        "\n"
        "def read_and_normalize(required):\n"
        "    missing = [c for c in required if c not in ('a', 'b')]\n"
        "    return missing\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r


def test_own_param_still_crits_when_it_reaches_a_sink_directly():
    """Regression guard: layer 1 fixes the CROSS-scope collision, not detection of a
    parameter that genuinely IS the function's own -- a bare `def f(cmd): eval(cmd)`
    with no wrapper indirection must stay crit, even alongside an unrelated sibling
    function using the same bare parameter name for something harmless."""
    src = (
        "def unrelated(cmd):\n"
        "    return len(cmd)\n"
        "\n"
        "\n"
        "def run_code(cmd):\n"
        "    eval(cmd)\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_module_level_source_flows_into_function_via_closure_read():
    """A module-level tainted source (os.environ) must still taint a function that
    reads it as a closure (module bucket == None) -- layer 1 must not silently drop
    the module-bucket case while fixing the per-function scoping."""
    src = (
        "import os\n"
        "import subprocess\n"
        "\n"
        "cmd = os.environ['USER_CMD']\n"
        "\n"
        "\n"
        "def run_it():\n"
        "    subprocess.run(cmd, shell=True)\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_global_declared_taint_still_crosses_functions():
    """Regression guard for the global/nonlocal bucket-redirection rewrite: a
    `global`-declared assignment in one function must still taint a read in another."""
    src = (
        "import subprocess\n"
        "\n"
        "cmd = None\n"
        "\n"
        "\n"
        "def set_cmd(user_cmd):\n"
        "    global cmd\n"
        "    cmd = user_cmd\n"
        "\n"
        "\n"
        "def run_it():\n"
        "    subprocess.run(cmd, shell=True)\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_nonlocal_declared_taint_still_resolves():
    """Regression guard: a `nonlocal`-declared write in a nested closure must still
    land in the enclosing function's own bucket and reach a sink there."""
    src = (
        "import subprocess\n"
        "\n"
        "\n"
        "def outer(user_cmd):\n"
        "    cmd = None\n"
        "\n"
        "    def setter():\n"
        "        nonlocal cmd\n"
        "        cmd = user_cmd\n"
        "\n"
        "    setter()\n"
        "    subprocess.run(cmd, shell=True)\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r


def test_many_function_scopes_do_not_lose_detection():
    """C-135 regression (round 1, B-413): a prior draft capped the number of
    distinct function scopes and fell back excess ones to the shared module bucket
    as a claimed 'fails toward crit, never toward silent PASS' safety valve. An
    independent adversarial pass proved the opposite: `_tainted_names_visible`'s
    shadow-subtraction treats a scope's own parameter as shadowing the module
    bucket's same-named entry, so a param dumped into the fallback bucket became
    INVISIBLE inside its own owning function -- a silent detection loss, not a
    safety valve. The cap was removed; every function gets its own isolated bucket
    regardless of file size. This pins a scaled-down version of the exact repro
    that found the bug: many unrelated dummy functions ahead of one real tainted
    wrapper must not suppress the real finding."""
    src = "\n".join(f"def _dummy{i}(x):\n    return x + {i}\n" for i in range(50))
    src += (
        "\n\nimport subprocess\n\n\n"
        "def evil_runner(cmd):\n"
        "    subprocess.call(cmd, shell=True)\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_wrapper_shell_interpreter_tainted_arg_stays_crit():
    """C-135 regression (round 1, B-413): layer 2 originally checked only argv[0]
    (the program name) for taint. When argv[0] is itself a shell/interpreter (sh,
    bash, env, sudo, xargs, ssh, python -c, ...), the REST of the argv list is not
    inert data -- it is text the interpreter parses and runs. A wrapper called only
    with a hardcoded `["sh", "-c", <tainted>]` must stay crit, not downgrade just
    because "sh" itself is a hardcoded literal."""
    src = (
        "import os, subprocess\n"
        "\n"
        "\n"
        "def run(cmd):\n"
        "    subprocess.check_call(cmd)\n"
        "\n"
        "\n"
        "def handle_webhook():\n"
        '    user_cmd = os.environ["WEBHOOK_PAYLOAD"]\n'
        '    run(["sh", "-c", user_cmd])\n'
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_wrapper_shell_interpreter_all_literal_args_stays_fixed():
    """CAPABILITY: the shell-interpreter widening above must not become a blanket
    'argv[0] is a shell -> always crit' rule -- when EVERY element (including the
    ones after the interpreter name) is a hardcoded literal, layer 2 must still
    correctly downgrade."""
    src = (
        "import subprocess\n"
        "\n"
        "\n"
        "def run(cmd):\n"
        "    subprocess.check_call(cmd)\n"
        "\n"
        "\n"
        "def main():\n"
        '    run(["sh", "-c", "echo hello"])\n'
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r


def test_general_interpreter_ordinary_module_args_not_command_injection():
    """C-135 regression (round 2, B-413, self-caught in integration): the
    shell-interpreter widening initially treated ANY invocation of a general-purpose
    interpreter (python/perl/ruby/node/...) as dangerous whenever a later argv
    element was tainted -- but `python -m edge_tts --text {text} --voice {voice}`
    (a real, previously-correctly-PASSing fixture) passes text/voice as ORDINARY CLI
    ARGUMENTS to a well-behaved module, not as code for python to execute. Only an
    explicit eval-style flag (-c/-e/--eval) makes an interpreter's later args into
    code; a bare module/script invocation must NOT crit."""
    src = (
        "import subprocess\n"
        "\n"
        "\n"
        "def say(text, voice):\n"
        '    subprocess.run(["python", "-m", "edge_tts", "--text", text, "--voice", voice])\n'
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r


def test_general_interpreter_eval_flag_tainted_arg_stays_crit():
    """CAPABILITY: the ordinary-args exemption above must not become a blanket
    'interpreters are always safe' rule -- an explicit -c/-e flag followed by a
    tainted string is genuine command injection."""
    src = (
        "import os, subprocess\n"
        "\n"
        "\n"
        "def run_code():\n"
        '    payload = os.environ["PAYLOAD"]\n'
        '    subprocess.run(["python", "-c", payload])\n'
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_reexec_wrapper_tainted_trailing_command_stays_crit():
    """CAPABILITY: env/sudo/doas/nohup/ssh re-exec their trailing args as a new
    command by construction -- no eval-flag needed for these, unlike general
    interpreters."""
    src = (
        "import os, subprocess\n"
        "\n"
        "\n"
        "def run():\n"
        '    cmd = os.environ["CMD"]\n'
        '    subprocess.run(["env", cmd])\n'
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_func_param_taint_by_scope_falls_back_for_unreachable_function():
    """A function nested inside a bare module-level `if` (not inside a class or
    another function) is never reached by `_build_toplevel_owner_map`'s top-level-only
    seed -- its params must fall back to the module bucket, not be dropped."""
    src = "if True:\n    def helper(x):\n        pass\n"
    tree = ast.parse(src)
    owner_map, parent_scope = skillast_mod._build_toplevel_owner_map([], [])
    taint = skillast_mod._func_param_taint_by_scope(tree, owner_map, parent_scope)
    assert "x" in taint.get(None, set())


# ---------------------------------------------------------------------------
# Layer 2: call-site argv resolution for wrapper functions
# ---------------------------------------------------------------------------


def test_wrapper_literal_call_sites_downgrades_to_arg_injection():
    """The ordinary wrapper idiom (case_01405/case_03476 shape): every real call site
    passes a hardcoded argv list with a fixed program -- must downgrade to
    TT5_ARG_INJECTION (info), never TT5_CMD_INJECTION (crit)."""
    src = (
        "import subprocess\n"
        "import sys\n"
        "\n"
        "\n"
        "def run(cmd, cwd):\n"
        "    subprocess.run(cmd, cwd=cwd, capture_output=True)\n"
        "\n"
        "\n"
        "def main():\n"
        "    run([sys.executable, '-m', 'tool_a', '--flag'], cwd='.')\n"
        "    run([sys.executable, '-m', 'tool_b'], cwd='.')\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r
    assert "TT5_ARG_INJECTION" in r
    assert r["TT5_ARG_INJECTION"].severity == "info"


def test_wrapper_keyword_bound_call_site_downgrades():
    """A call site binding the wrapper's parameter by KEYWORD (`run(cmd=[...])`) must
    resolve the same way as positional binding."""
    src = (
        "import subprocess\n"
        "\n"
        "\n"
        "def run(cmd):\n"
        "    subprocess.run(cmd)\n"
        "\n"
        "\n"
        "def main():\n"
        "    run(cmd=['git', '--version'])\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r
    assert "TT5_ARG_INJECTION" in r


def test_wrapper_var_bound_list_untainted_program_downgrades():
    """A call site binding the wrapper's parameter to a LOCAL variable that is itself
    bound (exactly once) to a literal list -- resolved through the existing
    `_list_bindings_by_call` machinery -- must also downgrade."""
    src = (
        "import subprocess\n"
        "\n"
        "\n"
        "def run(cmd):\n"
        "    subprocess.run(cmd)\n"
        "\n"
        "\n"
        "def main():\n"
        "    argv = ['git', 'status']\n"
        "    run(argv)\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r
    assert "TT5_ARG_INJECTION" in r


def test_wrapper_tainted_program_name_at_call_site_stays_crit():
    """MUST NOT swallow a genuine tainted-argv[0]-through-a-wrapper case: the wrapper
    call site passes an inline list whose program name is itself externally tainted."""
    src = (
        "import os\n"
        "import subprocess\n"
        "\n"
        "\n"
        "def run(cmd):\n"
        "    subprocess.run(cmd)\n"
        "\n"
        "\n"
        "def main():\n"
        "    interpreter = os.environ['BUILD_INTERPRETER']\n"
        "    run([interpreter, '-m', 'build_tool'])\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_wrapper_var_bound_tainted_program_name_stays_crit():
    """Same as above, but the tainted program name reaches the call site through a
    var-bound list (`_list_bindings_by_call`) rather than an inline list."""
    src = (
        "import os\n"
        "import subprocess\n"
        "\n"
        "\n"
        "def run(cmd):\n"
        "    subprocess.run(cmd)\n"
        "\n"
        "\n"
        "def main():\n"
        "    interpreter = os.environ['BUILD_INTERPRETER']\n"
        "    argv = [interpreter, '-m', 'build_tool']\n"
        "    run(argv)\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r


def test_wrapper_zero_call_sites_stays_crit():
    """Load-bearing: a wrapper helper with NO intra-file caller is genuinely unknown
    from outside the file and must stay crit -- the zero-call-sites rule."""
    src = (
        "import subprocess\n"
        "\n"
        "\n"
        "def run(cmd):\n"
        "    subprocess.run(cmd)\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_direct_param_no_wrapper_no_callers_stays_crit():
    """A parameter passed DIRECTLY to subprocess with no wrapper indirection at all
    (module-level source, or a function nobody calls) must stay crit."""
    src = "import subprocess\ndef run_cmd(cmd):\n    subprocess.run(cmd, shell=True)\n"
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_shell_true_still_crits_even_with_literal_call_sites():
    """The `shell=True` gate must run BEFORE layer 2's call-site resolution and
    short-circuit to crit unconditionally, regardless of how safe every call site
    looks under argv-list analysis."""
    src = (
        "import subprocess\n"
        "import sys\n"
        "\n"
        "\n"
        "def run(cmd):\n"
        "    subprocess.run(cmd, shell=True)\n"
        "\n"
        "\n"
        "def main():\n"
        "    run([sys.executable, '-m', 'tool_a'])\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_eval_sink_untouched_by_layer2_stays_crit():
    """Layer 2 only applies inside the `subprocess.*` branch -- eval() must stay crit
    even when the wrapper's only intra-file call site passes a literal string."""
    src = (
        "def run_code(code):\n"
        "    eval(code)\n"
        "\n"
        "\n"
        "def main():\n"
        "    run_code('print(1)')\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_os_system_untouched_by_layer2_stays_crit():
    """Layer 2 only applies inside the `subprocess.*` branch -- os.system() must stay
    crit even when the wrapper's only intra-file call site passes a literal string."""
    src = (
        "import os\n"
        "def run_cmd(cmd):\n"
        "    os.system(cmd)\n"
        "\n"
        "\n"
        "def main():\n"
        "    run_cmd('echo hi')\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_wrapper_star_args_in_definition_stays_crit():
    """A wrapper defined with `*args`/`**kwargs` cannot have its parameter position
    pinned down for every caller -- must stay unresolvable (crit)."""
    src = (
        "import subprocess\n"
        "\n"
        "\n"
        "def run(cmd, *extra):\n"
        "    subprocess.run(cmd)\n"
        "\n"
        "\n"
        "def main():\n"
        "    run(['git', 'status'])\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r


def test_wrapper_star_args_at_call_site_stays_crit():
    """A call site using `*args` unpacking cannot be safely positionally resolved --
    must stay crit."""
    src = (
        "import subprocess\n"
        "\n"
        "\n"
        "def run(cmd):\n"
        "    subprocess.run(cmd)\n"
        "\n"
        "\n"
        "def main():\n"
        "    argv = ['git', 'status']\n"
        "    run(*[argv])\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r


def test_wrapper_aliased_name_stays_crit():
    """The wrapper's bare name used as a plain VALUE somewhere (aliasing / passed as a
    callback) is an indirect call this walk cannot see -- must stay conservative
    (crit), not silently resolved via only the visible direct calls."""
    src = (
        "import subprocess\n"
        "\n"
        "\n"
        "def run(cmd):\n"
        "    subprocess.run(cmd)\n"
        "\n"
        "\n"
        "def main():\n"
        "    handler = run\n"
        "    handler(['git', 'status'])\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r


def test_wrapper_call_site_cap_stays_crit(monkeypatch):
    """B-413 safety cap: a wrapper with more intra-file call sites than
    `_MAX_WRAPPER_CALL_SITES` is treated as unresolvable (stays crit) rather than
    scanned in full."""
    monkeypatch.setattr(skillast_mod, "_MAX_WRAPPER_CALL_SITES", 2)
    calls = "\n".join(f"run(['prog', '--n', '{i}'])" for i in range(4))
    src = "import subprocess\ndef run(cmd):\n    subprocess.run(cmd)\n\n\n" + calls + "\n"
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r


def test_wrapper_default_value_call_site_stays_crit():
    """C-135 adversarial check: a call site that relies on the wrapper's own DEFAULT
    value (`run()` with no argument at all) is not modelled -- must stay crit rather
    than assume the default is safe."""
    src = (
        "import subprocess\n"
        "\n"
        "\n"
        "def run(cmd=None):\n"
        "    subprocess.run(cmd)\n"
        "\n"
        "\n"
        "def main():\n"
        "    run()\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r


def test_wrapper_mutated_list_binding_stays_crit():
    """C-135 adversarial check: a var-bound argv list that is safely literal at
    binding time but index-assigned (`argv[0] = ...`) before the call is exactly the
    mutation `_single_list_bindings_local` already excludes -- must stay unresolved
    (crit), not be read as the original safe literal."""
    src = (
        "import subprocess\n"
        "\n"
        "\n"
        "def run(cmd):\n"
        "    subprocess.run(cmd)\n"
        "\n"
        "\n"
        "def main(user_prog):\n"
        "    argv = ['git', 'status']\n"
        "    argv[0] = user_prog\n"
        "    run(argv)\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r


def test_wrapper_recursive_call_with_tainted_argv_stays_crit():
    """C-135 adversarial check: a wrapper that calls itself recursively is still
    caught by `_param_argv_call_sites`'s whole-file name match -- an unresolvable
    (tainted, non-literal) recursive call site must keep the whole check crit."""
    src = (
        "import subprocess\n"
        "\n"
        "\n"
        "def run(cmd, depth=0):\n"
        "    if depth > 3:\n"
        "        subprocess.run(cmd)\n"
        "        return\n"
        "    run(cmd, depth + 1)\n"
        "\n"
        "\n"
        "def main(user_input):\n"
        "    run([user_input])\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r


def test_wrapper_ambiguous_toplevel_name_stays_crit():
    """Two top-level defs sharing the wrapper's name -- ambiguous which one a caller
    means -- must stay unresolvable (crit)."""
    src = (
        "import subprocess\n"
        "\n"
        "\n"
        "def run(cmd):\n"
        "    subprocess.run(cmd)\n"
        "\n"
        "\n"
        "def run(cmd):  # noqa: F811 -- deliberately shadows the def above\n"
        "    subprocess.run(cmd, shell=True)\n"
        "\n"
        "\n"
        "def main():\n"
        "    run(['git', 'status'])\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r


# ---------------------------------------------------------------------------
# Fixture-level (vet_skill) regressions for both layers
# ---------------------------------------------------------------------------


def test_vet_clean_wrapper_argv_fixture_not_critical():
    """Named warn_* (not clean_*): TT5_CMD_INJECTION correctly no longer crits, but
    the pre-existing, orthogonal SHELL_INJECTION_RISK shape-only rule still WARNs on
    any non-literal ("cmd" is a bare Name) subprocess.run() call regardless of taint
    -- expected, unrelated to this fix, not a false positive to chase."""
    skill_dir = FIXTURES / "warn_taint_wrapper_argv" / "skills" / "wrapperskill"
    f = vet_skill(skill_dir)
    assert f.status != FAIL
    assert f.severity != "CRITICAL"


def test_vet_clean_cross_scope_collision_fixture_is_pass():
    skill_dir = FIXTURES / "clean_taint_cross_scope_collision" / "skills" / "venvskill"
    f = vet_skill(skill_dir)
    assert f.status == PASS


def test_vet_bad_wrapper_tainted_argv0_fixture_is_critical_fail():
    skill_dir = FIXTURES / "bad_taint_wrapper_tainted_argv0" / "skills" / "tainted_argv0_skill"
    f = vet_skill(skill_dir)
    assert f.status == FAIL
    assert f.severity == "CRITICAL"
    assert any(
        "cmd" in e.lower() or "injection" in e.lower() or "command" in e.lower()
        for e in (f.evidence or [])
    )


def test_vet_existing_cmdinject_fixture_still_critical():
    """Regression: the pre-existing direct-param fixture must still FAIL/CRITICAL."""
    skill_dir = FIXTURES / "bad_taint_cmdinject" / "skills" / "cmdskill"
    f = vet_skill(skill_dir)
    assert f.status == FAIL
    assert f.severity == "CRITICAL"


def test_vet_existing_argv_var_listform_fixture_still_pass():
    """Regression: the pre-existing scope-aware var-bound-argv fixture (sibling
    functions reusing the same local list name) must still PASS."""
    skill_dir = FIXTURES / "clean_taint_argv_var_listform" / "skills" / "argvskill"
    f = vet_skill(skill_dir)
    assert f.status == PASS
