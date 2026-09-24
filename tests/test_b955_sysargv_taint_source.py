"""CLAWSECCHECK-B-955 — `sys.argv` joins the TT4/TT5/SSRF taint engine's shared
external-source vocabulary.

Before this fix, `_value_is_tainted_source`/`_external_tainted_names` (skillast.py)
recognized function parameters, `os.getenv`/`os.environ[...]`, file reads, and
network input/`input()`/tool-result calls as external sources -- but NOT `sys.argv`,
even though a command-line argument is exactly as attacker/operator-influenced as an
environment variable for this engine's own threat model. A value that flowed ONLY
via `sys.argv` into `os.system`/`subprocess(..., shell=True)`/`exec`/`eval` was
missed entirely (no finding at all), not merely misclassified in severity.

`_rhs_has_sysargv` (mirroring the existing `_rhs_has_subscript_environ`) closes this:
a `Subscript`/slice on `sys.argv` (Attribute form) or a bare `argv[...]` (Name form,
`from sys import argv`), folded into `_value_is_tainted_source` itself so every one
of its callers (TT4/TT5/SSRF via `_expr_is_ext_tainted`/`_external_tainted_names`,
and the B-863 wrapper-position grammar's own `sourced()` closure) gets the new source
uniformly. Guarded against an ORDINARY local shadow of `sys`/`argv` (a parameter, a
plain reassignment, a `class sys:`/`def sys():`, ...) via `_rebound_names(tree)[0]`
-- the same file-wide, fail-safe discipline `_b863_a0_is_verified_sys_executable`
already established for its own `sys.executable` carve-out -- not a claim of
soundness against a deliberate, adversarial bypass (out of scope, exactly like the
equivalent `os.environ` spelling check, per B-906's own module comment).

Offline, read-only, stdlib only. Every `exec`/`eval`/`os.system`/`subprocess(...)`
spelling below is INERT test data handed to `analyze_python`'s read-only AST parser
(see its own docstring: "Never raises, never executes") -- this file never calls,
imports, or shells out to any of it, matching every sibling test module in this
directory (test_taint_extended.py, test_b906_ref_resolver.py, test_b916_inline_exec_
source_taint.py).
"""
from __future__ import annotations

from clawseccheck.skillast import analyze_python


def _rules(src: str) -> dict[str, object]:
    return {f.rule: f for f in analyze_python(src, "t.py")}


# ---------------------------------------------------------------------------
# The core gap: sys.argv reaching a genuinely dangerous sink now convicts,
# matching os.environ's existing severity for the identical sink shape.
# ---------------------------------------------------------------------------


def test_sysargv_to_os_system_is_crit_like_environ():
    src = 'import os, sys\nkey = sys.argv[1]\nos.system(key)\n'
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"

    env_equivalent = 'import os\nkey = os.environ["K"]\nos.system(key)\n'
    r_env = _rules(env_equivalent)
    assert r_env["TT5_CMD_INJECTION"].severity == r["TT5_CMD_INJECTION"].severity


def test_sysargv_to_subprocess_shell_true_is_crit():
    src = 'import sys, subprocess\nkey = sys.argv[1]\nsubprocess.run(key, shell=True)\n'
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_sysargv_to_exec_is_crit():
    src = 'import sys\ncmd = sys.argv[1]\nexec(cmd)\n'
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_sysargv_to_eval_is_crit():
    src = 'import sys\ncmd = sys.argv[1]\neval(cmd)\n'
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_sysargv_slice_to_subprocess_shell_true_is_crit():
    """A slice (`sys.argv[1:]` joined into a string), not just a single index --
    the same Subscript AST shape `_rhs_has_sysargv` matches either way."""
    src = (
        'import sys, subprocess\n'
        'cmd = " ".join(sys.argv[1:])\n'
        'subprocess.run(cmd, shell=True)\n'
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


# ---------------------------------------------------------------------------
# Both import forms.
# ---------------------------------------------------------------------------


def test_import_sys_attribute_form_is_recognized():
    src = 'import sys\nimport os\nkey = sys.argv[1]\nos.system(key)\n'
    assert _rules(src)["TT5_CMD_INJECTION"].severity == "crit"


def test_from_sys_import_argv_bare_name_form_is_recognized():
    src = 'from sys import argv\nimport os\nkey = argv[1]\nos.system(key)\n'
    assert _rules(src)["TT5_CMD_INJECTION"].severity == "crit"


# ---------------------------------------------------------------------------
# Benign control: a hardcoded value reaching the identical sink shape must
# stay clean -- the widening must not manufacture a new false positive.
# ---------------------------------------------------------------------------


def test_hardcoded_literal_to_os_system_is_still_clean():
    src = 'import os\nkey = "echo hi"\nos.system(key)\n'
    assert "TT5_CMD_INJECTION" not in _rules(src)


def test_unrelated_local_variable_named_like_a_cli_arg_is_still_clean():
    src = 'import os\nuser_choice = "yes"\nos.system(f"echo {user_choice}")\n'
    assert "TT5_CMD_INJECTION" not in _rules(src)


# ---------------------------------------------------------------------------
# Shadow guard: an ordinary local shadow of `sys`/`argv` must NOT be treated
# as the real module -- same discipline `_b863_a0_is_verified_sys_executable`
# already established for `sys.executable`.
# ---------------------------------------------------------------------------


def test_locally_reassigned_argv_name_is_not_treated_as_the_real_module():
    """`from sys import argv` followed by an ordinary reassignment of `argv`
    to a fixed, benign literal list -- `argv` no longer refers to the real
    `sys.argv` from that point on, so subscripting it must not convict."""
    src = (
        'import os\n'
        'from sys import argv\n'
        'argv = ["safe", "literal"]\n'
        'key = argv[1]\n'
        'os.system(key)\n'
    )
    assert "TT5_CMD_INJECTION" not in _rules(src)


def test_locally_shadowed_sys_class_is_not_treated_as_the_real_module():
    """A local `class sys:` binding shadows the module name entirely --
    `sys.argv` here is an ordinary class attribute access, not command-line
    input, and must not convict."""
    src = (
        'import os\n'
        'class sys:\n'
        '    argv = ["x", "y"]\n'
        'key = sys.argv[1]\n'
        'os.system(key)\n'
    )
    assert "TT5_CMD_INJECTION" not in _rules(src)
