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
uniformly.

Round 1 guarded this against an ORDINARY local shadow of `sys`/`argv` via a whole-
file `_rebound_names(tree)[0]` membership check. A C-135 review found that guard was
a real, cheap evasion rather than a merely theoretical one: because the check is
file-wide and scope-blind, ONE semantically inert decoy line anywhere in the file --
`sys = sys`, `for sys in range(1): pass`, `[sys for sys in range(1)]`, or the bare-
name form's `argv = argv` -- silenced a real, unrelated `sys.argv`/`argv` taint
finding anywhere else in the same file. Round 2 dropped the shadow guard entirely:
`_rhs_has_sysargv` is now permanently unguarded, exactly matching the sibling
`_rhs_has_subscript_environ` check's own B-906 precedent (a spelling-based taint-
source recognizer is not attempting adversarial soundness against shadowing; it
just must not let shadowing SUPPRESS a real finding, which a guard here would).

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
# Round 2 (post-C-135 review): `_rhs_has_sysargv` is now permanently unguarded,
# matching `_rhs_has_subscript_environ`'s own B-906 precedent exactly. A local
# rebinding of the NAME `sys`/`argv` elsewhere in the file -- benign or a
# deliberate decoy -- must not change the verdict on an actual `sys.argv`/
# `argv` subscript read. (Round 1 had this backwards: see the module docstring
# and the adversarial-decoy tests below for the exact evasion a C-135 review
# found and this round closes.)
# ---------------------------------------------------------------------------


def test_reassigning_argv_elsewhere_does_not_clear_an_earlier_real_read():
    """`from sys import argv` followed later by an ordinary reassignment of
    `argv` to a fixed, benign literal list. Under the OLD (round-1, buggy)
    file-wide shadow guard, this reassignment retroactively cleared the
    earlier real `argv[1]` read too -- exactly the evasion the review found.
    It must still convict."""
    src = (
        'import os\n'
        'from sys import argv\n'
        'key = argv[1]\n'
        'os.system(key)\n'
        'argv = ["safe", "literal"]\n'
    )
    assert "TT5_CMD_INJECTION" in _rules(src)


def test_a_local_sys_class_elsewhere_does_not_clear_an_earlier_real_read():
    """A local `class sys:` binding elsewhere in the file must not blind an
    earlier, real `sys.argv[...]` read reaching a dangerous sink -- same
    file-wide-blindness class of evasion as the `argv = argv` shape below,
    just spelled with a class definition instead of a reassignment."""
    src = (
        'import os, sys\n'
        'key = sys.argv[1]\n'
        'os.system(key)\n'
        'class sys:\n'
        '    argv = ["x", "y"]\n'
    )
    assert "TT5_CMD_INJECTION" in _rules(src)


# ---------------------------------------------------------------------------
# The exact adversarial-decoy shapes a C-135 review reproduced against round 1:
# one throwaway, semantically inert line anywhere in the file used to silence
# a real, unrelated sys.argv taint finding. All four must now still convict.
# ---------------------------------------------------------------------------


def test_inert_sys_equals_sys_decoy_does_not_suppress_a_real_finding():
    src = (
        'import os, sys\n'
        'key = sys.argv[1]\n'
        'os.system(key)\n'
        'sys = sys\n'
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_inert_for_sys_in_range_decoy_does_not_suppress_a_real_finding():
    src = (
        'import os, sys\n'
        'key = sys.argv[1]\n'
        'os.system(key)\n'
        'for sys in range(1):\n'
        '    pass\n'
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_inert_sys_comprehension_decoy_does_not_suppress_a_real_finding():
    src = (
        'import os, sys\n'
        'key = sys.argv[1]\n'
        'os.system(key)\n'
        '_ = [sys for sys in range(1)]\n'
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_inert_argv_equals_argv_decoy_does_not_suppress_a_real_finding():
    """Bare-name form: `from sys import argv` + `argv = argv` (a no-op) must
    not blind the earlier real `argv[1]` read."""
    src = (
        'import os\n'
        'from sys import argv\n'
        'key = argv[1]\n'
        'os.system(key)\n'
        'argv = argv\n'
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"
