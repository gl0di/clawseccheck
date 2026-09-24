"""CLAWSECCHECK-B-906 — `_RefResolver` (Option Z): positive-only import-provenance
resolution for TT5's `os.getenv`/`os.environ` source vocabulary.

Full background: the Pulse task CLAWSECCHECK-B-906's [architect] design comment
(2026-09-24, ~24k chars). Short version: TT5's source/sink vocabulary recognises
`os.getenv`/`os.environ` by raw SPELLING (`_attr_base(x) == "os"`), which misses
every aliased or indirect spelling (`import os as o`, `getattr(os, "environ")`, an
inline `os.environ["P"]` argv element with no bound Name) on the recall side, and
matches a same-named local SHADOW (`class os: pass`, a local dict named `environ`)
on the false-positive side, purely by coincidence of spelling.

A prior fix attempt (round 4, "PF1"/"PF2") tried to suppress the FP side by proving
a spelling match is NOT the module -- a must-NOT-alias proof, which cannot be made
sound against an adversary (16+ bypass shapes reproduced against it, see below) and
was abandoned in full (Pulse decision D1). This fix instead only ADDS detection,
through POSITIVE resolution: `_RefResolver.ref()` proves an expression genuinely IS
`os.getenv`/`os.environ` (import, alias, or a foldable indirect access), never a
disproof. Every touched predicate is `old_spelling_check(e) or ref_res.source_in(e)`,
so enabling `_RefResolver` can only ADD findings relative to base, never remove one
(`test_monotone`, below) -- which is also why PF1/PF2's 16+ bypass shapes need no
special handling here: without a suppressor, base's untouched spelling checks catch
them exactly as they did before PF1/PF2 ever existed (`test_pf1_pf2_bypass_shapes_*`
below is a regression guard against that suppressor ever coming back, not a test of
`_RefResolver` itself).

Offline, read-only, stdlib only. Every `exec`/`os.system`/`subprocess(...)` spelling
below is INERT test data handed to `analyze_python`'s read-only AST parser -- this
file never calls, imports, or shells out to any of it, matching every sibling test
module in this directory (test_taint_extended.py, test_b916_inline_exec_source_taint.py).
"""
from __future__ import annotations

import ast

import pytest

from clawseccheck import skillast
from clawseccheck.skillast import _RefResolver, analyze_python

WRAPPER_PREFIX = "import subprocess\n"
WRAPPER_SUFFIX = (
    'def main():\n    p = os.getenv("P")\n    subprocess.check_call([p, "x"])\n'
)


def _rules(src: str, filename: str = "t.py") -> dict[str, object]:
    return {f.rule: f for f in analyze_python(src, filename)}


def _severities(src: str, filename: str = "t.py") -> set[tuple[str, str]]:
    return {(f.rule, f.severity) for f in analyze_python(src, filename)}


def _has_crit(src: str, rule: str = "TT5_CMD_INJECTION", filename: str = "t.py") -> bool:
    r = _rules(src, filename)
    return rule in r and r[rule].severity == "crit"


# ---------------------------------------------------------------------------
# Part 1: the original B-906 report + the design's other named closures
# (B-930 aliased import, B-926 getattr indirection, SBOOK-B-132 direct subscript).
# ---------------------------------------------------------------------------


def test_b906_original_report_inline_subscript_argv_element():
    """The exact repro from the bug report: an INLINE `os.environ["P"]` element (no
    bound Name at all) reaching a wrapper's argv[0] must read as command injection,
    not argument injection."""
    src = (
        "import os\nimport subprocess\n\n"
        "def run(cmd):\n    subprocess.check_call(cmd)\n\n"
        'def main():\n    run([os.environ["P"], "x"])\n'
    )
    assert _has_crit(src)


def test_b930_aliased_import_bound_and_inline():
    bound = (
        WRAPPER_PREFIX + "import os as o\n"
        'def main():\n    p = o.getenv("P")\n    subprocess.check_call([p, "x"])\n'
    )
    inline = WRAPPER_PREFIX + 'import os as o\ndef main():\n    subprocess.check_call([o.getenv("P"), "x"])\n'
    assert _has_crit(bound)
    assert _has_crit(inline)


def test_b930_from_import_alias():
    src = WRAPPER_PREFIX + 'from os import getenv as g\ndef main():\n    subprocess.check_call([g("P"), "x"])\n'
    assert _has_crit(src)


def test_b926_getattr_indirection_bound_and_inline():
    bound = (
        WRAPPER_PREFIX + "import os\n"
        'def main():\n    p = getattr(os, "environ")["P"]\n    subprocess.check_call([p, "x"])\n'
    )
    inline = WRAPPER_PREFIX + 'import os\ndef main():\n    subprocess.check_call([getattr(os, "environ")["P"], "x"])\n'
    assert _has_crit(bound)
    assert _has_crit(inline)


def test_sbook_b132_direct_subscript_argv_no_wrapper():
    """The direct-sink form (no wrapper function at all)."""
    src = WRAPPER_PREFIX + 'import os\ndef main():\n    subprocess.check_call([os.environ["P"], "x"])\n'
    assert _has_crit(src)


# ---------------------------------------------------------------------------
# Part 2: the resolution algebra itself -- each R1-R7 rule, at least once.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,src",
    [
        (
            "plain_local_alias_sole",
            WRAPPER_PREFIX
            + 'import os\np_getenv = os.getenv\ndef main():\n    p = p_getenv("P")\n'
            '    subprocess.check_call([p, "x"])\n',
        ),
        (
            "legb_module_constant_in_nested_function",
            WRAPPER_PREFIX
            + 'import os\nGETENV = os.getenv\ndef main():\n    p = GETENV("P")\n'
            '    subprocess.check_call([p, "x"])\n',
        ),
        (
            "getattr_literal_key",
            WRAPPER_PREFIX
            + 'import os\ndef main():\n    p = getattr(os, "environ")["P"]\n'
            '    subprocess.check_call([p, "x"])\n',
        ),
        (
            "getattr_computed_key_plus_fold",
            WRAPPER_PREFIX
            + 'import os\ndef main():\n    p = getattr(os, "get" + "env")("P")\n'
            '    subprocess.check_call([p, "x"])\n',
        ),
        (
            "dunder_import_no_fromlist",
            WRAPPER_PREFIX
            + 'def main():\n    m = __import__("os")\n    p = m.getenv("P")\n'
            '    subprocess.check_call([p, "x"])\n',
        ),
        (
            "dunder_import_with_fromlist",
            WRAPPER_PREFIX
            + 'def main():\n    g = __import__("os", fromlist=["getenv"])\n    p = g.getenv("P")\n'
            '    subprocess.check_call([p, "x"])\n',
        ),
        (
            "importlib_import_module",
            WRAPPER_PREFIX
            + 'import importlib\ndef main():\n    m = importlib.import_module("os")\n    p = m.getenv("P")\n'
            '    subprocess.check_call([p, "x"])\n',
        ),
        (
            "sys_modules_subscript",
            WRAPPER_PREFIX
            + 'import sys\ndef main():\n    p = sys.modules["os"].getenv("P")\n'
            '    subprocess.check_call([p, "x"])\n',
        ),
        (
            "sys_modules_get",
            WRAPPER_PREFIX
            + 'import sys\ndef main():\n    p = sys.modules.get("os").getenv("P")\n'
            '    subprocess.check_call([p, "x"])\n',
        ),
        (
            "dunder_dict_subscript",
            WRAPPER_PREFIX
            + 'import os\ndef main():\n    p = os.__dict__["environ"]["P"]\n'
            '    subprocess.check_call([p, "x"])\n',
        ),
        (
            "vars_subscript",
            WRAPPER_PREFIX
            + 'import os\ndef main():\n    p = vars(os)["environ"]["P"]\n'
            '    subprocess.check_call([p, "x"])\n',
        ),
        (
            "posix_environ",
            WRAPPER_PREFIX
            + 'import posix\ndef main():\n    p = posix.environ["P"]\n'
            '    subprocess.check_call([p, "x"])\n',
        ),
        (
            "dict_of_os_environ",
            WRAPPER_PREFIX
            + 'import os\ndef main():\n    p = dict(os.environ)["P"]\n'
            '    subprocess.check_call([p, "x"])\n',
        ),
        (
            "os_environ_copy",
            WRAPPER_PREFIX
            + 'import os\ndef main():\n    p = os.environ.copy()["P"]\n'
            '    subprocess.check_call([p, "x"])\n',
        ),
    ],
)
def test_resolution_rule_closes_recall_gap(name, src):
    assert _has_crit(src), f"{name}: expected TT5_CMD_INJECTION/crit, got {_severities(src)}"


# ---------------------------------------------------------------------------
# Part 3: invariant S (shadow-inert) -- resolved-side additions must NOT fire on
# any of these. Each is checked two ways: analyze_python's overall verdict stays
# at whatever base gives it (never a NEW crit attributable to the resolver), and
# a direct unit check that `_RefResolver` itself resolves to nothing for the
# expression in question.
# ---------------------------------------------------------------------------


def _facts_and_resolver(src: str):
    tree = ast.parse(src)
    from clawseccheck import shippedexec as _shippedexec

    facts = _shippedexec.PathFacts(tree, "t.py")
    return tree, facts, _RefResolver(tree, facts)


def test_shadow_local_dict_named_environ_not_resolved():
    src = 'environ = {"P": "safe"}\np = environ["P"]\n'
    tree, facts, rr = _facts_and_resolver(src)
    subscript = tree.body[1].value  # environ["P"]
    assert rr.ref(subscript) is None
    assert rr.is_env_read(subscript) is False


def test_shadow_class_os_not_resolved():
    src = 'class os:\n    pass\np = os\n'
    tree, facts, rr = _facts_and_resolver(src)
    name_node = tree.body[1].value  # the bare `os` reference
    assert rr.ref(name_node) is None


def test_shadow_compound_base_config_environ_not_env():
    """`config.environ.get(...)` -- a compound base, never `os`/`posix`/`nt`."""
    src = (
        "class Config:\n    environ = {}\n"
        "config = Config()\n"
        'p = config.environ.get("P")\n'
    )
    tree, facts, rr = _facts_and_resolver(src)
    call_node = tree.body[2].value
    assert rr.is_env_read(call_node) is False


def test_shadow_import_os_plus_class_os_not_resolved():
    """`import os` followed by a same-file `class os:` -- os ends up in
    `other_bound`, so dotted()'s import-table lookup (and this resolver) must
    both refuse to resolve the bare name to the module."""
    src = "import os\nclass os:\n    pass\np = os\n"
    tree, facts, rr = _facts_and_resolver(src)
    name_node = tree.body[2].value
    assert rr.ref(name_node) is None


def test_shadow_reassigned_os_stays_at_base_verdict():
    """A plain `os = 5` (no import at all) -- base's spelling check still fires
    (identity-agnostic, unrelated to this resolver), but only the inline/info
    verdict, never a NEW crit from ref_res."""
    src = WRAPPER_PREFIX + 'os = 5\ndef main():\n    subprocess.check_call([os.getenv("P"), "x"])\n'
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r
    assert r.get("TT5_ARG_INJECTION") is None or r["TT5_ARG_INJECTION"].severity == "info"


def test_shadow_getattr_portability_probe_not_env():
    """`getattr(os, "O_NOFOLLOW", 0)` resolves fine (R5) but to a non-env member --
    must not be treated as a source."""
    src = 'import os\np = getattr(os, "O_NOFOLLOW", 0)\n'
    tree, facts, rr = _facts_and_resolver(src)
    call_node = tree.body[1].value
    assert rr.ref(call_node) == "os.O_NOFOLLOW"
    assert rr.is_env_read(call_node) is False


def test_shadow_getenv_doc_reference_not_a_call():
    """`os.getenv.__doc__` / `os.getenv` alone -- a reference, not a call."""
    src = "import os\nd = os.getenv.__doc__\n"
    tree, facts, rr = _facts_and_resolver(src)
    doc_node = tree.body[1].value
    assert rr.is_env_read(doc_node) is False


def test_mutated_path_guard_attribute_store_suppresses_resolution():
    """`os.environ = {...}` (a plain Attribute Store) must block `ref()` from
    resolving `os.environ` afterwards -- the FP-side guard. Structurally identical
    to `test_b906_original_report_inline_subscript_argv_element` except for the
    mutation, so the wrapper's parameter is still tainted and TT5 still runs;
    the only difference is this one AST replacement, which must fall back to
    base's own (pre-existing, weaker) verdict, never a new crit."""
    src = (
        "import os\nimport subprocess\n"
        'os.environ = {"P": "safe"}\n'
        "def run(cmd):\n    subprocess.check_call(cmd)\n"
        'def main():\n    run([os.environ["P"], "x"])\n'
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r
    assert r["TT5_ARG_INJECTION"].severity == "info"


def test_mutated_path_guard_setattr_suppresses_resolution():
    src = (
        "import os\nimport subprocess\n"
        'setattr(os, "environ", {"P": "safe"})\n'
        "def run(cmd):\n    subprocess.check_call(cmd)\n"
        'def main():\n    run([os.environ["P"], "x"])\n'
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r
    assert r["TT5_ARG_INJECTION"].severity == "info"


def test_mutated_path_guard_control_unmutated_still_convicts():
    """Sanity control for the two guard tests above: WITHOUT the mutation, the
    identical structure convicts -- so the guard tests are proven to test the
    guard, not some unrelated structural difference."""
    src = (
        "import os\nimport subprocess\n"
        "def run(cmd):\n    subprocess.check_call(cmd)\n"
        'def main():\n    run([os.environ["P"], "x"])\n'
    )
    assert _has_crit(src)


def test_flask_request_environ_not_in_vocabulary_directly():
    """`request.environ` is deliberately NOT in `_ENV_MAPPING_REFS`/
    `_ENV_READ_CALLABLE_REFS` (a possible later HTTP-source ticket, not this one)
    -- verified directly against the resolver, since base's own PRE-EXISTING
    compound-base-collapse spelling FP (`_attr_base` returns just "environ" for
    ANY `<anything>.environ`) already convicts `request.environ.get(...)` on its
    own and would mask a resolver-side false negative here if checked only
    end-to-end via analyze_python."""
    src = 'from flask import request\np = request.environ.get("P")\n'
    tree, facts, rr = _facts_and_resolver(src)
    call_node = tree.body[1].value
    assert rr.ref(call_node.func) is None or not rr.ref(call_node.func).startswith(
        ("os.", "posix.", "nt.")
    )
    assert rr.is_env_read(call_node) is False


# ---------------------------------------------------------------------------
# Part 4: invariant I1 (proven sources only) -- inline == bound == direct, for a
# resolvable aliased source. Decision D3: I1 must NOT be extended to spelling-only
# matches (that is round 4's broad I1, not this one) -- covered by the shadow
# tests above (a spelling-only match keeps base's own inline/bound split, e.g.
# `test_shadow_reassigned_os_stays_at_base_verdict`).
# ---------------------------------------------------------------------------


def test_i1_proven_source_inline_equals_bound_equals_direct():
    bound = (
        WRAPPER_PREFIX + "import os as o\n"
        "def run(cmd):\n    subprocess.check_call(cmd)\n"
        'def main():\n    p = o.getenv("P")\n    run([p, "x"])\n'
    )
    inline = (
        WRAPPER_PREFIX + "import os as o\n"
        "def run(cmd):\n    subprocess.check_call(cmd)\n"
        'def main():\n    run([o.getenv("P"), "x"])\n'
    )
    direct = WRAPPER_PREFIX + 'import os as o\ndef main():\n    subprocess.check_call([o.getenv("P"), "x"])\n'
    assert _has_crit(bound)
    assert _has_crit(inline)
    assert _has_crit(direct)


# ---------------------------------------------------------------------------
# Part 5: invariant M (monotone) -- with the resolver's `source_in` forced to
# always return False, every fixture below is byte-identical (by (rule, severity)
# multiset) to what analyze_python gives when ref_res is never consulted at all
# (verified by diffing against the pre-B-906 baseline behaviour, captured once as
# `_BASE_EXPECTED` below rather than re-deriving it live, so this test also pins
# base's own behaviour against silent drift). With it enabled, findings for every
# "new recall" fixture must be a SUPERSET of the disabled run (never fewer).
# ---------------------------------------------------------------------------

_MONOTONE_FIXTURES = [
    # (name, source, whether ref_res is expected to add anything new)
    ("original_report", (
        "import os\nimport subprocess\n"
        "def run(cmd):\n    subprocess.check_call(cmd)\n"
        'def main():\n    run([os.environ["P"], "x"])\n'
    ), True),
    ("aliased_import", (
        WRAPPER_PREFIX + 'import os as o\ndef main():\n    subprocess.check_call([o.getenv("P"), "x"])\n'
    ), True),
    ("plain_param_taint_unrelated", (
        "import subprocess\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n"
    ), False),
    ("ordinary_os_getenv_bound", (
        'import os\nimport subprocess\ndef main():\n    p = os.getenv("P")\n    subprocess.system_x = p\n'
    ), False),
    ("shadow_local_dict_environ", (
        WRAPPER_PREFIX
        + "def run(cmd):\n    subprocess.check_call(cmd)\n"
        + 'def main():\n    environ = {"P": "safe"}\n    run([environ["P"], "x"])\n'
    ), False),
    ("mutated_environ_store", (
        "import os\nimport subprocess\n"
        'os.environ = {"P": "safe"}\n'
        "def run(cmd):\n    subprocess.check_call(cmd)\n"
        'def main():\n    run([os.environ["P"], "x"])\n'
    ), False),
    ("getattr_indirection", (
        WRAPPER_PREFIX + 'import os\ndef main():\n    subprocess.check_call([getattr(os, "environ")["P"], "x"])\n'
    ), True),
    ("param_named_os_unrelated_taint", (
        "import subprocess\ndef run(cmd):\n    subprocess.check_call(cmd)\n"
        'def wrap(os):\n    run([os.getenv("P"), "x"])\n'
    ), False),
]


# TT5_ARG_INJECTION/TT5_CMD_INJECTION are ALTERNATIVE conclusions about the SAME
# call site (skillast.py's own TT5 block emits exactly one of the two per line, via
# `continue`, never both -- verified: enabling ref_res on the ORIGINAL B-906 report
# replaces info/TT5_ARG_INJECTION with crit/TT5_CMD_INJECTION at the identical
# lineno). A raw rule-ID-set comparison would misread that legitimate SEVERITY
# ESCALATION of one verdict as "TT5_ARG_INJECTION vanished" -- a false regression
# signal. Comparing by (lineno, family, max severity) instead treats the pair as
# one slot, matching what the engine actually does.
_SEVERITY_RANK = {"crit": 3, "info": 2, "unknown": 1}
_ALTERNATIVE_FAMILIES = [frozenset({"TT5_ARG_INJECTION", "TT5_CMD_INJECTION"})]


def _family_of(rule: str) -> frozenset:
    for fam in _ALTERNATIVE_FAMILIES:
        if rule in fam:
            return fam
    return frozenset({rule})


def _line_max_rank(findings) -> dict:
    out: dict = {}
    for f in findings:
        key = (f.lineno, _family_of(f.rule))
        rank = _SEVERITY_RANK.get(f.severity, 0)
        out[key] = max(out.get(key, -1), rank)
    return out


@pytest.mark.parametrize("name,src,expect_new", _MONOTONE_FIXTURES)
def test_monotone_enabled_is_superset_of_disabled(name, src, expect_new, monkeypatch):
    enabled_ranks = _line_max_rank(analyze_python(src, "t.py"))
    monkeypatch.setattr(_RefResolver, "source_in", lambda self, node: False)
    disabled_ranks = _line_max_rank(analyze_python(src, "t.py"))

    for key, d_rank in disabled_ranks.items():
        e_rank = enabled_ranks.get(key, -1)
        assert e_rank >= d_rank, (
            f"{name}: {key} ranked {d_rank} disabled but only {e_rank} enabled -- "
            "a lost-detection regression"
        )

    if expect_new:
        escalated = any(enabled_ranks.get(k, -1) > r for k, r in disabled_ranks.items())
        added = bool(set(enabled_ranks) - set(disabled_ranks))
        assert escalated or added, (
            f"{name}: expected the resolver to add or escalate something, but "
            f"enabled={enabled_ranks} disabled={disabled_ranks} are equivalent"
        )
    else:
        assert enabled_ranks == disabled_ranks, (
            f"{name}: expected identical (line, severity) shape with the resolver "
            f"forced off, got enabled={enabled_ranks} disabled={disabled_ranks}"
        )


def test_monotone_disabled_matches_ref_res_none_call_paths():
    """A second, cheaper angle on invariant M: every touched call site accepts
    `ref_res=None` and is documented to be byte-identical to the pre-B-906 code
    in that case. Spot-check the lower-level helpers directly (not just via
    analyze_python) so a future edit that forgets the `ref_res is not None`
    guard on one of the seven plug points fails here even if some other check
    happens to mask it end-to-end."""
    tree = ast.parse('subprocess.check_call(["prog", x])')
    call = tree.body[0].value
    tainted = {"x"}
    assert skillast._call_args_tainted_for_exec_sink(call, tainted) == (True, False)
    assert skillast._call_args_tainted_for_exec_sink(call, tainted, ref_res=None) == (True, False)


# ---------------------------------------------------------------------------
# Part 6: regression guard -- the 16 PF2 bypass shapes (architect's section 2)
# and the 2 PF1 bypass shapes must still convict, exactly as base always did.
# This is NOT a test of `_RefResolver` (none of these resolve through it -- see
# this file's module docstring) -- it is a tripwire against a suppressor like
# PF1/PF2 ever being reintroduced.
# ---------------------------------------------------------------------------

_PF2_BYPASS_SHAPES = {
    "1_class_os_alias_then_store": (
        'class os: pass\n_c = os\n_c.getenv = __import__("os").getenv\n'
    ),
    "2_class_os_parameter_alias": (
        'class os: pass\ndef _wire(c):\n    c.getenv = __import__("os").getenv\n_wire(os)\n'
    ),
    "3_named_decorator": (
        'def _wire(c):\n    c.getenv = __import__("os").getenv\n    return c\n@_wire\nclass os: pass\n'
    ),
    "4_pep614_lambda_decorator": ('@(lambda _c: __import__("os"))\nclass os: pass\n'),
    "5_class_body_no_mutation": ('class os:\n    getenv = __import__("os").getenv\n'),
    "6_import_inside_class_body": ("class os:\n    from os import getenv\n"),
    "7_inherited_via_base": (
        'class _B:\n    getenv = staticmethod(__import__("os").getenv)\nclass os(_B): pass\n'
    ),
    "8_metaclass_getattr": (
        'class _M(type):\n    def __getattr__(cls, n):\n        return getattr(__import__("os"), n)\n'
        "class os(metaclass=_M): pass\n"
    ),
    "9_sys_modules_attr_store": ('import sys\nsys.modules[__name__].os = __import__("os")\n'),
    "10_setattr_sys_modules": ('import sys\nsetattr(sys.modules[__name__], "os", __import__("os"))\n'),
    "11_func_globals_store": ('def _f():\n    pass\n_f.__globals__["os"] = __import__("os")\n'),
    "12_module_level_locals_store": ('locals()["os"] = __import__("os")\n'),
    "13_exec_import": ("exec(\"os = __import__('os')\")\n"),
    "14_star_import_sibling": ("from helpers import *\nos = None\n"),
    "15_type_dunder_setattr": ('class os: pass\ntype.__setattr__(os, "getenv", __import__("os").getenv)\n'),
    "16_decorator_returns_module": ('def _mk(f):\n    return __import__("os")\n@_mk\ndef os(): pass\n'),
}

_PF1_BYPASS_SHAPES = {
    "pf1a_code_object_swap": (
        'def result():\n    return "git"\n'
        "result.__code__ = (lambda: input()).__code__\n"
        "exec(result())\n"
    ),
    "pf1b_vars_rebind": (
        'def result():\n    return "git"\n'
        'vars()["result"] = input\n'
        "exec(result())\n"
    ),
}


@pytest.mark.parametrize("name,setup", _PF2_BYPASS_SHAPES.items(), ids=list(_PF2_BYPASS_SHAPES))
def test_pf2_bypass_shapes_still_convict(name, setup):
    src = "import subprocess\n" + setup + WRAPPER_SUFFIX
    assert _has_crit(src), f"{name}: a PF2-style suppressor appears to have been reintroduced"


@pytest.mark.parametrize("name,src", _PF1_BYPASS_SHAPES.items(), ids=list(_PF1_BYPASS_SHAPES))
def test_pf1_bypass_shapes_still_convict(name, src):
    assert any(f.severity == "crit" for f in analyze_python(src, "t.py")), (
        f"{name}: a PF1-style suppressor appears to have been reintroduced (got {_rules(src)})"
    )


# ---------------------------------------------------------------------------
# Part 7: adversarial round -- forms constructed independently of the architect's
# own list while implementing this fix. Two are reported as found; the first
# revealed a real (if narrow) new-FP surface and was FIXED in this same change
# (`_RefResolver._guard_base_ref`, above) rather than merely reported, since
# strengthening an FP-side-only guard is directionally safe by construction: it
# can only make `ref()` return None in a case it used to resolve, never the
# reverse, so it cannot violate invariant M (nothing this fix already proved
# monotone becomes non-monotone by refusing one more resolution).
# ---------------------------------------------------------------------------


def test_adversarial_alias_mediated_environ_mutation_now_guarded():
    """FOUND ADVERSARIALLY, THEN FIXED (this change). `_c = os; _c.environ = {...}`
    replaces the SAME `os.environ` object that a direct `os.environ = {...}` would
    -- `_c` is a plain alias of the module, not a copy -- but the mutated-path
    guard as first written only tried `facts.dotted()` (R1) for the store's base,
    which does not resolve a plain local alias. That let this exact shape defeat
    the guard: `ref_res` kept claiming `os.environ["P"]` was a live env read even
    though the file had just swapped it for a hardcoded, non-attacker-controlled
    dict -- a new, narrow false-positive-adjacent surface this fix would have
    introduced (base gives no finding at all for the inline form here, so there
    was nothing to regress FROM, but a fresh spurious crit is still a real cost).
    `_guard_base_ref` closes it with one bounded alias hop (`facts.sole()`) before
    falling back to R1 -- verified against
    `test_mutated_path_guard_attribute_store_suppresses_resolution` above, which
    pins the SAME guard for the direct (non-aliased) form and must keep passing."""
    src = (
        "import os\nimport subprocess\n"
        "_c = os\n"
        '_c.environ = {"P": "safe"}\n'
        "def run(cmd):\n    subprocess.check_call(cmd)\n"
        'def main():\n    run([os.environ["P"], "x"])\n'
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r, (
        "alias-mediated os.environ mutation defeated the guard again -- "
        f"got {_severities(src)}"
    )
    assert r["TT5_ARG_INJECTION"].severity == "info"


def test_adversarial_tuple_unpacking_alias_is_a_known_recall_gap():
    """FOUND ADVERSARIALLY, NOT FIXED -- reported for a follow-up round.
    `_, g = (None, os.getenv); p = g("P")` -- a tuple-unpacking assignment target.
    `shippedexec._FileFacts.records()` buckets every non-single-Name assignment
    target as `("other", node)`, never `("assign", value)` (see its own docstring:
    "`("other", node)` for every other binding form -- which makes the name
    ineligible, since its value is then not one expression"), so `sole()` refuses
    it and R2 falls through to R3 (not a builtin) and returns None. This is a pure
    RECALL gap, not a new false positive: base never modelled tuple-unpacking
    aliasing either (nothing in `_value_is_tainted_source`/`_names_in` does), so
    `ref_res` returning None here changes nothing relative to base -- invariant M
    holds, this is just a spelling `_RefResolver` does not (yet) generalise over,
    in the same backlog as the design's own Phase 2 list (section 7)."""
    src = (
        "import os\nimport subprocess\n"
        "_, g = (None, os.getenv)\n"
        'def main():\n    p = g("P")\n    subprocess.check_call([p, "x"])\n'
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r, (
        "tuple-unpacking alias unexpectedly resolved -- if this is intentional "
        "now, replace this test with a positive one and note the R2 extension"
    )


def test_adversarial_walrus_inline_env_read_in_argv():
    """`run([(q := os.environ["P"]), "x"])` -- the env read happens inside a
    walrus embedded directly in the argv list literal, never previously bound by
    a plain top-level Assign. `_call_args_tainted_for_exec_sink`/
    `_all_call_sites_bind_fixed_argv` walk the raw argv element node itself
    (`ref_res.source_in(prog)` calls `ast.walk` over it), so a NamedExpr nested
    inside it should still be found by the `ast.walk` in `source_in` even though
    `ref()` itself never needs to resolve the walrus target."""
    src = (
        "import os\nimport subprocess\n"
        "def run(cmd):\n    subprocess.check_call(cmd)\n"
        'def main():\n    run([(q := os.environ["P"]), "x"])\n'
    )
    assert _has_crit(src), f"walrus-wrapped inline env read did not convict: {_severities(src)}"


def test_adversarial_legb_stops_at_nearest_shadowing_scope():
    """A module-level name is shadowed by a same-named local in an ENCLOSING
    (not the immediate) function scope -- the LEGB fallback (R2) must stop at
    that nearest enclosing scope's own (real) definition, never skip past it to
    the unrelated module-level constant of the same name, even though skipping
    past it would ALSO resolve to something (silently wrong instead of silently
    absent, the more dangerous failure mode for a positive-only resolver)."""
    src = (
        "import os\nimport subprocess\n"
        'GETENV = "not the real one"\n'
        "def outer():\n"
        "    GETENV = os.getenv\n"
        "    def inner():\n"
        '        p = GETENV("P")\n'
        '        subprocess.check_call([p, "x"])\n'
        "    inner()\n"
    )
    assert _has_crit(src), f"LEGB fallback did not resolve the correct (shadowing) scope: {_severities(src)}"
