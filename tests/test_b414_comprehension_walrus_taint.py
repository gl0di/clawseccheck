"""Regression tests for CLAWSECCHECK-B-414: the shared scope/taint model
(clawseccheck/skillast.py, `_own_bound_names` / `_build_toplevel_owner_map` /
`_external_tainted_names`) had no case for comprehension (`ast.ListComp`/`SetComp`/
`DictComp`/`GeneratorExp`) or walrus (`ast.NamedExpr`) targets, and `ast.Lambda` --
though already named in `_NESTED_SCOPE_NODES` -- was never actually special-cased in
the owner-map walk. Found during CLAWSECCHECK-B-413's own C-135 adversarial review;
confirmed byte-identical before/after B-413 (pre-existing, shared by TT4 and TT5).

Two independent, confirmed-reproduced bugs, fixed together (they are two sides of the
SAME missing scope):

Shadow-soundness (FALSE POSITIVE, CRITICAL-severity, Golden Rule #5 territory) -- a
comprehension's own `for`-target (or a lambda's own parameter) reuses an outer
tainted binding's name over hardcoded-safe literals. Fixed by giving a comprehension
and a lambda their own owner-map scope bucket (`_build_toplevel_owner_map`) and
teaching `_own_bound_names` to compute a comprehension's own bound names as its
`for`-target(s) (Lambda's own-args handling already existed but was unreachable with
no scope bucket to invoke it on).

Propagation-soundness (silent FALSE NEGATIVE on the catalog's highest-severity check)
-- a comprehension's `for x in <tainted_iterable>` never tainted `x`, and a walrus
(`:=`) target was never in the taint propagation fixpoint at all. Fixed by extending
`_external_tainted_names`'s fixpoint with a comprehension-target pass (bucketed to the
comprehension's own new scope) and a NamedExpr pass (bucketed to the scope CONTAINING
the comprehension, per PEP 572, bubbling past any comprehension-type scope).

Offline, deterministic. No network calls, no writes outside tmp_path.
"""

from __future__ import annotations

import ast
from pathlib import Path

import clawseccheck.skillast as skillast_mod
from clawseccheck.catalog import FAIL, WARN
from clawseccheck.checks import vet_skill
from clawseccheck.skillast import analyze_python

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _rules(src: str) -> dict[str, object]:
    return {f.rule: f for f in analyze_python(src, "t.py")}


# ---------------------------------------------------------------------------
# The ticket's two verbatim repro cases
# ---------------------------------------------------------------------------


def test_comprehension_own_target_shadows_outer_param_not_crit():
    """The ticket's exact FP repro: a comprehension's OWN `for`-target reuses the
    enclosing function's tainted parameter name, but only ever iterates a hardcoded,
    safe literal list. Real Python 3 scoping makes the comprehension's own scope, so
    it must NOT crit."""
    src = (
        "import subprocess\n\n\n"
        "def process(user_cmd):\n"
        '    safe_commands = ["/bin/ls", "/bin/pwd", "/bin/whoami"]\n'
        "    results = [subprocess.run(user_cmd) for user_cmd in safe_commands]\n"
        "    return results\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r


def test_comprehension_tainted_iterable_taints_target_crit():
    """The ticket's exact FN repro: the comprehension's own loop variable is
    genuinely tainted because it comes from iterating a tainted (os.environ-derived)
    iterable -- must crit, same as the equivalent unrolled form."""
    src = (
        "import os\n"
        "import subprocess\n\n"
        'raw = os.environ.get("SKILL_BATCH_CMDS", "")\n'
        'cmds = raw.split(";")\n'
        "results = [subprocess.run(c, shell=True) for c in cmds]\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_lambda_own_param_shadows_outer_param_not_crit():
    """The ticket's lambda variant of the FP repro: a lambda's OWN parameter reuses
    the enclosing function's tainted parameter name, called only with hardcoded
    values. `ast.Lambda` was already named in `_NESTED_SCOPE_NODES` but never
    actually given its own owner-map scope bucket."""
    src = (
        "import subprocess\n\n\n"
        "def process(user_cmd):\n"
        "    f = lambda user_cmd: subprocess.run(user_cmd)\n"
        '    f("/bin/ls")\n'
        '    f("/bin/pwd")\n'
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r


def test_walrus_in_comprehension_conditional_target_taints_crit():
    """The ticket's walrus variant of the FN repro: a walrus target set inside an
    `if` clause of the comprehension, itself derived from the tainted `for`-target,
    must crit -- a silent miss on both the comprehension-target propagation AND the
    (previously entirely absent) NamedExpr propagation."""
    src = (
        "import os\n"
        "import subprocess\n\n"
        'raw = os.environ.get("SKILL_BATCH_CMDS", "")\n'
        'cmds = raw.split(";")\n'
        "results = [subprocess.run(y) for c in cmds if (y := c.strip())]\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


# ---------------------------------------------------------------------------
# C-135 adversarial cases
# ---------------------------------------------------------------------------


def test_nested_comprehension_inner_shadow_not_crit():
    """A comprehension nested inside another comprehension: the INNER comprehension's
    own `for`-target shadows an outer tainted name, iterating only a safe literal --
    must not crit even though it is two scope-levels deep."""
    src = (
        "import subprocess\n\n\n"
        "def process(user_cmd):\n"
        '    safe_rows = [["/bin/ls"], ["/bin/pwd"]]\n'
        "    results = [\n"
        "        [subprocess.run(user_cmd) for user_cmd in row]\n"
        "        for row in safe_rows\n"
        "    ]\n"
        "    return results\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r


def test_nested_comprehension_inner_tainted_iterable_crit():
    """A comprehension nested inside another comprehension: the INNER comprehension's
    iterable is itself derived from the tainted OUTER `for`-target -- taint must
    propagate through both scope levels."""
    src = (
        "import os\n"
        "import subprocess\n\n"
        'raw = os.environ.get("SKILL_BATCHES", "")\n'
        'batches = [raw.split(";")]\n'
        "results = [\n"
        "    [subprocess.run(c, shell=True) for c in batch]\n"
        "    for batch in batches\n"
        "]\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_comprehension_iterable_self_collides_with_own_target_name_still_crit():
    """C-135 (self-caught, second round): the FIRST generator's own iterable is
    evaluated in the scope CONTAINING the comprehension (PEP 530), before the
    comprehension's own `for`-target binding exists -- so when the iterable and the
    target happen to share the SAME bare name (`for cmds in cmds`, an unusual but
    syntactically ordinary self-referential rebind of the enclosing function's own
    tainted parameter), the outer occurrence's genuine taint must still be detected,
    not wrongly shadowed by the comprehension's own same-named target."""
    src = (
        "import subprocess\n\n\n"
        "def process(cmds):\n"
        "    results = [\n"
        "        subprocess.run(x, shell=True)\n"
        "        for cmds in cmds\n"
        "        for x in [cmds]\n"
        "    ]\n"
        "    return results\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_comprehension_iterable_name_collides_with_third_function_not_crit():
    """A comprehension's iterable name is a bare identifier that ALSO happens to be
    an externally-tainted local in a totally unrelated, third function elsewhere in
    the file -- the comprehension's own (safe, literal) `cmds` in `process` must not
    be conflated with `other_func`'s unrelated, genuinely tainted `cmds`."""
    src = (
        "import os\n"
        "import subprocess\n\n\n"
        "def other_func():\n"
        '    cmds = os.environ.get("UNRELATED", "").split(";")\n'
        "    return cmds\n\n\n"
        "def process():\n"
        '    cmds = ["/bin/ls", "/bin/pwd"]\n'
        "    results = [subprocess.run(c) for c in cmds]\n"
        "    return results\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r


def test_walrus_target_only_conditionally_bound_still_crit():
    """A walrus target that is only conditionally assigned (guarded by an `if` that
    is not always true) must still be treated as tainted wherever it IS read -- taint
    tracking is conservative/static, not a runtime reachability proof."""
    src = (
        "import os\n"
        "import subprocess\n\n"
        'raw = os.environ.get("SKILL_BATCH_CMDS", "")\n'
        'cmds = raw.split(";")\n'
        "results = [\n"
        "    subprocess.run(y, shell=True)\n"
        "    for c in cmds\n"
        '    if c.startswith("run:") and (y := c[4:])\n'
        "]\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_dict_comprehension_value_taint_still_crit():
    """DictComp is one of the four comprehension types this fix covers -- a tainted
    `for`-target flowing into the VALUE expression (not just ListComp's `elt`) must
    still crit."""
    src = (
        "import os\n"
        "import subprocess\n\n"
        'raw = os.environ.get("SKILL_BATCH_CMDS", "")\n'
        'cmds = raw.split(";")\n'
        "results = {c: subprocess.run(c, shell=True) for c in cmds}\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_generator_expression_taint_still_crit():
    """GeneratorExp is one of the four comprehension types -- must behave identically
    to ListComp for taint propagation."""
    src = (
        "import os\n"
        "import subprocess\n\n"
        'raw = os.environ.get("SKILL_BATCH_CMDS", "")\n'
        'cmds = raw.split(";")\n'
        "results = list(subprocess.run(c, shell=True) for c in cmds)\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_multiple_generators_second_iterable_depends_on_first_target_crit():
    """Two `for` clauses in ONE comprehension (`for a in A for b in B(a)`) share a
    single scope -- taint from the FIRST target must be visible to the SECOND
    generator's iterable expression, within the SAME comprehension scope bucket."""
    src = (
        "import os\n"
        "import subprocess\n\n"
        'raw = os.environ.get("SKILL_BATCH_CMDS", "")\n'
        'cmd_groups = [raw.split(";")]\n'
        "results = [\n"
        "    subprocess.run(c, shell=True)\n"
        "    for group in cmd_groups\n"
        "    for c in group\n"
        "]\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_lambda_closure_reads_outer_taint_still_crit():
    """A lambda with NO parameter of its own shadowing the name must still see a
    genuine closure read of the enclosing function's own tainted local -- giving the
    lambda its own owner-map scope bucket must not silently break the ancestor-chain
    closure-read mechanism `_tainted_names_visible` already relies on for nested
    functions (B-210)."""
    src = (
        "import subprocess\n\n\n"
        "def process(user_cmd):\n"
        "    f = lambda: subprocess.run(user_cmd)\n"
        "    f()\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_lambda_inside_comprehension_reads_outer_taint_still_crit():
    """A lambda nested INSIDE a comprehension (two new scope levels deep) with no
    shadowing parameter of its own must still see the enclosing function's genuine
    taint through both ancestor-chain hops."""
    src = (
        "import subprocess\n\n\n"
        "def process(user_cmd):\n"
        "    fns = [lambda: subprocess.run(user_cmd) for _ in range(3)]\n"
        "    for fn in fns:\n"
        "        fn()\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_comprehension_shadow_in_class_method_not_crit():
    """The shadow-soundness fix must also apply inside a class method's own scope
    (methods get their own isolated owner-map bucket, sibling to plain functions)."""
    src = (
        "import subprocess\n\n\n"
        "class Runner:\n"
        "    def process(self, user_cmd):\n"
        '        safe_commands = ["/bin/ls", "/bin/pwd"]\n'
        "        return [subprocess.run(user_cmd) for user_cmd in safe_commands]\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r


# ---------------------------------------------------------------------------
# No loss of detection: ordinary comprehension-adjacent taint must still fire
# ---------------------------------------------------------------------------


def test_comprehension_direct_param_use_still_crit():
    """A comprehension whose `elt` directly uses the ENCLOSING function's own
    tainted parameter (not shadowed by any `for`-target of the same name) must still
    crit -- the shadow fix must not become a blanket 'inside a comprehension is
    always safe' rule."""
    src = (
        "import subprocess\n\n\n"
        "def process(user_cmd):\n"
        "    return [subprocess.run(user_cmd) for _ in range(3)]\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_plain_walrus_outside_comprehension_still_propagates_crit():
    """A bare walrus assignment with no comprehension involved at all must also join
    the propagation fixpoint (this was ENTIRELY absent before B-414, not just inside
    comprehensions)."""
    src = (
        "import os\n"
        "import subprocess\n\n"
        "def run_it():\n"
        '    if (payload := os.environ.get("PAYLOAD")):\n'
        "        subprocess.run(payload, shell=True)\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_existing_b413_suite_shapes_untouched():
    """Sanity check that B-414 did not disturb B-413's own layer-1/layer-2
    resolution for a plain (non-comprehension) wrapper -- the ordinary
    `def run(cmd): subprocess.check_call(cmd)` idiom called only with hardcoded argv
    lists must still downgrade to non-crit."""
    src = (
        "import subprocess\n\n\n"
        "def run(cmd):\n"
        "    subprocess.run(cmd)\n\n\n"
        "def main():\n"
        '    run(["git", "status"])\n'
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r


# ---------------------------------------------------------------------------
# Structural unit tests for the new scope-model pieces
# ---------------------------------------------------------------------------


def test_own_bound_names_comprehension_scope_is_for_targets_only():
    tree = ast.parse("[x for a in A for b in B(a) if pred(b)]")
    listcomp = tree.body[0].value
    assert isinstance(listcomp, ast.ListComp)
    assert skillast_mod._own_bound_names(listcomp) == {"a", "b"}


def test_own_bound_names_comprehension_walrus_not_own_bound_name():
    """A walrus inside a comprehension's `ifs` must NOT be treated as the
    comprehension's own bound name (PEP 572: it binds in the containing scope)."""
    tree = ast.parse("[x for c in cmds if (y := c.strip())]")
    listcomp = tree.body[0].value
    assert "y" not in skillast_mod._own_bound_names(listcomp)


def test_own_bound_names_tuple_unpacking_comprehension_target():
    tree = ast.parse("{k: v for k, v in items.items()}")
    dictcomp = tree.body[0].value
    assert isinstance(dictcomp, ast.DictComp)
    assert skillast_mod._own_bound_names(dictcomp) == {"k", "v"}


def test_build_toplevel_owner_map_gives_comprehension_its_own_bucket():
    src = "def f(x):\n    return [y for y in range(x)]\n"
    tree = ast.parse(src)
    fn = tree.body[0]
    listcomp = fn.body[0].value
    owner_map, parent_scope = skillast_mod._build_toplevel_owner_map([fn], [])
    assert owner_map.get(listcomp) is listcomp
    assert parent_scope.get(listcomp) is fn


def test_build_toplevel_owner_map_gives_lambda_its_own_bucket():
    src = "def f(x):\n    g = lambda y: y\n    return g\n"
    tree = ast.parse(src)
    fn = tree.body[0]
    lam = fn.body[0].value
    assert isinstance(lam, ast.Lambda)
    owner_map, parent_scope = skillast_mod._build_toplevel_owner_map([fn], [])
    assert owner_map.get(lam) is lam
    assert parent_scope.get(lam) is fn


# ---------------------------------------------------------------------------
# Fixture-level (vet_skill) regressions
# ---------------------------------------------------------------------------


def test_vet_warn_comprehension_shadow_fixture_not_critical():
    """Named warn_* (not clean_*), same convention as B-413's warn_taint_wrapper_argv:
    TT5_CMD_INJECTION correctly no longer crits, but the pre-existing, orthogonal
    SHELL_INJECTION_RISK shape-only rule still WARNs on the non-literal
    subprocess.run() call form -- expected, unrelated to this fix."""
    skill_dir = FIXTURES / "warn_taint_comprehension_shadow" / "skills" / "comprehensionshadowskill"
    f = vet_skill(skill_dir)
    assert f.status != FAIL
    assert f.severity != "CRITICAL"
    assert f.status == WARN


def test_vet_bad_comprehension_iterable_fixture_is_critical_fail():
    skill_dir = FIXTURES / "bad_taint_comprehension_iterable" / "skills" / "batchcmdskill"
    f = vet_skill(skill_dir)
    assert f.status == FAIL
    assert f.severity == "CRITICAL"
    assert any(
        "injection" in e.lower() or "command" in e.lower() for e in (f.evidence or [])
    )
