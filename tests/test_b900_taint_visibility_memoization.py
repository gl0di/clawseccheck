"""Regression tests for CLAWSECCHECK-B-900 (clawseccheck/skillast.py,
`_tainted_names_visible`).

`_tainted_names_visible` recomputed `_global_declared_names(scope, owner_map)` --
a full `ast.walk(scope)` -- with zero memoization, on EVERY call. Its sibling
`_tainted_names` already memoizes the identical lookup (`global_cache[scope]`); this
function did not. A hot caller invokes it once per AST node in a loop, repeatedly
against the SAME `scope`: `_external_tainted_names`'s own assign/comprehension/with/
for/walrus fixpoint (up to 6 iterations) calls it once per statement/expression it
walks, so a file with one function holding many statements made this
O(k * scope_size) for the k nodes sharing that one scope -- quadratic in practice,
and by itself enough to push a synthetic-but-realistic file (one subprocess sink
inside a ~800-statement function) from well under a second to several seconds,
threatening `scanbudget.DEFAULT_CHECK_BUDGET_S` and degrading the WHOLE FILE to
UNKNOWN, not just one slow finding.

Fix: an optional `global_cache: dict | None = None` parameter, keyed by `scope`
alone (mirroring `_tainted_names`'s own `global_cache[scope]` pattern) -- `None`
(the default) reproduces the exact pre-fix behaviour (a fresh, uncached lookup every
call), so every call site NOT threaded through a hot loop is byte-for-byte
unaffected. `_external_tainted_names` -- the confirmed, measured hot path, the only
caller whose own loop iterates over a node COUNT that scales with file size against
a SHARED scope -- now threads through the `global_cache` dict it already builds for
its own (pre-existing) `_global_nonlocal_for` memoization, so the two consumers
share one cache instead of `_tainted_names_visible` building a second, separate one.

Two classes of test:

  * MECH -- perf regression via a monkeypatch call-count assertion (deterministic,
    no wall-clock flakiness), mirroring the precedent in
    test_b863_tt5_wrapper_position_grammar.py's own
    test_mech_perf_channel_walk_and_m_are_memoized_per_function.
  * CORRECTNESS -- the higher-risk half of this fix (a caching bug returns a WRONG
    value, not a missing detection): a direct differential, node-by-node over an
    entire file's AST, between `_tainted_names_visible` called with no cache
    (`global_cache=None`, the historical always-fresh behaviour) and called with a
    single shared cache threaded across the whole walk (what the hot loop actually
    does) -- across several scope shapes the function's own long docstring history
    (B-205/B-209/B-210/B-211/B-261) calls out as the subtle cases: a `global`
    redirect to the module bucket, a shadowed same-bare-name sibling scope, a
    genuine nested-closure read, and several sibling scopes with DIFFERENT own
    `global`-declared sets sharing one cache (proving no cross-scope contamination).

Offline, deterministic. No network calls, no writes outside pytest's tmp_path (none
of these tests touch the filesystem at all).
"""

from __future__ import annotations

import ast

import clawseccheck.skillast as skillast_mod
from clawseccheck.skillast import (
    _build_toplevel_owner_map,
    _external_tainted_names,
    _func_param_taint_by_scope,
    _tainted_names_visible,
    analyze_python,
)


def _toplevel_funcs(tree: ast.AST) -> list:
    return [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _toplevel_classes(tree: ast.AST) -> list:
    return [n for n in tree.body if isinstance(n, ast.ClassDef)]


def _ext_taint_for(src: str) -> tuple:
    """Build the same (tree, tainted, owner_map, parent_scope) shape
    `_external_tainted_names`'s own real callers assemble, so the differential
    below exercises `_tainted_names_visible` against a realistic `tainted` dict
    rather than a hand-built one."""
    tree = ast.parse(src)
    owner_map, parent_scope = _build_toplevel_owner_map(_toplevel_funcs(tree), _toplevel_classes(tree))
    shadow_cache: dict = {}
    func_param_taint = _func_param_taint_by_scope(tree, owner_map, parent_scope)
    tainted = _external_tainted_names(tree, func_param_taint, owner_map, parent_scope, shadow_cache)
    return tree, tainted, owner_map, parent_scope


def _assert_cache_matches_uncached(src: str) -> None:
    """The core correctness proof: for EVERY node in `src`'s AST, a call to
    `_tainted_names_visible` with a shared `global_cache` threaded across the whole
    walk (what a hot loop does) must return the IDENTICAL set a fresh, uncached call
    (`global_cache=None`, the pre-fix behaviour) returns at that same node. Node
    order matters (a cache bug would most plausibly surface as node N reusing scope
    S's `global_here` after a DIFFERENT scope was cached under a colliding key), so
    both passes walk the nodes in the SAME order."""
    tree, tainted, owner_map, parent_scope = _ext_taint_for(src)
    nodes = list(ast.walk(tree))
    shadow_cache_uncached: dict = {}
    shadow_cache_cached: dict = {}
    global_cache: dict = {}
    for n in nodes:
        uncached = _tainted_names_visible(n, tainted, owner_map, parent_scope, shadow_cache_uncached)
        cached = _tainted_names_visible(
            n, tainted, owner_map, parent_scope, shadow_cache_cached, global_cache
        )
        assert cached == uncached, (ast.dump(n)[:120], uncached, cached)


# ---------------------------------------------------------------------------
# MECH -- perf memoization.
# ---------------------------------------------------------------------------


def test_mech_perf_global_declared_names_memoized_per_scope_in_external_taint_fixpoint():
    """A single function with 600 near-identical statements + one subprocess sink:
    `_global_declared_names` must be called a small, BOUNDED number of times (once
    per distinct scope this file actually has), not once per statement per fixpoint
    iteration."""
    padding = "\n".join(f"    x_{i} = {i} + 1" for i in range(600))
    src = (
        "import os, subprocess\n\n"
        "def big():\n"
        "    cmd = os.environ['P']\n"
        + padding
        + "\n    subprocess.run(cmd, shell=True)\n"
    )

    calls = {"global": 0}
    real = skillast_mod._global_declared_names

    def counting(*a, **kw):
        calls["global"] += 1
        return real(*a, **kw)

    skillast_mod._global_declared_names = counting
    try:
        findings = skillast_mod.analyze_python(src, "t.py")
    finally:
        skillast_mod._global_declared_names = real

    assert any(f.rule == "TT5_CMD_INJECTION" for f in findings)
    # Pre-fix this was ~2 calls per statement (one per fixpoint iteration that still
    # finds something `changed`) -- ~1200 for 600 statements. Post-fix it is bounded
    # by the number of distinct scopes (module + the one function), independent of
    # statement count.
    assert calls["global"] < 10, calls


def test_mech_perf_scales_with_scope_count_not_statement_count():
    """Doubling the statement count inside the SAME single scope must not double the
    call count -- the defining signature of O(distinct scopes) instead of O(k)."""

    def _count_for(n_statements: int) -> int:
        padding = "\n".join(f"    x_{i} = {i} + 1" for i in range(n_statements))
        src = (
            "import os, subprocess\n\n"
            "def big():\n"
            "    cmd = os.environ['P']\n"
            + padding
            + "\n    subprocess.run(cmd, shell=True)\n"
        )
        calls = {"global": 0}
        real = skillast_mod._global_declared_names

        def counting(*a, **kw):
            calls["global"] += 1
            return real(*a, **kw)

        skillast_mod._global_declared_names = counting
        try:
            skillast_mod.analyze_python(src, "t.py")
        finally:
            skillast_mod._global_declared_names = real
        return calls["global"]

    small = _count_for(100)
    large = _count_for(900)
    assert large <= small, (small, large)


# ---------------------------------------------------------------------------
# CORRECTNESS -- cached result must equal the uncached result, node-by-node.
# ---------------------------------------------------------------------------


def test_global_redirect_scope_cached_matches_uncached():
    """B-261 shape: a `global`-declared assignment in one function, read in another
    -- exercises the `global_here` redirect-to-module-bucket branch this fix now
    caches."""
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
    _assert_cache_matches_uncached(src)
    # Sanity: the fix must not have changed the actual finding either.
    r = {f.rule for f in analyze_python(src, "t.py")}
    assert "TT5_CMD_INJECTION" in r


def test_nested_closure_read_with_unrelated_shadow_cached_matches_uncached():
    """B-210/B-211 shape: a genuine nested-closure read of an outer function's
    tainted local, alongside an UNRELATED sibling function reusing the exact same
    bare name for its own untainted local (must not falsely share taint) -- the
    shadow-subtraction path this fix's `global_cache` sits next to."""
    src = (
        "import os\n"
        "import subprocess\n"
        "\n"
        "\n"
        "def outer():\n"
        "    payload = os.environ['P']\n"
        "\n"
        "    def inner():\n"
        "        subprocess.run(payload, shell=True)\n"
        "\n"
        "    inner()\n"
        "\n"
        "\n"
        "def other():\n"
        "    payload = 'hardcoded-and-safe'\n"
        "    subprocess.run(payload, shell=True)\n"
    )
    _assert_cache_matches_uncached(src)
    r = {f.rule for f in analyze_python(src, "t.py")}
    assert "TT5_CMD_INJECTION" in r  # from outer/inner
    assert "TT5_ARG_INJECTION" not in r


def test_nonlocal_redirect_scope_cached_matches_uncached():
    """B-215 shape: a `nonlocal`-declared write lands in the ancestor's own bucket,
    not `scope`'s -- a different `global_cache`-adjacent bucketing path, exercised
    here for completeness alongside the `global` case above."""
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
    _assert_cache_matches_uncached(src)


def test_many_sibling_scopes_with_different_global_sets_do_not_cross_contaminate():
    """Several sibling functions, each declaring a DIFFERENT `global` name (or none
    at all) -- a cache keyed wrongly (e.g. by name instead of by scope object, or
    shared across an unrelated owner_map) would leak one function's `global_here`
    set into another's visibility computation. Every scope here is queried multiple
    times against ONE shared cache, in file order, then again in REVERSE order, to
    also catch an insertion-order-dependent bug."""
    src = (
        "import subprocess\n"
        "\n"
        "a = None\n"
        "b = None\n"
        "c = None\n"
        "\n"
        "\n"
        "def set_a(v):\n"
        "    global a\n"
        "    a = v\n"
        "\n"
        "\n"
        "def set_b(v):\n"
        "    global b\n"
        "    b = v\n"
        "\n"
        "\n"
        "def no_global(v):\n"
        "    local_only = v\n"
        "    return local_only\n"
        "\n"
        "\n"
        "def run_a():\n"
        "    subprocess.run(a, shell=True)\n"
        "\n"
        "\n"
        "def run_b():\n"
        "    subprocess.run(b, shell=True)\n"
    )
    _assert_cache_matches_uncached(src)

    tree, tainted, owner_map, parent_scope = _ext_taint_for(src)
    nodes = list(ast.walk(tree))
    shadow_cache_fwd: dict = {}
    global_cache: dict = {}
    forward = [
        _tainted_names_visible(n, tainted, owner_map, parent_scope, shadow_cache_fwd, global_cache)
        for n in nodes
    ]
    shadow_cache_rev: dict = {}
    global_cache_rev: dict = {}
    reverse = [
        _tainted_names_visible(n, tainted, owner_map, parent_scope, shadow_cache_rev, global_cache_rev)
        for n in reversed(nodes)
    ]
    reverse.reverse()
    assert forward == reverse

    r = {f.rule for f in analyze_python(src, "t.py")}
    assert "TT5_CMD_INJECTION" in r


def test_hot_loop_finding_set_identical_to_a_scope_with_only_one_statement():
    """End-to-end sanity: the SAME source, once with 600 padding statements (forces
    the cache to actually get reused many times) and once with a single statement
    (the cache is populated once and never reused), must produce the identical
    finding set -- statement COUNT changes nothing about the semantics, only how
    many times the (now-cached) lookup would have re-run."""

    def _make(n_statements: int) -> str:
        padding = "\n".join(f"    x_{i} = {i} + 1" for i in range(n_statements))
        return (
            "import os, subprocess\n\n"
            "def big():\n"
            "    cmd = os.environ['P']\n"
            + padding
            + "\n    subprocess.run(cmd, shell=True)\n"
        )

    small = {f.rule for f in analyze_python(_make(1), "t.py")}
    large = {f.rule for f in analyze_python(_make(600), "t.py")}
    assert small == large
    assert "TT5_CMD_INJECTION" in small
