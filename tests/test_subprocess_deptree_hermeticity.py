"""Subprocess CLI hermeticity: every audit-path spawn of the real clawseccheck CLI must
carry --no-deptree.

THE BUG THIS GUARDS. `cli.py` enables the npm dependency-tree walk by default
(`include_deptree=not args.no_deptree`, wired into `build_context()`/`audit()` at its
three call sites -- the default report path, `--explain`/`--retest`'s
`_run_single_check`, and the `.clawseccheckignore` match-listing path). `conftest.py`'s
autouse `_stub_deptree_scan` fixture neutralizes this FOR THE IN-PROCESS TEST
INTERPRETER via `monkeypatch.setattr(clawseccheck, "_deptree_scan", ...)` -- but
monkeypatch cannot cross a process boundary. Every test that spawns the CLI as a real
subprocess (`sys.executable -m clawseccheck[.cli] ...`) on the audit path therefore
still walks whatever npm tree happens to be installed on the machine running the suite.

WHY THIS IS A HERMETICITY BUG, NOT (ONLY) A SPEED ONE. `_stub_deptree_scan`'s own
docstring already makes the point about the in-process case: "the same hermeticity
break `_stub_host_detect` below exists to prevent -- a test reading real machine state
it never set up." A subprocess spawn missing `--no-deptree` reads that exact same real
machine state; its result depends on what is globally `npm install -g`'d on the box
running the suite, not on anything the test set up. The speed cost is a visible SYMPTOM
(measured: same invocation, subprocess, wall 3.29s default vs. 0.79s with
`--no-deptree`, ~97% of the difference inside `_deptree_scan -> scan_dep_tree ->
walk_dir_safely` per cProfile) -- a future reader who assumes that is the whole story
and exempts themselves from this guard "because it's just slow here" has missed why it
exists.

WHAT THIS GUARD DOES AND DOES NOT PROVE. It is a static, cooperative reader of this
repo's own test sources -- same spirit as test_module_layout.py / test_public_boundary.py
-- not a dataflow engine. For each `subprocess.run/Popen/check_call/check_output/call(...)`
call site (direct, or reached through exactly one local helper function -- the
`_run`/`_vet`/`_audit`-style helpers most test files define), it collects every argv
element it can prove is a string literal -- inlining a helper's own `*args`/`*extra`
spread by resolving it back to each of the helper's OWN call sites -- and asks:
  1. is this even a `clawseccheck`/`clawseccheck.cli` **module** spawn (`-m ...`), as
     opposed to a `-c SCRIPT` spawn (never goes through cli.py's argument parser) or an
     unrelated tool (`-m json.tool`, a bare script path, `git`, ...)?
  2. if so, does `_SAFE_MODE_FLAGS` (below) already prove this run takes one of the
     branches in `main()` that returns before ever reaching `build_context()`/`audit()`
     -- the vet family, `--canary`/`--redteam`/`--dryrun`/`--multiturn`/`--self-test` --
     so `include_deptree` is never consulted?
  3. if neither, is `--no-deptree` one of the literals?

An ordinary dynamic VALUE beside a literal flag (a tmp path, `str(x)`, an unrelated
variable) never hides another flag -- a single argv element is always exactly one
string -- so it is skipped rather than treated as "we can't tell". Only a `*spread` this
guard truly cannot trace at all (through neither a local list-builder loop nor one level
of helper-call substitution) is reported as UNRESOLVED rather than NEEDS THE FLAG.
Measured against this repo's real suite while designing this guard: 313 subprocess call
sites, 78 safe (vet-path / not a CLI spawn / -c script), 224 missing --no-deptree on the
audit path (47 files), 11 unresolved (8 files) -- see the module-level lists below for
where those two non-"safe" outcomes get recorded. Both are hard failures, never a silent
skip: a guard that stays quiet on what it cannot prove would recreate exactly the
"monkeypatch doesn't cross a process boundary" blind spot it exists to close. (Those four
numbers are a point-in-time measurement from when this guard was first written, not a
live invariant -- the corpus has since shrunk/changed and today's counts differ; nothing
below depends on them.)

A NAME THIS GUARD RESOLVES BEYOND LOCALS AND PARAMETERS. `*spread` was originally only
traced through a LOCAL variable or a helper's own parameter -- a bare module-level
global was invisible, which was itself a live blind spot:
`tests/test_b623_judge_packet_run_state.py` spreads `*REPO_ARGS` (`REPO_ARGS =
["-m", "clawseccheck"]`, a plain module global) into its subprocess argv from inside a
function. Because "-m" then never appeared in the visible literal set, and the ABSENCE
of "-m" was (wrongly) treated as proof of safety regardless of what an unresolved spread
might contain, this guard concluded "safe: no -m at all" even with `--no-deptree`
deleted from that exact call -- proven by deleting it and rerunning this guard, which
still passed 2/2. Fixed two ways, together:
  (a) `_partial_resolve()` now resolves a bare Name as a module global
      (`_resolve_module_global()`, scoped via `_ModuleScopeVisitor` to statements that
      are truly at module level -- descending into module-level if/for/while/try/with,
      never into a nested function/class/lambda) when it is not a local of the
      enclosing scope, and also resolves an `x + y` argv (`ast.BinOp`/`Add`) by
      recursing into both operands -- covers `PREFIX + ["--home", ...]` however deep
      the nesting.
  (b) `classify_known()` no longer treats "-m" being ABSENT from a partially-opaque
      known set as proof of "safe, not a module spawn" -- it defers (returns `None,
      None`) so the caller falls through to hole-tracing / UNRESOLVED instead. This
      closes the same hole for every OTHER way a `*spread` can still fail to resolve
      (below), not only the module-global case that motivated it. A companion bug in
      the same family, also fixed here: `_resolve_local()`/`_resolve_module_global()`
      used to call `_partial_resolve()` on an assignment's own value and keep only its
      `known` half, throwing away `opaque` -- so a LOCAL (not just a global) built from
      something unparseable (`x + y` before the BinOp fix existed, a comprehension, a
      ternary, ...) was reported as "resolved, contributes nothing" instead of opaque.
      Both functions now propagate `opaque` faithfully.

SHAPES DELIBERATELY LEFT UNRESOLVED -- reported as UNRESOLVED (fails loudly) rather than
guessed, each verified against this repo's real corpus (none currently occur; this is
the boundary for if/when one does):
  - **A class or instance attribute** (`self.ARGS`, `Runner.ARGS`) spread into argv: an
    `ast.Attribute`, not an `ast.Name`, so it never enters `_resolve_local`/
    `_resolve_module_global` at all and falls straight to `_partial_resolve`'s
    unconditional `return [], True`. Verified with a synthetic `class Runner: ARGS =
    [...]; def run(self): subprocess.run([sys.executable, *self.ARGS, ...])` --
    correctly yields UNRESOLVED, never "safe".
  - **A prefix imported from another test module**
    (`from test_foo import REPO_ARGS`): an `ast.ImportFrom` binding, not an
    `ast.Assign`/`ast.AugAssign`/`.append`/`.extend`, so `_resolve_module_global` never
    matches it (`saw` stays False) and it falls through to opaque, same as any other
    unresolved Name. Verified synthetically -- UNRESOLVED, not silently empty. Chasing
    the import into the other file's own AST would be a further generalization this
    guard does not attempt (no live case motivates the added complexity).
  - **A global (or local) built by a comprehension or a conditional EXPRESSION**
    (`ARGS = [x for x in (...)]`, `ARGS = A if COND else B`): neither is an
    `ast.Name`/`ast.List`/`ast.Tuple`/`ast.BinOp`-with-`Add`, so `_partial_resolve`
    falls to its unconditional opaque return, and -- now that `opaque` propagates
    correctly -- that reaches the caller as UNRESOLVED. (A conditional built from
    ordinary `if`/`else` STATEMENTS at module level, each branch a plain `Assign` to
    the same name, IS resolved -- see above -- consistent with the pre-existing
    non-path-sensitive treatment of conditional appends to a local.)
  - **`functools.partial(subprocess.run, argv, ...)`**: not an argv-resolution gap but
    a CALL-SITE ENUMERATION gap -- `_is_subprocess_call()` only matches an `ast.Call`
    whose own `func` is `subprocess.<name>` or a bare imported `<name>`; wrapping the
    function reference as `functools.partial`'s first argument means the
    `subprocess.run` reference is never itself called at that point (no `()` after
    it), so the enclosing `functools.partial(...)` call's `func` is `functools.partial`
    -- matching neither pattern. Verified synthetically: a
    `functools.partial(subprocess.run, [sys.executable, "-m", "clawseccheck", ...])`
    module global, invoked later as `runner()`, yields ZERO hits from this guard's
    call-site visitor -- not UNRESOLVED, not even visited. No live call site in this
    repo uses this shape (checked: every file importing `functools.partial`/`partial`
    has no `subprocess.*` call at all). Accepted as an out-of-scope limitation rather
    than resolved, because closing it needs a second call-site pattern (recognize
    `partial`/`functools.partial` wrapping a subprocess reference, and separately that
    ANY later bare-name call could be the resulting partial invoked, which this guard's
    per-call-site design does not track) that would be exercised by nothing today --
    if this shape is ever introduced, it must be caught by a human, not this guard,
    until it grows real alias tracking.
"""
from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = REPO_ROOT / "tests"
_THIS_FILE = Path(__file__).name

# Argparse flags dispatched in cli.py's main() BEFORE any of its three
# build_context()/audit() call sites -- grep `include_deptree=not args.no_deptree` for
# the three call sites; each name below is an `if _mode == "...": ... return N` block
# (the vet family goes through the shared `_vet_route` block) that main() takes
# strictly earlier. Proven by reading the dispatch table directly, not guessed. Note
# `--judge-packet` (bare) is deliberately ABSENT here even though `--vet-judge-packet`
# looks similar: the bare flag runs through the ordinary default audit path and only
# adds a rendering step afterward (`_mode == "judge_packet"` is dispatched well after
# the default `audit()` call), so it still needs --no-deptree like any other bare run.
#
# If a future flag is added that ALSO bypasses build_context()/audit(), the worst this
# causes is a false "needs-flag" here, fixed by adding it to this set with a comment
# naming the cli.py block that proves the bypass -- the guard errs toward
# re-investigating a new flag, never toward silently trusting one.
_SAFE_MODE_FLAGS = frozenset({
    "--vet", "--vet-skill", "--vet-plugin", "--vet-mcp", "--vet-source", "--vet-all",
    "--advise", "--canary", "--redteam", "--dryrun", "--multiturn", "--self-test",
    # The four below returned real "needs-flag" offenders the first time this guard ran
    # against the live corpus (tests/test_b580_trend_discloses_pruning.py,
    # tests/test_b775_audit_shim_no_bytecode.py) -- each verified by reading cli.py's own
    # dispatch table, not guessed:
    "--verify-history",  # `if _mode == "verify_history":` (cli.py ~4091) returns rc
                          # before the ignore-list audit() call (~4727) or the default
                          # report path (~4927).
    "--verify-events",   # `if _mode == "verify_events":` (cli.py ~4100), same shape,
                          # returns immediately after verify_history's block.
    "--verify-baseline",  # `if _mode == "verify_baseline":` (cli.py ~4114) returns 0/1
                          # from `_verify_baseline()` alone, no audit() call.
    "--watch-log",       # `if _mode == "watch_log":` (cli.py ~4797) renders the events
                          # journal and returns 0 (~4838), strictly before the shared
                          # attestation/bundle prelude that leads into the default
                          # audit() call at ~4927.
    "--version",         # `p.add_argument("--version", action="version", ...)`
                          # (cli.py ~3400): argparse's own "version" action prints and
                          # calls `sys.exit(0)` during `parse_args()`, before `main()`'s
                          # body -- and therefore before any `_mode ==` dispatch at all
                          # -- ever runs.
    # NOTE: top-level `--watch` (cli.py ~3950, `_run_watch_cli`) is DELIBERATELY not
    # listed here even though its own dispatch block never calls build_context()/
    # audit() either ("needs no audit() of its own", per its comment). Each debounce
    # cycle spawns a NESTED `--monitor` subprocess (watch.py's `_run_monitor_once`)
    # that DOES take the default, deptree-walking path, and that nested spawn has no
    # way to receive this test's own `--no-deptree` today (a production-code gap,
    # tracked separately -- see tests/test_watch.py's two subprocess-spawn call sites,
    # which pass `--no-deptree` on the OUTER process for forward-compatibility and
    # cleanliness, but it is currently a no-op for the inner one). Calling `--watch`
    # "safe" here would hide exactly the hermeticity gap this guard exists to catch.
})

# Call sites that must NOT carry --no-deptree, because the test's whole point is the
# real dependency-tree walk. Empty today: no subprocess test currently exercises B349
# end-to-end (tests/test_f167_deptree_hooks.py does that in-process, against a fixture
# tree, and never touches subprocess). Keyed "relative/path.py:function_qualname", each
# entry reasoned -- same shape as test_b661's _INDEPENDENT_OF_CONFIG / test_module_
# layout's _EXEMPT.
_DELIBERATE_DEPTREE_WALK: dict[str, str] = {
    # "test_bNNN_real_deptree_e2e.py:test_walks_a_real_npm_tree":
    #     "BNNN: the one end-to-end proof that scan_dep_tree() finds a real tree "
    #     "outside a fixture; builds its own throwaway node_modules under tmp_path so "
    #     "it stays hermetic despite not passing --no-deptree.",
    "tests/test_b632_vet_envelope_schema.py:"
    "test_vet_modes_emit_exactly_the_documented_base_envelope":
        "Not actually a deliberate walk -- a guard blind spot. `_emitted([flag, arg])` "
        "spreads a `pytest.mark.parametrize(\"flag\", [...])` value into the argv; this "
        "guard has no way to look inside a parametrize decorator, so `flag` is opaque to "
        "it. Hand-verified 2026-09-21 by reading the decorator two lines above the test: "
        "the only three values are '--vet-skill', '--vet-plugin', '--vet-mcp', all "
        "already in _SAFE_MODE_FLAGS. Re-check this entry if that parametrize list ever "
        "grows a new flag.",
}

# Call sites whose argv this guard cannot statically resolve at all, cleared BY HAND
# instead of by the guard's own logic. Each entry must name HOW it was checked and
# WHEN -- an unreviewed "trust me" entry here defeats the guard as completely as a
# missing --no-deptree would. Prefer simplifying the test's argv construction (usually
# a couple of lines) over adding an entry; this dict is for the genuine remainder.
_UNTRACEABLE_ARGV: dict[str, str] = {
    "tests/test_b728_dist_locator.py:_fails_rather_than_skips":
        "False positive, not a real gap: `_fails_rather_than_skips(call, what)` takes a "
        "PARAMETER named `call` (an arbitrary callable the test passes in) and invokes it "
        "as `call()` -- this guard's own `_is_subprocess_call` treats any bare `Name` "
        "matching {run,Popen,check_output,check_call,call} as `subprocess.call` (to "
        "support `from subprocess import run` style imports), so a local variable that "
        "merely happens to be named `call` collides with that heuristic. Hand-verified "
        "2026-09-21 by reading the function: it never imports or calls `subprocess.call`, "
        "it is a generic 'run this and expect an AssertionError, not a skip' helper used "
        "on ordinary Python callables in this file.",
    "tests/test_publish_workflow.py:_replay_staged_tree":
        "Real gap surfaced by the B-623 opacity-propagation fix (a local variable built "
        "from a function-call result, `staged = sorted(_staged_paths(...))`, used to be "
        "silently treated as 'resolved to zero contributions' -- see _resolve_local's "
        "docstring -- so this call site was invisible to the guard before; now it is "
        "correctly opaque). The call is `subprocess.run([\"git\", \"ls-files\", ..., \"--\", "
        "*staged], ...)`: argv[0] is the literal 'git', never `sys.executable`, so this can "
        "never be a `python -m clawseccheck[.cli]` spawn no matter what `staged` contains. "
        "`staged` itself only ever holds repo-relative path strings parsed out of the "
        "publish workflow's own `cp`/`rm -rf` lines by `_staged_paths()` (e.g. 'SKILL.md', "
        "'clawseccheck') -- there is no code path that could make an element equal '-m' or "
        "'clawseccheck'. Hand-verified 2026-09-21 by reading both `_replay_staged_tree` and "
        "`_staged_paths`.",
}

_SUBPROCESS_FUNCS = {"run", "Popen", "check_output", "check_call", "call"}


# --------------------------------------------------------------------------------
# AST plumbing: best-effort extraction of string-literal argv elements, inlining ONE
# level of local helper-function indirection. See the module docstring for exactly
# what this proves and what it hands back as "unresolved".
# --------------------------------------------------------------------------------

def _is_subprocess_call(node: ast.Call) -> bool:
    f = node.func
    if isinstance(f, ast.Attribute) and f.attr in _SUBPROCESS_FUNCS:
        return isinstance(f.value, ast.Name) and f.value.id == "subprocess"
    if isinstance(f, ast.Name) and f.id in _SUBPROCESS_FUNCS:
        return True  # `from subprocess import run` style
    return False


def _str_const(node: ast.expr) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _param_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[set[str], str | None]:
    names = {a.arg for a in fn.args.args} | {a.arg for a in fn.args.posonlyargs} \
        | {a.arg for a in fn.args.kwonlyargs}
    vararg = fn.args.vararg.arg if fn.args.vararg else None
    return names, vararg


def _resolve_local(name: str, scope: ast.AST,
                    module_tree: ast.Module) -> tuple[list[str], bool] | None:
    """Every string this LOCAL variable (assigned somewhere in *scope*) contributes,
    via its assignment(s) plus any `.append(...)`/`.extend([...])`/`+= [...]` on it,
    as (known, opaque) -- opaque propagated from whatever the assignment's OWN value
    resolves to, so a local built from something this guard cannot parse (`x + y`, a
    comprehension, a ternary, ...) is reported as opaque rather than silently "resolved
    to zero contributions" (the bug a prior version of this function had: it kept only
    `known` from a nested `_partial_resolve()` call and threw the opacity away).
    Returns None if *name* is never bound in *scope* at all -- the caller then tries a
    module global, then treating it as an external (helper-parameter) hole. Order and
    conditional appends/branches are deliberately ignored (see module docstring): this
    proves "the flag appears in the code that builds this argv", not "on every path
    through it"."""
    known: list[str] = []
    opaque = False
    saw = False
    for n in ast.walk(scope):
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets):
            saw = True
            k, o = _partial_resolve(n.value, scope, module_tree)
            known.extend(k)
            opaque = opaque or o
        elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name) and n.target.id == name:
            saw = True
            k, o = _partial_resolve(n.value, scope, module_tree)
            known.extend(k)
            opaque = opaque or o
        elif (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
              and isinstance(n.func.value, ast.Name) and n.func.value.id == name
              and n.func.attr in ("append", "extend")):
            saw = True
            if n.func.attr == "append" and len(n.args) == 1:
                s = _str_const(n.args[0])
                if s is not None:
                    known.append(s)
            elif n.func.attr == "extend" and len(n.args) == 1:
                k, o = _partial_resolve(n.args[0], scope, module_tree)
                known.extend(k)
                opaque = opaque or o
    return (known, opaque) if saw else None


class _ModuleScopeVisitor(ast.NodeVisitor):
    """Collects every Assign / AugAssign / append|extend-Call whose nearest enclosing
    scope is the module itself -- descends into ordinary module-level control flow
    (if/for/while/try/with), since a module global can legitimately be built
    conditionally (same non-path-sensitive philosophy as _resolve_local), but never
    into a nested function/class/lambda body, each of which is its own separate scope
    that must not leak a same-named local into this module-global lookup."""
    def __init__(self) -> None:
        self.hits: list[ast.AST] = []

    def visit_FunctionDef(self, node: ast.AST) -> None:  # noqa: N802
        return

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_ClassDef = visit_FunctionDef
    visit_Lambda = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        self.hits.append(node)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:  # noqa: N802
        self.hits.append(node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        self.hits.append(node)
        self.generic_visit(node)


def _resolve_module_global(name: str, module_tree: ast.Module) -> tuple[list[str], bool] | None:
    """Same contract as _resolve_local, but for a name bound at true MODULE scope --
    e.g. `REPO_ARGS = ["-m", "clawseccheck"]` at the top of a test file, then spread
    into a subprocess call as `*REPO_ARGS` from inside a function (a real, live case:
    tests/test_b623_judge_packet_run_state.py). Restricted to _ModuleScopeVisitor's
    module-only hits rather than ast.walk(module_tree), so a same-named LOCAL variable
    inside some unrelated function in the file is never mistaken for this global.
    Returns None if *name* has no such module-level assignment at all -- notably this
    also covers a name bound only via `import`/`from ... import ...` (no Assign node
    to find), so an imported prefix constant from another test module is correctly
    left unresolved (opaque) rather than silently treated as empty-and-safe; see the
    module docstring's "left deliberately unresolved" list."""
    v = _ModuleScopeVisitor()
    for stmt in module_tree.body:
        v.visit(stmt)
    known: list[str] = []
    opaque = False
    saw = False
    for n in v.hits:
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets):
            saw = True
            k, o = _partial_resolve(n.value, module_tree, module_tree)
            known.extend(k)
            opaque = opaque or o
        elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name) and n.target.id == name:
            saw = True
            k, o = _partial_resolve(n.value, module_tree, module_tree)
            known.extend(k)
            opaque = opaque or o
        elif (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
              and isinstance(n.func.value, ast.Name) and n.func.value.id == name
              and n.func.attr in ("append", "extend")):
            saw = True
            if n.func.attr == "append" and len(n.args) == 1:
                s = _str_const(n.args[0])
                if s is not None:
                    known.append(s)
            elif n.func.attr == "extend" and len(n.args) == 1:
                k, o = _partial_resolve(n.args[0], module_tree, module_tree)
                known.extend(k)
                opaque = opaque or o
    return (known, opaque) if saw else None


def _partial_resolve(node: ast.expr, scope: ast.AST,
                      module_tree: ast.Module) -> tuple[list[str], bool]:
    """(known, opaque). `known` is every string constant reachable from *node* -- an
    ordinary dynamic VALUE beside them (a path, `str(x)`, an unrelated name) is
    silently skipped, since a single argv element can never itself expand into more
    elements unless it is a `*spread`. `opaque=True` means some `*spread` could not be
    traced at all, so `known` may be missing flags a human should check.

    A bare Name is resolved as a LOCAL first (shadowing wins), then as a MODULE GLOBAL
    (`_resolve_module_global`) if *scope* is not already the module itself -- this is
    the fix for the B-623-test blind spot (a module-level `REPO_ARGS = ["-m", ...]`
    spread with `*REPO_ARGS` from inside a function). A `x + y` concatenation
    (`ast.BinOp`/`Add`) is resolved by recursing into both operands and combining --
    covers e.g. `PREFIX + ["--home", ...]`. Anything else this function cannot parse
    (a class/instance attribute like `self.ARGS`, a comprehension, a ternary, a
    dict/f-string, a name bound only by `import`) falls through to the unconditional
    `return [], True` at the bottom -- reported as opaque, never silently "empty and
    safe". See the module docstring for the full list of shapes deliberately left
    opaque rather than resolved, and why each is sound to leave that way."""
    if isinstance(node, ast.Name):
        local = _resolve_local(node.id, scope, module_tree)
        if local is not None:
            return local
        if scope is not module_tree:
            glob = _resolve_module_global(node.id, module_tree)
            if glob is not None:
                return glob
        return [], True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        lk, lo = _partial_resolve(node.left, scope, module_tree)
        rk, ro = _partial_resolve(node.right, scope, module_tree)
        return lk + rk, lo or ro
    if not isinstance(node, (ast.List, ast.Tuple)):
        return [], True
    known: list[str] = []
    opaque = False
    for elt in node.elts:
        if isinstance(elt, ast.Starred):
            k, o = _partial_resolve(elt.value, scope, module_tree)
            known.extend(k)
            opaque = opaque or o
            continue
        s = _str_const(elt)
        if s is not None:
            known.append(s)
    return known, opaque


def _fixed_literals(list_node: ast.expr) -> list[str]:
    """String literals directly in a List/Tuple, ignoring Starred elements entirely --
    used once a hole has been identified so the caller can check whether the FIXED part
    of a helper already proves the classification regardless of the hole."""
    if not isinstance(list_node, (ast.List, ast.Tuple)):
        return []
    return [s for elt in list_node.elts if not isinstance(elt, ast.Starred)
            for s in [_str_const(elt)] if s is not None]


def _external_hole(list_node: ast.expr, fn: ast.FunctionDef | ast.AsyncFunctionDef,
                    module_tree: ast.Module) -> str | None:
    """If *list_node* has exactly one `Starred(Name(x))` where x is a parameter of *fn*
    with no LOCAL binding inside fn (so its value can only come from a caller), return
    x. None for zero or ambiguous multiple holes -- this guard does not guess."""
    if not isinstance(list_node, (ast.List, ast.Tuple)):
        return None
    params, vararg = _param_names(fn)
    holes = [
        elt.value.id for elt in list_node.elts
        if isinstance(elt, ast.Starred) and isinstance(elt.value, ast.Name)
        and (elt.value.id in params or elt.value.id == vararg)
        and _resolve_local(elt.value.id, fn, module_tree) is None
    ]
    return holes[0] if len(holes) == 1 else None


def _call_site_arg_for_param(call: ast.Call, fn: ast.FunctionDef | ast.AsyncFunctionDef,
                              param_name: str):
    """Where *param_name* is bound at this *call* to *fn*: ('vararg', [trailing exprs])
    for a true `*param`, ('expr', node) for a positional/keyword parameter, or
    ('missing', None) if the call doesn't actually supply it (a default applies --
    treated as opaque by the caller)."""
    params, vararg = _param_names(fn)
    if param_name == vararg:
        n_named = len(fn.args.posonlyargs) + len(fn.args.args)
        return "vararg", call.args[n_named:]
    named = [a.arg for a in fn.args.posonlyargs] + [a.arg for a in fn.args.args]
    if param_name in named:
        idx = named.index(param_name)
        if idx < len(call.args):
            return "expr", call.args[idx]
    for kw in call.keywords:
        if kw.arg == param_name:
            return "expr", kw.value
    return "missing", None


def _resolve_vararg_tail(exprs: list[ast.expr], scope: ast.AST,
                          module_tree: ast.Module) -> tuple[list[str], bool]:
    known: list[str] = []
    opaque = False
    for e in exprs:
        if isinstance(e, ast.Starred):
            k, o = _partial_resolve(e.value, scope, module_tree)
            known.extend(k)
            opaque = opaque or o
        else:
            s = _str_const(e)
            if s is not None:
                known.append(s)
    return known, opaque


class _NoNestedFuncVisitor(ast.NodeVisitor):
    """Collects every ast.Call directly in a scope's body, without descending into
    nested function defs (each of those is analyzed as its own scope separately)."""
    def __init__(self) -> None:
        self.calls: list[ast.Call] = []

    def visit_FunctionDef(self, node: ast.AST) -> None:  # noqa: N802
        return

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        self.calls.append(node)
        self.generic_visit(node)


def _direct_calls(scope) -> list[ast.Call]:
    v = _NoNestedFuncVisitor()
    for stmt in scope.body:
        v.visit(stmt)
    return v.calls


def classify_known(known: list[str], opaque: bool = False):
    """(verdict, detail) from a literal set that may or may not be the WHOLE argv.
    verdict is 'safe' (a -c script, a non-clawseccheck -m spawn, or a mode flag that
    never reaches build_context()/audit()), 'ok' (--no-deptree present), or None
    (undetermined from `known` alone -- the caller decides based on whether anything
    was left opaque).

    *opaque* must be True whenever some part of the real argv could not be resolved
    (a `*spread` this guard couldn't trace). Every verdict this function returns while
    `known` merely lacks a flag (rather than contains one) is unsound under opacity --
    an unresolved spread could BE that missing flag -- so the "no -m at all" absence
    check below defers (returns None, None) when opaque, instead of concluding "safe".
    This is the fix for a real bug: `tests/test_b623_judge_packet_run_state.py` spreads
    a module global (`*REPO_ARGS`, itself `["-m", "clawseccheck"]`) into the argv; before
    _partial_resolve() learned to resolve module globals (see its docstring), "-m" was
    invisible to `known` and this function's ABSENCE-based branch declared the call site
    "safe: no -m at all" regardless of whether --no-deptree was actually present --
    proven live by removing --no-deptree from that exact call and rerunning this guard,
    which still passed. Every OTHER conclusion here is a PRESENCE check (a literal is
    definitely there) and stays sound regardless of *opaque*: a real flag found among
    `known` is true no matter what an unresolved remainder might also contain."""
    if "-c" in known[:3]:
        return "safe", "-c script (never goes through cli.py's argument parser)"
    if "-m" in known:
        idx = known.index("-m")
        target = known[idx + 1] if idx + 1 < len(known) else None
        if target not in ("clawseccheck", "clawseccheck.cli"):
            return "safe", f"-m {target!r} (not the clawseccheck CLI)"
    elif opaque:
        return None, None  # an unresolved spread could be hiding "-m ..." itself
    else:
        return "safe", "no -m at all (not a module spawn)"
    if "--no-deptree" in known:
        return "ok", "--no-deptree present"
    hit = _SAFE_MODE_FLAGS.intersection(known)
    if hit:
        return "safe", f"mode flag {sorted(hit)} never reaches build_context()/audit()"
    return None, None


def _test_files() -> list[Path]:
    return sorted(p for p in TESTS_DIR.glob("test_*.py") if p.name != _THIS_FILE)


def _analyze_file(path: Path):
    """Yield (lineno, qualname, verdict, detail) for every subprocess call site in
    *path*. verdict is one of 'safe', 'ok', 'needs-flag', 'unresolved'."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    funcs = {n.name: n for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}

    def qualname_of(scope) -> str:
        return getattr(scope, "name", "<module>")

    def enclosing_scope(call: ast.Call):
        best = tree
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                    and any(c is call for c in ast.walk(n)):
                best = n
        return best

    def find_call_sites(fn_name: str, exclude: ast.Call):
        sites = []
        for scope in (tree, *funcs.values()):
            for c in _direct_calls(scope):
                if c is not exclude and isinstance(c.func, ast.Name) and c.func.id == fn_name:
                    sites.append((c, scope))
        return sites

    def analyze(call: ast.Call, scope):
        if not call.args:
            yield (call.lineno, qualname_of(scope), "unresolved", "no positional argv arg")
            return
        first = call.args[0]
        known, opaque = _partial_resolve(first, scope, tree)
        verdict, detail = classify_known(known, opaque)
        if verdict is not None:
            yield (call.lineno, qualname_of(scope), verdict, detail)
            return
        if not opaque:
            yield (call.lineno, qualname_of(scope), "needs-flag",
                   "no --no-deptree / safe mode flag found in the (fully resolved) argv")
            return
        hole = _external_hole(first, scope, tree) if isinstance(
            scope, (ast.FunctionDef, ast.AsyncFunctionDef)) else None
        if hole is None:
            yield (call.lineno, qualname_of(scope), "unresolved",
                   "argv construction this guard cannot trace")
            return
        fixed = _fixed_literals(first)
        fv, fd = classify_known(fixed, True)  # the hole itself is, by construction, unresolved here
        if fv is not None:
            yield (call.lineno, qualname_of(scope), fv, fd + " (fixed part of the helper)")
            return
        sites = find_call_sites(scope.name, exclude=call)
        if not sites:
            yield (call.lineno, qualname_of(scope), "unresolved",
                   f"{scope.name}() is never called in this file; hole {hole!r} unresolved")
            return
        for site, site_scope in sites:
            kind, payload = _call_site_arg_for_param(site, scope, hole)
            if kind == "vararg":
                extra_known, extra_opaque = _resolve_vararg_tail(payload, site_scope, tree)
            elif kind == "expr":
                extra_known, extra_opaque = _partial_resolve(payload, site_scope, tree)
            else:
                extra_known, extra_opaque = [], True
            v, d = classify_known(fixed + extra_known, extra_opaque)
            if v is not None:
                yield (site.lineno, qualname_of(site_scope), v, d + f" (via {scope.name}(...))")
            elif not extra_opaque:
                yield (site.lineno, qualname_of(site_scope), "needs-flag",
                       f"no --no-deptree / safe mode flag, via {scope.name}(...)")
            else:
                yield (site.lineno, qualname_of(site_scope), "unresolved",
                       f"opaque {hole!r} argument passed to {scope.name}(...)")

    class _AllSubprocessCalls(ast.NodeVisitor):
        def __init__(self) -> None:
            self.hits: list[ast.Call] = []

        def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
            if _is_subprocess_call(node):
                self.hits.append(node)
            self.generic_visit(node)

    finder = _AllSubprocessCalls()
    finder.visit(tree)
    for call in finder.hits:
        yield from analyze(call, enclosing_scope(call))


def test_every_subprocess_cli_spawn_on_the_audit_path_passes_no_deptree() -> None:
    offenders = []
    for path in _test_files():
        for lineno, qualname, verdict, detail in _analyze_file(path):
            if verdict not in ("needs-flag", "unresolved"):
                continue
            key = f"{path.relative_to(REPO_ROOT)}:{qualname}"
            if verdict == "needs-flag" and key in _DELIBERATE_DEPTREE_WALK:
                continue
            if verdict == "unresolved" and key in _UNTRACEABLE_ARGV:
                continue
            loc = f"{path.relative_to(REPO_ROOT)}:{lineno} ({qualname})"
            if verdict == "needs-flag":
                offenders.append(
                    f"{loc}: spawns the CLI on the audit path without --no-deptree "
                    f"({detail}). This walks whatever npm tree is actually installed on "
                    "the machine running the suite -- a hermeticity break, not just a "
                    "~2.5s slowdown per invocation (see this module's docstring). Add "
                    f"--no-deptree to the argv, or if the test genuinely needs the real "
                    f"walk, add {key!r} to _DELIBERATE_DEPTREE_WALK with a reason."
                )
            else:
                offenders.append(
                    f"{loc}: {detail} -- this guard cannot prove --no-deptree is (or "
                    "isn't) present. Simplify the argv construction so it can, or, if "
                    f"that's not practical, add {key!r} to _UNTRACEABLE_ARGV stating how "
                    "you verified it by hand and when."
                )
    assert not offenders, (
        f"{len(offenders)} subprocess CLI spawn(s) fail the deptree hermeticity guard "
        "(CLAUDE.md §4 -- tests must be offline and hermetic):\n" + "\n".join(offenders)
    )


def test_deptree_exemption_lists_are_not_stale() -> None:
    """Mirror of test_module_layout's staleness guards: an entry naming a call site
    that no longer exists, or no longer needs the exemption, is dead weight that hides
    the next real regression behind a stale "already handled" -- remove it."""
    needs_flag_keys: set[str] = set()
    unresolved_keys: set[str] = set()
    for path in _test_files():
        for _lineno, qualname, verdict, _detail in _analyze_file(path):
            if verdict in ("needs-flag", "unresolved"):
                key = f"{path.relative_to(REPO_ROOT)}:{qualname}"
                (needs_flag_keys if verdict == "needs-flag" else unresolved_keys).add(key)
    stale_deliberate = [k for k in _DELIBERATE_DEPTREE_WALK if k not in needs_flag_keys]
    stale_untraceable = [k for k in _UNTRACEABLE_ARGV if k not in unresolved_keys]
    assert not stale_deliberate, (
        "_DELIBERATE_DEPTREE_WALK entries no longer matching a real "
        f"missing-flag call site (stale, remove them): {stale_deliberate}"
    )
    assert not stale_untraceable, (
        "_UNTRACEABLE_ARGV entries no longer matching a call site this guard actually "
        f"finds opaque (stale, remove them): {stale_untraceable}"
    )
