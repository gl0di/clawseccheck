"""Shared AST engine behind the subprocess-CLI hermeticity guards.

Factored out of ``tests/test_subprocess_deptree_hermeticity.py`` (CLAWSECCHECK-B-881)
so a SECOND guard -- ``tests/test_subprocess_host_hermeticity.py``, checking
``--no-host`` instead of ``--no-deptree`` -- can reuse the exact same argv-resolution
machinery rather than re-implementing (and re-diverging from) it. Everything in this
module is completely flag-agnostic: it only answers "what string literals can this
guard prove are in this subprocess call's argv, and is any part of that argv opaque
(unresolvable)?". Deciding what a resolved argv MEANS (which flag must be present,
which mode flags bypass the check entirely) is the caller's job -- see
``classify_known()``'s ``required_flag``/``safe_mode_flags`` parameters below, and each
guard module's own module-level constants.

See ``test_subprocess_deptree_hermeticity.py``'s module docstring for the full
rationale, the shapes this deliberately leaves UNRESOLVED, and the two real bugs this
engine's resolution logic already fixed (module-global spreads, opacity propagation) --
none of that is repeated here since it applies identically to every caller.
"""
from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = REPO_ROOT / "tests"

_SUBPROCESS_FUNCS = {"run", "Popen", "check_output", "check_call", "call"}


def is_subprocess_call(node: ast.Call) -> bool:
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
    via its assignment(s) plus any `.append(...)`/`.extend([...])`/`+= [...]` on it, as
    (known, opaque) -- opaque propagated from whatever the assignment's OWN value
    resolves to. Returns None if *name* is never bound in *scope* at all."""
    known: list[str] = []
    opaque = False
    saw = False
    for n in ast.walk(scope):
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets):
            saw = True
            k, o = partial_resolve(n.value, scope, module_tree)
            known.extend(k)
            opaque = opaque or o
        elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name) and n.target.id == name:
            saw = True
            k, o = partial_resolve(n.value, scope, module_tree)
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
                k, o = partial_resolve(n.args[0], scope, module_tree)
                known.extend(k)
                opaque = opaque or o
    return (known, opaque) if saw else None


class _ModuleScopeVisitor(ast.NodeVisitor):
    """Collects every Assign / AugAssign / append|extend-Call whose nearest enclosing
    scope is the module itself -- descends into ordinary module-level control flow
    (if/for/while/try/with), never into a nested function/class/lambda body."""
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
    """Same contract as _resolve_local, but for a name bound at true MODULE scope."""
    v = _ModuleScopeVisitor()
    for stmt in module_tree.body:
        v.visit(stmt)
    known: list[str] = []
    opaque = False
    saw = False
    for n in v.hits:
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets):
            saw = True
            k, o = partial_resolve(n.value, module_tree, module_tree)
            known.extend(k)
            opaque = opaque or o
        elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name) and n.target.id == name:
            saw = True
            k, o = partial_resolve(n.value, module_tree, module_tree)
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
                k, o = partial_resolve(n.args[0], module_tree, module_tree)
                known.extend(k)
                opaque = opaque or o
    return (known, opaque) if saw else None


def partial_resolve(node: ast.expr, scope: ast.AST,
                     module_tree: ast.Module) -> tuple[list[str], bool]:
    """(known, opaque). `known` is every string constant reachable from *node*.
    `opaque=True` means some `*spread` could not be traced at all, so `known` may be
    missing flags a human should check. See test_subprocess_deptree_hermeticity.py's
    module docstring for the full list of shapes deliberately left opaque."""
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
        lk, lo = partial_resolve(node.left, scope, module_tree)
        rk, ro = partial_resolve(node.right, scope, module_tree)
        return lk + rk, lo or ro
    if not isinstance(node, (ast.List, ast.Tuple)):
        return [], True
    known: list[str] = []
    opaque = False
    for elt in node.elts:
        if isinstance(elt, ast.Starred):
            k, o = partial_resolve(elt.value, scope, module_tree)
            known.extend(k)
            opaque = opaque or o
            continue
        s = _str_const(elt)
        if s is not None:
            known.append(s)
    return known, opaque


def _fixed_literals(list_node: ast.expr) -> list[str]:
    """String literals directly in a List/Tuple, ignoring Starred elements entirely."""
    if not isinstance(list_node, (ast.List, ast.Tuple)):
        return []
    return [s for elt in list_node.elts if not isinstance(elt, ast.Starred)
            for s in [_str_const(elt)] if s is not None]


def _external_hole(list_node: ast.expr, fn: ast.FunctionDef | ast.AsyncFunctionDef,
                    module_tree: ast.Module) -> str | None:
    """If *list_node* has exactly one `Starred(Name(x))` where x is a parameter of *fn*
    with no LOCAL binding inside fn, return x. None for zero or ambiguous multiple
    holes -- this guard does not guess."""
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
    ('missing', None) if the call doesn't actually supply it."""
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
            k, o = partial_resolve(e.value, scope, module_tree)
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


def classify_known(known: list[str], opaque: bool, required_flag: str,
                    safe_mode_flags: frozenset[str]):
    """(verdict, detail) from a literal set that may or may not be the WHOLE argv.
    verdict is 'safe' (a -c script, a non-clawseccheck -m spawn, or a mode flag in
    *safe_mode_flags* that never reaches build_context()/audit()), 'ok'
    (*required_flag* present), or None (undetermined from `known` alone -- the caller
    decides based on whether anything was left opaque).

    *opaque* must be True whenever some part of the real argv could not be traced. See
    test_subprocess_deptree_hermeticity.py's module docstring for why the "no -m at
    all" absence check below must defer under opacity rather than concluding "safe" --
    that was a real bug, fixed once here for every caller."""
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
    if required_flag in known:
        return "ok", f"{required_flag} present"
    hit = safe_mode_flags.intersection(known)
    if hit:
        return "safe", f"mode flag {sorted(hit)} never reaches build_context()/audit()"
    return None, None


def list_test_files(exclude_names: frozenset[str]) -> list[Path]:
    """Every tests/test_*.py file except *exclude_names* -- named without a `test_`
    prefix so importing it with `from _subprocess_argv import list_test_files` never
    gets collected as a test itself (pytest collects any `test_*` name a test module
    imports into its own namespace, not just ones it defines)."""
    return sorted(p for p in TESTS_DIR.glob("test_*.py") if p.name not in exclude_names)


def analyze_file(path: Path, required_flag: str, safe_mode_flags: frozenset[str]):
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

    def classify(known, opaque):
        return classify_known(known, opaque, required_flag, safe_mode_flags)

    def analyze(call: ast.Call, scope):
        if not call.args:
            yield (call.lineno, qualname_of(scope), "unresolved", "no positional argv arg")
            return
        first = call.args[0]
        known, opaque = partial_resolve(first, scope, tree)
        verdict, detail = classify(known, opaque)
        if verdict is not None:
            yield (call.lineno, qualname_of(scope), verdict, detail)
            return
        if not opaque:
            yield (call.lineno, qualname_of(scope), "needs-flag",
                   f"no {required_flag} / safe mode flag found in the (fully resolved) argv")
            return
        hole = _external_hole(first, scope, tree) if isinstance(
            scope, (ast.FunctionDef, ast.AsyncFunctionDef)) else None
        if hole is None:
            yield (call.lineno, qualname_of(scope), "unresolved",
                   "argv construction this guard cannot trace")
            return
        fixed = _fixed_literals(first)
        fv, fd = classify(fixed, True)  # the hole itself is, by construction, unresolved here
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
                extra_known, extra_opaque = partial_resolve(payload, site_scope, tree)
            else:
                extra_known, extra_opaque = [], True
            v, d = classify(fixed + extra_known, extra_opaque)
            if v is not None:
                yield (site.lineno, qualname_of(site_scope), v, d + f" (via {scope.name}(...))")
            elif not extra_opaque:
                yield (site.lineno, qualname_of(site_scope), "needs-flag",
                       f"no {required_flag} / safe mode flag, via {scope.name}(...)")
            else:
                yield (site.lineno, qualname_of(site_scope), "unresolved",
                       f"opaque {hole!r} argument passed to {scope.name}(...)")

    class _AllSubprocessCalls(ast.NodeVisitor):
        def __init__(self) -> None:
            self.hits: list[ast.Call] = []

        def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
            if is_subprocess_call(node):
                self.hits.append(node)
            self.generic_visit(node)

    finder = _AllSubprocessCalls()
    finder.visit(tree)
    for call in finder.hits:
        yield from analyze(call, enclosing_scope(call))
