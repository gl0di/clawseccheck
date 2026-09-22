"""CLAWSECCHECK-C-561 -- AST audit: every caller of ``toolgrant.granted`` in ``clawseccheck/``
is safe by construction against the GLOBAL_SCOPE/agent-id collision.

## The bug this hardens against

``toolgrant.GLOBAL_SCOPE`` used to be the plain string ``"global"`` -- and ``"global"`` is
also a legal agent id, so ``granted(cfg, tool, "global")`` for a roster row spelled
``global`` skipped the entry lookup and silently answered the wrong scope's policy (F-186).
The fix added a keyword, ``agent=True``, that a caller HOLDING a roster id had to remember
to pass -- a silent, easy-to-forget obligation with no exception and no log line to catch a
lapse, on a caller surface (four roster call sites as of this writing) that keeps growing.

CLAWSECCHECK-C-561 removed the flag entirely: ``GLOBAL_SCOPE`` is now a private sentinel
TYPE (``toolgrant._GlobalScope``), not a string, so no config value or copy-pasted literal
can ever be `is` it. There is no longer a keyword to forget. But the sentinel makes a NEW
mistake possible -- the mirror image of the old one: a caller who writes the literal string
``"global"`` meaning "the global scope" (its old, pre-sentinel spelling) instead of
importing ``GLOBAL_SCOPE``. That call is not a ``TypeError``; it silently asks for a roster
agent literally named ``global`` instead, which usually resolves the SAME as the true global
scope (no such agent exists), right up until an operator declares one that does.

## Why AST, not grep

A plain text search for ``granted(`` also matches the unrelated local variable named
``granted`` in ``checks/_capability.py`` (a ``set``, never called) and the word's many
prose uses in docstrings and evidence strings, so distinguishing an actual call needs a
parsed tree, not a regex. And a truncated sweep is exactly the failure mode that let the
third F-186 caller go quiet in the first place -- this file walks ``PKG.rglob("*.py")`` (the
whole package tree, no ``head``, no hand-maintained file list) and resolves each file's
OWN import aliases for ``toolgrant``/``granted`` rather than hard-coding one spelling, so a
call written as ``_toolgrant.granted(...)``, ``toolgrant.granted(...)`` or a bare
``granted(...)`` (after ``from .toolgrant import granted``) are all found the same way.

## What "safe by construction" means here

Every call that omits ``scope`` (defaults to the sentinel) or passes a non-literal
expression is safe: whatever string a computed scope evaluates to at runtime, the
sentinel's identity check reads it as a roster lookup, which is the CORRECT behaviour for a
real agent id -- including one that happens to be spelled ``global``. The only static
pattern that is NEVER safe is the literal string ``"global"`` where a scope argument goes;
that must be ``toolgrant.GLOBAL_SCOPE`` instead. A second, narrower check guards against the
OLD collision's own patch reappearing: ``granted()`` no longer has an ``agent`` parameter,
so a stray ``agent=`` keyword at a call site this audit finds is dead weight from a copied
pre-C-561 call, at best, and a ``TypeError`` waiting for that line to execute, at worst.

Offline, reads only the shipped package, stdlib only -- same idiom as
``tests/test_paired_call_sites.py``, including keying findings on the enclosing function
rather than the line number (a line number rots on the next unrelated edit above it).
"""
from __future__ import annotations

import ast
from pathlib import Path

PKG = Path(__file__).resolve().parents[1] / "clawseccheck"

# (rel path, enclosing function) known, as of CLAWSECCHECK-C-561 (2026-09-22), to call
# `granted()` at least once -- a NON-VACUITY / NON-TRUNCATION check on the walk itself, not
# an exhaustive allowlist. A new caller elsewhere needs no entry here and is not flagged by
# it. If the walk ever stops finding a call in one of these homes, either the site moved
# (confirm why, then update this set) or the AST resolution itself broke -- a new import
# shape it does not recognise -- and either way that must not go quiet, the exact way the
# third F-186 caller went quiet under `grep | head`.
_KNOWN_CALLER_HOMES = {
    ("toolpolicy.py", "_write_scopes"),
    ("checks/_capability.py", "_b68_fs_tools_granted"),
    ("checks/_shared.py", "_agent_tools_widenings"),
    ("checks/_shared.py", "_global_also_allow_granted"),
    ("checks/_config.py", "check_gateway_computer_plugin_reach"),
}


def _toolgrant_bindings(tree: ast.Module) -> dict:
    """local name -> "function" (bound directly to ``toolgrant.granted``) or "module" (bound
    to the ``toolgrant`` module itself, so ``<name>.granted(...)`` is a call) -- resolved per
    file from its OWN imports, whatever alias it happens to use."""
    bindings: dict = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                local = alias.asname or alias.name
                if alias.name == "granted" and module.rsplit(".", 1)[-1] == "toolgrant":
                    bindings[local] = "function"
                elif alias.name == "toolgrant":
                    bindings[local] = "module"
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.rsplit(".", 1)[-1] == "toolgrant":
                    bindings[alias.asname or alias.name.split(".")[0]] = "module"
    return bindings


def _scope_arg(call: ast.Call):
    """The AST node for `granted`'s `scope` argument, positional or keyword; `None` when the
    call omits it (defaults to `GLOBAL_SCOPE` -- always safe, not flagged)."""
    for kw in call.keywords:
        if kw.arg == "scope":
            return kw.value
    if len(call.args) >= 3:
        return call.args[2]
    return None


def _calls_in(path: Path) -> list:
    """[(rel, enclosing_fn, lineno, scope_node, call_node), ...] for every call to
    `granted` in one file."""
    rel = str(path.relative_to(PKG))
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
    bindings = _toolgrant_bindings(tree)
    if not bindings:
        return []
    out: list = []
    stack: list = []

    class V(ast.NodeVisitor):
        def visit_FunctionDef(self, node):  # noqa: N802
            stack.append(node.name)
            self.generic_visit(node)
            stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef  # noqa: N815

        def visit_Call(self, node):  # noqa: N802
            func = node.func
            is_granted_call = (
                (isinstance(func, ast.Name) and bindings.get(func.id) == "function")
                or (isinstance(func, ast.Attribute) and func.attr == "granted"
                    and isinstance(func.value, ast.Name)
                    and bindings.get(func.value.id) == "module")
            )
            if is_granted_call:
                out.append((rel, stack[-1] if stack else "<module>", node.lineno,
                            _scope_arg(node), node))
            self.generic_visit(node)

    V().visit(tree)
    return out


def _scan_package() -> list:
    calls: list = []
    for path in sorted(PKG.rglob("*.py")):
        calls += _calls_in(path)
    return calls


# --------------------------------------------------------------------- the live guards

def test_the_walk_is_not_vacuous_or_truncated():
    """Non-vacuity on the sweep itself, and the specific non-truncation check: every known
    caller home is still found. A version of this file that silently walked zero files, or
    stopped resolving one file's import alias, must fail here rather than pass every other
    test by finding nothing to check."""
    py_files = sorted(PKG.rglob("*.py"))
    assert len(py_files) >= 40, f"only {len(py_files)} .py files under {PKG} -- wrong path?"

    calls = _scan_package()
    assert len(calls) >= 7, calls  # 7 real call sites, grounded 2026-09-22 (see module docstring)

    found_homes = {(rel, fn) for rel, fn, _ln, _scope, _call in calls}
    missing = _KNOWN_CALLER_HOMES - found_homes
    assert not missing, (
        f"no `granted()` call found in {missing} -- either the call moved (update "
        f"_KNOWN_CALLER_HOMES after confirming why) or the AST resolution broke"
    )


def test_no_caller_passes_the_literal_string_global_as_scope():
    """The one way left to reintroduce a collision post-C-561: a scope argument that is the
    LITERAL string "global" is always wrong now -- it must be `toolgrant.GLOBAL_SCOPE` (the
    real global scope) or an expression holding an actual roster id. An expression is never
    flagged: whatever it evaluates to, the sentinel's identity check reads it as a roster
    lookup, which is correct even for an id that happens to be "global"."""
    offenders = []
    for rel, fn, lineno, scope, _call in _scan_package():
        if isinstance(scope, ast.Constant) and scope.value == "global":
            offenders.append(f"{rel}:{lineno} in {fn}()")
    assert not offenders, (
        "call(s) pass the literal \"global\" as scope -- use toolgrant.GLOBAL_SCOPE "
        "instead:\n  " + "\n  ".join(offenders)
    )


def test_no_caller_passes_the_removed_agent_keyword():
    """`granted()` no longer has an `agent` parameter -- C-561 removed it along with the
    collision it existed to patch over. A stray `agent=` at a call site is either a leftover
    from a pre-C-561 copy/paste or a straight `TypeError` waiting for that line to run;
    either way it must not exist, whether or not the fixture corpus ever exercises it."""
    offenders = []
    for rel, fn, lineno, _scope, call in _scan_package():
        if any(kw.arg == "agent" for kw in call.keywords):
            offenders.append(f"{rel}:{lineno} in {fn}()")
    assert not offenders, "stray agent= keyword at:\n  " + "\n  ".join(offenders)


# --------------------------------------------------------------------- the guard on itself

def test_it_catches_the_shape_of_the_defect_it_guards_against():
    """A guard that cannot be shown to catch the defect it is written for is decoration.
    Reconstructs the pre-C-561 collision shape: a call spelling the global scope out as the
    literal string "global" instead of importing the sentinel."""
    before = (
        "from .. import toolgrant as _toolgrant\n"
        "def _some_future_check(cfg):\n"
        "    return _toolgrant.granted(cfg, 'read', 'global')\n"
    )
    tree = ast.parse(before, filename="checks/_hypothetical.py")
    bindings = _toolgrant_bindings(tree)
    assert bindings == {"_toolgrant": "module"}
    hits = []

    class V(ast.NodeVisitor):
        def visit_Call(self, node):  # noqa: N802
            func = node.func
            if (isinstance(func, ast.Attribute) and func.attr == "granted"
                    and isinstance(func.value, ast.Name)
                    and bindings.get(func.value.id) == "module"):
                hits.append(_scope_arg(node))
            self.generic_visit(node)

    V().visit(tree)
    assert len(hits) == 1
    assert isinstance(hits[0], ast.Constant) and hits[0].value == "global"


def test_it_stays_quiet_on_the_fixed_form():
    """The other direction: the real, current call sites (the sentinel, a bare id variable,
    or no scope at all) must never be flagged."""
    after = (
        "from .. import toolgrant as _toolgrant\n"
        "def _some_future_check(cfg, entry_id):\n"
        "    a = _toolgrant.granted(cfg, 'read', _toolgrant.GLOBAL_SCOPE)\n"
        "    b = _toolgrant.granted(cfg, 'read', entry_id)\n"
        "    c = _toolgrant.granted(cfg, 'read')\n"
        "    return a, b, c\n"
    )
    tree = ast.parse(after, filename="checks/_hypothetical.py")
    bindings = _toolgrant_bindings(tree)
    scopes = []

    class V(ast.NodeVisitor):
        def visit_Call(self, node):  # noqa: N802
            func = node.func
            if (isinstance(func, ast.Attribute) and func.attr == "granted"
                    and isinstance(func.value, ast.Name)
                    and bindings.get(func.value.id) == "module"):
                scopes.append(_scope_arg(node))
            self.generic_visit(node)

    V().visit(tree)
    assert len(scopes) == 3
    assert not any(isinstance(s, ast.Constant) and s.value == "global" for s in scopes)


def test_a_bare_imported_granted_name_is_also_recognised():
    """`toolpolicy.py`'s own shape: `from .toolgrant import GLOBAL_SCOPE, granted`, then a
    bare `granted(...)` call -- must resolve the same as the `_toolgrant.granted(...)` shape,
    or this audit would silently miss that whole file."""
    src = (
        "from .toolgrant import GLOBAL_SCOPE, granted\n"
        "def _write_scopes(cfg, tool):\n"
        "    return granted(cfg, tool, 'global')\n"
    )
    tree = ast.parse(src, filename="toolpolicy.py")
    bindings = _toolgrant_bindings(tree)
    assert bindings.get("granted") == "function"
