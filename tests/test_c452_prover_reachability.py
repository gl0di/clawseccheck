"""A tool that proves absence must be able to reach what it claims to have looked at.

C-452, first slice. The parent epic (E-078) is about a signal computed once and rendered
by one surface out of ten. This is the same shape one level up: a *proving* tool — a gate,
a sweep, a comparison — that covers one of two input families and reports a clean result
without saying which one it walked.

The case that produced this guard: `scripts/fleet_fp_gate.py` imports `vet_plugin` and
calls it in

    engine_output = vet_plugin(...) if vet_kind == "plugin" else vet_skill(...)

where `vet_kind` is a keyword-only parameter defaulting to `"skill"` that **no call site
sets**. So `compare` has never once run the plugin engine, while 70 real plugin roots sit
on the machine it gates. A change confined to the plugin path gets `OK: no new real-fleet
FAIL` — a green that carries no information and does not say so.

The same file's own docstring already describes this exact defect for a different
parameter: leaving `include_deptree` off "left the fleet-FP gate structurally blind to the
newest FAIL-capable check — exactly the surface C-303 exists to guard." Repairing that
instance did not prevent this one, which is the whole argument for a guard instead of a
third repair.

Why static and not by running: the question is not "what did this run do" but "what can
this tool ever do", and an unreachable branch is invisible to any execution. This is the
one place in the epic where reading the code IS the measurement — and the guard is written
against the AST rather than by grep, because `vet_plugin` appears in an import line, a
docstring and a comment in this very file without any of them being a call.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"

#: Engines a proving tool can drive. Reaching one is what "walking an input family" means.
_ENGINES = frozenset({"audit", "vet_skill", "vet_plugin", "vet_mcp", "vet_source"})

#: Known-unreachable branches, each naming the task that owns the repair. An entry here is
#: a recorded decision, never a silencer: `test_no_exemption_outlives_its_reason` fails the
#: build once the gap it describes is gone, so the list cannot rot into a permanent excuse.
#: An empty dict is the goal state.
# Empty on purpose, and worth leaving in place empty: its one entry was removed by the
# repair it named, which is exactly what `test_no_exemption_outlives_its_reason` is for.
# The entry recorded that `build_snapshot`'s `vet_kind` had no CLI path, so `compare`
# never ran the plugin engine; that gap is closed — `build_snapshot` runs both vet
# engines, the parameter is gone, and the snapshot now states which engines produced it.
# The staleness half fired on the very next full run and named the entry, so nothing had
# to be remembered.
_ACCEPTED_UNREACHABLE: dict[tuple[str, str, str], str] = {}


def _prover_scripts():
    """Scripts that import an engine — i.e. tools that make claims about what they saw."""
    out = []
    for path in sorted(SCRIPTS.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported = {
            alias.asname or alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and (node.module or "").split(".")[0] == "clawseccheck"
            for alias in node.names
        }
        if imported & _ENGINES:
            out.append((path, tree, imported & _ENGINES))
    return out


def _kwonly_defaults(fn):
    """`{param: default}` for keyword-only params whose default is a literal."""
    out = {}
    for arg, default in zip(fn.args.kwonlyargs, fn.args.kw_defaults):
        if isinstance(default, ast.Constant):
            out[arg.arg] = default.value
    return out


def _branch_taken_by_default(test, defaults):
    """Which branch a `param == literal` test selects when nobody passes the param.

    Returns "body", "orelse", or None when the test is not a shape this understands. The
    None case matters: an unrecognised condition must NOT be treated as reachable-by-
    default, or the guard silently stops guarding whatever it cannot parse.
    """
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1 and len(test.comparators) == 1):
        return None
    left, op, right = test.left, test.ops[0], test.comparators[0]
    if not (isinstance(left, ast.Name) and isinstance(right, ast.Constant)):
        return None
    if left.id not in defaults:
        return None
    equal = defaults[left.id] == right.value
    if isinstance(op, ast.Eq):
        return "body" if equal else "orelse"
    if isinstance(op, ast.NotEq):
        return "orelse" if equal else "body"
    return None


def _engines_called_in(branch, engines):
    stmts = branch if isinstance(branch, list) else [branch]
    return {
        c.func.id
        for stmt in stmts
        for c in ast.walk(stmt)
        if isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id in engines
    }


def _gated_engine_calls(tree, engines):
    """`(function, param, engine)` for each engine call the DEFAULT parameter value skips.

    Two things this deliberately gets right, both learned by getting them wrong first:

    * It covers the conditional expression as well as the `if` statement. The real defect
      is a ternary, and a guard that only understood `if` would have been silently
      inapplicable to the one case it was written for.
    * It reports only the branch the default does NOT take. The first version reported both,
      so `vet_skill` — which runs on every single invocation, being the default — came back
      as unreachable. A guard that flags a reachable engine is noise, and noise gets deleted.
    """
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = {a.arg for a in fn.args.args} | {a.arg for a in fn.args.kwonlyargs}
        defaults = _kwonly_defaults(fn)
        for node in ast.walk(fn):
            if not isinstance(node, (ast.IfExp, ast.If)):
                continue
            gating = {
                n.id for n in ast.walk(node.test) if isinstance(n, ast.Name) and n.id in params
            }
            if not gating:
                continue
            taken = _branch_taken_by_default(node.test, defaults)
            if taken is None:
                continue
            skipped = node.orelse if taken == "body" else node.body
            for param in sorted(gating):
                for engine in sorted(_engines_called_in(skipped, engines)):
                    out.append((fn.name, param, engine))
    return sorted(set(out))


def _kwargs_passed_to(tree, func_name):
    """Every keyword a call site of *func_name* passes, anywhere in the module."""
    return {
        kw.arg
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == func_name
        for kw in node.keywords
        if kw.arg
    }


def _unreachable_engine_branches():
    """Engine calls no entry point of their own tool can select."""
    out = []
    for path, tree, engines in _prover_scripts():
        for fn_name, param, engine in _gated_engine_calls(tree, engines):
            if param in _kwargs_passed_to(tree, fn_name):
                continue
            out.append((path.name, fn_name, param, engine))
    return out


def test_a_proving_tool_can_reach_every_engine_it_imports():
    """An imported engine that no call site can select is a claim the tool cannot support.

    The failure message names the parameter, because the fix is always one of two things:
    pass it from the CLI, or stop importing the engine and say the family is out of scope.
    """
    wrong = [
        f"scripts/{script}: {fn}() calls {engine}() only when {param!r} is set, and no "
        f"call site sets it — the tool imports an engine it can never run"
        for script, fn, param, engine in _unreachable_engine_branches()
        if (script, fn, engine) not in _ACCEPTED_UNREACHABLE
    ]
    assert not wrong, (
        "a tool that reports absence must walk what it reports on:\n  " + "\n  ".join(wrong)
    )


def test_the_reachability_guard_bites_on_the_defect_it_was_written_for():
    """Guard the guard, on the real shape — a ternary gated by a keyword-only default.

    Pinned as source text rather than by pointing at the live file: once the defect is
    fixed, a control that reads the repo would stop exercising anything and this test
    would pass for the wrong reason ever after.
    """
    blind = ast.parse(
        "from clawseccheck import vet_plugin, vet_skill\n"
        "def build_snapshot(home, *, vet_kind='skill'):\n"
        "    return vet_plugin(home) if vet_kind == 'plugin' else vet_skill(home)\n"
        "def compare(args):\n"
        "    return build_snapshot(args.home)\n"
    )
    gated = _gated_engine_calls(blind, _ENGINES)
    assert ("build_snapshot", "vet_kind", "vet_plugin") in gated, gated
    # and the DEFAULT branch must not be reported: vet_skill runs on every invocation.
    assert ("build_snapshot", "vet_kind", "vet_skill") not in gated, gated
    assert "vet_kind" not in _kwargs_passed_to(blind, "build_snapshot")

    fixed = ast.parse(
        "from clawseccheck import vet_plugin, vet_skill\n"
        "def build_snapshot(home, *, vet_kind='skill'):\n"
        "    return vet_plugin(home) if vet_kind == 'plugin' else vet_skill(home)\n"
        "def compare(args):\n"
        "    return build_snapshot(args.home, vet_kind='plugin')\n"
    )
    assert "vet_kind" in _kwargs_passed_to(fixed, "build_snapshot")


def test_the_guard_reads_an_if_statement_as_well_as_a_ternary():
    """The real defect is a ternary. A guard that only understood `if` would have been
    inapplicable to it, so both forms are pinned — the same guard-the-guard reasoning the
    doc-facts RISK-range test uses."""
    stmt = ast.parse(
        "from clawseccheck import vet_plugin\n"
        "def run(home, *, kind='skill'):\n"
        "    if kind == 'plugin':\n"
        "        return vet_plugin(home)\n"
        "    return None\n"
    )
    assert ("run", "kind", "vet_plugin") in _gated_engine_calls(stmt, _ENGINES)


def test_an_ungated_engine_call_is_not_reported():
    """A tool that always runs its engine has nothing to declare — the guard must stay
    silent, or it becomes noise and gets deleted."""
    plain = ast.parse(
        "from clawseccheck import vet_skill\n"
        "def run(home):\n"
        "    return vet_skill(home)\n"
    )
    assert _gated_engine_calls(plain, _ENGINES) == []


def test_no_exemption_outlives_its_reason():
    """An exemption whose gap is gone must fail, or the list becomes a permanent excuse.

    This is the half that makes the registry honest. Without it, an entry added during one
    repair keeps silencing the guard after the repair lands, and the next regression of the
    same shape is admitted without anyone deciding — which is how the `include_deptree`
    fix failed to prevent the `vet_kind` one.
    """
    live = {(script, fn, engine) for script, fn, _param, engine in _unreachable_engine_branches()}
    stale = sorted(key for key in _ACCEPTED_UNREACHABLE if key not in live)
    assert not stale, (
        "these branches are reachable again — delete the exemption rather than leaving it "
        f"to silence the next one: {stale}"
    )


def test_every_exemption_names_a_task():
    """A reason without an owner is a note, not a decision."""
    missing = sorted(
        key for key, reason in _ACCEPTED_UNREACHABLE.items()
        if "CLAWSECCHECK-" not in reason
    )
    assert not missing, f"exemptions with no task id: {missing}"
