"""B-918 — `_value_is_tainted_source` recursed on itself with no depth bound.

`_value_is_tainted_source` (skillast.py) used to recurse on itself -- a Call's own
args/keywords/func in one branch, every other node's full child set in the other --
with no depth counter at all. A pathologically left-nested expression (a long
`a / b / c / ...` BinOp chain, a padded `.joinpath(...).joinpath(...)....` method
chain) drove that recursion straight into an uncaught `RecursionError`.

Independently reproduced on this box (Python 3.12.3, default `sys.getrecursionlimit()`
== 1000, no pytest/ambient-stack padding beyond the interpreter's own bare top level):
the largest non-crashing chain length was 995 terms for the bare `/`-chain shape and
496 for the `.joinpath()` chain (each `.joinpath()` call costs two AST levels -- a
Call wrapping an Attribute -- so it crashes at roughly half the term count of an
equal-depth BinOp chain); both numbers match the numbers this was filed with. Also
confirmed the crash was not contained to the helper: `analyze_python`'s own docstring
promises "Never raises, never executes", but its outer `try`/`except` only wraps the
setup phase (`ast.parse` through building `_RefResolver`), not the later per-node
loops that actually call this function, so the same `RecursionError` propagated
straight out of `analyze_python` on unpatched code -- a genuine contract break, not
merely an internal-helper crash. `test_analyze_python_never_raises_on_pathological_
chain_reaching_exec_sink` pins that end to end.

A first fix bounded the recursion with an explicit depth counter (mirroring
`_FOLD_MAX_DEPTH`), giving up past the cap with `True` ("assume tainted") rather than
crashing. That default turned out to be unsound in the OTHER direction on further
review: this function is also reached on entirely ordinary code that legitimately
chains well past any reasonable depth cap -- a hardcoded character-folding table built
as `s.replace(a, b).replace(c, d)....` routinely runs to 100+ `.replace()` calls (well
over 200 AST levels, by the same two-levels-per-call arithmetic as `.joinpath()`) on a
value with NO external input whatsoever. A depth cap giving up as "tainted" there would
manufacture a false TT5_CMD_INJECTION conviction on a plain constant reaching an
exec-family sink -- trading the crash for a real, reachable false-positive FAIL.
`test_long_benign_replace_chain_is_not_tainted` and its `analyze_python`-level
end-to-end twin pin that this shape is clean.

So the final fix drops the depth cap entirely and rewrites the function as a plain
iterative worklist walk -- the same idiom `_has_uncovered_inline_source` (this module)
already uses for nearly the same source vocabulary (`os.getenv`/`environ.get`,
`_is_external_source_call`, `_is_tool_result_call`). Nothing in the original recursive
version depended on call depth, so an explicit Python list standing in for the call
stack is exactly equivalent node-for-node: every reachable node is still visited
exactly once, with the same checks applied, but held in heap memory instead of the
interpreter's ~1000-frame C recursion limit. There is consequently no depth at which
this can crash, and no fail-safe "give up" default to pick at all -- every node this
function is ever asked about gets a real, exact answer, in either direction. See
`test_deep_chain_with_taint_buried_at_the_far_end_is_still_caught` for the concrete
precision payoff: an unbounded exact walk finds real taint arbitrarily deep, which a
depth-capped version (in either fail-safe direction) fundamentally cannot promise.

Offline, read-only, stdlib only -- builds inert AST nodes, never executes anything.
"""
from __future__ import annotations

import ast

from clawseccheck.skillast import _value_is_tainted_source, analyze_python


def _slash_chain(n: int) -> ast.AST:
    """`a0 / a1 / a2 / ... / a{n-1}` as a left-associative BinOp tree, n terms."""
    src = "x = " + " / ".join(f"a{i}" for i in range(n)) + "\n"
    return ast.parse(src).body[0].value


def _joinpath_chain(n: int) -> ast.AST:
    """`p.joinpath("a0").joinpath("a1")....joinpath("a{n-1}")`, n calls."""
    src = "x = p" + "".join(f'.joinpath("a{i}")' for i in range(n)) + "\n"
    return ast.parse(src).body[0].value


def _replace_chain(n: int) -> ast.AST:
    """`"seed".replace("a0", "b0").replace("a1", "b1")....`, n calls -- the benign
    character-folding-table shape this fix must not over-taint."""
    calls = "".join(f'.replace("a{i}", "b{i}")' for i in range(n))
    return ast.parse(f'x = "seed"{calls}\n').body[0].value


# --------------------------------------------------------------------------- #
# Before/after: chains long enough to have crashed unpatched code must now    #
# return a correct, deterministic result instead of raising.                  #
# --------------------------------------------------------------------------- #


def test_deep_slash_chain_does_not_crash_and_is_genuinely_not_tainted():
    node = _slash_chain(2000)  # well past the measured 995-term crash threshold
    assert _value_is_tainted_source(node, set()) is False


def test_deep_joinpath_chain_does_not_crash_and_is_genuinely_not_tainted():
    node = _joinpath_chain(2000)  # well past the measured 496-term crash threshold
    assert _value_is_tainted_source(node, set()) is False


def test_analyze_python_never_raises_on_pathological_chain_reaching_exec_sink():
    """The end-to-end contract `analyze_python`'s own docstring promises ("Never
    raises, never executes") -- confirmed broken on unpatched code (this exact source
    raises `RecursionError` straight out of `analyze_python`, not just the helper)."""
    names = " / ".join(f"a{i}" for i in range(1500))
    src = f"import os\nexec({names})\n"
    findings = analyze_python(src, "x.py")  # must not raise
    assert isinstance(findings, list)


# --------------------------------------------------------------------------- #
# The false-positive this fix specifically avoids: an unbounded, EXACT walk   #
# never has to "give up" and guess, in either direction.                      #
# --------------------------------------------------------------------------- #


def test_long_benign_replace_chain_is_not_tainted():
    """A hardcoded character-folding/transliteration table -- a real shape, not a
    contrived one -- chained deep enough to exceed any reasonable depth cap, but
    carrying no external input anywhere. Must resolve to a plain, exact `False`."""
    for n in (50, 113, 133, 200, 500):
        node = _replace_chain(n)
        assert _value_is_tainted_source(node, set()) is False, n


def test_long_benign_replace_chain_into_a_shell_sink_does_not_convict():
    """The `analyze_python`-level payoff: the same benign chain, reaching an actual
    shell sink, must not produce a false TT5_CMD_INJECTION crit."""
    calls = "".join(f'.replace("a{i}", "b{i}")' for i in range(133))
    src = f'import subprocess\nx = "seed"{calls}\nsubprocess.run(f"echo {{x}}", shell=True)\n'
    findings = analyze_python(src, "y.py")
    assert not any(f.severity == "crit" for f in findings), findings


def test_deep_chain_with_taint_buried_at_the_far_end_is_still_caught():
    """The precision an unbounded exact walk buys over any depth-capped
    approximation: a single genuine external source at the deepest point of an
    otherwise huge chain is still found, no matter how far down it sits."""
    names = [f"a{i}" for i in range(1999)] + ['os.getenv("SECRET")']
    node = ast.parse("x = " + " / ".join(names) + "\n").body[0].value
    assert _value_is_tainted_source(node, set()) is True


def test_deep_chain_genuinely_clean_throughout_is_not_tainted():
    node = _slash_chain(2000)
    assert _value_is_tainted_source(node, set()) is False


# --------------------------------------------------------------------------- #
# Regression pins: ordinary, non-pathological depths are completely unaffected.#
# --------------------------------------------------------------------------- #


def test_shallow_chain_with_no_taint_is_not_tainted():
    node = _slash_chain(3)
    assert _value_is_tainted_source(node, set()) is False


def test_shallow_chain_with_a_genuinely_tainted_name_is_tainted():
    node = _slash_chain(3)
    assert _value_is_tainted_source(node, {"a1"}) is True


def test_os_getenv_is_still_recognized_as_a_source():
    node = ast.parse('os.getenv("X")\n').body[0].value
    assert _value_is_tainted_source(node, set()) is True


def test_plain_literal_is_not_tainted():
    node = ast.parse('"just a literal"\n').body[0].value
    assert _value_is_tainted_source(node, set()) is False
