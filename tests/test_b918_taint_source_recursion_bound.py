"""B-918 — `_value_is_tainted_source` recursed on itself with no depth bound.

`_value_is_tainted_source` (skillast.py) walks a Call's own args/keywords/func, and
falls through to every OTHER node's full child set otherwise, recursing on both
branches with no depth counter at all. Most real Python expressions are shallow
enough this never mattered, but a pathologically left-nested expression -- a long
`a / b / c / ...` BinOp chain, or a padded `.joinpath(...).joinpath(...)....` method
chain -- drives its own recursion straight into an uncaught `RecursionError`.

Independently reproduced on this box (Python 3.12.3, default `sys.getrecursionlimit()`
== 1000, no pytest/ambient-stack padding beyond the interpreter's own bare top level):
the largest non-crashing chain length was 995 terms for the bare `/`-chain shape and
496 for the `.joinpath()` chain (each `.joinpath()` call costs two AST levels -- a
Call wrapping an Attribute -- so it crashes at roughly half the term count of an
equal-depth BinOp chain); both numbers match the ticket's own cited approximations.
The exact crash threshold is NOT a fixed constant of this function -- it is
`sys.getrecursionlimit()` minus however much ambient stack the caller chain (pytest,
an outer `ast.walk` pass, a nested analysis helper) has already used by the time
`_value_is_tainted_source` is reached, so a real caller several frames deep crashes at
a noticeably SMALLER N than a bare top-level call does (confirmed directly: the same
995-term chain that survives at bare top level already crashes when called from one
extra layer of enclosing function scope). This is exactly why the fix below is an
absolute depth cap threaded explicitly through the recursion, not a relative "add N
more frames" budget -- it must hold regardless of how deep the caller already is.

Also confirmed directly: this is not merely an internal-helper crash. `analyze_python`
itself, whose own docstring promises "Never raises, never executes", propagates the
same uncaught `RecursionError` on unpatched code when the pathological chain is fed to
it as real source text reaching an exec sink -- its outer `try`/`except (SyntaxError,
ValueError, RecursionError, MemoryError, OverflowError)` covers only the setup phase
(`ast.parse` through building `_RefResolver`), not the later per-node analysis loops
where `_value_is_tainted_source` actually runs. `test_analyze_python_never_raises_on_
pathological_chain_reaching_exec_sink` below pins that contract end to end.

Fix mirrors `_FOLD_MAX_DEPTH`'s explicit depth-threading pattern (see that constant's
own comment on `_fold_seg`/`_fold_fs_path`): an explicit `depth` parameter, defaulted
to 0 so every caller OUTSIDE this recursive family is unaffected, incremented on each
of the two recursive calls, checked with `if depth > _TAINT_SOURCE_MAX_DEPTH`. Never a
`try`/`except RecursionError` around a caller -- that shape is the exact defect
CLAWSECCHECK-B-830 round 2 introduced and round 3 removed (see `_FOLD_MAX_DEPTH`'s own
comment): it swallows the error at whatever unpredictable partial state the real C
stack happened to overflow at, leaving the value's taint status unproven rather than a
clean, deterministic bound.

Deliberately the OPPOSITE give-up value from the fold family: `_fold_seg` gives up by
returning `None` ("unresolved"), safe there because a fold only ever backs a literal
PATH-STRING match -- giving up can only ever suppress a match, never manufacture one.
`_value_is_tainted_source` instead feeds a taint-propagation OR-disjunction that GROWS
a tainted-name set consulted by FAIL-capable sink checks (TT5/TT4/SSRF, the exec-sink
exemption gates) -- there, degrading to `False` ("not tainted") on give-up would be the
unsound direction the ticket warns about, so past the cap this returns `True` ("assume
tainted") instead, which can only ever WIDEN what downstream sink checks scrutinize,
never manufacture a false exemption from a genuine conviction. See `test_analyze_
python_pathological_chain_into_exec_sink_still_convicts` below for the concrete effect
of that choice: the exact same pathological input that used to crash the scanner now
gets flagged as a crit finding instead of silently passing through unexamined.

Offline, read-only, stdlib only -- builds inert AST nodes, never executes anything.
"""
from __future__ import annotations

import ast

import pytest

from clawseccheck.skillast import (
    _TAINT_SOURCE_MAX_DEPTH,
    _value_is_tainted_source,
    analyze_python,
)


def _slash_chain(n: int) -> ast.AST:
    """`a0 / a1 / a2 / ... / a{n-1}` as a left-associative BinOp tree, n terms."""
    src = "x = " + " / ".join(f"a{i}" for i in range(n)) + "\n"
    return ast.parse(src).body[0].value


def _joinpath_chain(n: int) -> ast.AST:
    """`p.joinpath("a0").joinpath("a1")....joinpath("a{n-1}")`, n calls."""
    src = "x = p" + "".join(f'.joinpath("a{i}")' for i in range(n)) + "\n"
    return ast.parse(src).body[0].value


# --------------------------------------------------------------------------- #
# Before/after: a chain long enough to have crashed unpatched code must now   #
# return a deterministic result instead of raising.                          #
# --------------------------------------------------------------------------- #


def test_deep_slash_chain_does_not_crash_and_is_assumed_tainted():
    node = _slash_chain(2000)  # well past both the 995 measured threshold and the cap
    assert _value_is_tainted_source(node, set()) is True


def test_deep_joinpath_chain_does_not_crash_and_is_assumed_tainted():
    node = _joinpath_chain(2000)  # well past both the 496 measured threshold and the cap
    assert _value_is_tainted_source(node, set()) is True


def test_analyze_python_never_raises_on_pathological_chain_reaching_exec_sink():
    """The end-to-end contract `analyze_python`'s own docstring promises ("Never
    raises, never executes") -- confirmed broken on unpatched code (this exact source
    raises `RecursionError` straight out of `analyze_python`, not just the helper)."""
    names = " / ".join(f"a{i}" for i in range(1500))
    src = f"import os\nexec({names})\n"
    findings = analyze_python(src, "x.py")  # must not raise
    assert isinstance(findings, list)


def test_analyze_python_pathological_chain_into_exec_sink_still_convicts():
    """The security-relevant payoff of the "assume tainted" give-up default: the same
    pathological input that used to crash the scanner outright is now examined and
    flagged, not silently waved through as clean."""
    names = " / ".join(f"a{i}" for i in range(1500))
    src = f"import os\nexec({names})\n"
    findings = analyze_python(src, "x.py")
    assert any(f.rule == "TT5_CMD_INJECTION" and f.severity == "crit" for f in findings)


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


def test_chain_comfortably_under_the_depth_cap_with_no_taint_is_still_not_tainted():
    """Proves the cap itself is not so tight that ordinary, non-pathological (if
    unusually long) real code gets over-approximated -- only genuinely pathological
    depths past `_TAINT_SOURCE_MAX_DEPTH` fall back to the give-up default."""
    node = _slash_chain(_TAINT_SOURCE_MAX_DEPTH - 20)
    assert _value_is_tainted_source(node, set()) is False


@pytest.mark.parametrize("n", [_TAINT_SOURCE_MAX_DEPTH + 50, _TAINT_SOURCE_MAX_DEPTH + 500])
def test_chain_past_the_depth_cap_gives_up_tainted_regardless_of_content(n):
    """Once past the cap, the give-up default fires even though nothing in the chain
    is actually externally sourced -- the documented, deliberate over-approximation."""
    node = _slash_chain(n)
    assert _value_is_tainted_source(node, set()) is True
