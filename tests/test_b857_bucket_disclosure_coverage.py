"""CLAWSECCHECK-B-857 item 1 — the structural test the B-745 review found missing.

``check_installed_skills`` is a first-match-wins cascade over ``_signal_buckets``
(``_b13_verdict``'s own C-256 census comment, ``checks/_vet.py``). A bucket registered
into that dict only at ITS OWN point in the cascade — after several earlier
``if <bucket>: return _b13_verdict(...)`` arms have already had their chance to return —
is invisible to every one of those earlier winners: the key simply is not in the dict yet
when they call ``_b13_verdict``. B-746 (``path_traversal``) and B-745 (``_stowaway_note``,
carved out of ``warnings``) each fixed one instance of this by registering the fact
EAGERLY, before the cascade begins.

The B-745 review found three siblings — ``skill_limit_hits``, the rest of ``warnings``,
and ``warns_squat`` — left "unhandled and undeclared": still registered late, with no
test enforcing that this is a *decision* rather than an oversight, and no written reason.
``_B13_WINNER_ONLY_BUCKETS`` (``checks/_vet.py``, just above ``check_installed_skills``)
is that decision, made explicit; this file is the structural test the review asked for.

It parses the real cascade source (the same technique ``test_b746_cascade_rank_order.py``
already uses for cascade ORDER) rather than hand-listing bucket names, so a FUTURE late
registration — one nobody has thought about yet — fails the build here instead of
silently reproducing this exact gap a second time.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import ast
from pathlib import Path

from clawseccheck.checks._vet import _B13_WINNER_ONLY_BUCKETS

REPO = Path(__file__).resolve().parent.parent
_VET_SRC = REPO / "clawseccheck" / "checks" / "_vet.py"


def _tree():
    return ast.parse(_VET_SRC.read_text(encoding="utf-8"), filename=str(_VET_SRC))


def _check_installed_skills_fn():
    return next(
        n for n in ast.walk(_tree())
        if isinstance(n, ast.FunctionDef) and n.name == "check_installed_skills"
    )


def _is_b13_verdict_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Return)
        and isinstance(node.value, ast.Call)
        and (getattr(node.value.func, "id", None) or getattr(node.value.func, "attr", None))
        == "_b13_verdict"
    )


def _first_cascade_lineno(fn: ast.FunctionDef) -> int:
    """The line of the FIRST ``if <bucket>: ... return _b13_verdict(...)`` arm.

    Every ``_signal_buckets[...] = ...`` assignment at or after this line executes only
    when every earlier arm's condition was false — i.e. it is reachable, but its OWN
    key is not yet in the dict when an earlier arm wins.
    """
    for stmt in fn.body:
        if isinstance(stmt, ast.If) and any(_is_b13_verdict_call(n) for n in ast.walk(stmt)):
            return stmt.lineno
    raise AssertionError(
        "no `if <bucket>: return _b13_verdict(...)` arm found in check_installed_skills — "
        "has the cascade been restructured? This test needs updating to match."
    )


def _dict_literal_keys(fn: ast.FunctionDef) -> set:
    """String keys of the one `` _signal_buckets: dict[str, list] = {...}`` literal."""
    keys: set = set()
    for stmt in fn.body:
        if (
            isinstance(stmt, ast.AnnAssign)
            and isinstance(stmt.target, ast.Name)
            and stmt.target.id == "_signal_buckets"
            and isinstance(stmt.value, ast.Dict)
        ):
            for k in stmt.value.keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    keys.add(k.value)
            return keys
    raise AssertionError("no `_signal_buckets: dict[str, list] = {...}` literal found")


def _subscript_registrations(fn: ast.FunctionDef) -> list:
    """``[(key, lineno), ...]`` for every top-level ``_signal_buckets["key"] = ...``
    assignment OUTSIDE the initial dict literal, in source order."""
    out = []
    for stmt in fn.body:
        if not (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1):
            continue
        target = stmt.targets[0]
        if not (
            isinstance(target, ast.Subscript)
            and isinstance(target.value, ast.Name)
            and target.value.id == "_signal_buckets"
        ):
            continue
        sl = target.slice
        key_node = sl.value if isinstance(sl, getattr(ast, "Index", ())) else sl
        if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
            out.append((key_node.value, stmt.lineno))
    return out


def _early_and_late():
    """Return (early_keys, late_registrations) for the real, current cascade source."""
    fn = _check_installed_skills_fn()
    first_cascade = _first_cascade_lineno(fn)
    dict_keys = _dict_literal_keys(fn)
    subscripts = _subscript_registrations(fn)
    early = dict_keys | {k for k, ln in subscripts if ln < first_cascade}
    late = [(k, ln) for k, ln in subscripts if ln >= first_cascade]
    return early, late


# ---------------------------------------------------------------------------
# The structural contract itself
# ---------------------------------------------------------------------------

def test_every_late_registered_bucket_is_declared_winner_only():
    """The DoD line, made mechanical: every fact the cascade can disclose is reachable
    regardless of which arm returns (an "early" registration), OR is explicitly
    registered as winner-only with a reason (a key in ``_B13_WINNER_ONLY_BUCKETS``).

    Revert the fix (empty or shrink ``_B13_WINNER_ONLY_BUCKETS``) and this fails — the
    three real late registrations (`skill_limit_hits`/`warnings`/`warns_squat`) are
    always found from source, independent of the registry under test.
    """
    _early, late = _early_and_late()
    undeclared = [key for key, _lineno in late if key not in _B13_WINNER_ONLY_BUCKETS]
    assert undeclared == [], (
        "late-registered _signal_buckets key(s) with no explicit winner-only "
        f"declaration: {undeclared!r}. Either move the registration before the first "
        "cascade `if` (like path_traversal/B-746), or add an entry with a reason to "
        "_B13_WINNER_ONLY_BUCKETS in checks/_vet.py."
    )


def test_winner_only_declarations_are_not_stale():
    """Every declared key must correspond to a bucket that is REALLY late-registered
    today — a leftover entry for a bucket since moved eager would silently stop
    meaning anything and nobody would notice."""
    _early, late = _early_and_late()
    real_late_keys = {key for key, _lineno in late}
    stale = set(_B13_WINNER_ONLY_BUCKETS) - real_late_keys
    assert stale == set(), (
        f"_B13_WINNER_ONLY_BUCKETS names bucket(s) no longer late-registered: "
        f"{stale!r} — remove the stale entry (the bucket is presumably eager now, "
        "which is strictly better and needs no declaration)."
    )


def test_winner_only_reasons_are_substantive():
    """A one-word or empty 'reason' would satisfy the letter of the contract while
    defeating its point — this is meant to be read, at review time, by a human."""
    for key, reason in _B13_WINNER_ONLY_BUCKETS.items():
        assert isinstance(reason, str) and len(reason.strip()) >= 40, (
            f"_B13_WINNER_ONLY_BUCKETS[{key!r}] reason is too thin to be a real "
            f"justification: {reason!r}"
        )


def test_current_late_registrations_are_exactly_the_known_three():
    """Regression pin for the exact class the B-745 review named. A NEW late bucket
    is still caught by the general test above (it would just need a declaration); this
    additionally pins that the three known ones have not silently changed shape."""
    _early, late = _early_and_late()
    assert {key for key, _lineno in late} == {"skill_limit_hits", "warnings", "warns_squat"}


def test_path_traversal_and_stowaway_note_are_registered_early():
    """The two facts B-746 and B-745 already promoted must stay promoted — regressing
    either back to a late registration would silently reopen a fixed bug and this test
    would not catch it via the "late" checks above (nothing requires an EARLY key to
    also appear in _B13_WINNER_ONLY_BUCKETS, correctly — it does not need one)."""
    early, _late = _early_and_late()
    assert "path_traversal" in early
    assert "_stowaway_note" in early
