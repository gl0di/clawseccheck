"""C-129 / B-276 / C-426: _PRIMARY_MODES and _main()'s dispatch cannot drift apart.

**The property this module guards was inverted by C-426 part B, and the reason is worth
keeping.** Until then, ``_main()``'s ``if args.X: ... return`` cascade DECIDED which mode
ran, and ``_PRIMARY_MODES`` merely NAMED the winner for the coherence notes. Two
mechanisms, hand-kept in agreement:

* adding a terminal mode to ``_main()`` while forgetting ``_PRIMARY_MODES`` silently
  reintroduced the B-067 silent-drop bug for that mode (C-129), and
* reordering — or mis-typing the order once — made ``_flag_coherence_notes`` name the
  WRONG winner (B-276). When B-276 was filed the two disagreed in **27 pairs**; the
  visible worst case was ``--monitor --judge-packet`` printing ``note: --judge-packet
  ignored (running --monitor)`` while ``_main()`` in fact ran ``--judge-packet``.

This module answered that with AST extraction of the cascade plus a sequence-equality
assertion. That worked, but it made the guarantee a *test* rather than a *structure*:
the two mechanisms still existed, and only CI stopped them diverging.

C-426 part B removed the second mechanism. ``_resolve_mode`` elects the mode from
``_PRIMARY_MODES``, ``_main`` dispatches on ``_mode == "..."``, and
``_flag_coherence_notes`` names the winner from the same call — so "which mode runs" and
"which mode the note names" are now one value, and B-276 cannot recur by construction.

What remains worth guarding is different, and these tests assert it:

1. every table entry HAS a branch — a missing one is a flag that parses and does nothing;
2. every branch names a string that IS in the table — a typo is dead code, silently;
3. the branches stay in table order — order still decides which side of the ``audit()``
   call a mode lands on, which is what ``_ATTEST_CONSUMERS`` depends on;
4. no mode dispatches from a bare ``args.X`` guard any more — that is the C-129
   protection, pointed the way round the new structure needs.
"""
from __future__ import annotations

import ast
from pathlib import Path

from clawseccheck.cli import _ATTEST_CONSUMERS, _PRIMARY_MODES

CLI_PATH = Path(__file__).resolve().parent.parent / "clawseccheck" / "cli.py"

# args.<attr> names that may legitimately be tested by a returning top-level `if` in
# _main() WITHOUT being a primary mode: output selectors, CI gates, enrichment modifiers
# and plumbing. A new terminal mode must be registered in _PRIMARY_MODES and dispatched
# through `_mode ==` — or consciously added here, which is then a visible, reviewed
# choice rather than a silent drop.
NON_MODE_ATTRS = frozenset({
    "json", "card", "save", "full", "attest",          # output / enrichment modifiers
    "emit_manifest",                                   # --vet-skill side output (B98/F-083)
    "vet_judge_packet",                                # --vet-skill side output (C-254)
    "fail_on", "exit_code", "no_history",              # CI gates / history plumbing
    "trend", "monitor",                                # read again at the history gate
    "pdf", "dashboard",                                # the C-373/C-374 composition
    "home", "history", "state", "events", "seed",      # value plumbing read in branches
    "ascii", "no_native", "no_host", "verbose", "debug", "log",
    "no_update_notice", "no_freshness_notice", "show_suppressed_ids",
})

# The first mode dispatched AFTER the audit(attestation=...) call in _main(). Every mode
# from here to the end genuinely consumes --attest, because its ctx/findings come out of
# that call. See _ATTEST_CONSUMERS.
_FIRST_POST_AUDIT_MODE = "risk_paths"


def _main_fn() -> ast.FunctionDef:
    tree = ast.parse(CLI_PATH.read_text(encoding="utf-8"))
    return next(n for n in tree.body
                if isinstance(n, ast.FunctionDef) and n.name == "_main")


def _attrs_in(node: ast.AST) -> set[str]:
    """Every `args.<attr>` attribute access inside *node*."""
    found: set[str] = set()
    for sub in ast.walk(node):
        if (isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name)
                and sub.value.id == "args"):
            found.add(sub.attr)
    return found


def _top_level_ifs(body: list[ast.stmt]):
    """Top-level `if` statements of _main(), following each `elif` chain.

    Restricted to the function's own body on purpose: the vet family's router is an
    if/elif chain at the same level, and `_mode == "sarif"` must not be confused with
    the `args.sarif` side output tested deep inside the --vet block.
    """
    for stmt in body:
        if not isinstance(stmt, ast.If):
            continue
        node = stmt
        while True:
            yield node
            if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
                node = node.orelse[0]  # `elif` — same cascade level
            else:
                break


def _mode_literals(test: ast.AST) -> list[str]:
    """Every string X in a `_mode == "X"` comparison inside *test*."""
    out: list[str] = []
    for sub in ast.walk(test):
        if not isinstance(sub, ast.Compare) or len(sub.ops) != 1:
            continue
        if not isinstance(sub.ops[0], ast.Eq):
            continue
        left, right = sub.left, sub.comparators[0]
        if isinstance(left, ast.Name) and left.id == "_mode" and isinstance(right, ast.Constant):
            if isinstance(right.value, str):
                out.append(right.value)
    return out


def _dispatch_order() -> list[str]:
    """Mode names in the order _main()'s top-level branches first test for them."""
    first_seen: dict[str, int] = {}
    for node in _top_level_ifs(_main_fn().body):
        for name in _mode_literals(node.test):
            if name not in first_seen:
                first_seen[name] = node.test.lineno
    return [n for n, _ln in sorted(first_seen.items(), key=lambda kv: kv[1])]


def _terminal_if_attrs() -> set[str]:
    """args attrs tested by an `if` in _main() whose direct body returns."""
    attrs: set[str] = set()
    for node in ast.walk(_main_fn()):
        if not isinstance(node, ast.If):
            continue
        if any(isinstance(stmt, ast.Return) for stmt in node.body):
            attrs |= _attrs_in(node.test)
    return attrs


class TestModeDriftGuard:
    def test_every_primary_mode_has_a_dispatch_branch(self):
        declared = {attr for attr, _flag, _kind in _PRIMARY_MODES}
        dispatched = set(_dispatch_order())
        missing = sorted(declared - dispatched)
        assert not missing, (
            f"_PRIMARY_MODES entries with no `_mode == \"...\"` branch in _main(): "
            f"{missing} — the flag parses and then does nothing at all, which is the "
            f"B-067 silent drop with a new cause. Add the branch, or drop the entry."
        )

    def test_every_dispatch_branch_names_a_registered_mode(self):
        declared = {attr for attr, _flag, _kind in _PRIMARY_MODES}
        stray = sorted(set(_dispatch_order()) - declared)
        assert not stray, (
            f"_main() dispatches on mode names absent from _PRIMARY_MODES: {stray} — "
            f"_resolve_mode can never return them, so the branch is dead code. Register "
            f"the mode or fix the typo."
        )

    def test_dispatch_order_matches_the_declared_table_order(self):
        # Only one branch can match now, so order no longer decides the winner — but it
        # still decides which side of the audit() call a mode lands on, and that is what
        # _ATTEST_CONSUMERS below is derived from. A silently reordered branch would move
        # a mode across that boundary.
        declared = [attr for attr, _flag, _kind in _PRIMARY_MODES]
        actual = _dispatch_order()
        assert declared == actual, (
            "_PRIMARY_MODES is out of order with _main()'s dispatch branches.\n"
            f"  declared : {declared}\n"
            f"  _main()  : {actual}\n"
            "The table elects the mode; _main() implements it. Keeping the two in the "
            "same order is what makes the post-audit tail derivable (see "
            "_ATTEST_CONSUMERS) and the file readable in dispatch order."
        )

    def test_no_mode_still_dispatches_from_a_bare_args_guard(self):
        # The C-129 protection, pointed the way round the new structure needs: a new
        # terminal mode added as `if args.newthing: ... return` bypasses the table
        # entirely, and _flag_coherence_notes would never know it ran.
        mode_attrs = {attr for attr, _flag, _kind in _PRIMARY_MODES}
        offenders = sorted((_terminal_if_attrs() & mode_attrs) - NON_MODE_ATTRS)
        assert not offenders, (
            f"these registered modes are still dispatched by a bare `if args.X: ... "
            f"return` guard: {offenders} — dispatch must go through `_mode == \"...\"` "
            f"so _PRIMARY_MODES stays the single source of truth (C-426 part B)."
        )

    def test_attest_consumers_is_the_post_audit_tail_of_the_dispatch(self):
        # _ATTEST_CONSUMERS is "every mode dispatched after audit(attestation=...)",
        # i.e. a contiguous tail. Deriving it here keeps the two from drifting the way
        # "behavioral" did (B-301).
        order = _dispatch_order()
        tail = set(order[order.index(_FIRST_POST_AUDIT_MODE):])
        assert set(_ATTEST_CONSUMERS) == tail, (
            "_ATTEST_CONSUMERS must equal the modes dispatched after "
            f"audit(attestation=...) — the tail from {_FIRST_POST_AUDIT_MODE!r} on.\n"
            f"  missing from _ATTEST_CONSUMERS: {sorted(tail - set(_ATTEST_CONSUMERS))}\n"
            f"  wrongly listed (run BEFORE audit()): "
            f"{sorted(set(_ATTEST_CONSUMERS) - tail)}"
        )
