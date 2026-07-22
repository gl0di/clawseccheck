"""C-129 / B-276: _PRIMARY_MODES must not drift from main()'s terminal-mode cascade.

``_PRIMARY_MODES`` hand-duplicates BOTH the membership AND the *order* of the
``if args.X: ... return`` branches in ``cli._main``. Nothing used to tie the two
together, so:

* adding a new terminal mode to ``_main()`` while forgetting ``_PRIMARY_MODES``
  silently reintroduced the B-067 silent-drop bug for that mode (C-129), and
* reordering — or simply mis-typing the order once — made
  ``_flag_coherence_notes`` name the WRONG winner (B-276). At the time B-276 was
  filed the two disagreed in **27 pairs**; the user-visible worst case was
  ``--monitor --judge-packet`` printing ``note: --judge-packet ignored (running
  --monitor)`` on stderr while ``_main()`` actually ran ``--judge-packet``.

The original guard's docstring already claimed it protected the order. It did not:
both of its tests used set arithmetic and asserted membership only. These tests now
assert **sequence equality**, which is the property the module actually needs.
"""
from __future__ import annotations

import ast
from pathlib import Path

from clawseccheck.cli import _ATTEST_CONSUMERS, _PRIMARY_MODES

CLI_PATH = Path(__file__).resolve().parent.parent / "clawseccheck" / "cli.py"

# args.<attr> names that legitimately appear in a returning `if` inside main() without
# being primary modes: output selectors, CI gates, enrichment modifiers, and plumbing.
# Adding a NEW terminal mode requires registering it in _PRIMARY_MODES (preferred) or
# consciously adding it here — either way the drift is now a visible, reviewed choice.
NON_MODE_ATTRS = frozenset({
    "json", "card", "save", "full", "attest",          # output / enrichment modifiers
    "emit_manifest",                                   # --vet-skill side output (B98/F-083)
    "vet_judge_packet",                                # --vet-skill side output (C-254)
    "fail_under", "exit_code", "no_history",           # CI gates / history plumbing
    "trend", "monitor",                                # also modes, kept for cascade logic
    "home", "history", "state", "events", "seed",      # value plumbing read in branches
    "ascii", "no_native", "no_host", "verbose", "debug", "log",
    "no_update_notice", "no_freshness_notice", "show_suppressed_ids",
})

# The first mode dispatched AFTER the audit(attestation=...) call in _main(). Every
# mode from here to the end of the cascade genuinely consumes --attest, because its
# ctx/findings come out of that audit() call. See _ATTEST_CONSUMERS.
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


def _tested_attrs(test: ast.AST) -> list[tuple[int, str]]:
    """(lineno, attr) for every `args.X` or `getattr(args, "X", ...)` in an if-test."""
    out: list[tuple[int, str]] = []
    for sub in ast.walk(test):
        if (isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name)
                and sub.value.id == "args"):
            out.append((sub.lineno, sub.attr))
        elif (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name)
                and sub.func.id == "getattr" and len(sub.args) > 1
                and isinstance(sub.args[0], ast.Name) and sub.args[0].id == "args"
                and isinstance(sub.args[1], ast.Constant)
                and isinstance(sub.args[1].value, str)):
            out.append((sub.lineno, sub.args[1].value))
    return out


def _top_level_ifs(body: list[ast.stmt]):
    """Top-level `if` statements of _main(), following each `elif` chain.

    Restricted to the function's own body on purpose: `args.sarif` is *also* tested
    deep inside the --vet block as a side output (~cli.py:794), and counting that
    nested test would place `sarif` in the middle of the vet family instead of at its
    real cascade position.
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


def _cascade_order() -> list[str]:
    """Registered mode attrs in the order _main()'s top-level cascade first tests them."""
    modes = {attr for attr, _flag, _kind in _PRIMARY_MODES}
    first_seen: dict[str, int] = {}
    for node in _top_level_ifs(_main_fn().body):
        for lineno, attr in _tested_attrs(node.test):
            if attr in modes and attr not in first_seen:
                first_seen[attr] = lineno
    return [a for a, _ln in sorted(first_seen.items(), key=lambda kv: kv[1])]


def _terminal_if_attrs() -> set[str]:
    """args attrs tested by `if` statements in main() whose direct body returns."""
    attrs: set[str] = set()
    for node in ast.walk(_main_fn()):
        if not isinstance(node, ast.If):
            continue
        if any(isinstance(stmt, ast.Return) for stmt in node.body):
            attrs |= _attrs_in(node.test)
    return attrs


class TestModeDriftGuard:
    def test_every_terminal_branch_attr_is_registered(self):
        mode_attrs = {attr for attr, _flag, _kind in _PRIMARY_MODES}
        terminal = _terminal_if_attrs()
        unregistered = terminal - mode_attrs - NON_MODE_ATTRS
        assert not unregistered, (
            f"main() has terminal `if args.X: ... return` branches not registered in "
            f"_PRIMARY_MODES (or NON_MODE_ATTRS): {sorted(unregistered)} — register the "
            f"mode so _flag_coherence_notes can track it (B-067)."
        )

    def test_every_primary_mode_is_actually_used_in_main(self):
        # The reverse direction: a stale _PRIMARY_MODES entry whose branch was removed.
        used = _attrs_in(_main_fn())
        stale = {attr for attr, _f, _k in _PRIMARY_MODES} - used
        assert not stale, f"_PRIMARY_MODES entries with no args.<attr> use in main(): {sorted(stale)}"

    def test_every_primary_mode_is_reachable_in_the_top_level_cascade(self):
        # Sanity check on the extractor itself: if a mode is dispatched somewhere the
        # extractor cannot see, the order assertion below would silently skip it.
        declared = [attr for attr, _f, _k in _PRIMARY_MODES]
        missing = sorted(set(declared) - set(_cascade_order()))
        assert not missing, (
            f"_PRIMARY_MODES entries not found in _main()'s top-level if-cascade: "
            f"{missing} — either the mode moved into a nested block (make it top-level) "
            f"or _cascade_order()'s extractor needs to learn the new dispatch shape."
        )

    def test_primary_modes_order_matches_the_main_cascade_exactly(self):
        # B-276: THE assertion this module always advertised and never made. Equality,
        # not membership — _flag_coherence_notes takes active[0] as "the winner", so a
        # wrong order makes it name a mode that did not run.
        declared = [attr for attr, _f, _k in _PRIMARY_MODES]
        actual = _cascade_order()
        assert declared == actual, (
            "_PRIMARY_MODES is out of order with _main()'s dispatch cascade.\n"
            f"  declared : {declared}\n"
            f"  _main()  : {actual}\n"
            "Reorder _PRIMARY_MODES to match _main(). The list decides which mode the "
            "stderr coherence note NAMES; _main() decides which mode actually runs. "
            "When they disagree the note accuses the wrong flag (B-276)."
        )

    def test_attest_consumers_is_the_post_audit_tail_of_the_cascade(self):
        # _ATTEST_CONSUMERS is "every mode dispatched after audit(attestation=...)",
        # i.e. a contiguous tail of the cascade. Deriving it here keeps the two from
        # drifting the way "behavioral" did (B-301).
        order = _cascade_order()
        tail = set(order[order.index(_FIRST_POST_AUDIT_MODE):])
        assert set(_ATTEST_CONSUMERS) == tail, (
            "_ATTEST_CONSUMERS must equal the modes dispatched after audit(attestation=...) "
            f"— i.e. the cascade tail from {_FIRST_POST_AUDIT_MODE!r} onward.\n"
            f"  missing from _ATTEST_CONSUMERS: {sorted(tail - set(_ATTEST_CONSUMERS))}\n"
            f"  wrongly listed (run BEFORE audit()): {sorted(set(_ATTEST_CONSUMERS) - tail)}"
        )
