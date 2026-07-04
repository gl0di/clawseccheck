"""C-129: _PRIMARY_MODES must not drift from main()'s terminal-mode cascade.

_PRIMARY_MODES hand-duplicates the order of ``if args.X: ... return`` branches in
``cli.main``. Nothing used to tie the two together, so adding a new terminal mode to
main() while forgetting _PRIMARY_MODES silently reintroduced the B-067 silent-drop bug
for that mode. This guard walks main()'s AST: every ``args.<attr>`` tested by an ``if``
whose body returns must be a registered mode or an explicitly-listed non-mode flag.
"""
from __future__ import annotations

import ast
from pathlib import Path

from clawseccheck.cli import _PRIMARY_MODES

CLI_PATH = Path(__file__).resolve().parent.parent / "clawseccheck" / "cli.py"

# args.<attr> names that legitimately appear in a returning `if` inside main() without
# being primary modes: output selectors, CI gates, enrichment modifiers, and plumbing.
# Adding a NEW terminal mode requires registering it in _PRIMARY_MODES (preferred) or
# consciously adding it here — either way the drift is now a visible, reviewed choice.
NON_MODE_ATTRS = frozenset({
    "json", "card", "save", "full", "attest",          # output / enrichment modifiers
    "emit_manifest",                                   # --vet-skill side output (B98/F-083)
    "fail_under", "exit_code", "no_history",           # CI gates / history plumbing
    "trend", "monitor",                                # also modes, kept for cascade logic
    "home", "history", "state", "events", "seed",      # value plumbing read in branches
    "ascii", "no_native", "no_host", "verbose", "debug", "log",
    "no_update_notice", "no_freshness_notice", "show_suppressed_ids",
})


def _attrs_in(node: ast.AST) -> set[str]:
    """Every `args.<attr>` attribute access inside *node*."""
    found: set[str] = set()
    for sub in ast.walk(node):
        if (isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name)
                and sub.value.id == "args"):
            found.add(sub.attr)
    return found


def _terminal_if_attrs() -> set[str]:
    """args attrs tested by `if` statements in main() whose direct body returns."""
    tree = ast.parse(CLI_PATH.read_text(encoding="utf-8"))
    main_fn = next(n for n in tree.body
                   if isinstance(n, ast.FunctionDef) and n.name == "main")
    attrs: set[str] = set()
    for node in ast.walk(main_fn):
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
        tree = ast.parse(CLI_PATH.read_text(encoding="utf-8"))
        main_fn = next(n for n in tree.body
                       if isinstance(n, ast.FunctionDef) and n.name == "main")
        used = _attrs_in(main_fn)
        stale = {attr for attr, _f, _k in _PRIMARY_MODES} - used
        assert not stale, f"_PRIMARY_MODES entries with no args.<attr> use in main(): {sorted(stale)}"