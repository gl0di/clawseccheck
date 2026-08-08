"""Screen 12 — full capability palette (F-045), organised by mode (C-428).

Two load-bearing guards:

* the original drift guard — every ``cli._PRIMARY_MODES`` flag is represented in
  the palette (or explicitly exempt), so the palette and ``cli.py`` can't diverge;
* the C-428 completeness guard — every flag ``cli.py``'s parser declares is
  assigned to exactly one mode, so a new flag cannot be added without someone
  deciding where a human would look for it.

Offline, deterministic, no writes.
"""
from __future__ import annotations

import ast
from pathlib import Path

from clawseccheck.cli import _PRIMARY_MODES
from clawseccheck.palette import (
    CROSS,
    EXEMPT_FROM_PALETTE,
    MODE_A,
    MODE_B,
    MODE_C,
    MODE_HEADING,
    MODE_ORDER,
    _PALETTE,
    duplicated_flag_assignments,
    flag_modes,
    grounded_flags,
    render_palette,
)

_CLI_SRC = Path("clawseccheck/cli.py")


def _parser_flags() -> set[str]:
    """Every ``--flag`` literal cli.py passes to ``add_argument``.

    Derived from the source rather than from a hand-kept list, so the guard below
    sees a new flag the moment it is declared — which is the whole point of it.
    """
    flags: set[str] = set()
    for node in ast.walk(ast.parse(_CLI_SRC.read_text(encoding="utf-8"))):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_argument"):
            continue
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) \
                    and arg.value.startswith("--"):
                flags.add(arg.value)
    return flags


# ── Drift guard (the point of the grounded registry) ─────────────────────────

class TestGrounding:
    def test_every_primary_mode_is_in_the_palette(self):
        grounded = grounded_flags()
        missing = [flag for _attr, flag, _kind in _PRIMARY_MODES
                   if flag not in EXEMPT_FROM_PALETTE and flag not in grounded]
        assert not missing, f"palette is missing capabilities from _PRIMARY_MODES: {missing}"

    def test_exemptions_are_real_modes(self):
        # An exemption that no longer names a real mode is dead weight — catch it.
        mode_flags = {flag for _a, flag, _k in _PRIMARY_MODES}
        stale = [f for f in EXEMPT_FROM_PALETTE if f not in mode_flags]
        assert not stale, f"EXEMPT_FROM_PALETTE names non-existent modes: {stale}"

    def test_grounded_flags_are_real_cli_flags(self):
        # Guard against a typo'd flag in the registry: every grounded flag must
        # actually appear in cli.py's source (where add_argument declares it).
        src = Path("clawseccheck/cli.py").read_text(encoding="utf-8")
        bogus = [f for f in grounded_flags() if f not in src]
        assert not bogus, f"palette grounds to flags not present in cli.py: {bogus}"


# ── C-428: every flag lands in exactly one mode ───────────────────────────────

class TestModeCompleteness:
    """A flag cannot be silently orphaned from the presentation.

    The three modes plus the cross-cutting group must partition the parser's
    flags: total (nothing unassigned) and disjoint (nothing claimed twice).
    """

    def test_every_parser_flag_has_a_mode(self):
        unassigned = sorted(_parser_flags() - set(flag_modes()))
        assert not unassigned, (
            "these CLI flags belong to no mode — add each to a palette row or to "
            f"palette._UNLISTED_FLAG_MODES: {unassigned}")

    def test_no_mode_assignment_names_a_flag_that_does_not_exist(self):
        stale = sorted(set(flag_modes()) - _parser_flags())
        assert not stale, f"mode map names flags cli.py does not declare: {stale}"

    def test_no_flag_is_claimed_twice(self):
        dupes = sorted(duplicated_flag_assignments())
        assert not dupes, (
            "these flags are claimed by BOTH a palette row and the unlisted table; "
            f"drop the unlisted entry: {dupes}")

    def test_every_mode_is_used(self):
        used = set(flag_modes().values())
        assert used == set(MODE_ORDER), f"unused or unknown modes: {used ^ set(MODE_ORDER)}"

    def test_every_category_declares_a_known_mode(self):
        bad = [c.title for c in _PALETTE if c.mode not in MODE_ORDER]
        assert not bad, f"palette categories with an unknown mode: {bad}"


# ── Rendering ─────────────────────────────────────────────────────────────────

class TestRender:
    def test_every_entry_title_is_rendered(self):
        # C-428: a mode holding exactly one category prints its heading instead of
        # repeating the category name, so "every category title appears" is no
        # longer the right shape. What must hold is that nothing is hidden: every
        # entry a user could reach is on the screen.
        out = render_palette()
        for cat in _PALETTE:
            for entry in cat.entries:
                assert entry.title in out, f"{entry.title!r} missing from the palette"

    def test_all_three_modes_are_headed(self):
        out = render_palette()
        for mode in (MODE_A, MODE_B, MODE_C, CROSS):
            heading, _question, _produces = MODE_HEADING[mode]
            assert heading in out, f"mode heading {heading!r} missing"

    def test_each_mode_says_what_it_produces(self):
        """The honesty invariant, on the index screen as well as in the report."""
        out = render_palette()
        assert "a grade only when all five layers ran" in out
        assert "events, never a number" in out
        assert "INSTALL / CAUTION / DO-NOT-INSTALL — not a letter grade" in out

    def test_readonly_and_live_tags_present(self):
        out = render_palette()
        assert "✅ read-only" in out
        assert "⚡" in out  # live-agent disclosure

    def test_modifiers_and_help_footer(self):
        out = render_palette()
        assert "Add to any:" in out
        assert '"private"' in out and "--no-history" in out
        assert 'say "help"' in out

    def test_says_no_flag_was_removed(self):
        # A scripted user must not read the rebuild as flags having gone away.
        assert "nothing here was removed" in render_palette()

    def test_check_count_substituted(self):
        assert "81 checks over config, files and permissions" in render_palette(n_checks=81)

    def test_check_count_falls_back_when_unknown(self):
        out = render_palette(n_checks=None)
        assert "all checks over config, files and permissions" in out
        assert "{n}" not in out  # placeholder never leaks

    # ── B-471: the screen has to survive a wrapping chat client ──────────────

    def test_no_row_is_wider_than_a_chat_message(self):
        """B-471 for good: the bug was a 273-char row, not the padding alone.

        The padding cap only bounds the column; a single over-long blurb still
        stretched the rendered line past it. Bound the rendered row itself, so a
        verbose blurb fails the build instead of shredding the layout.
        """
        for text in (render_palette(n_checks=184),
                     render_palette(n_checks=184, ascii_only=True)):
            over = [(len(ln), ln) for ln in text.splitlines() if len(ln) > 108]
            assert not over, f"{len(over)} row(s) past 108 chars: {over[:2]}"

    def test_palette_fits_one_chat_message(self):
        assert len(render_palette(n_checks=184)) < 8000

    def test_ascii_is_pure_ascii(self):
        out = render_palette(n_checks=81, ascii_only=True)
        assert out.isascii()
        assert "(live)" in out          # ⚡ folded, not dropped
        assert "🦞" not in out and "✅" not in out

    def test_every_entry_shows_its_flag_or_default(self):
        out = render_palette()
        for cat in _PALETTE:
            for e in cat.entries:
                token = "(default)" if (e.flag is None and not e.also) else e.flag
                assert token in out
