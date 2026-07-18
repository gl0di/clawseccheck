"""clawseccheck.brand — the single source of brand truth.

Layer 1 leaf module (see the repo-root CLAUDE.md §3 dependency flow): stdlib only,
imports **nothing** from the rest of ``clawseccheck``. Every renderer imports FROM
this module; it never imports them — that keeps the dependency graph acyclic.

## Three reach tiers, kept as three separate kinds of export

A live Telegram + web-chat test proved that not everything a renderer *emits*
actually *reaches* the user the same way, so this module deliberately keeps three
tiers apart instead of exposing one flat "brand" blob:

1. **Seen everywhere** — :data:`MASCOT`, :data:`WORDMARK`, :func:`header`,
   :func:`frame`. Plain text; it survives every channel OpenClaw relays a skill's
   output over (a real terminal, web ControlUI, Telegram, Discord, ...).
2. **Terminal-only** — :data:`GRADE_ANSI` and each :class:`SeverityStyle`'s
   ``ansi`` field: ``ansi.py`` colour-palette *names* (not escape codes). Colour
   never reaches a chat channel (no ANSI there); only an interactive terminal
   renders it, and only when ``ansi.should_color()`` says so.
3. **HTML / badge-only** — :data:`GRADE_HEX`, :data:`BRAND_RED`, each
   ``SeverityStyle``'s ``hex`` field, and :data:`LOGO_SVG`. A graphical logo mark
   is physically impossible to deliver in a chat message; it can only appear in
   the self-contained ``--html`` export or the shareable ``--badge`` SVG file.

Nothing in this module does I/O, reads the clock, or reads the environment — every
export is a pure constant or a pure string-building function, so it is trivially
testable and safe to import from anywhere (including a check or a test) without
side effects.
"""
from __future__ import annotations

from dataclasses import dataclass

# ── Tier 1: seen everywhere (text, every channel) ────────────────────────────

MASCOT = "🦞"
"""The brand mascot emoji ("the Claw"). Header line only, once per screen; dropped
entirely under ``--ascii`` (never folded to an ASCII substitute — there isn't one)."""

WORDMARK = "ClawSecCheck"
"""The product name exactly as it must render everywhere — never abbreviated,
re-cased, or translated (output is English-only; see CLAUDE.md §9)."""

SEPARATOR = " · "
"""The one brand separator between the wordmark and a subtitle/version."""

ASCII_SEPARATOR = " - "
"""``SEPARATOR``'s pure-ASCII fallback, used whenever ``ascii_only=True``."""

FRAME_WIDTH = 30
"""Default rule width for :func:`frame` (matches the existing family-header frames)."""


def header(subtitle: str = "", *, ascii_only: bool = False) -> str:
    """The one brand header line: ``"🦞 ClawSecCheck · {subtitle}"``.

    An empty *subtitle* renders just the (optionally mascot-prefixed) wordmark,
    with no trailing separator. ``ascii_only`` drops the mascot and folds the
    separator to ``" - "`` — the same convention every current renderer hand-rolls
    (``menu.render_menu``, ``menu.render_onboarding``, ``palette.render_palette``).
    Pure text; identical output every call for the same arguments.
    """
    prefix = WORDMARK if ascii_only else f"{MASCOT} {WORDMARK}"
    if not subtitle:
        return prefix
    sep = ASCII_SEPARATOR if ascii_only else SEPARATOR
    return f"{prefix}{sep}{subtitle}"


def frame(label: str, *, width: int = FRAME_WIDTH) -> list[str]:
    """The open 3-sided frame used for family-section headers (design-system.md
    Component 3 / Layer 2): a top and bottom rule with **no right border**.

    That is deliberate: a closed box needs its right edge to line up, and emoji
    render at variable width, so it visibly breaks. With nothing to misalign on
    the right, this frame holds together in a monospace surface (terminal,
    ControlUI code-block) *and* degrades to three harmless plain lines in a
    proportional one (Telegram) — the single box-art exception to the plain-text
    baseline every other screen uses.

    Returns the three lines as a list (top rule, label line, bottom rule) so a
    caller can ``lines.extend(frame(...))`` or join them directly. *label* should
    already carry any trailing count text (e.g. ``"🌐 Exposure & Network — 1
    issue(s)"``) — this function only draws the frame around it.
    """
    rule = "─" * width
    return [f"┌{rule}", f"│ {label}", f"└{rule}"]


# ── Tier 2 + 3: colour palette ────────────────────────────────────────────────
#
# Grade -> colour is kept as two *separate*, distinctly-named dicts on purpose.
# report.py used to define a single `_GRADE_COLOR` name twice — once with ANSI
# palette names, once (later in the file) with hex codes — so the second
# definition silently shadowed the first and the terminal grade letter/score-bar
# fill rendered with no colour at all. Two names that can never collide fixes
# that class of bug structurally instead of relying on file-order discipline.

GRADE_HEX: dict[str, str] = {
    "A": "#4c1",
    "B": "#97ca00",
    "C": "#dfb317",
    "D": "#fe7d37",
    "F": "#e05d44",
}
"""Grade letter -> hex colour. **HTML / badge-only** (Tier 3) — the SVG badge and
the ``--html`` export are the only surfaces that are static files rather than
channel-relayed text, so they are the only place a grade colour can appear."""

GRADE_ANSI: dict[str, str] = {
    "A": "green",
    "B": "green",
    "C": "yellow",
    "D": "bright_yellow",
    "F": "red",
}
"""Grade letter -> ``ansi.py`` palette colour *name* (not an escape code).
**Terminal-only** (Tier 2) — pass straight to ``ansi.paint(text,
grade_ansi(grade), enabled=color)``; ``color`` must already be gated by
``ansi.should_color()``."""

BRAND_RED = "#e34234"
"""The one brand accent colour, independent of any grade/severity ramp — used by
the logo mark and HTML accent highlights. **HTML / badge-only** (Tier 3)."""

_DEFAULT_HEX = "#9f9f9f"
_DEFAULT_ANSI = "grey"


def grade_hex(grade: str) -> str:
    """Grade (possibly ``"A+"``/``"B-"``) -> hex colour, falling back to a neutral
    grey for anything unrecognized. **HTML / badge-only** (Tier 3)."""
    return GRADE_HEX.get((grade or "")[:1].upper(), _DEFAULT_HEX)


def grade_ansi(grade: str) -> str:
    """Grade (possibly ``"A+"``/``"B-"``) -> ``ansi.py`` palette colour name,
    falling back to ``"grey"`` for anything unrecognized. **Terminal-only**
    (Tier 2)."""
    return GRADE_ANSI.get((grade or "")[:1].upper(), _DEFAULT_ANSI)


@dataclass(frozen=True)
class SeverityStyle:
    """One severity level's presentation, one field per reach tier."""

    glyph: str  # Tier 1 — seen everywhere: the severity dot (chat + terminal + HTML)
    ansi: str   # Tier 2 — terminal-only: an ansi.py palette colour name
    hex: str    # Tier 3 — HTML/badge-only: a hex colour


# Derived FROM the same grade ramp GRADE_ANSI/GRADE_HEX use (CRITICAL/HIGH share
# grade F's colour, MEDIUM shares grade C's) rather than a second, independently
# hand-kept colour set that could drift from it. The glyphs match
# design-system.md's Layer 0 glyph legend and report.py's existing severity dots.
SEVERITY: dict[str, SeverityStyle] = {
    "CRITICAL": SeverityStyle("🔴", GRADE_ANSI["F"], GRADE_HEX["F"]),
    "HIGH": SeverityStyle("🟠", GRADE_ANSI["F"], GRADE_HEX["F"]),
    "MEDIUM": SeverityStyle("🟡", GRADE_ANSI["C"], GRADE_HEX["C"]),
    "LOW": SeverityStyle("⚪", _DEFAULT_ANSI, _DEFAULT_HEX),
}
"""Severity name -> :class:`SeverityStyle`. The severity **glyph** (Tier 1) is what
actually reaches a chat channel; ``ansi``/``hex`` are additive, higher-reach-tier
enhancements a terminal or the HTML export may layer on top."""


# ── Tier 3: the graphical mark (HTML / badge-only) ───────────────────────────
#
# PROVISIONAL placeholder mark: a minimal, self-contained abstract "claw pincer"
# glyph in BRAND_RED — no external assets/fonts/references (matches the --html
# export's existing "single self-contained file" rule), so it is safe to inline
# wherever a real graphical logo is wanted today. The *final* mark art is an
# explicit follow-up (a sibling brand-epic task) that only needs to replace this
# one constant; every HTML/badge caller should read LOGO_SVG rather than
# hand-copy it, so that follow-up is a one-file change.
LOGO_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" '
    'width="64" height="64" role="img" aria-label="ClawSecCheck">'
    '<circle cx="32" cy="32" r="30" fill="#e34234"/>'
    '<path d="M20 24 Q13 32 20 40" fill="none" stroke="#fff" stroke-width="4" '
    'stroke-linecap="round"/>'
    '<path d="M44 24 Q51 32 44 40" fill="none" stroke="#fff" stroke-width="4" '
    'stroke-linecap="round"/>'
    '<circle cx="32" cy="32" r="5" fill="#fff"/>'
    "</svg>"
)
"""A minimal, self-contained SVG mark (no external assets/fonts/network refs) for
the ``--html`` export and the ``--badge`` SVG. **HTML / badge-only** (Tier 3) — a
graphical logo cannot be delivered through any chat channel. See the PROVISIONAL
note above: the mark art itself is a placeholder pending the final design."""
