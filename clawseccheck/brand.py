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
    "HIGH": SeverityStyle("🟠", GRADE_ANSI["D"], GRADE_HEX["D"]),
    "MEDIUM": SeverityStyle("🟡", GRADE_ANSI["C"], GRADE_HEX["C"]),
    "LOW": SeverityStyle("⚪", GRADE_ANSI["B"], GRADE_HEX["B"]),
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

# A 64x64 raster PNG of the real mascot mark (shield + claws + check), base64-inlined
# so the browser-tab icon stays self-contained — no external file reference, no
# network fetch. Source art lives at docs/assets/logo.png (cropped/resized from
# there); regenerate this constant if that source ever changes. Deliberately NOT a
# replacement for LOGO_SVG above: LOGO_SVG's value is being a tiny set of vector
# paths that render.py re-nests inside the 14px shields.io badge icon (see
# report.py's `_LOGO_INNER`) — a raster blob would be pointless at that size and
# would bloat every `--badge` SVG. This constant is favicon-only.
FAVICON_DATA_URI = (
    "data:image/png;base64,"
    "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"
    "TkSuQmCC"
)
"""64x64 favicon PNG for the ``--html`` export's ``<head>``, base64-inlined. **HTML
/ badge-only** (Tier 3) — same reach constraint as :data:`LOGO_SVG`, but this one is
the real mascot art, not the vector placeholder; see :func:`clawseccheck.report.
render_html`."""
