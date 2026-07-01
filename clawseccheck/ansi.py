"""Hand-rolled ANSI colour — stdlib only, opt-in, terminal-safe.

Colour is a *presentation* layer for the human terminal report only. It is:

- **Opt-in / auto-off:** enabled only for an interactive TTY, and always
  disabled by ``--no-color`` or the ``NO_COLOR`` convention (https://no-color.org).
- **Never applied to untrusted data as data:** ``report._sanitize`` has already
  stripped every ESC/OSC sequence out of findings, skill names and payloads, so
  the only escape sequences in the output are the fixed SGR codes emitted *here*,
  wrapping our own known tokens (grade letter, icons, labels, score-bar cells).
  A hostile skill/config therefore cannot inject or break out of colour.
- **Strippable:** ``strip_ansi`` removes exactly the SGR codes we emit, so a
  saved report (``--save``) or a piped stream can be made plain again.

No third-party dependency (no ``colorama``); Python 3.9+.
"""
from __future__ import annotations

import os
import re
import sys

_ESC = "\x1b["

# Select-Graphic-Rendition codes we use. Kept tiny and fixed on purpose.
_CODES: dict[str, str] = {
    "reset": "0",
    "bold": "1",
    "dim": "2",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "grey": "90",
    "bright_red": "91",
    "bright_yellow": "93",
}

# Matches only the SGR sequences paint() emits: ESC [ <digits/;> m
_SGR_RE = re.compile(r"\x1b\[[0-9;]*m")


def should_color(*, no_color_flag: bool = False, stream=None, env=None) -> bool:
    """Decide whether ANSI colour should be emitted.

    Precedence (first match wins):
      1. ``--no-color`` flag        → off (explicit user opt-out).
      2. ``NO_COLOR`` present       → off (any value, incl. empty; the no-color.org spec).
      3. ``FORCE_COLOR`` present    → on  (explicit opt-in, even when not a TTY).
      4. ``stream.isatty()``        → on when interactive, else off.
    """
    env = os.environ if env is None else env
    if no_color_flag:
        return False
    if "NO_COLOR" in env:
        return False
    if "FORCE_COLOR" in env:
        return True
    stream = sys.stdout if stream is None else stream
    try:
        return bool(stream.isatty())
    except Exception:
        # A stream with no isatty() (or one that raises) is treated as non-interactive.
        return False


def paint(text: str, *styles: str, enabled: bool = True) -> str:
    """Wrap *text* in the given SGR *styles*, closing with a reset.

    A no-op when disabled, when *text* is empty, or when no (known) style is
    given — so callers can pass ``enabled=color`` unconditionally.
    """
    if not enabled or not text or not styles:
        return text
    codes = ";".join(_CODES[s] for s in styles if s in _CODES)
    if not codes:
        return text
    return f"{_ESC}{codes}m{text}{_ESC}0m"


def strip_ansi(text: str) -> str:
    """Remove the SGR sequences paint() emits, leaving plain text."""
    return _SGR_RE.sub("", text)
