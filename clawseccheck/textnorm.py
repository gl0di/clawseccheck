"""Unicode de-obfuscation pre-pass for ClawSecCheck content scanning.

Provides two public functions:
  normalize_for_scan(text) -- NFKC-fold + strip invisibles + confusable map
  obfuscation_signals(text) -- human-readable evidence of de-obfuscation changes

Stdlib-only (unicodedata, re). Leaf module: no imports from other
clawseccheck modules (avoids the circular-import risk).

CRITICAL: never folds Hebrew U+0590–05FF — those code points are explicitly
excluded from _CONFUSABLES so RTL / Hebrew bootstrap files are never corrupted.
"""
from __future__ import annotations

import re
import unicodedata

# ---------------------------------------------------------------------------
# Invisible / bidi-control characters to strip before NFKC fold.
# Ranges:
#   U+200B–200D  : zero-width space, ZWNJ, ZWJ
#   U+FEFF       : BOM / zero-width no-break space (common in injected text)
#   U+00AD       : soft hyphen (invisible in most renderers)
#   U+202A–202E  : LRE, RLE, PDF, LRO, RLO (bidi embedding/override)
#   U+2060       : word joiner (invisible)
#   U+2066–2069  : LRI, RLI, FSI, PDI (Unicode 6.3 bidi isolates)
# ---------------------------------------------------------------------------
_INVISIBLE_RE = re.compile(
    "["
    "​-‍"   # zero-width space / ZWNJ / ZWJ
    "﻿"           # BOM / ZWNBSP
    "­"           # soft hyphen
    "‪-‮"   # bidi embedding/override controls
    "⁠"           # word joiner
    "⁦-⁩"   # bidi isolates
    "]"
)

# ---------------------------------------------------------------------------
# Curated confusable map: Cyrillic/Greek lookalikes -> ASCII equivalents.
# MUST NOT include any code point in U+0590–05FF (Hebrew block).
#
# Groundings:
#   Cyrillic small а U+0430, е U+0435, о U+043E, р U+0440, с U+0441,
#   х U+0445, ѕ U+0455, і U+0456 (Ukrainian/Belarusian і)
#   Greek letters: ο (omicron) U+03BF, α U+03B1
# ---------------------------------------------------------------------------
_CONFUSABLES: dict[int, str] = {
    # Cyrillic confusables
    0x0430: "a",   # Cyrillic small а → ASCII a
    0x0435: "e",   # Cyrillic small е → ASCII e  (THE injection evasion char)
    0x043E: "o",   # Cyrillic small о → ASCII o
    0x0440: "p",   # Cyrillic small р → ASCII p
    0x0441: "c",   # Cyrillic small с → ASCII c
    0x0445: "x",   # Cyrillic small х → ASCII x
    0x0455: "s",   # Cyrillic small ѕ → ASCII s
    0x0456: "i",   # Cyrillic/Ukrainian і → ASCII i
    # Greek confusables
    0x03B1: "a",   # Greek small α → ASCII a
    0x03BF: "o",   # Greek small ο (omicron) → ASCII o
}
# Build a str.translate table from the dict.
_CONFUSABLES_TABLE = str.maketrans(_CONFUSABLES)

# ---------------------------------------------------------------------------
# Hebrew block guard (U+0590–U+05FF).  No code point in this range appears
# in _CONFUSABLES — this assertion catches a future edit that accidentally
# adds one.
# ---------------------------------------------------------------------------
assert all(0x0590 > cp or cp > 0x05FF for cp in _CONFUSABLES), (
    "textnorm._CONFUSABLES must never include Hebrew block U+0590–05FF"
)


def normalize_for_scan(text: str) -> str:
    """Return a de-obfuscated copy of *text* suitable for pattern matching.

    Steps (in order):
      1. Strip invisible / bidi-control characters
         (U+200B–200D, U+FEFF, U+202A–202E, U+2060, U+2066–2069, U+00AD).
      2. NFKC normalization (collapses fullwidth, ligatures, etc.).
      3. Confusable folding: Cyrillic/Greek lookalikes → ASCII via
         *_CONFUSABLES* (see module-level dict).

    Read-only and lossy by design: the original *text* is never mutated.
    Hebrew characters (U+0590–05FF) are explicitly excluded from step 3.
    """
    stripped = _INVISIBLE_RE.sub("", text)
    nfkc = unicodedata.normalize("NFKC", stripped)
    return nfkc.translate(_CONFUSABLES_TABLE)


def obfuscation_signals(text: str) -> list[str]:
    """Return human-readable evidence strings for each class of de-obfuscation
    that *changed* the text.  Returns an empty list when the text is clean.

    Signal categories (all checked independently):
      - "zero-width / invisible characters found" — invisible chars stripped
      - "bidi-override / embedding controls found" — bidi controls stripped
      - "confusable characters folded to ASCII" — confusable map applied
    """
    signals: list[str] = []

    # Check invisible chars (zero-width, soft hyphen, BOM, word joiner).
    _ZERO_WIDTH_RE = re.compile(
        "[​-‍﻿­⁠]"
    )
    _BIDI_RE = re.compile(
        "[‪-‮⁦-⁩]"
    )

    if _ZERO_WIDTH_RE.search(text):
        signals.append("zero-width / invisible characters found")
    if _BIDI_RE.search(text):
        signals.append("bidi-override / embedding controls found")

    # Check whether confusable folding would change the NFKC-normalized text.
    nfkc = unicodedata.normalize("NFKC", _INVISIBLE_RE.sub("", text))
    if nfkc.translate(_CONFUSABLES_TABLE) != nfkc:
        signals.append("confusable characters folded to ASCII")

    return signals


_ASCII_LATIN = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")


def confusable_in_ascii_context(text: str) -> bool:
    """True when a confusable char (Cyrillic/Greek lookalike that folds to ASCII) sits in
    the SAME word-token as plain ASCII-Latin letters — i.e. a homoglyph swapped into an
    otherwise-Latin word (e.g. ``іgnore``, ``оriginally``).

    Whole-script non-Latin runs (legitimate i18n like ``Привет`` or ``Ελληνικά``) contain
    no ASCII-Latin letters within the token, so they are NOT flagged — this is what keeps
    B58 from false-firing on multilingual prose while still catching homoglyph substitution
    inside Latin-context text. Read-only, stdlib-only.
    """
    stripped = _INVISIBLE_RE.sub("", text)
    for token in re.findall(r"\w+", stripped, re.UNICODE):
        if not any(ch in _ASCII_LATIN for ch in token):
            continue  # whole non-Latin (or all-digit) token — benign i18n, not a mix
        if any(ord(ch) in _CONFUSABLES for ch in token):
            return True
    return False
