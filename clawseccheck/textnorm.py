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


# ---------------------------------------------------------------------------
# Unicode Tag block (U+E0000–U+E007F) de-obfuscation (B-232).
#
# The Tag block is a set of "ASCII mirror" code points, invisible in virtually
# every font/renderer (no glyph is defined for them anywhere). U+E0020–U+E007E
# ("TAG SPACE" .. "TAG TILDE") each mirror ASCII 0x20–0x7E at a fixed offset
# (-0xE0000), so a complete ASCII message can be smuggled as an entirely
# invisible run of Tag characters ("ASCII smuggling" / invisible-Unicode prompt
# injection). Unicode's own NFKC compatibility decomposition does NOT map the
# Tag block to its ASCII mirror -- there is no compatibility-decomposition
# relationship defined for these code points -- so `unicodedata.normalize(
# "NFKC", ...)` leaves a Tag-encoded payload untouched: it is invisible AND
# NFKC-inert, and never reaches INJECTION_PATTERNS unless decoded here.
#
# LEGITIMATE USE (must not false-fire): regional/subdivision flag emoji (the
# Scotland / England / Wales flags, among others) are built from a black-flag
# base (U+1F3F4) followed by a short Tag-character run spelling an ISO 3166-2
# region code and terminated by U+E007F CANCEL TAG. See
# _is_tag_run_flag_subdivision below -- this is the one documented benign use
# of the block and is excluded from the WARN-worthy signal (though the
# characters are still folded/stripped either way, same as any other
# de-obfuscation pass).
# ---------------------------------------------------------------------------
_TAG_BLOCK_LO = 0xE0000
_TAG_BLOCK_HI = 0xE007F
_TAG_PRINTABLE_LO = 0xE0020  # TAG SPACE -> ASCII 0x20 ' '
_TAG_PRINTABLE_HI = 0xE007E  # TAG TILDE -> ASCII 0x7E '~'
_TAG_CANCEL = 0xE007F  # CANCEL TAG -- terminates a flag-subdivision run

# Fold table: printable Tag chars decode to their ASCII mirror (revealing a
# smuggled payload as plain, matchable text); the remaining non-printable Tag
# code points -- U+E0000 LANGUAGE TAG (deprecated), U+E0001 (deprecated), the
# unassigned U+E0002-E001F range, and CANCEL TAG itself -- fold to "" (i.e.
# stripped), the same treatment _INVISIBLE_RE already gives other invisible
# control ranges above.
_TAG_TABLE: dict[int, str] = {
    cp: (
        chr(cp - _TAG_BLOCK_LO)
        if _TAG_PRINTABLE_LO <= cp <= _TAG_PRINTABLE_HI
        else ""
    )
    for cp in range(_TAG_BLOCK_LO, _TAG_BLOCK_HI + 1)
}
_TAG_BLOCK_TABLE = str.maketrans(_TAG_TABLE)

_TAG_RUN_RE = re.compile("[\U000e0000-\U000e007f]+")

# Black-flag base code point for regional/subdivision flag emoji sequences.
_FLAG_BASE_CP = 0x1F3F4


def _is_tag_run_flag_subdivision(text: str, m: "re.Match[str]") -> bool:
    """True when the Tag-character run *m* is a legitimate regional/subdivision flag
    emoji sequence: immediately preceded by the black-flag base (U+1F3F4) and
    terminated by CANCEL TAG (U+E007F) -- the documented Unicode mechanism behind
    flags like Scotland/England/Wales. Any other Tag run (bare, not flag-anchored, or
    not CANCEL-terminated) is NOT exempted."""
    start = m.start()
    if start == 0 or ord(text[start - 1]) != _FLAG_BASE_CP:
        return False
    return ord(m.group()[-1]) == _TAG_CANCEL


def _has_suspicious_tag_run(text: str) -> bool:
    """True when *text* contains a Unicode Tag-block run that is NOT a legitimate
    flag-subdivision sequence (see _is_tag_run_flag_subdivision)."""
    for m in _TAG_RUN_RE.finditer(text):
        if not _is_tag_run_flag_subdivision(text, m):
            return True
    return False


# ---------------------------------------------------------------------------
# Emoji / pictographic codepoint ranges (B-088 / A3).
#
# unicodedata (stdlib) does not expose the Unicode "Extended_Pictographic"
# property, so this is a small, explicit range list covering the blocks that
# matter for detecting legitimate emoji ZWJ sequences (e.g. 🧑‍⚖️, family
# emoji, profession emoji). Not a complete emoji-property implementation —
# just enough to distinguish "ZWJ between two emoji" (benign) from "ZWJ
# splicing ASCII/other text" (obfuscation).
#
# Ranges (grounded in the Unicode emoji blocks):
#   U+1F300–1F5FF : Miscellaneous Symbols and Pictographs
#   U+1F600–1F64F : Emoticons
#   U+1F680–1F6FF : Transport and Map Symbols
#   U+1F700–1FAFF : Symbols/Pictographs Extended-A, Supplemental Symbols, etc.
#   U+2600–27BF   : Miscellaneous Symbols + Dingbats (☀ ✂ etc.)
#   U+2B00–2BFF   : Miscellaneous Symbols and Arrows (⭐ etc.)
#   U+1F000–1F0FF : Mahjong/Domino/Playing Cards (rare, but pictographic)
#   U+2190–21FF   : Arrows block (a few are used as emoji, e.g. ↔️ ↩️)
#   U+1F1E6–1F1FF : Regional indicator symbols (flag emoji pairs)
#   U+1F3FB–1F3FF : Emoji skin-tone modifiers (Fitzpatrick modifiers)
#   U+FE0F        : Variation Selector-16 (emoji presentation selector)
#   U+20E3        : Combining enclosing keycap (keycap emoji, e.g. 1️⃣)
#   U+1F9B0–1F9B3 : Emoji hair-style components (red hair, curly hair, ...)
# ---------------------------------------------------------------------------
_EMOJI_RANGES: tuple[tuple[int, int], ...] = (
    (0x1F300, 0x1F5FF),
    (0x1F600, 0x1F64F),
    (0x1F680, 0x1F6FF),
    (0x1F700, 0x1FAFF),
    (0x2600, 0x27BF),
    (0x2B00, 0x2BFF),
    (0x1F000, 0x1F0FF),
    (0x2190, 0x21FF),
    (0x1F1E6, 0x1F1FF),
    (0x1F3FB, 0x1F3FF),
    (0xFE0F, 0xFE0F),
    (0x20E3, 0x20E3),
    (0x1F9B0, 0x1F9B3),
)


def _is_emoji_codepoint(cp: int) -> bool:
    """True when *cp* (an integer code point) falls in one of the emoji /
    pictographic blocks in *_EMOJI_RANGES* — including emoji modifiers
    (skin tones, variation selector, keycap) that flank a ZWJ in real
    emoji ZWJ sequences (e.g. the skin-toned 🧑🏽‍⚖️).
    """
    return any(lo <= cp <= hi for lo, hi in _EMOJI_RANGES)


# Codepoints that are "emoji-adjacent" modifiers rather than emoji themselves
# — when scanning outward from a ZWJ, skip over these before checking
# whether the next real character is an emoji.
_EMOJI_MODIFIERS = frozenset({0xFE0F, *range(0x1F3FB, 0x1F400)})


def _is_zwj_between_emoji(chars: list[str], idx: int) -> bool:
    """True when the ZWJ at *chars[idx]* sits between two emoji code points,
    i.e. it is part of a legitimate emoji ZWJ sequence (professions, family
    groupings, skin-toned variants, etc.) rather than obfuscation splicing
    unrelated text.

    Skips over emoji modifiers (variation selector, skin-tone modifiers)
    immediately adjacent to the ZWJ before checking the flanking character,
    so ``🧑🏽‍⚖️`` (person + skin-tone + ZWJ + scales + VS-16) is recognised.
    """
    # Walk left, skipping modifiers, to find the nearest substantive char.
    left = idx - 1
    while left >= 0 and ord(chars[left]) in _EMOJI_MODIFIERS:
        left -= 1
    # Walk right, skipping modifiers, to find the nearest substantive char.
    right = idx + 1
    while right < len(chars) and ord(chars[right]) in _EMOJI_MODIFIERS:
        right += 1

    if left < 0 or right >= len(chars):
        return False  # ZWJ at start/end of string — never exempt

    return _is_emoji_codepoint(ord(chars[left])) and _is_emoji_codepoint(
        ord(chars[right])
    )


def normalize_for_scan(text: str) -> str:
    """Return a de-obfuscated copy of *text* suitable for pattern matching.

    Steps (in order):
      1. Strip invisible / bidi-control characters
         (U+200B–200D, U+FEFF, U+202A–202E, U+2060, U+2066–2069, U+00AD).
      2. NFKC normalization (collapses fullwidth, ligatures, etc.).
      3. Unicode Tag-block (U+E0000–E007F) fold/strip: printable Tag chars decode to
         their ASCII mirror (revealing an ASCII-smuggled payload); non-printable Tag
         code points are stripped. NFKC does not touch this block (see *_TAG_TABLE*),
         so it is handled explicitly here (B-232).
      4. Confusable folding: Cyrillic/Greek lookalikes → ASCII via
         *_CONFUSABLES* (see module-level dict).

    Read-only and lossy by design: the original *text* is never mutated.
    Hebrew characters (U+0590–05FF) are explicitly excluded from step 4.
    """
    stripped = _INVISIBLE_RE.sub("", text)
    nfkc = unicodedata.normalize("NFKC", stripped)
    tag_decoded = nfkc.translate(_TAG_BLOCK_TABLE)
    return tag_decoded.translate(_CONFUSABLES_TABLE)


def _has_suspicious_zero_width(text: str, zero_width_re: "re.Pattern[str]") -> bool:
    """True when *text* contains a zero-width / invisible char that is NOT
    explained away as part of a legitimate emoji ZWJ sequence (B-088 / A3).

    U+200B (zero-width space), U+FEFF (BOM), and U+2060 (word joiner) are
    always suspicious — there is no legitimate reason for them to appear in
    bootstrap/skill text. U+200D (ZWJ) is suspicious UNLESS it sits between
    two emoji code points (see *_is_zwj_between_emoji*), in which case it is
    a normal emoji ZWJ sequence (e.g. 🧑‍⚖️) and must not be flagged.

    Iterates over Python ``str`` code points directly (each element of a
    Python 3 ``str`` is already a full code point, astral chars included —
    no UTF-16 surrogate handling needed).
    """
    match = zero_width_re.search(text)
    if not match:
        return False

    chars = list(text)
    # Re-scan by code-point index so ZWJ neighbours can be inspected.
    for idx, ch in enumerate(chars):
        if not zero_width_re.match(ch):
            continue
        if ord(ch) == 0x200D and _is_zwj_between_emoji(chars, idx):
            continue  # legitimate emoji ZWJ sequence — not suspicious
        return True
    return False


def obfuscation_signals(text: str) -> list[str]:
    """Return human-readable evidence strings for each class of de-obfuscation
    that *changed* the text.  Returns an empty list when the text is clean.

    Signal categories (all checked independently):
      - "zero-width / invisible characters found" — invisible chars stripped
      - "bidi-override / embedding controls found" — bidi controls stripped
      - "Unicode Tag-block characters found" — Tag-block (U+E0000-E007F) run present,
        not explained away as a legitimate flag-subdivision emoji sequence (B-232)
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

    if _has_suspicious_zero_width(text, _ZERO_WIDTH_RE):
        signals.append("zero-width / invisible characters found")
    if _BIDI_RE.search(text):
        signals.append("bidi-override / embedding controls found")
    if _has_suspicious_tag_run(text):
        signals.append("Unicode Tag-block characters found")

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


def _nfkc_ascii_fold_changed(text: str) -> bool:
    """True when NFKC-normalizing some word-token of *text* turns it into a
    DIFFERENT, purely-ASCII string -- i.e. the token is spelled in a non-ASCII
    Unicode form (fullwidth, Mathematical Alphanumeric Symbols bold/italic/
    fraktur/sans-serif, etc.) whose canonical Unicode identity IS an ASCII
    letter/digit, just presented in another width or style.

    This is a broader, non-enumerated companion to `confusable_in_ascii_context`'s
    curated Cyrillic/Greek table: it needs no per-block list because "NFKC
    compatibility-decomposes to plain ASCII" is exactly what those blocks are
    FOR by Unicode's own design (fullwidth forms and the Mathematical
    Alphanumeric Symbols block exist precisely as compatibility-equivalent
    stylistic variants of ASCII) -- so one generic check covers the whole
    class instead of chasing individual blocks (fullwidth today, some other
    block tomorrow).

    Genuine non-Latin scripts are NOT compatibility-equivalent to ASCII under
    NFKC -- real Cyrillic/Greek/CJK letters do not decompose to Latin at all,
    which is precisely why `confusable_in_ascii_context` needs its own curated
    lookalike table instead of relying on NFKC for THAT class of homoglyph.
    So whole-script legitimate prose is never swept in by this signal; only
    characters whose Unicode identity already IS an ASCII letter/digit trigger
    it.

    Tokenized the same way as `confusable_in_ascii_context` (`\\w+`, UNICODE,
    after stripping invisibles) so both signals see the same candidate spans.
    Read-only, stdlib-only.
    """
    stripped = _INVISIBLE_RE.sub("", text)
    for token in re.findall(r"\w+", stripped, re.UNICODE):
        if token.isascii():
            continue  # nothing non-ASCII to fold
        folded = unicodedata.normalize("NFKC", token)
        if folded != token and folded.isascii():
            return True
    return False
