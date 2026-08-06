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

# ---------------------------------------------------------------------------
# Merge the Tag-block fold table and the confusables table into ONE translate
# table, so normalize_for_scan does a single `.translate` pass instead of two
# (str.translate is a hot spot on large blobs -- merging the tables removes an
# entire full-string pass with no change in output).
#
# Semantically identical to the old sequential `.translate(_TAG_BLOCK_TABLE)`
# then `.translate(_CONFUSABLES_TABLE)`:
#   1. Key domains are disjoint: _TAG_TABLE keys are U+E0000-E007F; _CONFUSABLES
#      keys are U+03xx/U+04xx (`set(_TAG_TABLE) & set(_CONFUSABLES) == set()`).
#   2. Sequential-vs-merged application differs only if the SECOND table is
#      non-identity somewhere in the first table's OUTPUT range. _TAG_TABLE's
#      output is exactly ASCII 0x20-0x7E plus deletions; _CONFUSABLES is the
#      identity on the whole of ASCII -- its minimum key is U+03B1 (0x3B1),
#      i.e. `all(k >= 128 for k in _CONFUSABLES)`. So applying _CONFUSABLES
#      after the Tag fold can never touch what the Tag fold just produced,
#      which is exactly what a single merged-table pass also guarantees.
# Verified further by a 20k-string seeded fuzz (old two-pass vs merged
# .translate) in tests/test_textnorm.py.
#
# `{**a, **b}` rather than `a | b` -- dict-merge `|` exists since 3.9, but the
# unpack form is unambiguous about "no keys collide" at a glance.
_NORM_TABLE = str.maketrans({**_TAG_TABLE, **_CONFUSABLES})

# Hebrew block guard (U+0590-U+05FF), extended to _NORM_TABLE -- the table
# actually applied by normalize_for_scan now that A2 merged the two passes --
# so the invariant belongs here too, not just on the raw _CONFUSABLES dict
# above. No code point in this range may ever be a translate key, or RTL /
# Hebrew bootstrap files would be silently corrupted.
assert all(0x0590 > cp or cp > 0x05FF for cp in _NORM_TABLE), (
    "textnorm._NORM_TABLE must never include Hebrew block U+0590–05FF"
)

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


# ---------------------------------------------------------------------------
# Module-level, content-keyed memo for normalize_for_scan on large blobs. The
# same multi-megabyte skill/bootstrap blobs get re-normalized call after call
# across the many checks that each independently normalize the same content
# (plus a per-skill content-security ring that re-scans those same blobs
# again), so the total characters normalized in a run can run many times over
# the actual size of the corpus being scanned.
#
# Keyed by the STRING ITSELF, never by id(). CPython can and does reuse a
# freed string's memory address for an unrelated object; keying by id() would
# let a later, different blob silently inherit an earlier blob's cached
# normalization -- in a security scanner that is a live mine, not a
# performance trade-off. A plain dict already compares/hashes str keys by
# content, so this is the natural, not the clever, choice.
#
# _NORM_MEMO_MIN_CHARS: below this, the memo lookup/insert overhead (hashing
# the whole string) is not worth it -- measured: caching everything (no
# threshold) or a 4 KiB threshold both cost MORE wall-clock than a 64 KiB
# threshold, because thousands of small entries buy nothing (the win lives
# entirely in a handful of megabyte-scale blobs) while still paying full
# hashing cost on every call. This value also structurally excludes
# logscan.py's per-line scanning path: logscan._MAX_LINE_LEN caps every line
# it hands to normalize_for_scan at 8000 chars, well under this threshold, so
# that hot per-line path never touches the memo at all -- no call-site change
# needed there.
#
# _NORM_MEMO_MAX_CHARS: total retained-character BUDGET across every admitted
# entry (not a per-string cap) -- a hard ceiling on how much normalized text
# this process holds onto for its lifetime. Real-config measurement: ~4.1 MB
# retained across 5 entries at the 64 KiB threshold.
_NORM_MEMO_MIN_CHARS = 65_536
_NORM_MEMO_MAX_CHARS = 64_000_000

# Admit-until-full, NO eviction -- deliberate, not a missing feature. Every
# check walks ctx.installed_skills / ctx.bootstrap in the same order, so a
# FIFO/LRU cache filled to capacity would evict exactly the entry the very
# next check needs, converging to ~0% hit rate on a large corpus. Admit-until-
# full instead degrades gracefully (the first K blobs encountered stay fast;
# anything beyond the budget is simply computed at today's cost, same as
# having no memo) and gives a one-number memory ceiling.
_NORM_MEMO: dict[str, str] = {}
_NORM_MEMO_CHARS = 0


def _norm_memo_clear() -> None:
    """Reset the module-level normalize_for_scan memo. Test-only: lets tests start
    from a clean slate instead of leaking cached blobs across test cases (the memo
    is otherwise process-lifetime by design -- see _NORM_MEMO above)."""
    global _NORM_MEMO_CHARS
    _NORM_MEMO.clear()
    _NORM_MEMO_CHARS = 0


def _normalize_uncached(text: str) -> str:
    """Do the actual de-obfuscation work for *text* -- see normalize_for_scan (the
    public entry point) for the ASCII fast-path and content-keyed memo wrapped
    around this.

    Steps (in order):
      1. Strip invisible / bidi-control characters
         (U+200B–200D, U+FEFF, U+202A–202E, U+2060, U+2066–2069, U+00AD).
      2. NFKC normalization (collapses fullwidth, ligatures, etc.).
      3. Unicode Tag-block (U+E0000–E007F) fold/strip AND confusable folding
         (Cyrillic/Greek lookalikes → ASCII), applied together in a single
         `.translate(_NORM_TABLE)` pass (see *_NORM_TABLE* for why merging the
         two translate tables into one is safe). Printable Tag chars decode
         to their ASCII mirror (revealing an ASCII-smuggled payload);
         non-printable Tag code points are stripped. NFKC does not touch the
         Tag block (see *_TAG_TABLE*), so it is handled explicitly here
         (B-232).

    Read-only and lossy by design: the original *text* is never mutated.
    Hebrew characters (U+0590–05FF) are explicitly excluded from confusable
    folding (see the assert next to *_NORM_TABLE*).
    """
    stripped = _INVISIBLE_RE.sub("", text)
    nfkc = unicodedata.normalize("NFKC", stripped)
    return nfkc.translate(_NORM_TABLE)


def normalize_for_scan(text: str) -> str:
    """Return a de-obfuscated copy of *text* suitable for pattern matching.

    Two optimizations wrap the real work, done in *_normalize_uncached* -- see
    its docstring for the actual steps:

      - ASCII fast-path: every step of *_normalize_uncached* is the identity
        transform on a pure-ASCII string (``_INVISIBLE_RE``'s lowest target is
        U+00AD; ASCII is NFKC-stable; every ``_NORM_TABLE`` key is >= U+03B1) --
        proven exhaustively over all 128 code points, not sampled. So a pure-
        ASCII *text* is returned AS-IS: same object, no copy (safe -- Python
        `str` is immutable, and every caller only uses the result for offsets
        within itself).
      - Content-keyed memo: blobs of at least *_NORM_MEMO_MIN_CHARS* are looked
        up / stored in *_NORM_MEMO* by their own content (see that module-level
        comment for why -- never by `id()`) up to the *_NORM_MEMO_MAX_CHARS*
        retained-character budget, admit-until-full with no eviction. A short
        non-ASCII string, or any ASCII string (caught by the fast-path first),
        never touches the memo. Call `_norm_memo_clear()` to reset it.
    """
    if text.isascii():
        return text
    n = len(text)
    if n < _NORM_MEMO_MIN_CHARS:
        return _normalize_uncached(text)
    cached = _NORM_MEMO.get(text)
    if cached is not None:
        return cached
    result = _normalize_uncached(text)
    global _NORM_MEMO_CHARS
    if _NORM_MEMO_CHARS + n <= _NORM_MEMO_MAX_CHARS:
        _NORM_MEMO[text] = result
        _NORM_MEMO_CHARS += n
    return result


def _has_suspicious_zero_width(text: str, zero_width_re: "re.Pattern[str]") -> bool:
    """True when *text* contains a zero-width / invisible char that is NOT
    explained away as part of a legitimate emoji ZWJ sequence (B-088 / A3).

    Every code point *zero_width_re* matches is unconditionally suspicious --
    see the class comment above ``_ZERO_WIDTH_RE`` in *obfuscation_signals* for
    the full, curated list (B-450) and why each member has no honest use in
    agent-facing text -- with exactly ONE exception: U+200D (ZWJ) is suspicious
    UNLESS it sits between two emoji code points (see *_is_zwj_between_emoji*),
    in which case it is a normal emoji ZWJ sequence (e.g. 🧑‍⚖️) and must
    not be flagged.

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

    # ------------------------------------------------------------------------
    # B-450 (Tier 1): the "zero-width / invisible characters found" class below.
    # EVERY downstream consumer of this signal -- C-038's MCP tool-description
    # band, B349's install-time dependency-tree targets, the skill content ring,
    # B58 -- runs ONLY if this class matches, so a code point missing here is
    # invisible to the whole engine, not just to this function.
    #
    # ORIGINAL SIX (pre-B-450): U+200B-200D (ZWSP/ZWNJ/ZWJ), U+FEFF (BOM),
    # U+00AD (soft hyphen), U+2060 (word joiner).
    #
    # TIER 1 ADDED HERE -- format characters (Unicode category Cf) with no
    # honest use in agent-facing prose, unconditionally suspicious like the
    # original six (no per-character exemption needed, unlike U+200D below):
    #   U+2061-2064 : FUNCTION APPLICATION, INVISIBLE TIMES, INVISIBLE SEPARATOR,
    #                 INVISIBLE PLUS -- mathematical-notation invisibles, the
    #                 immediate neighbours of U+2060 WORD JOINER (already in the
    #                 class) and strictly LESS legitimate in a tool description
    #                 than it is. This is the must-have: a two-symbol
    #                 substitution channel over U+2062/U+2063 alone carried a
    #                 44-char exfiltration directive as 352 invisible code points
    #                 through `vet_mcp` with verdict PASS and no finding at all.
    #   U+FFF9-FFFB : interlinear annotation anchor/separator/terminator -- a
    #                 deprecated Unicode mechanism with no rendering support in
    #                 any mainstream font/terminal; nothing in agent-facing text
    #                 has a legitimate reason to carry one.
    #   U+206A-206F : deprecated format controls (inhibit/activate symmetric
    #                 swapping, inhibit/activate Arabic-form shaping,
    #                 national/nominal digit shapes) -- formally deprecated by
    #                 Unicode since version 6.3.0; the replacement markup
    #                 mechanism carries no reason to appear in a tool
    #                 description or bootstrap file either.
    #   U+180E      : MONGOLIAN VOWEL SEPARATOR -- category Cf (format,
    #                 invisible) since Unicode 10.0; no honest reason to appear
    #                 outside literal Mongolian text runs, and never in an MCP
    #                 tool description or install-time target.
    #
    # TIER 2 -- DELIBERATELY DEFERRED, NOT IN THIS CLASS (record only; do not
    # add without the per-character discriminator described below):
    #   U+FE00-FE0F : variation selectors. Legitimate and PERVASIVE here --
    #                 U+FE0F alone is what turns a base glyph into emoji
    #                 presentation (an emoji heart, warning sign or check mark
    #                 each carry it), so a bare presence signal would false-fire
    #                 on ordinary emoji-using prose across the whole engine
    #                 (B58, the content ring, C-038).
    #   U+2800      : BRAILLE PATTERN BLANK -- legitimate whenever real Braille
    #                 text is present (a blank cell inside a Braille run),
    #                 indistinguishable from an invisible-channel member without
    #                 knowing whether it sits among other Braille Patterns code
    #                 points (U+2800-28FF).
    #   U+3164, U+FFA0 : HANGUL FILLER / HALFWIDTH HANGUL FILLER -- legitimate
    #                 as Hangul jamo composition placeholders in real Korean
    #                 text.
    #   Sound direction for a future Tier 2: count the code point, but excuse it
    #   per character when it sits among genuinely related script/emoji context
    #   -- not a bare presence class. `_is_emoji_codepoint` (above) and
    #   `_is_zwj_between_emoji`'s flanking-character check are the existing
    #   precedent for that shape; adding Tier 2 to this class without one would
    #   just move the false-positive class B-450 was scoped to avoid (punishing
    #   an ordinary emoji/Korean/Braille user) onto these code points instead.
    # ------------------------------------------------------------------------
    _ZERO_WIDTH_RE = re.compile(
        "[­᠎​-‍⁠-⁤⁪-⁯﻿￹-￻]"
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


# ---------------------------------------------------------------------------
# Output-side ASCII folding (--ascii)
#
# The counterpart to the input-side normalization above: this folds the unicode
# THIS TOOL EMITS down for a console that cannot render it. Deliberately a
# separate table from `_CONFUSABLES` — that one exists to defeat an attacker's
# homoglyph obfuscation on untrusted input, this one exists so a legacy terminal
# still reads our own prose.
#
# B-483: it lives here, in the leaf, because there were SIX ascii-folding sites
# in the package and only two of them applied a mapping table at all — the other
# four did a bare `.encode("ascii", "replace")`, so every em dash, ellipsis and
# arrow in `--self-test`, `--dryrun`, `--multiturn`, `--next` and the PDF came
# out as a literal `?`. Measured: 60 lines of `--self-test --ascii` output,
# including the harness material an operator pastes to their agent
# (`[UNTRUSTED INPUT ? simulated email body]`). The two sites that DID map had
# drifted into two different tables. One table, one function, one import.
ASCII_MAP = str.maketrans({
    # dashes / spacing punctuation (escapes, not literals: a non-breaking and a thin
    # space are indistinguishable in source and one shadows the other silently)
    "—": "-", "–": "-", "‑": "-", "‒": "-", "―": "-",
    "\u00a0": " ", "\u2009": " ", "\u202f": " ",
    # separators used as list/field dividers in our own output
    "·": "-", "•": "*", "‣": "*", "▪": "*",
    # quotes
    "’": "'", "‘": "'", "‚": "'", "“": '"', "”": '"', "„": '"',
    # math / comparison
    "×": "x", "÷": "/", "≤": "<=", "≥": ">=", "≈": "~", "≠": "!=", "±": "+/-",
    "\u2212": "-",  # MINUS SIGN — pdf.py's one entry this table lacked
    # arrows
    "→": "->", "←": "<-", "↔": "<->", "⇒": "=>",
    # misc prose
    "…": "...", "§": "S", "©": "(c)", "®": "(r)", "™": "(tm)", "°": " deg",
    "½": "1/2", "¼": "1/4", "¾": "3/4",
})


def asciify(text: str) -> str:
    """Fold the unicode we emit down to pure ASCII for legacy consoles.

    Anything with no sensible ASCII spelling still becomes `?` — that is the
    honest outcome for a glyph the console cannot show, and callers that own a
    real ASCII alternative (icon tables, box-drawing rules) are expected to
    substitute it BEFORE calling this, exactly as they already do. This is the
    backstop, not the first line."""
    return text.translate(ASCII_MAP).encode("ascii", "replace").decode("ascii")
