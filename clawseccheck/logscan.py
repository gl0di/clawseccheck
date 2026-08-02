"""Bounded, redacted content scanner for the agent's own log sinks (E-044 Phase 1 substrate).

Reuses the check engine's OWN vetted indicator regexes — never invents a new secret /
exfil / injection pattern (design doc §2, §6: growing the regex surface grows the ReDoS
attack surface too, C-214/B-192 precedent). This is the SAME cross-package import shape
``logsafe.py`` already uses for ``SECRET_PATTERNS``/``SECRET_KEY_RE``
(``from .checks import SECRET_KEY_RE, SECRET_PATTERNS``): ``checks/__init__.py``
deliberately never imports ``logsafe``/this module at its own top level (several checks/
topic modules import ``logsafe`` LAZILY inside function bodies for exactly this reason —
see ``checks/_vet.py``'s comment on it), so importing the aggregator from this Layer-1 leaf
does not cycle.

§8-style privacy boundary: every sample string this module RETURNS has already been passed
through ``logsafe.redact()`` — a caller must never see raw log content, only redacted
evidence + counts. For trajectory-sidecar files specifically, classes 3 (dangerous
capability) and 5 (anomaly/tamper) read ONLY envelope/metadata fields (``type``, ``name``,
``seq``, ``ts``, ``traceSchema``, ``schemaVersion``) — never ``data.arguments``/``output``/
``result``/``contentItems`` (mirrors ``trajectory.py``/``behavioral.py``'s own contract).
Classes 1/2/4/6 are a plain-text scan applied uniformly to every sink kind (including
trajectory files, whose raw JSONL lines can of course also carry a leaked secret or an
injected instruction in a tool argument) — this mirrors ``trajaudit.py``'s Dave-ratified
precedent of reading trajectory ``data.arguments`` in memory ONLY to test membership of an
already-vetted indicator, never to extract or echo the payload itself.

DoS guards (first-class, per the design doc §6 / the B-192 lesson): a per-file byte cap
(~2 MiB) stops reading and marks ``truncated``; an over-long single line is skipped (never
regex-matched) and also marks ``truncated``; a cooperative per-file wall-clock deadline
(reusing ``scanbudget``'s own monotonic-deadline helpers — the same ones ``run_all`` uses
for its outer per-audit cap) marks ``timed_out`` and stops early.

C-327: a base64 blob whose decoded bytes are themselves a gzip/zlib stream (the HF
agent-intrusion precedent — ``exec(gzip.decompress(base64.b64decode(...)))`` packed
payloads, chosen specifically to defeat a naive text scan) is decompressed ONE layer
deeper and the recovered text is re-scanned with the SAME indicator regexes every
ordinary line already goes through. This is a decompression-bomb sink risk by
construction (a few compressed KB can claim to be gigabytes), so it is bounded the same
way collector.py's own archive unpacking already bounds gzip/bz2/xz/zip expansion (that
DoS class is on record here too — an unbounded expansion in EffectSimulator crashed the
desktop three times via OOM before it was capped): a hard per-blob output-byte cap
(``_MAX_DECODED_BLOB_BYTES``) enforced by STREAMING reads/decompress calls that are
capped as bytes are produced, never by decompressing first and measuring after; a cap
on the number of candidate blobs tried per line (``_MAX_BLOBS_PER_LINE``); and no
recursion into a further layer found inside the decompressed text (one layer only, per
this task's explicit scope — see ``_scan_line_content``'s ``allow_blob_decode``
parameter). Reaching the per-blob cap marks ``blob_decode_truncated``/``truncated`` and
simply stops reading that blob; it never raises. A malformed/truncated compressed
stream is caught and treated as "not decompressible", also never raising. There is
still no HARD (SIGALRM) per-file timeout here, but the reason has changed and is worth
stating plainly,
because the old one no longer holds: nesting a second ``scanbudget.check_deadline`` inside
this function used to be actively unsafe — the check that calls this
(``check_log_threat_hunt``, B164) runs inside ``run_all``'s own per-check itimer, and the
context manager disarmed ``SIGALRM`` unconditionally on exit, so a nested block would have
deleted run_all's hard cap for the rest of the check rather than bounding this call.
``check_deadline`` is now re-entrant (a stack of absolute deadlines; an inner block is
clamped to the outer's remaining time and the outer is restored on exit), so that hazard is
gone and a per-file hard timeout COULD be wired up here. It simply has not been: the
cooperative deadline already bounds this loop, which reads files line by line and yields to
Python constantly, so there is nothing here a hard timer could interrupt that the
cooperative one cannot. Adding one would be a behaviour change needing its own
adversarial review, not a free upgrade.
"""
from __future__ import annotations

import base64
import binascii
import gzip
import io
import json
import zlib
from dataclasses import dataclass, field
from datetime import datetime

from . import attest
from . import logsafe as _logsafe
from .checks import (
    LOG_SCAN_INJECTION_PATTERNS,
    SECRET_PATTERNS,
    _B64_BLOB_RE,
    _B64URL_BLOB_RE,
    _CRED_RE,
    _EXFIL_RE,
    _KNOWN_EXFIL_HOST_RE,
    _SECRET_PATH_RE,
)
# B-383 item 3: `_read_with_limit` is collector.py's own streaming byte-cap read loop
# (proven there against a real decompression-bomb DoS while unpacking a skill archive) —
# this module used to duplicate the identical algorithm as `_read_stream_capped` rather
# than import it, risking a future cap-arithmetic fix landing on only one copy. Reused
# directly, under this module's existing private name, per the same cross-package
# private-helper-import shape `checks/_shared.py` already uses for collector.py helpers
# (`_escape_embedded_header_lines`, `_is_own_source`, ...). collector.py does not import
# this module (or checks/), so there is no import cycle.
from .collector import _read_with_limit as _read_stream_capped
from .logdiscovery import LogSink
from .scanbudget import audit_budget_exceeded
from .textnorm import normalize_for_scan

_MAX_BYTES_PER_FILE = 2 * 1024 * 1024  # ~2 MiB per-file read cap (DoS guard)
_MAX_LINE_LEN = 8000  # a line longer than this gets WINDOWED (see _OVERSIZED_WINDOW_CHARS
# below), never fully regex-matched. DO NOT RAISE THIS: it is the DoS/ReDoS bound the
# B-192 OOM lesson and C-214 exist to enforce (a real 225,191-char trajectory line has
# been observed on the real fleet) — the fix here is to stop SKIPPING an oversized line
# outright, not to widen how much of it gets regex-matched.

# B-285/LOG-1: measured on the real fleet (73 trajectory files, 3,896 lines, 33.8 MB),
# 769 lines (86.8% of the corpus BY VOLUME) exceeded _MAX_LINE_LEN and were skipped with
# ZERO regex matching — the largest tool outputs (a fetched page, an MCP dump) are
# exactly where an indirect-injection payload lives, and they were exactly what got
# dropped. Instead of skipping, scan a BOUNDED window at each end of the line: the first
# and last _OVERSIZED_WINDOW_CHARS characters, via two independent calls to the SAME
# `_scan_line_content` every ordinary line already goes through — never the full
# battery over the whole line. Total chars actually regex-scanned per oversized line is
# therefore capped at 2 * _OVERSIZED_WINDOW_CHARS <= _MAX_LINE_LEN, i.e. never MORE than
# the per-line regex-cost budget an ordinary max-length line already costs today — this
# is why windowing does not reopen the DoS bound the cap exists for. A payload is only
# guaranteed to be caught when it is FULLY CONTAINED within one of the two windows
# (line[:W] or line[-W:]); this leaves TWO gaps, not one — (a) a payload placed entirely
# outside both windows (i.e. in the unscanned span between them), and (b) a payload that
# STRADDLES a window's edge (starts inside a window but extends past it, so the window
# slice cuts the match string in half and the regex never sees the full pattern in
# either call) — the second gap can bite even a few characters into an otherwise-covered
# line, not just "the middle" of a huge one. Both are an honest, documented limitation,
# not a defect (see scan_log_file's truncation note, which now describes both gaps
# rather than naming only the first) — and it is DELIBERATELY not the fix for RT-1/F-133
# (a field-scoped `context.compiled` reader): windowing bounds cost, it does not make
# full-battery scanning of a 60KB+ line safe.
#
# Window size measured, not guessed: at window=4000 (half of _MAX_LINE_LEN), the real
# fleet's `check_log_threat_hunt` (B164) wall-clock over all 73 trajectory sinks rose
# from ~7.6s (before this fix) to ~13-14s — uncomfortably close to `scanbudget`'s
# per-check hard budget (`DEFAULT_CHECK_BUDGET_S`, 15s: a check that exceeds it gets
# SIGALRM-interrupted mid-scan and degrades to UNKNOWN, losing the very coverage this
# fix adds). 3000 gives a comfortable margin (~10.6s measured, ~30%+ headroom) while
# losing only 1 of 46 real-fleet corroborated sinks versus window=4000 — a good trade,
# not a guess (see the task's real-fleet re-measurement for the full window-size sweep).
_OVERSIZED_WINDOW_CHARS = 3000  # first 3000 + last 3000 chars
_MAX_SAMPLES_PER_CLASS = 5

# C-327: bounded gzip/zlib decode depth for a base64 blob (see the module docstring's
# DoS-guards paragraph). Independent of every OTHER cap in this module because it bounds
# a different resource: `_MAX_BYTES_PER_FILE` bounds bytes *read*; `_MAX_LINE_LEN` bounds
# chars *regex-matched* in one call; this pair bounds bytes a single decompress call may
# *produce* and how many such calls one line may trigger — a decompression bomb's whole
# point is a tiny input claiming a huge output, so an input-side cap alone cannot bound it.
_MAX_DECODED_BLOB_BYTES = 262_144  # 256 KiB hard streaming-output cap per blob — a
# fraction of the whole-file byte cap on purpose: this bounds ONE embedded blob, not the
# file, and the indicator regexes only need to SEE a payload once, never hold an
# unbounded copy of it.
_MAX_BLOBS_PER_LINE = 4  # candidate base64 blobs tried per line/window — bounds how many
# decompression attempts one adversarial line stuffed with blob-shaped runs can force.

# Trajectory schema anchors (mirrors trajectory.py's own grounded constants — recon §9.1).
_TRACE_SCHEMA = "openclaw-trajectory"
_SCHEMA_VERSION = 1

SIGNAL_CLASSES = (
    "injection_against_agent",
    "exfil_evidence",
    "dangerous_capability",
    "env_compromise_ioc",
    "anomaly_tamper",
    "secrets_at_rest",
)


@dataclass
class LogScanResult:
    sink: LogSink
    counts: dict = field(default_factory=dict)  # signal_class -> hit count
    samples: list = field(default_factory=list)  # REDACTED "class: snippet" strings, capped
    truncated: bool = False
    bytes_scanned: int = 0
    timed_out: bool = False
    skill_ioc_hits: dict = field(default_factory=dict)  # normalized-tok -> count (C-221)
    # B-285/LOG-1: quantified oversized-line disclosure (see _OVERSIZED_WINDOW_CHARS
    # above). `truncated` alone used to be the only signal, and it fired for two very
    # different reasons (the per-file byte cap, and a per-line skip) with no way to tell
    # which, or how much was actually affected — `byte_cap_truncated` disambiguates the
    # former; these three fields quantify the latter.
    byte_cap_truncated: bool = False  # this file's per-file byte cap (not a line) fired
    oversized_lines: int = 0  # count of lines that exceeded _MAX_LINE_LEN
    oversized_line_chars: int = 0  # total char length of those oversized lines
    unscanned_middle_chars: int = 0  # chars between the two windows, never regex-scanned
    # C-327: disambiguates a bounded-decompression-bomb cap hit (a base64 blob's
    # gzip/zlib layer produced more than _MAX_DECODED_BLOB_BYTES) from every other
    # reason `truncated` can be True — mirrors how `byte_cap_truncated` already
    # disambiguates the whole-file byte cap from a per-line skip.
    blob_decode_truncated: bool = False
    # I-025/B-309 (RETRACTED, C-135 8th round, Dave's 2026-07-22 ruling): this project
    # tried, across four rounds (follow-ups #1-#4), to make the same-line
    # SECRET_PATTERNS + _EXFIL_RE pairing above ("exfil_evidence") sound enough to CAP
    # the A-F grade — first by requiring a named drop-host, then an independent
    # transport verb, then narrowing to an "attacker-exclusive" OOB/canary host set.
    # THREE independent adversarial reviews of the final attempt converged: no
    # enumerable host set is both narrow enough to exclude dual-use developer tooling
    # (ngrok/pastebin/webhook.site) and broad enough to still catch real exfiltration,
    # because this tool's OWN AUDIENCE (security-conscious operators) legitimately
    # sends secrets to the exact OOB/canary infrastructure (interactsh/oast, Burp
    # Collaborator, dnslog, Canarytokens) a real attacker would also use — the two are
    # byte-identical on a single log line; only intent/provenance differs, which a
    # regex cannot recover. See `_scan_line_content`'s Class 2 comment (just above the
    # retraction note) for the full history. This field, and the CAP-eligibility
    # machinery that read it (`Finding.exfil_evidence_signal`, `scoring.py`'s B164
    # arm), are removed — the same-line pairing still corroborates a WARN exactly as
    # it always has, via the unchanged `counts["exfil_evidence"]` key; it simply can
    # never additionally CAP the grade. The trajaudit-indicator signal is the only
    # remaining CAP-eligible source for I-025/B-309.


# C-135 (2026-07-15, real-fleet sanity pass against ~/.openclaw): a trajectory JSONL
# record is ONE JSON object per line and can embed an entire message/tool-output
# history (sender name, chat IDs, message text...) well under the 8000-char pathological-
# line cap. Passing the WHOLE line to _add_sample as "evidence" leaked all of that
# verbatim, because logsafe.redact() only masks secret-SHAPED substrings (API keys,
# password= pairs, ...) — it was never meant to sanitize arbitrary bulk prose/PII, the
# same lesson already learned the hard way for adjudication.py's judge-packet (F-113).
# Fix: every sample is a short, BOUNDED excerpt around the actual match, never the
# full line/record — bounding the blast radius regardless of how much unrelated
# sensitive content shares that line.
_SAMPLE_CONTEXT_CHARS = 60


def _windowed(text: str, start: int, end: int) -> str:
    """A short excerpt of *text* around [start, end) — never the whole string."""
    lo = max(0, start - _SAMPLE_CONTEXT_CHARS)
    hi = min(len(text), end + _SAMPLE_CONTEXT_CHARS)
    prefix = "…" if lo > 0 else ""
    suffix = "…" if hi < len(text) else ""
    return prefix + text[lo:hi] + suffix


def _add_sample(result: LogScanResult, signal: str, raw_snippet: str) -> None:
    """Bump *signal*'s counter and, up to the per-class cap, store a REDACTED sample.

    ``raw_snippet`` MUST already be a bounded excerpt (see ``_windowed``), never a
    whole raw line/record — it is passed through ``logsafe.redact()`` as defense in
    depth before it is ever stored on the result, but redact() alone is not a bulk-
    text sanitizer (see the C-135 note above), so the caller's own bounding is what
    actually limits the blast radius here.
    """
    result.counts[signal] = result.counts.get(signal, 0) + 1
    stored = sum(1 for s in result.samples if s.startswith(f"{signal}: "))
    if stored < _MAX_SAMPLES_PER_CLASS:
        result.samples.append(f"{signal}: {_logsafe.redact(raw_snippet)}")


_PRINTABLE_DECODE_RATIO = 0.85  # same threshold checks/_content.py's _reassembles_to_payload
# already uses for this exact discrimination — not a new number invented for this module.


def _decodes_to_printable_blob(token: str) -> bool:
    """B-249 FP fix (C-135, 2026-07-18): True only when *token* actually decodes as
    base64 (standard or URL-safe) to bytes that are overwhelmingly printable — the real
    signature of an encoded TEXT payload (a credential string, a stolen secret) as
    opposed to incidental high-entropy bytes.

    The bare shape tests this replaced (``_B64_BLOB_RE`` / ``_B64URL_BLOB_RE`` — a run of
    40+ base64-alphabet characters, nothing else) are NOT an encoding discriminator at
    all: any 40+ char run of hex digits (a git SHA, a sha256) or an ordinary hyphenated
    URL/doc-slug ("getting-started-with-local-webhook-testing-and-tunnels") also matches
    that character class, because base64's alphabet is just alnum (+ `-`/`_`). A real-fleet
    adversarial pass (C-135) reproduced BOTH as live false positives: a benign kubectl/
    ngrok devops sink (git-SHA build param) and a benign npm/docs sink (a plain-English
    slug) both flipped this WARN-only class from silent to firing on ordinary developer
    logs. This is the exact same unsound "bare blob" shape that
    ``_secrecy_credential_or_encoding_anchor`` in checks/_content.py already tried and
    RETRACTED for the same reason (two real-fleet false positives there too) — see that
    function's docstring.

    Decoding and measuring the printable-byte ratio of the RESULT (not the input) is a
    genuine test: decoding a hex SHA or an English slug as base64 yields near-random
    bytes (~30-40% printable in practice), while decoding a real base64-encoded text
    string (a credential, a token) yields ~100% printable bytes almost always. This
    reuses the SAME 0.85 threshold and the SAME "decode, then measure printable ratio"
    technique ``_reassembles_to_payload`` (checks/_content.py) already uses to make this
    exact distinction elsewhere in the codebase — not a new invented heuristic.

    Deliberately does NOT reuse ``_content.py``'s ``_try_b64_decode``: that helper does
    ``raw.decode("utf-8", "ignore")``, which silently DROPS invalid byte sequences before
    the printable check ever runs — on random/garbage bytes that drops most of the
    string, leaving a short "survivor" remainder that then reads as deceptively
    printable. The ratio here is measured over the full raw decoded bytes.

    Known accepted residual (documented, not chased further — WARN-only/scored=False,
    Golden Rule #5 is about FAIL): a genuinely base64-encoded ENGLISH-TEXT value in an
    otherwise-ordinary param (e.g. a webhook "sig=" test value) decodes to printable text
    just like a real exfiltrated secret does — the two are structurally identical once
    encoded, and no static content-shape test can tell them apart without semantic
    judgment of what the value actually is. Narrowing further by param name (an allowlist
    of "safe" names like sig/token/auth) was considered and rejected: it is
    guessable/evadable by a real attacker and is exactly the kind of additional narrow
    special case the project's C-135 history shows does not converge (checks/_content.py's
    own retraction note; delete/simplify, don't keep stacking conditions).

    I-025/B-309 tried, for a time, to make B164's exfil_evidence class eligible to CAP
    the A-F grade, which would have promoted this residual into a live false-positive
    grade CAP too. That whole CAP mechanism was RETRACTED as unsound for reasons
    independent of this residual (C-135 8th round, Dave's 2026-07-22 ruling — see the
    retraction note above `_scan_line_content`'s Class 2 comment), so the sentence
    above is simply true: this residual is WARN-only, unconditionally.
    """
    for urlsafe in (False, True):
        try:
            pad = (-len(token)) % 4
            padded = token + "=" * pad
            raw = (
                base64.urlsafe_b64decode(padded)
                if urlsafe
                else base64.b64decode(padded, validate=True)
            )
        except (binascii.Error, ValueError):
            continue
        if not raw:
            continue
        printable = sum(1 for b in raw if 32 <= b < 127 or b in (9, 10, 13))
        if printable / len(raw) >= _PRINTABLE_DECODE_RATIO:
            return True
    return False


def _decode_b64_variants(token: str):
    """Yield each base64 decode of *token* that produces non-empty bytes — standard
    alphabet first, then URL-safe. Mirrors the two-variant decode loop
    ``_decodes_to_printable_blob`` already uses (same padding, same two encoders), but is
    kept as its own small generator: that function's job is "does this decode to
    printable text" and it stops at the first variant satisfying THAT test, whereas a
    gzip/zlib layer underneath is by definition NOT printable, so a caller checking for
    one needs every successfully-decoded raw candidate, not just the first.
    """
    pad = (-len(token)) % 4
    padded = token + "=" * pad
    for urlsafe in (False, True):
        try:
            raw = (
                base64.urlsafe_b64decode(padded)
                if urlsafe
                else base64.b64decode(padded, validate=True)
            )
        except (binascii.Error, ValueError):
            continue
        if raw:
            yield raw


def _looks_like_zlib_header(raw: bytes) -> bool:
    """True when the first two bytes of *raw* satisfy the zlib stream header check
    (RFC 1950 §2.2): CMF's low nibble names the DEFLATE compression method (8), and
    ``(CMF*256 + FLG) % 31 == 0`` (the header's own check-bits). A cheap, CORRECT
    pre-filter — ``zlib.decompressobj()`` is still the real validator below — that
    avoids attempting a decompress on bytes that provably cannot be a zlib stream (e.g.
    a base64-decoded English-text blob that happens to start with the ASCII byte
    ``0x78`` ('x'))."""
    if len(raw) < 2:
        return False
    cmf, flg = raw[0], raw[1]
    return (cmf & 0x0F) == 8 and ((cmf * 256 + flg) % 31 == 0)


def _bounded_decompress(raw: bytes) -> tuple[bytes | None, bool]:
    """If *raw* looks like a gzip or zlib stream, bounded-streaming-decompress it and
    return ``(decompressed_bytes, truncated)``. Returns ``(None, False)`` when *raw* is
    not gzip/zlib-shaped at all — the caller then treats *raw* itself as the payload
    (already handled elsewhere by ``_decodes_to_printable_blob``). Never raises: a
    malformed/truncated compressed stream (garbage after a real magic number, a
    decompression bomb cut off mid-stream by the cap) is caught and reported as "not
    decompressible" rather than propagating — this function is a pure best-effort probe,
    never a hard requirement that *raw* actually be valid compressed data.

    The output cap (``_MAX_DECODED_BLOB_BYTES``) is enforced by STREAMING reads/decompress
    calls bounded as bytes are produced — never by calling a whole-buffer ``.decompress()``
    and measuring the result afterward, which is exactly the decompression-bomb sink this
    task exists to close (a few compressed KB can legitimately claim to be gigabytes).
    """
    if raw[:2] == b"\x1f\x8b":
        # gzip.GzipFile.read(n) is itself a bounded streaming decompress (it delegates to
        # zlib's own max-length-bounded inflate internally) — the SAME primitive
        # collector.py's decompress_and_classify already trusts for gzip archive members.
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb") as gz:
                return _read_stream_capped(gz, _MAX_DECODED_BLOB_BYTES)
        except (OSError, EOFError, zlib.error):
            return None, False

    if _looks_like_zlib_header(raw):
        # No file-like wrapper ships for a bare zlib stream (unlike gzip/bz2/xz), so the
        # bounded-streaming primitive here is zlib's own documented pattern for it:
        # `decompressobj().decompress(data, max_length)` returns AT MOST max_length bytes
        # per call, leaving any not-yet-processed compressed bytes in `unconsumed_tail` —
        # the same "checked as bytes are produced" guarantee as the gzip path above, just
        # expressed through zlib's own lower-level bounded call instead of a file object.
        try:
            decomp = zlib.decompressobj()
            out = bytearray()
            chunk = decomp.decompress(raw, _MAX_DECODED_BLOB_BYTES + 1)
            out.extend(chunk)
            while decomp.unconsumed_tail and len(out) <= _MAX_DECODED_BLOB_BYTES:
                remaining = _MAX_DECODED_BLOB_BYTES + 1 - len(out)
                if remaining <= 0:
                    break
                chunk = decomp.decompress(decomp.unconsumed_tail, remaining)
                if not chunk:
                    break
                out.extend(chunk)
        except zlib.error:
            return None, False
        if len(out) > _MAX_DECODED_BLOB_BYTES:
            return bytes(out[:_MAX_DECODED_BLOB_BYTES]), True
        return bytes(out), False

    return None, False


# B-383 item 2: `_scan_blob_for_compressed_indicators` used to unconditionally
# run `_decode_b64_variants` + `_bounded_decompress` on every candidate token, on every
# scanned line, with no cheap "could this even be compressed" pre-check first. Base64
# encodes 3 raw bytes per 4-char group with NO overlap into the next group, so the FIRST
# base64 chars of a stream depend ONLY on the first raw bytes — and those are fixed by the
# compressed format's own header:
#   - gzip (RFC 1952): the magic (0x1F, 0x8B) is followed by CM (compression method), and
#     the ONLY value any real encoder assigns is 8 (deflate — 0-7 are reserved/unused), so
#     bytes[0:3] are always exactly b"\x1f\x8b\x08", which base64-encodes to the fixed
#     4-char prefix "H4sI" — a COMPLETE, sound test (any real gzip stream starts this way).
#   - zlib (RFC 1950): `_looks_like_zlib_header` above already validates the CMF/FLG
#     checksum; in practice every encoder that does not deliberately customize the window
#     size (Python's `zlib.compress()`/`compressobj()` default `wbits=15`, and virtually
#     every other library's default) emits CMF=0x78. Base64's FIRST char depends on CMF
#     ALONE (it is the top 6 bits of byte0 — base64 groups never straddle into byte1 for
#     the first char), so it is always 'e' for that CMF regardless of which FLG
#     (compression LEVEL) byte follows. Deliberately NOT the tighter "eJ" (CMF=0x78,
#     FLG=0x9C — only the DEFAULT compression level): FLG's top two bits are the FLEVEL hint
#     (RFC 1950 §2.2) and differ per level — `zlib.compress(data, 9)` (best compression, a
#     plausible choice for an attacker shrinking an exfil payload so it clears fewer
#     detection thresholds) starts "eN", not "eJ". An "eJ"-only filter would silently stop
#     detecting every zlib payload compressed at any level but the default — exactly the
#     false negative Golden Rule #5/C-135 exists to catch — so this filter checks only the
#     single CMF-derived char, never the level-dependent second one.
# A token satisfying neither prefix cannot decode to a gzip/zlib stream `_bounded_decompress`
# would ever accept, so skipping it costs zero real detections. Follows the same
# `_maybe_secret_path_match`/`_SECRET_PATH_KEYWORDS` fast-path idiom already used above.
_COMPRESSED_B64_PREFIXES = ("H4sI", "e")


def _maybe_compressed_blob(token: str) -> bool:
    """Cheap `startswith()` pre-check: True only when *token* COULD decode to a gzip/zlib
    stream — see `_COMPRESSED_B64_PREFIXES` above for why these are sound (no false
    negatives on a real gzip/zlib payload), not guessed."""
    return token.startswith(_COMPRESSED_B64_PREFIXES)


def _scan_blob_for_compressed_indicators(
    result: LogScanResult, token: str, *, is_trajectory: bool
) -> None:
    """C-327: one layer deeper than ``_decodes_to_printable_blob`` — if *token* is a
    base64 blob whose decoded bytes are themselves a gzip/zlib stream (the HF
    agent-intrusion ``exec(gzip.decompress(base64.b64decode(...)))`` packing shape),
    bounded-decompress it and re-scan the recovered text with the SAME already-vetted
    indicator regexes every ordinary line goes through (``_scan_line_content`` — never a
    new pattern, per this module's own docstring). Silent (does nothing) when *token*
    does not decode to a gzip/zlib stream at all — a bare base64 blob of plain text is
    already this module's OTHER, narrower B-249 corroboration path, not this one.

    Deliberately never recurses into a further blob layer found INSIDE the decompressed
    text: only the outermost ``_scan_line_content`` call (``allow_blob_decode=True``)
    ever reaches this function, and it always calls back in with
    ``allow_blob_decode=False``. One layer only, per this task's explicit scope — a
    gzip-of-gzip-of-base64 chain is not chased.

    B-383 item 2: bails out BEFORE any decode attempt when ``token`` cannot possibly be a
    base64-encoded gzip/zlib stream — see ``_maybe_compressed_blob``.
    """
    if not _maybe_compressed_blob(token):
        return
    for raw in _decode_b64_variants(token):
        data, blob_truncated = _bounded_decompress(raw)
        if data is None:
            continue
        if blob_truncated:
            result.blob_decode_truncated = True
            result.truncated = True
        text = data.decode("utf-8", errors="replace")
        if not text.strip():
            return
        # B-431: this used to hand the ENTIRE decompressed document to
        # `_scan_line_content` as one synthetic "line". Every FP guard in that function
        # (Class 2/4's same-line AND-pairing, Class 6's per-line secrets_at_rest) relies
        # on `line` being one actual line of the source document — collapsing a genuine
        # multi-line document (a support bundle, a JSON diagnostics dump, an application
        # log) into one string let a secret-shaped token on one original line pair with
        # an exfil-transport token on an entirely DIFFERENT original line, exactly the
        # cross-line collapse that discipline exists to prevent. Re-split on the SAME
        # line boundaries the plaintext path (`scan_log_file`) already respects, and
        # apply that same per-line oversized-window discipline to each split line, so a
        # decompressed document gets exactly the AND-pairing behavior it would have had
        # if it had been scanned as a plaintext file in the first place.
        for decoded_line in text.splitlines():
            if not decoded_line.strip():
                continue
            if len(decoded_line) > _MAX_LINE_LEN:
                # Same windowing discipline as an oversized RAW line (see
                # _OVERSIZED_WINDOW_CHARS above) — a single decompressed line can be just
                # as long, and the regex-cost bound windowing exists to enforce does not
                # stop applying just because the line came from a decode step instead of
                # the file directly.
                head = decoded_line[:_OVERSIZED_WINDOW_CHARS]
                tail = decoded_line[-_OVERSIZED_WINDOW_CHARS:]
                _scan_line_content(result, head, is_trajectory=is_trajectory, allow_blob_decode=False)
                _scan_line_content(result, tail, is_trajectory=is_trajectory, allow_blob_decode=False)
            else:
                _scan_line_content(result, decoded_line, is_trajectory=is_trajectory, allow_blob_decode=False)
        return  # one successful decompression is enough; don't also try the other b64 variant


# B-285/LOG-1 perf finding: `_SECRET_PATH_RE` (checks/_shared.py) is
# `[\w./~+-]*(?:secret|token|credential|password|api[_-]?key)[\w./~+-]*` — its two
# UNBOUNDED `[\w./~+-]*` quantifiers straddling a fixed alternation make it O(n^2) on any
# text with no matching keyword (measured: ~0.45s on 4000 word-characters, ~1.9s on
# 8000). That cost was already latent at the ordinary `_MAX_LINE_LEN` cap, but this
# module never had a reason to exercise it on OVERSIZED lines before — they were
# skipped outright. Once oversized lines are windowed instead (see
# `_OVERSIZED_WINDOW_CHARS`), this module calls `_scan_line_content` on hundreds of
# large windows per real trajectory corpus, and paying an O(n^2) regex on each one
# measurably pushed a real-fleet scan (73 files) from ~7.6s to ~16s — over the
# per-check hard budget (`scanbudget.DEFAULT_CHECK_BUDGET_S`, 15s). Fixing the shared
# regex itself is out of this task's scope (checks/_shared.py, consumed by other
# checks too — a change there needs its own C-135 pass). Instead: `_SECRET_PATH_RE` can
# ONLY ever match when one of its five keyword alternatives is literally present, so a
# cheap substring pre-check that finds NONE of them proves no match is possible and
# skips the expensive regex entirely — a pure fast-path, never a behavior change.
_SECRET_PATH_KEYWORDS = ("secret", "token", "credential", "password", "apikey", "api_key", "api-key")


def _maybe_secret_path_match(line: str):
    """`_SECRET_PATH_RE.search(line)`, but skip the (O(n^2)-worst-case) regex call
    entirely when a cheap substring pre-check proves it cannot match — see the note
    above `_SECRET_PATH_KEYWORDS`."""
    low = line.lower()
    if not any(kw in low for kw in _SECRET_PATH_KEYWORDS):
        return None
    return _SECRET_PATH_RE.search(line)


# B-383 item 1 (trivial detection evasion, FIXED): `_B64_BLOB_RE`
# (`[A-Za-z0-9+/]{40,}={0,2}`) and `_B64URL_BLOB_RE` (`[A-Za-z0-9_-]{40,}`) have DISJOINT
# character classes on "+"/"/" vs "-"/"_" — a blob encoded in ONE alphabet is matched
# WHOLLY by its own pattern but only in FRAGMENTS (split at every "-"/"_" for a standard
# blob run through the URL-safe pattern, or at every "+"/"/" for a URL-safe blob run
# through the standard pattern) by the other. The OLD collection loop consumed the
# `_MAX_BLOBS_PER_LINE` cap PER PATTERN, `break`-ing out of the outer `for pat in (...)`
# loop the moment the cap filled — so a `base64.urlsafe_b64encode(...)` blob's first four
# 40+-char standard-alphabet FRAGMENTS (found by `_B64_BLOB_RE`, which cannot see the
# blob's own "-"/"_" chars as separators) filled the cap and the loop broke BEFORE
# `_B64URL_BLOB_RE` — the only pattern that would have matched the blob WHOLE — ever ran.
# Net effect: `base64.urlsafe_b64encode(gzip.compress(payload))` produced ZERO detections
# while the byte-identical payload via `base64.b64encode` was caught.
# Fix: collect candidate spans from BOTH patterns FIRST (the line is already bounded to
# `_MAX_LINE_LEN`/`_OVERSIZED_WINDOW_CHARS` by every caller, so this is not a new DoS
# surface — same total regex work as before, just not abandoned halfway through), then
# keep only the MAXIMAL spans: a match strictly CONTAINED inside another match's span is
# always a same-blob fragment produced by the "wrong" alphabet's pattern splitting on a
# character it cannot match, and is dropped rather than counted against the cap. The cap
# is then applied to the surviving DISTINCT spans, combined across both patterns.
def _collect_blob_tokens(line: str) -> list:
    """Return up to `_MAX_BLOBS_PER_LINE` distinct base64 blob-candidate tokens from
    *line*, trying both the standard and URL-safe alphabets — see the note above for why
    the cap is applied to combined, maximal SPANS rather than per-pattern match counts."""
    candidates = []  # (start, end, token) — end recomputed post-rstrip so a stray "="
    # padding suffix `_B64_BLOB_RE` alone can match doesn't make its span look wider than
    # an identical run `_B64URL_BLOB_RE` (which never matches "=") found for the same blob.
    for pat in (_B64_BLOB_RE, _B64URL_BLOB_RE):
        for m in pat.finditer(line):
            token = m.group(0).rstrip("=")
            if len(token) < 40:
                continue
            candidates.append((m.start(), m.start() + len(token), token))

    def _is_contained(i) -> bool:
        start, end, _ = candidates[i]
        return any(
            j != i and o_start <= start and end <= o_end and (o_start, o_end) != (start, end)
            for j, (o_start, o_end, _) in enumerate(candidates)
        )

    maximal = [c for i, c in enumerate(candidates) if not _is_contained(i)]

    seen_spans = set()
    tokens = []
    for start, end, token in sorted(maximal, key=lambda c: c[0]):
        span = (start, end)
        if span in seen_spans:
            continue
        seen_spans.add(span)
        tokens.append(token)
        if len(tokens) >= _MAX_BLOBS_PER_LINE:
            break
    return tokens


# I-025/B-309, C-135 8th ROUND (RETRACTED, 2026-07-21/22): follow-ups #2/#3/#4 above tried
# progressively narrower host/verb gates (a named drop-host, then an independent transport
# verb, then an attacker-exclusive OOB/canary host set) to make the same-line
# `exfil_evidence` pairing sound enough to CAP the A-F grade. THREE independent
# adversarial (C-135) reviews of the #4 fix converged on the same conclusion: no
# enumerable host set is both (a) narrow enough to exclude dual-use developer tooling
# (ngrok/transfer.sh/pastebin/webhook.site — follow-up #4's own motivating FP) and (b)
# broad enough to still catch real exfiltration, because THIS TOOL'S OWN AUDIENCE
# (security-conscious OpenClaw operators) legitimately sends secrets to the exact
# "attacker-exclusive" OOB/canary infrastructure follow-up #4 chose (interactsh/oast,
# Burp Collaborator, dnslog, Canarytokens) as part of routine, authorized security
# testing — a pentester posting a token to their OWN oast.pro collector, or a
# blue-teamer generating a Canarytoken with a real API key, is byte-identical on a
# single log line to a real attacker exfiltrating that same secret to that same class
# of host. The FP and the FN are the same defect: the only discriminator is
# INTENT/PROVENANCE, which a stdlib regex over one log line cannot recover — reproduced
# end-to-end and confirmed unfixable by any host-list edit (see Dave's 2026-07-22
# ruling and PULSE task history for the full three-review writeup).
#
# Dave's ruling (2026-07-22): demote this ENTIRE same-line arm to WARN-only, permanently
# — it can no longer CAP the grade at all. The bare same-line SECRET_PATTERNS + _EXFIL_RE
# pairing just below still corroborates a WARN exactly as it always has (unchanged); only
# the CAP-eligible counter this arm used to feed (`exfil_evidence_same_line_hits`,
# `Finding.exfil_evidence_signal`) is removed, along with `_EXFIL_TRANSPORT_VERB_RE` and
# `_CAP_ELIGIBLE_EXFIL_HOST_RE` (both existed ONLY to gate that counter). See
# scoring.py's `_runtime_cap_signal` (trajaudit-indicator match is now the ONLY B164-
# adjacent signal that may CAP), and tests/test_i025_runtime_cap.py's regression pinning
# that no same-line log shape — including an attacker-exclusive OOB host — can cap.


def _scan_line_content(
    result: LogScanResult,
    line: str,
    *,
    is_trajectory: bool = False,
    cred_seen_before: bool = False,
    allow_blob_decode: bool = True,
) -> bool:
    """Classes 1 / 2 / 4 / 6 — plain-text pattern scan over one (already length-capped)
    line. Applied uniformly to every sink kind, including trajectory sidecar lines.

    ``cred_seen_before`` — True when an earlier line in THIS SAME sink already showed a
    credential-shaped path read (``_CRED_RE``); feeds the B-249 cross-line exfil-evidence
    extension below. Returns whether THIS line itself is a cred-path read, so the caller
    can fold it into the running state for the next line (mirrors how ``last_seq``/
    ``last_ts`` are threaded through ``scan_log_file``'s loop).

    ``allow_blob_decode`` — C-327: gates the gzip/zlib-beneath-base64 decode-and-rescan
    step at the end of this function. Always False when THIS call is itself scanning
    already-decompressed text (``_scan_blob_for_compressed_indicators`` sets it so),
    which is what bounds the decode depth at exactly one layer — a gzip-of-gzip chain is
    never chased.
    """
    normalized = normalize_for_scan(line)

    # Class 1 — injection_against_agent: a narrow, cheap subset of the content-ring's
    # injection markers (INJECTION_PATTERNS, checks/_shared.py — PLUS one extra bounded
    # canonical-override pattern, LOG_SCAN_INJECTION_PATTERNS, F-127/C-135: fixes an
    # end-to-end FN where "ignore all previous instructions"/"disregard all prior
    # instructions"/"forget everything above" — the single most canonical injection
    # phrasing — missed INJECTION_PATTERNS' narrower single-modifier "ignore" form and had
    # no "disregard"/"forget" verb at all; kept OUT of INJECTION_PATTERNS itself since that
    # list is also consumed un-corroborated by B6/B58/C074, see LOG_SCAN_INJECTION_PATTERNS'
    # docstring) over de-obfuscated text. Deliberately NOT the full ~247-regex
    # SKILL_CONTENT_RING — that set is sized and calibrated for scanning trusted-author
    # skill SOURCE, not arbitrary, attacker-influenced LOG text (design doc §6 DoS-surface
    # note). Windowed over `normalized` (not `line`): normalize_for_scan can strip
    # invisible/bidi chars, so a span found in `normalized` is not guaranteed to be a valid
    # index into `line`.
    for pat in LOG_SCAN_INJECTION_PATTERNS:
        m = pat.search(normalized)
        if m:
            _add_sample(result, "injection_against_agent", _windowed(normalized, m.start(), m.end()))
            break

    # Class 2 — exfil_evidence: a secret pattern AND an exfil-transport/host token on the
    # SAME line (mirrors checks/__init__.py's own same-line `_has_cred_exfil` rule — the
    # established low-FP shape for THAT rule's own domain, skill-authored markdown/code
    # prose). WARN-only: bumps the shared `counts["exfil_evidence"]` key on a bare
    # secret-shaped literal paired with any dual-use transport verb (curl/wget/POST/
    # base64/…), same as always.
    #
    # I-025/B-309 tried, across four rounds, to make a narrower version of this same
    # pairing eligible to CAP the A-F grade (a named drop-host, then an independent
    # transport verb, then an attacker-exclusive OOB/canary host set) — RETRACTED (C-135
    # 8th round, Dave's 2026-07-22 ruling): this tool's own audience legitimately sends
    # secrets to the exact OOB/canary infrastructure the final attempt chose as
    # "attacker-exclusive," so the false-positive and the true-positive are
    # byte-identical on one log line; no enumerable host set discriminates them. See the
    # retraction note above this function for the full history. This class is WARN-only,
    # permanently — see `scoring.py`'s `_runtime_cap_signal` for the (now
    # trajaudit-indicator-only) CAP source.
    secret_m = next((m for m in (p.search(line) for p in SECRET_PATTERNS) if m), None)
    exfil_m = _EXFIL_RE.search(line)
    if secret_m and exfil_m:
        lo, hi = min(secret_m.start(), exfil_m.start()), max(secret_m.end(), exfil_m.end())
        _add_sample(result, "exfil_evidence", _windowed(line, lo, hi))

    # Class 2 extension (B-249): an OPAQUE base64-encoded exfil payload has no cleartext
    # secret to pair against the same-line rule above, so a beacon that carries stolen
    # data as a base64 GET/URL param (rather than a recognizable credential string) slips
    # past it entirely — this was the confirmed gap: an injection -> cred-read -> base64
    # GET-exfil-to-a-drop-host sequence produced neither exfil_evidence (no same-line
    # secret) nor env_compromise_ioc (the exfil line carries no cred-shaped path itself).
    # Corroborate ACROSS the sink instead of requiring same-line: a real credential-shaped
    # PATH read (_CRED_RE — narrow: .aws/credentials, .ssh/id_*, keychain, wallet.dat, ...)
    # EARLIER in this same sink, followed by a LATER line naming a KNOWN, low-base-rate
    # drop-point host (_KNOWN_EXFIL_HOST_RE — the same narrow host list this check's own
    # C-221 cross-artifact axis already trusts) that ALSO carries a base64-alphabet run of
    # 40+ chars (_B64_BLOB_RE / _B64URL_BLOB_RE — the SAME vetted blob regexes the content-
    # ring already uses; never a new pattern).
    #
    # CORRECTION (B-249 FP fix, C-135, 2026-07-18): a bare base64-BLOB-SHAPE match (just
    # the character class, `_B64_BLOB_RE`/`_B64URL_BLOB_RE` alone) is NOT actually a base64
    # discriminator and is NOT "materially narrower" than the retracted
    # `_secrecy_credential_or_encoding_anchor` attempt this comment used to claim it was —
    # a 40+ char run of hex digits (a git SHA) or an ordinary hyphenated URL/doc slug
    # matches that same character class trivially. A real-fleet adversarial pass confirmed
    # this fires on ordinary developer sessions: a kubectl/ngrok devops sink (cred-path
    # ~/.kube/config, then a git-SHA build param to a *.ngrok-free.app host) and an
    # npm/docs sink (cred-path ~/.npmrc, then a plain-English doc-slug URL to a
    # *.ngrok-free.app host) both flipped this WARN-only class from silent to firing. The
    # fix: additionally require the matched blob to actually DECODE (as real base64) to
    # overwhelmingly printable bytes (`_decodes_to_printable_blob` — see its docstring for
    # why this, unlike the character-class shape, is a genuine encoding test, and for the
    # one documented residual it does not close).
    #
    # This arm's own documented residual (a benign base64-ENGLISH-TEXT `sig=`-style
    # value, indistinguishable by content shape from a real exfiltrated secret) is
    # WARN-only, as is the same-line arm above (see its retraction note) — nothing in
    # this module can CAP the A-F grade any more; only the trajaudit-indicator signal
    # can (scoring.py's `_runtime_cap_signal`).
    if cred_seen_before:
        host_m = _KNOWN_EXFIL_HOST_RE.search(line)
        blob_m = _B64_BLOB_RE.search(line) or _B64URL_BLOB_RE.search(line)
        if host_m and blob_m and _decodes_to_printable_blob(blob_m.group(0)):
            lo, hi = min(host_m.start(), blob_m.start()), max(host_m.end(), blob_m.end())
            _add_sample(
                result,
                "exfil_evidence",
                "cred-read earlier in this sink, then an encoded param to a known drop "
                "host: " + _windowed(line, lo, hi),
            )

    # Class 4 — env_compromise_ioc: a credential-shaped path/secret-named path token AND
    # an exfil-transport/host token on the SAME line. C-135 note: the literal task spec
    # read as "any bare _CRED_RE/_SECRET_PATH_RE/_EXFIL_RE hit anywhere in the file", but
    # _EXFIL_RE alone matches very common, benign terms (curl/wget/fetch(/POST/base64) that
    # show up in perfectly ordinary tool-call text for any web/exec-capable agent. Every
    # OTHER consumer of these same regexes in this codebase already requires a same-line
    # AND pairing (never a bare hit) precisely to avoid that noise; this class keeps that
    # same, already-proven-low-FP discipline instead of a strictly-worse bare-hit reading.
    cred_m = _CRED_RE.search(line) or _maybe_secret_path_match(line)
    if cred_m and exfil_m:
        lo, hi = min(cred_m.start(), exfil_m.start()), max(cred_m.end(), exfil_m.end())
        _add_sample(result, "env_compromise_ioc", _windowed(line, lo, hi))

    # Class 6 — secrets_at_rest (content half only; the world-readable-permission half is
    # applied once per FILE by the calling check, which already owns that perm-check logic
    # — B19/_other_can_reach_read in checks/_egress.py — so it is not duplicated here):
    # SECRET_PATTERNS, or a Luhn-valid credit-card-shaped digit run (logsafe's own PAN
    # candidate regex — never a new pattern). PAN/Luhn is skipped for trajectory sinks
    # specifically (C-135, 2026-07-15 real-fleet pass): trajectory JSON is saturated with
    # large numeric fields (epoch-ms timestamps, seq/thread/usage counters) and a 13-digit
    # epoch timestamp coincidentally passes the Luhn checksum often enough in practice that
    # it fired on nearly every real trajectory file sampled — pure noise, no card data
    # involved. SECRET_PATTERNS (actual credential-shaped text) still applies everywhere,
    # including trajectory sinks.
    pan_m = None
    if not is_trajectory:
        for m in _logsafe._PAN_CANDIDATE_RE.finditer(line):
            digits = "".join(ch for ch in m.group(0) if ch.isdigit())
            if 13 <= len(digits) <= 19 and _logsafe._luhn_ok(digits):
                pan_m = m
                break
    at_rest_m = secret_m or pan_m
    if at_rest_m:
        _add_sample(result, "secrets_at_rest", _windowed(line, at_rest_m.start(), at_rest_m.end()))

    # C-327 — decode one layer deeper: a base64 blob whose decoded bytes are themselves
    # gzip/zlib-compressed (the HF agent-intrusion packing shape) is invisible to every
    # check above, since the compressed bytes are not printable/matchable text. Bounded to
    # _MAX_BLOBS_PER_LINE distinct blob SPANS across BOTH alphabets combined (see
    # `_collect_blob_tokens`) so a line stuffed with many blob-shaped tokens cannot
    # multiply decompression attempts. `allow_blob_decode=False` (set only when this call
    # is itself scanning already-decompressed text) skips this entirely — one layer only,
    # never recursive.
    if allow_blob_decode:
        for token in _collect_blob_tokens(line):
            _scan_blob_for_compressed_indicators(result, token, is_trajectory=is_trajectory)

    return bool(_CRED_RE.search(line))


def _parse_iso_ts(ts: str):
    """Best-effort ISO-8601 parse (accepts a trailing 'Z'). Raises ValueError on failure —
    callers must catch it; never guesses a timestamp."""
    s = ts.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


def _scan_trajectory_record(result: LogScanResult, line: str, last_seq, last_ts):
    """Classes 3 (dangerous_capability) + 5 (anomaly_tamper) — trajectory JSON records
    only. Metadata-only (§8 boundary, recon §15.3): reads only traceSchema/schemaVersion/
    seq/ts/type/data.name — NEVER data.arguments/output/result/contentItems.

    Returns the updated ``(last_seq, last_ts)`` state for the next call.
    """
    try:
        rec = json.loads(line)
    except ValueError:
        return last_seq, last_ts
    if not isinstance(rec, dict):
        return last_seq, last_ts

    # Class 5a — schema/version mismatch is itself an anomaly (recon §15.3 grounded set).
    if rec.get("traceSchema") != _TRACE_SCHEMA or rec.get("schemaVersion") != _SCHEMA_VERSION:
        _add_sample(result, "anomaly_tamper", "unexpected traceSchema/schemaVersion")
        return last_seq, last_ts

    # Class 5b — seq gaps / non-monotonic seq within this file.
    # C-135 (2026-07-15, real-fleet sanity pass): one physical sidecar file can carry
    # MULTIPLE sessions back to back (confirmed against a real trajectory — every
    # "non-monotonic seq" false hit lined up exactly with a session.started record).
    # A fresh session legitimately restarts its own seq counter, so a session.started
    # record is a deliberate reset point, not tamper evidence — skip the continuity
    # checks for exactly this transition, but still re-baseline last_seq/last_ts to it.
    seq = rec.get("seq")
    is_session_boundary = rec.get("type") == "session.started"
    if isinstance(seq, int):
        if is_session_boundary:
            pass
        elif last_seq is not None and seq <= last_seq:
            _add_sample(result, "anomaly_tamper", f"non-monotonic seq ({last_seq} -> {seq})")
        elif last_seq is not None and seq != last_seq + 1:
            _add_sample(result, "anomaly_tamper", f"seq gap ({last_seq} -> {seq})")
        last_seq = seq

    # Class 5c — ts out-of-order or unparseable.
    ts = rec.get("ts")
    if isinstance(ts, str) and ts.strip():
        try:
            parsed_ts = _parse_iso_ts(ts)
        except (ValueError, TypeError):
            _add_sample(result, "anomaly_tamper", "unparseable ts")
        else:
            if last_ts is not None and parsed_ts < last_ts:
                _add_sample(result, "anomaly_tamper", "ts out-of-order")
            last_ts = parsed_ts

    # Class 3 — dangerous_capability: a HIGH-BLAST verb PROVEN in this trajectory (reuses
    # attest.classify_verb — the SAME authoritative verb taxonomy T3/B84 already build on
    # — rather than behavioral._classify_verb_role, which lives in a Layer-3 module this
    # Layer-1 leaf must not import).
    if rec.get("type") == "tool.call":
        data = rec.get("data")
        name = data.get("name") if isinstance(data, dict) else None
        if isinstance(name, str) and name.strip():
            cls = attest.classify_verb(name)
            if cls in attest.HIGH_BLAST_CLASSES:
                _add_sample(result, "dangerous_capability", f"verb classified {cls}")

    return last_seq, last_ts


def scan_log_file(sink: LogSink, deadline, skill_iocs: dict | None = None) -> LogScanResult:
    """Bounded, redacted content scan of one log sink. Read-only; never raises.

    ``deadline`` is a ``time.monotonic()``-relative deadline (e.g. from
    ``scanbudget.audit_deadline()``), or ``None`` to disable the per-file soft cap.
    ``skill_iocs`` (optional) is a normalized-token -> declaring-skill-name map (see
    ``checks.correlation_indicators``, C-221); when given, each line is also tested for
    substring membership of those tokens — a cross-artifact correlation signal — without
    ever storing the raw line, only the already-vetted token + a hit count.
    """
    result = LogScanResult(sink=sink)
    path = sink.path

    is_trajectory = sink.kind == "trajectory"
    last_seq = None
    last_ts = None
    cred_seen = False  # B-249: has an EARLIER line in this sink shown a cred-path read?

    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                line_bytes = len(raw_line.encode("utf-8", errors="replace"))
                if result.bytes_scanned + line_bytes > _MAX_BYTES_PER_FILE:
                    result.truncated = True
                    result.byte_cap_truncated = True
                    break
                result.bytes_scanned += line_bytes

                if deadline is not None and audit_budget_exceeded(deadline):
                    result.timed_out = True
                    break

                line = raw_line.rstrip("\n")
                if len(line) > _MAX_LINE_LEN:
                    result.truncated = True
                    result.oversized_lines += 1
                    result.oversized_line_chars += len(line)
                    # C-135 (2026-07-15, real-fleet sanity pass): a legitimate tool.result
                    # record (e.g. a large file read or web-fetch output) routinely exceeds
                    # _MAX_LINE_LEN and lands here — completely normal, not an attack. If
                    # last_seq/last_ts were left as-is, the NEXT record's seq/ts would look
                    # like it "jumped" past whatever this skipped record's seq/ts was,
                    # firing a false anomaly_tamper hit for every oversized-but-benign
                    # record in the file (confirmed against a real trajectory: every large
                    # tool.result produced a spurious "seq gap"). Reset both so continuity
                    # checking cleanly resumes from the next record instead of blaming a
                    # skip on tampering. This module deliberately still does NOT parse an
                    # oversized line as a trajectory record (classes 3/5, _scan_trajectory_
                    # record): that's a metadata-only JSON read, not the content-scan
                    # coverage gap this fix targets, and is explicitly RT-1/F-133's
                    # scope (a field-scoped `context.compiled` reader), not this one.
                    if is_trajectory:
                        last_seq, last_ts = None, None

                    # B-285/LOG-1: windowed content scan (classes 1/2/4/6) instead of a
                    # bare skip — see _OVERSIZED_WINDOW_CHARS above for why this is safe.
                    # Two independent calls (head, then tail) through the SAME per-line
                    # scanner every ordinary line uses; never the full line in one call.
                    head = line[:_OVERSIZED_WINDOW_CHARS]
                    tail = line[-_OVERSIZED_WINDOW_CHARS:]
                    result.unscanned_middle_chars += (
                        len(line) - len(head) - len(tail)
                    )
                    cred_head = _scan_line_content(
                        result, head, is_trajectory=is_trajectory, cred_seen_before=cred_seen
                    )
                    cred_tail = _scan_line_content(
                        result, tail, is_trajectory=is_trajectory,
                        cred_seen_before=cred_seen or cred_head,
                    )
                    cred_seen = cred_seen or cred_head or cred_tail
                    continue  # the MIDDLE of the line is still never regex-matched
                if not line.strip():
                    continue

                cred_here = _scan_line_content(
                    result, line, is_trajectory=is_trajectory, cred_seen_before=cred_seen
                )
                cred_seen = cred_seen or cred_here
                if skill_iocs:
                    low = line.lower()
                    for tok in skill_iocs:
                        if tok in low:
                            result.skill_ioc_hits[tok] = result.skill_ioc_hits.get(tok, 0) + 1
                if is_trajectory:
                    last_seq, last_ts = _scan_trajectory_record(result, line, last_seq, last_ts)
    except OSError:
        pass

    return result


def _fmt_chars(n: int) -> str:
    """Human-scale a char count for a disclosure string (chars ~= bytes for the ASCII-
    heavy tool-output text this fires on; never claims exactness beyond that)."""
    if n >= 1024 * 1024:
        return f"~{n / (1024 * 1024):.1f} MB"
    if n >= 1024:
        return f"~{n / 1024:.1f} KB"
    return f"{n} chars"


def summarize_truncation(results) -> str:
    """Build a quantified truncation-disclosure suffix (leading with a space) from a
    list of per-sink :class:`LogScanResult` objects, or ``""`` when nothing was
    truncated at all.

    B-285/LOG-1: B164 (``check_log_threat_hunt``) and B180
    (``check_memory_reconsumption_injection``) both used to append the exact same
    generic "Some file(s) hit the scan's byte/line cap — results may be incomplete"
    sentence regardless of how much was actually skipped. That's kept as the honest
    fallback for the (now separately tracked) per-file BYTE cap, which this module
    still cannot quantify further (a file stops being read entirely, so there's no
    "how much of THIS line" figure to give) — but the oversized-LINE case is now fully
    quantified: how many lines, how much volume, and how much of that volume the
    first/last-window scan still could not reach (see ``_OVERSIZED_WINDOW_CHARS``).
    This intentionally does NOT claim the coverage gap is closed: a payload is only
    guaranteed to be caught when FULLY CONTAINED within one of the two windows — one
    placed outside both windows entirely, OR one that merely STRADDLES a window's edge
    (starts inside a window but extends past it, splitting the match across the window
    boundary), is still missed either way. Earlier wording here said only "in the
    middle" of the line, which described the first gap but not the second — a boundary-
    straddling payload only a few characters into an otherwise-scanned window is missed
    for the same reason, not because it sits anywhere near the line's midpoint (C-135
    adversarial finding). This disclosure now names both gaps rather than reading as
    blanket "results may be incomplete" noise a reader can't act on.

    Lives here (not duplicated in each check module) so the two consumers can never
    drift to different wording for the same underlying counters.
    """
    oversized_lines = sum(r.oversized_lines for r in results)
    oversized_chars = sum(r.oversized_line_chars for r in results)
    unscanned_chars = sum(r.unscanned_middle_chars for r in results)
    any_byte_capped = any(r.byte_cap_truncated for r in results)
    any_timed_out = any(r.timed_out for r in results)

    parts = []
    if oversized_lines:
        parts.append(
            f"{oversized_lines} line(s) totalling {_fmt_chars(oversized_chars)} exceeded "
            f"the {_MAX_LINE_LEN}-char scan cap; each was scanned in bounded first/last "
            f"{_OVERSIZED_WINDOW_CHARS}-char windows only, leaving "
            f"{_fmt_chars(unscanned_chars)} outside those windows entirely unscanned "
            "(a payload placed outside the first/last windows, or one straddling a "
            "window's edge, would not be detected either way)."
        )
    if any_byte_capped:
        parts.append(
            "Some file(s) also hit the scan's per-file byte cap — results may be "
            "incomplete."
            if oversized_lines
            else "Some file(s) hit the scan's per-file byte cap — results may be "
            "incomplete."
        )
    if any_timed_out:
        parts.append("Some file(s) hit the per-file scan timeout — results may be incomplete.")
    return (" " + " ".join(parts)) if parts else ""
