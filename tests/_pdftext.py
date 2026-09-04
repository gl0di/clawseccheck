"""What a generated PDF actually DREW — parsed the way the format says, not by regex.

Tests assert on PDF content without needing poppler installed, so they decompress the page
content streams themselves. Every module that did this rolled its own regex, and the common
shape was::

    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", data, re.S):
        try:
            out += zlib.decompress(m.group(1)).decode(...)
        except zlib.error:
            continue

**Both halves of that are wrong, and together they fail silently.**

A content stream is BINARY. Its end is given by the `/Length` key precisely because it
cannot be found by scanning — any byte sequence may appear inside it. `pdf.py` writes
`compressed + b"\nendstream"`, so the `\r?\n` in that pattern is meant to consume the
writer's separator; when the compressed data itself ENDS in `\r`, the pattern consumes that
byte too and hands zlib a stream one byte short.

Then the `except: continue` turns the resulting decompression failure into an EMPTY result,
so the caller's assertion reports "the phrase is not in the PDF" when the truth is "the
phrase could not be looked for". A parse error reading as absent content is the same defect
this project keeps finding in its own checks, reproduced in its test helpers.

Measured, not theorised: on 2026-09-04 the version stamp changed the drawn text by a few
characters, the compressed bytes landed differently, and exactly one of ten layer/status
PDFs ended in `\r`. Its stream was 936 bytes; the regex captured 935; extraction returned
"" and the test reported a missing sentence that was in fact present. Parsing the same
bytes by `/Length` returns 2,610 characters and finds it. The PDF was never wrong.

That the roll of the dice had been favourable until then is the point: this was a latent
flake, not a new break, and it will recur in any copy still parsing by regex.
"""
from __future__ import annotations

import re
import zlib

#: `<< ... /Length N ... >> stream\r?\n` — the header, with the byte count the format
#: guarantees. Matched non-greedily inside one dictionary so a later object's `/Length`
#: cannot be picked up for an earlier stream.
_STREAM_HEADER = re.compile(rb"<<(?:[^<>]|<<[^>]*>>)*?/Length\s+(\d+)(?:[^<>]|<<[^>]*>>)*?>>\s*stream\r?\n")


def content_streams(data: bytes) -> "list[bytes]":
    """Every stream in *data*, decompressed, in document order.

    Raises ``AssertionError`` naming the offending stream when one cannot be decompressed.
    A helper that returns less than it found would make "could not read" indistinguishable
    from "there was nothing there" — which is the bug this module exists to remove, not to
    reproduce.
    """
    out: "list[bytes]" = []
    for index, match in enumerate(_STREAM_HEADER.finditer(data)):
        declared = int(match.group(1))
        raw = data[match.end():match.end() + declared]
        if len(raw) != declared:
            raise AssertionError(
                f"stream {index}: /Length says {declared} bytes but only {len(raw)} remain "
                "in the document — the PDF is truncated, which is a finding about the "
                "writer, not something to skip past")
        try:
            out.append(zlib.decompress(raw))
        except zlib.error as exc:
            raise AssertionError(
                f"stream {index}: {declared} bytes declared, and zlib refused them ({exc}). "
                "This is a parse failure, NOT an empty page — do not let it read as absent "
                "content.") from exc
    return out


def content_text(data: bytes) -> str:
    """All content streams decompressed, decoded and concatenated.

    ``latin-1`` so every byte round-trips: the caller is searching for drawn text operands,
    and PDF string literals escape parentheses, so ``(advisory)`` appears as
    ``\\(advisory\\)``.
    """
    return "".join(s.decode("latin-1", "replace") for s in content_streams(data))
