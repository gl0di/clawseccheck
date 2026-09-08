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


def _streams(data: bytes) -> "list[tuple[bytes, bytes]]":
    """Every stream as ``(dictionary, decompressed payload)``, in document order."""
    out: "list[tuple[bytes, bytes]]" = []
    for index, match in enumerate(_STREAM_HEADER.finditer(data)):
        declared = int(match.group(1))
        raw = data[match.end():match.end() + declared]
        if len(raw) != declared:
            raise AssertionError(
                f"stream {index}: /Length says {declared} bytes but only {len(raw)} remain "
                "in the document — the PDF is truncated, which is a finding about the "
                "writer, not something to skip past")
        try:
            out.append((match.group(0), zlib.decompress(raw)))
        except zlib.error as exc:
            raise AssertionError(
                f"stream {index}: {declared} bytes declared, and zlib refused them ({exc}). "
                "This is a parse failure, NOT an empty page — do not let it read as absent "
                "content.") from exc
    return out


def content_streams(data: bytes) -> "list[bytes]":
    """Every stream in *data*, decompressed, in document order — images included.

    Raises ``AssertionError`` naming the offending stream when one cannot be decompressed.
    A helper that returns less than it found would make "could not read" indistinguishable
    from "there was nothing there" — which is the bug this module exists to remove, not to
    reproduce.

    Use this when the image samples are the subject. To ask what the page DREW, use
    ``content_text`` — see the warning on it.
    """
    return [payload for _dict, payload in _streams(data)]


def page_content_streams(data: bytes) -> "list[bytes]":
    """Only the streams that carry drawing operators — image XObjects excluded."""
    return [payload for dic, payload in _streams(data) if b"/Subtype /Image" not in dic]


def content_text(data: bytes) -> str:
    """What the pages DRAW, decompressed, decoded and concatenated — no image samples.

    ``latin-1`` so every byte round-trips: the caller is searching for drawn text operands,
    and PDF string literals escape parentheses, so ``(advisory)`` appears as
    ``\\(advisory\\)``.

    **Image XObjects are excluded, and that is a correctness requirement, not a tidiness
    one.** Since the header mark became an embedded raster, a PDF carries two streams of
    arbitrary compressed image samples. Concatenating them with the page's operators makes
    every byte value appear somewhere in the "text", so any assertion of the form "this
    character never reaches the PDF" passes or fails by coincidence. Measured on the report
    that first showed it: 27 ESC and 57 BEL bytes inside the mascot, none in the page
    operators — enough to fail a hostile-name sanitisation guard that the renderer was in
    fact satisfying. The same joining also lets a stray ``(`` inside image data open a
    string literal that runs on into a real stream, capturing binary as though it had been
    drawn.
    """
    return "".join(s.decode("latin-1", "replace") for s in page_content_streams(data))


def shown_strings(data: bytes) -> str:
    """The PDF's shown text: the operands of every ``Tj``, newline-joined, in order.

    Stricter than ``content_text``, which also returns the operators themselves. Prefer
    this when asserting that some character never reaches a reader — an operand is what a
    reader sees, and nothing else in a content stream is.
    """
    out = []
    for stream in page_content_streams(data):
        blob = stream.decode("latin-1", "replace")
        out += [re.sub(r"\\([()\\])", r"\1", m.group(1))
                for m in re.finditer(r"\((.*?)\)\s*Tj", blob, re.S)]
    return "\n".join(out)
