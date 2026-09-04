"""`tests/_pdftext.py` — a parse failure must never read as an empty page.

The helper replaced nine hand-rolled regex extractors' worst variant. Two properties are
pinned here because losing either reproduces the original defect:

1. a compressed stream whose last byte is `\r` (or `\n`) is read WHOLE — the regex form
   consumed that byte as part of its `endstream` separator and handed zlib a short stream;
2. a stream that genuinely cannot be decompressed RAISES — the regex form caught
   `zlib.error` and continued, so the caller received `""` and reported absent content.

Property 2 is the one that made property 1 invisible for as long as it did.

Offline, stdlib only, writes nothing.
"""
from __future__ import annotations

import zlib

import pytest

from _pdftext import content_streams, content_text


def _pdf_with(payload: bytes, *, length: int | None = None) -> bytes:
    """A minimal document carrying one Flate stream, written the way `pdf.py` writes one:
    `compressed + b"\\nendstream"`."""
    body = zlib.compress(payload)
    declared = len(body) if length is None else length
    return (b"%PDF-1.4\n1 0 obj\n<< /Length " + str(declared).encode()
            + b" /Filter /FlateDecode >>\nstream\n" + body + b"\nendstream\nendobj\n")


def _payload_compressing_to_last_byte(target: int) -> bytes:
    """Text whose Flate output ends in *target*. Searched rather than hardcoded: the byte a
    given input compresses to is not something to assert from memory."""
    for n in range(1, 4000):
        candidate = b"drawn text " * n
        if zlib.compress(candidate)[-1:] == bytes([target]):
            return candidate
    raise AssertionError(f"no payload found whose compressed form ends in {target:#x}")


# ── property 1: the byte the old regex ate ───────────────────────────────────────────

@pytest.mark.parametrize("last, name", [(0x0D, "carriage return"), (0x0A, "line feed")])
def test_a_stream_ending_in_a_separator_byte_is_read_whole(last, name):
    """THE regression. `pdf.py` writes `compressed + b"\\nendstream"`, so a pattern ending
    `\\r?\\nendstream` consumes the writer's separator — and one more byte when the
    compressed body itself ends in one."""
    payload = _payload_compressing_to_last_byte(last)
    assert zlib.compress(payload)[-1] == last, "test setup: the payload must end in it"
    assert payload.decode() in content_text(_pdf_with(payload)), (
        f"a stream whose compressed body ends in a {name} was not read whole")


def test_the_old_regex_really_did_lose_that_byte():
    """A positive control for the test above: without it, property 1 could pass because the
    hazard never existed. This reproduces the retired pattern and shows it truncating."""
    import re
    payload = _payload_compressing_to_last_byte(0x0D)
    data = _pdf_with(payload)
    match = re.search(rb"stream\r?\n(.*?)\r?\nendstream", data, re.S)
    assert match, "the retired pattern should still find something to be wrong about"
    assert len(match.group(1)) == len(zlib.compress(payload)) - 1, (
        "the retired pattern no longer truncates, so this file is guarding a hazard that "
        "is gone — check whether pdf.py changed how it terminates a stream")
    with pytest.raises(zlib.error):
        zlib.decompress(match.group(1))


# ── property 2: a failure is loud ────────────────────────────────────────────────────

def test_undecompressable_bytes_raise_rather_than_returning_nothing():
    """The half that hid the other. `except zlib.error: continue` made a parse failure
    indistinguishable from a blank page, so an assertion about drawn text reported the text
    missing when it had simply never been looked for."""
    corrupt = b"\x78\x9c" + b"not really deflate data"
    data = (b"%PDF-1.4\n1 0 obj\n<< /Length " + str(len(corrupt)).encode()
            + b" /Filter /FlateDecode >>\nstream\n" + corrupt + b"\nendstream\n")
    with pytest.raises(AssertionError, match="NOT an empty page"):
        content_text(data)


def test_a_truncated_document_raises_instead_of_returning_a_partial_stream():
    payload = b"drawn text " * 40
    data = _pdf_with(payload, length=len(zlib.compress(payload)) + 500)
    with pytest.raises(AssertionError, match="truncated"):
        content_streams(data)


# ── the shape stays shared ───────────────────────────────────────────────────────────

def test_the_two_migrated_modules_do_not_keep_a_private_copy():
    """B-483's rule, applied to this parser: one reader, or the next author writes a second
    that drifts. Nine modules carried three divergent variants; these two carried the one
    that lost a byte, and they must not grow it back."""
    from pathlib import Path
    tests = Path(__file__).resolve().parent
    offenders = [
        name for name in ("test_pdf.py", "test_c423_ungraded_pdf_incident.py")
        if rb"\r?\nendstream" in (tests / name).read_bytes()
    ]
    assert not offenders, (
        f"{offenders} parse a PDF stream by scanning for `endstream` again — use "
        "`_pdftext.content_text` / `content_streams`, which read the /Length the format "
        "provides for exactly this reason")
