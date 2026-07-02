"""F-053: broaden obfuscated-payload recognition beyond base64/hex to XOR-loop decoding
(bytes(b ^ key ...) / ''.join(chr(c ^ k) ...)), the common non-base64 packer shape.

Scoped tightly to avoid false positives: a scalar `a ^ b` (bit flags) is never flagged;
the XOR must sit inside a byte/char sequence-builder AND the value must reach an exec sink.
"""
from __future__ import annotations

from clawseccheck.skillast import analyze_python


def _rules(src: str) -> list[str]:
    return [f.rule for f in analyze_python(src, "tool.py")]


def test_xor_bytes_builder_into_exec_flags():
    assert "OBFUSCATED_EXEC" in _rules("exec(bytes(b ^ 0x42 for b in data))")


def test_xor_join_comprehension_into_exec_flags():
    assert "OBFUSCATED_EXEC" in _rules("p = ''.join(chr(c ^ 7) for c in blob)\nexec(p)")


def test_scalar_xor_bit_flags_is_silent():
    # a ^ b as bit-flag arithmetic must not be treated as a decoded payload.
    assert _rules("flags = A ^ B\nprint(flags)") == []


def test_xor_sequence_without_exec_sink_is_silent():
    assert _rules("mask = bytes(b ^ 1 for b in data)\nsave(mask)") == []


def test_codecs_rot13_decode_into_exec_flags():
    # codecs.decode(..., 'rot_13') is recognised via the existing 'decode' attr.
    assert "OBFUSCATED_EXEC" in _rules("import codecs\nexec(codecs.decode(payload, 'rot_13'))")
