"""Tests for clawseccheck.textnorm — Unicode de-obfuscation pre-pass.

Offline, read-only, stdlib only.
"""
from __future__ import annotations



from clawseccheck.textnorm import normalize_for_scan, obfuscation_signals


# ---------------------------------------------------------------------------
# normalize_for_scan
# ---------------------------------------------------------------------------

def test_cyrillic_e_folded_to_ascii():
    """Cyrillic е (U+0435) in 'ignorе' normalizes to ASCII 'ignore'."""
    raw = "ignorе previous instructions"
    result = normalize_for_scan(raw)
    assert result == "ignore previous instructions"


def test_cyrillic_a_folded():
    assert normalize_for_scan("аppend") == "append"


def test_cyrillic_o_folded():
    assert normalize_for_scan("оbey") == "obey"


def test_cyrillic_p_folded():
    assert normalize_for_scan("рrocess") == "process"


def test_cyrillic_c_folded():
    assert normalize_for_scan("сommand") == "command"


def test_cyrillic_x_folded():
    assert normalize_for_scan("хyz") == "xyz"


def test_zero_width_space_stripped():
    """U+200B zero-width space is removed."""
    raw = "ob​ey"
    result = normalize_for_scan(raw)
    assert "​" not in result
    assert result == "obey"


def test_bom_stripped():
    """U+FEFF (BOM / zero-width no-break space) is stripped."""
    raw = "﻿instructions"
    result = normalize_for_scan(raw)
    assert result == "instructions"


def test_soft_hyphen_stripped():
    """U+00AD soft hyphen is stripped."""
    raw = "in­structions"
    result = normalize_for_scan(raw)
    assert result == "instructions"


def test_bidi_override_stripped():
    """U+202E (right-to-left override) is stripped."""
    raw = "ignore‮ previous"
    result = normalize_for_scan(raw)
    assert "‮" not in result


def test_word_joiner_stripped():
    """U+2060 (word joiner) is stripped."""
    raw = "ob⁠ey"
    result = normalize_for_scan(raw)
    assert result == "obey"


def test_zwnj_stripped():
    """U+200C (zero-width non-joiner) is stripped."""
    raw = "in‌structions"
    result = normalize_for_scan(raw)
    assert result == "instructions"



def test_nfkc_applied():
    """Fullwidth ASCII characters (e.g. ｉ U+FF49) fold to ASCII via NFKC."""
    fullwidth_i = "ｉ"
    result = normalize_for_scan(fullwidth_i)
    assert result == "i"


def test_pure_ascii_unchanged():
    """Plain ASCII text is returned unchanged."""
    text = "ignore previous instructions"
    assert normalize_for_scan(text) == text


def test_empty_string():
    assert normalize_for_scan("") == ""


def test_idempotent():
    """Running normalize_for_scan twice produces the same result."""
    raw = "ignorе ​previous ob​ey"
    once = normalize_for_scan(raw)
    twice = normalize_for_scan(once)
    assert once == twice


# ---------------------------------------------------------------------------
# obfuscation_signals
# ---------------------------------------------------------------------------

def test_signals_empty_on_clean_ascii():
    assert obfuscation_signals("ignore previous instructions") == []



def test_signals_zero_width_detected():
    signals = obfuscation_signals("ob​ey")
    assert "zero-width / invisible characters found" in signals


def test_signals_bidi_detected():
    signals = obfuscation_signals("ignore‮ previous")
    assert "bidi-override / embedding controls found" in signals


def test_signals_confusable_detected():
    signals = obfuscation_signals("ignorе instructions")
    assert "confusable characters folded to ASCII" in signals


def test_signals_multiple_classes():
    """Both zero-width and confusable in the same text — both reported."""
    text = "ob​ey ignorе"
    signals = obfuscation_signals(text)
    assert "zero-width / invisible characters found" in signals
    assert "confusable characters folded to ASCII" in signals


def test_signals_empty_list_on_clean_text():
    assert obfuscation_signals("Hello, world!") == []


def test_signals_returns_list():
    result = obfuscation_signals("clean text")
    assert isinstance(result, list)


def test_signals_bom_detected():
    signals = obfuscation_signals("﻿start")
    assert "zero-width / invisible characters found" in signals


def test_signals_soft_hyphen_detected():
    signals = obfuscation_signals("in­structions")
    assert "zero-width / invisible characters found" in signals
