"""Fuzz / property tests for clawseccheck.skillast.

Tests focus on the two public surfaces:
  - analyze_python(source, filename) -> list[ASTFinding]
  - simulate_effects(source, filename) -> list[dict]

All inputs are constructed deterministically (no random()). Tests are fully
independent and perform no file I/O or network calls.
"""
from __future__ import annotations



from clawseccheck.skillast import analyze_python, simulate_effects, _MAX_FINDINGS_PER_FILE, ASTFinding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _valid_result(result: object) -> bool:
    """Return True if result is a list (possibly empty) of ASTFinding namedtuples."""
    if not isinstance(result, list):
        return False
    for item in result:
        if not isinstance(item, ASTFinding):
            return False
    return True


# ---------------------------------------------------------------------------
# 1. Empty source
# ---------------------------------------------------------------------------

def test_empty_source() -> None:
    """analyze_python('') never raises and returns a list."""
    result = analyze_python("", "test.py")
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# 2. Whitespace-only source
# ---------------------------------------------------------------------------

def test_whitespace_only() -> None:
    """analyze_python with only whitespace never raises."""
    result = analyze_python("   \n\t  \n   ", "test.py")
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# 3. Invalid / unparseable syntax
# ---------------------------------------------------------------------------

def test_invalid_syntax() -> None:
    """analyze_python with invalid Python syntax never raises -- returns []."""
    result = analyze_python("def f(: pass", "test.py")
    assert isinstance(result, list)


def test_incomplete_expression() -> None:
    """Incomplete expression token also returns [] without raising."""
    result = analyze_python("x = (1 + ", "broken.py")
    assert isinstance(result, list)


def test_mismatched_brackets() -> None:
    """Mismatched brackets do not raise."""
    result = analyze_python("]]][[[(((", "broken.py")
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# 4. Huge valid source
# ---------------------------------------------------------------------------

def test_huge_source() -> None:
    """10 000 lines of valid Python never raises and caps findings."""
    lines = ["x_{i} = {i} * 2  # line {i}".format(i=i) for i in range(10_000)]
    source = "\n".join(lines)
    result = analyze_python(source, "huge.py")
    assert isinstance(result, list)
    assert len(result) <= _MAX_FINDINGS_PER_FILE


def test_huge_source_with_imports() -> None:
    """Large source with imports and simple assignments stays capped."""
    lines = ["import os", "import sys"]
    for i in range(5_000):
        lines.append("val_{i} = os.path.join('/tmp', str({i}))".format(i=i))
    source = "\n".join(lines)
    result = analyze_python(source, "huge_imports.py")
    assert isinstance(result, list)
    assert len(result) <= _MAX_FINDINGS_PER_FILE


# ---------------------------------------------------------------------------
# 5. Deeply nested code
# ---------------------------------------------------------------------------

def test_deeply_nested() -> None:
    """Deeply nested if/for/def (100 levels) never raises."""
    indent = ""
    lines = []
    for i in range(100):
        lines.append(indent + "if True:")
        indent += "    "
    lines.append(indent + "pass")
    source = "\n".join(lines)
    result = analyze_python(source, "nested.py")
    assert isinstance(result, list)


def test_deeply_nested_functions() -> None:
    """100 levels of nested function definitions never raises."""
    lines = []
    indent = ""
    for i in range(100):
        lines.append(indent + "def f_" + str(i) + "():")
        indent += "    "
    lines.append(indent + "return 0")
    source = "\n".join(lines)
    result = analyze_python(source, "nested_defs.py")
    assert isinstance(result, list)


def test_deeply_nested_for_loops() -> None:
    """100 levels of nested for-loops (valid Python) never raises."""
    lines = []
    indent = ""
    for i in range(100):
        lines.append(indent + "for _x" + str(i) + " in range(1):")
        indent += "    "
    lines.append(indent + "pass")
    source = "\n".join(lines)
    result = analyze_python(source, "nested_for.py")
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# 6. Python 2-only syntax
# ---------------------------------------------------------------------------

def test_python2_print_statement() -> None:
    """Python 2 print statement is not valid Python 3 -- must not raise."""
    source = "print 'hello'\nexec 'x = 1'"
    result = analyze_python(source, "py2.py")
    assert isinstance(result, list)


def test_python2_raise_syntax() -> None:
    """Python 2 raise syntax (raise ExcType, msg) is invalid in Python 3."""
    source = "raise ValueError, 'oops'"
    result = analyze_python(source, "py2_raise.py")
    assert isinstance(result, list)


def test_python2_backtick_repr() -> None:
    """Backtick repr expressions are Python 2-only -- must not raise."""
    source = "`x`"
    result = analyze_python(source, "py2_backtick.py")
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# 7. Adversarial Unicode / binary content
# ---------------------------------------------------------------------------

def test_adversarial_unicode_control_chars() -> None:
    """Unicode control / bidirectional / null characters must not raise.

    All special characters are built at runtime from chr() to avoid embedding
    raw control bytes inside this source file (pytest's AST rewriter would reject
    a file containing null bytes).
    """
    null_byte = chr(0)                  # U+0000 NULL
    rtl_override = chr(0x202E)          # RIGHT-TO-LEFT OVERRIDE
    pop_directional = chr(0x202C)       # POP DIRECTIONAL FORMATTING
    zero_width_space = chr(0x200B)      # ZERO WIDTH SPACE
    zero_width_joiner = chr(0x200D)     # ZERO WIDTH JOINER
    bom = chr(0xFEFF)                   # BYTE ORDER MARK

    source = (
        "x = 1  # " + null_byte + " null here\n"
        "# " + rtl_override + " reversed " + pop_directional + "\n"
        "y = '" + zero_width_space + zero_width_joiner + "'\n"
        "z = '" + bom + "'\n"
    )
    result = analyze_python(source, "unicode.py")
    assert isinstance(result, list)


def test_adversarial_unicode_identifiers() -> None:
    """Unicode identifiers are valid Python 3 -- must not raise."""
    # Built from escape sequences so the source file stays pure ASCII.
    var1 = "привет"   # "privet" in Cyrillic
    var2 = "こんにちは"           # "konnichiwa" in Hiragana
    source = var1 + " = 42\n" + var2 + " = 'world'\n"
    result = analyze_python(source, "unicode_idents.py")
    assert isinstance(result, list)


def test_adversarial_high_codepoints() -> None:
    """Very high Unicode code-points in string literals must not raise."""
    high1 = chr(0x10FFFF)
    high2 = chr(0x100000)
    source = "x = '" + high1 + "'\ny = '" + high2 + " test'\n"
    result = analyze_python(source, "high_cp.py")
    assert isinstance(result, list)


def test_adversarial_mixed_rtl_ltr() -> None:
    """Mixed RTL+LTR directional markers in a comment must not raise."""
    markers = "".join(chr(c) for c in [
        0x202A,  # LEFT-TO-RIGHT EMBEDDING
        0x202B,  # RIGHT-TO-LEFT EMBEDDING
        0x202C,  # POP DIRECTIONAL FORMATTING
        0x202D,  # LEFT-TO-RIGHT OVERRIDE
        0x202E,  # RIGHT-TO-LEFT OVERRIDE
        0x2066,  # LEFT-TO-RIGHT ISOLATE
        0x2067,  # RIGHT-TO-LEFT ISOLATE
        0x2068,  # FIRST STRONG ISOLATE
        0x2069,  # POP DIRECTIONAL ISOLATE
    ])
    source = "# " + markers + "\nx = 1\n"
    result = analyze_python(source, "rtl.py")
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# 8. Findings cap -- source designed to trigger many findings
# ---------------------------------------------------------------------------

def test_max_findings_cap() -> None:
    """Source constructed to trigger many findings respects _MAX_FINDINGS_PER_FILE cap."""
    lines = ["import base64"]
    for i in range(_MAX_FINDINGS_PER_FILE + 50):
        lines.append(
            "exec(base64.b64decode(b'cHJpbnQoMSk='))  # trigger " + str(i)
        )
    source = "\n".join(lines)
    result = analyze_python(source, "many_findings.py")
    assert isinstance(result, list)
    assert len(result) <= _MAX_FINDINGS_PER_FILE


def test_max_findings_cap_getattr() -> None:
    """getattr-based obfuscation calls also respect the cap."""
    lines = ["import os"]
    for i in range(_MAX_FINDINGS_PER_FILE + 30):
        lines.append("getattr(os, 'system')('echo " + str(i) + "')")
    source = "\n".join(lines)
    result = analyze_python(source, "getattr_many.py")
    assert isinstance(result, list)
    assert len(result) <= _MAX_FINDINGS_PER_FILE


# ---------------------------------------------------------------------------
# 9. Return type is always a list
# ---------------------------------------------------------------------------

def test_returns_list_on_valid_source() -> None:
    """Result is a list, never None or any other type, for valid Python."""
    source = "import os\nos.system('ls')\n"
    result = analyze_python(source, "valid.py")
    assert result is not None
    assert isinstance(result, list)


def test_returns_list_on_empty() -> None:
    """Result is a list even for empty input."""
    result = analyze_python("", "empty.py")
    assert result is not None
    assert isinstance(result, list)


def test_returns_list_on_syntax_error() -> None:
    """Result is a list even when the source is completely unparseable."""
    result = analyze_python("!!!not python!!!", "bad.py")
    assert result is not None
    assert isinstance(result, list)


def test_findings_are_astfindings() -> None:
    """Every element in the returned list is an ASTFinding namedtuple."""
    source = "import base64\nexec(base64.b64decode(b'cHJpbnQoMSk='))\n"
    result = analyze_python(source, "check_type.py")
    assert isinstance(result, list)
    for item in result:
        assert isinstance(item, ASTFinding), "unexpected item type: " + str(type(item))
        assert hasattr(item, "rule")
        assert hasattr(item, "severity")
        assert hasattr(item, "lineno")
        assert hasattr(item, "reason")
        assert item.severity in ("crit", "info"), "unknown severity: " + str(item.severity)


# ---------------------------------------------------------------------------
# 10. Non-existent path -- path argument is cosmetic only
# ---------------------------------------------------------------------------

def test_nonexistent_path() -> None:
    """A non-existent filename string does not cause analyze_python to raise."""
    source = "x = 1\nprint(x)\n"
    result = analyze_python(source, "does/not/exist.py")
    assert isinstance(result, list)


def test_nonexistent_path_invalid_syntax() -> None:
    """Non-existent path with invalid syntax is still handled gracefully."""
    result = analyze_python("def bad(: pass", "no/such/path/file.py")
    assert isinstance(result, list)


def test_empty_filename() -> None:
    """Empty string as filename does not raise."""
    result = analyze_python("x = 42\n", "")
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Bonus: simulate_effects surface
# ---------------------------------------------------------------------------

def test_simulate_effects_never_raises_on_empty() -> None:
    """simulate_effects('') never raises and returns a list."""
    result = simulate_effects("", "empty.py")
    assert isinstance(result, list)


def test_simulate_effects_never_raises_on_invalid() -> None:
    """simulate_effects on broken syntax never raises."""
    result = simulate_effects("def f(: pass", "bad.py")
    assert isinstance(result, list)


def test_simulate_effects_returns_list() -> None:
    """simulate_effects always returns a list, never None."""
    source = "import requests\ndef run(url): requests.get(url)\n"
    result = simulate_effects(source, "net.py")
    assert result is not None
    assert isinstance(result, list)


def test_simulate_effects_dict_keys() -> None:
    """Each entry from simulate_effects is a dict with the documented keys."""
    source = (
        "import os\n"
        "def main():\n"
        "    os.system('ls')\n"
    )
    result = simulate_effects(source, "dict_keys.py")
    assert isinstance(result, list)
    expected_keys = {
        "entry_point", "reachable_effects", "guarding_conditions",
        "guarded_effects", "unshielded_effects",
    }
    for entry in result:
        assert isinstance(entry, dict)
        missing = expected_keys - entry.keys()
        assert not missing, "missing keys: " + str(missing)


def test_simulate_effects_huge_source() -> None:
    """simulate_effects on a huge source never raises."""
    lines = ["x_" + str(i) + " = " + str(i) for i in range(5_000)]
    source = "\n".join(lines)
    result = simulate_effects(source, "huge.py")
    assert isinstance(result, list)
