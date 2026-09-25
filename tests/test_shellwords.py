"""CLAWSECCHECK-B-986 P2: clawseccheck/shellwords.py -- the real (non-shlex)
shell word/command splitter curlargv.py's positional parsing is built on.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from clawseccheck import shellwords as sw


def _words(text: str):
    cmds = sw.scan_line(text)
    assert cmds is not None
    assert len(cmds) == 1
    return cmds[0].words


def _word_texts(text: str):
    return [w.text for w in _words(text)]


# ---------------------------------------------------------------------------
# Basic splitting
# ---------------------------------------------------------------------------


def test_simple_command_splits_on_whitespace():
    assert _word_texts("curl -sS https://example.com") == [
        "curl",
        "-sS",
        "https://example.com",
    ]


def test_word_positions_are_absolute_offsets():
    text = "curl https://example.com"
    words = _words(text)
    for w in words:
        assert text[w.start : w.end] == w.text


def test_multiple_spaces_and_tabs_collapse():
    assert _word_texts("curl   \t  -sS\thttps://x") == ["curl", "-sS", "https://x"]


# ---------------------------------------------------------------------------
# Simple-command separators
# ---------------------------------------------------------------------------


def test_semicolon_splits_two_commands():
    cmds = sw.scan_line("curl a; curl b")
    assert cmds is not None
    assert [tuple(w.text for w in c.words) for c in cmds] == [
        ("curl", "a"),
        ("curl", "b"),
    ]


def test_double_ampersand_splits_two_commands():
    cmds = sw.scan_line("curl a && curl b")
    assert cmds is not None
    assert len(cmds) == 2


def test_double_pipe_splits_two_commands():
    cmds = sw.scan_line("curl a || curl b")
    assert cmds is not None
    assert len(cmds) == 2


def test_single_pipe_splits_two_commands():
    cmds = sw.scan_line("curl a | grep b")
    assert cmds is not None
    assert len(cmds) == 2
    assert cmds[1].words[0].text == "grep"


def test_single_ampersand_splits_two_commands():
    cmds = sw.scan_line("curl a & curl b")
    assert cmds is not None
    assert len(cmds) == 2


def test_trailing_separator_with_no_following_command_is_tolerated():
    cmds = sw.scan_line("curl a;")
    assert cmds is not None
    assert len(cmds) == 1


# ---------------------------------------------------------------------------
# Quoting
# ---------------------------------------------------------------------------


def test_double_quoted_word_with_spaces_is_one_word():
    words = _words('curl -H "Authorization: Bearer xyz" https://x')
    assert [w.text for w in words] == [
        "curl",
        "-H",
        '"Authorization: Bearer xyz"',
        "https://x",
    ]


def test_single_quoted_word_with_spaces_is_one_word():
    words = _words("curl -d 'a b c' https://x")
    assert words[2].text == "'a b c'"


def test_quoted_word_parts_are_all_quoted():
    words = _words('curl -H "Authorization: Bearer xyz"')
    header = words[2]
    assert header.parts and all(p.quoted for p in header.parts)
    assert header.is_fully_literal


# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------


def test_variable_in_double_quotes_is_detected():
    words = _words('curl -H "Authorization: Bearer $TOKEN"')
    header = words[2]
    assert header.has_variable
    assert header.variable_count == 1
    var_parts = [p for p in header.parts if p.kind == "variable"]
    assert var_parts[0].text == "$TOKEN"
    assert var_parts[0].quoted is True


def test_braced_variable_is_detected():
    words = _words('curl "https://${API_SERVER}/api"')
    dest = words[1]
    var_parts = [p for p in dest.parts if p.kind == "variable"]
    assert len(var_parts) == 1
    assert var_parts[0].text == "${API_SERVER}"


def test_two_variables_in_one_word_both_counted():
    words = _words('curl "$A$B"')
    assert words[1].variable_count == 2


def test_bare_dollar_with_no_name_is_literal():
    words = _words("curl 'price=$'")
    # inside single quotes nothing is special at all -- sanity check first
    assert words[1].variable_count == 0
    words2 = _words('curl "price=$ more"')
    assert words2[1].variable_count == 0


def test_unquoted_variable_outside_quotes():
    words = _words("curl $URL")
    assert words[1].has_variable
    assert words[1].parts[0].quoted is False


# ---------------------------------------------------------------------------
# Command substitution
# ---------------------------------------------------------------------------


def test_dollar_paren_command_substitution_detected():
    words = _words('curl -H "Authorization: Bearer $(cat /var/run/secret)"')
    header = words[2]
    assert header.has_cmdsub
    sub = [p for p in header.parts if p.kind == "cmdsub"][0]
    assert sub.text == "$(cat /var/run/secret)"
    assert sub.quoted is True


def test_backtick_command_substitution_detected():
    words = _words("curl -H \"Authorization: Bearer `cat /var/run/secret`\"")
    header = words[2]
    assert header.has_cmdsub


def test_nested_parens_inside_command_substitution_stay_inside_one_part():
    words = _words('curl "$(echo $(echo inner))"')
    word = words[1]
    cmdsub_parts = [p for p in word.parts if p.kind == "cmdsub"]
    assert len(cmdsub_parts) == 1
    assert cmdsub_parts[0].text == "$(echo $(echo inner))"
    # nothing outside the quotes/cmdsub leaks in as a separate variable/glob part
    assert all(p.kind in ("cmdsub", "literal") for p in word.parts)


def test_quotes_inside_command_substitution_do_not_confuse_outer_quoting():
    words = _words('curl -H "X: $(echo "a b")" https://x')
    assert len(words) == 4
    assert words[3].text == "https://x"


# ---------------------------------------------------------------------------
# Globs / braces (shell-level semantics: quoting suppresses both)
# ---------------------------------------------------------------------------


def test_unquoted_star_is_glob():
    words = _words("curl -T *.key https://x")
    assert words[2].has_glob


def test_quoted_star_is_not_glob():
    words = _words('curl -T "*.key" https://x')
    assert not words[2].has_glob
    assert words[2].is_fully_literal


def test_bracket_class_glob():
    words = _words("curl file[0-9].txt")
    assert words[1].has_glob


def test_unquoted_brace_expansion_with_comma_detected():
    words = _words('curl "https://{a,b}/x"')
    # the whole word is double-quoted -> brace expansion is SUPPRESSED by
    # bash, so this must NOT be tagged brace (quoting wins).
    assert not words[1].has_brace


def test_unquoted_unquoted_brace_expansion_detected():
    words = _words("curl https://x/{a,b}")
    assert words[1].has_brace


def test_lone_brace_with_no_comma_or_range_is_not_expansion_shaped():
    words = _words("curl https://x/{foo}")
    assert not words[1].has_brace


def test_range_brace_expansion_detected():
    words = _words("curl https://x/{1..3}")
    assert words[1].has_brace


# ---------------------------------------------------------------------------
# Fail-closed: unbalanced / paren anomalies
# ---------------------------------------------------------------------------


def test_unbalanced_double_quote_returns_none():
    assert sw.scan_line('curl -H "Authorization: Bearer xyz') is None


def test_unbalanced_single_quote_returns_none():
    assert sw.scan_line("curl -d 'a b c") is None


def test_unbalanced_dollar_paren_returns_none():
    assert sw.scan_line('curl -H "Authorization: $(cat /x"') is None


def test_unbalanced_braced_variable_inside_double_quotes_returns_none():
    # _word_scan_state does not separately track `${` once already inside a
    # double-quoted context (only the outer quote's own close ends the
    # word) -- _split_word_parts is what must catch this case instead. See
    # its docstring.
    assert sw.scan_line('curl "${TOKEN"') is None


def test_unbalanced_braced_variable_unquoted_returns_none():
    assert sw.scan_line("curl ${TOKEN") is None


def test_bare_open_paren_at_command_position_returns_none():
    assert sw.scan_line("(cd /tmp && curl https://x)") is None


def test_bare_open_paren_inside_a_word_returns_none():
    assert sw.scan_line("curl foo(bar) https://x") is None


def test_stray_close_paren_returns_none():
    assert sw.scan_line("curl foo) https://x") is None


def test_arithmetic_expansion_is_tolerated_not_a_paren_anomaly():
    # $((...)) nests two '(' inside an already-open $( context -- must NOT
    # trip the bare-paren fail-closed rule.
    cmds = sw.scan_line("curl --retry $((1+2)) https://x")
    assert cmds is not None
    word = cmds[0].words[2]
    assert word.text == "$((1+2))"
    assert word.has_variable is False  # cmdsub, not variable
    assert word.has_cmdsub is True


# ---------------------------------------------------------------------------
# _sh_loop_word_end parity (moved from skillast.py -- same algorithm)
# ---------------------------------------------------------------------------


def test_sh_loop_word_end_simple_value():
    text = "TOKEN=abc123 next"
    end = sw._sh_loop_word_end(text, text.index("abc123"))
    assert text[text.index("abc123") : end] == "abc123"


def test_sh_loop_word_end_quoted_value_with_space():
    text = 'TOKEN="a b c" next'
    start = text.index('"')
    end = sw._sh_loop_word_end(text, start)
    assert text[start:end] == '"a b c"'


def test_sh_loop_word_end_never_crosses_newline():
    text = "TOKEN=abc\nnext"
    end = sw._sh_loop_word_end(text, text.index("abc"))
    assert end == text.index("\n")


def test_sh_loop_word_end_matches_word_scan_state_end():
    text = 'TOKEN="a $(cat /x) b" rest'
    start = text.index('"')
    end1 = sw._sh_loop_word_end(text, start)
    end2, unbalanced, anomaly = sw._word_scan_state(text, start)
    assert end1 == end2
    assert not unbalanced and not anomaly


# ---------------------------------------------------------------------------
# CLAWSECCHECK-B-986 round 5 P1: param_refs -- bare vs operator classifier
# ---------------------------------------------------------------------------


def _refs(text: str, name: str, lo: int = None, hi: int = None):
    if lo is None:
        lo = 0
    if hi is None:
        hi = len(text)
    return sw.param_refs(text, name, lo, hi)


def test_param_refs_unbraced_is_bare():
    text = "echo $t done"
    refs = _refs(text, "t")
    assert len(refs) == 1
    ref = refs[0]
    assert ref.bare is True
    assert text[ref.start : ref.end] == "$t"


def test_param_refs_exactly_braced_is_bare():
    text = 'echo "${t}" done'
    refs = _refs(text, "t")
    assert len(refs) == 1
    ref = refs[0]
    assert ref.bare is True
    assert text[ref.start : ref.end] == "${t}"


def test_param_refs_suffix_operator_truncation_is_operator():
    text = 'echo "${t%%pattern}" done'
    refs = _refs(text, "t")
    assert len(refs) == 1
    ref = refs[0]
    assert ref.bare is False
    assert text[ref.start : ref.end] == "${t%%pattern}"


def test_param_refs_pattern_substitution_is_operator():
    text = 'echo "${t/x/y}" done'
    refs = _refs(text, "t")
    assert len(refs) == 1
    assert refs[0].bare is False
    assert text[refs[0].start : refs[0].end] == "${t/x/y}"


def test_param_refs_substring_extraction_is_operator():
    text = 'echo "${t:0:0}" done'
    refs = _refs(text, "t")
    assert len(refs) == 1
    assert refs[0].bare is False


def test_param_refs_default_value_operator_is_operator():
    text = 'echo "${t:-}" done'
    refs = _refs(text, "t")
    assert len(refs) == 1
    assert refs[0].bare is False


def test_param_refs_error_if_unset_operator_is_operator():
    text = 'echo "${t:?}" done'
    refs = _refs(text, "t")
    assert len(refs) == 1
    assert refs[0].bare is False


def test_param_refs_assign_default_operator_is_operator():
    text = 'echo "${t=x}" done'
    refs = _refs(text, "t")
    assert len(refs) == 1
    assert refs[0].bare is False


def test_param_refs_hash_prefix_strip_is_operator():
    text = 'echo "${t#*}" done'
    refs = _refs(text, "t")
    assert len(refs) == 1
    assert refs[0].bare is False


def test_param_refs_unbalanced_brace_is_operator_spanning_to_hi():
    text = 'echo "${t%%unterminated'
    hi = len(text)
    refs = _refs(text, "t", 0, hi)
    assert len(refs) == 1
    ref = refs[0]
    assert ref.bare is False
    assert ref.end == hi


def test_param_refs_finds_references_inside_command_substitution():
    """The whole point: scan_line treats $(...) as one opaque cmdsub Part, so
    a Part-walking implementation would miss references inside it entirely.
    param_refs scans raw text, so it must still find them."""
    text = 'curl -H "Authorization: Bearer $(cat "${t%%x}")" https://x'
    refs = _refs(text, "t")
    assert len(refs) == 1
    ref = refs[0]
    assert ref.bare is False
    assert text[ref.start : ref.end] == "${t%%x}"


def test_param_refs_no_reference_to_a_different_name():
    text = "echo $team $t_other ${totally} done"
    refs = _refs(text, "t")
    assert refs == ()


def test_param_refs_respects_lo_hi_window():
    text = "$t $t $t"
    # only the middle reference (offsets 3-5) is in-window
    refs = _refs(text, "t", 3, 5)
    assert len(refs) == 1
    assert refs[0].start == 3


def test_param_refs_multiple_references_mixed_bare_and_operator():
    text = 'echo $t "${t}" "${t%%x}"'
    refs = _refs(text, "t")
    assert len(refs) == 3
    assert [r.bare for r in refs] == [True, True, False]


def test_param_refs_nested_braced_reference_inside_operator():
    text = 'echo "${t/x/${u}}"'
    refs_t = _refs(text, "t")
    assert len(refs_t) == 1
    assert refs_t[0].bare is False
    refs_u = _refs(text, "u")
    assert len(refs_u) == 1
    assert refs_u[0].bare is True


def test_param_refs_is_o_of_span_length_plus_hits_many_balanced_pairs():
    """Perf guard: N nested `${t:-` opens followed by N closes must not
    trigger an O(hits * text length) blowup (see the module comment above
    `param_refs` in shellwords.py)."""
    import time

    n = 8000
    text = ("${t:-" * n) + ("}" * n)
    start = time.monotonic()
    refs = sw.param_refs(text, "t", 0, len(text))
    elapsed = time.monotonic() - start
    assert len(refs) == n
    assert elapsed < 2.0


def test_param_refs_is_fast_on_many_unbalanced_opens():
    """Perf guard: N unbalanced `${t` opens (no closing brace at all) must
    each resolve in O(1) via the dict lookup, not a fresh balanced-end scan
    per hit."""
    import time

    n = 8000
    text = "${t " * n
    start = time.monotonic()
    refs = sw.param_refs(text, "t", 0, len(text))
    elapsed = time.monotonic() - start
    assert len(refs) == n
    assert all(not r.bare for r in refs)
    assert elapsed < 2.0
