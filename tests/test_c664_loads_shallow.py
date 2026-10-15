"""C-664 slice A: `configloader.loads_shallow`, the reader of untrusted JSON that never recurses.

`json.loads` and `ast.literal_eval` give up (RecursionError) at a depth that belongs to the
interpreter and the process, and rejecting a document for being deep is an evasion when the
document is a third party's (a manifest padded past the limit stops declaring anything).
`loads_shallow` returns the shallow part of any document exactly as `json.loads` /
`loads_json5` return it, and replaces every subtree that opens past `max_depth` with the
`ELIDED` marker. These tests pin:

* the value is identical to the ordinary parser's for everything inside the bound (seeded
  differential fuzz in both modes, plus hand-written boundary, padding and JSON5 cases);
* it raises ValueError exactly where the ordinary parser does (the same fuzz, the context
  tricks that depend on a deep subtree being a LIST, unterminated strings, huge integers);
* it never recurses (100,000 and 1,000,000 levels, also with the recursion limit lowered);
* the marker cannot be forged, and the one known class of difference is pinned, not hidden.

Offline, stdlib only, writes nothing.
"""
from __future__ import annotations

import copy
import json
import random
import sys
import time
import traceback

import pytest

from clawseccheck import configloader
from clawseccheck.configloader import (
    ELIDED,
    SHALLOW_JSON_DEPTH,
    JSONNestingError,
    ShallowJSON,
    loads_json5,
    loads_shallow,
)

MODES = pytest.mark.parametrize("json5", [False, True], ids=["strict", "json5"])


def _nested(depth: int, inner: str = "") -> str:
    return "[" * depth + inner + "]" * depth


def _truncate(value, bound: int, level: int = 0):
    """What an unlimited parser's value looks like once everything past `bound` is ELIDED."""
    if isinstance(value, (list, dict)):
        level += 1
        if level > bound:
            return ELIDED
        if isinstance(value, list):
            return [_truncate(item, bound, level) for item in value]
        return {key: _truncate(item, bound, level) for key, item in value.items()}
    return value


def _canon(value):
    """A comparable form (NaN != NaN, so compare through json.dumps) with ELIDED visible."""
    if value is ELIDED:
        return {"<elided>": 1}
    if isinstance(value, list):
        return [_canon(item) for item in value]
    if isinstance(value, dict):
        return {key: _canon(item) for key, item in value.items()}
    return value


def _same(left, right) -> bool:
    return json.dumps(_canon(left), allow_nan=True) == json.dumps(_canon(right), allow_nan=True)


def _depth_of(value) -> int:
    """Nesting depth of a parsed value, iteratively (the value itself can be 64 levels)."""
    deepest = 0
    todo = [(value, 0)]
    while todo:
        node, level = todo.pop()
        if isinstance(node, list):
            level += 1
            deepest = max(deepest, level)
            todo.extend((item, level) for item in node)
        elif isinstance(node, dict):
            level += 1
            deepest = max(deepest, level)
            todo.extend((item, level) for item in node.values())
    return deepest


def _ordinary(text: str, json5: bool):
    return loads_json5(text) if json5 else json.loads(text)


# ----------------------------------------------------------------------------- the surface
def test_surface():
    assert SHALLOW_JSON_DEPTH == 64
    result = loads_shallow('{"a": [1, 2]}')
    assert isinstance(result, ShallowJSON)
    assert result == ({"a": [1, 2]}, 0)
    assert (result.value, result.elided) == ({"a": [1, 2]}, 0)


def test_elided_is_a_singleton_that_cannot_pass_for_data():
    assert not isinstance(ELIDED, (str, list, dict, int, float, tuple))
    assert repr(ELIDED) == "ELIDED"
    assert copy.copy(ELIDED) is ELIDED
    assert copy.deepcopy({"k": [ELIDED]})["k"][0] is ELIDED
    with pytest.raises(TypeError):
        json.dumps({"k": ELIDED})  # loud, never a silent empty value


def test_max_depth_must_be_a_positive_integer():
    for bad in (0, -1, 1.5, "3", None, True):
        with pytest.raises(ValueError):
            loads_shallow("[]", max_depth=bad)


def test_text_must_be_text():
    with pytest.raises(TypeError):
        loads_shallow(5)  # as json.loads
    with pytest.raises(TypeError):
        loads_shallow(None)


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "utf-16", "utf-32"])
def test_bytes_are_decoded_the_way_json_loads_decodes_them(encoding):
    text = '{"name": "café", "deep": %s}' % _nested(100)
    data = text.encode(encoding)
    assert json.loads(data) == json.loads(text)
    assert _same(loads_shallow(data, max_depth=8).value, loads_shallow(text, max_depth=8).value)
    assert loads_shallow(bytearray(data), max_depth=8).elided == 1
    with pytest.raises(ValueError):
        loads_shallow(b"\xff\xfe\xfa[1]")


# ----------------------------------------------------------- identical inside the bound
SHALLOW_DOCS = [
    "[]", "{}", "0", "-1.5e3", '"text"', "true", "false", "null", "NaN", "Infinity", "-Infinity",
    '{"b": 1, "a": [1, {"c": null}], "b": 2}',            # duplicate key: the last one wins
    '{"\\u006b": "\\ud800", "n": 12345678901234567890123}',  # escapes, lone surrogate, big int
    '  \n\t[1, 2,\n 3]  ',
    '{"nested": %s}' % _nested(SHALLOW_JSON_DEPTH - 1),     # exactly at the bound
    _nested(SHALLOW_JSON_DEPTH),
]


@MODES
@pytest.mark.parametrize("text", SHALLOW_DOCS)
def test_a_document_within_the_bound_is_what_the_ordinary_parser_returns(text, json5):
    got = loads_shallow(text, json5=json5)
    assert _same(got.value, _ordinary(text, json5))
    assert got.elided == 0


@MODES
@pytest.mark.parametrize("bound", [1, 2, 5, SHALLOW_JSON_DEPTH])
def test_the_bound_is_exact(bound, json5):
    # `bound` levels are all kept ...
    at = loads_shallow(_nested(bound), json5=json5, max_depth=bound)
    assert at.value == json.loads(_nested(bound)) and at.elided == 0
    # ... and the array that opens at level bound + 1 is the marker, and nothing else is lost.
    over = loads_shallow(_nested(bound + 1), json5=json5, max_depth=bound)
    expect = ELIDED
    for _ in range(bound):
        expect = [expect]
    assert over.value == expect and over.elided == 1
    assert _depth_of(over.value) == bound


@MODES
def test_objects_count_as_levels_too(json5):
    text = '{"a": {"b": [{"c": 1}]}, "z": 1}'
    got = loads_shallow(text, json5=json5, max_depth=3)
    assert got.value == {"a": {"b": [ELIDED]}, "z": 1} and got.elided == 1


# --------------------------------------------------------------- padding hides nothing
@MODES
@pytest.mark.parametrize("pad", [SHALLOW_JSON_DEPTH + 1, 201, 1_000, 100_000])
def test_a_padded_manifest_still_declares_what_it_declares(pad, json5):
    # The evasion that sank a fixed limit: `skills` and `id` sit beside a subtree padded to
    # any depth. Every field must be read exactly as in the unpadded document.
    text = '{"id": "evil", "pad": %s, "skills": ["./payload"], "configSchema": {"type": "object"}}' % (
        _nested(pad))
    plain = '{"id": "evil", "pad": [], "skills": ["./payload"], "configSchema": {"type": "object"}}'
    got = loads_shallow(text, json5=json5)
    assert got.value["id"] == "evil"
    assert got.value["skills"] == ["./payload"]
    assert got.value["configSchema"] == {"type": "object"}
    assert got.elided == 1
    assert list(got.value) == list(json.loads(plain))
    # the padded subtree is kept as far as the bound reaches, then the marker
    assert _depth_of(got.value["pad"]) == SHALLOW_JSON_DEPTH - 1
    assert got.value["id"] == json.loads(plain)["id"]


@MODES
def test_two_deep_subtrees_are_counted_and_a_discarded_one_is_not(json5):
    deep = _nested(100)
    two = loads_shallow('{"a": %s, "b": [%s]}' % (deep, deep), json5=json5, max_depth=4)
    assert two.elided == 2
    # A duplicate key throws the first value away, marker included: the count is of what is IN
    # the result.
    dup = loads_shallow('{"a": %s, "a": 1}' % deep, json5=json5, max_depth=4)
    assert dup.value == {"a": 1} and dup.elided == 0
    dup = loads_shallow('{"a": 1, "a": %s}' % deep, json5=json5, max_depth=4)
    assert dup.elided == 1 and dup.value == {"a": [[[ELIDED]]]}


@MODES
def test_brackets_inside_strings_are_not_nesting(json5):
    text = '{"a": "%s", "b": ["%s"]}' % ("[" * 5000, "{" * 5000)
    got = loads_shallow(text, json5=json5, max_depth=3)
    assert got.value == json.loads(text) and got.elided == 0
    # ... also after escaped quotes and escaped backslashes
    text = '[["\\"%s", "\\\\"], %s]' % ("[" * 200, _nested(10))
    got = loads_shallow(text, json5=json5, max_depth=4)
    assert got.value[0] == ['"' + "[" * 200, "\\"] and got.elided == 1


# ------------------------------------------------------------------ the large cases
@MODES
@pytest.mark.parametrize("levels", [100_000, 1_000_000])
def test_enormous_nesting_is_read_without_recursion_and_fast(levels, json5):
    text = '{"skills": ["./evil"], "pad": %s, "id": "x"}' % _nested(levels)
    if json5:
        text = "// a comment\n" + text  # forces the JSON5 reader
    started = time.perf_counter()
    got = loads_shallow(text, json5=json5)
    took = time.perf_counter() - started
    assert got.value["skills"] == ["./evil"] and got.value["id"] == "x"
    assert got.elided == 1
    assert _depth_of(got.value["pad"]) == SHALLOW_JSON_DEPTH - 1
    if levels == 1_000_000:
        assert took < 5, f"1,000,000 levels took {took:.1f}s"


@MODES
def test_the_answer_does_not_depend_on_the_recursion_limit(json5):
    # Control first: the lowered limit really is in force for ordinary Python code.
    here = len(traceback.extract_stack())

    def recurse(n):
        return 0 if n == 0 else 1 + recurse(n - 1)

    text = '{"pad": %s, "id": "x"}' % _nested(100_000)
    if json5:
        text = "// c\n" + text
    previous = sys.getrecursionlimit()
    sys.setrecursionlimit(here + 400)
    try:
        with pytest.raises(RecursionError):
            recurse(here + 600)
        got = loads_shallow(text, json5=json5)
    finally:
        sys.setrecursionlimit(previous)
    assert got.value["id"] == "x" and got.elided == 1


def test_a_stack_too_small_for_the_parser_is_a_value_error_not_recursion_error(monkeypatch):
    def refuse(*_args, **_kwargs):
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(configloader.json, "loads", refuse)
    with pytest.raises(JSONNestingError) as seen:
        loads_shallow("[1]")
    assert isinstance(seen.value, ValueError) and not isinstance(seen.value, RecursionError)
    with pytest.raises(JSONNestingError):
        loads_shallow(_nested(500), max_depth=4)  # the layered read has the same answer


# --------------------------------------------------------------- errors are the parser's
INVALID = [
    "", "   ", "[", "]", "{", "}", "[1,]", '{"a"}', '{"a":1,}', "nul", "[1 2]", "'x'", "{1: 2}",
    "﻿[]", '["a\nb"]', '"\\x41"', "1e", "--1", '{"a": [1, 2}', "[1]x", "[1][2]",
]


@MODES
@pytest.mark.parametrize("text", INVALID)
def test_invalid_text_is_a_value_error_where_the_ordinary_parser_raises(text, json5):
    try:
        expected = ("ok", _ordinary(text, json5))
    except ValueError:
        expected = ("error", None)
    try:
        got = ("ok", loads_shallow(text, json5=json5).value)
    except ValueError:
        got = ("error", None)
    assert got[0] == expected[0]
    if expected[0] == "ok":
        assert _same(got[1], expected[1])


@MODES
@pytest.mark.parametrize("make", [
    lambda d: "[" * d,                                        # never closed
    lambda d: "]" * d,
    lambda d: "[" * d + "}" * d,                              # wrong closer
    lambda d: _nested(d) + "x",                               # trailing garbage
    lambda d: _nested(d) + "]",                               # one closer too many
    lambda d: _nested(d, "1,,"),                              # empty slot
    lambda d: _nested(d, '"unterminated'),                    # the string swallows the closers
    lambda d: _nested(d, '"a\nb"'),                           # raw control character in a string
    lambda d: _nested(d, "9" * 5000),                         # integer past the digit limit
    lambda d: _nested(d, "01"),
    lambda d: "[" * d + "1 2" + "]" * d,
    lambda d: '{"a":' * d + "1" + "}" * d + "}",
])
@pytest.mark.parametrize("depth", [3, 100, 5_000])
def test_deep_invalid_text_is_a_value_error(make, depth, json5):
    text = make(depth)
    if depth <= 100:
        with pytest.raises(ValueError):  # the ordinary parser agrees on the small instance
            _ordinary(text, json5)
    with pytest.raises(ValueError):
        loads_shallow(text, json5=json5, max_depth=2)
    with pytest.raises(ValueError):
        loads_shallow(text, json5=json5)


@MODES
def test_a_deep_subtree_does_not_hide_an_error_elsewhere_in_the_document(json5):
    deep = _nested(500)
    for text in ('{"a": %s, "b": }' % deep, '{"a": %s "b": 1}' % deep, '{"a": %s,, "b": 1}' % deep,
                 '{"a": %s}x' % deep, '[%s, 1 2]' % deep):
        with pytest.raises(ValueError):
            loads_shallow(text, json5=json5)


@MODES
def test_an_error_inside_the_deep_subtree_is_still_an_error(json5):
    # The elided part is parsed too: it cannot smuggle in text no parser would accept.
    for inner in ("1 2", '"a\nb"', "[,]", "{,}", '{"a" 1}', "tru"):
        text = '{"id": "x", "pad": %s}' % _nested(200, inner)
        with pytest.raises(ValueError):
            loads_shallow(text, json5=json5)
        with pytest.raises(ValueError):
            loads_shallow(_nested(200, inner), json5=json5, max_depth=3)


@MODES
def test_a_huge_integer_is_a_value_error_as_in_json_loads(json5):
    digits = "9" * 5000
    shallow = "[" + digits + "]"
    with pytest.raises(ValueError):
        json.loads(shallow)
    with pytest.raises(ValueError):
        loads_shallow(shallow, json5=json5)
    with pytest.raises(ValueError):
        loads_shallow(_nested(300, digits), json5=json5)


@MODES
def test_the_context_tricks_that_need_the_deep_subtree_to_be_a_list_fail_as_the_original_does(json5):
    # Each of these is invalid because of WHAT FOLLOWS a bracketed value, and each turns into
    # something valid if the deep subtree is replaced by an opaque string. It is replaced by a
    # list of its own kind, so the verdict is the original's.
    deep = _nested(100)
    for template in ("{%s: 1}", '{"a", %s}', '"a" %s', "r%s", "1%s", "%s %s", "{%s}", "-%s",
                     "(%s", "%s)", "[%s,,]", '{"a": 1 %s}'):
        text = template % ((deep, deep) if template.count("%s") == 2 else (deep,))
        with pytest.raises(ValueError):
            _ordinary(text, json5)  # 100 levels: the ordinary parser answers on every Python
        with pytest.raises(ValueError):
            loads_shallow(text, json5=json5, max_depth=8)
        with pytest.raises(ValueError):
            loads_shallow(text, json5=json5, max_depth=1)


def test_a_valid_context_around_a_deep_subtree_is_not_refused():
    deep = _nested(100)
    assert loads_shallow("[%s, %s]" % (deep, deep), max_depth=8).elided == 2
    # Python lets a parenthesised value through `ast.literal_eval`; the JSON5 reader inherits it.
    assert loads_shallow("(%s)" % deep, json5=True, max_depth=8).elided == 1


# --------------------------------------------------------------------------- JSON5 lexing
def test_json5_brackets_in_comments_and_single_quoted_strings_are_not_nesting():
    comment = "// " + "[" * 500 + "\n"
    block = "/* " + "{" * 500 + " */"
    text = comment + block + "{ key: 'x' , note: '" + "[" * 500 + "', list: [1, 2,], }"
    got = loads_shallow(text, json5=True, max_depth=3)
    assert got.value == {"key": "x", "note": "[" * 500, "list": [1, 2]} and got.elided == 0
    assert got.value == loads_json5(text)


def test_json5_a_bracket_in_a_comment_does_not_close_or_open_anything():
    deep = _nested(100)
    text = "// ] ] ]\n{ pad: %s, /* [ [ [ */ id: 'x', // }\n }" % deep
    got = loads_shallow(text, json5=True, max_depth=4)
    assert got.value["id"] == "x" and got.elided == 1
    assert got.value == _truncate(loads_json5(text), 4)


def test_json5_double_slash_inside_a_string_is_not_a_comment():
    text = "{ url: 'http://example.test/a', pad: %s, other: \"b//c\" }" % _nested(100)
    got = loads_shallow(text, json5=True, max_depth=4)
    assert got.value["url"] == "http://example.test/a" and got.value["other"] == "b//c"
    assert got.elided == 1


def test_json5_escaped_quote_in_a_single_quoted_string():
    text = "{ a: 'it\\'s [', pad: %s, b: 'x' }" % _nested(100)
    got = loads_shallow(text, json5=True, max_depth=4)
    assert got.value["a"] == "it's [" and got.value["b"] == "x" and got.elided == 1


def test_json5_unterminated_block_comment_is_a_value_error():
    with pytest.raises(ValueError):
        loads_shallow("[1] /* never closed", json5=True)
    with pytest.raises(ValueError):
        loads_shallow("/* x\n" + _nested(300), json5=True)


def test_json5_nan_infinity_unquoted_keys_and_trailing_commas():
    text = "{ n: NaN, i: Infinity, m: -Infinity, list: [1, 2,], pad: %s, }" % _nested(100)
    got = loads_shallow(text, json5=True, max_depth=3)
    assert got.value["n"] != got.value["n"]  # NaN
    assert got.value["i"] == float("inf") and got.value["m"] == float("-inf")
    assert got.value["list"] == [1, 2] and got.elided == 1


def test_json5_strict_json_is_read_by_the_json_parser_not_the_literal_one():
    # `\/` is a valid JSON escape ("/"). loads_json5 asks json.loads first, so a document that
    # is valid JSON gets "/", also when it is deep; a document that needs the JSON5 reader gets
    # "/" too (C-728: the JSON5 reader applies JSON5's escape rules, not Python's, which read
    # a backslash and a slash), also deep.
    strict = '{"p": "a\\/b", "pad": %s}' % _nested(100)
    assert loads_shallow(strict, json5=True, max_depth=4).value["p"] == "a/b"
    lenient = "// c\n{\"p\": \"a\\/b\", \"pad\": %s}" % _nested(100)
    expected = loads_json5(lenient)["p"]
    assert loads_shallow(lenient, json5=True, max_depth=4).value["p"] == expected
    assert expected == "a/b"


@pytest.mark.parametrize("text", [
    "[[ # ]\n 1 ]]",                       # a Python comment hides a bracket
    "['''[[[''']",                         # a Python triple-quoted string holds brackets
    '["""]]]"""]',
    "[ [ # [ \n ] ]",
])
def test_json5_python_only_spellings_are_parsed_whole_as_loads_json5_parses_them(text):
    # Neither `#` comments nor triple-quoted strings are JSON5; `ast.literal_eval` accepts
    # them and the layer scan cannot follow them, so the text is not layered: the value is
    # exactly loads_json5's (nothing elided) even when the bound is smaller than its depth.
    expected = loads_json5(text)
    got = loads_shallow(text, json5=True, max_depth=1)
    assert got.value == expected and got.elided == 0


def test_json5_python_only_spelling_in_a_too_deep_document_is_refused_never_a_crash():
    for text in ("# c\n" + _nested(300_000), "['''x''', %s]" % _nested(300_000)):
        with pytest.raises(ValueError) as seen:
            loads_shallow(text, json5=True)
        assert not isinstance(seen.value, RecursionError)


def test_json5_with_a_python_comment_is_not_elided_and_a_too_deep_one_is_refused():
    # The caveat in the loads_shallow docstring, pinned as measured: `#` (or a tripled quote)
    # outside a string sends the text down the whole-text path, so the usual guarantee that
    # everything past max_depth becomes ELIDED does not hold there.
    text = '{"skills":[1],"pad":' + _nested(100) + "} # c"
    got = loads_shallow(text, json5=True, max_depth=8)
    assert got.elided == 0 and got.value["skills"] == [1]
    assert _depth_of(got.value) == 101  # root + 100: nothing was cut at max_depth + 1
    assert got.value == loads_json5(text)
    # The same document without the comment IS cut at the bound (the control).
    plain = loads_shallow('{"skills":[1],"pad":' + _nested(100) + "}", json5=True, max_depth=8)
    assert plain.elided == 1 and _depth_of(plain.value) == 8
    # Deeper than literal_eval follows: a ValueError, not a crash and not a reading.
    for refused in (_nested(300) + " # x", "# x\n" + _nested(300)):
        with pytest.raises(ValueError) as seen:
            loads_shallow(refused, json5=True)
        assert not isinstance(seen.value, RecursionError)
        with pytest.raises(ValueError):
            loads_json5(refused)


def test_json5_layers_are_parsed_separately_so_a_paren_heavy_document_is_accepted():
    # Accepted difference, never the reverse: `ast.literal_eval` refuses 200 nested
    # brackets/parentheses in one text, but no single layer here reaches that. 100 parens
    # around 150 brackets is 250 in loads_json5's eyes and 100 + 65 in each layer's.
    text = "(" * 100 + "[" * 150 + "]" * 150 + ")" * 100
    with pytest.raises(ValueError):
        loads_json5(text)
    got = loads_shallow(text, json5=True)
    assert got.elided == 1 and _depth_of(got.value) == SHALLOW_JSON_DEPTH
    # Never the reverse: the same shape with fewer parens is accepted by both, and the
    # layered read is loads_json5's value cut at the bound.
    ok = "(" * 20 + "[" * 150 + "]" * 150 + ")" * 20
    expected = loads_json5(ok)
    assert _same(loads_shallow(ok, json5=True).value, _truncate(expected, SHALLOW_JSON_DEPTH))


# ------------------------------------------------------------------ the marker is not forgeable
class _Nonces:
    """Stands in for `secrets.token_hex`: hands out a fixed list of values, in order."""

    def __init__(self, *values):
        self.values = list(values)
        self.calls = 0

    def __call__(self, nbytes=32):
        self.calls += 1
        return self.values.pop(0)


def _escaped(token: str) -> str:
    return "".join("\\u%04x" % ord(c) for c in token)


FIRST, SECOND = "a" * 32, "b" * 32


@MODES
def test_the_nonce_is_random_per_call_and_long(monkeypatch, json5):
    seen = []
    real = configloader.secrets.token_hex

    def spy(nbytes=32):
        value = real(nbytes)
        seen.append(value)
        return value

    monkeypatch.setattr(configloader.secrets, "token_hex", spy)
    for _ in range(3):
        loads_shallow('{"a": %s}' % _nested(100), json5=json5, max_depth=4)
    assert len(seen) == 3 and len(set(seen)) == 3
    assert all(len(token) >= 32 for token in seen)


@MODES
def test_a_nonce_that_occurs_in_the_text_is_replaced_not_trusted(monkeypatch, json5):
    nonces = _Nonces(FIRST, SECOND)
    monkeypatch.setattr(configloader.secrets, "token_hex", nonces)
    # The document carries a list that looks exactly like a marker made with the first nonce.
    text = '{"decoy": ["%s"], "pad": %s}' % (FIRST, _nested(100))
    got = loads_shallow(text, json5=json5, max_depth=4)
    assert got.value["decoy"] == [FIRST]  # kept as the data it is, not turned into ELIDED
    assert got.elided == 1 and nonces.calls == 2


@MODES
def test_a_string_that_only_decodes_to_the_nonce_is_refused(monkeypatch, json5):
    # The nonce is not in the text, so it is accepted; the escapes spell it once decoded.
    forged = _escaped(FIRST)
    deep = _nested(100)
    for text in ('{"a": "%s", "pad": %s}' % (forged, deep),             # a string value
                 '{"%s": 1, "pad": %s}' % (forged, deep),               # a key
                 '{"a": ["x", "%s"], "pad": %s}' % (forged, deep)):     # a longer list
        monkeypatch.setattr(configloader.secrets, "token_hex", _Nonces(FIRST))
        assert FIRST not in text
        with pytest.raises(ValueError):
            loads_shallow(text, json5=json5, max_depth=4)


@MODES
def test_more_markers_than_the_text_inserted_is_refused(monkeypatch, json5):
    # One deep subtree means one marker; a forged lookalike beside it makes two.
    monkeypatch.setattr(configloader.secrets, "token_hex", _Nonces(FIRST))
    text = '{"real": %s, "fake": ["%s"]}' % (_nested(100), _escaped(FIRST))
    with pytest.raises(ValueError):
        loads_shallow(text, json5=json5, max_depth=4)


# ------------------------------------------------------- the one pinned class of difference
def test_pinned_difference_python_only_value_inside_a_discarded_deep_subtree():
    # `loads_json5` reads the WHOLE text with `ast.literal_eval`, then drops the first "a"
    # (a later duplicate key replaces it) before it checks that every value is JSON. The
    # layered read checks each layer on its own, so a Python-only literal (a set, a tuple, a
    # bytes literal, an integer key) inside a layer deeper than the bound is seen, and the
    # text is refused, where `loads_json5` accepts it (`{"a": 1}`). Refusing is the safe
    # direction: these literals are Python, not JSON5, so the text is not a document OpenClaw
    # itself would read. Pinned so it cannot change unnoticed.
    for literal in ("{1, 2}", "(1,)", "b'x'", "{1: 2}"):
        text = "{'a': [[[ %s ]]], 'a': 1}" % literal
        assert loads_json5(text) == {"a": 1}
        with pytest.raises(ValueError):
            loads_shallow(text, json5=True, max_depth=1)
        # The same literal inside the bound (layer 0) is dropped exactly as loads_json5 drops it.
        shallow = "{'a': %s, 'a': 1}" % literal
        assert loads_json5(shallow) == {"a": 1}
        assert loads_shallow(shallow, json5=True, max_depth=4).value == {"a": 1}
        # Not discarded: both refuse.
        for kept in ("{'a': [[[ %s ]]]}" % literal, "{'a': 1, 'b': [[[ %s ]]]}" % literal):
            with pytest.raises(ValueError):
                loads_json5(kept)
            with pytest.raises(ValueError):
                loads_shallow(kept, json5=True, max_depth=1)


# ------------------------------------------------------------------ differential fuzz
_ATOMS_VALID = [
    "1", "-0.5e3", "0", "true", "false", "null", '"a"', '"[{"', '"\\"]"', '"\\\\"', '"\\u0041"',
    '"\\/"', '"\\ud800"', "1e999", "[]", "{}", '"{[ ]}"', "NaN", "Infinity", "-Infinity",
]
_ATOMS_JSON5 = [
    "'s[q'", "'it\\'s]'", "/*[*/1", "// ]\n2", "+1", "0x1F", ".5", "'a\\x41'", '"a" "b"',
    "1_0", "'x' // [\n", "'\\\n'",
]
_ATOMS_BROKEN = ['"x\ny"', "9" * 5000, "'''[[['''", "# ]\n1", '"""[["""', "(1,)", "\\", "tru"]
_KEYS_VALID = ['"k"', '"k"', '"[x"', '"\\u006b"', '"z"', '""']
_KEYS_JSON5 = ["k", "'k'", "$k", "_k", "'a]'"]
_MUTATIONS = ["[", "]", "{", "}", ",", ":", '"', "'", "\\", "x", "", "/*", "*/", "//", "#"]


def _document(rng: random.Random, level: int, atoms, keys, tails) -> str:
    roll = rng.random()
    if level > 8 or roll < (0.08 if level < 4 else 0.3):
        return rng.choice(atoms)
    if roll < 0.65:
        items = ",".join(_document(rng, level + 1, atoms, keys, tails)
                         for _ in range(rng.randint(0, 3)))
        return "[" + items + (rng.choice(tails) if items else "") + "]"
    pairs = ",".join(
        "%s:%s" % (rng.choice([rng.choice(keys), '"z"']),
                   _document(rng, level + 1, atoms, keys, tails))
        for _ in range(rng.randint(0, 3)))
    return "{" + pairs + "}"


def _mutate(rng: random.Random, text: str, rate: float) -> str:
    if not text or rng.random() >= rate:
        return text
    at = rng.randrange(len(text))
    return text[:at] + rng.choice(_MUTATIONS) + text[at + 1:]


def _outcome(read):
    try:
        return "ok", read()
    except ValueError:
        return "error", None


def _fuzz(seed: int, documents: int, json5: bool, bounds, mutation_rate: float, atoms, keys):
    tails = ["", "", ",", " // ]\n"] if json5 else ["", "", "", " "]
    import warnings
    rng = random.Random(seed)
    stats = {"cases": 0, "ok": 0, "error": 0, "elided": 0, "mismatch": []}
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # literal_eval warns about invalid escapes
        for _ in range(documents):
            text = _mutate(rng, _document(rng, 0, atoms, keys, tails), mutation_rate)
            reference = _outcome(lambda t=text: _ordinary(t, json5))
            for bound in bounds:
                stats["cases"] += 1
                got = _outcome(lambda t=text, b=bound: loads_shallow(t, json5=json5, max_depth=b))
                if got[0] != reference[0]:
                    stats["mismatch"].append(("outcome", bound, text[:120]))
                    continue
                stats[got[0]] += 1
                if got[0] == "error":
                    continue
                result = got[1]
                if result.elided:
                    stats["elided"] += 1
                if not _same(result.value, _truncate(reference[1], bound)):
                    # `#` and tripled quotes are parsed whole (not layered, so not truncated)
                    if not (json5 and ("#" in text or "'''" in text or '"""' in text)
                            and _same(result.value, reference[1])):
                        stats["mismatch"].append(("value", bound, text[:120]))
    return stats


@pytest.mark.parametrize("json5", [False, True], ids=["strict", "json5"])
def test_fuzz_agrees_with_the_ordinary_parser(json5):
    # Seeded; documents up to 9 levels read with bounds 1, 2, 3 and 5, so many of them are
    # layered (and the ordinary parser can still answer for the reference). Python-only
    # literals are left out here: their one class of difference is pinned above. A quarter of
    # the documents carry one random character edit, so refusals are exercised as much as
    # values. The run is deterministic (seeds 664 / 665): strict 7,844 valid, 2,156 refused,
    # 4,261 with a marker in the result; json5 7,472 / 2,528 / 3,665 (out of 10,000 cases
    # each). Only the floors below are asserted, so a change of generator needs no edit here.
    atoms = (_ATOMS_VALID + (_ATOMS_JSON5 if json5 else [])) * 25 + (
        _ATOMS_BROKEN if json5 else [])
    keys = _KEYS_VALID + (_KEYS_JSON5 if json5 else [])
    atoms = [a for a in atoms if a != "(1,)"]
    stats = _fuzz(seed=664 + json5, documents=2_500, json5=json5, bounds=(1, 2, 3, 5),
                  mutation_rate=0.25, atoms=atoms, keys=keys)
    assert stats["mismatch"] == [], stats["mismatch"][:5]
    assert stats["cases"] == 2_500 * 4
    # The fuzz must exercise the layered path, valid documents and refusals alike.
    assert stats["ok"] > 6_000 and stats["error"] > 1_000, stats
    assert stats["elided"] > 2_500, stats


@pytest.mark.parametrize("json5", [False, True], ids=["strict", "json5"])
def test_fuzz_inside_the_bound_is_exactly_the_ordinary_parser(json5):
    # Same generator, but a bound no document reaches: no layering, no marker, no difference.
    atoms = _ATOMS_VALID + (_ATOMS_JSON5 if json5 else [])
    keys = _KEYS_VALID + (_KEYS_JSON5 if json5 else [])
    stats = _fuzz(seed=7_664 + json5, documents=500, json5=json5, bounds=(64,),
                  mutation_rate=0.3, atoms=atoms, keys=keys)
    assert stats["mismatch"] == [], stats["mismatch"][:5]
    assert stats["elided"] == 0 and stats["ok"] > 150, stats
