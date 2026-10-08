"""C-648 round 2: the JSON nesting limit is OURS, not the interpreter's.

How deep a document `json.loads` follows before it raises RecursionError is a property of
the interpreter and, on CPython 3.14, of the process stack size (measured 2026-10-05: 991
levels on 3.9.25, 9,997 on 3.12.3, 57,974 on 3.14.4 with the default 8 MB stack and more
than 400,000 under `ulimit -s 65536`, which is what a CI runner has). A verdict that
depended on whether the parser happened to give up differed from machine to machine.
`configloader.json_nesting_exceeds` / `loads_bounded` decide from the TEXT, before any
parser runs, so the answer is one figure everywhere.

Nothing here takes an expectation from what `json.loads` does in the running interpreter
(the exceptions are the explicit checks that, within the limit, `loads_bounded` returns
exactly what `json.loads` returns, and that `loads_json5` - which reads untrusted manifests -
is NOT bounded by our limit). Offline, stdlib only, no files.
"""
from __future__ import annotations

import inspect
import json
import random
import time

import pytest

from clawseccheck import configloader
from clawseccheck.configloader import (
    JSONNestingError,
    MAX_JSON_NESTING,
    json_nesting_exceeds,
    loads_bounded,
    loads_json5,
)

LIMIT = MAX_JSON_NESTING


def _arrays(n: int) -> str:
    return "[" * n + "]" * n


def _objects(n: int) -> str:
    return '{"a":' * n + "1" + "}" * n


def _mixed(n: int) -> str:
    opens = ["[" if i % 2 == 0 else '{"a":' for i in range(n)]
    closes = ["]" if i % 2 == 0 else "}" for i in range(n)]
    return "".join(opens) + "1" + "".join(reversed(closes))


SHAPES = {"arrays": _arrays, "objects": _objects, "mixed": _mixed}


def test_the_limit_sits_between_every_real_document_and_every_interpreter():
    # Real documents measured 2026-10-05 nest at most 20 levels (files under ~/.openclaw),
    # 17 (the installed OpenClaw package) and 10 (SQLite state rows); the shallowest depth
    # an interpreter follows, CPython 3.9 from inside a 300-frame call stack, is 691.
    assert 100 <= LIMIT < 691


# ------------------------------------------------------------------------ the boundary
@pytest.mark.parametrize("kind", sorted(SHAPES))
@pytest.mark.parametrize("as_type", [str, bytes, bytearray])
def test_exact_boundary(kind, as_type):
    build = SHAPES[kind]

    def doc(n):
        text = build(n)
        return text if as_type is str else as_type(text.encode("ascii"))

    assert json_nesting_exceeds(doc(LIMIT - 1)) is False
    assert json_nesting_exceeds(doc(LIMIT)) is False
    assert json_nesting_exceeds(doc(LIMIT + 1)) is True
    assert json_nesting_exceeds(doc(LIMIT + 1000)) is True


@pytest.mark.parametrize("limit", [0, 1, 2, 7, 50])
def test_the_limit_argument_moves_the_boundary(limit):
    assert json_nesting_exceeds(_arrays(limit), limit) is False
    assert json_nesting_exceeds(_arrays(limit + 1), limit) is True
    assert json_nesting_exceeds(_objects(limit + 1), limit) is True


def test_a_wide_document_is_not_a_deep_one():
    # Many siblings at depth 2: the count of brackets is far above the limit, the depth is not.
    wide = "[" + ",".join(["[]"] * (LIMIT * 20)) + "]"
    assert wide.count("[") > LIMIT
    assert json_nesting_exceeds(wide) is False
    wide_objects = "{" + ",".join('"k%d":{"x":[1]}' % i for i in range(LIMIT * 5)) + "}"
    assert json_nesting_exceeds(wide_objects) is False


def test_a_deep_document_that_closes_and_reopens_counts_the_deepest_point():
    # Depth LIMIT, back out completely, then LIMIT + 1: only the deepest point matters.
    assert json_nesting_exceeds("[" + _arrays(LIMIT - 1) + "," + _arrays(LIMIT) + "]") is True
    assert json_nesting_exceeds("[" + _arrays(LIMIT - 1) + "," + _arrays(LIMIT - 1) + "]") is False


# --------------------------------------------------------------- brackets inside strings
def test_brackets_inside_a_string_do_not_count():
    assert json_nesting_exceeds('{"a": "' + "[" * (LIMIT * 3) + '"}') is False
    assert json_nesting_exceeds('{"a": "' + "{" * (LIMIT * 3) + '"}') is False
    assert json_nesting_exceeds('["' + "]" * (LIMIT * 3) + '"]') is False


def test_an_escaped_quote_does_not_end_the_string():
    # The quote after the backslash is part of the string, so the brackets after it are too.
    assert json_nesting_exceeds('{"a": "\\"' + "[" * (LIMIT * 3) + '"}') is False
    assert json_nesting_exceeds('{"a": "x\\"y\\"' + "[" * (LIMIT * 3) + '"}') is False


def test_a_backslash_before_a_quote_ends_the_string_when_it_is_itself_escaped():
    # `\\` is one backslash; the quote after it closes the string, so what follows is real.
    after = '{"a": "x\\\\", "b": %s}'
    assert json_nesting_exceeds(after % _arrays(LIMIT)) is True        # 1 + LIMIT levels
    assert json_nesting_exceeds(after % _arrays(LIMIT - 1)) is False   # exactly LIMIT levels
    # Three backslashes: `\\` then `\"`: the quote is escaped, the string runs on.
    swallowed = '{"a": "x\\\\\\" ' + "[" * (LIMIT * 3) + '"}'
    assert json_nesting_exceeds(swallowed) is False


def test_a_string_ending_in_an_escaped_backslash_closes_normally():
    assert json_nesting_exceeds('["\\\\"]') is False
    doc = '["a\\\\", ' + _arrays(LIMIT) + "]"
    assert json_nesting_exceeds(doc) is True  # the string closed: 1 + LIMIT real levels
    assert json_nesting_exceeds('["a\\\\", ' + _arrays(LIMIT - 1) + "]") is False


def test_non_ascii_text_in_strings_and_keys_is_inert():
    inert = '{"é中\U0001f600": "[[[[", "k": "é' + "[" * (LIMIT * 2) + '"}'
    assert json_nesting_exceeds(inert) is False
    assert json_nesting_exceeds(inert.encode("utf-8")) is False
    deep = '{"é中\U0001f600": ' + _arrays(LIMIT) + "}"
    assert json_nesting_exceeds(deep) is True
    assert json_nesting_exceeds(deep.encode("utf-8")) is True


# ------------------------------------------------------------------------- encodings
ENCODINGS = ["utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "utf-32",
             "utf-32-le", "utf-32-be"]


@pytest.mark.parametrize("encoding", ENCODINGS)
def test_bytes_are_read_the_way_json_loads_reads_them(encoding):
    over = ('{"s": "é[[[", "d": ' + _arrays(LIMIT) + "}").encode(encoding)
    under = ('{"s": "é[[[", "d": ' + _arrays(LIMIT - 1) + "}").encode(encoding)
    assert json_nesting_exceeds(over) is True, encoding
    assert json_nesting_exceeds(under) is False, encoding
    # ...and the brackets inside the (non-ASCII) string are not counted in any encoding.
    inert = ('{"s": "é' + "[" * (LIMIT * 2) + '"}').encode(encoding)
    assert json_nesting_exceeds(inert) is False, encoding
    # within the limit loads_bounded returns exactly what json.loads returns
    assert loads_bounded(under) == json.loads(under)
    with pytest.raises(JSONNestingError):
        loads_bounded(over)


# ------------------------------------------------------------ garbage never raises here
GARBAGE = [
    "", " ", "]", "][", "}{", "[[[", "[" * (LIMIT * 2), "]" * (LIMIT * 2), '"', '"\\', "\\",
    '{"a": "\\', '["abc', "[1,", "{,}", "\ud800", "[\ud800]", "\x00", "[\x00]",
    '"' * 7, "\\\\" * 5, '["\\"', '{"a":' * (LIMIT + 5),
    b"", b"\xff", b"\xff\xfe", b"\xff\xfe\x00", b"\x00\x00\x00", b"\x00\x00\x00\x00",
    b"[\xff]", b"\xef\xbb\xbf", b"\xef\xbb\xbf[", b"\xfe\xff", b"\xff\xfe\xff\xfe\xff",
    b'["\xe9"]', b"{\x00", b"\x00[",
]


@pytest.mark.parametrize("garbage", GARBAGE, ids=repr)
def test_the_scanner_itself_never_raises_on_garbage(garbage):
    assert json_nesting_exceeds(garbage) in (True, False)
    assert json_nesting_exceeds(garbage, 0) in (True, False)


@pytest.mark.parametrize("garbage", GARBAGE, ids=repr)
def test_loads_bounded_lets_the_parser_say_what_is_wrong(garbage):
    # Either the nesting limit or the parser's own ValueError - never anything else.
    with pytest.raises(ValueError):
        loads_bounded(garbage)


@pytest.mark.parametrize("not_text", [None, 5, 1.5, [], {}, ("[",)])
def test_a_non_text_input_is_not_the_scanners_business(not_text):
    assert json_nesting_exceeds(not_text) is False


# --------------------------------------------------------------------- loads_bounded
def test_loads_bounded_returns_what_json_loads_returns_within_the_limit():
    value = {"a": [1, 2.5, None, True, "x\"y\\"], "b": {"c": [{"d": []}]}, "e": "[[["}
    text = json.dumps(value)
    assert loads_bounded(text) == value
    assert loads_bounded(text.encode()) == value
    deepest = _arrays(LIMIT)
    assert loads_bounded(deepest) == json.loads(deepest)


def test_nesting_beyond_the_limit_is_a_value_error_with_a_message_that_names_the_limit():
    with pytest.raises(JSONNestingError) as info:
        loads_bounded(_arrays(LIMIT + 1))
    assert isinstance(info.value, ValueError)
    assert not isinstance(info.value, json.JSONDecodeError)
    message = str(info.value)
    assert str(LIMIT) in message
    assert "[" not in message and "{" not in message  # never echoes the document


def test_max_nesting_overrides_the_default():
    assert loads_bounded("[[[1]]]", max_nesting=3) == [[[1]]]
    with pytest.raises(JSONNestingError):
        loads_bounded("[[[[1]]]]", max_nesting=3)
    # a larger limit admits what the default refuses (the parser itself still decides after)
    assert loads_bounded(_arrays(LIMIT + 5), max_nesting=LIMIT + 5) == json.loads(
        _arrays(LIMIT + 5))


@pytest.mark.parametrize("depth", [LIMIT + 1, 1_500, 20_000, 400_000])
def test_over_the_limit_the_interpreters_parser_is_never_reached(monkeypatch, depth):
    """The claim of this task in one test: the answer comes from our limit. Depths 20,000
    and 400,000 are ones an interpreter (3.14 with a large stack) WOULD have parsed; the
    parser is replaced by a tripwire to prove it is not consulted."""
    def boom(*_a, **_k):
        raise AssertionError("json.loads was reached for an over-deep document")

    monkeypatch.setattr(configloader.json, "loads", boom)
    for build in (_arrays, _objects, _mixed):
        text = build(depth)
        with pytest.raises(JSONNestingError):
            loads_bounded(text)
        with pytest.raises(JSONNestingError):
            loads_bounded(text.encode("ascii"))


def test_at_the_limit_the_parser_is_reached(monkeypatch):
    seen = []
    real = json.loads

    def spy(data, *a, **k):
        seen.append(1)
        return real(data, *a, **k)

    monkeypatch.setattr(configloader.json, "loads", spy)
    assert loads_bounded(_arrays(LIMIT)) == real(_arrays(LIMIT))
    assert seen


# ------------------------------------------------- loads_json5 is deliberately not bounded
def test_loads_json5_has_no_nesting_limit_of_ours():
    # `loads_json5` is what reads untrusted third-party manifests (`vet_plugin`). A limit of
    # our own there would let a manifest padded past it hide what it declares, so the
    # historical behaviour stays: no `max_nesting` parameter, and a document just over
    # MAX_JSON_NESTING is parsed exactly as `json.loads` parses it (250 levels is far below
    # what any supported interpreter's parser gives up at).
    assert "max_nesting" not in inspect.signature(loads_json5).parameters
    depth = LIMIT + 50
    assert loads_json5(_arrays(depth)) == json.loads(_arrays(depth))


def test_loads_json5_still_reads_json5():
    text = "{ // a comment\n  key: 'single', list: [1, 2,], nested: {a: [[1]],},\n}"
    assert loads_json5(text) == {"key": "single", "list": [1, 2], "nested": {"a": [[1]]}}


# ------------------------------------------------------------------ cost (generous bounds)
def _cpu_seconds(fn, *args):
    start = time.process_time()
    result = fn(*args)
    return result, time.process_time() - start


def test_ten_megabytes_of_shallow_brackets_is_answered_quickly():
    # The adversarial "many shallow brackets" shape: far more brackets than the limit, none
    # of them deep. Measured ~0.16 s; the bound is two orders of magnitude of headroom.
    doc = "[" + ",".join(["[]"] * 3_300_000) + "]"
    assert len(doc) > 9_000_000
    answer, spent = _cpu_seconds(json_nesting_exceeds, doc)
    assert answer is False
    assert spent < 15, spent
    answer, spent = _cpu_seconds(json_nesting_exceeds, doc.encode())
    assert answer is False
    assert spent < 15, spent


def test_two_megabytes_of_nothing_but_brackets_is_answered_quickly():
    deep = "[" * 1_000_000 + "]" * 1_000_000
    answer, spent = _cpu_seconds(json_nesting_exceeds, deep)
    assert answer is True
    assert spent < 10, spent
    shallow = "[]" * 1_000_000
    answer, spent = _cpu_seconds(json_nesting_exceeds, shallow)
    assert answer is False
    assert spent < 10, spent


def test_a_two_megabyte_realistic_document_is_answered_quickly():
    doc = json.dumps([
        {"id": i, "name": 'item "%d" [x]' % i, "tags": ["a", "b", "c"], "nested": {"x": [1, 2, 3]},
         "text": "line\nbreak \\ backslash"}
        for i in range(17_000)
    ])
    assert len(doc) > 1_500_000
    answer, spent = _cpu_seconds(json_nesting_exceeds, doc)
    assert answer is False
    assert spent < 10, spent


def test_a_huge_run_of_escapes_does_not_blow_up_time_or_memory():
    # A regex that loops over escape pairs holds ~60 bytes of backtracking state per pair
    # (measured: 600 MB for a 10 MB string of escapes); this scan does not loop over them.
    doc = '["' + "\\n" * 3_000_000 + '\\"' * 1_000_000 + '"' + ",[]" * 5_000 + "]"
    answer, spent = _cpu_seconds(json_nesting_exceeds, doc)
    assert answer is False
    assert spent < 10, spent


# ------------------------------------------------- property check vs a naive reference
def _naive_max_depth(text: str) -> int:
    """A per-character reference scanner for the same model: strings are double-quoted,
    a backslash escapes the next character, and an unterminated string runs to the end."""
    depth = best = 0
    in_string = False
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if in_string:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_string = False
        elif c == '"':
            in_string = True
        elif c in "[{":
            depth += 1
            best = max(best, depth)
        elif c in "]}":
            depth -= 1
        i += 1
    return best


def _object_depth(value) -> int:
    """Nesting depth of a parsed value, computed without recursion."""
    best = 0
    stack = [(value, 1)]
    while stack:
        item, d = stack.pop()
        if isinstance(item, dict):
            best = max(best, d)
            stack.extend((v, d + 1) for v in item.values())
        elif isinstance(item, list):
            best = max(best, d)
            stack.extend((v, d + 1) for v in item)
    return best


_ALPHABET = ['a', 'b', ' ', '"', "\\", "[", "]", "{", "}", "\n", "/", "é", "中",
             "\U0001f600", "\\\\", '\\"']


def _random_string(rnd: random.Random) -> str:
    return "".join(rnd.choice(_ALPHABET) for _ in range(rnd.randint(0, 6)))


def _random_value(rnd: random.Random, depth_left: int):
    roll = rnd.random()
    if depth_left <= 0 or roll < 0.25:
        return rnd.choice([0, -3, 1.5, True, False, None, _random_string(rnd)])
    if roll < 0.62:
        return [_random_value(rnd, depth_left - 1) for _ in range(rnd.randint(0, 3))]
    return {_random_string(rnd): _random_value(rnd, depth_left - 1)
            for _ in range(rnd.randint(0, 3))}


def test_the_scanner_agrees_with_a_naive_reference_on_random_documents():
    rnd = random.Random(648)
    checked = 0
    for _ in range(400):
        value = _random_value(rnd, rnd.randint(0, 9))
        text = json.dumps(value, ensure_ascii=rnd.random() < 0.5,
                          separators=rnd.choice([(", ", ": "), (",", ":")]))
        reference = _naive_max_depth(text)
        assert reference == _object_depth(value), "the reference itself is wrong"
        for limit in range(0, 11):
            expected = reference > limit
            assert json_nesting_exceeds(text, limit) is expected, (text, limit)
            assert json_nesting_exceeds(text.encode("utf-8"), limit) is expected, (text, limit)
            checked += 1
        # a prefix cut anywhere (inside a string, after a backslash, mid-token): the same model
        cut = text[: rnd.randrange(len(text) + 1)]
        for limit in (0, 1, 3):
            assert json_nesting_exceeds(cut, limit) is (_naive_max_depth(cut) > limit), (cut, limit)
        # and the limit is decided the same way by loads_bounded
        if reference <= 4:
            assert loads_bounded(text, max_nesting=4) == value
        else:
            with pytest.raises(JSONNestingError):
                loads_bounded(text, max_nesting=4)
    assert checked == 400 * 11


def test_random_texts_with_no_structure_at_all_never_raise():
    rnd = random.Random(6480)
    for _ in range(300):
        text = "".join(rnd.choice(_ALPHABET + ["1", ",", ":"]) for _ in range(rnd.randint(0, 40)))
        for limit in (0, 2):
            assert json_nesting_exceeds(text, limit) in (True, False)
            assert json_nesting_exceeds(text.encode("utf-8"), limit) in (True, False)
