"""C-728 -- the JSON5 reader reads strings and whitespace the way the platform does.

OpenClaw parses its config with the ``json5`` npm package (2.2.3, a declared dependency of
the ``openclaw`` package). ``loads_json5`` used to hand every string to Python with its escapes
untouched, so Python's escape rules applied, and it refused whitespace the platform accepts
(U+00A0, U+2028, U+2029, U+000B, U+3000, the rest of the Zs class), so the audit went blind
or read a different value on a config the platform runs.

Three layers, all driven by ONE generated corpus (``build_corpus``):

* **Offline** -- the platform's answers are pinned in ``tests/c728_json5_oracle.json`` and the
  reader (``feff_is_space=True``, how OpenClaw config files are read) is compared with them:
  every document the platform accepts must be accepted with an equal value, and the only
  documents we accept that the platform refuses are the pinned ``D`` list below.
  Controls prove the comparison can fail.
* **Live, local-only** -- the same corpus through the real package (one ``node`` process) must
  give the pinned answers back, and the reader must agree with it directly. Skipped when
  ``node`` or the package is missing.
* **Platform parity** -- ``openclaw config validate`` over five whitespace documents gives the
  same accept/refuse as the package, so the package is the parser the config path uses.

Regenerate the pin only on a machine with the matching OpenClaw installed::

    PYTHONPATH=tests:. python3 tests/test_c728_json5_parity.py --write

Source and data contain only ASCII; every other character is spelled as an escape.
"""
from __future__ import annotations

import json
import os
import shutil
import string
import subprocess
import sys
import time
import warnings
from array import array
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
PIN = TESTS / "c728_json5_oracle.json"

# --------------------------------------------------------------------------- the corpus
#: Shapes the reader ACCEPTS although the platform refuses them (C-728 item D). A config the
#: platform refuses is not in force, so over-acceptance is the harmless direction; it is a
#: recorded limit, not a defect. Pinned by name so a later change in either direction shows.
D_SHAPES = {
    "digit_separator": '{"a":1_000}',
    "octal_literal": '{"a":0o17}',
    "adjacent_strings": '{"a":"x" "y"}',
    "python_true": '{"a":True}',
    "raw_string_prefix": '{"a":r"x"}',
    "parenthesised_string": '{"a":("x")}',
}
# The same older difference for the other ordinary whitespace: a sign followed by a space, tab,
# line feed, form feed or carriage return is accepted here and refused by the platform.
for _name, _ws in (("space", " "), ("tab", "\t"), ("lf", "\n"), ("ff", "\f"), ("cr", "\r")):
    for _shape, _tmpl in (("minus_digit", '{"a":-%s1}'), ("plus_digit", '{"a":+%s1}'),
                          ("minus_infinity", '{"a":-%sInfinity}')):
        D_SHAPES[_name + "_after_" + _shape] = _tmpl % _ws
# Found by the structure corpus below: the same harmless direction, other Python spellings.
D_SHAPES.update({
    "double_zero": "00",
    "python_true_top_level": "True",
    "python_none_top_level": "None",
    "binary_literal": '{"a": 0b11}',
    "unicode_string_prefix": "{\"a\": u'x'}",
    "parenthesised_number_after_a_sign": '{"a": -(1)}',
    "triple_quoted_string": '{"a": ' + "'" * 3 + "x" + "'" * 3 + "}",
    "backslash_line_continuation": '{"a": ' + chr(92) + "\n 1}",
    # Found by differential fuzzing: Python reads "#" as a comment, and a number glued to
    # the word Infinity as one number.
    "python_hash_comment": "[]#x",
    "python_hash_comment_hides_the_rest": '{"a": 1 # , "b": 2\n}',
    "digits_glued_to_infinity": "9Infinity",
})
PINNED_OVER_ACCEPTANCE = frozenset(D_SHAPES)

#: Documents the platform ACCEPTS and this reader refuses: the costly direction (a config that
#: is in force would be reported as unparseable), so the list is pinned and must not grow.
#: Not seen in a real config: a ``\\uXXXX`` escape inside an UNQUOTED key. The reader's answer
#: for it is "could not be parsed", never a misread value.
KNOWN_REFUSALS = frozenset(json.dumps(d) for d in (
    "{" + chr(92) + "u0061: 1}", "{a" + chr(92) + "u0062: 1}",
))

#: Code points tried as whitespace at every token position. The platform accepts some of them
#: (the pinned answers say which); the rest (U+200B, U+0085, U+180E ...) it refuses, and so must we.
_WS_CANDIDATES = (
    [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680, 0x180E]
    + list(range(0x2000, 0x200C)) + [0x2028, 0x2029, 0x202F, 0x205F, 0x2060, 0x3000, 0xFEFF]
    + [0x00, 0x1C, 0x1D, 0x1E, 0x1F, 0x7F]
)
_WS_POSITIONS = (
    "{w}{{\"a\":1}}", "{{{w}\"a\":1}}", "{{\"a\"{w}:1}}", "{{\"a\":{w}1}}", "{{\"a\":1{w},\"b\":2}}",
    "{{\"a\":1,{w}\"b\":2}}", "{{\"a\":1{w}}}", "{{\"a\":1}}{w}", "{{\"a\":1{w}2}}",
    "{{\"a\":tr{w}ue}}", "{{\"a\":-{w}1}}", "{{\"a\":+{w}1}}", "{{\"a\":1e-{w}5}}",
    "{{\"a\":-{w}Infinity}}", "{{a{w}b:1}}", "{{a{w}:1}}", "{{true{w}:1}}", "[1{w},2]",
    "{{\"a\":{w}tru{w}e}}", "{{\"a\":1.{w}5}}",
)
_PUNCT = "/\\'\"`~!@#$%^&*()-_=+[]{};:,.<>? "
_LINE_ENDINGS = ("\n", "\r", "\r\n", "\u2028", "\u2029")


def _escape_docs():
    for quote in ("'", '"'):
        for ch in string.ascii_letters + string.digits + _PUNCT + "\u00a0\u2028\u0085\u180e":
            esc = "\\" + ch
            for body in (esc + "bc", "ab" + esc + "cd", "ab" + esc):
                yield "/*c*/{\"k\":" + quote + body + quote + "}"
        for kind in "xu":
            for k in range(0, 6):
                body = "ab\\" + kind + "aF09B"[:k] + "g"
                yield "/*c*/{\"k\":" + quote + body + quote + "}"
                yield "/*c*/{\"k\":" + quote + "\\" + kind + "aF09B"[:k] + quote + "}"
        for body in (
            "\\ud83d\\ude00", "\\uD83D\\uDE00", "\\ud83d\\uDE00", "\\ude00\\ud83d", "\\ud83d",
            "\\ude00", "\\ud83d\\ud83d", "\\ud83d\\u0041", "\\ud83dx", "\\ud83d\\ude00\\ud83d\\ude00",
            "\\ud83d\\ud83d\\ude00", "\\ud83d\\ude00\\ude00", "\\ud800\\udc00", "\\udbff\\udfff",
            "\\udbff\\ue000", "\\ud7ff\\udc00", "a\\ud83d\\ude00b", "\\ud83d\\\\ude00",
            "\\ud83d\\", "\U0001f600", "\\ud83d" + "\U0001f600",
            "a\\0b", "\\0", "\\00", "\\01", "\\08", "x\\0y", "\\0\\0", "\\10", "\\101", "\\400",
            "\\x41\\x42", "\\x4", "\\x", "\\u", "\\u00", "\\u004", "\\u0041",
            "a\tb", "a\u2028b", "a\u2029b", "a\x7fb", "a\ufeffb", "a\u00a0b",
        ):
            yield "/*c*/{\"k\":" + quote + body + quote + "}"
        for end in _LINE_ENDINGS:
            for body in ("a\\" + end + "b", "\\" + end + "ab", "ab\\" + end, "a\\" + end + end + "b"):
                yield "/*c*/{\"k\":" + quote + body + quote + "}"
            for body in ("a" + end + "b",):  # a raw line terminator inside a string
                yield "/*c*/{\"k\":" + quote + body + quote + "}"
    # a bare backslash at the end of the text, unterminated strings
    yield "/*c*/{\"k\":'abc\\"
    yield "/*c*/{\"k\":'abc"
    yield "/*c*/{\"k\":\"https:\\/\\/x\\/y\"}"


def _whitespace_docs():
    for cp in _WS_CANDIDATES:
        w = chr(cp)
        for pos in _WS_POSITIONS:
            yield pos.format(w=w)
        yield "{\"a\":1," + w + "}"                      # trailing comma then mark
        yield "/*c*/" + w + "{\"a\":'x" + w + "y'}"     # inside a string it stays data
        yield "{\"a\":1}" + w + "// c"
        yield "// c" + w + "\n{\"a\":1}"                # inside a comment it is just text
        yield "/* c" + w + " */{\"a\":1}"


def _comment_docs():
    for end in _LINE_ENDINGS + ("\x0b", "\x0c", "\x85", "\u180e", ""):
        yield "{ // n" + end + " \"a\": 1 }"
        yield "{ // n" + end + "\"a\": 1, \"b\": 2 }"
        yield "// n" + end + "{\"a\": 1}"
        yield "{\"a\": 1} // n" + end
        yield "{\"a\": 1, // 'x" + end + " \"b\": 2}"
        yield "{\"a\": 1 /* n" + end + " */, \"b\": 2}"
    yield "{ // n\u2028 \"a\": {\"b\": 1}}"
    yield "{\"a\": 1} // n\u2028 {\"hidden\": true}"
    yield "{\"a\":1}\u2028// c"
    yield "{\"a\":1}//"


def _structure_docs():
    """Shapes around the escape and whitespace rules: comments next to keys and signs,
    numbers, keys, commas. Nothing here is special-cased by the reader; the oracle decides."""
    for end in _LINE_ENDINGS:
        for sign in "+-":
            yield "{ // a" + sign + end + " \"a\": 1 }"          # the comment ends in a sign
            yield "{\"a\": 1, // x " + sign + end + "\"b\": 2}"
    for w in ("\u00a0", "\u2028", "\u3000", "\ufeff", "\x0b"):
        yield "{\"a\": \"x-\"" + w + "}"                        # a string ending in a sign
        yield "{\"a\": 1 /* - */" + w + ", \"b\": 2}"
        yield "{a" + w + "/*c*/" + w + ": 1}"
        yield "[-1" + w + ", +1" + w + "]"
    yield from _STRUCTURE


_Q3 = "'" * 3
_STRUCTURE = (
    "{a /*c*/: 1}", "{a/*c*/:1}", "{a // c\n : 1}", "{a // c\r\n: 1}", "{a // c\u2028: 1}",
    "{true /*c*/ : 1}", "{null/**/:1, Infinity /* x */ : 2}", "{a /* : */ : 1}",
    "{a /*c*/ b: 1}", "{\"a\": tru/**/e}", "{\"a\": true /* : */ }", "{\"a\": true // :\n}",
    "{\"a\": null /* : */, \"b\": 1}", "{a /*c", "{a /*c*/}", "{a /*c*/, }",
    "{a /**/ /**/ // x\n /**/ : 1}",
    "{$a: 1, _b: 2, a1: 3, \u00e9: 4}", "{a-b: 1}", "{1: 2}", "{a.b: 1}", "{'a': 1, \"b\": 2,}",
    "[1, 2, ]", "[,]", "[1,,2]", "{,}", "{\"a\": 1,,}", "", " ", "// only\n", "/* only */",
    "1", "-1", "+1", ".5", "5.", "-.5", "+5.", "1e5", "1E+5", "1e-5", "1.5e3", "0x1F", "0X1f",
    "-0x10", "+0x10", "0x", "0x1G", "012", "00", "0", "-0", "+0", "1.", ".", "-", "+", "1e",
    "1e+", "--1", "++1", "+-1", "Infinity", "-Infinity", "+Infinity", "NaN", "-NaN", "+NaN",
    "infinity", "nan", "INFINITY", "true", "false", "null", "True", "None", "undefined", "tru",
    "nul", "truee", "'a'", "\"a\"", "'a\"b'", "\"a'b\"", "'a\\'b'", "\"a\\\"b\"", "''", "\"\"",
    "[1 2]", "{\"a\" 1}", "{\"a\": 1 \"b\": 2}", "[1] [2]", "{} {}", "[1]]", "{\"a\": [}",
    "[\"a\": 1]", "{\"a\": 1, \"a\": 2}", "{\"a\": {\"a\": {\"a\": [[[1, {\"b\": null}]]]}}}",
    "{\"__proto__\": 1}", "{\"a\": 12345678901234567890}", "{\"a\": 1e400}", "{\"a\": -1e400}",
    "{\"a\": 0.1e-400}", "{\"a\": 9007199254740993}", "{\"a\": 0xFFFFFFFFFFFFFFFFFF}",
    "[1.0, 1.50, 1e0, 0.0, -0.0, 0e0]", "{\"a\": 1j}", "{\"a\": 1if}", "[1or 2]",
    "{\"a\": 0b11}", "{\"a\": 1L}", "{\"a\": 0x1p3}", "{\"a\": b'x'}", "{\"a\": f'x'}",
    "{\"a\": u'x'}", "{\"a\": [1, 2}", "{\"a\": (1, 2)}", "{\"a\": {1, 2}}", "{\"a\": ...}",
    "{\"a\": 1;}", "{\"a\": 1}\n{\"b\": 2}", "{\"a\": `x`}", "{\"a\": 'x' + 'y'}",
    "{\"a\": 1 + 1}", "{\"a\": -(1)}", "{\"a\": [1][0]}", "{\"a\": not 1}",
    "{\"a\": 1 if 1 else 2}", "{\"a\": lambda: 1}", "{\"a\": " + _Q3 + "x" + _Q3 + "}",
    "{\"a\": \\\n 1}", "{\\u0061: 1}", "{a\\u0062: 1}",
)


def build_corpus() -> dict:
    """Return ``{key: doc}`` -- the key is ``json.dumps(doc)`` (ASCII, stable, lone-surrogate safe)."""
    docs = dict.fromkeys(list(_escape_docs()) + list(_whitespace_docs()) + list(_comment_docs())
                         + list(_structure_docs()) + list(D_SHAPES.values()))
    return {json.dumps(d): d for d in docs}


def _units(doc: str) -> list:
    return list(array("H", doc.encode("utf-16-le", "surrogatepass")))


def _text(units) -> str:
    return array("H", units).tobytes().decode("utf-16-le", "surrogatepass")


def canon_platform(node):
    """The oracle's tagged value as a comparable Python structure."""
    t = node["t"]
    if t == "z":
        return ("z",)
    if t == "b":
        return ("b", node["v"])
    if t == "n":
        return ("n", repr(float(node["s"]) + 0.0))    # -0.0 + 0.0 == 0.0: compared as 0
    if t == "s":
        return ("s", _text(node["u"]))
    if t == "a":
        return ("a", tuple(canon_platform(x) for x in node["v"]))
    # Sorted: a JavaScript object lists integer-like keys first, a dict keeps source order.
    return ("o", tuple(sorted((_text(k["u"]), canon_platform(v)) for k, v in node["v"])))


def canon_ours(value):
    if value is None:
        return ("z",)
    if isinstance(value, bool):
        return ("b", value)
    if isinstance(value, (int, float)):
        return ("n", repr(float(value) + 0.0))
    if isinstance(value, str):
        return ("s", value)
    if isinstance(value, list):
        return ("a", tuple(canon_ours(x) for x in value))
    return ("o", tuple(sorted((k, canon_ours(v)) for k, v in value.items())))


def read(doc: str):
    """The reader under test: how an OpenClaw config file is read. ``None`` means refused."""
    from clawseccheck.configloader import loads_json5

    try:
        return ("ok", canon_ours(loads_json5(doc, feff_is_space=True)))
    except ValueError:
        return None


def compare(answers: dict, corpus: dict, reader=read) -> dict:
    """Bucket every corpus document by how *reader* and the pinned platform answer differ."""
    out = {"refused": [], "value": [], "over": []}
    for key, doc in corpus.items():
        ans = answers[key]
        got = reader(doc)
        if ans is None:
            if got is not None:
                out["over"].append(key)
        elif got is None:
            out["refused"].append(key)
        elif got != ("ok", canon_platform(ans)):
            out["value"].append(key)
    return out


# ----------------------------------------------------------------------------- the oracle
_NODE_SCRIPT = r"""
const J = require(process.env.C728_JSON5);
const enc = (v) => {
  if (v === null) return {t: 'z'};
  if (typeof v === 'boolean') return {t: 'b', v: v};
  if (typeof v === 'number') return {t: 'n', s: String(v), z: Object.is(v, -0)};
  if (typeof v === 'string') return {t: 's', u: Array.from({length: v.length}, (_, i) => v.charCodeAt(i))};
  if (Array.isArray(v)) return {t: 'a', v: v.map(enc)};
  return {t: 'o', v: Object.keys(v).map((k) => [enc(k), enc(v[k])])};
};
let buf = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (d) => { buf += d; });
process.stdin.on('end', () => {
  const out = JSON.parse(buf).map((units) => {
    const s = units.map((u) => String.fromCharCode(u)).join('');
    try { return {ok: 1, v: enc(J.parse(s))}; } catch (e) { return {ok: 0}; }
  });
  process.stdout.write(JSON.stringify(out));
});
"""


def find_json5():
    """``openclaw`` on the PATH -> real path -> the directory with its package.json -> json5."""
    exe = shutil.which("openclaw")
    if exe is None or shutil.which("node") is None:
        return None
    here = Path(os.path.realpath(exe)).parent
    for cand in (here, *here.parents):
        if (cand / "package.json").is_file():
            pkg = cand / "node_modules" / "json5"
            return pkg if (pkg / "package.json").is_file() else None
    return None


def ask_platform(json5_dir: Path, docs: list) -> list:
    """One ``node`` process; ``None`` where the package refuses, else the tagged value."""
    env = dict(os.environ, C728_JSON5=str(json5_dir))
    proc = subprocess.run(["node", "-e", _NODE_SCRIPT], input=json.dumps([_units(d) for d in docs]),
                          capture_output=True, text=True, timeout=300, env=env)
    assert proc.returncode == 0, proc.stderr[-1500:]
    return [r["v"] if r["ok"] else None for r in json.loads(proc.stdout)]


def space_scan(json5_dir: Path) -> list:
    """Every BMP code point (not a surrogate) the package accepts as whitespace before a key."""
    cps = [c for c in range(0x10000) if not 0xD800 <= c <= 0xDFFF]
    answers = ask_platform(json5_dir, ["{" + chr(c) + "\"a\":1}" for c in cps])
    return [c for c, a in zip(cps, answers) if a is not None]


def write_pin() -> None:
    json5_dir = find_json5()
    if json5_dir is None:
        raise SystemExit("openclaw (and its json5 package) or node is not available")
    corpus = build_corpus()
    keys = list(corpus)
    answers = ask_platform(json5_dir, [corpus[k] for k in keys])
    version = json.loads((json5_dir / "package.json").read_text())["version"]
    data = {"json5": version, "answers": dict(zip(keys, answers)), "space_scan": space_scan(json5_dir)}
    PIN.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n")
    print(f"wrote {PIN} ({len(keys)} documents, json5 {version})")


def _pin() -> dict:
    return json.loads(PIN.read_text())


# ------------------------------------------------------------------------ offline: the pin
def test_the_pin_covers_exactly_the_corpus():
    """A corpus edit without ``--write`` would leave documents unchecked (or stale answers)."""
    assert set(_pin()["answers"]) == set(build_corpus())


def test_the_reader_matches_the_pinned_platform_answers():
    pin, corpus = _pin(), build_corpus()
    got = compare(pin["answers"], corpus)
    refused = [k for k in got["refused"] if k not in KNOWN_REFUSALS]
    assert refused == [], f"platform accepts, we refuse: {refused[:5]}"
    assert set(got["refused"]) == set(KNOWN_REFUSALS)
    assert got["value"] == [], f"value differs from the platform: {got['value'][:5]}"
    by_doc = {json.dumps(d): n for n, d in D_SHAPES.items()}
    unexplained = [k for k in got["over"] if k not in by_doc]
    assert unexplained == [], f"accepted here, refused by the platform: {unexplained[:5]}"
    assert {by_doc[k] for k in got["over"]} == set(PINNED_OVER_ACCEPTANCE)


def test_the_comparison_can_fail_on_a_reader_without_the_whitespace_rule():
    """Control: the flag-off reader refuses the whitespace the platform accepts."""
    from clawseccheck.configloader import loads_json5

    def flag_off(doc):
        try:
            return ("ok", canon_ours(loads_json5(doc)))
        except ValueError:
            return None

    got = compare(_pin()["answers"], build_corpus(), flag_off)
    assert len(got["refused"]) > 50


def test_the_comparison_can_fail_on_a_reader_that_misreads_a_value():
    """Control: a reader that corrupts every string value is caught as a value difference."""
    def tampered(doc):
        got = read(doc)
        if got is None:
            return None
        return ("ok", _bang(got[1]))

    got = compare(_pin()["answers"], build_corpus(), tampered)
    assert len(got["value"]) > 100


def _bang(node):
    if node[0] == "s":
        return ("s", node[1] + "!")
    if node[0] == "a":
        return ("a", tuple(_bang(x) for x in node[1]))
    if node[0] == "o":
        return ("o", tuple((k, _bang(v)) for k, v in node[1]))
    return node


def test_the_whitespace_set_is_exactly_the_platforms():
    """Every BMP code point as the separator before a key: whatever the platform accepts we do."""
    expected = set(_pin()["space_scan"])
    ours = {c for c in range(0x10000) if not 0xD800 <= c <= 0xDFFF
            and read("{" + chr(c) + "\"a\":1}") is not None}
    # The only extras are the Python string prefixes r R u U ("raw_string_prefix" above).
    assert ours - expected == {ord(c) for c in "rRuU"}
    assert expected <= ours
    assert {0xA0, 0x2028, 0x2029, 0x0B, 0x3000, 0xFEFF} <= ours
    assert not {0x200B, 0x85, 0x180E} & ours


def test_the_headline_cases_read_as_the_platform_reads_them():
    """Readable anchors for the headline cases (the corpus covers the rest)."""
    from clawseccheck.configloader import loads_json5

    def cfg(text):
        return loads_json5("/*c*/" + text, feff_is_space=True)

    assert cfg('{"u":"https:\\/\\/x"}') == {"u": "https://x"}
    assert cfg('{"u":"\\a\\e C:\\q"}') == {"u": "ae C:q"}
    assert cfg('{"u":"\\ud83d\\ude00"}') == {"u": "\U0001f600"}
    assert cfg('{"u":"\\ud83d"}') == {"u": "\ud83d"}
    assert cfg('{"u":"\\U\\N"}') == {"u": "UN"}
    assert cfg('{"u":"x\\0y"}') == {"u": "x\x00y"}
    assert cfg('{"u":"a\\\r\nb"}') == {"u": "ab"}
    assert cfg('{"u":"a\\\u2028b"}') == {"u": "ab"}
    assert cfg('{\u00a0"a"\u3000:\u000b1}') == {"a": 1}
    assert cfg('{ // n\u2028 "a": 1 }') == {"a": 1}
    for refused in ('{"u":"\\101"}', '{"u":"\\01"}', '{"u":"\\1"}', '{"u":"\\x4"}',
                    '{"u":"\\u004"}', '{"a":-\u00a01}', '{"a":1\u200b}'):
        with pytest.raises(ValueError):
            cfg(refused)


def test_the_escape_rules_do_not_change_the_flag_off_reader_on_valid_json5_values():
    """The string rule is the platform's whichever way the reader is called."""
    from clawseccheck.configloader import loads_json5

    assert loads_json5("/*c*/{'u':'\\/\\a'}") == {"u": "/a"}
    with pytest.raises(ValueError):
        loads_json5("/*c*/{'u':'\\101'}")


# ----------------------------------------------------------------------- no warning leaks
def test_no_document_in_the_corpus_emits_a_warning():
    from clawseccheck.configloader import loads_json5

    with warnings.catch_warnings(record=True) as seen:
        warnings.simplefilter("always")
        for doc in build_corpus().values():
            for flag in (True, False):
                try:
                    loads_json5(doc, feff_is_space=flag)
                except ValueError:
                    pass
    assert [str(w.message) for w in seen] == []


def test_a_compiler_warning_is_a_refusal_and_never_reaches_the_user(monkeypatch):
    """The guard: should any spelling make the compiler warn, the document is refused (not read
    as if the warning were absent) and nothing is emitted."""
    from clawseccheck import configloader

    def warns(_source):
        warnings.warn("invalid escape sequence", SyntaxWarning, stacklevel=1)
        return {}

    monkeypatch.setattr(configloader.ast, "literal_eval", warns)
    with warnings.catch_warnings(record=True) as seen:
        warnings.simplefilter("always")
        with pytest.raises(ValueError):
            configloader.loads_json5("// c\n{}")
    assert seen == []


def test_a_long_escape_run_is_read_in_linear_time():
    from clawseccheck.configloader import loads_json5

    def timed(n):
        text = "/*c*/{'k':'" + "\\a" * n + "'}"
        start = time.perf_counter()
        assert loads_json5(text, feff_is_space=True) == {"k": "a" * n}
        return time.perf_counter() - start

    timed(1000)
    small, large = timed(20_000), timed(200_000)
    assert large < max(small * 40, 1.0)


# ------------------------------------------------------------- live: the package, the CLI
JSON5_DIR = find_json5()
needs_package = pytest.mark.skipif(JSON5_DIR is None, reason="node or the openclaw json5 package is missing")


@needs_package
def test_live_the_package_still_gives_the_pinned_answers():
    corpus = build_corpus()
    keys = list(corpus)
    live = dict(zip(keys, ask_platform(JSON5_DIR, [corpus[k] for k in keys])))
    pin = _pin()
    assert [k for k in keys if live[k] != pin["answers"][k]][:5] == []
    assert space_scan(JSON5_DIR) == pin["space_scan"]


@needs_package
def test_live_the_reader_agrees_with_the_package():
    corpus = build_corpus()
    keys = list(corpus)
    live = dict(zip(keys, ask_platform(JSON5_DIR, [corpus[k] for k in keys])))
    got = compare(live, corpus)
    assert set(got["refused"]) == set(KNOWN_REFUSALS)
    assert got["value"] == []
    assert {k for k in got["over"]} == {json.dumps(D_SHAPES[n]) for n in PINNED_OVER_ACCEPTANCE}


_VALIDATE_SHAPES = [
    ("nbsp_between_tokens", "{\u00a0\"gateway\":\u00a0{\"port\":18789}}", 0),
    ("ideographic_space_and_vt", "{\u3000\"gateway\":\u000b{\"port\":18789}}", 0),
    ("line_separator_ends_a_comment", "{ // n\u2028 \"gateway\": {\"port\":18789}}", 0),
    ("zero_width_space_between_tokens", "{\u200b\"gateway\":{\"port\":18789}}", 1),
    ("nel_between_tokens", "{\u0085\"gateway\":{\"port\":18789}}", 1),
]


@needs_package
@pytest.mark.skipif(shutil.which("openclaw") is None, reason="the openclaw CLI is not on the PATH")
@pytest.mark.parametrize("shape,text,rc", _VALIDATE_SHAPES, ids=[s[0] for s in _VALIDATE_SHAPES])
def test_live_config_validate_gives_the_packages_verdict(tmp_path, shape, text, rc):
    """``openclaw config validate`` accepts/refuses exactly what the package does, and so does
    the reader: the package is the parser the config path uses."""
    path = tmp_path / "openclaw.json"
    path.write_bytes(text.encode("utf-8"))
    path.chmod(0o600)
    env = dict(os.environ)
    env.update(HOME=str(tmp_path), OPENCLAW_HOME=str(tmp_path), OPENCLAW_STATE_DIR=str(tmp_path),
               OPENCLAW_CONFIG_PATH=str(path))
    got = subprocess.run(["openclaw", "config", "validate"], env=env, capture_output=True,
                         text=True, timeout=120).returncode
    assert got == rc
    assert (ask_platform(JSON5_DIR, [text])[0] is not None) is (rc == 0)
    assert (read(text) is not None) is (rc == 0)


if __name__ == "__main__":
    if sys.argv[1:] == ["--write"]:
        write_pin()
    else:
        raise SystemExit("usage: PYTHONPATH=tests:. python3 tests/test_c728_json5_parity.py --write")
