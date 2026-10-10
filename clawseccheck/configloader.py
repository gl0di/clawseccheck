"""Bounded, read-only OpenClaw JSON5 configuration loader.

Supports the JSON5 forms used by OpenClaw and resolves ``$include`` with the same
security boundaries documented by the host: bounded fragments, ten nested levels,
cycle detection, deep-merge ordering, and confinement to configured include roots.
Pure stdlib; never executes input or writes files.
"""
from __future__ import annotations

import ast
import hashlib
import io
import json
import os
import re
import secrets
from array import array
from itertools import accumulate
from pathlib import Path
from typing import NamedTuple
from . import pathprobe

_MAX_INCLUDE_BYTES = 2_000_000
_MAX_INCLUDE_DEPTH = 10
_MAX_INCLUDE_PATH_CHARS = 4096
# Global fan-out budget: cycle detection only blocks a file re-including an ANCESTOR, so the
# same fragment re-read across sibling branches ({$include: ['./f','./f',...]}) could fan out
# to fanout**depth reads and hang the audit - a hostile-config DoS. Cap total fragment reads
# across the whole resolution (a real config includes only a handful of fragments). (C-135)
_MAX_INCLUDE_FRAGMENTS = 64
_NAN_MARKER = "__clawseccheck_json5_nan__"


class ConfigLoadError(ValueError):
    pass


# --- bounded nesting (C-648) -------------------------------------------------------------
# How deep a JSON document may nest before this tool refuses to read it. The limit is OURS,
# not the interpreter's: `json.loads` gives up (RecursionError) at a depth that is a property
# of the interpreter and, on the newest, of the process, so a verdict that depended on
# whether the parser happened to give up differed from machine to machine. Measured
# 2026-10-05, `json.loads("[" * n + "]" * n)`: the deepest document that parses is 991 levels
# on CPython 3.9.25 (841 from inside a 150-frame call stack, 691 from 300 frames), 9,997 on
# 3.12.3, and on 3.14.4 it follows the STACK SIZE - 57,974 with the default 8 MB stack, more
# than 400,000 under `ulimit -s 65536` (a CI runner's larger stack). One figure, enforced
# before the parser sees the text, gives the same answer everywhere.
#
# 200 because nothing real is anywhere near it. Maximum nesting depth measured the same day,
# read-only, with a per-byte reference scanner: 20 across the 879 JSON/JSON5/JSONL files
# under ~/.openclaw (the deepest is a cached tool catalogue; plugin manifests are far
# shallower), 17 across the 930 *.json files of the installed OpenClaw package, and 10 across
# the 1,626 JSON-looking values in the SQLite state tables (config_machine_state.value_json
# is the deepest). 200 is ten times the deepest real document and far below what even
# Python 3.9 follows from deep inside a call stack.
#
# Where it applies: readers for which "too deep -> UNKNOWN" is an honest answer (the
# attestation file, the paired-device stores), through `loads_bounded`. It is deliberately
# NOT applied to `loads_json5` or to `vet_plugin`'s manifest: for untrusted third-party
# JSON a limit of our own would let a manifest padded past it hide what it declares, so
# that path keeps the interpreter's own recursion guard. The reader that does not need to
# reject is `loads_shallow` below (C-664): it returns the shallow part of any document and
# replaces what lies deeper with a marker, so padding hides nothing.
MAX_JSON_NESTING = 200


class JSONNestingError(ValueError):
    """A JSON text nests deeper than this tool is willing to read.

    A ``ValueError`` on purpose: every reader that already treats "not valid JSON" as
    "unparseable" (``except ValueError`` / ``except (OSError, ValueError)``) thereby treats
    "nested too deeply" the same way, which is the honest answer and the same one on every
    interpreter. The message names the limit, never the document.
    """


# One pass of C-level regex work instead of a Python loop per character (a 2 MB document
# costs tens of milliseconds, measured):
#   1. drop every backslash escape pair, so an escaped quote can neither open nor close a
#      string;
#   2. drop every string literal (valid JSON has a backslash only inside a string, so step 1
#      cannot touch anything else);
#   3. keep only the brackets, as +1 / -1 bytes, and take the maximum running sum.
# A string left open at the end of the text swallows the rest of it, which is where
# `json.loads` stops too, with its own ValueError.
_ESCAPE_STR = re.compile(r"\\.", re.S)
_ESCAPE_BYTES = re.compile(rb"\\.", re.S)
_STRING_STR = re.compile(r'"[^"]*"?')
_STRING_BYTES = re.compile(rb'"[^"]*"?')
_BRACKET_STEP = bytearray(256)
for _c in b"[{":
    _BRACKET_STEP[_c] = 1
for _c in b"]}":
    _BRACKET_STEP[_c] = 255  # -1 once read as a signed byte
_BRACKET_STEP = bytes(_BRACKET_STEP)
_NOT_A_BRACKET = bytes(c for c in range(256) if c not in b"[]{}")


def _depth_exceeds(text_bytes: bytes, limit: int) -> bool:
    """Whether the brackets of *text_bytes* (strings already removed) nest past *limit*."""
    steps = text_bytes.translate(_BRACKET_STEP, _NOT_A_BRACKET)
    return max(accumulate(array("b", steps)), default=0) > limit


def json_nesting_exceeds(data, limit: int = MAX_JSON_NESTING) -> bool:
    """True when the JSON text *data* opens more than *limit* nested arrays/objects at any point.

    Never recurses and never raises: it answers about the TEXT, before any parser sees it.
    Brackets inside string literals do not count, including after an escaped quote
    (``\\"``) and after an escaped backslash (``\\\\``). *data* is ``str`` or
    ``bytes``/``bytearray``; bytes are read the way ``json.loads`` reads them
    (``json.detect_encoding``: UTF-8, UTF-8 with BOM, UTF-16, UTF-32), and bytes that do not
    decode, or any other type, answer False so that ``json.loads`` raises its own error.

    The answer is exact for valid JSON, and for any text the stdlib parser would descend
    into: the parser follows only a strictly valid prefix, and in a valid prefix this scan
    sees exactly the structure the parser does. Past the first syntax error it is
    unspecified (the parser has already stopped there), so JSON5-only syntax (single-quoted
    strings, comments, which this scan does not understand) is outside this model;
    ``loads_json5`` does not call it.
    """
    if isinstance(data, str):
        if data.count("[") + data.count("{") <= limit:
            return False  # cannot be deeper than the number of openers - no scan needed
        stripped = _STRING_STR.sub("", _ESCAPE_STR.sub("", data))
        return _depth_exceeds(stripped.encode("ascii", "ignore"), limit)
    if isinstance(data, (bytes, bytearray)):
        if data.count(b"[") + data.count(b"{") <= limit:
            return False
        try:
            encoding = json.detect_encoding(data)
        except (TypeError, ValueError):
            return False
        if encoding in ("utf-8", "utf-8-sig"):
            # '[', '{', '"' and the backslash are ASCII, and no byte of a multi-byte UTF-8
            # sequence is, so UTF-8 can be scanned without decoding it.
            stripped = _STRING_BYTES.sub(b"", _ESCAPE_BYTES.sub(b"", bytes(data)))
            return _depth_exceeds(stripped, limit)
        try:
            text = bytes(data).decode(encoding, "surrogatepass")
        except (UnicodeDecodeError, LookupError):
            return False
        return json_nesting_exceeds(text, limit)
    return False


def loads_bounded(data, *, max_nesting: int = MAX_JSON_NESTING):
    """``json.loads`` for text that may be hostile: refuses nesting deeper than *max_nesting*.

    Raises :class:`JSONNestingError` (a ``ValueError``) for a document nested deeper than
    the limit, before the parser sees it, and otherwise returns exactly what ``json.loads``
    returns (including its own ``ValueError`` for bad JSON). The ``RecursionError`` net a
    caller already has stays as a second line of defence; it no longer decides the answer.
    """
    if json_nesting_exceeds(data, max_nesting):
        raise JSONNestingError(f"JSON is nested deeper than {max_nesting} levels")
    return json.loads(data)


def _json5_to_python_literal(text: str) -> str:
    """Translate OpenClaw's JSON5 syntax into a safe Python literal."""
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]

        if ch in ("'", '"'):
            quote = ch
            out.append(ch)
            i += 1
            while i < n:
                cur = text[i]
                if cur == "\\":
                    if i + 1 >= n:
                        out.append(cur)
                        i += 1
                        break
                    nxt = text[i + 1]
                    if nxt == "\n":
                        i += 2
                        continue
                    if nxt == "\r":
                        i += 2
                        if i < n and text[i] == "\n":
                            i += 1
                        continue
                    out.extend((cur, nxt))
                    i += 2
                    continue
                out.append(cur)
                i += 1
                if cur == quote:
                    break
            continue

        if ch == "/" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "/":
                i += 2
                while i < n and text[i] not in "\r\n":
                    i += 1
                continue
            if nxt == "*":
                end = text.find("*/", i + 2)
                if end < 0:
                    raise json.JSONDecodeError("unterminated block comment", text, i)
                # A comment is whitespace. Keep at least one separator so hostile input
                # such as ``1/*comment*/2`` cannot be silently reinterpreted as ``12``.
                out.append(" " + "\n" * text[i:end + 2].count("\n"))
                i = end + 2
                continue

        if ch.isalpha() or ch in "_$":
            start = i
            i += 1
            while i < n and (text[i].isalnum() or text[i] in "_$"):
                i += 1
            token = text[start:i]
            look = i
            while look < n and text[look].isspace():
                look += 1
            if look < n and text[look] == ":":
                out.append(json.dumps(token))
            else:
                out.append({
                    "true": "True",
                    "false": "False",
                    "null": "None",
                    "Infinity": "1e999",
                    # JSON5 supports NaN; a tuple is impossible in JSON5 input, so it is
                    # an unambiguous literal_eval-safe marker restored after parsing.
                    "NaN": repr((_NAN_MARKER,)),
                }.get(token, token))
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def _is_json_value(value: object) -> bool:
    if value is None or isinstance(value, (str, bool, int, float)):
        return True
    if isinstance(value, list):
        return all(_is_json_value(item) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and _is_json_value(item) for key, item in value.items())
    return False


def _restore_special_numbers(value: object) -> object:
    if value == (_NAN_MARKER,):
        return float("nan")
    if isinstance(value, list):
        return [_restore_special_numbers(item) for item in value]
    if isinstance(value, dict):
        return {key: _restore_special_numbers(item) for key, item in value.items()}
    return value


def _loads_json5_lenient(text: str, strict_error: "Exception | None" = None):
    """The JSON5 half of :func:`loads_json5`: *text* has already failed (or skipped) strict JSON."""
    try:
        parsed = ast.literal_eval(_json5_to_python_literal(text).strip())
    except (SyntaxError, ValueError, TypeError, MemoryError) as exc:
        pos = getattr(exc, "offset", None)
        raise json.JSONDecodeError(str(exc), text, max(0, int(pos or 1) - 1)) from strict_error
    parsed = _restore_special_numbers(parsed)
    if not _is_json_value(parsed):
        raise json.JSONDecodeError("value is not JSON-compatible", text, 0) from strict_error
    return parsed


def loads_json5(text: str):
    """Parse strict JSON first, then the bounded JSON5-compatible lexical form."""
    try:
        return json.loads(text)
    except json.JSONDecodeError as strict_error:
        return _loads_json5_lenient(text, strict_error)


# --- shallow reading of untrusted JSON (C-664) --------------------------------------------
# `json.loads` and `ast.literal_eval` recurse, so the depth they give up at is a property of
# the interpreter and the process (see MAX_JSON_NESTING above) and a hostile document can
# end a whole audit with a RecursionError. Rejecting a document that nests too deeply is an
# evasion when the document is a third party's: padding a manifest past the limit hides what
# it declares. `loads_shallow` reads it instead. It cuts the text into LAYERS of at most
# `max_depth` levels with a flat, stack-based scan (no recursion, so the answer does not
# depend on the interpreter, its recursion limit or the stack size), parses every layer with
# the ordinary parser, and keeps the top layer, in which each subtree that opens at
# `max_depth` + 1 is replaced by ELIDED. No value parser of our own: every byte of the text
# is read by `json.loads` (or by the JSON5 reader), so ValueError, duplicate keys, big
# numbers, NaN and lone surrogates behave as they do there.
SHALLOW_JSON_DEPTH = 64


class _Elided:
    """Type of :data:`ELIDED`: a singleton, deliberately not a ``str``, ``list`` or ``dict``."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "ELIDED"

    def __reduce__(self):
        return "ELIDED"  # copy / pickle give back the same object, so `is ELIDED` holds

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self


ELIDED = _Elided()


class ShallowJSON(NamedTuple):
    """What :func:`loads_shallow` returns: the value and how many ELIDED markers it holds."""

    value: object
    elided: int


# Same lexing as `_json5_to_python_literal` (strings with escapes, `//` and block comments;
# an unterminated string runs to the end of the text), reduced to what a nesting scan needs:
# the strings and comments to skip, and the brackets. A `/*` that never closes is an error
# there, so it is a token here. JSON5 mode has three more tokens: the JSON5 reader hands its
# output to `ast.literal_eval`, which reads `#` (a Python comment) and a tripled quote (a
# Python triple-quoted string) in ways this scan cannot follow, and either can hide or show
# brackets. Neither is JSON5, so seeing one makes the stage parse the text whole, as
# `loads_json5` does (`_Unlexable`).
_STRICT_TOKEN = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"?|[\[\]{}]', re.S)
_JSON5_TOKEN = re.compile(
    r"'''|\"\"\"|#"
    r'|"[^"\\]*(?:\\.[^"\\]*)*"?|\'[^\'\\]*(?:\\.[^\'\\]*)*\'?'
    r'|//[^\r\n]*|/\*.*?\*/|/\*|[\[\]{}]',
    re.S,
)
_BRACKET_PAIR = {"]": "[", "}": "{"}


class _Unlexable(Exception):
    """The text uses a Python-only spelling the layer scan cannot follow (JSON5 mode only)."""


def _split_layers(text: str, token_re: "re.Pattern", bound: int) -> list:
    """Cut *text* into layers: ``[start, end, child_spans]``, layer 0 being the whole text.

    An opener at depth ``d`` with ``(d - 1) % bound == 0`` (and ``d > 1``) starts a layer
    that ends at its matching closer; the span is recorded in the layer around it. Brackets
    that do not match raise ``JSONDecodeError``, as every parser would.
    """
    layers: list = [[0, len(text), []]]
    open_layers = [0]
    stack: list = []
    for m in token_re.finditer(text):
        tok = m.group()
        if tok == "[" or tok == "{":
            stack.append(tok)
            depth = len(stack)
            if depth > 1 and (depth - 1) % bound == 0:
                layers.append([m.start(), 0, []])
                open_layers.append(len(layers) - 1)
        elif tok == "]" or tok == "}":
            depth = len(stack)
            if not stack or stack.pop() != _BRACKET_PAIR[tok]:
                raise json.JSONDecodeError("mismatched brackets", text, m.start())
            if depth > 1 and (depth - 1) % bound == 0:
                index = open_layers.pop()
                layers[index][1] = m.end()
                layers[open_layers[-1]][2].append((layers[index][0], m.end()))
        elif tok == "/*":
            raise json.JSONDecodeError("unterminated block comment", text, m.start())
        elif tok == "#" or tok == "'''" or tok == '"""':
            raise _Unlexable
    if stack:
        raise json.JSONDecodeError("unclosed bracket", text, len(text))
    return layers


# A plain ValueError, not a JSONDecodeError: the JSON5 mode retries on a JSONDecodeError, and
# a forged marker is not "this text is not strict JSON".
_FORGED = "document contains the marker token"


def _new_nonce(text: str) -> str:
    """A fresh random token that does not occur in *text* (a marker cannot be forged)."""
    while True:
        nonce = secrets.token_hex(16)
        if nonce not in text:
            return nonce


def _parse_layer(parse, text: str):
    try:
        return parse(text)
    except RecursionError as exc:
        # A layer is at most `max_depth` + 1 levels, so this means the caller's own stack
        # (or an absurd `max_depth`) is spent: refuse like any unreadable document.
        raise JSONNestingError("JSON could not be parsed within the available stack") from exc


def _swap_markers(root, nonce: str) -> tuple:
    """Replace every ``[nonce]`` list in *root* by ELIDED, in place; return (root, count).

    Iterative. The nonce anywhere else (a key, or a string that only the escapes of the
    original can produce, since the text itself does not contain it) means the text forged
    a marker: ``ValueError``.
    """
    count = 0
    todo = [root]
    while todo:
        node = todo.pop()
        if isinstance(node, dict):
            for key in node:
                if nonce in key:
                    raise ValueError(_FORGED)
            slots = list(node.items())
        elif isinstance(node, list):
            slots = list(enumerate(node))
        else:
            continue
        for slot, item in slots:
            if isinstance(item, list):
                if len(item) == 1 and item[0] == nonce:
                    node[slot] = ELIDED
                    count += 1
                else:
                    todo.append(item)
            elif isinstance(item, dict):
                todo.append(item)
            elif isinstance(item, str) and nonce in item:
                raise ValueError(_FORGED)
    return root, count


def _read_layers(text: str, layers: list, nonce: str, parse) -> tuple:
    """Parse every layer with *parse*; return (top layer's value, markers left in it)."""
    marker = ' ["%s"] ' % nonce  # a list: unhashable, so never a key; the spaces are defensive
    top, elided = None, 0
    checked: set = set()  # short deeper layers already found valid (padding repeats them)
    for index, (start, end, kids) in enumerate(layers):
        pieces = []
        pos = start
        for kid_start, kid_end in kids:
            pieces.append(text[pos:kid_start])
            pieces.append(marker)
            pos = kid_end
        pieces.append(text[pos:end])
        chunk = "".join(pieces)
        if index and len(chunk) <= 1024:
            if chunk in checked:
                continue
            checked.add(chunk)
        value = _parse_layer(parse, chunk)
        if index == 0:
            top, elided = _swap_markers(value, nonce)
            if elided > len(kids):
                # More markers than were inserted (a duplicate key can only remove them).
                raise ValueError(_FORGED)
        # Deeper layers are read for validity only; their values are dropped here.
    return top, elided


def _shallow(text: str, bound: int, json5: bool) -> ShallowJSON:
    whole = loads_json5 if json5 else json.loads
    direct, refusal_is_final = None, True
    if text.count("[") + text.count("{") <= bound:
        direct = whole  # cannot nest past the bound, whatever the syntax
    elif not json_nesting_exceeds(text, bound):
        # The scan is exact for valid JSON and only for that: in JSON5 mode this is a first
        # try, and text that is not strict JSON goes to the layered read below.
        direct, refusal_is_final = json.loads, not json5
    if direct is not None:
        try:
            return ShallowJSON(_parse_layer(direct, text), 0)
        except JSONNestingError:
            pass  # not even this fits the stack we have: the layered read below decides
        except json.JSONDecodeError:
            if refusal_is_final:
                raise
    try:
        layers = _split_layers(text, _JSON5_TOKEN if json5 else _STRICT_TOKEN, bound)
    except _Unlexable:
        # Parsed whole, as `loads_json5` parses it: nothing is elided, and a text too deep
        # for the stack is JSONNestingError rather than RecursionError.
        return ShallowJSON(_parse_layer(whole, text), 0)
    nonce = _new_nonce(text)
    if not json5:
        return ShallowJSON(*_read_layers(text, layers, nonce, json.loads))
    # JSON5 mode reads as `loads_json5` does: strict JSON for the whole text if it is valid
    # JSON, else the JSON5 reader for the whole text. Valid JSON has no token the JSON5 scan
    # adds (no single quote, comment or `#` outside a string), so one scan serves both; if
    # any layer is not strict JSON the whole text is not, and every layer is read again.
    try:
        return ShallowJSON(*_read_layers(text, layers, nonce, json.loads))
    except json.JSONDecodeError as strict_error:
        return ShallowJSON(*_read_layers(
            text, layers, nonce,
            lambda chunk, cause=strict_error: _loads_json5_lenient(chunk, cause)))


def loads_shallow(text, *, json5: bool = False,
                  max_depth: int = SHALLOW_JSON_DEPTH) -> ShallowJSON:
    """Read untrusted JSON (``json5=True``: JSON5 as :func:`loads_json5` reads it) without
    recursing and without refusing it for being deep.

    Returns ``ShallowJSON(value, elided)``. Arrays and objects nested up to *max_depth*
    levels (the root is level 1) come back exactly as ``json.loads`` / ``loads_json5``
    return them; each array or object that opens at level *max_depth* + 1 is replaced by
    :data:`ELIDED`, and *elided* counts the markers that remain in the value. Nothing in
    the first *max_depth* levels depends on what lies deeper, so padding hides nothing.

    Raises ``ValueError`` where ``json.loads`` / ``loads_json5`` would for the same text if
    they had an unlimited stack (the whole text is parsed, layer by layer), never
    ``RecursionError``: a stack too small even for one layer is ``JSONNestingError``.
    *text* is ``str`` or ``bytes`` (decoded as ``json.loads`` decodes it).

    JSON5 caveats. (1) When the text has a ``#`` comment or a tripled quote outside a
    string (neither is JSON5; ``ast.literal_eval`` accepts both and the layer scan cannot
    follow them) the text is parsed whole, as ``loads_json5`` parses it: NOTHING is
    elided, however deep it is, and a document deeper than ``literal_eval`` follows is a
    ``ValueError``. For example ``'{"pad": ' + '[' * 100 + ']' * 100 + '} # c'`` comes back
    with all 101 levels and ``elided == 0``, and 300 levels followed by ``# x`` is a
    ``ValueError``. (2) A layer is *max_depth* + 1 levels and ``literal_eval`` accepts 200
    nested brackets and refuses 201, so keep *max_depth* at 199 or less in JSON5 mode.
    (3) Accepted differences, pinned by ``tests/test_c664_loads_shallow.py``: a Python-only
    literal (a set, a tuple) inside a too-deep subtree that a later duplicate key discards
    is rejected here, where ``loads_json5`` drops it with the key; and, because layers are
    parsed separately, ``"(" * 100 + "[" * 150 + "]" * 150 + ")" * 100`` is accepted here
    while ``loads_json5`` refuses it for the tokenizer's 200-nesting limit. The second
    difference only ever accepts; nothing ``loads_json5`` accepts is refused for it.
    """
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode(json.detect_encoding(text), "surrogatepass")
    elif not isinstance(text, str):
        raise TypeError(f"the JSON text must be str, bytes or bytearray, not {type(text).__name__}")
    if not isinstance(max_depth, int) or isinstance(max_depth, bool) or max_depth < 1:
        raise ValueError("max_depth must be a positive integer")
    return _shallow(text, max_depth, json5)


def _read_with_limit(file_obj: io.BufferedIOBase, byte_limit: int) -> tuple[bytes, bool]:
    out = bytearray()
    while True:
        chunk = file_obj.read(byte_limit + 1 - len(out))
        if not chunk:
            return bytes(out), False
        out.extend(chunk)
        if len(out) > byte_limit:
            return bytes(out[:byte_limit]), True


def _read_fragment(path: Path, byte_limit: int,
                   digest_out: "list | None" = None) -> object:
    with path.open("rb") as fp:
        raw, truncated = _read_with_limit(fp, byte_limit)
    if truncated:
        raise ConfigLoadError(
            f"{path.name} exceeded the {byte_limit // 1_000_000}MB cap"
        )
    # C-417: hand back a digest of the bytes THIS read saw, for a caller that needs to
    # record what it audited. Taken here rather than by a second read at the call site:
    # two reads are two different files whenever anything writes in between, and a
    # snapshot pairing one file's digest with another file's parsed values is a record
    # that cannot be true of any single moment.
    if digest_out is not None:
        digest_out.append(hashlib.sha256(raw).hexdigest())
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigLoadError(f"{path.name} is not valid UTF-8: {exc}") from exc
    try:
        return loads_json5(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ConfigLoadError(f"could not parse {path}: {exc}") from exc


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, value in override.items():
        if isinstance(result.get(key), dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _within_roots(path: Path, roots: tuple[Path, ...]) -> bool:
    return any(path == root or root in path.parents for root in roots)


def _allowed_roots(config_dir: Path) -> tuple[Path, ...]:
    roots = [config_dir.resolve()]
    for raw in os.environ.get("OPENCLAW_INCLUDE_ROOTS", "").split(os.pathsep):
        if not raw.strip():
            continue
        candidate = Path(raw).expanduser()
        if not candidate.is_absolute():
            continue
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, ValueError, RuntimeError):
            continue
        if pathprobe.is_dir(resolved) and resolved not in roots:
            roots.append(resolved)
    return tuple(roots)


def _resolve(
    value: object,
    *,
    current_file: Path,
    roots: tuple[Path, ...],
    stack: tuple[Path, ...],
    depth: int,
    budget: list[int],
) -> object:
    if isinstance(value, list):
        return [
            _resolve(item, current_file=current_file, roots=roots, stack=stack,
                     depth=depth, budget=budget)
            for item in value
        ]
    if not isinstance(value, dict):
        return value
    if "$include" not in value:
        return {
            key: _resolve(item, current_file=current_file, roots=roots, stack=stack,
                          depth=depth, budget=budget)
            for key, item in value.items()
        }

    spec = value.get("$include")
    if isinstance(spec, str):
        names = [spec]
    elif isinstance(spec, list) and spec and all(isinstance(item, str) for item in spec):
        names = list(spec)
    else:
        raise ConfigLoadError("$include must be a path string or a non-empty list of paths")
    if depth >= _MAX_INCLUDE_DEPTH:
        raise ConfigLoadError(f"nested $include exceeds {_MAX_INCLUDE_DEPTH} levels")

    merged: dict = {}
    for raw_name in names:
        if "\x00" in raw_name or not (0 < len(raw_name) < _MAX_INCLUDE_PATH_CHARS):
            raise ConfigLoadError("$include path has an invalid length or null byte")
        candidate = Path(raw_name).expanduser()
        if not candidate.is_absolute():
            candidate = current_file.parent / candidate
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, ValueError, RuntimeError) as exc:
            raise ConfigLoadError(f"could not resolve $include {raw_name!r}: {exc}") from exc
        if len(str(resolved)) >= _MAX_INCLUDE_PATH_CHARS:
            raise ConfigLoadError("resolved $include path is too long")
        if not _within_roots(resolved, roots):
            raise ConfigLoadError(f"$include escapes the allowed config roots: {raw_name!r}")
        if resolved in stack:
            raise ConfigLoadError(f"circular $include detected at {raw_name!r}")
        # C-135: bound total fragment reads so a sibling fan-out cannot expand exponentially
        # (cycle detection above only blocks ancestor re-includes, not sibling re-reads).
        budget[0] += 1
        if budget[0] > _MAX_INCLUDE_FRAGMENTS:
            raise ConfigLoadError(
                f"$include expands to more than {_MAX_INCLUDE_FRAGMENTS} fragments"
            )
        included = _resolve(
            _read_fragment(resolved, _MAX_INCLUDE_BYTES),
            current_file=resolved,
            roots=roots,
            stack=stack + (resolved,),
            depth=depth + 1,
            budget=budget,
        )
        if not isinstance(included, dict):
            raise ConfigLoadError(f"$include {raw_name!r} must contain an object")
        merged = _deep_merge(merged, included)

    siblings = {
        key: _resolve(item, current_file=current_file, roots=roots, stack=stack,
                      depth=depth, budget=budget)
        for key, item in value.items()
        if key != "$include"
    }
    return _deep_merge(merged, siblings)


def load_openclaw_config(path: Path, *, root_byte_limit: int,
                         root_digest: "list | None" = None) -> dict:
    """Load and flatten one OpenClaw config without crossing its trust boundary.

    *root_digest* - C-417: pass a **fresh** list to receive the sha256 hex of the ROOT
    file's bytes as this load read them. It is appended to, not assigned, so a list reused
    across two loads holds both digests and ``[0]`` is the older one; every caller here
    builds a new list per load. The list stays empty when the load raises.

    Root only: ``$include`` fragments are merged into the returned dict but are not covered
    by this digest, so an unchanged digest means "the root file is unchanged", never "the
    config is unchanged". The fragments are covered instead by monitor.py's
    ``_config_resolved_sha256``, which hashes the RESOLVED dict this load returns, so
    no second read of the fragments happens and no path of theirs is recorded.
    """
    config_dir = path.parent.resolve()
    try:
        resolved = path.resolve(strict=True)
    except (OSError, ValueError, RuntimeError) as exc:
        raise ConfigLoadError(f"could not resolve config path: {exc}") from exc
    if not _within_roots(resolved, (config_dir,)):
        raise ConfigLoadError("openclaw.json symlink escapes its config directory")
    parsed = _resolve(
        _read_fragment(resolved, root_byte_limit, digest_out=root_digest),
        current_file=resolved,
        roots=_allowed_roots(config_dir),
        stack=(resolved,),
        depth=0,
        budget=[0],
    )
    if not isinstance(parsed, dict):
        raise ConfigLoadError(
            f"malformed {path}: expected a JSON object, got {type(parsed).__name__}"
        )
    return parsed
