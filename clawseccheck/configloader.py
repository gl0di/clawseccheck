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
from array import array
from itertools import accumulate
from pathlib import Path
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
# that path keeps the interpreter's own recursion guard (a better design is tracked as
# C-664).
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


def loads_json5(text: str):
    """Parse strict JSON first, then the bounded JSON5-compatible lexical form."""
    try:
        return json.loads(text)
    except json.JSONDecodeError as strict_error:
        try:
            parsed = ast.literal_eval(_json5_to_python_literal(text).strip())
        except (SyntaxError, ValueError, TypeError, MemoryError) as exc:
            pos = getattr(exc, "offset", None)
            raise json.JSONDecodeError(str(exc), text, max(0, int(pos or 1) - 1)) from strict_error
        parsed = _restore_special_numbers(parsed)
        if not _is_json_value(parsed):
            raise json.JSONDecodeError("value is not JSON-compatible", text, 0) from strict_error
        return parsed


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
