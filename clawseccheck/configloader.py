"""Bounded, read-only OpenClaw JSON5 configuration loader.

Supports the JSON5 forms used by OpenClaw and resolves ``$include`` with the same
security boundaries documented by the host: bounded fragments, ten nested levels,
cycle detection, deep-merge ordering, and confinement to configured include roots.
Pure stdlib; never executes input or writes files.
"""
from __future__ import annotations

import ast
import io
import json
import os
from pathlib import Path

_MAX_INCLUDE_BYTES = 2_000_000
_MAX_INCLUDE_DEPTH = 10
_MAX_INCLUDE_PATH_CHARS = 4096
# Global fan-out budget: cycle detection only blocks a file re-including an ANCESTOR, so the
# same fragment re-read across sibling branches ({$include: ['./f','./f',...]}) could fan out
# to fanout**depth reads and hang the audit — a hostile-config DoS. Cap total fragment reads
# across the whole resolution (a real config includes only a handful of fragments). (C-135)
_MAX_INCLUDE_FRAGMENTS = 64
_NAN_MARKER = "__clawseccheck_json5_nan__"


class ConfigLoadError(ValueError):
    pass


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


def _read_fragment(path: Path, byte_limit: int) -> object:
    with path.open("rb") as fp:
        raw, truncated = _read_with_limit(fp, byte_limit)
    if truncated:
        raise ConfigLoadError(
            f"{path.name} exceeded the {byte_limit // 1_000_000}MB cap"
        )
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
        if resolved.is_dir() and resolved not in roots:
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


def load_openclaw_config(path: Path, *, root_byte_limit: int) -> dict:
    """Load and flatten one OpenClaw config without crossing its trust boundary."""
    config_dir = path.parent.resolve()
    try:
        resolved = path.resolve(strict=True)
    except (OSError, ValueError, RuntimeError) as exc:
        raise ConfigLoadError(f"could not resolve config path: {exc}") from exc
    if not _within_roots(resolved, (config_dir,)):
        raise ConfigLoadError("openclaw.json symlink escapes its config directory")
    parsed = _resolve(
        _read_fragment(resolved, root_byte_limit),
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
