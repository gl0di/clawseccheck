"""CLAWSECCHECK-B-986 P3: real positional argv parsing for one curl
invocation's own argument words, against clawseccheck/curlgrammar.py's role
table.

Takes a tuple of `shellwords.Word` -- the ARGUMENTS only (the caller has
already stripped the command name itself, and any `sudo`/wrapper prefix --
identifying "which shellwords.SimpleCommand IS the curl invocation" is the
caller's domain-specific job, not this module's) -- and returns one
`ArgToken` per parsed argument, each carrying its resolved role from the
closed set in curlgrammar.py (plus the two parser-level roles `UNKNOWN` and
`POSITIONAL_END` does not exist; a bare positional word's role is `DEST`,
same as `--url`'s value, since curl treats both identically as the request
URL).

Two curl-parser facts drive this (both verified directly against a real curl
8.5.0 -- see curlgrammar.py's module docstring):
  * No `--option=value` glued long-option syntax -- `_resolve_long` never
    splits on `=`; a long option's value, when it takes one, is always the
    NEXT whole shell word.
  * An unambiguous PREFIX of a long option name resolves to that option
    (`--noprox` -> `--noproxy`) -- exact match wins immediately over any
    prefix reasoning; two or more prefix candidates (or zero) is UNKNOWN.

Short options cluster (`-sSo FILE` == `-s -S -o FILE`) and the first
value-taking short option in a cluster consumes the REST of that same shell
word as its glued value (`-oFILE`, or clustered `-sSoFILE`) if any remains,
else the next whole word (standard getopt-style short-option parsing).

Fail-closed: any option not resolved by an EXACT or valid unique-PREFIX
match is `UNKNOWN` -- never silently treated as `SAFE`. A `UNKNOWN`/`HOP`/
`CONFIG` token anywhere is what makes skillast.py's B-415 exemption refuse
(see its own module for the policy; this module only parses).
"""
from __future__ import annotations

from dataclasses import dataclass

from . import curlgrammar as g
from . import shellwords


@dataclass(frozen=True)
class ArgToken:
    role: str  # a curlgrammar.ROLES member, or "UNKNOWN"
    long_name: "str | None"  # resolved option long name; None for DEST positionals/UNKNOWN
    flag_text: str  # literal flag spelling as written ("" for a bare positional)
    flag_start: int
    flag_end: int
    value_word: "shellwords.Word | None"  # populated when the value IS a whole word
    value_start: "int | None"  # absolute offsets of the value's text span
    value_end: "int | None"
    value_text: "str | None"


def _resolve_long(name_part: str) -> "str | None":
    """*name_part* is the text after a word's leading `--` (no `=` splitting
    -- see module docstring). Exact match wins immediately; otherwise an
    unambiguous prefix; otherwise UNKNOWN (None)."""
    full = "--" + name_part
    if full in g.OPTION_ARITY:
        return full
    candidates = [n for n in g.OPTION_ARITY if n.startswith(full)]
    if len(candidates) == 1:
        return candidates[0]
    return None


def _unknown_token(word: "shellwords.Word") -> ArgToken:
    return ArgToken("UNKNOWN", None, word.text, word.start, word.end, None, None, None, None)


def _positional_token(word: "shellwords.Word") -> ArgToken:
    return ArgToken(
        "DEST", None, "", word.start, word.start, word, word.start, word.end, word.text
    )


def _bool_token(long_name: str, word: "shellwords.Word") -> ArgToken:
    return ArgToken(
        g.OPTION_ROLE[long_name], long_name, word.text, word.start, word.end, None, None, None, None
    )


def parse_argv(argv: "tuple[shellwords.Word, ...]") -> "tuple[ArgToken, ...]":
    """*argv* is one curl invocation's own argument words (command name and
    any `sudo`/wrapper prefix already stripped by the caller). Returns one
    ArgToken per parsed argument -- a value-taking flag and its value
    together become exactly one ArgToken (the value's span is on that same
    token, not a separate one), except a short-option cluster's leading
    BOOLEAN flags each get their own token before the cluster's
    value-consuming flag's token."""
    tokens: list = []
    i = 0
    n = len(argv)
    end_of_options = False
    while i < n:
        w = argv[i]
        text = w.text
        if end_of_options:
            tokens.append(_positional_token(w))
            i += 1
            continue
        if text == "--":
            end_of_options = True
            i += 1
            continue
        if text.startswith("--") and len(text) > 2:
            name_part = text[2:]
            long_name = _resolve_long(name_part)
            if long_name is None:
                tokens.append(_unknown_token(w))
                i += 1
                continue
            if g.OPTION_ARITY[long_name] == "bool":
                tokens.append(_bool_token(long_name, w))
                i += 1
                continue
            if i + 1 < n:
                vw = argv[i + 1]
                tokens.append(
                    ArgToken(
                        g.OPTION_ROLE[long_name],
                        long_name,
                        text,
                        w.start,
                        w.end,
                        vw,
                        vw.start,
                        vw.end,
                        vw.text,
                    )
                )
                i += 2
            else:
                tokens.append(
                    ArgToken(
                        g.OPTION_ROLE[long_name], long_name, text, w.start, w.end, None, None, None, None
                    )
                )
                i += 1
            continue
        if text.startswith("-") and len(text) > 1:
            body = text[1:]
            j = 0
            consumed_next = False
            while j < len(body):
                ch = body[j]
                long_name = g.SHORT_TO_LONG.get(ch)
                flag_start = w.start + 1 + j
                if long_name is None:
                    tokens.append(
                        ArgToken(
                            "UNKNOWN",
                            None,
                            "-" + ch,
                            flag_start,
                            flag_start + 1,
                            None,
                            None,
                            None,
                            None,
                        )
                    )
                    j += 1
                    continue
                if g.OPTION_ARITY[long_name] == "bool":
                    tokens.append(
                        ArgToken(
                            g.OPTION_ROLE[long_name],
                            long_name,
                            "-" + ch,
                            flag_start,
                            flag_start + 1,
                            None,
                            None,
                            None,
                            None,
                        )
                    )
                    j += 1
                    continue
                # value-taking short option: rest of THIS word (if any) is
                # its glued value; else the next whole word.
                if j + 1 < len(body):
                    value_start = flag_start + 1
                    value_end = w.end
                    tokens.append(
                        ArgToken(
                            g.OPTION_ROLE[long_name],
                            long_name,
                            "-" + ch,
                            flag_start,
                            flag_start + 1,
                            None,
                            value_start,
                            value_end,
                            w.text[value_start - w.start : value_end - w.start],
                        )
                    )
                elif i + 1 < n:
                    vw = argv[i + 1]
                    tokens.append(
                        ArgToken(
                            g.OPTION_ROLE[long_name],
                            long_name,
                            "-" + ch,
                            flag_start,
                            flag_start + 1,
                            vw,
                            vw.start,
                            vw.end,
                            vw.text,
                        )
                    )
                    consumed_next = True
                else:
                    tokens.append(
                        ArgToken(
                            g.OPTION_ROLE[long_name],
                            long_name,
                            "-" + ch,
                            flag_start,
                            flag_start + 1,
                            None,
                            None,
                            None,
                            None,
                        )
                    )
                break  # a value-taking short option always ends its cluster
            i += 2 if consumed_next else 1
            continue
        tokens.append(_positional_token(w))
        i += 1
    return tuple(tokens)


def roles_present(tokens: "tuple[ArgToken, ...]") -> "frozenset[str]":
    return frozenset(t.role for t in tokens)


def tokens_with_role(tokens: "tuple[ArgToken, ...]", role: str) -> "tuple[ArgToken, ...]":
    return tuple(t for t in tokens if t.role == role)
