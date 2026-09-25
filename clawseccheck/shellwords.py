"""CLAWSECCHECK-B-986 P2: a real (non-`shlex`) shell word/command splitter.

Splits ONE shell logical line into simple commands (top-level `;`/`&&`/`||`/
`|`/`&`-separated), each a sequence of `Word`s that keep their own source
position, further broken into typed `Part`s (literal/variable/
command-substitution/glob/brace), each tagged with whether it sits inside an
active quote.

Deliberately NOT `shlex`: `shlex` has no word positions, mis-splits
`$(...)`/`${...}` (it has no concept of nested shell constructs at all), and
was already tried and retracted in this codebase once before for a 13.5x
cost blowup on adversarial input (B-534) -- stdlib `shlex` is a POSIX-ish
tokenizer for a DIFFERENT, simpler grammar than a real shell's, not a
shortcut around writing this.

Fail-closed contract: `scan_line` returns None -- never a best-effort partial
result -- for any of:
  * an unbalanced quote, `$(...)`, `` `...` ``, or `${...}` left open at the
    end of the line;
  * a bare (unquoted, not `$`-prefixed) `(` or a stray `)` encountered
    outside any of the above -- a subshell/compound-command opener or a
    syntax error, neither of which this module tries to model.
Every caller MUST treat None as "no exemption" -- see B-986's callers in
skillast.py.

Quote semantics mirrored here (confirmed against real bash, not assumed):
double quotes suppress BOTH shell glob expansion (`"*.txt"` stays literal)
AND shell brace expansion (`"{a,b}"` stays literal) -- `Part.quoted` reflects
this, and a `glob`/`brace` Part is only ever emitted for UNQUOTED shell
metacharacters. curl has its OWN, separate `{...}`/`[...]` URL-globbing
feature that operates on the literal argument text regardless of shell
quoting (a shell-quoted `"https://{a,b}/x"` still reaches curl as one
argument, which curl itself then glob-expands into two requests unless
`-g`/`--globoff` is given) -- a consumer caring about THAT needs to inspect
`Word.text` directly, not `Part.kind == "glob"/"brace"` here (see
skillast.py's B-415 in-cluster destination check, which does exactly that).
"""
from __future__ import annotations

from dataclasses import dataclass

_QUOTE_CLOSE = {"'": "'", "`": "`", "{": "}"}
_SEPARATOR_CHARS = " \t;&|<>"
_VAR_IDENT_RE_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"
)
_VAR_SPECIAL_CHARS = frozenset("@*#?-$!0123456789")


@dataclass(frozen=True)
class Part:
    """One typed slice of a Word's source text. `start`/`end` are absolute
    offsets into the original line text passed to `scan_line` (not relative
    to the word)."""

    kind: str  # "literal" | "variable" | "cmdsub" | "glob" | "brace"
    text: str
    start: int
    end: int
    quoted: bool  # inside an active '...' or "..." at this point


@dataclass(frozen=True)
class Word:
    text: str  # raw source text, quotes/substitutions intact
    start: int
    end: int
    parts: "tuple[Part, ...]"

    @property
    def has_variable(self) -> bool:
        return any(p.kind == "variable" for p in self.parts)

    @property
    def has_cmdsub(self) -> bool:
        return any(p.kind == "cmdsub" for p in self.parts)

    @property
    def has_glob(self) -> bool:
        return any(p.kind == "glob" for p in self.parts)

    @property
    def has_brace(self) -> bool:
        return any(p.kind == "brace" for p in self.parts)

    @property
    def variable_count(self) -> int:
        return sum(1 for p in self.parts if p.kind == "variable")

    @property
    def is_fully_literal(self) -> bool:
        return all(p.kind == "literal" for p in self.parts)


@dataclass(frozen=True)
class SimpleCommand:
    words: "tuple[Word, ...]"


# --------------------------------------------------------------------------
# Word-boundary scanning -- the primitive B-894 already built and reviewed
# for finding an assignment's own value-word end. Factored here into
# `_word_scan_state`, which additionally reports the two fail-closed signals
# `scan_line` needs (an unbalanced quote/substitution left open, and a bare
# top-level '('/stray ')'); `_sh_loop_word_end` is now a thin wrapper
# preserving its EXACT prior return value for its one remaining caller in
# skillast.py (`_sh_loop_bound_names`'s region) and anything importing it by
# name for tests -- see tests/test_shellwords.py's parity tests.
# --------------------------------------------------------------------------
def _word_scan_state(text: str, start: int):
    """Returns `(end, unbalanced, paren_anomaly)`:
      * `end` -- same value `_sh_loop_word_end` has always returned: the
        offset where the word starting at `start` ends (quotes/`$(...)`/
        `${...}`/backticks nest; unquoted whitespace or a separator ends it;
        never crosses a newline).
      * `unbalanced` -- True when a quote/substitution/`${...}` was still
        open at end-of-line (or end-of-text).
      * `paren_anomaly` -- True when a bare `(` was opened while nothing was
        already open (not immediately after `$`, not itself nested inside
        an existing quote/substitution), or a stray `)` was hit with nothing
        open to close -- either way, a shape this scanner does not model.
    """
    stop = text.find("\n", start)
    stop = len(text) if stop == -1 else stop
    stack: list = []
    paren_anomaly = False
    i = start
    while i < stop:
        c = text[i]
        top = stack[-1] if stack else ""
        if c == "\\" and top != "'":
            i += 2
            continue
        if top in ("'", "`", "{"):
            if c == _QUOTE_CLOSE[top]:
                stack.pop()
        elif top == '"':
            if c == '"':
                stack.pop()
            elif c == "`" or (c == "$" and text.startswith("(", i + 1)):
                stack.append(c if c == "`" else "(")
                i += c == "$"
        elif c in "'\"`":
            stack.append(c)
        elif c == "$" and text.startswith(("(", "{"), i + 1):
            stack.append(text[i + 1])
            i += 1
        elif c == "(":
            if not stack:
                paren_anomaly = True
            stack.append("(")
        elif c == ")":
            if not stack:
                return i, False, True
            stack.pop()
        elif not stack and c in _SEPARATOR_CHARS:
            return i, False, paren_anomaly
        i += 1
    end = min(i, stop)
    return end, bool(stack), paren_anomaly


def _sh_loop_word_end(text: str, start: int) -> int:
    """End offset of the shell word starting at *start* (an assignment's
    value): quotes, `$(…)`, `${…}` and backticks nest; unquoted whitespace or
    a separator ends it. Never crosses a newline, so a call is always bounded
    by its own line.

    Unchanged behavior/signature -- see `_word_scan_state` above, which this
    now delegates to (the same algorithm, factored so `scan_line` can also
    see the unbalanced/paren-anomaly signals this wrapper discards)."""
    return _word_scan_state(text, start)[0]


# --------------------------------------------------------------------------
# Part-level breakdown of one already-boundary-validated word.
# --------------------------------------------------------------------------
def _find_balanced_end(text: str, open_pos: int, opener: str, closer: str) -> "int | None":
    """*text[open_pos]* is *opener*; returns the index of its matching
    *closer* (nesting the same opener/closer pair), or None if never
    balanced before end-of-text. Used for `${...}` matching only -- `$(...)`/
    backtick substitutions reuse `_word_scan_state`'s own stack machinery via
    `_cmdsub_end` below instead, since their content can itself contain
    quotes that a naive brace counter would mis-nest."""
    depth = 0
    i = open_pos
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _cmdsub_end(text: str, open_pos: int, backtick: bool) -> "int | None":
    """*text[open_pos:]* starts a command substitution (`` ` `` or `$(`).
    Returns the index just past its matching close, honoring nested quotes/
    substitutions inside -- reuses the same balance rules as
    `_word_scan_state` rather than a naive character count, since the
    substitution's own content can freely contain further quotes/
    substitutions of its own."""
    n = len(text)
    if backtick:
        i = open_pos + 1
        while i < n:
            if text[i] == "\\":
                i += 2
                continue
            if text[i] == "`":
                return i + 1
            i += 1
        return None
    # "$(" -- reuse the generic scanner starting AT the '(' so its own
    # stack machinery (which already nests quotes/further substitutions
    # correctly) tells us where the matching ')' is.
    stack = ["("]
    i = open_pos + 2
    while i < n:
        c = text[i]
        top = stack[-1]
        if c == "\\" and top != "'":
            i += 2
            continue
        if top in ("'", "`", "{"):
            if c == _QUOTE_CLOSE[top]:
                stack.pop()
        elif top == '"':
            if c == '"':
                stack.pop()
            elif c == "`" or (c == "$" and text.startswith("(", i + 1)):
                stack.append(c if c == "`" else "(")
                i += c == "$"
        elif c in "'\"`":
            stack.append(c)
        elif c == "$" and text.startswith(("(", "{"), i + 1):
            stack.append(text[i + 1])
            i += 1
        elif c == "(":
            stack.append("(")
        elif c == ")":
            stack.pop()
            if not stack:
                return i + 1
        i += 1
    return None


def _var_name_end(text: str, at: int) -> int:
    """*text[at]* is the first char after a bare (unbraced) `$`. Returns the
    end of the identifier/special-parameter name, or *at* itself if `$` is
    not actually followed by a valid variable-name start (a lone `$` with
    nothing recognizable after it is then just a literal character)."""
    n = len(text)
    if at >= n:
        return at
    c = text[at]
    if c in _VAR_SPECIAL_CHARS:
        return at + 1
    if c.isalpha() or c == "_":
        j = at + 1
        while j < n and text[j] in _VAR_IDENT_RE_CHARS:
            j += 1
        return j
    return at


def _brace_expansion_end(text: str, open_pos: int, word_end: int) -> "int | None":
    """*text[open_pos]* is an unquoted, non-`$`-prefixed `{`. Returns the end
    of a bash brace-EXPANSION-shaped run (a matching `}` within *word_end*
    with a top-level `,` or `..` between them), or None if this `{` is not
    brace-expansion-shaped (bash leaves a lone `{foo}` with no comma/range
    alone -- it is not real brace expansion, just literal characters)."""
    depth = 0
    has_marker = False
    i = open_pos
    while i < word_end:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1 if has_marker else None
        elif depth == 1 and (c == "," or (c == "." and text[i : i + 2] == "..")):
            has_marker = True
        i += 1
    return None


def _split_word_parts(text: str, start: int, end: int) -> "tuple[Part, ...] | None":
    """Breaks one already-boundary-validated word (`text[start:end]`, as
    returned by `_word_scan_state`) into typed Parts. Returns None if it
    finds an unterminated `${...}` that `_word_scan_state` itself could not
    see (that scanner does not track `${` specially once already inside a
    double-quoted context -- see this module's test suite for the isolating
    repro) -- callers (`scan_line`) must treat this exactly like any other
    fail-closed signal.

    Quote-state transitions are flush points: every literal Part is
    homogeneous (either entirely quoted or entirely not) by construction --
    the opening quote character starts the pending quoted run and the
    closing quote character ends it (both count as "quoted"), rather than
    being decided by whatever the quote state happens to be at the next
    unrelated flush."""
    parts: list = []
    quote_stack: list = []  # '\'' or '"' only -- substitutions handled as opaque spans
    i = start
    lit_start = start

    def flush(upto: int, quoted_override=None) -> None:
        nonlocal lit_start
        if upto > lit_start:
            q = bool(quote_stack) if quoted_override is None else quoted_override
            parts.append(Part("literal", text[lit_start:upto], lit_start, upto, q))
        lit_start = upto

    while i < end:
        c = text[i]
        top = quote_stack[-1] if quote_stack else ""
        if c == "\\" and top != "'":
            i += 2
            continue
        if top == "'":
            if c == "'":
                flush(i + 1, quoted_override=True)
                quote_stack.pop()
            i += 1
            continue
        if top == '"':
            if c == '"':
                flush(i + 1, quoted_override=True)
                quote_stack.pop()
                i += 1
                continue
            if c == "`" or (c == "$" and text[i + 1 : i + 2] == "("):
                flush(i)
                sub_end = _cmdsub_end(text, i, backtick=(c == "`"))
                if sub_end is None or sub_end > end:
                    return None
                parts.append(Part("cmdsub", text[i:sub_end], i, sub_end, True))
                i = lit_start = sub_end
                continue
            if c == "$" and text[i + 1 : i + 2] == "{":
                flush(i)
                brace_end = _find_balanced_end(text, i + 1, "{", "}")
                if brace_end is None or brace_end + 1 > end:
                    return None
                var_end = brace_end + 1
                parts.append(Part("variable", text[i:var_end], i, var_end, True))
                i = lit_start = var_end
                continue
            if c == "$":
                var_end = _var_name_end(text, i + 1)
                if var_end == i + 1:
                    # bare '$' with no recognizable name after it -- literal
                    i += 1
                    continue
                flush(i)
                parts.append(Part("variable", text[i:var_end], i, var_end, True))
                i = lit_start = var_end
                continue
            i += 1
            continue
        # --- unquoted / not-inside-single-or-double-quote context ---
        if c in "'\"":
            flush(i)
            quote_stack.append(c)
            i += 1
            continue
        if c == "`" or (c == "$" and text[i + 1 : i + 2] == "("):
            flush(i)
            sub_end = _cmdsub_end(text, i, backtick=(c == "`"))
            if sub_end is None or sub_end > end:
                return None
            parts.append(Part("cmdsub", text[i:sub_end], i, sub_end, False))
            i = lit_start = sub_end
            continue
        if c == "$" and text[i + 1 : i + 2] == "{":
            flush(i)
            brace_end = _find_balanced_end(text, i + 1, "{", "}")
            if brace_end is None or brace_end + 1 > end:
                return None
            var_end = brace_end + 1
            parts.append(Part("variable", text[i:var_end], i, var_end, False))
            i = lit_start = var_end
            continue
        if c == "$":
            var_end = _var_name_end(text, i + 1)
            if var_end == i + 1:
                # bare '$' with nothing recognizable after it -- literal char
                i += 1
                continue
            flush(i)
            parts.append(Part("variable", text[i:var_end], i, var_end, False))
            i = lit_start = var_end
            continue
        if c == "{":
            brace_end = _brace_expansion_end(text, i, end)
            if brace_end is not None:
                flush(i)
                parts.append(Part("brace", text[i:brace_end], i, brace_end, False))
                i = lit_start = brace_end
                continue
            i += 1
            continue
        if c in "*?[":
            flush(i)
            glob_end = i + 1
            if c == "[":
                close = text.find("]", i + 1, end)
                if close != -1:
                    glob_end = close + 1
            parts.append(Part("glob", text[i:glob_end], i, glob_end, False))
            i = lit_start = glob_end
            continue
        i += 1

    if quote_stack:
        return None  # left open inside this word -- _word_scan_state missed it (see docstring)
    flush(end)
    return tuple(parts)


# --------------------------------------------------------------------------
# Top-level: one logical line -> simple commands.
# --------------------------------------------------------------------------
_TWO_CHAR_SEPS = ("&&", "||")


def scan_line(text: str) -> "tuple[SimpleCommand, ...] | None":
    """Splits one shell logical line (no embedded, unescaped newline is
    assumed meaningful past the first -- word scanning never crosses `\\n`
    anyway) into simple commands at top-level `;`/`&&`/`||`/`|`/`&`
    boundaries. Returns None (fail closed) on any unbalanced quote/
    substitution or paren anomaly -- see the module docstring."""
    n = len(text)
    pos = 0
    commands: list = []
    current: list = []
    while pos < n:
        c = text[pos]
        if c in " \t":
            pos += 1
            continue
        if c == "\n":
            pos += 1
            continue
        if text[pos : pos + 2] in _TWO_CHAR_SEPS:
            if current:
                commands.append(SimpleCommand(tuple(current)))
                current = []
            pos += 2
            continue
        if c in ";&|":
            if current:
                commands.append(SimpleCommand(tuple(current)))
                current = []
            pos += 1
            continue
        if c in "()":
            return None  # bare paren at command-start position -- unmodelled
        end, unbalanced, paren_anomaly = _word_scan_state(text, pos)
        if unbalanced or paren_anomaly:
            return None
        if end <= pos:
            return None  # scanner made no progress -- refuse rather than loop
        parts = _split_word_parts(text, pos, end)
        if parts is None:
            return None
        current.append(Word(text[pos:end], pos, end, parts))
        pos = end
    if current:
        commands.append(SimpleCommand(tuple(current)))
    return tuple(commands)
