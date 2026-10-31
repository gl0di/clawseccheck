"""gypbuild - read the build steps of a gyp build config, and classify their commands.

Layer 1 leaf (stdlib only). It renders no verdict: ``deptree`` feeds the steps' script
files to B349, and ``checks/_lifecycle.py``'s B42 judges a skill's own steps.

WHAT GYP RUNS (B-1004). Grounded against the gyp that node-gyp 12.2.0/12.3.0 vendors
(``gyp/pylib/gyp``): ``input.py``'s ``LoadOneBuildFile`` reads a build file as a Python
expression (``eval`` with empty builtins); ``actions``, ``rules`` and ``postbuilds`` are the
target keys whose entries carry an ``action`` argv that the generators turn into a shell
command (``generator/make.py`` ``WriteActions`` / ``WriteRules``; ``postbuilds`` only on
the mac flavor). A list key may carry a merge suffix (``=`` / ``+`` / ``?``,
``MergeDicts``) or a list filter (``!`` exclude / ``/`` regex, ``ProcessListFiltersInDict``),
and ``ProcessVariablesAndConditionsInDict`` recurses into EVERY dict - so a ``conditions``
list inside an action entry can supply or extend its ``action``, and every key of a dict
is also visible to it as the automatic variable ``_<key>`` (``_inputs``, ``_outputs``).
References are ``<(v)``, ``>(v)``, ``^(v)`` (early / late / late-late) and the list splice
``<@(v)``, with names matching ``[-a-zA-Z0-9_.]``. ``includes`` and ``dependencies`` pull
further build files into the same build.

HOW THIS READS IT. ``ast.literal_eval``: literals only, nothing evaluated. What it cannot
resolve is reported as UNEXAMINED rather than dropped - a non-literal file, nested
conditions or a list filter on an ``action``, a reference no file read here defines, more
variable combinations than are tried - because each of those is a way to make a literal
reader see nothing while gyp runs the command unchanged. Variables are collected from
every ``variables`` dict with ALL their values; gyp scopes them per dict and this does
not, so a reference is tried against every value seen for that name. That over-approximates
(it can flag a value gyp would not pick); it does not model gyp's scoping.
"""
from __future__ import annotations

import ast
import itertools
import re
import shlex
import warnings
from dataclasses import dataclass

from .configloader import json_nesting_exceeds

# Bounds on the walk over the parsed value and on what one file may contribute. The text
# itself is bounded by the caller (deptree.MAX_GYP_BYTES). A hit is disclosed.
MAX_GYP_ACTIONS = 40
MAX_GYP_NODES = 50_000
MAX_GYP_NESTING = 64
MAX_ARGV_CANDIDATES = 32
MAX_NESTED_COMMANDS = 3

GYP_EXEC_KEYS = ("actions", "rules", "postbuilds")
_COND_KEYS = ("conditions", "target_conditions")


@dataclass(frozen=True)
class GypBuildStep:
    """One `action` argv from a gyp `actions` / `rules` / `postbuilds` entry.

    `argv` is the list as written (each element coerced to `str`), references unexpanded.
    `name` is the entry's `action_name` / `rule_name` / `postbuild_name`, or "".
    `unexamined` is non-empty when the argv could not be assembled from the file alone.
    `local_vars` holds gyp's automatic `_<key>` variables of the entry and its target.
    """

    key: str
    name: str
    argv: tuple
    unexamined: str = ""
    local_vars: tuple = ()


@dataclass(frozen=True)
class GypBuildConfig:
    steps: tuple = ()
    # name -> tuple of every value seen for it (a str, or a tuple of str for a list).
    variables: dict = None  # type: ignore[assignment]
    # (kind, value): `includes` entries, and `dependencies` entries naming a build file.
    references: tuple = ()


def _strip_merge_suffix(key: str) -> str:
    """gyp's list-merge suffixes (`actions+`, `actions=`, `actions?`) name the same key."""
    return key[:-1] if key[-1:] in ("=", "+", "?") else key


_GYP_FILE_REF_RE = re.compile(r"\.gypi?(?::|\Z)")


def _argv_of(value) -> "tuple | None":
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)) and value:
        return tuple(str(a) for a in value)
    return None


def _auto_vars(d: dict) -> dict:
    """gyp's automatic `_<key>` variables for one dict (str and list-of-str values)."""
    out: dict = {}
    for k, v in d.items():
        if not isinstance(k, str) or not k or k[-1] in "=+?!/":
            continue
        if isinstance(v, (str, int)) and not isinstance(v, bool):
            out["_" + k] = (str(v),)
        elif isinstance(v, (list, tuple)) and all(isinstance(x, str) for x in v):
            out["_" + k] = (tuple(v),)
    return out


def _entry_argvs(entry: dict) -> "tuple[list, str]":
    """Every argv an action entry can end up with, and an unexamined reason if any.

    gyp processes `conditions` inside the entry itself, so a branch may set (`action`,
    `action=`) or extend (`action+`) the argv. Conditions are not evaluated: every branch is
    a candidate. Nested conditions, and a list filter (`action!` / `action/`), are reported.
    """
    base = None
    plus: list = []
    why = ""
    for k, v in entry.items():
        if not isinstance(k, str):
            continue
        if k in ("action!", "action/"):
            why = "its command is rewritten by a gyp list filter (action! / action/)"
            continue
        if _strip_merge_suffix(k) != "action":
            continue
        argv = _argv_of(v)
        if argv is None:
            continue
        if k.endswith("+"):
            plus.append(argv)
        elif base is None or not k.endswith("?"):
            base = argv
    out: list = []
    if base is not None:
        out.append(base)
    for add in plus:
        out.append((base or ()) + add)
    for ck in _COND_KEYS:
        conds = entry.get(ck)
        if not isinstance(conds, (list, tuple)):
            continue
        for cond in conds:
            if not isinstance(cond, (list, tuple)):
                continue
            for branch in cond[1:]:
                if not isinstance(branch, dict):
                    continue
                for k, v in branch.items():
                    if not isinstance(k, str):
                        continue
                    if _strip_merge_suffix(k) in _COND_KEYS:
                        why = "its command is assembled by nested gyp conditions"
                        continue
                    if k in ("action!", "action/"):
                        why = "its command is rewritten by a gyp list filter (action! / action/)"
                        continue
                    if _strip_merge_suffix(k) != "action":
                        continue
                    argv = _argv_of(v)
                    if argv is None:
                        continue
                    out.append((base or ()) + argv if k.endswith("+") else argv)
    return out, why


def parse_gyp_build_config(text: str, *, capped=None) -> GypBuildConfig:
    """Build steps, variables and file references of one gyp build config.

    A file that is not a plain literal dict (gyp would still `eval` an expression such as
    `'a' + 'b'`), a walk that hits `MAX_GYP_NODES`, and a step past `MAX_GYP_ACTIONS` are
    all disclosed through *capped* (a list), never returned as "no build steps".
    """
    try:
        if json_nesting_exceeds(text, MAX_GYP_NESTING):
            # Same bracket-depth gate the JSON readers use: past it, literal_eval's own
            # recursion decides the answer. Counting may over-estimate on a single-quoted
            # string holding brackets, which only errs toward "not examined" (disclosed).
            value = None
        else:
            with warnings.catch_warnings():
                # An invalid escape ("\/") is a SyntaxWarning; it must not reach the terminal.
                warnings.simplefilter("ignore")
                value = ast.literal_eval(text)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        value = None
    if not isinstance(value, dict):
        _note(capped, "is not a plain literal - its build steps were not examined")
        return GypBuildConfig(variables={})

    steps: list = []
    variables: dict = {}
    refs: list = []
    stack: list = [value]
    nodes = 0
    while stack:
        nodes += 1
        if nodes > MAX_GYP_NODES:
            _note(capped, "is too large to walk - the rest of its build steps were not examined")
            break
        cur = stack.pop()
        if isinstance(cur, (list, tuple)):
            stack.extend(cur)
            continue
        if not isinstance(cur, dict):
            continue
        holder_vars = None
        for key, val in cur.items():
            if not isinstance(key, str) or not key:
                continue
            base = _strip_merge_suffix(key)
            if base == "variables" and isinstance(val, dict):
                for vname, vval in val.items():
                    if not isinstance(vname, str):
                        continue
                    if isinstance(vval, str):
                        item = vval
                    elif isinstance(vval, (list, tuple)) and all(isinstance(x, str) for x in vval):
                        item = tuple(vval)
                    else:
                        continue
                    seen = variables.setdefault(vname.rstrip("%"), [])
                    if item not in seen:
                        seen.append(item)
            elif base == "includes" and isinstance(val, (list, tuple)):
                refs.extend(("includes", str(x)) for x in val if isinstance(x, str))
            elif base == "dependencies" and isinstance(val, (list, tuple)):
                refs.extend(("dependencies", x) for x in val
                            if isinstance(x, str) and _GYP_FILE_REF_RE.search(x))
            elif base in GYP_EXEC_KEYS and isinstance(val, (list, tuple)):
                if holder_vars is None:
                    holder_vars = _auto_vars(cur)
                for entry in val:
                    if not isinstance(entry, dict):
                        continue
                    argvs, why = _entry_argvs(entry)
                    label = next(
                        (entry[k] for k in ("action_name", "rule_name", "postbuild_name")
                         if isinstance(entry.get(k), str)),
                        "",
                    )[:80]
                    local = {**holder_vars, **_auto_vars(entry)}
                    for argv in argvs or ([()] if why else []):
                        if len(steps) >= MAX_GYP_ACTIONS:
                            _note(capped, "has more build steps than are examined - the rest were not")
                            break
                        steps.append(GypBuildStep(base, label, tuple(argv), why,
                                                  tuple(sorted(local.items()))))
            stack.append(val)
    return GypBuildConfig(
        steps=tuple(steps),
        variables={k: tuple(v) for k, v in variables.items()},
        references=tuple(dict.fromkeys(refs)),
    )


def _note(capped, reason: str) -> None:
    if capped is not None and reason not in capped:
        capped.append(reason)


# --------------------------------------------------------------------------------------
# Variable expansion
# --------------------------------------------------------------------------------------
_NAME = r"[-a-zA-Z0-9_.]+"
_REF_RE = re.compile(r"[<>^]\((" + _NAME + r")\)")
_SPLICE_RE = re.compile(r"[<>^]@\((" + _NAME + r")\)\Z")
# A whole-token reference to something a build file cannot define: a gyp variable, or a
# make / shell variable (`$(CC)`, `${X}`) the generator leaves for the build to expand.
_WHOLE_REF_RE = re.compile(r"(?:[<>^]@?\(" + _NAME + r"\)|\$\([A-Za-z_]\w*\)|\$\{[A-Za-z_]\w*\})\Z")
UNRESOLVED = "\x00"  # prefix marking an argv element that still holds an unresolved reference


def _expand_token(tok: str, variables: dict, depth: int = 0) -> list:
    """Every string *tok* can expand to (each a candidate), unresolved refs kept marked."""
    if depth > 3:
        return [UNRESOLVED + tok]
    m = _REF_RE.search(tok)
    if not m:
        return [tok]
    values = [v for v in variables.get(m.group(1), ()) if isinstance(v, str)]
    if not values:
        head, tail = tok[: m.end()], tok[m.end():]
        rest = _expand_token(tail, variables, depth) if _REF_RE.search(tail) else [tail]
        return [UNRESOLVED + head + r.lstrip(UNRESOLVED) for r in rest]
    out: list = []
    for v in values:
        out.extend(_expand_token(tok[: m.start()] + v + tok[m.end():], variables, depth + 1))
    return out


def _candidates(variables) -> dict:
    """Normalise to name -> tuple of candidate values (a str, or a tuple for a gyp list).

    `parse_gyp_build_config` returns that shape; so must every caller that merges several
    files' variables (a LIST here is read as ONE gyp list value, not as candidates). A plain
    `{name: value}` mapping is accepted too.
    """
    out: dict = {}
    for k, v in (variables or {}).items():
        if isinstance(v, str):
            out[k] = (v,)
        elif isinstance(v, list):
            out[k] = (tuple(str(x) for x in v),)
        elif isinstance(v, tuple):
            out[k] = v
    return out


def expand_argv(argv, variables) -> "tuple[list, bool]":
    """Candidate argvs after gyp variable expansion, and whether a bound was hit."""
    variables = _candidates(variables)
    per: list = []
    capped = False
    for tok in argv:
        tok = str(tok)
        sm = _SPLICE_RE.match(tok)
        if sm:
            lists = [v for v in variables.get(sm.group(1), ()) if isinstance(v, tuple)]
            per.append([tuple(lst) for lst in lists] or [(UNRESOLVED + tok,)])
            continue
        expanded = _expand_token(tok, variables)
        if len(expanded) > MAX_ARGV_CANDIDATES:
            capped = True
        per.append([(t,) for t in expanded[:MAX_ARGV_CANDIDATES]])
    out: list = []
    for combo in itertools.product(*per):
        if len(out) >= MAX_ARGV_CANDIDATES:
            capped = True
            break
        out.append(tuple(t for part in combo for t in part))
    return out, capped


# --------------------------------------------------------------------------------------
# Command classification
# --------------------------------------------------------------------------------------
_PLAIN_FILE_RE = re.compile(r"[\w./\\-]+\.[A-Za-z0-9]{1,5}\Z")
_SCRIPT_EXT_RE = re.compile(
    r"\.(?:js|mjs|cjs|ts|mts|cts|py|pyw|sh|bash|zsh|pl|pm|rb|php|lua|ps1|psm1|bat|cmd|tcl|awk)\Z",
    re.I,
)
_SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "ash", "mksh", "yash", "fish",
                     "tcsh", "csh"})
_FETCHERS = frozenset({"curl", "wget", "aria2c"})
# A make recipe expands `$(shell ...)` and the shell expands `$(...)` once make has turned
# `$$` into `$`, and backticks: inside ANY argument, not only argv[0].
_SUBST_RE = re.compile(r"\$\(shell[\s)]|\$\$\(|`")

# Each interpreter's own inline-code switch, as that interpreter documents it. This is a
# NAME LIST, and like any name list it is open-ended: an interpreter not named here is not
# recognised. Covered: node / bun (`-e`/`--eval`, `-p`/`--print`, a `data:` module through
# `--import`/`--require`/`--loader`), python / pypy (`-c`, glued after no-argument flags),
# POSIX and csh-family shells (`-c`), perl (`-e`/`-E`), ruby (`-e`), php (`-r`), lua /
# osascript / R / Rscript / julia / elixir / groovy / jrunscript / scala (`-e`; julia also
# `-E`), expect / guile (`-c`), awk (its program text), deno's `eval` subcommand, su and
# script (`-c`), `cmd /c` and `/k`, and PowerShell (anything but a `-File` script).
_PY_INLINE_RE = re.compile(r"-[bBdEhiIOPqsSuvVx]*c")
_PERL_INLINE_RE = re.compile(r"-[nplaswWtTuU0-9]*[eE]")
_RUBY_INLINE_RE = re.compile(r"-[nplaswdvWy]*e")
_SHELL_INLINE_RE = re.compile(r"-[A-Za-z]*c[A-Za-z]*\Z")
_E_FAMILIES = frozenset({"lua", "osascript", "r", "rscript", "julia", "elixir", "groovy",
                         "jrunscript", "scala"})
# Options KNOWN to take the next argument as their value. An option not listed here does
# not end the scan either: a long option without `=` is assumed to take a value, a short
# one is not. What does end it is the first operand that is not such a value.
_VALUE_OPTS = {
    "node": frozenset({"-r", "-C", "-i"}),
    "python": frozenset({"-W", "-X", "-Q"}),
    "shell": frozenset({"-o", "+o", "-O", "+O"}),
    "perl": frozenset({"-I", "-M", "-m", "-x"}),
    "ruby": frozenset({"-I", "-r", "-C", "-E", "-F"}),
    "awk": frozenset({"-F", "-v", "-W"}),
}


def _base(tok: str) -> str:
    b = re.split(r"[\\/]", tok.lstrip(UNRESOLVED))[-1].lower()
    return b[:-4] if b.endswith(".exe") else b


def _family(tok: str) -> "str | None":
    b = _base(tok)
    if b in ("node", "nodejs", "bun"):
        return "node"
    if re.fullmatch(r"(?:python|pypy)(?:\d+(?:\.\d+)?t?)?", b):
        return "python"
    if b in _SHELLS:
        return "shell"
    if b in ("perl", "ruby", "php", "deno", "cmd", "su", "script", "npm"):
        return b
    if b in ("awk", "gawk", "mawk", "nawk"):
        return "awk"
    if b in ("expect", "guile"):
        return "c-flag"
    if b in ("lua", "luajit") or re.fullmatch(r"lua\d+(?:\.\d+)?", b) or b in _E_FAMILIES:
        return "e-flag"
    if b in ("powershell", "pwsh"):
        return "powershell"
    return None


def _plain_script_command(code: str) -> bool:
    """True when an inline shell/cmd/PowerShell command just runs one script file."""
    if re.search(r"[;&|`$<>()\n]", code):
        return False
    try:
        words = shlex.split(code)
    except ValueError:
        return False
    return bool(words) and bool(_SCRIPT_EXT_RE.search(words[0]) or words[0].startswith(("./", "../")))


def classify_build_step(argv, variables=None) -> "tuple[str, str] | None":
    """What a build-step argv runs, when it is something no other scanner can read.

    Returns None for an ordinary step (a program, or an interpreter running a script FILE,
    which the content scanners read like any other file), else `(kind, what)`:

      ("inline", "<interpreter>")  code passed on the command line;
      ("shell", "<what>")          an inline shell command - often an honest one-liner
                                   (`sh -c "cd x && make"`), never proof of anything;
      ("fetch", "<tool>")          a download / registry fetch at build time;
      ("unresolved", "<why>")      what runs depends on something this scan did not resolve.

    Every argv position is tried, not only argv[0], so a wrapper this does not know
    (`chroot / node -e`, `find -exec node -e`) cannot hide the interpreter behind it.
    """
    cands, capped = expand_argv(argv, variables or {})
    if capped:
        return ("unresolved", "it has more gyp variable combinations than are examined")
    results = [_classify_any(list(a), 0) for a in cands]
    for kind in ("inline", "shell", "fetch", "unresolved"):
        for r in results:
            if r is not None and r[0] == kind:
                return r
    return None


def _unresolved(tok: str) -> bool:
    return tok.startswith(UNRESOLVED)


def _undefined_ref(tok: str) -> str:
    m = re.search(r"[<>^]@?\(" + _NAME + r"\)", tok)
    return m.group(0) if m else tok.lstrip(UNRESOLVED)


def _classify_any(args: list, depth: int) -> "tuple[str, str] | None":
    if not args or depth > MAX_NESTED_COMMANDS:
        return ("unresolved", "commands are nested deeper than are examined") if args else None
    found: list = []
    for tok in args:
        raw = tok.lstrip(UNRESOLVED)
        if _SUBST_RE.search(raw):
            found.append(("shell", "a make/shell command substitution"))
        if raw.startswith("NODE_OPTIONS=") and "data:" in raw:
            found.append(("inline", "node (NODE_OPTIONS)"))
    found.append(_classify_head(args))
    for i in range(1, len(args)):
        b = _base(args[i])
        if b == "env":
            for j in range(i + 1, len(args)):
                a = args[j].lstrip(UNRESOLVED)
                s = None
                if a in ("-S", "--split-string") and j + 1 < len(args):
                    s = args[j + 1].lstrip(UNRESOLVED)
                elif a.startswith("--split-string="):
                    s = a.split("=", 1)[1]
                elif a.startswith("-S") and len(a) > 2:
                    s = a[2:]
                if s is not None:
                    try:
                        found.append(_classify_any(shlex.split(s), depth + 1))
                    except ValueError:
                        found.append(("unresolved", "env -S carries an unparseable command"))
                    break
        elif _is_program(b):
            found.append(_classify_at(args, i))
    if _base(args[0]) == "env":
        for j in range(1, len(args)):
            a = args[j].lstrip(UNRESOLVED)
            if a in ("-S", "--split-string") and j + 1 < len(args):
                try:
                    found.append(_classify_any(shlex.split(args[j + 1].lstrip(UNRESOLVED)), depth + 1))
                except ValueError:
                    found.append(("unresolved", "env -S carries an unparseable command"))
                break
    for kind in ("inline", "shell", "fetch", "unresolved"):
        for r in found:
            if r is not None and r[0] == kind:
                return r
    return None


def _is_program(b: str) -> bool:
    return (b in _FETCHERS or b in ("certutil", "npx", "git", "eval")
            or _family(b) is not None)


def _classify_head(args: list) -> "tuple[str, str] | None":
    """argv[0] handled specially: a program named only by a reference."""
    arg0 = args[0]
    raw0 = arg0.lstrip(UNRESOLVED)
    if _unresolved(arg0) and _WHOLE_REF_RE.match(raw0):
        if raw0[1:2] == "@":
            return ("unresolved", f"the command is spliced in from {raw0}, which no build file read here defines")
        rest = args[1:]
        if len(rest) >= 2 and rest[0].lstrip(UNRESOLVED) in ("-e", "-p", "-c", "--eval", "--print", "/c", "/C") \
                and not _PLAIN_FILE_RE.match(rest[1].lstrip(UNRESOLVED)):
            return ("unresolved", f"a program named by {raw0}, which no build file read here defines, "
                                  "is given inline code")
        return None
    if re.fullmatch(r"\$\([A-Za-z_]\w*\)|\$\{[A-Za-z_]\w*\}", raw0):
        return None  # a make/shell variable (`$(CC)`): resolved by the build, not a script host
    return _classify_at(args, 0)


def _classify_at(args: list, i: int) -> "tuple[str, str] | None":
    b = _base(args[i])
    rest = [a for a in args[i + 1:]]
    plain = [a.lstrip(UNRESOLVED) for a in rest]
    if b in _FETCHERS or b == "npx":
        return ("fetch", b)
    if b == "certutil":
        return ("fetch", b) if any(a.lower().lstrip("-/") == "urlcache" for a in plain) else None
    if b == "git":
        ops = [a for a in plain if not a.startswith("-")]
        return ("fetch", "git " + ops[0]) if ops and ops[0] in ("clone", "fetch", "pull", "submodule") else None
    if b == "eval":
        return ("shell", "eval")
    fam = _family(b)
    if fam is None:
        return None
    if fam == "cmd":
        for j, a in enumerate(plain):
            low = a.lower()
            if low.startswith(("/c", "/k")):
                code = " ".join([a[2:]] + plain[j + 1:]).strip()
                return None if _plain_script_command(code) else ("shell", "cmd")
            if not a.startswith("/"):
                return None
        return None
    if fam == "powershell":
        # Quiet only for the forms read here: `-File <script>` and `-Command <script>`.
        # Every other invocation (abbreviated switches, a positional command) is an inline
        # PowerShell command; PowerShell's own parameter grammar is NOT modelled.
        for j, a in enumerate(plain):
            low = a.lower().lstrip("-/")
            if a[:1] in "-/" and low in ("file", "f"):
                return None
            if a[:1] in "-/" and low in ("command", "c"):
                nxt = plain[j + 1] if j + 1 < len(plain) else ""
                return None if _plain_script_command(nxt) else ("shell", b)
        return ("shell", b)
    if fam == "npm":
        ops = [a for a in plain if not a.startswith("-")]
        if ops and ops[0] in ("exec", "x"):
            return ("shell", "npm exec -c") if any(a in ("-c", "--call") or a.startswith("--call=")
                                                    for a in plain) else ("fetch", "npm exec")
        return None
    if fam == "deno":
        for a in plain:
            if not a.startswith("-"):
                return ("inline", "deno") if a == "eval" else None
        return None
    takes_value = False
    for j, a0 in enumerate(rest):
        a = a0.lstrip(UNRESOLVED)
        nxt = plain[j + 1] if j + 1 < len(plain) else ""
        if takes_value:
            takes_value = False
            if not a.startswith("-"):
                continue  # the option's value; an option-shaped token is never swallowed
        if _unresolved(a0):
            if a.startswith("-") or not _PLAIN_FILE_RE.match(re.sub(r"[<>^]@?\(" + _NAME + r"\)", "x", a)):
                return ("unresolved", f"its arguments use {_undefined_ref(a0)}, which no build file "
                                      "read here defines")
            return None  # `<(DEPTH)/tools/gen.py`: the script file, its directory unresolved
        if fam == "awk" and (a in ("-f", "--file") or a.startswith("--file=")):
            return None  # the program comes from a file, read like any other
        hit = _inline_switch(fam, b, a, nxt)
        if hit is not None:
            return hit
        if a in ("--",) or (fam == "python" and a in ("-m", "-")):
            return None
        if a.startswith("-") or (fam == "shell" and a.startswith("+")):
            takes_value = a in _VALUE_OPTS.get(fam, ()) or (a.startswith("--") and "=" not in a)
            continue
        if fam == "awk":
            return ("inline", b)  # the first operand of awk is its program text
        return None  # the script file: what follows is the script's own arguments
    return None


def _inline_switch(fam: str, b: str, a: str, nxt: str) -> "tuple[str, str] | None":
    if fam == "node":
        if a in ("-e", "-p", "-pe", "--eval", "--print") or a.startswith(("--eval=", "--print=")):
            return ("inline", b)
        if (a in ("--import", "--require", "-r", "--loader", "--experimental-loader")
                and nxt.startswith("data:")) or re.match(
                    r"--(?:import|require|loader|experimental-loader)=data:", a):
            return ("inline", b)
    elif fam == "python":
        if _PY_INLINE_RE.match(a):
            return ("inline", b)
    elif fam == "perl":
        if _PERL_INLINE_RE.match(a):
            return ("inline", b)
    elif fam == "ruby":
        if _RUBY_INLINE_RE.match(a):
            return ("inline", b)
    elif fam == "php":
        if a in ("-r", "--run") or (a.startswith("-r") and len(a) > 2):
            return ("inline", b)
    elif fam == "e-flag":
        if a.startswith("-e") or a in ("--eval", "-E", "--print"):
            return ("inline", b)
    elif fam == "c-flag":
        if a == "-c":
            return ("inline", b)
    elif fam == "awk":
        if a in ("-e", "--source") or a.startswith("--source="):
            return ("inline", b)
    elif fam in ("shell", "su", "script"):
        if _SHELL_INLINE_RE.match(a) or a == "--command":
            return None if _plain_script_command(nxt) else ("shell", b)
    return None


def runs_inline_code(argv, variables=None) -> bool:
    """True when *argv* runs inline interpreter code or an inline shell command."""
    r = classify_build_step(argv, variables)
    return r is not None and r[0] in ("inline", "shell")
