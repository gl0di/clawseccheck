"""gypbuild - read the build steps of a gyp build config, and classify their commands.

Layer 1 leaf (stdlib only). It renders no verdict: ``deptree`` feeds the steps' script
files to B349, and ``checks/_lifecycle.py``'s B42 judges a skill's own steps.

WHAT GYP RUNS (B-1004). Grounded against the gyp that node-gyp 12.2.0/12.3.0 vendors
(``gyp/pylib/gyp``): ``input.py``'s ``LoadOneBuildFile`` reads a build file as a Python
expression (``eval`` with empty builtins); ``actions``, ``rules`` and ``postbuilds`` are the
target keys whose entries carry an ``action`` argv that the generators turn into a shell
command (``generator/make.py`` ``WriteActions`` / ``WriteRules``; ``postbuilds`` only on
the mac flavor, via ``xcode_emulation.GetSpecPostbuildCommands``). A list key may carry
gyp's ``=`` / ``+`` / ``?`` merge suffix (``input.py`` ``MergeDicts``), and
``ProcessVariablesAndConditionsInDict`` recurses into EVERY dict - so a ``conditions``
list inside an action entry can supply or extend its ``action``. Variable references
(``<(v)``, ``>(v)``, and the list splice ``<@(v)``) are expanded before anything runs.
``includes`` and ``dependencies`` pull further build files into the same build.

HOW THIS READS IT. ``ast.literal_eval``: literals only, nothing evaluated. Anything this
cannot resolve soundly is reported as UNEXAMINED rather than dropped - a non-literal file,
nested conditions around an ``action``, a variable reference that decides what program
runs - because each of those is a way to make a literal reader see nothing while gyp runs
the command unchanged. Variables are collected from every ``variables`` dict in the file
with ALL their values (gyp scopes them per dict, this does not), and a reference is tried
against each value, so a second same-named definition cannot hide the one gyp uses.
"""
from __future__ import annotations

import ast
import itertools
import re
import shlex
import warnings
from dataclasses import dataclass

# Bounds on the walk over the parsed value and on what one file may contribute. The text
# itself is bounded by the caller (deptree.MAX_GYP_BYTES). A hit is disclosed via *capped*.
MAX_GYP_ACTIONS = 40
MAX_GYP_NODES = 50_000
MAX_ARGV_CANDIDATES = 32

GYP_EXEC_KEYS = ("actions", "rules", "postbuilds")
_COND_KEYS = ("conditions", "target_conditions")


@dataclass(frozen=True)
class GypBuildStep:
    """One `action` argv from a gyp `actions` / `rules` / `postbuilds` entry.

    `argv` is the list as written (each element coerced to `str`), references unexpanded.
    `name` is the entry's `action_name` / `rule_name` / `postbuild_name`, or "".
    `unexamined` is non-empty when the argv could not be assembled from the file alone.
    """

    key: str
    name: str
    argv: tuple
    unexamined: str = ""


@dataclass(frozen=True)
class GypBuildConfig:
    steps: tuple = ()
    # name -> tuple of every value seen for it (a str, or a tuple of str for a list).
    variables: dict = None  # type: ignore[assignment]
    # `includes` entries and `dependencies` entries that name another build file.
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


def _entry_argvs(entry: dict) -> "tuple[list, str]":
    """Every argv an action entry can end up with, and an unexamined reason if any.

    gyp processes `conditions` inside the entry itself, so a branch may set (`action`,
    `action=`) or extend (`action+`) the argv. Conditions are not evaluated: every branch is
    a candidate. Conditions nested inside a branch are not followed - that is reported.
    """
    base = None
    plus: list = []
    for k, v in entry.items():
        if not isinstance(k, str) or _strip_merge_suffix(k) != "action":
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
    why = ""
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
        with warnings.catch_warnings():
            # An invalid escape ("\/") is a SyntaxWarning; it must not reach the terminal.
            warnings.simplefilter("ignore")
            value = ast.literal_eval(text)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        value = None
    if not isinstance(value, dict):
        _note(capped, "is not a plain literal — its build steps were not examined")
        return GypBuildConfig(variables={})

    steps: list = []
    variables: dict = {}
    refs: list = []
    stack: list = [value]
    nodes = 0
    while stack:
        nodes += 1
        if nodes > MAX_GYP_NODES:
            _note(capped, "is too large to walk — the rest of its build steps were not examined")
            break
        cur = stack.pop()
        if isinstance(cur, (list, tuple)):
            stack.extend(cur)
            continue
        if not isinstance(cur, dict):
            continue
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
                refs.extend(str(x) for x in val if isinstance(x, str))
            elif base == "dependencies" and isinstance(val, (list, tuple)):
                refs.extend(x for x in val if isinstance(x, str) and _GYP_FILE_REF_RE.search(x))
            elif base in GYP_EXEC_KEYS and isinstance(val, (list, tuple)):
                for entry in val:
                    if not isinstance(entry, dict):
                        continue
                    argvs, why = _entry_argvs(entry)
                    label = next(
                        (entry[k] for k in ("action_name", "rule_name", "postbuild_name")
                         if isinstance(entry.get(k), str)),
                        "",
                    )[:80]
                    for argv in argvs or ([()] if why else []):
                        if len(steps) >= MAX_GYP_ACTIONS:
                            _note(capped, "has more build steps than are examined — the rest were not")
                            break
                        steps.append(GypBuildStep(base, label, tuple(argv), why))
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
_REF_RE = re.compile(r"[<>]\(([A-Za-z_][\w.]*)\)")
_SPLICE_RE = re.compile(r"[<>]@\(([A-Za-z_][\w.]*)\)\Z")
# A whole-token reference to something this file cannot define: a gyp variable, or a make
# / shell variable (`$(CC)`, `${X}`) the generator leaves for the build to expand.
_WHOLE_REF_RE = re.compile(r"(?:[<>]@?\([A-Za-z_][\w.]*\)|\$\([A-Za-z_]\w*\)|\$\{[A-Za-z_]\w*\})\Z")
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
        # Leave this reference in place but keep expanding any others in the token.
        head, tail = tok[: m.end()], tok[m.end():]
        rest = _expand_token(tail, variables, depth) if _REF_RE.search(tail) else [tail]
        return [UNRESOLVED + head + r.lstrip(UNRESOLVED) for r in rest]
    out: list = []
    for v in values:
        for r in _expand_token(tok[: m.start()] + v + tok[m.end():], variables, depth + 1):
            out.append(r)
    return out


def _candidates(variables) -> dict:
    """Normalise to name -> tuple of candidate values (a str, or a tuple for a gyp list).

    `parse_gyp_build_config` already returns that shape; a plain `{name: value}` mapping
    (one value per name, a list meaning a gyp list) is accepted too.
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


def expand_argv(argv, variables) -> list:
    """Candidate argvs after gyp variable expansion, capped at MAX_ARGV_CANDIDATES."""
    variables = _candidates(variables)
    per: list = []
    for tok in argv:
        tok = str(tok)
        sm = _SPLICE_RE.match(tok)
        if sm:
            lists = [v for v in variables.get(sm.group(1), ()) if isinstance(v, tuple)]
            per.append([tuple(lst) for lst in lists] or [(UNRESOLVED + tok,)])
            continue
        per.append([(t,) for t in _expand_token(tok, variables)][:MAX_ARGV_CANDIDATES])
    out: list = []
    for combo in itertools.product(*per):
        out.append(tuple(t for part in combo for t in part))
        if len(out) >= MAX_ARGV_CANDIDATES:
            break
    return out


# --------------------------------------------------------------------------------------
# Command classification
# --------------------------------------------------------------------------------------
# Script-file extensions: the argument that is the program's own script file. Scanning for
# an inline-code switch stops there - after it, every argument is the script's own.
_SCRIPT_EXT_RE = re.compile(
    r"\.(?:js|mjs|cjs|ts|mts|cts|py|pyw|sh|bash|zsh|pl|pm|rb|php|lua|ps1|psm1|bat|cmd|tcl|awk)\Z",
    re.I,
)
# Any plain file operand (`x.c`, `out/gen.h`): a compiler's `-c x.c`, not inline code.
_PLAIN_FILE_RE = re.compile(r"[\w./\\-]+\.[A-Za-z0-9]{1,5}\Z")
_SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "ash", "mksh", "yash", "fish",
                     "tcsh", "csh"})
# Wrappers that run the command named after their own options.
_WRAPPERS = frozenset({"env", "nice", "nohup", "timeout", "command", "exec", "xargs",
                       "busybox", "stdbuf", "setsid", "ionice", "chrt", "taskset", "sudo",
                       "doas", "time"})
_FETCHERS = frozenset({"curl", "wget"})

# Each interpreter's own inline-code switch, documented by that interpreter: node / bun
# `-e`/`--eval` and `-p`/`--print`; python `-c` (glued allowed, after no-argument flags);
# POSIX shells `-c`; perl `-e`/`-E`; ruby `-e`; php `-r`; lua `-e`; osascript `-e`;
# deno's `eval` subcommand; `cmd /c` and `/k`; PowerShell `-Command`/`-c` and
# `-EncodedCommand`/`-e`/`-ec` (abbreviations such as `-co`/`-en` are accepted by
# PowerShell but were NOT verified here, so they are not claimed).
_PY_INLINE_RE = re.compile(r"-[bBdEhiIOPqsSuvVx]*c")
_PERL_INLINE_RE = re.compile(r"-[nplaswWtTuU0-9]*[eE]")
_RUBY_INLINE_RE = re.compile(r"-[nplaswdvWy]*e")
_SHELL_INLINE_RE = re.compile(r"-[A-Za-z]*c[A-Za-z]*\Z")
# Options whose VALUE may look like a script file. Only used to keep scanning past that
# value - never to stop - so an option missing here cannot hide an inline switch.
_VALUE_OPTS = {
    "node": frozenset({"-r", "--require", "--import", "--loader", "--experimental-loader",
                       "--env-file", "--env-file-if-exists"}),
    "python": frozenset({"-W", "-X"}),
    "perl": frozenset({"-I", "-M", "-m"}),
    "ruby": frozenset({"-I", "-r"}),
}


def _base(tok: str) -> str:
    b = re.split(r"[\\/]", tok)[-1].lower()
    return b[:-4] if b.endswith(".exe") else b


def _family(arg0: str) -> "str | None":
    b = _base(arg0)
    if b in ("node", "nodejs", "bun"):
        return "node"
    if re.fullmatch(r"(?:python|pypy)(?:\d+(?:\.\d+)?t?)?", b):
        return "python"
    if b in _SHELLS:
        return "shell"
    if b in ("perl", "ruby", "php", "deno", "osascript", "cmd"):
        return b
    if b in ("lua", "luajit") or re.fullmatch(r"lua\d+(?:\.\d+)?", b):
        return "lua"
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


_WRAPPER_VALUE_OPTS = {
    "env": {"-u", "--unset", "-C", "--chdir"},
    "nice": {"-n", "--adjustment"},
    "timeout": {"-s", "--signal", "-k", "--kill-after"},
    "xargs": {"-a", "--arg-file", "-d", "--delimiter", "-E", "-e", "-I", "-i", "-L", "-l",
              "-n", "--max-args", "-P", "--max-procs", "-s", "--max-chars"},
    "stdbuf": {"-i", "-o", "-e"}, "exec": {"-a"}, "ionice": {"-c", "-n", "-p"},
    "chrt": {"-p"}, "sudo": {"-u", "-g", "-C", "-D", "-h", "-p", "-U"}, "doas": {"-u", "-C"},
}


def _is_program(tok: str) -> bool:
    b = _base(tok)
    return b in _WRAPPERS or b in _FETCHERS or b == "eval" or _family(tok) is not None


def _strip_wrappers(args: list) -> "tuple[list, bool]":
    """Drop leading wrapper commands and their own options.

    Returns `(argv, node_options_inline)`: the wrapped argv, and whether an `env`
    assignment put a `data:` module into NODE_OPTIONS. Each wrapper's own value-taking
    options consume their value (`env -u NAME`, `nice -n 5`, `timeout -s KILL 5`); an
    option this does not know is skipped and the search for the program goes on, and if
    the token reached is not a known program the next few are tried too - so an unknown
    wrapper option cannot hide the interpreter behind its value.
    """
    node_opts = False
    for _ in range(6):
        if not args or _base(args[0]) not in _WRAPPERS:
            return args, node_opts
        w = _base(args[0])
        rest = list(args[1:])
        if w == "busybox":
            args = rest
            continue
        takes = _WRAPPER_VALUE_OPTS.get(w, set())
        i = 0
        while i < len(rest):
            a = rest[i]
            if w == "env" and (a in ("-S", "--split-string") or a.startswith(("-S", "--split-string="))):
                if a in ("-S", "--split-string"):
                    s, after = (rest[i + 1] if i + 1 < len(rest) else ""), rest[i + 2:]
                else:
                    s, after = (a.split("=", 1)[1] if a.startswith("--") else a[2:]), rest[i + 1:]
                try:
                    rest = shlex.split(s) + after
                except ValueError:
                    rest = s.split() + after
                i = 0
                continue
            if w == "env" and re.fullmatch(r"[A-Za-z_]\w*=.*", a, re.S):
                if a.startswith("NODE_OPTIONS=") and "data:" in a:
                    node_opts = True
                i += 1
                continue
            if a.startswith("-") and a != "-":
                i += 2 if a in takes else 1
                continue
            if w == "timeout" and re.fullmatch(r"[\d.]+[smhd]?", a):
                i += 1
                continue
            if w in ("chrt", "taskset", "nice") and re.fullmatch(r"[\dxa-fA-F,-]+", a):
                i += 1
                continue
            break
        rest = rest[i:]
        if rest and not _is_program(rest[0]):
            # Keep looking: an unknown option's value may stand where the program goes.
            for j in range(1, min(4, len(rest))):
                if _is_program(rest[j]):
                    rest = rest[j:]
                    break
        args = rest
    return args, node_opts


def classify_build_step(argv, variables=None) -> "tuple[str, str] | None":
    """What a build-step argv runs, when it is something no other scanner can read.

    Returns None for an ordinary step (a program, or an interpreter running a script FILE,
    which the content scanners read like any other file), else `(kind, what)`:

      ("inline", "<interpreter>")  code passed on the command line;
      ("shell", "<shell>")         an inline shell command - often an honest one-liner
                                   (`sh -c "cd x && make"`), never proof of anything;
      ("fetch", "<curl|wget>")     a download at build time;
      ("unresolved", "<why>")      the program or its switches come from a reference this
                                   file does not resolve, so what runs was not examined.

    A candidate argv is tried for every value a referenced variable has.
    """
    results = [_classify_one(list(a)) for a in expand_argv(argv, variables or {})]
    for kind in ("inline", "shell", "fetch", "unresolved"):
        for r in results:
            if r is not None and r[0] == kind:
                return r
    return None


def _unresolved(tok: str) -> bool:
    return tok.startswith(UNRESOLVED)


def _classify_one(args: list) -> "tuple[str, str] | None":
    args, node_opts = _strip_wrappers(args)
    if not args:
        return None
    if node_opts and _family(args[0].lstrip(UNRESOLVED)) == "node":
        return ("inline", "node")
    if _base(args[0]) == "eval":
        return ("shell", "eval")
    arg0 = args[0]
    raw0 = arg0.lstrip(UNRESOLVED)
    if _unresolved(arg0):
        if not _WHOLE_REF_RE.match(raw0):
            arg0 = raw0  # a reference inside a path: judge the program by its basename
        elif raw0.startswith(("<@", ">@")):
            return ("unresolved", "the command is spliced in from a gyp list variable this file does not define")
        else:
            # A program named only by an undefined reference. An inline switch right after
            # it, followed by something that is not a plain file, is the only shape judged.
            rest = args[1:]
            if len(rest) >= 2 and rest[0] in ("-e", "-p", "-c", "--eval", "--print", "/c", "/C") \
                    and not _PLAIN_FILE_RE.match(rest[1].lstrip(UNRESOLVED)):
                return ("unresolved", f"an undefined program reference ({raw0}) is given inline code")
            return None
    elif re.fullmatch(r"\$\([A-Za-z_]\w*\)|\$\{[A-Za-z_]\w*\}", raw0):
        return None  # a make/shell variable (`$(CC)`): resolved by the build, not a script host
    fam = _family(arg0)
    b = _base(arg0)
    if fam is None:
        return ("fetch", b) if b in _FETCHERS else None
    rest = args[1:]
    if fam == "cmd":
        for i, a in enumerate(rest):
            if a.lower() in ("/c", "/k"):
                code = " ".join(t.lstrip(UNRESOLVED) for t in rest[i + 1:])
                return None if _plain_script_command(code) else ("shell", "cmd")
            if not a.startswith("/"):
                return None
        return None
    if fam == "deno":
        for a in rest:
            if a == "eval":
                return ("inline", "deno")
            if not a.startswith("-"):
                return None
        return None
    prev = ""
    for i, a0 in enumerate(rest):
        a = a0.lstrip(UNRESOLVED)
        if _unresolved(a0):
            if _SCRIPT_EXT_RE.search(a) and prev not in _VALUE_OPTS.get(fam, ()):
                return None  # `<(DEPTH)/tools/gen.py`: the script file, its dir unresolved
            return ("unresolved", "a gyp variable this file does not define decides the interpreter's arguments")
        nxt = rest[i + 1].lstrip(UNRESOLVED) if i + 1 < len(rest) else ""
        hit = None
        if fam == "node":
            if a in ("-e", "-p", "-pe", "--eval", "--print") or a.startswith(("--eval=", "--print=")):
                hit = ("inline", b)
            elif (a in ("--import", "--require", "-r", "--loader", "--experimental-loader") and nxt.startswith("data:")) \
                    or re.match(r"--(?:import|require|loader|experimental-loader)=data:", a):
                hit = ("inline", b)
            elif a == "--":
                return None
        elif fam == "python":
            if _PY_INLINE_RE.match(a):
                hit = ("inline", b)
            elif a == "-m" or a == "--":
                return None
        elif fam == "perl":
            if _PERL_INLINE_RE.match(a):
                hit = ("inline", b)
        elif fam == "ruby":
            if _RUBY_INLINE_RE.match(a):
                hit = ("inline", b)
        elif fam == "php":
            if a in ("-r", "--run") or (a.startswith("-r") and len(a) > 2):
                hit = ("inline", b)
        elif fam in ("lua", "osascript"):
            if a.startswith("-e"):
                hit = ("inline", b)
        elif fam == "shell":
            if _SHELL_INLINE_RE.match(a) or a == "--command":
                return None if _plain_script_command(nxt) else ("shell", b)
            if a == "--":
                return None
        elif fam == "powershell":
            low = a.lower()
            if low in ("-command", "-c", "-encodedcommand", "-e", "-ec"):
                if low in ("-command", "-c") and _plain_script_command(nxt):
                    return None
                return ("shell", b)
            if low in ("-file", "-f"):
                return None
        if hit:
            return hit
        if _SCRIPT_EXT_RE.search(a) and prev not in _VALUE_OPTS.get(fam, ()):
            return None  # the script file: what follows is the script's own arguments
        prev = a
    return None


def runs_inline_code(argv, variables=None) -> bool:
    """True when *argv* runs inline interpreter code or an inline shell command."""
    r = classify_build_step(argv, variables)
    return r is not None and r[0] in ("inline", "shell")


_EXEC_TEXT_RE = re.compile(r"<!@?\(|['\"](?:actions|rules|postbuilds)[=+?]?['\"]\s*:")


def gyp_text_runs_commands(text: str) -> bool:
    """Cheap textual test: does a build config carry a `<!(...)` or a build-step key?"""
    return bool(_EXEC_TEXT_RE.search(text or ""))
