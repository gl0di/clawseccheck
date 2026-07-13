"""Read-only AST analysis of Python files inside a skill (NO code execution).

Regex alone is blind to obfuscation — for example, a base64-decoded payload passed
to a dynamic-evaluation built-in, `getattr(os, "sys"+"tem")(...)`,
`__import__("os").system(...)`, or `marshal.loads(...)`. We parse Python files with
the stdlib `ast` module — **parse only, never compile or run** — and flag a small,
high-confidence set of malware-grade constructs, plus some informational "dangerous
sink" usage that the B13 engine only escalates when the skill already shows a
credential/exfil signal (so a skill that merely uses subprocess is never failed on
its own).

Pure stdlib. Offline. Best-effort: a file that does not parse (templates, Python 2,
JS mislabelled as .py) yields no findings rather than an error.

IMPORTANT — this module contains string constants that name dangerous built-ins and
decode functions. These are DETECTION PATTERN DATA assembled at import time; this
module never calls or evaluates any of them.
"""

from __future__ import annotations

import ast
import re
from collections import namedtuple

from .scanbudget import ScanBudgetExceeded

# A finding: rule id, severity ("crit" = malware-grade / FAIL-eligible on its own;
# "info" = common sink, escalates only alongside a cred/exfil signal), source line, reason.
ASTFinding = namedtuple("ASTFinding", "rule severity lineno reason")

# Detection pattern sets — assembled from parts so static scanners don't mistake
# these string DATA constants for actual function calls or dynamic-evaluation use.
# This module DETECTS these patterns; it does NOT call or evaluate any of them.
_DECODE_FUNCS = {
    "b64" + "decode",
    "urlsafe_b64" + "decode",
    "b16" + "decode",
    "b32" + "decode",
    "b85" + "decode",
    "a85" + "decode",
    "un" + "hexlify",
    "de" + "compress",
}
_DECODE_ATTRS = _DECODE_FUNCS | {"de" + "code", "from" + "hex", "join"}
_EXEC_NAMES = {"ex" + "ec", "ev" + "al"}
_DANGEROUS_ATTRS = {
    "sys" + "tem",
    "po" + "pen",
    "ex" + "ec",
    "ev" + "al",
    "spawn",
    "spawnl",
    "spawnv",
    "spawnve",
    "call",
    "run",
    "check_output",
    "check_call",
    "Po" + "pen",
}
_DESERIALIZE_MODS = {"pickle", "cpickle", "_pickle", "marshal", "dill", "torch"}
# yaml.load(...) is unconditionally unsafe with NO Loader= kwarg (older pyyaml defaults to
# the arbitrary-code-execution Loader) or an explicit unsafe Loader; yaml.safe_load(...) has
# a different attribute name entirely and is never touched by this rule. Only a Loader of
# SafeLoader/CSafeLoader/BaseLoader/CBaseLoader makes yaml.load(...) itself safe (F-098/L1-1).
_YAML_SAFE_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"}
# Objects on which a *dynamic* getattr(...)() is obfuscation rather than ordinary
# dynamic dispatch: getattr(os, x)() is suspicious; getattr(plugin, handler)() is not.
_DANGEROUS_OBJ = {
    "os",
    "subprocess",
    "sys",
    "builtins",
    "__builtins__",
    "importlib",
    "ctypes",
    "posix",
    "commands",
}

# B-140: provider-shaped hardcoded credential detection. Prefixes assembled from parts
# so this module's OWN detection-pattern data is never mistaken for a live secret by a
# naive scanner (same style as _DECODE_FUNCS / _DANGEROUS_ATTRS above). This module only
# DETECTS a string shape; it never contains, logs, or reproduces a real secret value.
_PROVIDER_TOKEN_PREFIXES = (
    "sk-ant-", "sk-proj-", "sk_live_", "sk_test_", "sk-", "sk_",
    "AKIA", "AIza", "gh" + "p_", "gh" + "o_", "gh" + "s_", "gh" + "r_", "gh" + "u_",
    "xox" + "b-", "xox" + "a-", "xox" + "p-", "xox" + "r-", "xox" + "s-",
    "tvly-", "xai-", "gsk_",
)
_PROVIDER_TOKEN_RE = re.compile(
    r"^(?:" + "|".join(re.escape(p) for p in _PROVIDER_TOKEN_PREFIXES) + r")[A-Za-z0-9_-]{12,}$"
)
_PLACEHOLDER_TOKEN_RE = re.compile(
    r"(?i)(your[_-]?key|changeme|xxxx|example|placeholder|redacted|dummy|<[a-z_]+>|\.\.\.)"
)


def _is_hardcoded_provider_secret(node: ast.AST) -> bool:
    """True if *node* is a string-literal constant shaped like a real provider API key
    (a known prefix + a long high-entropy-looking tail) and NOT an obvious placeholder/
    example value. Never inspects or logs the matched value itself — callers must only
    report the env-var key name and pattern shape, never this string."""
    if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
        return False
    val = node.value
    return bool(_PROVIDER_TOKEN_RE.match(val)) and not _PLACEHOLDER_TOKEN_RE.search(val)


_MAX_FINDINGS_PER_FILE = 25

# B-192: EffectSimulator.State.reached_sinks grows without bound across nested
# branches/loops (each simulate_if/simulate_loop merge duplicates the same sink
# reached via different paths). A deeply-nested-but-tiny skill can drive this past
# 2^depth entries, exhausting memory well before any wall-clock budget fires. This
# caps the DISTINCT (effect, sink, guards) combinations a single simulation may
# track — far beyond any real skill (<100) — and is generous enough to only trip on
# adversarial guard-combination explosion, degrading to an honest UNKNOWN (never a
# silent PASS) via the existing ScanBudgetExceeded -> run_all handler.
_MAX_REACHED_SINKS = 10_000

# Taint (CRED_EXFIL_FLOW): a credential-FILE's contents flowing into a network sink.
# Sources are credential FILE paths ONLY — NOT environment variables — so the common
# legit "read OPENAI_API_KEY, send it as an auth header" pattern is never flagged.

# Taint (ENV_EXFIL_FLOW): env-var reads and agent-config-file reads flowing into a
# network sink.  Severity is "info" so the WARN path in the checks engine controls escalation;
# FAIL is never automatic because legitimate skills routinely send API keys to trusted
# endpoints (e.g. posting ANTHROPIC_API_KEY to api.anthropic.com).
_AGENT_CONFIG_PATH_RE = re.compile(
    r"\.openclaw/|~/.openclaw|~\\\.openclaw|~/\.config/[^/\"']+/", re.I
)

# Sink keyword args that carry a credential as intended auth material (env key ->
# Authorization header is the normal way a skill talks to its own API). A secret here is
# NOT exfiltration; only a secret in the URL, body, params, or a positional arg is.
_ENV_AUTH_KWARGS = frozenset({"headers", "auth", "cert"})

_CRED_PATH_RE = re.compile(
    r"\.ssh/id_|\bid_rsa\b|\bid_ed25519\b|\.aws/credentials|login\.keychain|wallet\.dat|"
    r"keystore\.json|\.npmrc|\.pypirc|\.netrc|\.docker/config|\.kube/config|"
    r"\.config/gcloud|/\.?secrets?\b|cookies\.sqlite|Cookies\b",
    re.I,
)
_NET_SINK_ATTRS_ANY = {"post", "put", "patch", "urlopen", "request"}
_NET_SINK_ATTRS_BASED = {"send", "sendall", "sendto", "connect"}
_NET_SINK_BASES = {
    "requests",
    "httpx",
    "urllib",
    "socket",
    "aiohttp",
    "smtplib",
    "ftplib",
    "session",
}

# ---------------------------------------------------------------------------
# Extended taint: TT4 (file-read->network), TT5 (external->exec), SSRF
# ---------------------------------------------------------------------------

# Call names that signal external/tool/LLM output — conservative, noun-like result vars.
# A variable assigned from ANY call whose name matches this pattern is treated as tainted.
_TOOL_RESULT_CALL_RE = re.compile(r"\b(response|result|completion|output|message|reply)\b", re.I)

# Network source attrs: a call to one of these reads data FROM the network.
_NET_SOURCE_ATTRS = {"get", "urlopen", "urlretrieve", "read", "recv", "recvfrom"}
_NET_SOURCE_BASES = {"requests", "httpx", "urllib", "urllib.request"}

# Exec/shell sinks for TT5 — assembled from parts (detection data, not calls).
_EXEC_SINK_NAMES = {"ex" + "ec", "ev" + "al"}
_EXEC_SINK_OS_ATTRS = {"sys" + "tem", "po" + "pen"}
_EXEC_SINK_SUBP_ATTRS = {"run", "call", "check_output", "check_call", "Popen"}
_EXEC_SINK_BASES_OS = {"os"}
_EXEC_SINK_BASES_SUBP = {"subprocess"}

# Network-out sinks for TT4 (data-bearing) and SSRF (fetch).
_NET_OUT_SINK_DATA_ATTRS = {"post", "put", "patch"}
_NET_OUT_SINK_SEND_ATTRS = {"send", "sendall", "sendto"}
_NET_OUT_SINK_FETCH_ATTRS = {"get", "urlopen"}  # SSRF sinks
_NET_OUT_SINK_BASES = {
    "requests",
    "httpx",
    "urllib",
    "urllib.request",
    "socket",
    "aiohttp",
    "smtplib",
    "ftplib",
    "session",
}

# Internal metadata / SSRF-attractive endpoints.
_SSRF_LITERAL_RE = re.compile(
    r"169\.254\.169\.254|metadata\.internal|localhost|127\.0\.0\.1|::1", re.I
)

# File-read call patterns for TT4 source detection.
_FILE_READ_METHOD_ATTRS = {"read", "read_text", "readline", "readlines", "read_bytes"}
_FILE_OPEN_NAMES = {"open"}


def _is_external_source_call(node: ast.Call) -> bool:
    """True if *node* is a call that introduces external/untrusted data."""
    f = node.func
    # input()
    if isinstance(f, ast.Name) and f.id == "input":
        return True
    # requests.get / httpx.get / urllib.urlopen — network input.
    if isinstance(f, ast.Attribute):
        base = _attr_base(f.value)
        if f.attr in _NET_SOURCE_ATTRS and base in _NET_SOURCE_BASES:
            return True
        # .read() / .read_text() on any file object — file-read source.
        if f.attr in _FILE_READ_METHOD_ATTRS:
            return True
    if isinstance(f, ast.Name) and f.id in _FILE_OPEN_NAMES:
        return True
    return False


def _is_tool_result_call(node: ast.Call) -> bool:
    """True if the call's name suggests a model/tool result variable."""
    f = node.func
    name = ""
    if isinstance(f, ast.Name):
        name = f.id
    elif isinstance(f, ast.Attribute):
        name = f.attr
    return bool(_TOOL_RESULT_CALL_RE.search(name))


def _rhs_has_subscript_environ(node: ast.AST) -> bool:
    """True if *node* is or contains os.environ[...] (subscript form)."""
    for n in ast.walk(node):
        if isinstance(n, ast.Subscript):
            v = n.value
            if isinstance(v, ast.Attribute) and v.attr == "environ" and _attr_base(v.value) == "os":
                return True
            if isinstance(v, ast.Name) and v.id == "environ":
                return True
    return False


def _rhs_has_fstring_taint(node: ast.AST, tainted: set[str]) -> bool:
    """True if *node* is an f-string (JoinedStr) containing a tainted name."""
    for n in ast.walk(node):
        if isinstance(n, ast.JoinedStr):
            if _names_in(n) & tainted:
                return True
    return False


def _value_is_tainted_source(node: ast.AST, tainted: set[str]) -> bool:
    """True if *node* derives from an external source or a tainted name."""
    if isinstance(node, ast.Name) and node.id in tainted:
        return True
    if isinstance(node, ast.Call):
        call = node
        f = call.func
        # os.getenv
        if isinstance(f, ast.Attribute) and f.attr == "getenv" and _attr_base(f.value) == "os":
            return True
        # environ.get(...)
        if isinstance(f, ast.Attribute) and f.attr == "get" and _attr_base(f.value) == "environ":
            return True
        if _is_external_source_call(call):
            return True
        if _is_tool_result_call(call):
            return True
        # Recurse into args — catches open(...).read() chain.
        for child in ast.iter_child_nodes(call):
            if _value_is_tainted_source(child, tainted):
                return True
    else:
        for child in ast.iter_child_nodes(node):
            if _value_is_tainted_source(child, tainted):
                return True
    return False


def _external_tainted_names(tree: ast.AST, func_params: set[str]) -> set[str]:
    """Compute tainted names for TT4/TT5/SSRF rules.

    Sources: function parameters, os.getenv/os.environ[...], open/read (file),
    requests.get/urllib.urlopen/httpx.get (network input), input(), tool-result calls.
    Propagation: assignment, dict/list packing, f-strings, fixpoint up to 6 iterations.
    """
    tainted: set[str] = set(func_params)
    assigns = [n for n in ast.walk(tree) if isinstance(n, (ast.Assign, ast.AugAssign))]

    for _ in range(6):
        changed = False
        for a in assigns:
            rhs = a.value
            targets = a.targets if isinstance(a, ast.Assign) else [a.target]
            sourced = (
                _value_is_tainted_source(rhs, tainted)
                or _rhs_has_subscript_environ(rhs)
                or _rhs_has_fstring_taint(rhs, tainted)
                or bool(_names_in(rhs) & tainted)
            )
            if sourced:
                for t in targets:
                    if isinstance(t, ast.Name) and t.id not in tainted:
                        tainted.add(t.id)
                        changed = True
                    elif isinstance(t, (ast.Tuple, ast.List)):
                        for elt in t.elts:
                            if isinstance(elt, ast.Name) and elt.id not in tainted:
                                tainted.add(elt.id)
                                changed = True
        if not changed:
            break
    return tainted


def _collect_func_params(tree: ast.AST) -> set[str]:
    """All argument names of all function definitions in *tree*."""
    params: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
                params.add(arg.arg)
            if node.args.vararg:
                params.add(node.args.vararg.arg)
            if node.args.kwarg:
                params.add(node.args.kwarg.arg)
    return params


def _is_exec_sink_call(func: ast.AST) -> tuple:
    """Return (is_exec_sink, sink_description) for a call node's func."""
    if isinstance(func, ast.Name) and func.id in _EXEC_SINK_NAMES:
        return True, func.id
    if isinstance(func, ast.Attribute):
        base = _attr_base(func.value)
        if base in _EXEC_SINK_BASES_OS and func.attr in _EXEC_SINK_OS_ATTRS:
            return True, f"os.{func.attr}"
        if base in _EXEC_SINK_BASES_SUBP and func.attr in _EXEC_SINK_SUBP_ATTRS:
            return True, f"subprocess.{func.attr}"
    return False, ""


def _is_net_out_data_sink(func: ast.AST) -> tuple:
    """Return (is_data_net_sink, sink_description) — POST/PUT/PATCH/send* sinks."""
    if isinstance(func, ast.Attribute):
        base = _attr_base(func.value)
        if func.attr in _NET_OUT_SINK_DATA_ATTRS and base in _NET_OUT_SINK_BASES:
            return True, f"{base}.{func.attr}"
        if func.attr in _NET_OUT_SINK_SEND_ATTRS and base in _NET_OUT_SINK_BASES:
            return True, f"{base}.{func.attr}"
    return False, ""


def _is_ssrf_sink_call(func: ast.AST) -> tuple:
    """Return (is_ssrf_sink, sink_description) — GET/urlopen sinks."""
    if isinstance(func, ast.Name) and func.id == "urlopen":
        return True, "urlopen"
    if isinstance(func, ast.Attribute):
        base = _attr_base(func.value)
        if func.attr in _NET_OUT_SINK_FETCH_ATTRS and base in _NET_OUT_SINK_BASES:
            return True, f"{base}.{func.attr}"
    return False, ""


def _call_args_tainted(node: ast.Call, tainted: set[str]) -> tuple:
    """Return (any_tainted, first_arg_direct).

    first_arg_direct: first positional arg is a tainted Name directly.
    """
    all_args = list(node.args) + [kw.value for kw in node.keywords]
    any_tainted = False
    for arg_node in all_args:
        if _names_in(arg_node) & tainted:
            any_tainted = True
            break
        for sub in ast.walk(arg_node):
            if isinstance(sub, ast.JoinedStr) and _names_in(sub) & tainted:
                any_tainted = True
                break
        if any_tainted:
            break
    direct = bool(node.args and isinstance(node.args[0], ast.Name) and node.args[0].id in tainted)
    return any_tainted, direct


def _scope_own_nodes(scope: ast.AST):
    """Yield nodes belonging to `scope`'s own body, WITHOUT descending into nested
    function/class/lambda scopes (whose local names are unrelated). Used so a local
    name reused across sibling functions is resolved per-scope, not conflated."""
    body = (
        scope.body
        if isinstance(scope, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef))
        else [scope]
    )
    stack = list(body)
    while stack:
        n = stack.pop()
        yield n
        for child in ast.iter_child_nodes(n):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue  # nested scope — resolved on its own pass
            stack.append(child)


def _single_list_bindings_local(scope: ast.AST) -> dict[str, ast.List | ast.Tuple]:
    """Names bound EXACTLY ONCE to a list/tuple literal within `scope`'s own body,
    with no later mutation that could change argv[0] (`cmd[0] = ...` / `cmd.insert(...)`).

    Resolves the common real-world safe pattern where the command list is built in a
    local before the call (`cmd = [prog, *args]; subprocess.run(cmd)`) rather than
    passed inline. Conservative: a name reassigned, index-assigned, or `insert`-mutated
    is omitted, so the caller falls back to the command-injection default rather than
    risk a false downgrade.
    """
    assign_count: dict[str, int] = {}
    bindings: dict[str, ast.List | ast.Tuple] = {}
    unsafe: set[str] = set()
    for n in _scope_own_nodes(scope):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    assign_count[t.id] = assign_count.get(t.id, 0) + 1
                    if isinstance(n.value, (ast.List, ast.Tuple)):
                        bindings[t.id] = n.value
                    else:
                        unsafe.add(t.id)  # bound to a non-literal -> unresolvable
                elif isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name):
                    unsafe.add(t.value.id)  # cmd[0] = ... could replace the program
        elif isinstance(n, ast.Call):
            f = n.func
            if (
                isinstance(f, ast.Attribute)
                and f.attr == "insert"
                and isinstance(f.value, ast.Name)
            ):
                unsafe.add(f.value.id)  # cmd.insert(0, ...) could shift argv[0]
    return {k: v for k, v in bindings.items() if assign_count.get(k, 0) == 1 and k not in unsafe}


def _list_bindings_by_call(tree: ast.AST) -> dict[ast.Call, dict[str, ast.List | ast.Tuple]]:
    """Map each Call node to the single-list-bindings visible in its enclosing scope
    (module scope for top-level calls). Per-scope so a local name reused across sibling
    functions is not conflated into ambiguity."""
    out: dict[ast.Call, dict[str, ast.List | ast.Tuple]] = {}
    scopes = [tree] + [
        n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    for scope in scopes:
        binds = _single_list_bindings_local(scope)
        for n in _scope_own_nodes(scope):
            if isinstance(n, ast.Call):
                out[n] = binds
    return out


def _subprocess_taint_is_command_injection(
    node: ast.Call, tainted: set, list_bindings: dict[str, ast.List | ast.Tuple] | None = None
) -> bool:
    """For a subprocess.* call with tainted input, is it command-injection grade?

    True  -> shell=True (or a non-literal shell value), OR a non-list first arg
             (string command / tainted program path), OR the program element argv[0]
             is itself tainted.
    False -> argv-list form with shell not True and a fixed (untainted) program — the
             tainted value is only a non-program argument. That is argument injection
             (low risk: metacharacters are literal argv data passed to execve), NOT
             command injection. Regression guard for the B13 false-positive class.

    The argv list may be inline (`run([prog, arg])`) or bound to a local resolved via
    ``list_bindings`` (`cmd = [prog, arg]; run(cmd)`) — the dominant real-world form.
    """
    for kw in node.keywords:
        if kw.arg == "shell":
            v = kw.value
            if isinstance(v, ast.Constant) and v.value is False:
                break  # explicit shell=False -> fall through to the argv-form check
            return True  # shell=True, or a dynamic value we cannot prove is False
    first = node.args[0] if node.args else None
    if isinstance(first, ast.Name) and list_bindings:
        first = list_bindings.get(first.id, first)  # resolve a var-bound command list
    if isinstance(first, (ast.List, ast.Tuple)):
        prog = first.elts[0] if first.elts else None
        if prog is not None and (_names_in(prog) & tainted):
            return True  # tainted program name -> arbitrary program execution
        return False  # only a non-program argv element is tainted -> argument injection
    return True  # string / name / concat first arg -> string command or program path


def _subprocess_call_is_fixed_argv(
    node: ast.Call, list_bindings: dict[str, ast.List | ast.Tuple] | None = None
) -> bool:
    """B-132: True when a subprocess.* call's command is a literal argv LIST (inline or a
    var bound to exactly one list/tuple literal — see _single_list_bindings_local) and
    shell is not True. This is a pure SHAPE check, independent of taint: a fixed argv list
    passes its elements to execve as literal argv data, not through a shell, so it cannot
    be split/re-interpreted the way a concatenated/interpolated command STRING can — much
    lower risk regardless of whether any element happens to be attacker-influenced.
    Mirrors _subprocess_taint_is_command_injection's list-resolution but without requiring
    a taint set, so it can gate the untainted DANGEROUS_SINK info-sink classification too.
    """
    for kw in node.keywords:
        if kw.arg == "shell":
            v = kw.value
            if not (isinstance(v, ast.Constant) and v.value is False):
                return False  # shell=True, or a dynamic value we cannot prove is False
    first = node.args[0] if node.args else None
    if isinstance(first, ast.Name) and list_bindings:
        first = list_bindings.get(first.id, first)  # resolve a var-bound command list
    return isinstance(first, (ast.List, ast.Tuple))


def _file_read_tainted_names(tree: ast.AST) -> set[str]:
    """Names whose value derives from a file-read operation (for TT4 source)."""
    tainted: set[str] = set()
    assigns = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)]
    for _ in range(4):
        changed = False
        for a in assigns:
            if _names_in(a.value) & tainted or _is_file_read_value(a.value, tainted):
                for t in a.targets:
                    if isinstance(t, ast.Name) and t.id not in tainted:
                        tainted.add(t.id)
                        changed = True
        if not changed:
            break
    return tainted


def _is_file_read_value(node: ast.AST, tainted: set[str]) -> bool:
    """True if *node* is a file-read expression or references a file-read tainted name."""
    if isinstance(node, ast.Name) and node.id in tainted:
        return True
    if isinstance(node, ast.Call):
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr in _FILE_READ_METHOD_ATTRS:
            return True
        for child in ast.iter_child_nodes(node):
            if _is_file_read_value(child, tainted):
                return True
    return False


def _file_tainted(source: str, tree: ast.AST) -> set[str]:
    """Pre-filtered file-read taint: only run when the source has an open()/read_text() call."""
    if "open(" not in source and "read_text" not in source and "read_bytes" not in source:
        return set()
    return _file_read_tainted_names(tree)


def _is_env_read_value(node: ast.AST) -> bool:
    """True if *node* is a direct env-var read call (os.getenv, os.environ.get, os.environ[...]).

    Does NOT include file reads, network reads, or any other external source — env-var
    reads only, so the taint set stays tightly scoped to the ENV_EXFIL_FLOW rule.
    """
    if isinstance(node, ast.Call):
        f = node.func
        # os.getenv("X")
        if isinstance(f, ast.Attribute) and f.attr == "getenv" and _attr_base(f.value) == "os":
            return True
        # os.environ.get("X") — func is Attribute(value=Attribute(value=Name("os"), attr="environ"), attr="get")
        if isinstance(f, ast.Attribute) and f.attr == "get":
            base = f.value
            if (
                isinstance(base, ast.Attribute)
                and base.attr == "environ"
                and _attr_base(base.value) == "os"
            ):
                return True
            # environ.get("X") when environ was imported directly
            if isinstance(base, ast.Name) and base.id == "environ":
                return True
    return False


def _env_tainted_names(tree: ast.AST) -> set[str]:
    """Names whose value derives from an env-var read (transitively).

    Sources: os.getenv(), os.environ.get(), os.environ[...] subscript, environ[...].
    Propagation: simple assignment fixpoint (up to 4 iterations).
    """
    tainted: set[str] = set()
    assigns = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)]
    for _ in range(4):
        changed = False
        for a in assigns:
            rhs = a.value
            sourced = (
                _is_env_read_value(rhs)
                or _rhs_has_subscript_environ(rhs)
                or bool(_names_in(rhs) & tainted)
            )
            if not sourced:
                # Walk into f-strings and BinOp so  url + os.getenv("KEY") also taints url+key
                for sub in ast.walk(rhs):
                    if sub is rhs:
                        continue
                    if _is_env_read_value(sub) or _rhs_has_subscript_environ(sub):
                        sourced = True
                        break
            if sourced:
                for t in a.targets:
                    if isinstance(t, ast.Name) and t.id not in tainted:
                        tainted.add(t.id)
                        changed = True
                    elif isinstance(t, (ast.Tuple, ast.List)):
                        for elt in t.elts:
                            if isinstance(elt, ast.Name) and elt.id not in tainted:
                                tainted.add(elt.id)
                                changed = True
        if not changed:
            break
    return tainted


def _has_agent_config_path_const(node: ast.AST) -> bool:
    """True if the subtree contains a string constant naming an agent config file path."""
    for n in ast.walk(node):
        if (
            isinstance(n, ast.Constant)
            and isinstance(n.value, str)
            and _AGENT_CONFIG_PATH_RE.search(n.value)
        ):
            return True
    return False


def _agent_config_file_tainted_names(source: str, tree: ast.AST) -> set[str]:
    """Names whose value derives from reading an agent-config file (transitively).

    Like _file_read_tainted_names but restricted to file-reads whose path argument
    contains an agent-config path literal (.openclaw/, ~/.config/<agent>/).
    Returns an empty set when no agent-config path appears in the source (fast path).
    """
    if not _AGENT_CONFIG_PATH_RE.search(source):
        return set()
    tainted: set[str] = set()
    assigns = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)]
    for _ in range(4):
        changed = False
        for a in assigns:
            rhs = a.value
            sourced = bool(_names_in(rhs) & tainted) or _is_agent_config_read_value(rhs, tainted)
            if sourced:
                for t in a.targets:
                    if isinstance(t, ast.Name) and t.id not in tainted:
                        tainted.add(t.id)
                        changed = True
        if not changed:
            break
    return tainted


def _is_agent_config_read_value(node: ast.AST, tainted: set[str]) -> bool:
    """True if *node* is a file-read on a path that is an agent-config path literal,
    or references a name already tainted by such a read."""
    if isinstance(node, ast.Name) and node.id in tainted:
        return True
    if isinstance(node, ast.Call):
        f = node.func
        # .read() / .read_text() / .readlines() / .read_bytes() on an open() call
        # whose path argument is an agent-config path literal.
        if isinstance(f, ast.Attribute) and f.attr in _FILE_READ_METHOD_ATTRS:
            # The object being called on may be an open(path) call.
            if _is_agent_config_open_call(f.value):
                return True
            # Or a tainted name (propagation).
            if isinstance(f.value, ast.Name) and f.value.id in tainted:
                return True
        # open(path) or Path(path).read_text() etc — check if path has agent-config literal.
        if isinstance(f, ast.Name) and f.id in _FILE_OPEN_NAMES:
            if node.args and _has_agent_config_path_const(node.args[0]):
                return True
        # Recurse for chained calls.
        for child in ast.iter_child_nodes(node):
            if _is_agent_config_read_value(child, tainted):
                return True
    return False


def _is_agent_config_open_call(node: ast.AST) -> bool:
    """True if *node* is an open(path) call where path is an agent-config path literal."""
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    if isinstance(f, ast.Name) and f.id in _FILE_OPEN_NAMES:
        return bool(node.args and _has_agent_config_path_const(node.args[0]))
    return False


def _has_cred_path_const(node: ast.AST) -> bool:
    """True if the subtree contains a string constant naming a credential file."""
    for n in ast.walk(node):
        if (
            isinstance(n, ast.Constant)
            and isinstance(n.value, str)
            and _CRED_PATH_RE.search(n.value)
        ):
            return True
    return False


def _is_net_sink(func: ast.AST) -> bool:
    if isinstance(func, ast.Name):
        return func.id == "urlopen"
    if isinstance(func, ast.Attribute):
        if func.attr in _NET_SINK_ATTRS_ANY:
            return True
        if func.attr in _NET_SINK_ATTRS_BASED:
            return _attr_base(func.value) in _NET_SINK_BASES
    return False


def _cred_tainted_names(tree: ast.AST) -> set[str]:
    """Names whose value derives from reading a credential file (transitively)."""
    tainted: set[str] = set()
    assigns = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)]
    for _ in range(4):  # small fixpoint for multi-step flows (p = path; k = open(p).read())
        changed = False
        for a in assigns:
            if _has_cred_path_const(a.value) or (_names_in(a.value) & tainted):
                for t in a.targets:
                    if isinstance(t, ast.Name) and t.id not in tainted:
                        tainted.add(t.id)
                        changed = True
        if not changed:
            break
    return tainted


def _is_decode_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    if isinstance(f, ast.Name) and f.id in _DECODE_FUNCS:
        return True
    return isinstance(f, ast.Attribute) and f.attr in _DECODE_ATTRS


def _has_xor_decode(node: ast.AST) -> bool:
    """F-053: True when the subtree builds a byte/char sequence via XOR — bytes(...^...),
    bytearray(...^...), or a comprehension containing ^ — the common non-base64
    obfuscation. A scalar `a ^ b` (bit flags) is NOT flagged: the XOR must sit inside a
    sequence-builder or comprehension, which is the decode shape."""
    for n in ast.walk(node):
        if (
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id in ("bytes", "bytearray")
        ):
            if any(isinstance(s, ast.BinOp) and isinstance(s.op, ast.BitXor) for s in ast.walk(n)):
                return True
        if isinstance(n, (ast.ListComp, ast.GeneratorExp, ast.SetComp)):
            if any(isinstance(s, ast.BinOp) and isinstance(s.op, ast.BitXor) for s in ast.walk(n)):
                return True
    return False


def _subtree_has_decode(node: ast.AST) -> bool:
    return any(_is_decode_call(n) for n in ast.walk(node)) or _has_xor_decode(node)


# F-058: code-level time-bomb / sandbox-evasion. Narrow on purpose — wall-clock date
# (datetime.now()/date.today()/utcnow) and environment presence (os.environ / os.getenv)
# only; NOT time.time() elapsed-timeouts or sys.platform checks, which are ordinary flow.
_TIMEBOMB_DATE_HINTS = {"now", "today", "utcnow", "fromtimestamp", "datetime", "date"}


def _suspicious_guard_kind(test: ast.AST) -> str:
    """Classify an `if` test as a date/time or environment gate; '' if neither."""
    for n in ast.walk(test):
        if isinstance(n, ast.Attribute):
            if n.attr in _TIMEBOMB_DATE_HINTS:
                return "a wall-clock date"
            if n.attr in ("environ", "getenv"):
                return "an environment-variable"
        if isinstance(n, ast.Name) and n.id in _TIMEBOMB_DATE_HINTS:
            return "a wall-clock date"
    return ""


def _conditional_sink_findings(tree: ast.AST) -> list:
    """A dangerous sink (exec/eval/os.system/subprocess or a network call) reachable only
    under a date/time or environment guard — the code-level time-bomb / sandbox-evasion
    pattern, distinct from B65's prose sleeper-trigger. WARN-grade (conditional execution
    has legit uses): the checks engine routes CONDITIONAL_SINK to a WARN, never an automatic FAIL."""
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        kind = _suspicious_guard_kind(node.test)
        if not kind:
            continue
        found = False
        for stmt in (*node.body, *node.orelse):
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Call):
                    is_exec, sink = _is_exec_sink_call(sub.func)
                    if is_exec or _is_net_sink(sub.func):
                        ln = getattr(sub, "lineno", getattr(node, "lineno", 0))
                        out.append(
                            ASTFinding(
                                "CONDITIONAL_SINK",
                                "info",
                                ln,
                                f"a dangerous sink ({sink or 'network call'}) runs only under {kind} "
                                "condition — possible time-bomb / sandbox-evasion gating",
                            )
                        )
                        found = True
                        break
            if found:
                break
    return out


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _tainted_names(tree: ast.AST) -> set[str]:
    """Names assigned from a decode/decompress expression — so a dynamic-eval call on
    `payload`, where `payload` was assigned `base64.b64decode(...)` earlier, is still
    recognised."""
    tainted: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and _subtree_has_decode(node.value):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    tainted.add(t.id)
    return tainted


def _attr_base(value: ast.AST) -> str:
    if isinstance(value, ast.Name):
        return value.id.lower()
    if isinstance(value, ast.Attribute):
        return value.attr.lower()
    return ""


# D1 (defensibility / import-path hijack): world-writable prefixes an attacker on the
# same host can typically write to, so a sys.path entry rooted there is hijackable.
_WRITABLE_PATH_PREFIXES = ("/tmp/", "/var/tmp/", "/private/tmp/", "/dev/shm/")


def _is_sys_path_mutation(call: ast.Call) -> ast.AST | None:
    """If `call` is sys.path.insert(...)/sys.path.append(...), return the path-argument
    node (the location being added to the import search path); else None."""
    f = call.func
    if not (
        isinstance(f, ast.Attribute)
        and f.attr in ("insert", "append")
        and isinstance(f.value, ast.Attribute)
        and f.value.attr == "path"
        and isinstance(f.value.value, ast.Name)
        and f.value.value.id == "sys"
    ):
        return None
    if f.attr == "insert":
        return call.args[1] if len(call.args) >= 2 else None
    return call.args[0] if call.args else None


def _is_writable_import_path(node: ast.AST) -> bool:
    """True if a sys.path entry is attacker-influenceable — a relative or world-writable
    string literal, or a value derived from an environment variable. The benign self-dir
    form (anchored on __file__) is NOT flagged here: install-directory writability is a
    separate defensibility signal, not an import-path hijack via an untrusted location.
    """
    if any(isinstance(x, ast.Name) and x.id == "__file__" for x in ast.walk(node)):
        return False
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        p = node.value
        if p.startswith(_WRITABLE_PATH_PREFIXES) or p in ("/tmp", "/var/tmp"):
            return True
        return not p.startswith("/")  # relative path -> resolves against the CWD
    if _rhs_has_subscript_environ(node) or any(_is_env_read_value(x) for x in ast.walk(node)):
        return True
    return False


def analyze_python(source: str, filename: str = "<skill>") -> list[ASTFinding]:
    """Return AST findings for one Python source string. Never raises, never executes.

    On a parse failure (SyntaxError, Python 2 syntax, pathological nesting, etc.)
    emits a single AST_UNANALYZABLE finding instead of returning an empty list, so
    callers can distinguish "clean file" from "file the AST/taint layer could not scan".
    """
    try:
        tree = ast.parse(source)
        tainted = _tainted_names(tree)
        # B-132: precompute fixed-argv-list bindings once so the plain subprocess.*
        # DANGEROUS_SINK check below can tell a safe `subprocess.run(['prog', arg])`
        # (or `cmd = ['prog', arg]; subprocess.run(cmd)`) apart from a spliced/
        # interpolated command string — independent of taint (this is a shape check,
        # not a taint check; see _subprocess_call_is_fixed_argv).
        list_bindings_by_call = _list_bindings_by_call(tree)
    except (SyntaxError, ValueError, RecursionError, MemoryError, OverflowError) as exc:
        err_type = type(exc).__name__
        return [
            ASTFinding(
                "AST_UNANALYZABLE",
                "unknown",
                0,
                f"could not parse {filename} ({err_type}) — file not analyzed by the AST/taint layer",
            )
        ]

    out: list[ASTFinding] = []
    seen: set[tuple[str, int]] = set()

    def add(rule: str, severity: str, lineno: int, reason: str) -> None:
        key = (rule, lineno)
        if key in seen:
            return
        seen.add(key)
        out.append(ASTFinding(rule, severity, lineno, reason))

    for node in ast.walk(tree):
        if len(out) >= _MAX_FINDINGS_PER_FILE:
            break
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        ln = getattr(node, "lineno", 0)

        # B-140(b): os.getenv("KEY", "<provider-shaped-literal>") / os.environ.get("KEY", "<...>")
        # — a hardcoded provider-shaped secret used as the literal fallback/default arg.
        if isinstance(f, ast.Attribute) and len(node.args) >= 2:
            is_os_getenv = f.attr == "getenv" and _attr_base(f.value) == "os"
            is_environ_get = f.attr == "get" and (
                (
                    isinstance(f.value, ast.Attribute)
                    and f.value.attr == "environ"
                    and _attr_base(f.value.value) == "os"
                )
                or (isinstance(f.value, ast.Name) and f.value.id == "environ")
            )
            if is_os_getenv or is_environ_get:
                default_arg = node.args[1]
                if _is_hardcoded_provider_secret(default_arg):
                    key_node = node.args[0]
                    key_repr = (
                        key_node.value
                        if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str)
                        else "<dynamic>"
                    )
                    call_name = "os.getenv" if is_os_getenv else f"{_attr_base(f.value)}.get"
                    add(
                        "HARDCODED_PROVIDER_SECRET",
                        "crit",
                        ln,
                        f"hardcoded provider-shaped secret as the default arg of "
                        f"{call_name}({key_repr!r}, ...)",
                    )
                continue

        # A call to a dynamic-evaluation builtin (the names in _EXEC_NAMES):
        # an obfuscated/decoded or tainted argument = crit; a plain one = info.
        if isinstance(f, ast.Name) and f.id in _EXEC_NAMES and node.args:
            arg = node.args[0]
            if _subtree_has_decode(arg) or (_names_in(arg) & tainted):
                add(
                    "OBFUSCATED_EXEC",
                    "crit",
                    ln,
                    f"a call to {f.id} on a decoded/obfuscated string (hidden payload execution)",
                )
            else:
                add("DANGEROUS_SINK", "info", ln, f"a dynamic {f.id} call")
            continue

        # getattr(obj, name)(...) — obfuscated call.
        # crit only for a dangerous attribute literal, OR a dynamic attr on a dangerous
        # module (os/subprocess/...). A dynamic attr on an ordinary object is normal
        # dynamic dispatch (plugin frameworks) -> info, so it never FAILs on its own.
        if isinstance(f, ast.Call) and isinstance(f.func, ast.Name) and f.func.id == "getattr":
            first = f.args[0] if f.args else None
            second = f.args[1] if len(f.args) >= 2 else None
            literal_str = isinstance(second, ast.Constant) and isinstance(second.value, str)
            dynamic = second is not None and not literal_str
            dangerous_literal = literal_str and second.value in _DANGEROUS_ATTRS
            base_obj = _attr_base(first) if first is not None else ""
            if dangerous_literal or (dynamic and base_obj in _DANGEROUS_OBJ):
                add(
                    "GETATTR_INDIRECTION",
                    "crit",
                    ln,
                    "getattr(...)() indirection to a dangerous attribute (obfuscated call)",
                )
            elif dynamic:
                add("GETATTR_INDIRECTION", "info", ln, "dynamic getattr(...)() dispatch")
            continue

        # __import__("os").system(...) / importlib.import_module("os").system(...)
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Call):
            inner = f.value.func
            is_dyn_import = (isinstance(inner, ast.Name) and inner.id == "__import__") or (
                isinstance(inner, ast.Attribute) and inner.attr == "import_module"
            )
            if is_dyn_import and f.attr in _DANGEROUS_ATTRS:
                add(
                    "DYNAMIC_IMPORT_EXEC",
                    "crit",
                    ln,
                    f"__import__(...).{f.attr}() — dynamic import to evade static scan",
                )
                continue

        # D1 (defensibility): sys.path.insert/append to a relative / writable / env-derived
        # location — an import-path hijack surface. Anyone who can write that path drops a
        # module the skill then imports. The benign self-dir form (dirname(__file__)) is clean.
        _sp_arg = _is_sys_path_mutation(node)
        if _sp_arg is not None:
            if _is_writable_import_path(_sp_arg):
                add(
                    "IMPORT_FROM_WRITABLE",
                    "info",
                    ln,
                    "sys.path is extended with a relative / writable / env-derived location — "
                    "anyone able to write that path can hijack the skill's imports",
                )
            continue

        # pickle/marshal/dill/torch.loads/load(...) — info (code-exec only if data untrusted).
        # yaml.load(...) is a special case (F-098/L1-1): unsafe unless an explicit safe
        # Loader= kwarg is given; yaml.safe_load has a different attr name and never reaches
        # here at all, so it stays clean without any special-casing.
        if isinstance(f, ast.Attribute) and f.attr in ("loads", "load"):
            mod = _attr_base(f.value)
            if mod == "yaml" and f.attr == "load":
                loader_kw = next((kw for kw in node.keywords if kw.arg == "Loader"), None)
                loader_name = (
                    loader_kw.value.attr
                    if loader_kw is not None and isinstance(loader_kw.value, ast.Attribute)
                    else (
                        loader_kw.value.id
                        if loader_kw is not None and isinstance(loader_kw.value, ast.Name)
                        else None
                    )
                )
                if loader_name not in _YAML_SAFE_LOADERS:
                    add(
                        "DESERIALIZE_CODE",
                        "info",
                        ln,
                        "yaml.load() without a safe Loader (SafeLoader/BaseLoader) — "
                        "arbitrary-code-execution risk if the data is untrusted",
                    )
                continue
            # B-132: torch.load(..., weights_only=True) is PyTorch's own safe-loading
            # flag (analogous to yaml's SafeLoader) — it restricts unpickling to a fixed
            # allowlist of tensor/primitive types, so it is not a code-exec-on-load risk
            # the way a bare torch.load()/pickle.load() is. Skip flagging it entirely,
            # mirroring the yaml.load(Loader=SafeLoader) special-case above.
            if mod == "torch" and f.attr == "load":
                wo_kw = next((kw for kw in node.keywords if kw.arg == "weights_only"), None)
                if (
                    wo_kw is not None
                    and isinstance(wo_kw.value, ast.Constant)
                    and wo_kw.value.value is True
                ):
                    continue
            if mod in _DESERIALIZE_MODS:
                add(
                    "DESERIALIZE_CODE",
                    "info",
                    ln,
                    f"{mod}.{f.attr}() deserialization (code-exec risk if data is untrusted)",
                )
                continue

        # os.system/popen/exec*/spawn*, subprocess.* — info shell/exec sinks
        if isinstance(f, ast.Attribute):
            base = _attr_base(f.value)
            is_os = base == "os" and (
                f.attr in ("system", "popen")
                or f.attr.startswith("ex" + "ec")
                or f.attr.startswith("spawn")
            )
            is_subp = base == "subprocess" and f.attr in (
                "run",
                "call",
                "check_output",
                "check_call",
                "Popen",
            )
            # B-132: a subprocess.* call with a literal, fixed argv list (shell not True)
            # passes its arguments straight to execve — not through a shell — so it is
            # far lower risk than a spliced/interpolated command string and should not
            # weigh the same as a genuine shell-exec sink. Skip flagging it entirely here
            # (it still participates fully in the separate taint-aware TT5 pass below,
            # which already distinguishes command- from argument-injection).
            if is_subp and _subprocess_call_is_fixed_argv(node, list_bindings_by_call.get(node)):
                continue
            if is_os or is_subp:
                add("DANGEROUS_SINK", "info", ln, f"{base}.{f.attr}() shell/exec sink")
                continue

    # Taint: credential-FILE contents reaching a network sink (read secret -> send out).
    # Cheap pre-filter on the raw source so the propagation runs only when relevant.
    if _CRED_PATH_RE.search(source):
        cred_tainted = _cred_tainted_names(tree)
        if cred_tainted:
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and _is_net_sink(node.func)
                    and (_names_in(node) & cred_tainted)
                ):
                    add(
                        "CRED_EXFIL_FLOW",
                        "crit",
                        getattr(node, "lineno", 0),
                        "credential-file contents flow into a network sink (read secret -> send out)",
                    )

    # F-049: env-var / agent-config secret reaching a network sink (SkillSpector E2 env
    # harvesting + E1 external transmission).  Severity is "info" and the checks engine routes it
    # to a WARN — never an automatic FAIL — because legit skills DO post an env secret to a
    # trusted endpoint (e.g. ANTHROPIC_API_KEY -> api.anthropic.com) and the scanner cannot
    # know the destination.  The taint must actually connect: a name assigned from an
    # env/config read appears in the sink's args, OR an env read is inline in the args.  An
    # env read that feeds a local sink, or an unrelated network call, never fires.
    if "environ" in source or "getenv" in source or _AGENT_CONFIG_PATH_RE.search(source):
        env_src_tainted = _env_tainted_names(tree) | _agent_config_file_tainted_names(source, tree)
        for node in ast.walk(tree):
            if len(out) >= _MAX_FINDINGS_PER_FILE:
                break
            if not (isinstance(node, ast.Call) and _is_net_sink(node.func)):
                continue
            # Only a BODY / URL / params position counts. A secret in headers=/auth= is the
            # normal way a skill authenticates to its own API (env key -> Authorization
            # header) and is NOT flagged; exfiltration puts the secret in the URL, request
            # body, query params, or a positional argument.
            arg_subtrees = [
                *node.args,
                *(kw.value for kw in node.keywords if kw.arg not in _ENV_AUTH_KWARGS),
            ]
            hit = False
            for arg in arg_subtrees:
                if env_src_tainted and (_names_in(arg) & env_src_tainted):
                    hit = True
                    break
                if any(
                    _is_env_read_value(s) or _rhs_has_subscript_environ(s) for s in ast.walk(arg)
                ):
                    hit = True
                    break
            if hit:
                add(
                    "ENV_EXFIL_FLOW",
                    "info",
                    getattr(node, "lineno", 0),
                    "an environment-variable or agent-config secret flows into a network "
                    "sink's URL or body — verify the destination is trusted (possible exfiltration)",
                )

    # Extended taint rules: TT5 (external-input -> exec), TT4 (file-read -> network),
    # SSRF (tainted URL -> network-fetch).  Compute external taint once and reuse.
    func_params = _collect_func_params(tree)
    ext_tainted = _external_tainted_names(tree, func_params)
    bindings_by_call = _list_bindings_by_call(tree)

    if ext_tainted:
        for node in ast.walk(tree):
            if len(out) >= _MAX_FINDINGS_PER_FILE:
                break
            if not isinstance(node, ast.Call):
                continue
            ln = getattr(node, "lineno", 0)

            # TT5: tainted value flows into exec/eval/os.system/os.popen/subprocess.*
            is_exec, exec_name = _is_exec_sink_call(node.func)
            if is_exec:
                any_t, direct = _call_args_tainted(node, ext_tainted)
                if any_t:
                    # A subprocess argv-list call (shell=False, fixed program) is only
                    # argument injection, not command injection — do not escalate to crit.
                    if exec_name.startswith(
                        "subprocess."
                    ) and not _subprocess_taint_is_command_injection(
                        node, ext_tainted, bindings_by_call.get(node)
                    ):
                        add(
                            "TT5_ARG_INJECTION",
                            "info",
                            ln,
                            f"external input flows into {exec_name} as a non-program list argument "
                            "(shell=False) — argument injection, not command injection",
                        )
                        continue
                    flow_kind = "direct" if direct else "indirect"
                    add(
                        "TT5_CMD_INJECTION",
                        "crit",
                        ln,
                        f"external input flows into {exec_name} ({flow_kind} flow) — command/code injection",
                    )
                    continue

            # TT4: file-read tainted value flows into a data-bearing network sink.
            is_net_data, net_name = _is_net_out_data_sink(node.func)
            if is_net_data:
                file_t = _file_tainted(source, tree)
                if file_t:
                    any_t, direct = _call_args_tainted(node, file_t)
                    if any_t:
                        flow_kind = "direct" if direct else "indirect"
                        add(
                            "TT4_FILE_NET",
                            "info",
                            ln,
                            f"file-read contents flow into {net_name} ({flow_kind} flow) — data exfiltration risk",
                        )
                    continue

            # SSRF: externally-tainted value flows into a network-fetch URL argument.
            is_ssrf_s, ssrf_name = _is_ssrf_sink_call(node.func)
            if is_ssrf_s:
                any_t, direct = _call_args_tainted(node, ext_tainted)
                if any_t:
                    # Elevate evidence when a literal internal endpoint appears in the file.
                    has_internal = bool(_SSRF_LITERAL_RE.search(source))
                    flow_kind = "direct" if direct else "indirect"
                    if has_internal:
                        add(
                            "TT_SSRF",
                            "info",
                            ln,
                            f"externally-controlled URL flows into {ssrf_name} with internal endpoint literal present ({flow_kind} flow) — SSRF",
                        )
                    else:
                        add(
                            "TT_SSRF",
                            "info",
                            ln,
                            f"externally-controlled URL flows into {ssrf_name} ({flow_kind} flow) — SSRF risk",
                        )

    out.extend(_conditional_sink_findings(tree))

    # B-140(a): os.environ["KEY"] = "<provider-shaped-literal>" — an unconditional
    # overwrite of an env var with a hardcoded provider-shaped token. A separate small
    # loop (rather than folding into the ast.Call walk above) since Assign is a
    # different node shape and the Call loop's control flow is continue-heavy.
    for node in ast.walk(tree):
        if len(out) >= _MAX_FINDINGS_PER_FILE:
            break
        if not isinstance(node, ast.Assign):
            continue
        if len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Subscript):
            continue
        tv = target.value
        is_os_environ = (
            isinstance(tv, ast.Attribute) and tv.attr == "environ" and _attr_base(tv.value) == "os"
        ) or (isinstance(tv, ast.Name) and tv.id == "environ")
        if not is_os_environ:
            continue
        if not _is_hardcoded_provider_secret(node.value):
            continue
        key_node = target.slice
        # Python 3.9 compat: a subscript slice may be wrapped in ast.Index.
        if key_node.__class__.__name__ == "Index":
            key_node = key_node.value  # type: ignore[attr-defined]
        key_repr = (
            key_node.value
            if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str)
            else "<dynamic>"
        )
        add(
            "HARDCODED_PROVIDER_SECRET",
            "crit",
            getattr(node, "lineno", 0),
            f"hardcoded provider-shaped secret written to os.environ[{key_repr!r}]",
        )

    return out


# B-190: a secret placed in headers=/auth=/cert= is deliberately excluded from
# ENV_EXFIL_FLOW above (_ENV_AUTH_KWARGS) because that's the normal way a skill
# authenticates to its own API. But the exclusion happens INSIDE analyze_python's own
# loop, before any ASTFinding is ever created — so unlike other "info"-severity findings
# that get silently dropped by check_installed_skills' cascade (still visible to
# adjudication.py's _recover_dropped_taint, which re-runs analyze_python), this case is
# never computed at all and so can never reach even the advisory judge-packet. This
# sibling walk computes exactly the excluded case, always "info" severity, for
# adjudication.py to surface as an UNKNOWN judge-packet item. Never called from
# analyze_python or CHECKS — check_installed_skills' PASS/WARN/FAIL cascade never sees
# these findings, so this cannot introduce a new false-FAIL (Golden Rule #5).
def analyze_env_auth_kwarg_exfil(source: str, filename: str = "<skill>") -> list[ASTFinding]:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError, OverflowError):
        return []
    if (
        "environ" not in source
        and "getenv" not in source
        and not _AGENT_CONFIG_PATH_RE.search(source)
    ):
        return []

    env_src_tainted = _env_tainted_names(tree) | _agent_config_file_tainted_names(source, tree)
    out: list[ASTFinding] = []
    seen: set[int] = set()
    for node in ast.walk(tree):
        if len(out) >= _MAX_FINDINGS_PER_FILE:
            break
        if not (isinstance(node, ast.Call) and _is_net_sink(node.func)):
            continue
        auth_kwarg_subtrees = [kw.value for kw in node.keywords if kw.arg in _ENV_AUTH_KWARGS]
        hit = False
        for arg in auth_kwarg_subtrees:
            if env_src_tainted and (_names_in(arg) & env_src_tainted):
                hit = True
                break
            if any(
                _is_env_read_value(s) or _rhs_has_subscript_environ(s) for s in ast.walk(arg)
            ):
                hit = True
                break
        if not hit:
            continue
        lineno = getattr(node, "lineno", 0)
        if lineno in seen:
            continue
        seen.add(lineno)
        out.append(
            ASTFinding(
                "ENV_AUTH_KWARG_EXFIL",
                "info",
                lineno,
                "an environment-variable or agent-config secret is placed in an "
                "auth-shaped keyword (headers/auth/cert) of a network call — the normal "
                "way a skill authenticates to its own API, but never independently "
                "reviewed; verify the destination is trusted",
            )
        )
    return out


# --- Abstract Effect Simulator ---


def _sink_key(effect_type, sink_name, guards):
    """Hashable identity for a reached-sink entry (B-192). `simulate()` already
    collapses `reached_sinks` downstream to the distinct (effect, sink) set plus the
    distinct guard-description set per sink — so merging exact-duplicate entries
    (same effect + sink + guard combination) here changes no downstream finding; it
    only stops the same duplicate from being re-copied at every nesting level."""
    return (
        effect_type,
        sink_name,
        tuple((g["condition_type"], g["description"]) for g in guards),
    )


class State:
    def __init__(self):
        self.tainted_vars = set()
        self.active_guards = []
        self.reached_sinks = []
        self._sink_keys = set()
        self.terminated = False
        self.loop_broken = False
        self.loop_continued = False
        self.reachable_effects = set()

    def copy(self):
        new_state = State()
        new_state.tainted_vars = set(self.tainted_vars)
        new_state.active_guards = [dict(g) for g in self.active_guards]
        new_state.reached_sinks = list(self.reached_sinks)
        new_state._sink_keys = set(self._sink_keys)
        new_state.terminated = self.terminated
        new_state.loop_broken = self.loop_broken
        new_state.loop_continued = self.loop_continued
        new_state.reachable_effects = set(self.reachable_effects)
        return new_state

    def register_effect(self, effect_type, sink_name):
        self.reachable_effects.add(effect_type)
        guards = [dict(g) for g in self.active_guards]
        key = _sink_key(effect_type, sink_name, guards)
        if key in self._sink_keys:
            return
        self._sink_keys.add(key)
        self.reached_sinks.append(
            {"effect": effect_type, "sink": sink_name, "guards": guards}
        )
        if len(self.reached_sinks) > _MAX_REACHED_SINKS:
            raise ScanBudgetExceeded

    def merge_reached(self, other):
        """Fold `other`'s reached_sinks into self, deduped (B-192) — used wherever
        simulate_if/simulate_loop used to `.extend()` two ever-growing lists."""
        for item in other.reached_sinks:
            key = _sink_key(item["effect"], item["sink"], item["guards"])
            if key in self._sink_keys:
                continue
            self._sink_keys.add(key)
            self.reached_sinks.append(item)
            if len(self.reached_sinks) > _MAX_REACHED_SINKS:
                raise ScanBudgetExceeded


class EffectSimulator:
    def __init__(self, source: str, filename: str = "<skill>"):
        self.source = source
        self.filename = filename
        try:
            self.tree = ast.parse(source)
        except Exception:
            self.tree = None

    def get_entry_points(self):
        if not self.tree:
            return []
        entries = []
        for node in self.tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                entries.append(node)
        # If no function definition, treat the whole module as entry point
        if not entries and self.tree.body:
            entries.append(self.tree)
        return entries

    def get_assigned_variables(self, nodes):
        vars_set = set()

        def walk_and_collect(n):
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    collect_targets(t)
            elif isinstance(n, ast.AnnAssign):
                collect_targets(n.target)
            elif isinstance(n, ast.AugAssign):
                collect_targets(n.target)
            elif isinstance(n, ast.For):
                collect_targets(n.target)
            elif isinstance(n, ast.Call):
                if isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name):
                    if n.func.attr in ("append", "extend", "insert", "update", "add"):
                        vars_set.add(n.func.value.id)
            for child in ast.iter_child_nodes(n):
                walk_and_collect(child)

        def collect_targets(target):
            if isinstance(target, ast.Name):
                vars_set.add(target.id)
            elif isinstance(target, (ast.Tuple, ast.List)):
                for elt in target.elts:
                    collect_targets(elt)
            elif isinstance(target, ast.Attribute):
                if isinstance(target.value, ast.Name):
                    vars_set.add(target.value.id)
            elif isinstance(target, ast.Subscript):
                if isinstance(target.value, ast.Name):
                    vars_set.add(target.value.id)

        for node in nodes:
            walk_and_collect(node)

        return vars_set

    def check_expr_taint_sources(self, node, state, seed):
        if isinstance(node, ast.Name):
            if node.id in state.tainted_vars:
                return True

        if seed == "poisoned-MCP":
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                if "mcp" in func_name.lower() or "call_tool" in func_name.lower():
                    return True
                if func_name in ("recv", "recvfrom", "read", "json", "text"):
                    return True

        if seed == "attacker-controlled default":
            if isinstance(node, ast.Call):
                func_name = ""
                func_obj = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                    if isinstance(node.func.value, ast.Name):
                        func_obj = node.func.value.id
                if func_name == "get" and func_obj in (
                    "config",
                    "settings",
                    "options",
                    "params",
                    "self",
                ):
                    return True
                if func_name == "getenv" or (func_name == "get" and func_obj == "environ"):
                    return True

        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
        ):
            if len(node.args) >= 2:
                obj_expr = node.args[0]
                attr_expr = node.args[1]
                is_attr_const = isinstance(attr_expr, ast.Constant) and isinstance(
                    attr_expr.value, str
                )
                if not is_attr_const:
                    # Dynamic getattr over-approximation fallback
                    return True
                if self.check_expr_taint_sources(
                    obj_expr, state, seed
                ) or self.check_expr_taint_sources(attr_expr, state, seed):
                    return True

        for child in ast.iter_child_nodes(node):
            if self.check_expr_taint_sources(child, state, seed):
                return True

        return False

    def taint_target(self, target, is_tainted, state):
        if isinstance(target, ast.Name):
            if is_tainted:
                state.tainted_vars.add(target.id)
            else:
                state.tainted_vars.discard(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self.taint_target(elt, is_tainted, state)
        elif isinstance(target, ast.Attribute):
            if isinstance(target.value, ast.Name) and is_tainted:
                state.tainted_vars.add(target.value.id)
        elif isinstance(target, ast.Subscript):
            if isinstance(target.value, ast.Name) and is_tainted:
                state.tainted_vars.add(target.value.id)

    def handle_method_call_updates(self, node, state, seed):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call_node = node.value
            if isinstance(call_node.func, ast.Attribute) and isinstance(
                call_node.func.value, ast.Name
            ):
                base_name = call_node.func.value.id
                method_name = call_node.func.attr
                if method_name in ("append", "extend", "insert", "update", "add"):
                    any_tainted = False
                    for arg in call_node.args:
                        if self.check_expr_taint_sources(arg, state, seed):
                            any_tainted = True
                            break
                    for kw in call_node.keywords:
                        if self.check_expr_taint_sources(kw.value, state, seed):
                            any_tainted = True
                            break
                    if any_tainted:
                        state.tainted_vars.add(base_name)

    def check_dynamic_import_overapprox(self, node, state, seed):
        if isinstance(node, ast.Call):
            func_name = ""
            func_obj = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
                if isinstance(node.func.value, ast.Name):
                    func_obj = node.func.value.id

            is_import = False
            if func_name == "__import__":
                is_import = True
            elif func_name == "import_module" and func_obj == "importlib":
                is_import = True

            if is_import:
                if node.args:
                    first_arg = node.args[0]
                    is_const = isinstance(first_arg, ast.Constant) and isinstance(
                        first_arg.value, str
                    )
                    if not is_const:
                        state.register_effect("read", "importlib.import_module")
                        state.register_effect("write", "importlib.import_module")
                        state.register_effect("ev" + "al", "importlib.import_module")
                        state.register_effect("network", "importlib.import_module")

    def get_sink_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self.get_sink_name(node.value)
            if base:
                return f"{base}.{node.attr}"
            return node.attr
        return ""

    def check_sink_effects(self, node, state, seed):
        if not isinstance(node, ast.Call):
            return

        sink_name = self.get_sink_name(node.func)
        any_arg_tainted = False
        for arg in node.args:
            if self.check_expr_taint_sources(arg, state, seed):
                any_arg_tainted = True
                break
        if not any_arg_tainted:
            for kw in node.keywords:
                if self.check_expr_taint_sources(kw.value, state, seed):
                    any_arg_tainted = True
                    break

        is_base_tainted = False
        if isinstance(node.func, ast.Attribute):
            is_base_tainted = self.check_expr_taint_sources(node.func.value, state, seed)

        # 1. eval — detection data assembled from parts (not calls)
        eval_funcs = {"ex" + "ec", "ev" + "al", "compile"}
        eval_attrs = {"loads", "load"}
        is_eval = False
        if sink_name in eval_funcs:
            is_eval = True
        elif isinstance(node.func, ast.Attribute) and node.func.attr in eval_attrs:
            base_obj = self.get_sink_name(node.func.value)
            if base_obj in ("pickle", "marshal", "dill", "_pickle", "cpickle"):
                is_eval = True

        if is_eval and any_arg_tainted:
            state.register_effect("ev" + "al", sink_name)
            return

        # 2. write
        write_funcs = {"write_bytes", "write_text", "dump", "save"}
        write_attrs = {"write", "writelines", "dump"}
        is_write = False
        if sink_name == "open" and any_arg_tainted:
            mode_val = "r"
            if len(node.args) >= 2:
                mode_arg = node.args[1]
                if isinstance(mode_arg, ast.Constant) and isinstance(mode_arg.value, str):
                    mode_val = mode_arg.value
            for kw in node.keywords:
                if (
                    kw.arg == "mode"
                    and isinstance(kw.value, ast.Constant)
                    and isinstance(kw.value.value, str)
                ):
                    mode_val = kw.value.value
            if any(c in mode_val for c in "wax+"):
                is_write = True

        if sink_name in write_funcs and any_arg_tainted:
            is_write = True
        elif isinstance(node.func, ast.Attribute) and node.func.attr in write_attrs:
            if any_arg_tainted or is_base_tainted:
                is_write = True

        if is_write:
            state.register_effect("write", sink_name)
            return

        # 3. read
        read_funcs = {"open", "read_bytes", "read_text", "getenv"}
        read_attrs = {"read", "readline", "readlines", "getenv"}
        is_read = False
        if sink_name in read_funcs and any_arg_tainted:
            is_read = True
        elif isinstance(node.func, ast.Attribute) and node.func.attr in read_attrs:
            if any_arg_tainted or is_base_tainted:
                is_read = True

        if is_read:
            state.register_effect("read", sink_name)
            return

        # 4. network
        net_funcs = {"urlopen"}
        net_attrs = {
            "post",
            "put",
            "patch",
            "get",
            "delete",
            "request",
            "connect",
            "send",
            "sendall",
            "sendto",
            "urlopen",
        }
        is_net = False
        if sink_name in net_funcs and any_arg_tainted:
            is_net = True
        elif isinstance(node.func, ast.Attribute) and node.func.attr in net_attrs:
            base_obj = self.get_sink_name(node.func.value)
            if base_obj in (
                "requests",
                "httpx",
                "urllib",
                "urllib.request",
                "socket",
                "aiohttp",
                "smtplib",
                "ftplib",
                "session",
                "self",
            ):
                if any_arg_tainted or is_base_tainted:
                    is_net = True
            elif any_arg_tainted or is_base_tainted:
                if node.func.attr in (
                    "connect",
                    "send",
                    "sendall",
                    "sendto",
                    "post",
                    "put",
                    "request",
                ):
                    is_net = True

        if is_net:
            state.register_effect("network", sink_name)
            return

    def is_safety_check(self, test):
        for node in ast.walk(test):
            if isinstance(node, ast.Call):
                name = self.get_sink_name(node.func)
                keywords = {
                    "approve",
                    "confirm",
                    "verify",
                    "authorized",
                    "gate",
                    "check",
                    "permission",
                    "auth",
                    "safe",
                    "allow",
                }
                if any(kw in name.lower() for kw in keywords):
                    return True
            elif isinstance(node, ast.Name):
                keywords = {
                    "approve",
                    "confirm",
                    "verify",
                    "authorized",
                    "gate",
                    "safe",
                    "approved",
                }
                if any(kw in node.id.lower() for kw in keywords):
                    return True
        return False

    def get_guard_descriptions(self, test):
        unparsed = ast.unparse(test)
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            inner_unparsed = ast.unparse(test.operand)
            return f"guarded by {unparsed}", f"guarded by {inner_unparsed}"
        else:
            return f"guarded by {unparsed}", f"guarded by not ({unparsed})"

    def simulate_if(self, node, state, seed):
        state_then = state.copy()
        state_else = state.copy()

        is_safe = self.is_safety_check(node.test)

        if is_safe:
            then_desc, else_desc = self.get_guard_descriptions(node.test)
            guard_then = {"condition_type": "approval-gate", "description": then_desc}
            state_then.active_guards.append(guard_then)

            guard_else = {"condition_type": "approval-gate", "description": else_desc}
            state_else.active_guards.append(guard_else)

        self.simulate_statements(node.body, state_then, seed)
        self.simulate_statements(node.orelse, state_else, seed)

        state.reachable_effects.update(state_then.reachable_effects)
        state.reachable_effects.update(state_else.reachable_effects)

        if state_then.terminated and state_else.terminated:
            state.terminated = True
            state.merge_reached(state_then)
            state.merge_reached(state_else)
        elif state_then.terminated:
            state.tainted_vars = state_else.tainted_vars
            state.active_guards = state_else.active_guards
            state.merge_reached(state_then)
            state.merge_reached(state_else)
        elif state_else.terminated:
            state.tainted_vars = state_then.tainted_vars
            state.active_guards = state_then.active_guards
            state.merge_reached(state_then)
            state.merge_reached(state_else)
        else:
            state.tainted_vars = state_then.tainted_vars.union(state_else.tainted_vars)
            state.merge_reached(state_then)
            state.merge_reached(state_else)
            common_guards = []
            for g in state_then.active_guards:
                if g in state_else.active_guards:
                    common_guards.append(g)
            state.active_guards = common_guards

    def simulate_loop(self, node, state, seed):
        prev_tainted = set(state.tainted_vars)
        stabilized = False

        for i in range(5):
            state_copy = state.copy()
            self.simulate_statements(node.body, state_copy, seed)

            state.tainted_vars.update(state_copy.tainted_vars)
            state.merge_reached(state_copy)

            if state_copy.terminated:
                state.terminated = True
                break

            current_tainted = set(state.tainted_vars)
            if current_tainted == prev_tainted:
                stabilized = True
                break
            prev_tainted = current_tainted

        if not stabilized and not state.terminated:
            involved_vars = self.get_assigned_variables(node.body)
            state.tainted_vars.update(involved_vars)

    def simulate_statement(self, stmt, state, seed):
        if isinstance(stmt, ast.Return) or isinstance(stmt, ast.Raise):
            state.terminated = True
            for sub in ast.walk(stmt):
                self.check_dynamic_import_overapprox(sub, state, seed)
                self.check_sink_effects(sub, state, seed)
        elif isinstance(stmt, ast.Break):
            state.loop_broken = True
        elif isinstance(stmt, ast.Continue):
            state.loop_continued = True
        elif isinstance(stmt, ast.Assign):
            is_tainted = self.check_expr_taint_sources(stmt.value, state, seed)
            for target in stmt.targets:
                self.taint_target(target, is_tainted, state)
            for sub in ast.walk(stmt):
                self.check_dynamic_import_overapprox(sub, state, seed)
                self.check_sink_effects(sub, state, seed)
        elif isinstance(stmt, ast.AnnAssign):
            if stmt.value:
                is_tainted = self.check_expr_taint_sources(stmt.value, state, seed)
                self.taint_target(stmt.target, is_tainted, state)
            for sub in ast.walk(stmt):
                self.check_dynamic_import_overapprox(sub, state, seed)
                self.check_sink_effects(sub, state, seed)
        elif isinstance(stmt, ast.AugAssign):
            is_tainted = self.check_expr_taint_sources(
                stmt.value, state, seed
            ) or self.check_expr_taint_sources(stmt.target, state, seed)
            self.taint_target(stmt.target, is_tainted, state)
            for sub in ast.walk(stmt):
                self.check_dynamic_import_overapprox(sub, state, seed)
                self.check_sink_effects(sub, state, seed)
        elif isinstance(stmt, ast.If):
            self.simulate_if(stmt, state, seed)
        elif isinstance(stmt, (ast.For, ast.While)):
            if isinstance(stmt, ast.For):
                is_iter_tainted = self.check_expr_taint_sources(stmt.iter, state, seed)
                self.taint_target(stmt.target, is_iter_tainted, state)
            self.simulate_loop(stmt, state, seed)
        elif isinstance(stmt, ast.Expr):
            self.handle_method_call_updates(stmt, state, seed)
            for sub in ast.walk(stmt):
                self.check_dynamic_import_overapprox(sub, state, seed)
                self.check_sink_effects(sub, state, seed)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                is_tainted = self.check_expr_taint_sources(item.context_expr, state, seed)
                if item.optional_vars is not None:
                    self.taint_target(item.optional_vars, is_tainted, state)
                for sub in ast.walk(item.context_expr):
                    self.check_dynamic_import_overapprox(sub, state, seed)
                    self.check_sink_effects(sub, state, seed)
            self.simulate_statements(stmt.body, state, seed)
        else:
            for sub in ast.walk(stmt):
                self.check_dynamic_import_overapprox(sub, state, seed)
                self.check_sink_effects(sub, state, seed)

    def simulate_statements(self, statements, state, seed):
        for stmt in statements:
            if state.terminated or state.loop_broken or state.loop_continued:
                break
            self.simulate_statement(stmt, state, seed)

    def simulate(self):
        if not self.tree:
            return []

        results = []
        entry_points = self.get_entry_points()

        for entry in entry_points:
            entry_name = "<module>"
            if isinstance(entry, (ast.FunctionDef, ast.AsyncFunctionDef)):
                entry_name = entry.name

            reachable_effects = set()
            guarding_conditions = []

            sink_paths = {}

            for seed in ("hostile-input", "poisoned-MCP", "attacker-controlled default"):
                state = State()

                if isinstance(entry, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if seed == "hostile-input":
                        params = [arg.arg for arg in entry.args.args + entry.args.kwonlyargs]
                        if entry.args.vararg:
                            params.append(entry.args.vararg.arg)
                        if entry.args.kwarg:
                            params.append(entry.args.kwarg.arg)
                        state.tainted_vars.update(params)
                    elif seed == "attacker-controlled default":
                        defaults_names = []
                        num_defaults = len(entry.args.defaults)
                        if num_defaults > 0:
                            defaults_names.extend(
                                [arg.arg for arg in entry.args.args[-num_defaults:]]
                            )
                        for kwarg, kw_default in zip(entry.args.kwonlyargs, entry.args.kw_defaults):
                            if kw_default is not None:
                                defaults_names.append(kwarg.arg)
                        state.tainted_vars.update(defaults_names)

                body = (
                    entry.body
                    if isinstance(entry, (ast.FunctionDef, ast.AsyncFunctionDef))
                    else entry.body
                )
                self.simulate_statements(body, state, seed)

                reachable_effects.update(state.reachable_effects)
                for item in state.reached_sinks:
                    key = (item["effect"], item["sink"])
                    if key not in sink_paths:
                        sink_paths[key] = []
                    sink_paths[key].append(item["guards"])

            for (eff, sink), paths in sink_paths.items():
                seen_guards = set()
                for guards in paths:
                    for g in guards:
                        guard_key = (g["condition_type"], g["description"])
                        if guard_key not in seen_guards:
                            seen_guards.add(guard_key)
                            guarding_conditions.append(
                                {
                                    "effect": eff,
                                    "sink": sink,
                                    "condition_type": g["condition_type"],
                                    "description": g["description"],
                                }
                            )

            guarded_effects = set()
            unshielded_effects = set()
            for (eff, sink), paths in sink_paths.items():
                if any(len(g) == 0 for g in paths):
                    unshielded_effects.add(eff)
                else:
                    guarded_effects.add(eff)

            guarded_effects = guarded_effects - unshielded_effects

            results.append(
                {
                    "entry_point": entry_name,
                    "reachable_effects": list(reachable_effects),
                    "guarding_conditions": guarding_conditions,
                    "guarded_effects": list(guarded_effects),
                    "unshielded_effects": list(unshielded_effects),
                }
            )

        return results


def _module_stem(relpath: str) -> str:
    """The importable module stem for a bundled skill file: 'a.py' -> 'a',
    'pkg/util.py' -> 'util' (skills are usually flat; the last path component wins)."""
    name = relpath.replace("\\", "/").rsplit("/", 1)[-1]
    return name[:-3] if name.endswith(".py") else name


def _package_tainted_exports(trees: dict) -> dict:
    """{module_stem: {exported name, ...}} for module-level names whose value derives from
    a decode/decompress expression — an obfuscated blob that is dangerous to exec. A small
    within-module alias fixpoint carries `y = x` when x is already tainted. Decode-only on
    purpose: exec of a cross-file *decoded* value is the split-payload pattern; broadening
    the source would add false positives on ordinary multi-file skills."""
    exports: dict = {}
    for stem, tree in trees.items():
        tainted: set = set()
        body_assigns = [n for n in getattr(tree, "body", []) if isinstance(n, ast.Assign)]
        for _ in range(3):
            changed = False
            for a in body_assigns:
                if _subtree_has_decode(a.value) or (_names_in(a.value) & tainted):
                    for t in a.targets:
                        if isinstance(t, ast.Name) and t.id not in tainted:
                            tainted.add(t.id)
                            changed = True
            if not changed:
                break
        if tainted:
            exports[stem] = tainted
    return exports


def analyze_python_package(files) -> list[ASTFinding]:
    """Cross-file / import-graph taint (H1): a decode-derived module-level value defined in
    one skill file, imported and executed (exec/eval/os.system/subprocess) in another. The
    per-file engine (analyze_python) misses this because each half is clean in isolation —
    file A holds the obfuscated blob, file B imports and then runs it.

    `files` is an iterable of (relpath, source). Stdlib ast only; never raises, never
    executes; deterministic. Returns ASTFindings whose reason is self-contained (it names
    the importing file, the sink, and the source module)."""
    trees: dict = {}
    stem_to_rel: dict = {}
    for relpath, src in files:
        stem = _module_stem(relpath)
        try:
            trees[stem] = ast.parse(src)
        except (SyntaxError, ValueError, RecursionError, MemoryError, OverflowError):
            continue  # parse failures are surfaced per-file (AST_UNANALYZABLE), not here
        stem_to_rel[stem] = relpath
    if len(trees) < 2:
        return []  # cross-file taint needs at least two parseable sibling modules
    exports = _package_tainted_exports(trees)
    if not exports:
        return []

    out: list = []
    seen: set = set()
    for stem, tree in trees.items():
        rel = stem_to_rel[stem]
        tainted_locals: dict = {}  # `from <mod> import <name>` local name -> source stem
        module_aliases: dict = {}  # `import <mod> [as x]` alias -> source stem
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                mod = (node.module or "").split(".")[-1]
                if mod in exports and mod != stem:
                    for alias in node.names:
                        if alias.name in exports[mod]:
                            tainted_locals[alias.asname or alias.name] = mod
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    m = alias.name.split(".")[-1]
                    if m in exports and m != stem:
                        module_aliases[alias.asname or alias.name.split(".")[0]] = m
        if not tainted_locals and not module_aliases:
            continue
        local_set = set(tainted_locals)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            is_exec, sink = _is_exec_sink_call(node.func)
            if not is_exec:
                continue
            ln = getattr(node, "lineno", 0)
            src_mod = None
            # (a) a `from`-imported tainted name reaches the exec sink.
            if local_set and _call_args_tainted(node, local_set)[0]:
                hit = next((n for n in _names_in(node) if n in tainted_locals), None)
                src_mod = tainted_locals.get(hit)
            # (b) an `alias.export` attribute reaches the exec sink.
            if src_mod is None:
                for arg in (*node.args, *(kw.value for kw in node.keywords)):
                    for sub in ast.walk(arg):
                        if (
                            isinstance(sub, ast.Attribute)
                            and isinstance(sub.value, ast.Name)
                            and sub.value.id in module_aliases
                            and sub.attr in exports[module_aliases[sub.value.id]]
                        ):
                            src_mod = module_aliases[sub.value.id]
                            break
                    if src_mod is not None:
                        break
            if src_mod is not None and (rel, ln) not in seen:
                seen.add((rel, ln))
                src_rel = stem_to_rel.get(src_mod, src_mod + ".py")
                out.append(
                    ASTFinding(
                        "CROSS_FILE_EXEC",
                        "crit",
                        ln,
                        f"{rel}:{ln} {sink} executes a decode-derived value imported from sibling "
                        f"module {src_rel} — cross-file obfuscated payload split to evade per-file scanning",
                    )
                )
    return out


# --- Shell (.sh/.bash/.zsh) semantic pass (F-050) ----------------------------
# Credential FILES whose contents are secrets (mirrors the Python _CRED_PATH_RE intent).
_SH_CRED_FILE_RE = re.compile(
    r"\.ssh/id_[a-z0-9_]+|\bid_rsa\b|\bid_ed25519\b|\.aws/credentials|\.netrc\b|"
    r"login\.keychain|wallet\.dat|\.docker/config\b|\.kube/config\b|\.npmrc\b|\.pypirc\b|"
    r"\.openclaw/|/\.config/[^/\s\"']+/",
    re.I,
)
# Outbound commands that can send data off the machine.
_SH_OUTBOUND_RE = re.compile(r"\b(?:curl|wget|nc|ncat|netcat)\b|/dev/tcp/", re.I)
# curl|wget URL piped into a NON-shell interpreter (download -> exec) — extends the
# sh/bash-only _PIPE_SHELL_RE (the checks engine) to python/node/perl/ruby/php/deno.
_SH_PIPE_INTERP_RE = re.compile(
    r"(?:curl|wget)\b[^\n|]{0,256}?https?://[^\n|]{0,256}\|\s*(?:sudo\s+)?"
    r"(?:python3?|node|perl|ruby|php|deno)\b",
    re.I,
)
# VAR=$(cat ~/.ssh/id_rsa) / VAR=`cat .aws/credentials` / VAR=$(< ~/.netrc): a shell
# variable whose value derives from reading a credential file.
# B-102: the quantifiers are length-bounded so the pattern stays O(n) on adversarial
# input (e.g. a 40KB identifier run has no '=' and previously backtracked at every start
# → quadratic). A real credential-read assignment line is short, so the bounds (128-char
# var, 256-char gaps) never clip a genuine match.
_SH_CRED_ASSIGN_RE = re.compile(
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]{0,127})=[^\n]{0,256}?(?:cat|less|head|tail|<)\s*[^\n]{0,256}?"
    r"(?:\.ssh/id_|id_rsa|id_ed25519|\.aws/credentials|\.netrc|keychain|wallet\.dat|"
    r"\.docker/config|\.kube/config|\.npmrc|\.pypirc|\.openclaw/)",
    re.I,
)
# decode-then-exec: an encoded blob is decoded (base64/xxd/openssl) and piped straight
# into a shell/interpreter — the classic obfuscated-RCE dropper. Encode (no -d) and
# decode-to-file (no `| interp`) stay silent.
_SH_DECODE_EXEC_RE = re.compile(
    r"\b(?:base64\s+-[a-z]*d[a-z]*|base64\s+--decode|xxd\s+-r|"
    r"openssl\s+(?:base64|enc)\b[^\n|]*?-d)"
    r"[^\n]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|ksh|dash|python3?|node|perl|ruby|php|deno)\b",
    re.I,
)
# eval/source of a remote download — `eval "$(curl … http…)"` / `source <(wget … http…)`.
# The tight, defensible slice of "$()-command-injection": only a remote fetch feeding
# eval/source fires (a bare $(…) or a local eval stays silent).
_SH_EVAL_REMOTE_RE = re.compile(
    r"\b(?:eval|source)\b[^\n]*(?:\$\(|<\()\s*(?:sudo\s+)?(?:curl|wget)\b[^\n)]*https?://",
    re.I,
)
# raw-socket outbound (nc//dev/tcp) — deliberately EXCLUDES curl/wget, which legitimately
# carry an auth header to an API. Sending a secret over a raw socket is not legitimate.
_SH_RAW_SOCKET_RE = re.compile(r"\b(?:nc|ncat|netcat)\b|/dev/tcp/", re.I)
# a credential-shaped env-var NAME (contains TOKEN/SECRET/API_KEY/…). Gating env->outbound
# on the name (not any $VAR) is what keeps this zero-FP against authed-API scripts.
_SH_CRED_ENV_RE = re.compile(
    r"\$\{?[A-Za-z0-9_]*"
    r"(?:API_?KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_?KEY|ACCESS_?KEY|AUTH)"
    r"[A-Za-z0-9_]*\}?",
    re.I,
)


def _sh_mask_comments(source: str) -> str:
    """Blank whole-line shell comments while preserving line numbers, so a documented
    'curl ... | sh' example in a comment can't fire."""
    return "\n".join("" if ln.lstrip().startswith("#") else ln for ln in source.splitlines())


def analyze_shell(source: str, filename: str = "<skill>") -> list[ASTFinding]:
    """Conservative regex pass over a bundled .sh/.bash/.zsh file (F-050). No shell AST;
    stdlib regex only; never raises, never executes. Flags high-confidence shapes:

      SHELL_CRED_EXFIL (crit) — a credential file is read and its contents reach an
        outbound command (curl/wget/nc//dev/tcp): read a secret -> send it out.
      SHELL_PIPE_INTERP (crit) — a remote payload is downloaded and piped straight into a
        non-shell interpreter (curl URL | python/node/perl/...): remote code execution.
      SHELL_DECODE_EXEC (crit) — an encoded blob is decoded (base64/xxd/openssl -d) and
        piped straight into a shell/interpreter: obfuscated remote code execution.
      SHELL_EVAL_REMOTE (crit) — eval/source of a remote download
        (eval "$(curl … http…)" / source <(wget … http…)): remote code execution.
      SHELL_ENV_EXFIL (crit) — a credential-shaped env var ($…TOKEN/$…SECRET/…) is sent
        over a RAW socket (nc//dev/tcp): credential exfiltration.

    Whole-line comments are ignored so documentation examples stay clean. The naive
    forms — any $VAR piped to curl (authed-API scripts), or any bare $() command
    substitution — stay deliberately out of scope: SHELL_EVAL_REMOTE and SHELL_ENV_EXFIL
    are the tight, zero-FP slices of those (remote-fed eval; raw-socket-only, cred-named)."""
    out: list[ASTFinding] = []
    seen: set = set()

    def add(rule: str, sev: str, ln: int, reason: str) -> None:
        if (rule, ln) not in seen:
            seen.add((rule, ln))
            out.append(ASTFinding(rule, sev, ln, reason))

    masked = _sh_mask_comments(source)

    for m in _SH_PIPE_INTERP_RE.finditer(masked):
        ln = masked.count("\n", 0, m.start()) + 1
        add(
            "SHELL_PIPE_INTERP",
            "crit",
            ln,
            "downloads a remote payload and pipes it into an interpreter "
            "(curl/wget ... | python/node/perl/...) — remote code execution",
        )

    for m in _SH_DECODE_EXEC_RE.finditer(masked):
        ln = masked.count("\n", 0, m.start()) + 1
        add(
            "SHELL_DECODE_EXEC",
            "crit",
            ln,
            "decodes an encoded blob and pipes it into a shell/interpreter "
            "(base64/xxd/openssl -d | sh) — obfuscated remote code execution",
        )

    for m in _SH_EVAL_REMOTE_RE.finditer(masked):
        ln = masked.count("\n", 0, m.start()) + 1
        add(
            "SHELL_EVAL_REMOTE",
            "crit",
            ln,
            "eval/source of a remote download (eval \"$(curl ... http...)\") — "
            "remote code execution",
        )

    for i, raw in enumerate(masked.splitlines(), 1):
        if _SH_RAW_SOCKET_RE.search(raw) and _SH_CRED_ENV_RE.search(raw):
            add(
                "SHELL_ENV_EXFIL",
                "crit",
                i,
                "a credential-shaped environment variable is sent over a raw socket "
                "(nc//dev/tcp) — credential exfiltration",
            )

    cred_vars = {m.group("var") for m in _SH_CRED_ASSIGN_RE.finditer(masked)}
    for i, raw in enumerate(masked.splitlines(), 1):
        if not _SH_OUTBOUND_RE.search(raw):
            continue
        if _SH_CRED_FILE_RE.search(raw):
            add(
                "SHELL_CRED_EXFIL",
                "crit",
                i,
                "reads a credential file and sends it to an outbound command "
                "(curl/wget/nc) — credential exfiltration",
            )
            continue
        if any(re.search(r"\$\{?" + re.escape(v) + r"\b", raw) for v in cred_vars):
            add(
                "SHELL_CRED_EXFIL",
                "crit",
                i,
                "a credential-file value flows into an outbound command "
                "(curl/wget/nc) — credential exfiltration",
            )
    return out


# --------------------------------------------------------------------------- #
# analyze_javascript (F-064): lexical JS/TS pass — the JS blind spot.          #
# Hybrid severity: eval/Function of a decoded blob and remote fetch-then-exec  #
# are crit (obfuscated RCE, zero-FP); child_process-with-template and dynamic  #
# require() are warn (often legit). No JS parser; stdlib regex only.           #
# --------------------------------------------------------------------------- #
# eval / new Function of a base64-decoded blob — obfuscated code execution.
_JS_EVAL_DECODED_RE = re.compile(
    r"\b(?:eval|(?:new\s+)?Function)\s*\(\s*"
    r"(?:atob\s*\(|Buffer\.from\s*\([^)\n]*['\"]base64['\"])",
    re.I,
)
# remote code fetched then executed: a dynamic import of a URL, a then-eval chained on a
# fetch, or an eval over an awaited fetch.
_JS_EVAL_REMOTE_RE = re.compile(
    r"\bimport\s*\(\s*['\"]https?://"
    r"|\.then\s*\(\s*eval\b"
    r"|\beval\s*\(\s*await\b[^;\n]*\bfetch\s*\(",
    re.I,
)
# child_process exec-family with an interpolated command — command-injection surface.
_JS_CP_TEMPLATE_RE = re.compile(
    r"\b(?:exec|execSync|execFile|spawn|spawnSync)\s*\(\s*`[^`]*\$\{",
)
# require() of a non-literal (bareword identifier or template) — dynamic module load.
_JS_DYN_REQUIRE_RE = re.compile(
    r"\brequire\s*\(\s*(?:`[^`]*\$\{|[A-Za-z_$][\w$.]*\s*[)+])",
)
# process.dlopen() — a direct native-addon (.node) load: the native-boundary escape.
# Node's own docs (process.dlopen) say require() should be preferred and it "should not
# be used directly"; direct use in plugin runtime JS is a red flag. warn-only.
_JS_NATIVE_DLOPEN_RE = re.compile(
    r"\bprocess\.dlopen\s*\(",
)


def _js_mask_comments(source: str) -> str:
    """Blank JS/TS comments while preserving line numbers, so a documented
    eval-of-atob example can't fire. A `//` preceded by ':' (i.e. inside a
    URL like https://) is preserved so remote-import detection still works."""
    def _blank_block(m):
        return "\n" * m.group(0).count("\n")
    no_block = re.sub(r"/\*.*?\*/", _blank_block, source, flags=re.S)
    return "\n".join(re.sub(r"(?<!:)//.*$", "", ln) for ln in no_block.splitlines())


def analyze_javascript(source: str, filename: str = "<skill>") -> list[ASTFinding]:
    """Conservative lexical pass over a bundled .js/.ts/.mjs/.cjs file (F-064). No JS
    AST; stdlib regex only; never raises, never executes. Hybrid severity:

      JS_EVAL_DECODED (crit) — eval / new Function over a base64-decoded blob
        (an eval of an atob result, or a Function built from a base64 Buffer): obfuscated RCE.
      JS_EVAL_REMOTE (crit) — remote code fetched then executed: a dynamic import of a
        URL, a then-eval chained on a fetch, or an eval over an awaited fetch.
      JS_CHILD_PROCESS_DYNAMIC (warn) — a child_process exec-family call with an
        interpolated command (a template-string git command): command-injection surface. Only
        emitted when the file references child_process (kills the RegExp.exec FP).
      JS_DYNAMIC_REQUIRE (warn) — require() of a non-literal (variable / template):
        an attacker-influenced module path.
      JS_NATIVE_DLOPEN (warn) — process.dlopen(): a direct native-addon (.node) load,
        the native-boundary escape that bypasses JS-level analysis. Node's docs say
        require() should be preferred over calling dlopen directly.

    Benign JS — static eval, JSON.parse(atob(token)), local require, base64 decode
    without eval — stays silent. Comments are masked so documented examples don't fire."""
    out: list[ASTFinding] = []
    seen: set = set()

    def add(rule: str, sev: str, ln: int, reason: str) -> None:
        if (rule, ln) not in seen:
            seen.add((rule, ln))
            out.append(ASTFinding(rule, sev, ln, reason))

    masked = _js_mask_comments(source)

    for m in _JS_EVAL_DECODED_RE.finditer(masked):
        ln = masked.count("\n", 0, m.start()) + 1
        add(
            "JS_EVAL_DECODED",
            "crit",
            ln,
            "eval/Function over a base64-decoded blob — "
            "obfuscated remote code execution",
        )

    for m in _JS_EVAL_REMOTE_RE.finditer(masked):
        ln = masked.count("\n", 0, m.start()) + 1
        add(
            "JS_EVAL_REMOTE",
            "crit",
            ln,
            "remote code is fetched and executed (a URL import, or a fetched "
            "blob passed straight to eval) — remote code execution",
        )

    if "child_process" in masked:
        for m in _JS_CP_TEMPLATE_RE.finditer(masked):
            ln = masked.count("\n", 0, m.start()) + 1
            add(
                "JS_CHILD_PROCESS_DYNAMIC",
                "warn",
                ln,
                "child_process exec/spawn with an interpolated command "
                "(`git ${x}`) — command-injection surface",
            )

    for m in _JS_DYN_REQUIRE_RE.finditer(masked):
        ln = masked.count("\n", 0, m.start()) + 1
        add(
            "JS_DYNAMIC_REQUIRE",
            "warn",
            ln,
            "require() of a non-literal (variable/template) — a dynamic, "
            "possibly attacker-influenced module path",
        )

    for m in _JS_NATIVE_DLOPEN_RE.finditer(masked):
        ln = masked.count("\n", 0, m.start()) + 1
        add(
            "JS_NATIVE_DLOPEN",
            "warn",
            ln,
            "process.dlopen() loads a native addon (.node) directly — a "
            "native-boundary escape that bypasses JS-level analysis; require() "
            "is the normal loader",
        )

    return out


def simulate_effects(source: str, filename: str = "<skill>") -> list[dict]:
    """Analyze Python source to simulate reachable effects and guarding conditions under seeds.

    Never raises, returns an empty list on failure — EXCEPT ScanBudgetExceeded
    (C-175), which must propagate: the caller (checks/_vet.py's
    check_installed_skills) relies on it reaching run_all's dedicated handler,
    which converts a budget hit into an honest UNKNOWN finding. Swallowing it
    here made a truncated, incomplete simulation indistinguishable from "found
    nothing" — a scan cut short mid-analysis silently reported PASS.
    """
    try:
        return EffectSimulator(source, filename).simulate()
    except ScanBudgetExceeded:
        raise
    except Exception:
        return []
