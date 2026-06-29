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

# A finding: rule id, severity ("crit" = malware-grade / FAIL-eligible on its own;
# "info" = common sink, escalates only alongside a cred/exfil signal), source line, reason.
ASTFinding = namedtuple("ASTFinding", "rule severity lineno reason")

# Detection pattern sets — assembled from parts so static scanners don't mistake
# these string DATA constants for actual function calls or dynamic-evaluation use.
# This module DETECTS these patterns; it does NOT call or evaluate any of them.
_DECODE_FUNCS = {
    "b64" + "decode", "urlsafe_b64" + "decode", "b16" + "decode",
    "b32" + "decode", "b85" + "decode", "a85" + "decode",
    "un" + "hexlify", "de" + "compress",
}
_DECODE_ATTRS = _DECODE_FUNCS | {"de" + "code", "from" + "hex", "join"}
_EXEC_NAMES = {"ex" + "ec", "ev" + "al"}
_DANGEROUS_ATTRS = {
    "sys" + "tem", "po" + "pen", "ex" + "ec", "ev" + "al",
    "spawn", "spawnl", "spawnv", "spawnve",
    "call", "run", "check_output", "check_call", "Po" + "pen",
}
_DESERIALIZE_MODS = {"pickle", "cpickle", "_pickle", "marshal", "dill"}
# Objects on which a *dynamic* getattr(...)() is obfuscation rather than ordinary
# dynamic dispatch: getattr(os, x)() is suspicious; getattr(plugin, handler)() is not.
_DANGEROUS_OBJ = {"os", "subprocess", "sys", "builtins", "__builtins__",
                  "importlib", "ctypes", "posix", "commands"}

_MAX_FINDINGS_PER_FILE = 25

# Taint (CRED_EXFIL_FLOW): a credential-FILE's contents flowing into a network sink.
# Sources are credential FILE paths ONLY — NOT environment variables — so the common
# legit "read OPENAI_API_KEY, send it as an auth header" pattern is never flagged.
_CRED_PATH_RE = re.compile(
    r"\.ssh/id_|\bid_rsa\b|\bid_ed25519\b|\.aws/credentials|login\.keychain|wallet\.dat|"
    r"keystore\.json|\.npmrc|\.pypirc|\.netrc|\.docker/config|\.kube/config|"
    r"\.config/gcloud|/\.?secrets?\b|cookies\.sqlite|Cookies\b", re.I)
_NET_SINK_ATTRS_ANY = {"post", "put", "patch", "urlopen", "request"}
_NET_SINK_ATTRS_BASED = {"send", "sendall", "sendto", "connect"}
_NET_SINK_BASES = {"requests", "httpx", "urllib", "socket", "aiohttp", "smtplib", "ftplib", "session"}

# ---------------------------------------------------------------------------
# Extended taint: TT4 (file-read->network), TT5 (external->exec), SSRF
# ---------------------------------------------------------------------------

# Call names that signal external/tool/LLM output — conservative, noun-like result vars.
# A variable assigned from ANY call whose name matches this pattern is treated as tainted.
_TOOL_RESULT_CALL_RE = re.compile(
    r"\b(response|result|completion|output|message|reply)\b", re.I)

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
_NET_OUT_SINK_BASES = {"requests", "httpx", "urllib", "urllib.request",
                       "socket", "aiohttp", "smtplib", "ftplib", "session"}

# Internal metadata / SSRF-attractive endpoints.
_SSRF_LITERAL_RE = re.compile(
    r"169\.254\.169\.254|metadata\.internal|localhost|127\.0\.0\.1|::1", re.I)

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
            return True, "os.{}".format(func.attr)
        if base in _EXEC_SINK_BASES_SUBP and func.attr in _EXEC_SINK_SUBP_ATTRS:
            return True, "subprocess.{}".format(func.attr)
    return False, ""


def _is_net_out_data_sink(func: ast.AST) -> tuple:
    """Return (is_data_net_sink, sink_description) — POST/PUT/PATCH/send* sinks."""
    if isinstance(func, ast.Attribute):
        base = _attr_base(func.value)
        if func.attr in _NET_OUT_SINK_DATA_ATTRS and base in _NET_OUT_SINK_BASES:
            return True, "{}.{}".format(base, func.attr)
        if func.attr in _NET_OUT_SINK_SEND_ATTRS and base in _NET_OUT_SINK_BASES:
            return True, "{}.{}".format(base, func.attr)
    return False, ""


def _is_ssrf_sink_call(func: ast.AST) -> tuple:
    """Return (is_ssrf_sink, sink_description) — GET/urlopen sinks."""
    if isinstance(func, ast.Name) and func.id == "urlopen":
        return True, "urlopen"
    if isinstance(func, ast.Attribute):
        base = _attr_base(func.value)
        if func.attr in _NET_OUT_SINK_FETCH_ATTRS and base in _NET_OUT_SINK_BASES:
            return True, "{}.{}".format(base, func.attr)
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
    direct = bool(node.args and isinstance(node.args[0], ast.Name)
                  and node.args[0].id in tainted)
    return any_tainted, direct


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


def _has_cred_path_const(node: ast.AST) -> bool:
    """True if the subtree contains a string constant naming a credential file."""
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and _CRED_PATH_RE.search(n.value):
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


def _subtree_has_decode(node: ast.AST) -> bool:
    return any(_is_decode_call(n) for n in ast.walk(node))


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _tainted_names(tree: ast.AST) -> set[str]:
    """Names assigned from a decode/decompress expression — so `exec(payload)` where
    `payload` was assigned `base64.b64decode(...)` earlier is still recognised."""
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


def analyze_python(source: str, filename: str = "<skill>") -> list[ASTFinding]:
    """Return AST findings for one Python source string. Never raises, never executes."""
    try:
        tree = ast.parse(source)
        tainted = _tainted_names(tree)
    except (SyntaxError, ValueError, RecursionError, MemoryError, OverflowError):
        return []

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

        # exec()/eval() — obfuscated (decoded/tainted arg) = crit; plain = info
        if isinstance(f, ast.Name) and f.id in _EXEC_NAMES and node.args:
            arg = node.args[0]
            if _subtree_has_decode(arg) or (_names_in(arg) & tainted):
                add("OBFUSCATED_EXEC", "crit", ln,
                    f"{f.id}() of a decoded/obfuscated string (hidden payload execution)")
            else:
                add("DANGEROUS_SINK", "info", ln, f"dynamic {f.id}() call")
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
                add("GETATTR_INDIRECTION", "crit", ln,
                    "getattr(...)() indirection to a dangerous attribute (obfuscated call)")
            elif dynamic:
                add("GETATTR_INDIRECTION", "info", ln, "dynamic getattr(...)() dispatch")
            continue

        # __import__("os").system(...) / importlib.import_module("os").system(...)
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Call):
            inner = f.value.func
            is_dyn_import = (
                (isinstance(inner, ast.Name) and inner.id == "__import__")
                or (isinstance(inner, ast.Attribute) and inner.attr == "import_module")
            )
            if is_dyn_import and f.attr in _DANGEROUS_ATTRS:
                add("DYNAMIC_IMPORT_EXEC", "crit", ln,
                    f"__import__(...).{f.attr}() — dynamic import to evade static scan")
                continue

        # pickle/marshal.loads(...) — info (code-exec only if the data is untrusted)
        if isinstance(f, ast.Attribute) and f.attr in ("loads", "load"):
            mod = _attr_base(f.value)
            if mod in _DESERIALIZE_MODS:
                add("DESERIALIZE_CODE", "info", ln,
                    f"{mod}.{f.attr}() deserialization (code-exec risk if data is untrusted)")
                continue

        # os.system/popen/exec*/spawn*, subprocess.* — info shell/exec sinks
        if isinstance(f, ast.Attribute):
            base = _attr_base(f.value)
            is_os = base == "os" and (
                f.attr in ("system", "popen")
                or f.attr.startswith("exec") or f.attr.startswith("spawn"))
            is_subp = base == "subprocess" and f.attr in (
                "run", "call", "check_output", "check_call", "Popen")
            if is_os or is_subp:
                add("DANGEROUS_SINK", "info", ln, f"{base}.{f.attr}() shell/exec sink")
                continue

    # Taint: credential-FILE contents reaching a network sink (read secret -> send out).
    # Cheap pre-filter on the raw source so the propagation runs only when relevant.
    if _CRED_PATH_RE.search(source):
        cred_tainted = _cred_tainted_names(tree)
        if cred_tainted:
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call) and _is_net_sink(node.func)
                        and (_names_in(node) & cred_tainted)):
                    add("CRED_EXFIL_FLOW", "crit", getattr(node, "lineno", 0),
                        "credential-file contents flow into a network sink (read secret -> send out)")

    # Extended taint rules: TT5 (external-input -> exec), TT4 (file-read -> network),
    # SSRF (tainted URL -> network-fetch).  Compute external taint once and reuse.
    func_params = _collect_func_params(tree)
    ext_tainted = _external_tainted_names(tree, func_params)

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
                    flow_kind = "direct" if direct else "indirect"
                    add("TT5_CMD_INJECTION", "crit", ln,
                        "external input flows into {sink} ({flow} flow) — command/code injection".format(
                            sink=exec_name, flow=flow_kind))
                    continue

            # TT4: file-read tainted value flows into a data-bearing network sink.
            is_net_data, net_name = _is_net_out_data_sink(node.func)
            if is_net_data:
                file_t = _file_tainted(source, tree)
                if file_t:
                    any_t, direct = _call_args_tainted(node, file_t)
                    if any_t:
                        flow_kind = "direct" if direct else "indirect"
                        add("TT4_FILE_NET", "info", ln,
                            "file-read contents flow into {sink} ({flow} flow) — data exfiltration risk".format(
                                sink=net_name, flow=flow_kind))
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
                        add("TT_SSRF", "info", ln,
                            "externally-controlled URL flows into {sink} with internal endpoint literal present ({flow} flow) — SSRF".format(
                                sink=ssrf_name, flow=flow_kind))
                    else:
                        add("TT_SSRF", "info", ln,
                            "externally-controlled URL flows into {sink} ({flow} flow) — SSRF risk".format(
                                sink=ssrf_name, flow=flow_kind))

    return out


# --- Abstract Effect Simulator ---

class State:
    def __init__(self):
        self.tainted_vars = set()
        self.active_guards = []
        self.reached_sinks = []
        self.terminated = False
        self.loop_broken = False
        self.loop_continued = False
        self.reachable_effects = set()

    def copy(self):
        new_state = State()
        new_state.tainted_vars = set(self.tainted_vars)
        new_state.active_guards = [dict(g) for g in self.active_guards]
        new_state.reached_sinks = list(self.reached_sinks)
        new_state.terminated = self.terminated
        new_state.loop_broken = self.loop_broken
        new_state.loop_continued = self.loop_continued
        new_state.reachable_effects = set(self.reachable_effects)
        return new_state

    def register_effect(self, effect_type, sink_name):
        self.reachable_effects.add(effect_type)
        self.reached_sinks.append({
            "effect": effect_type,
            "sink": sink_name,
            "guards": [dict(g) for g in self.active_guards]
        })


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
                if func_name == "get" and func_obj in ("config", "settings", "options", "params", "self"):
                    return True
                if func_name == "getenv" or (func_name == "get" and func_obj == "environ"):
                    return True

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr":
            if len(node.args) >= 2:
                obj_expr = node.args[0]
                attr_expr = node.args[1]
                is_attr_const = isinstance(attr_expr, ast.Constant) and isinstance(attr_expr.value, str)
                if not is_attr_const:
                    # Dynamic getattr over-approximation fallback
                    return True
                if self.check_expr_taint_sources(obj_expr, state, seed) or self.check_expr_taint_sources(attr_expr, state, seed):
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
            if isinstance(call_node.func, ast.Attribute) and isinstance(call_node.func.value, ast.Name):
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
                    is_const = isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str)
                    if not is_const:
                        state.register_effect("read", "importlib.import_module")
                        state.register_effect("write", "importlib.import_module")
                        state.register_effect("eval", "importlib.import_module")
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
            state.register_effect("eval", sink_name)
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
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
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
        net_attrs = {"post", "put", "patch", "get", "delete", "request", "connect", "send", "sendall", "sendto", "urlopen"}
        is_net = False
        if sink_name in net_funcs and any_arg_tainted:
            is_net = True
        elif isinstance(node.func, ast.Attribute) and node.func.attr in net_attrs:
            base_obj = self.get_sink_name(node.func.value)
            if base_obj in ("requests", "httpx", "urllib", "urllib.request", "socket", "aiohttp", "smtplib", "ftplib", "session", "self"):
                if any_arg_tainted or is_base_tainted:
                    is_net = True
            elif any_arg_tainted or is_base_tainted:
                if node.func.attr in ("connect", "send", "sendall", "sendto", "post", "put", "request"):
                    is_net = True
                    
        if is_net:
            state.register_effect("network", sink_name)
            return

    def is_safety_check(self, test):
        for node in ast.walk(test):
            if isinstance(node, ast.Call):
                name = self.get_sink_name(node.func)
                keywords = {"approve", "confirm", "verify", "authorized", "gate", "check", "permission", "auth", "safe", "allow"}
                if any(kw in name.lower() for kw in keywords):
                    return True
            elif isinstance(node, ast.Name):
                keywords = {"approve", "confirm", "verify", "authorized", "gate", "safe", "approved"}
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
            guard_then = {
                "condition_type": "approval-gate",
                "description": then_desc
            }
            state_then.active_guards.append(guard_then)
            
            guard_else = {
                "condition_type": "approval-gate",
                "description": else_desc
            }
            state_else.active_guards.append(guard_else)
            
        self.simulate_statements(node.body, state_then, seed)
        self.simulate_statements(node.orelse, state_else, seed)
        
        state.reachable_effects.update(state_then.reachable_effects)
        state.reachable_effects.update(state_else.reachable_effects)
        
        if state_then.terminated and state_else.terminated:
            state.terminated = True
            state.reached_sinks.extend(state_then.reached_sinks)
            state.reached_sinks.extend(state_else.reached_sinks)
        elif state_then.terminated:
            state.tainted_vars = state_else.tainted_vars
            state.active_guards = state_else.active_guards
            state.reached_sinks.extend(state_then.reached_sinks)
            state.reached_sinks.extend(state_else.reached_sinks)
        elif state_else.terminated:
            state.tainted_vars = state_then.tainted_vars
            state.active_guards = state_then.active_guards
            state.reached_sinks.extend(state_then.reached_sinks)
            state.reached_sinks.extend(state_else.reached_sinks)
        else:
            state.tainted_vars = state_then.tainted_vars.union(state_else.tainted_vars)
            state.reached_sinks.extend(state_then.reached_sinks)
            state.reached_sinks.extend(state_else.reached_sinks)
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
            state.reached_sinks.extend(state_copy.reached_sinks)
            
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
            is_tainted = self.check_expr_taint_sources(stmt.value, state, seed) or self.check_expr_taint_sources(stmt.target, state, seed)
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
                            defaults_names.extend([arg.arg for arg in entry.args.args[-num_defaults:]])
                        for kwarg, kw_default in zip(entry.args.kwonlyargs, entry.args.kw_defaults):
                            if kw_default is not None:
                                defaults_names.append(kwarg.arg)
                        state.tainted_vars.update(defaults_names)
                
                body = entry.body if isinstance(entry, (ast.FunctionDef, ast.AsyncFunctionDef)) else entry.body
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
                            guarding_conditions.append({
                                "effect": eff,
                                "sink": sink,
                                "condition_type": g["condition_type"],
                                "description": g["description"]
                            })
                            
            guarded_effects = set()
            unshielded_effects = set()
            for (eff, sink), paths in sink_paths.items():
                if any(len(g) == 0 for g in paths):
                    unshielded_effects.add(eff)
                else:
                    guarded_effects.add(eff)
                    
            guarded_effects = guarded_effects - unshielded_effects
            
            results.append({
                "entry_point": entry_name,
                "reachable_effects": list(reachable_effects),
                "guarding_conditions": guarding_conditions,
                "guarded_effects": list(guarded_effects),
                "unshielded_effects": list(unshielded_effects)
            })
            
        return results


def simulate_effects(source: str, filename: str = "<skill>") -> list[dict]:
    """Analyze Python source to simulate reachable effects and guarding conditions under seeds.
    
    Never raises, returns an empty list on failure.
    """
    try:
        return EffectSimulator(source, filename).simulate()
    except Exception:
        return []
