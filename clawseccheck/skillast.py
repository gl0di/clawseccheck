"""Read-only AST analysis of Python files inside a skill (NO code execution).

Regex alone is blind to obfuscation: `exec(base64.b64decode(...))`,
`getattr(os, "sys"+"tem")(...)`, `__import__("os").system(...)`, `marshal.loads(...)`.
We parse Python files with the stdlib `ast` module — **parse only, never compile or
exec** — and flag a small, high-confidence set of malware-grade constructs, plus some
informational "dangerous sink" usage that the B13 engine only escalates when the skill
already shows a credential/exfil signal (so a skill that merely uses subprocess is never
failed on its own).

Pure stdlib. Offline. Best-effort: a file that does not parse (templates, Python 2, JS
mislabelled as .py) yields no findings rather than an error.
"""
from __future__ import annotations

import ast
import re
from collections import namedtuple

# A finding: rule id, severity ("crit" = malware-grade / FAIL-eligible on its own;
# "info" = common sink, escalates only alongside a cred/exfil signal), source line, reason.
ASTFinding = namedtuple("ASTFinding", "rule severity lineno reason")

# functions/methods whose presence inside an exec()/eval() argument means the executed
# string was decoded/decompressed at runtime — i.e. hidden from a plain-text scan.
_DECODE_FUNCS = {
    "b64decode", "urlsafe_b64decode", "b16decode", "b32decode", "b85decode",
    "a85decode", "unhexlify", "decompress",
}
_DECODE_ATTRS = _DECODE_FUNCS | {"decode", "fromhex", "join"}
_EXEC_NAMES = {"exec", "eval"}
_DANGEROUS_ATTRS = {
    "system", "popen", "exec", "eval", "spawn", "spawnl", "spawnv", "spawnve",
    "call", "run", "check_output", "check_call", "Popen",
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

    return out
