"""Proof that an ``exec()``/``eval()`` call runs exactly a file its own artifact ships.

B-638. ``skillast.analyze_python`` reads every ``open()``/``.read()`` as external input,
so the ``setup.py`` idiom that requests, urllib3 and hundreds of packages use to read
their own ``__version__.py`` without importing the package::

    here = os.path.abspath(os.path.dirname(__file__))
    about = {}
    with open(os.path.join(here, "pkg", "__version__.py"), encoding="utf-8") as f:
        exec(f.read(), about)

was convicted as ``TT5_CMD_INJECTION`` (and, spelled with ``.decode()`` and a variable,
as ``OBFUSCATED_EXEC``) -- a critical FAIL on code that executes nothing but a file the
package ships. The earlier carve-out (``skillast._path_expr_is_dunder_file_relative``)
asked whether the path expression MENTIONED ``__file__``; an independent C-135 pass
showed that any carve-out keyed on token presence is unsound (``os.path.join`` swallowing
the anchor on an absolute argument, ``..`` traversal, a decorative ``__file__`` in a dead
branch, a shadowed ``__file__``, laundering through ``os.environ``). This module answers
the question that pass said had to be answered instead: does the call provably execute
the bytes of one specific file that is part of the artifact, and that this scan analysed?

WHY "EXACT" AND NOT "UNTAINTED". The first design considered here removed shipped-file
reads from the taint sources and let the taint engine decide. That is unsound: taint
propagates through ``src = src.replace("#", "")``, and a transformation of analysed
content is not analysed content -- uncommenting a line turns a comment the scan read as
inert into code. So the carve-out applies only when the executed value IS the file's
content: the read itself, optionally ``.decode()``-d with UTF-8 or wrapped in
``compile()``, or a local bound exactly once to one of those.

WHAT HAS TO HOLD, all of it, or the call keeps its conviction:

* The path resolves -- by modelling ``os.path.dirname/abspath/realpath/normpath/join``
  and ``pathlib`` ``Path/parent/resolve/absolute/"/"/joinpath/with_name`` over
  ``__file__`` and literal segments -- to a relpath inside the artifact root that is in
  the set of files the caller analysed. Every such file was reached by a symlink-free
  walk, so its lexical path names exactly the bytes that were scanned. A ``..`` may only
  climb a directory that is part of the scanned file's own location (literal components
  could be symlinks the walk skipped); a lexical ``dirname``/``.parent`` is refused on a
  value whose last component is ``..``/``.``/empty, where the lexical and physical
  answers differ; an absolute or drive-bearing literal is refused.
* The read is the WHOLE file, read-only, decoded exactly as the scanner decoded it:
  ``open``/``io.open``/``codecs.open`` in a literal read mode with no ``opener``,
  UTF-8 or no encoding, strict errors; ``Path.read_text``/``read_bytes``. A handle must
  not be touched by anything else first (``readline()`` then ``read()`` executes a
  suffix, and a suffix of a file can mean something the whole file does not). Bytes
  must be decoded before they are executed -- ``exec(bytes)`` honours a PEP 263 coding
  cookie the scanner's ``str`` parse never saw.
* The namespace it runs in cannot carry a spoofed ``__file__`` or ``open``: an empty
  dict literal, or a name bound once to one and only ever read afterwards. Without a
  namespace the target inherits this file's globals, so it must sit in the same
  directory or never mention ``__file__``.
* Every name the expression uses resolves statically: ``__file__`` never rebound, the
  builtins never shadowed, the path helpers bound by a real import, and every local
  bound exactly once -- in the SAME function when the call is inside one, because a
  module global read by a function can be replaced from another file after import.
* This file does nothing that could put different bytes at that path first: no
  write-mode open, file-moving or process-spawning call, no network client, no
  ``os.chdir``, no import of a module the artifact itself ships.
* No file in the artifact reaches the interpreter's own namespaces -- builtins,
  ``sys.modules``, frames, ``__dict__``/``__globals__``, ``setattr``/``vars``,
  ``importlib``/``runpy``/``pickle``/``ctypes``/``mock``, a store to an attribute named
  like the callables above -- ships a module named like the stdlib ones the read goes
  through, or contains any other ``exec``/``eval``/``compile``. Those are how a SECOND
  file would swap the content under a read this file can only see from the inside
  (``analyze_python`` is per-file; B-655 retracted an exemption for exactly that reason).
  Any file that cannot be parsed voids the carve-out for the whole artifact, since it
  cannot be checked for any of this.

ONE CONDITION SHORT. A call that meets every condition except membership -- its path
provably stays inside the artifact, but the file there is not one the scan analysed
(missing from what was vetted, or not Python) -- is reported separately
(`ShippedArtifact.unshipped_exec_sites`). What runs there is decided later, by whatever
puts a file at that path; that is neither proof of a payload nor proof of safety, so the
caller reports it WARN-grade, never as the crit a path leaving the artifact still gets.
The canonical case is a repro or a partial checkout of a package whose version file was
not included; in a real sdist the file is shipped and the call is simply cleared.

WHAT IS NOT CLAIMED. A file that writes a path the artifact ships, then imports it, runs
the written code without any exec and is not flagged at HEAD either; so is
``runpy.run_path``/``importlib`` on a planted file. A chain that plants a file through a
second module and has THIS call execute it therefore gains nothing an attacker does not
already have without it, and detecting it belongs where the planting happens. The
refusal list above is a list of spellings: a way to reach the interpreter's namespaces
that it does not name is outside what a static pass can promise, and is the reason this
is a carve-out a caller must opt into by passing the artifact, never a default.

Stdlib only. Layer 1: imports nothing from the package. Never executes, imports or
evaluates anything it reads; its only filesystem access is `lstat`/`stat` of paths inside
the artifact root, to tell an absent target from a present one (`ShippedArtifact._absent`).
"""

from __future__ import annotations

import ast
import codecs
import os
import re
import stat

# Detection pattern data, assembled from parts (the skillast.py convention) so a static
# scanner does not mistake these string constants for dynamic-evaluation use. This module
# names these built-ins; it never calls or evaluates any of them.
_EX, _EV = "ex" + "ec", "ev" + "al"
# The call names this module can certify. Anything else is out of scope.
_EXEC_CALLS = frozenset({"builtins." + _EX, "builtins." + _EV})
_DYNAMIC_CODE = _EXEC_CALLS | {"builtins.compile"}
_BUILTINS_USED = frozenset({"open", "compile", "str", "dict", _EX, _EV})
_EXEC_WORD_RE = re.compile(r"\b(?:" + _EX + "|" + _EV + r")\b")
_ENCODING_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")

_OSPATH = ("os.path.", "posixpath.")
_PATH_CLASSES = frozenset(
    {"pathlib.Path", "pathlib.PosixPath", "pathlib.PurePath", "pathlib.PurePosixPath"}
)

# Namespace-tampering spellings. Any of these ANYWHERE in the artifact voids the carve-out.
_TAMPER_NAMES = frozenset(
    {"__builtins__", "__import__", "globals", "vars", "locals", "setattr", "delattr"}
)
_TAMPER_ATTRS = frozenset({
    # dunder gadgets that reach a module's or the interpreter's namespace
    "__dict__", "__globals__", "__builtins__", "__self__", "__subclasses__", "__bases__",
    "__base__", "__mro__", "__closure__", "__code__", "__loader__", "__spec__",
    "__getattribute__", "__setattr__", "__delattr__", "__import__",
    # frames, import machinery, code objects, monkeypatching helpers
    "f_globals", "f_locals", "f_builtins", "f_back", "_getframe", "gi_frame", "tb_frame",
    "cr_frame", "ag_frame", "modules", "meta_path", "path_hooks", "path_importer_cache",
    "CodeType", "setattr", "delattr", "mock",
})
_TAMPER_MODULES = frozenset({
    "builtins", "importlib", "runpy", "imp", "pkgutil", "zipimport", "inspect", "gc",
    "ctypes", "pickle", "_pickle", "cPickle", "marshal", "shelve", "dill", "cloudpickle",
    "copyreg", "timeit", "doctest", "code", "codeop", "pdb", "bdb", "cProfile", "profile",
    "trace", "operator", "site", "sitecustomize", "usercustomize", "pkg_resources", "mock",
})
_TAMPER_DOTTED_MODULES = frozenset({"logging.config", "unittest.mock"})
# A STORE to an attribute with one of these names replaces something the proof relies on.
_TAMPER_STORE_ATTRS = frozenset({
    "open", "read", "decode", "compile", _EX, _EV, "str", "fspath", "__file__",
    "os", "io", "codecs", "pathlib", "posixpath", "Path", "PurePath", "PosixPath",
    "PurePosixPath", "__truediv__", "__fspath__",
    # the os.path helpers the resolver models (`self.path = ...` is handled apart: a
    # store to `.path` counts unless it is on `self`, the ordinary instance attribute)
    "join", "dirname", "abspath", "realpath", "normpath",
})
# Directories the collectors never read: a target under one exists but was not analysed.
_UNREAD_DIRS = frozenset({".git", ".hg", ".svn", "__pycache__", "node_modules"})
# Module-namespace names a file executed WITHOUT its own namespace must not rebind.
_MODULE_MAGIC = frozenset({
    "__file__", "__name__", "__builtins__", "__spec__", "__loader__", "__package__",
    "__path__", "__cached__", "__doc__", "__annotations__", "__dict__", "__class__",
})
# The same, for the pathlib-read spellings only (`.read_text()`), where the Path object's
# own methods produce the content. Kept apart because `self.parent = ...` is common and
# should not cost the builtin-`open` spelling its carve-out.
_PATHLIB_STORE_ATTRS = frozenset(
    {"parent", "resolve", "absolute", "joinpath", "with_name", "read_text", "read_bytes"}
)
# An artifact file shadowing one of these would replace the code the read goes through.
_SHADOW_SENSITIVE = frozenset({
    "os", "posixpath", "ntpath", "genericpath", "pathlib", "io", "_io", "codecs",
    "encodings", "builtins", "stat", "fnmatch", "re", "functools", "operator", "sys",
    "site", "sitecustomize", "usercustomize", "abc", "collections", "types", "warnings",
    "urllib", "itertools", "errno", "glob",
})

# This file must not be able to put different bytes at the path before reading it.
_SIDE_EFFECT_ROOTS = frozenset({
    "subprocess", "shutil", "socket", "requests", "httpx", "aiohttp", "urllib", "urllib3",
    "http", "ftplib", "pty", "multiprocessing", "tarfile", "zipfile", "tempfile",
    "asyncio", "smtplib", "telnetlib", "paramiko", "webbrowser", "wget", "pycurl",
})
_OS_SAFE_CALLS = frozenset({
    "os.getenv", "os.environ.get", "os.fspath", "os.getcwd", "os.listdir", "os.scandir",
    "os.walk", "os.stat", "os.lstat", "os.cpu_count", "os.getpid",
})
_WRITE_METHODS = frozenset({
    "write", "writelines", "write_text", "write_bytes", "rename", "symlink_to",
    "hardlink_to", "link_to", "touch", "chmod", "extractall", "extract", "urlretrieve",
    "retrbinary", "download", "download_file", "mkfifo", "chdir", "fchdir",
})
# Attribute stores rooted in one of these imports change what the read resolves to.
_READ_PATH_ROOTS = frozenset({"os", "posixpath", "ntpath", "pathlib", "io", "codecs", "builtins"})

_NS_READ_METHODS = frozenset({"get", "items", "keys", "values", "copy"})
_MAX_DEPTH = 12


def _norm_relpath(rel: str) -> "str | None":
    """`rel` as '/'-joined components, or None when it is not a plain in-artifact path."""
    rel = rel.replace("\\", "/")
    if rel.startswith("/") or "::" in rel or ":" in rel:
        return None
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        return None
    return "/".join(parts)


def _module_names(rels) -> set:
    """Every name an artifact file could be imported as: each directory and file stem."""
    out: set = set()
    for rel in rels:
        parts = rel.split("/")
        out.update(parts[:-1])
        out.add(parts[-1].split(".", 1)[0])
    out.discard("")
    return out


def _utf8_literal(node: "ast.AST | None") -> bool:
    """True when *node* is absent-equivalent (None) or a literal naming the UTF-8 codec."""
    if node is None:
        return True
    if isinstance(node, ast.Constant) and node.value is None:
        return True
    if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
        return False
    if not _ENCODING_NAME_RE.match(node.value):
        return False
    try:
        return codecs.lookup(node.value).name == "utf-8"
    except LookupError:
        return False


def _strict_literal(node: "ast.AST | None") -> bool:
    if node is None:
        return True
    return isinstance(node, ast.Constant) and node.value in (None, "strict")


def _tampers(tree: ast.AST) -> bool:
    """Does this file reach the interpreter's namespaces by any spelling we recognise?"""
    for n in ast.walk(tree):
        if isinstance(n, ast.Name) and n.id in _TAMPER_NAMES:
            return True
        if isinstance(n, ast.Attribute):
            if n.attr in _TAMPER_ATTRS:
                return True
            if isinstance(n.ctx, (ast.Store, ast.Del)) and (
                n.attr in _TAMPER_STORE_ATTRS
                or (n.attr == "path" and not (isinstance(n.value, ast.Name)
                                               and n.value.id == "self"))
            ):
                return True
            if n.attr in ("chdir", "fchdir"):
                return True
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and "__file__" in n.value:
            return True
        if isinstance(n, ast.keyword) and n.arg == "__file__":
            return True
        if (
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id == "getattr"
            and len(n.args) >= 2
        ):
            name = n.args[1]
            if not (isinstance(name, ast.Constant) and isinstance(name.value, str)):
                return True
            if name.value in _TAMPER_ATTRS or name.value in ("chdir", "fchdir"):
                return True
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] in _TAMPER_MODULES or any(
                    a.name == m or a.name.startswith(m + ".") for m in _TAMPER_DOTTED_MODULES
                ):
                    return True
        if isinstance(n, ast.ImportFrom):
            mod = n.module or ""
            if mod.split(".")[0] in _TAMPER_MODULES:
                return True
            for a in n.names:
                full = f"{mod}.{a.name}" if mod else a.name
                if a.name == "chdir" or any(
                    full == m or full.startswith(m + ".") or mod == m
                    for m in _TAMPER_DOTTED_MODULES
                ):
                    return True
    return False


def _pathlib_tampers(tree: ast.AST) -> bool:
    return any(
        isinstance(n, ast.Attribute)
        and isinstance(n.ctx, (ast.Store, ast.Del))
        and n.attr in _PATHLIB_STORE_ATTRS
        for n in ast.walk(tree)
    )


def _bound_names(tree: ast.AST) -> "tuple[set, set]":
    """(names bound anywhere by a non-import form, names bound anywhere by an import)."""
    other: set = set()
    imported: set = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            other.add(n.id)
        elif isinstance(n, ast.arg):
            other.add(n.arg)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            other.add(n.name)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            other.add(n.name)
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            other.update(n.names)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for a in n.names:
                imported.add(a.asname or a.name.split(".")[0])
        else:
            for field in ("name", "rest"):  # match-statement captures (3.10+)
                v = getattr(n, field, None)
                if isinstance(v, str) and type(n).__name__.startswith("Match"):
                    other.add(v)
    return other, imported


class _Path:
    """A statically resolved path: components below the artifact root.

    `real` counts the leading components known to be real directories (the scanned
    file's own location, which the symlink-free walk proved), so a `..` may pop them;
    `tail` is True when the value's LAST lexical component is `..`/`.`/empty, where a
    lexical dirname/.parent disagrees with the filesystem.
    """

    __slots__ = ("kind", "parts", "real", "tail")

    def __init__(self, kind: str, parts: tuple, real: int, tail: bool = False) -> None:
        self.kind, self.parts, self.real, self.tail = kind, parts, real, tail

    def up(self, kind: "str | None" = None) -> "_Path | None":
        if not self.parts or self.tail:
            return None
        parts = self.parts[:-1]
        return _Path(kind or self.kind, parts, min(self.real, len(parts)))

    def join(self, seg: str, kind: "str | None" = None) -> "_Path | None":
        if not seg or seg.startswith("/") or any(c in seg for c in ("\\", "\x00", ":")):
            return None
        parts = list(self.parts)
        real = self.real
        comps = seg.split("/")
        for c in comps:
            if c in ("", "."):
                continue
            if c == "..":
                if not parts or len(parts) > real:
                    return None
                parts.pop()
                real = len(parts)
            else:
                parts.append(c)
        return _Path(kind or self.kind, tuple(parts), real, comps[-1] in ("", ".", ".."))

    def normalised(self, kind: "str | None" = None) -> "_Path":
        return _Path(kind or self.kind, self.parts, self.real)


class _FileFacts:
    """Everything one file's proof needs, computed once."""

    def __init__(self, tree: ast.AST, relpath: str, artifact: "ShippedArtifact",
                 module_names: set, pathlib_tampered: bool) -> None:
        self.tree = tree
        self.relpath = relpath
        self.relparts = tuple(relpath.split("/"))
        self.artifact = artifact
        self.pathlib_tampered = pathlib_tampered
        self.parents: dict = {}
        for p in ast.walk(tree):
            for c in ast.iter_child_nodes(p):
                if isinstance(c, (ast.Load, ast.Store, ast.Del)):
                    # CPython reuses ONE Load/Store/Del instance for every occurrence
                    # in the tree (ast.Load() etc. are singletons), so keying this
                    # dict by node identity would silently overwrite the "parent" on
                    # every ctx occurrence, leaving whichever was walked last -- an
                    # arbitrary, usually very deep, node. Nothing legitimately climbs
                    # FROM a ctx node (every real caller starts from the Name/
                    # Attribute/Subscript that owns it, which has its own correct
                    # entry here), so recording nothing for them is both correct
                    # (scope_of() sees an immediate `is None` instead of a bogus deep
                    # climb) and avoids a pathological O(depth) walk for every ctx
                    # node a full `ast.walk()` scope_of() sweep visits.
                    continue
                self.parents[c] = p
        self.other_bound, self.import_bound = _bound_names(tree)
        self.star = any(
            isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names)
            for n in ast.walk(tree)
        )
        self.table = self._import_table()
        self.declared = {
            name for n in ast.walk(tree) if isinstance(n, (ast.Global, ast.Nonlocal))
            for name in n.names
        }
        self._records: dict = {}
        # When True, a resolved in-artifact path counts as a target even if the artifact
        # does not ship it as analysed Python -- used only to find the calls that fail the
        # proof for that one reason (`exact_calls`' second pass).
        self.any_target = False
        self.blocked = self.star or self._blocked(module_names)
        # B-917 locate() LEGB fallback (2.1): lazily computed and cached, since most
        # files never take this path. `None` means "not computed yet" for the
        # whole-file tamper flag; the per-name cache starts empty.
        self._legb_tampers: "bool | None" = None
        self._legb_attr_store_cache: dict = {}

    # ── names ──────────────────────────────────────────────────────────────────────────

    def _import_table(self) -> dict:
        """alias -> dotted target, for names bound ONLY by one kind of import."""
        seen: dict = {}
        bad: set = set()
        for n in ast.walk(self.tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    key = a.asname or a.name.split(".")[0]
                    val = a.name if a.asname else a.name.split(".")[0]
                    if seen.setdefault(key, val) != val:
                        bad.add(key)
            elif isinstance(n, ast.ImportFrom):
                for a in n.names:
                    key = a.asname or a.name
                    if n.level or not n.module:
                        bad.add(key)
                        continue
                    val = f"{n.module}.{a.name}"
                    if seen.setdefault(key, val) != val:
                        bad.add(key)
        return {k: v for k, v in seen.items() if k not in bad and k not in self.other_bound}

    def dotted(self, node: ast.AST) -> "str | None":
        if isinstance(node, ast.Name):
            if node.id in self.table:
                return self.table[node.id]
            if (
                node.id in _BUILTINS_USED
                and not self.star
                and node.id not in self.other_bound
                and node.id not in self.import_bound
            ):
                return "builtins." + node.id
            return None
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
            base = self.dotted(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    def scope_of(self, node: ast.AST) -> "ast.AST | None":
        """The Module or function whose body evaluates *node*; None for anything else."""
        child, cur = node, self.parents.get(node)
        while cur is not None:
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return cur if child in cur.body else None
            if isinstance(cur, (ast.ClassDef, ast.Lambda, ast.ListComp, ast.SetComp,
                                ast.DictComp, ast.GeneratorExp)):
                return None
            child, cur = cur, self.parents.get(cur)
        return self.tree if isinstance(child, ast.Module) else None

    def _own_nodes(self, scope: ast.AST):
        """Nodes evaluated in *scope*: its body, not nested bodies (their decorators,
        defaults and annotations ARE evaluated here, and a walrus there binds here)."""
        stack = list(scope.body)
        while stack:
            n = stack.pop()
            yield n
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                parts = list(getattr(n, "decorator_list", []) or [])
                args = getattr(n, "args", None)
                if args is not None:
                    parts += list(args.defaults) + [d for d in args.kw_defaults if d is not None]
                    for a in (*args.posonlyargs, *args.args, *args.kwonlyargs,
                              args.vararg, args.kwarg):
                        if a is not None and a.annotation is not None:
                            parts.append(a.annotation)
                if getattr(n, "returns", None) is not None:
                    parts.append(n.returns)
                parts += list(getattr(n, "bases", []) or [])
                parts += [k.value for k in (getattr(n, "keywords", []) or [])]
                stack.extend(parts)
                continue
            stack.extend(ast.iter_child_nodes(n))

    def records(self, scope: ast.AST) -> dict:
        """name -> [binding record] for *scope*'s own bindings.

        ("assign", value, node) for `name = value`; ("with", item, node) for
        `with ctx as name:`; ("other", node) for every other binding form -- which makes
        the name ineligible, since its value is then not one expression."""
        if scope in self._records:
            return self._records[scope]
        out: dict = {}

        def add(name, rec):
            out.setdefault(name, []).append(rec)

        def targets(t):
            if isinstance(t, ast.Name):
                yield t.id
            elif isinstance(t, (ast.Tuple, ast.List)):
                for e in t.elts:
                    yield from targets(e)
            elif isinstance(t, ast.Starred):
                yield from targets(t.value)

        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            a = scope.args
            for p in (*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg):
                if p is not None:
                    add(p.arg, ("other", p))
        for n in self._own_nodes(scope):
            if isinstance(n, ast.Assign):
                if len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                    add(n.targets[0].id, ("assign", n.value, n))
                else:
                    for t in n.targets:
                        for name in targets(t):
                            add(name, ("other", n))
            elif isinstance(n, (ast.AugAssign, ast.AnnAssign)):
                for name in targets(n.target):
                    add(name, ("other", n))
            elif isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension)):
                for name in targets(n.target):
                    add(name, ("other", n))
            elif isinstance(n, (ast.With, ast.AsyncWith)):
                for item in n.items:
                    v = item.optional_vars
                    if isinstance(v, ast.Name) and isinstance(n, ast.With):
                        add(v.id, ("with", item, n))
                    elif v is not None:
                        for name in targets(v):
                            add(name, ("other", n))
            elif isinstance(n, ast.NamedExpr):
                for name in targets(n.target):
                    add(name, ("other", n))
            elif isinstance(n, (ast.Import, ast.ImportFrom)):
                for a in n.names:
                    add(a.asname or a.name.split(".")[0], ("other", n))
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                add(n.name, ("other", n))
            elif isinstance(n, ast.ExceptHandler) and n.name:
                add(n.name, ("other", n))
            elif isinstance(n, ast.Delete):
                for t in n.targets:
                    for name in targets(t):
                        add(name, ("other", n))
            elif isinstance(n, (ast.Global, ast.Nonlocal)):
                for name in n.names:
                    add(name, ("other", n))
            elif type(n).__name__.startswith("Match"):
                for field in ("name", "rest"):
                    v = getattr(n, field, None)
                    if isinstance(v, str):
                        add(v, ("other", n))
        self._records[scope] = out
        return out

    def sole(self, name: str, scope: ast.AST, before: "ast.AST | None" = None):
        """The reaching binding of *name* in *scope*, or None.
        One binding: unchanged (a function never falls back to a module global -- another
        file can replace a module attribute after import, and a local cannot). Several:
        disqualified unless *before* is given and every binding is a plain Assign that is
        a direct, unconditional statement of *scope*'s own body (never inside a branch,
        loop, def or class) -- then the last one before *before* in body order wins
        (B-638: a same-scope rebind split across two lines resolves like one nested
        expression); any boundary-crossing or non-Assign binding disqualifies outright."""
        if name == "__file__" or name in self.declared:
            return None
        recs = self.records(scope).get(name, [])
        if len(recs) == 1:
            return None if recs[0][0] == "other" else recs[0]
        if before is None or not recs or any(r[0] != "assign" for r in recs):
            return None
        body = getattr(scope, "body", None) or []
        if any(self.parents.get(r[2]) is not scope or r[2] not in body for r in recs):
            return None
        limit = self._stmt_index(before, scope, body)
        if limit is None:
            return None
        reaching = sorted((body.index(r[2]), r) for r in recs if body.index(r[2]) < limit)
        return reaching[-1][1] if reaching else None

    def _stmt_index(self, node: ast.AST, scope: ast.AST, body: list) -> "int | None":
        """Index in *body* of the statement transitively evaluating *node*, or None."""
        child, cur = node, self.parents.get(node)
        while cur is not None and cur is not scope:
            child, cur = cur, self.parents.get(cur)
        return body.index(child) if cur is scope and child in body else None

    def _legb_blocked(self, name: str) -> bool:
        """Guard for `locate()`'s LEGB fallback (b917-design.md 2.1). A function-scope
        read with no local binding may resolve through an enclosing/module scope --
        but not when this file could later replace what that resolution depends on:
        an attribute store `X.<name> = ...` naming this exact identifier (a plugin
        re-pointing a module constant through some object's attribute of the same
        name), or any of this file's own namespace-tampering spellings (`_tampers()`
        -- reflection/monkeypatch/import-machinery access, which can rebind a
        "module constant" by a route this resolver does not model at all). Sound over
        precise: this only ever REFUSES a resolution, never manufactures one.
        Lazily computed and cached -- most files never take this path."""
        if self._legb_tampers is None:
            self._legb_tampers = _tampers(self.tree)
        if self._legb_tampers:
            return True
        if name not in self._legb_attr_store_cache:
            self._legb_attr_store_cache[name] = any(
                isinstance(n, ast.Attribute) and isinstance(n.ctx, (ast.Store, ast.Del))
                and n.attr == name
                for n in ast.walk(self.tree)
            )
        return self._legb_attr_store_cache[name]

    def _legb_lookup(self, name: str, scope: ast.AST) -> "tuple | None":
        """`(record, defining_scope)` for *name*, found by walking from *scope*
        through each enclosing function scope and finally the module scope (LEGB,
        minus class scope -- a function never sees its enclosing class's namespace,
        matching Python's own scoping rule). No `before`: the read lives in a
        DIFFERENT, nested scope that runs later, so *scope*'s body order does not
        bound it -- `sole()`'s default (`before=None`) already requires exactly one,
        unconditional, direct-body binding, which is what makes this sound.

        Stops at the FIRST enclosing scope that binds *name* at all (B-917 fix
        round 2): `sole()` returning None means either "no record here" or "a
        record exists but is not a single, resolvable, direct-body binding" --
        e.g. a parameter, a for/with/comprehension target, an except-as name, a
        nested def/class, or an import. Real Python scoping makes any of those a
        local of that scope for its ENTIRE body, so the walk must stop there --
        never treat "sole() could not resolve it" as "this scope is free, keep
        walking outward", or an intermediate scope's own (unresolvable) binding of
        the same name gets skipped in favour of a further-out one it does not
        actually shadow to. Only a scope with NO record for *name* at all lets the
        walk continue past it. Returns None when no enclosing scope resolves
        *name* this way (whether never bound, or blocked by an unresolvable
        binding somewhere along the walk)."""
        cur = scope
        while True:
            nxt = self.scope_of(cur)
            if nxt is None:
                return None
            if self.records(nxt).get(name):
                rec = self.sole(name, nxt)
                return (rec, nxt) if rec is not None else None
            if nxt is self.tree:
                return None
            cur = nxt

    def literal(self, node: ast.AST, scope: ast.AST) -> "str | None":
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            rec = self.sole(node.id, scope)
            if rec and rec[0] == "assign":
                v = rec[1]
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    return v.value
        return None

    # ── this file's own blockers ────────────────────────────────────────────────────────

    def _blocked(self, module_names: set) -> bool:
        for n in ast.walk(self.tree):
            # `__file__` may never be anything but the interpreter's own value.
            if isinstance(n, ast.Name) and n.id == "__file__" and not isinstance(n.ctx, ast.Load):
                return True
            if isinstance(n, ast.arg) and n.arg == "__file__":
                return True
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and (
                n.name == "__file__"
            ):
                return True
            if isinstance(n, ast.ExceptHandler) and n.name == "__file__":
                return True
            if isinstance(n, (ast.Global, ast.Nonlocal)) and "__file__" in n.names:
                return True
            if isinstance(n, ast.alias) and "__file__" in (n.name, n.asname):
                return True
            if type(n).__name__.startswith("Match") and "__file__" in (
                getattr(n, "name", None), getattr(n, "rest", None)
            ):
                return True
            # No import of a module the artifact ships, and no relative import.
            if isinstance(n, ast.Import):
                if any(a.name.split(".")[0] in module_names for a in n.names):
                    return True
            if isinstance(n, ast.ImportFrom):
                if n.level or (n.module or "").split(".")[0] in module_names:
                    return True
            # Nothing that rebinds what the read resolves through.
            if isinstance(n, ast.Attribute) and isinstance(n.ctx, (ast.Store, ast.Del)):
                root = self.dotted(n.value)
                if root and root.split(".")[0] in _READ_PATH_ROOTS:
                    return True
            if isinstance(n, ast.Call) and self._side_effect(n):
                return True
        return False

    def _side_effect(self, call: ast.Call) -> bool:
        """Could this call write a file, spawn a process, reach the network or move cwd?"""
        d = self.dotted(call.func)
        if d:
            root = d.split(".")[0]
            if root in _SIDE_EFFECT_ROOTS:
                return True
            if root == "os" and not (d.startswith("os.path.") or d in _OS_SAFE_CALLS):
                return True
            if d in ("builtins.open", "io.open", "codecs.open"):
                return self._open_mode(call, d) is None
        if isinstance(call.func, ast.Attribute):
            if call.func.attr in _WRITE_METHODS:
                return True
            if call.func.attr == "open" and not d:
                # `Path(...).open(mode)`: a method open must be provably read-only too.
                mode = call.args[0] if call.args else next(
                    (k.value for k in call.keywords if k.arg == "mode"), None
                )
                return not self._read_mode(mode)
        return False

    @staticmethod
    def _read_mode(mode: "ast.AST | None") -> "str | None":
        """The literal read-only mode, "r" when absent, else None."""
        if mode is None:
            return "r"
        if not (isinstance(mode, ast.Constant) and isinstance(mode.value, str)):
            return None
        m = mode.value
        if not m or "r" not in m or not set(m) <= set("rbt") or len(set(m)) != len(m):
            return None
        return m

    def _bind_open(self, call: ast.Call, d: str) -> "dict | None":
        """Bind an open-family call's arguments to parameter names, or None if unusual."""
        if d == "codecs.open":
            params = ("filename", "mode", "encoding", "errors", "buffering")
        else:
            params = ("file", "mode", "buffering", "encoding", "errors", "newline")
        if len(call.args) > len(params) or any(isinstance(a, ast.Starred) for a in call.args):
            return None
        bound = dict(zip(params, call.args))
        for k in call.keywords:
            if k.arg is None or k.arg not in params or k.arg in bound:
                return None  # **kw, opener=, closefd=, or a duplicate
            bound[k.arg] = k.value
        return bound

    def _open_mode(self, call: ast.Call, d: str) -> "str | None":
        bound = self._bind_open(call, d)
        return None if bound is None else self._read_mode(bound.get("mode"))

    # ── path resolution ─────────────────────────────────────────────────────────────────

    def resolve(self, e: ast.AST, scope: ast.AST, depth: int = 0) -> "_Path | None":
        if depth > _MAX_DEPTH:
            return None
        if isinstance(e, ast.Name):
            if e.id == "__file__":
                return _Path("str", self.relparts, len(self.relparts))
            rec = self.sole(e.id, scope, before=e)
            if rec is None or rec[0] != "assign":
                return None
            return self.resolve(rec[1], scope, depth + 1)
        if isinstance(e, ast.Attribute) and isinstance(e.ctx, ast.Load) and e.attr == "parent":
            base = self.resolve(e.value, scope, depth + 1)
            return base.up() if base is not None and base.kind == "path" else None
        if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Div):
            base = self.resolve(e.left, scope, depth + 1)
            seg = self.literal(e.right, scope)
            if base is None or base.kind != "path" or seg is None:
                return None
            return base.join(seg)
        if not isinstance(e, ast.Call) or e.keywords or any(
            isinstance(a, ast.Starred) for a in e.args
        ):
            return None
        d = self.dotted(e.func)
        if d:
            if d.startswith(_OSPATH):
                fn = d.rsplit(".", 1)[1]
                if fn in ("dirname", "abspath", "realpath", "normpath") and len(e.args) == 1:
                    base = self.resolve(e.args[0], scope, depth + 1)
                    if base is None:
                        return None
                    return base.up("str") if fn == "dirname" else base.normalised("str")
                if fn == "join" and e.args:
                    return self._join(e.args[0], e.args[1:], scope, depth, "str")
                return None
            if d in ("os.fspath", "builtins.str") and len(e.args) == 1:
                base = self.resolve(e.args[0], scope, depth + 1)
                return None if base is None else _Path("str", base.parts, base.real, base.tail)
            if d in _PATH_CLASSES and e.args:
                return self._join(e.args[0], e.args[1:], scope, depth, "path")
            return None
        if isinstance(e.func, ast.Attribute):
            base = self.resolve(e.func.value, scope, depth + 1)
            if base is None or base.kind != "path":
                return None
            attr = e.func.attr
            if attr in ("resolve", "absolute") and not e.args:
                return base.normalised()
            if attr == "joinpath":
                return self._join_segments(base, e.args, scope)
            if attr == "with_name" and len(e.args) == 1:
                name = self.literal(e.args[0], scope)
                if not name or name in (".", "..") or "/" in name:
                    return None
                parent = base.up()
                return None if parent is None else parent.join(name)
        return None

    def _join(self, first, rest, scope, depth, kind) -> "_Path | None":
        base = self.resolve(first, scope, depth + 1)
        if base is None:
            return None
        return self._join_segments(_Path(kind, base.parts, base.real, base.tail), rest, scope)

    def _join_segments(self, base: _Path, segs, scope) -> "_Path | None":
        cur: "_Path | None" = base
        for s in segs:
            seg = self.literal(s, scope)
            if seg is None or cur is None:
                return None
            cur = cur.join(seg)
        return cur

    # ── B-917: the shared location resolver (loader sinks / staged imports) ────────────

    def locate(self, e: ast.AST, scope: ast.AST, depth: int = 0) -> "Loc | None":
        """Where *e* points, anchored (FILE/CWD/ABS/TEMP/HOME/SYM) -- see `Loc`.

        Reuses `sole()`/`dotted()`/`literal()`/the import table exactly like
        `resolve()` above, which stays untouched: this is a pure addition, never
        called from the B-638 proof path.
        """
        if depth > _MAX_DEPTH:
            return None
        if isinstance(e, ast.Name):
            if e.id == "__file__":
                return Loc("FILE", self.relparts)
            rec, found_scope = self._reaching(e, scope)
            if rec is not None:
                if rec[0] == "assign":
                    return self.locate(rec[1], found_scope, depth + 1)
                if rec[0] == "with":
                    return self.locate(rec[1].context_expr, found_scope, depth + 1)
            # Unresolvable (a parameter, several bindings, a loop/comprehension
            # target, ...) -- still a stable identity: the SAME name in the SAME
            # scope always resolves here the same way, so two reads of it compare
            # DEFINITE while a DIFFERENT unresolvable name never does. `tail`: what
            # its visible bindings say about the final component (`_bindings_suffixed`).
            return Loc("SYM", (), sym=("name", id(scope), e.id),
                       tail="module" if self._bindings_suffixed(e.id, scope) else None)
        if isinstance(e, ast.Attribute) and isinstance(e.ctx, ast.Load) and e.attr == "parent":
            base = self.locate(e.value, scope, depth + 1)
            return base.up() if base is not None else None
        if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Div):
            base = self.locate(e.left, scope, depth + 1)
            if base is None:
                return None
            return self._join_expr(base, e.right, scope)
        if isinstance(e, ast.Constant) and isinstance(e.value, str):
            return self._locate_literal(e.value)
        if (
            isinstance(e, ast.Subscript) and isinstance(e.value, ast.Attribute)
            and e.value.attr == "parents" and isinstance(e.slice, ast.Constant)
            and isinstance(e.slice.value, int) and e.slice.value >= 0
        ):
            base = self.locate(e.value.value, scope, depth + 1)
            cur = base
            for _ in range(e.slice.value + 1):
                if cur is None:
                    return None
                cur = cur.up()
            return cur
        if not isinstance(e, ast.Call) or e.keywords or any(
            isinstance(a, ast.Starred) for a in e.args
        ):
            return None
        d = self.dotted(e.func)
        if d:
            if d.startswith(_OSPATH):
                fn = d.rsplit(".", 1)[1]
                if fn in ("dirname", "abspath", "realpath", "normpath") and len(e.args) == 1:
                    base = self.locate(e.args[0], scope, depth + 1)
                    return base.up() if fn == "dirname" and base is not None else base
                if fn == "join" and e.args:
                    return self._locate_join(e.args[0], e.args[1:], scope, depth)
                if fn == "expanduser" and len(e.args) == 1:
                    return Loc("HOME", ()) if self.literal(e.args[0], scope) == "~" else None
                return None
            if d in ("os.fspath", "builtins.str") and len(e.args) == 1:
                return self.locate(e.args[0], scope, depth + 1)
            if d in _PATH_CLASSES and e.args:
                return self._locate_join(e.args[0], e.args[1:], scope, depth)
            if d == "os.getcwd" and not e.args:
                return Loc("CWD", ())
            if d == "tempfile.gettempdir" and not e.args:
                return Loc("TEMP", ())
            if d == "pathlib.Path.home" and not e.args:
                return Loc("HOME", ())
            # Any other call this resolver does not model (tempfile.mkdtemp(),
            # os.environ.get(...), input(), a remote fetch, ...) is still one
            # identifiable expression -- see the SYM comment above.
            return Loc("SYM", (), sym=("call", id(e)),
                       tail="module" if self._module_suffixed(e, scope) else None)
        if isinstance(e.func, ast.Attribute):
            base = self.locate(e.func.value, scope, depth + 1)
            if base is None:
                return None
            attr = e.func.attr
            if attr in ("resolve", "absolute") and not e.args:
                return base
            if attr == "joinpath":
                cur = base
                for a in e.args:
                    cur = self._join_expr(cur, a, scope)
                return cur
            if attr == "with_name" and len(e.args) == 1:
                name = self.literal(e.args[0], scope)
                if not name or name in (".", "..") or "/" in name:
                    return None
                parent = base.up()
                return None if parent is None else parent.join(name)
            return None
        return None

    def _reaching(self, e: ast.Name, scope: ast.AST) -> tuple:
        """`(record, defining_scope)` for a Name read -- `sole()` in *scope*, then the
        LEGB walk below -- or `(None, scope)`. Shared by `locate()` and
        `_module_suffixed()` so a path and its final component resolve names alike."""
        rec = self.sole(e.id, scope, before=e)
        found_scope = scope
        # LEGB fallback (b917-design.md 2.1), `resolve()` deliberately lacks this:
        # a name read inside a function with no binding in that function (and not
        # declared global/nonlocal -- sole() already refuses those outright) is
        # looked up in its enclosing function scopes and then the module scope.
        # Required for the r2-D1 shape: a module constant read inside a function.
        #
        # Gated on "no record for e.id in *scope* at all" (B-917 fix round 2),
        # never on "sole() returned None" alone: sole() also returns None when
        # *scope* DOES bind the name, just not through one resolvable, direct
        # assignment (a parameter, a for/with/comprehension target, an
        # except-as name, ...). That binding makes the name local to *scope*
        # for its entire body -- real Python scoping never falls back to an
        # enclosing/module scope for it, resolvable or not. Walking past it
        # (e.g. because a same-named module constant exists) is a false
        # correlation: a `def load_plugin(CACHE_DIR): ... import x` whose
        # parameter merely shares a name with an unrelated module-level
        # `CACHE_DIR` must resolve to SYM, not to the module constant.
        if (
            rec is None
            and not self._legb_blocked(e.id)
            and not self.records(scope).get(e.id)
        ):
            found = self._legb_lookup(e.id, scope)
            if found is not None:
                rec, found_scope = found
        return rec, found_scope

    def _join_expr(self, base: "Loc", seg_expr: ast.AST, scope: ast.AST) -> "Loc":
        """`base.join()` one path-segment EXPRESSION. A segment `literal()` cannot read
        still says something about the path's final component when how it is built
        carries a module-file extension (`f"{name}.py"`) -- recorded as `Loc.tail`."""
        seg = self.literal(seg_expr, scope)
        if seg is not None:
            return base.join(seg)
        return base.join(None, module_tail=self._module_suffixed(seg_expr, scope))

    def _module_suffixed(self, e: ast.AST, scope: ast.AST, depth: int = 0) -> bool:
        """Could the string *e* produces be a module file's name, going by what is
        visible in how it is built? True when any string literal in it -- or in a
        binding of any name it reads (`_bindings_suffixed`) -- ends in a module-file
        suffix or is a bare module extension (`f"{n}.py"`, `n + ".py"`,
        `s.replace(".tmp", ".py")`, `".".join([n, "py"])`). Evidence, not proof: it
        only ever keeps a staged-import question open, never closes one."""
        if depth > _MAX_DEPTH:
            return False
        for n in ast.walk(e):
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                v = n.value.casefold()
                if v.endswith(_MODULE_FILE_SUFFIXES) or "." + v in _MODULE_FILE_SUFFIXES:
                    return True
            elif isinstance(n, ast.Name) and self._bindings_suffixed(n.id, scope, depth + 1):
                return True
        return False

    def _bindings_suffixed(self, name: str, scope: ast.AST, depth: int = 0) -> bool:
        """`_module_suffixed` over EVERY assignment of *name* in the nearest scope
        (from *scope* outward) that binds it at all -- all of them, not just a
        single reaching one, so a conditionally rebound destination still counts."""
        if depth > _MAX_DEPTH:
            return False
        cur = scope
        while cur is not None:
            recs = self.records(cur).get(name)
            if recs:
                return any(
                    (r[0] == "assign" and self._module_suffixed(r[1], cur, depth + 1))
                    or (r[0] == "with"
                        and self._module_suffixed(r[1].context_expr, cur, depth + 1))
                    for r in recs
                )
            if cur is self.tree:
                return False
            cur = self.scope_of(cur)
        return False

    def _locate_literal(self, s: str) -> "Loc":
        if s.startswith("/"):
            return Loc("ABS", tuple(p for p in s.split("/") if p not in ("", ".")))
        return Loc("CWD", ()).join(s)

    def _locate_join(self, first: ast.AST, rest, scope: ast.AST, depth: int) -> "Loc | None":
        base = self.locate(first, scope, depth + 1)
        if base is None:
            return None
        cur = base
        for s in rest:
            cur = self._join_expr(cur, s, scope)
        return cur

    def shipped(self, path_node: ast.AST, scope: ast.AST) -> "str | None":
        """The analysed artifact file *path_node* names, or None."""
        p = self.resolve(path_node, scope)
        if p is None or not p.parts:
            return None
        rel = "/".join(p.parts)
        return rel if rel in self.artifact.exec_paths or self.any_target else None

    # ── the executed value ──────────────────────────────────────────────────────────────

    def _open_read(self, call: ast.AST, scope: ast.AST) -> "tuple | None":
        """(kind, target) for an open-family call that reads a whole shipped file."""
        if not isinstance(call, ast.Call):
            return None
        d = self.dotted(call.func)
        if d not in ("builtins.open", "io.open", "codecs.open"):
            return None
        bound = self._bind_open(call, d)
        if bound is None:
            return None
        mode = self._read_mode(bound.get("mode"))
        if mode is None:
            return None
        if not (_utf8_literal(bound.get("encoding")) and _strict_literal(bound.get("errors"))):
            return None
        for k in ("buffering", "newline"):
            if k in bound and not isinstance(bound[k], ast.Constant):
                return None
        path = bound.get("file", bound.get("filename"))
        target = None if path is None else self.shipped(path, scope)
        if target is None:
            return None
        explicit = bound.get("encoding") is not None and not (
            isinstance(bound.get("encoding"), ast.Constant) and bound["encoding"].value is None
        )
        decoded = d == "codecs.open" and explicit
        kind = "bytes" if "b" in mode and not decoded else "str"
        if kind == "str" and not explicit and not self._locale_proof(target):
            return None
        return (kind, target)

    def _locale_proof(self, target: str) -> bool:
        """A text read with no encoding decodes with the process locale, which code can
        change at run time (`locale.setlocale`) to one where a byte pair swallows a `\\`
        (GB18030, Shift_JIS) and moves a string boundary the scan saw. Only an all-ASCII
        file reads the same under every locale Python accepts."""
        return self.artifact.sources.get(target, "").isascii()

    def _inside_body(self, node: ast.AST, stmt: ast.AST) -> bool:
        """Is *node* evaluated by one of `stmt.body`'s statements, in the same scope?"""
        child, cur = node, self.parents.get(node)
        while cur is not None:
            if cur is stmt:
                return child in stmt.body
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                                ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp,
                                ast.GeneratorExp)):
                return False
            child, cur = cur, self.parents.get(cur)
        return False

    def _handle_uses_ok(self, name: str, region, read_call: ast.Call) -> bool:
        """Inside *region*, is *name* only read by `read_call` (plus any `.close()`)?"""
        reads = 0
        for n in region:
            for x in ast.walk(n):
                if not (isinstance(x, ast.Name) and x.id == name):
                    continue
                if not isinstance(x.ctx, ast.Load):
                    return False
                parent = self.parents.get(x)
                call = self.parents.get(parent)
                if not (isinstance(parent, ast.Attribute) and isinstance(call, ast.Call)
                        and call.func is parent):
                    return False
                if call is read_call:
                    reads += 1
                elif parent.attr != "close" or call.args or call.keywords:
                    return False
        return reads == 1

    def _read_call(self, call: ast.Call, scope: ast.AST) -> "tuple | None":
        """(kind, target) when *call* is `<handle>.read()` of a whole shipped file."""
        recv = call.func.value
        if isinstance(recv, ast.Call):
            return self._open_read(recv, scope)
        if not isinstance(recv, ast.Name) or recv.id in self.declared:
            return None
        name = recv.id
        # `with open(P) as h: ... h.read()` -- the nearest enclosing `with` binding h.
        cur = self.parents.get(call)
        while cur is not None and cur is not scope:
            if isinstance(cur, ast.With) and any(
                isinstance(i.optional_vars, ast.Name) and i.optional_vars.id == name
                for i in cur.items
            ):
                items = [i for i in cur.items
                         if isinstance(i.optional_vars, ast.Name) and i.optional_vars.id == name]
                if len(items) != 1 or not self._inside_body(call, cur):
                    return None
                others = [i.context_expr for i in cur.items if i is not items[0]]
                others += [i.optional_vars for i in cur.items
                           if i is not items[0] and i.optional_vars is not None]
                if any(isinstance(x, ast.Name) and x.id == name
                       for o in others for x in ast.walk(o)):
                    return None
                if not self._handle_uses_ok(name, cur.body, call):
                    return None
                return self._open_read(items[0].context_expr, scope)
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                                ast.Lambda)):
                break
            cur = self.parents.get(cur)
        # `h = open(P)` bound once in this scope, touched by nothing else.
        rec = self.sole(name, scope, before=call)
        if rec is None or rec[0] != "assign":
            return None
        region = [self.tree] if scope is self.tree else [scope]
        uses = [x for r in region for x in ast.walk(r)
                if isinstance(x, ast.Name) and x.id == name and isinstance(x.ctx, ast.Load)]
        if not uses or not self._handle_uses_ok(name, [u for u in uses], call):
            return None
        return self._open_read(rec[1], scope)

    def content(self, e: ast.AST, scope: ast.AST, covered: list, depth: int = 0):
        """(kind, target) when *e* evaluates to exactly a shipped file's content, where
        kind is "str", "bytes" or "code"; None otherwise. Calls it relies on go into
        *covered* so the artifact-wide stray-dynamic-code scan can tell them apart."""
        if depth > _MAX_DEPTH:
            return None
        if isinstance(e, ast.Name):
            rec = self.sole(e.id, scope, before=e)
            if rec is None or rec[0] != "assign":
                return None
            return self.content(rec[1], scope, covered, depth + 1)
        if not isinstance(e, ast.Call) or any(isinstance(a, ast.Starred) for a in e.args):
            return None
        d = self.dotted(e.func)
        if d == "builtins.compile":
            if len(e.args) != 3 or e.keywords:
                return None
            mode = e.args[2]
            if not (isinstance(mode, ast.Constant) and mode.value in ("exec", "eval", "single")):
                return None
            inner = self.content(e.args[0], scope, covered, depth + 1)
            if inner is None or inner[0] != "str":
                return None
            covered.append(e)
            return ("code", inner[1])
        if not isinstance(e.func, ast.Attribute) or d:
            return None
        attr = e.func.attr
        if attr == "decode":
            if len(e.args) > 2 or any(k.arg not in ("encoding", "errors") for k in e.keywords):
                return None
            kw = {k.arg: k.value for k in e.keywords}
            enc = e.args[0] if e.args else kw.get("encoding")
            err = e.args[1] if len(e.args) > 1 else kw.get("errors")
            if not (_utf8_literal(enc) and _strict_literal(err)):
                return None
            inner = self.content(e.func.value, scope, covered, depth + 1)
            return ("str", inner[1]) if inner is not None and inner[0] == "bytes" else None
        if attr == "read" and not e.args and not e.keywords:
            return self._read_call(e, scope)
        if attr in ("read_text", "read_bytes") and not e.args and not self.pathlib_tampered:
            allowed = {"encoding", "errors", "newline"} if attr == "read_text" else set()
            kw = {k.arg: k.value for k in e.keywords}
            if any(k not in allowed for k in kw):
                return None
            if not (_utf8_literal(kw.get("encoding")) and _strict_literal(kw.get("errors"))):
                return None
            p = self.resolve(e.func.value, scope)
            if p is None or p.kind != "path" or not p.parts:
                return None
            rel = "/".join(p.parts)
            if rel not in self.artifact.exec_paths and not self.any_target:
                return None
            enc = kw.get("encoding")
            if attr == "read_text" and (enc is None or (
                isinstance(enc, ast.Constant) and enc.value is None
            )) and not self._locale_proof(rel):
                return None
            return ("str" if attr == "read_text" else "bytes", rel)
        return None

    def _namespace_ok(self, arg: ast.AST, scope: ast.AST, call: ast.Call) -> bool:
        """An empty dict, or a name bound once to one, handed to THIS call alone and only
        ever read otherwise. A namespace shared by two calls lets the first file executed
        pre-load names (`open`, `__file__`) the second file resolves through."""
        if isinstance(arg, ast.Dict) and not arg.keys:
            return True
        if (isinstance(arg, ast.Call) and self.dotted(arg.func) == "builtins.dict"
                and not arg.args and not arg.keywords):
            return True
        if not isinstance(arg, ast.Name):
            return False
        rec = self.sole(arg.id, scope, before=arg)
        if rec is None or rec[0] != "assign" or not self._namespace_ok(rec[1], scope, call):
            return False
        region = self.tree if scope is self.tree else scope
        for x in ast.walk(region):
            if not (isinstance(x, ast.Name) and x.id == arg.id):
                continue
            parent = self.parents.get(x)
            if parent is rec[2] and not isinstance(x.ctx, ast.Load):
                continue  # the binding itself
            if not isinstance(x.ctx, ast.Load):
                return False
            if isinstance(parent, ast.Subscript) and parent.value is x and isinstance(
                parent.ctx, ast.Load
            ):
                continue
            if isinstance(parent, ast.Compare):
                continue
            grand = self.parents.get(parent)
            if (isinstance(parent, ast.Attribute) and parent.attr in _NS_READ_METHODS
                    and isinstance(grand, ast.Call) and grand.func is parent):
                continue
            if parent is call and x in call.args[1:]:
                continue
            return False
        return True

    def _constants_only(self, target: str) -> bool:
        """Is *target* nothing but literal assignments to names this file never uses?"""
        tree = self.artifact.trees.get(target)
        if tree is None:
            return False
        # A constant cannot be called into doing anything, so the only harm left is
        # REBINDING something this file binds, imports or resolves its proof through.
        mine = self.other_bound | self.import_bound | set(self.table) | _MODULE_MAGIC
        mine |= _BUILTINS_USED

        def literal(v) -> bool:
            if isinstance(v, ast.Constant):
                return True
            if isinstance(v, (ast.Tuple, ast.List, ast.Set)):
                return all(literal(e) for e in v.elts)
            if isinstance(v, ast.Dict):
                return all(k is not None and literal(k) for k in v.keys) and all(
                    literal(x) for x in v.values
                )
            return isinstance(v, ast.UnaryOp) and isinstance(v.operand, ast.Constant)

        for stmt in tree.body:
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                continue  # a docstring
            if isinstance(stmt, ast.Assign) and literal(stmt.value) and all(
                isinstance(t, ast.Name) and t.id not in mine for t in stmt.targets
            ):
                continue
            if (isinstance(stmt, ast.AnnAssign) and stmt.value is not None
                    and literal(stmt.value)
                    and isinstance(stmt.annotation, (ast.Name, ast.Constant))
                    and isinstance(stmt.target, ast.Name) and stmt.target.id not in mine):
                continue  # a module-level annotation IS evaluated: a bare name only
            return False
        return True

    def exact_calls(self) -> "tuple[list, list, list]":
        """(exec/eval calls proven to run exactly a shipped file, every call they use,
        (call, target) for calls that meet every condition but one: their target is a path
        inside the artifact that it does not ship as analysed Python)."""
        if self.blocked:
            return [], [], []
        exact, covered = self._exact_pass()
        done = {id(c) for c, _ in exact}
        self.any_target = True
        try:
            loose, loose_used = self._exact_pass()
        finally:
            self.any_target = False
        unshipped = [(c, t) for c, t in loose if id(c) not in done]
        covered.extend(loose_used)
        return [c for c, _ in exact], covered, unshipped

    def _exact_pass(self) -> "tuple[list, list]":
        exact: list = []
        covered: list = []
        for n in ast.walk(self.tree):
            if not (isinstance(n, ast.Call) and self.dotted(n.func) in _EXEC_CALLS):
                continue
            if n.keywords or not 1 <= len(n.args) <= 3 or any(
                isinstance(a, ast.Starred) for a in n.args
            ):
                continue
            scope = self.scope_of(n)
            if scope is None:
                continue
            used: list = []
            got = self.content(n.args[0], scope, used)
            if got is None or got[0] not in ("str", "code"):
                continue
            if not all(self._namespace_ok(a, scope, n) for a in n.args[1:]):
                continue
            if len(n.args) == 1 and got[1] in self.artifact.sources and not (
                self._constants_only(got[1])
            ):
                # No namespace: the target runs in THIS file's own globals. It reads names
                # its standalone analysis never saw bound and can rebind `open`, `here` or
                # `__name__` under this file's later code. Only a file of plain constant
                # assignments to names this file does not use is the same as importing it.
                # (An unshipped target's content is unknown anyway -- that is the WARN tier.)
                continue
            exact.append((n, got[1]))
            covered.extend(used)
        return exact, covered


# B-917: writable-by-anyone literal prefixes for the loader-sink world-writable tier
# (T3). Deliberately narrow -- these are the shapes the ticket's own PoCs use
# (`/tmp/...`) and the ones `tempfile.gettempdir()` resolves to on every POSIX target
# this project supports; a bespoke writable mount is not guessable statically.
_WRITABLE_PATH_PREFIXES = (("tmp",), ("var", "tmp"), ("dev", "shm"))
# The file-name endings a standard path-based import finder loads a module from:
# source, legacy/optimised bytecode and extension modules (every platform tag of an
# extension suffix ends in ".so"/".pyd"). Used only to read what a COMPUTED final path
# component (`Loc.tail`) is known to be.
_MODULE_FILE_SUFFIXES = (".py", ".pyw", ".pyc", ".pyo", ".pyd", ".so")


class Loc:
    """A statically resolved location for the B-917 loader-sink / staged-import
    correlation, distinct from `_Path` (which `resolve()` uses for the B-638 proof
    above and stays byte-identical here).

    `anchor` is one of ``"FILE"`` (the artifact file's own directory, `parts` are
    artifact-root-relative -- the same convention `_Path`/`resolve()` uses),
    ``"CWD"`` (the process working directory), ``"ABS"`` (an absolute literal),
    ``"TEMP"`` (`tempfile.gettempdir()`), ``"HOME"`` (the user's home directory), or
    ``"SYM"`` (an expression this resolver cannot read through, but can still tell
    apart from a DIFFERENT such expression by identity -- `sym` is the id of its
    single reaching definition, or of the call itself when there is none to bind).

    `exact` is False once a `join()` had to drop a segment it could not read as a
    literal (an f-string suffix, a computed name): the anchor and whatever was
    resolved so far are kept (still enough to answer "is this under a writable
    directory"), but a caller doing exact-location correlation (B-917 section C)
    should not trust `parts` past that point.

    `tail` says what is known about the path's FINAL component when it is not the
    literal `parts[-1]`: ``"module"`` when how it is built visibly carries a
    module-file extension (`_MODULE_FILE_SUFFIXES`, e.g. `f"{name}.py"` --
    `_FileFacts._module_suffixed`), ``"opaque"`` when a `join()` dropped it with no
    such evidence, None otherwise (it is `parts[-1]`, or, for a bare SYM, nothing
    is known). b917-design.md 2.1's `leaf` / `leaf_py` for a computed leaf; read by
    the staged-import correlation, never by `loc_eq()`.
    """

    __slots__ = ("anchor", "parts", "sym", "exact", "tail")

    def __init__(self, anchor: str, parts: tuple, sym=None, exact: bool = True,
                 tail: "str | None" = None) -> None:
        self.anchor = anchor
        self.parts = parts
        self.sym = sym
        self.exact = exact
        self.tail = tail

    def __repr__(self) -> str:  # pragma: no cover - debug aid only
        return (f"Loc({self.anchor!r}, {self.parts!r}, sym={self.sym!r}, "
                f"exact={self.exact!r}, tail={self.tail!r})")

    @property
    def final_name(self) -> "str | None":
        """The path's final component when it is a known literal, else None."""
        return self.parts[-1] if self.parts and self.tail is None else None

    @property
    def leaf_py(self) -> bool:
        return bool(self.parts) and self.parts[-1].lower().endswith(".py")

    @property
    def writable(self) -> bool:
        """Is this location under a directory anyone on the box can write to?"""
        if self.anchor == "TEMP":
            return True
        if self.anchor != "ABS" or not self.parts:
            return False
        return any(
            self.parts[: len(pfx)] == pfx for pfx in _WRITABLE_PATH_PREFIXES
        )

    def up(self) -> "Loc | None":
        if not self.parts:
            return None
        return Loc(self.anchor, self.parts[:-1], self.sym, self.exact)

    def join(self, seg: "str | None", module_tail: bool = False) -> "Loc":
        """Append one literal path segment, or -- when `seg` is None (the caller
        could not read it as a literal, e.g. an f-string) or otherwise unusable --
        keep this location's anchor and parts as-is but mark the result inexact
        (B-917: this is what lets `tempfile.gettempdir()` joined with an
        f-string-named leaf still register as a writable TEMP location, matching the
        real `_config_sync.py`-shaped malicious corpus case). The dropped segment
        becomes the result's `tail`: ``"module"`` when the caller found module-file
        evidence in it (*module_tail*), else ``"opaque"``."""
        if seg is None or "\x00" in seg or "\\" in seg or ":" in seg:
            known = module_tail or (
                seg is not None and seg.casefold().endswith(_MODULE_FILE_SUFFIXES)
            )
            return Loc(self.anchor, self.parts, self.sym, False,
                       "module" if known else "opaque")
        if seg.startswith("/"):
            parts = tuple(p for p in seg.split("/") if p not in ("", "."))
            return Loc("ABS", parts, None, True)
        parts = list(self.parts)
        tail = self.tail  # a segment of only "."/"" leaves the final component as is
        for c in seg.split("/"):
            if c in ("", "."):
                continue
            tail = None
            if c == "..":
                if parts:
                    parts.pop()
            else:
                parts.append(c)
        return Loc(self.anchor, tuple(parts), self.sym, self.exact, tail)


def loc_eq(a: "Loc | None", b: "Loc | None") -> str:
    """``"DEFINITE"``, ``"UNDETERMINED"`` or ``"DEFINITE_NOT"`` -- B-917 section A.

    Deciding a verdict from location EQUALITY rather than a one-sided "is this
    spelling foreign" predicate is the fix for the R2/R3 churn `b917-design.md`
    documents: a predicate over one side of a write/import pair cannot answer a
    question about both sides.
    """
    if a is None or b is None:
        return "UNDETERMINED"
    if a.anchor == "SYM" or b.anchor == "SYM":
        if (
            a.anchor == "SYM" and b.anchor == "SYM"
            and a.sym is not None and a.sym == b.sym and a.parts == b.parts
        ):
            return "DEFINITE"
        return "UNDETERMINED"
    # CWD and FILE are the one anchor pair that can be the SAME directory at run
    # time (a script invoked from its own directory) without any static evidence
    # either way -- so a mismatch between exactly these two is uncertain, never a
    # confident non-match, but ONLY once the rest of the path already lines up;
    # two different subpaths are still unrelated regardless of which of CWD/FILE
    # either one turns out to mean.
    cwd_file_pair = {a.anchor, b.anchor} <= {"CWD", "FILE"}
    if a.anchor != b.anchor and not cwd_file_pair:
        return "DEFINITE_NOT"
    if a.parts == b.parts:
        return "DEFINITE" if a.anchor == b.anchor else "UNDETERMINED"
    return "DEFINITE_NOT"


class ShippedArtifact:
    """The Python files of one artifact, as the caller analyses them (B-638).

    *files* is every ``(relpath, source)`` pair the caller runs ``analyze_python`` over
    for this artifact; *exec_paths* optionally narrows which of them may be the TARGET of
    an exec (default: all of them except notebooks, whose analysed source is extracted
    code cells rather than the bytes on disk). Pass it to ``analyze_python(artifact=...)``.
    Computed lazily and once; cheap when no file mentions ``exec``/``eval``.
    """

    def __init__(self, files, exec_paths=None, root=None) -> None:
        self.sources: dict = {}
        self.trees: dict = {}
        # The artifact's directory on disk, used ONLY to tell a target that is genuinely
        # absent from one that exists but was not analysed (see `_absent`). None means the
        # caller cannot say, so no call is ever classed "unshipped" and each keeps its
        # conviction.
        self.root = root
        self._root_ok: "bool | None" = None
        # Every file, including a duplicate or an oddly-named one: all of them are
        # checked for tampering and stray dynamic code, only `sources` can be a target.
        self._all: list = []
        for rel, src in files:
            norm = _norm_relpath(rel)
            first = norm is not None and norm not in self.sources
            if first:
                self.sources[norm] = src
            self._all.append((norm if first else None, src))
        if exec_paths is None:
            exec_paths = [r for r in self.sources if not r.lower().endswith(".ipynb")]
        self.exec_paths = frozenset(
            n for n in (_norm_relpath(r) for r in exec_paths)
            if n is not None and n in self.sources and not n.lower().endswith(".ipynb")
        )
        self._sites: "dict | None" = None

    def classify(self, relpath: str) -> str:
        """B-917 tier T4: is *relpath* (already artifact-root-relative, as a `Loc`'s
        FILE-anchored `parts` are) ``"analysed"`` (this scan read it as Python),
        ``"absent"`` (provably not on disk -- see `_absent`), or
        ``"present_unanalysed"`` (on disk, or we cannot tell, but not analysed as
        Python -- a notebook, a non-Python file, or nothing this call can verify
        either way)? Never raises; a caller with no filesystem to check against
        (`root=None`) gets ``"present_unanalysed"`` for anything it does not already
        hold as analysed source, which is the conservative (never-crit) answer."""
        norm = _norm_relpath(relpath)
        if norm is None:
            return "present_unanalysed"
        if norm in self.exec_paths:
            return "analysed"
        if self._absent(norm):
            return "absent"
        return "present_unanalysed"

    def exact_exec_sites(self, relpath: str, source: str) -> frozenset:
        """(lineno, col_offset) of every exec/eval call in *relpath* that provably runs
        exactly a file this artifact ships. Empty unless *source* is the text this
        artifact holds for *relpath*."""
        return self._lookup(relpath, source)[0]

    def unshipped_exec_sites(self, relpath: str, source: str) -> dict:
        """(lineno, col_offset) -> target, for exec/eval calls that meet every condition
        of the proof except one: the path they read resolves inside the artifact, but the
        artifact does not ship it as analysed Python. What runs there is unknown -- neither
        proven benign nor evidence of anything (Golden Rule #4)."""
        return self._lookup(relpath, source)[1]

    def _lookup(self, relpath: str, source: str) -> tuple:
        norm = _norm_relpath(relpath)
        if norm is None or self.sources.get(norm) != source:
            return frozenset(), {}
        if self._sites is None:
            self._sites = self._compute()
        return self._sites.get(norm, (frozenset(), {}))

    def _compute(self) -> dict:
        if not any(_EXEC_WORD_RE.search(src) for _, src in self._all):
            return {}
        names = _module_names(self.sources)
        if names & _SHADOW_SENSITIVE:
            return {}
        trees: list = []
        for rel, src in self._all:
            try:
                tree = ast.parse(src)
            except (SyntaxError, ValueError, RecursionError, MemoryError, OverflowError):
                return {}  # a file we cannot read could do anything listed above
            if _tampers(tree):
                return {}
            trees.append((rel, tree))
            if rel is not None:
                self.trees[rel] = tree
        pathlib_tampered = any(_pathlib_tampers(t) for _, t in trees)
        sites: dict = {}
        for rel, tree in trees:
            facts = _FileFacts(tree, rel or "", self, names, pathlib_tampered)
            exact, covered, unshipped = facts.exact_calls() if rel else ([], [], [])
            ok = set(map(id, exact)) | set(map(id, covered)) | {id(c) for c, _ in unshipped}
            for n in ast.walk(tree):
                # Any OTHER reference to exec/eval/compile -- a call we could not prove,
                # or the builtin taken as a value -- is dynamic code we cannot see into.
                if isinstance(n, ast.Name) and facts.dotted(n) in _DYNAMIC_CODE:
                    call = facts.parents.get(n)
                    if not (isinstance(call, ast.Call) and call.func is n and id(call) in ok):
                        return {}
            if rel:
                sites[rel] = (
                    frozenset((c.lineno, c.col_offset) for c in exact),
                    {(c.lineno, c.col_offset): t for c, t in unshipped if self._absent(t)},
                )
        return sites

    def _absent(self, target: str) -> bool:
        """Is *target* provably NOT on disk in the artifact?

        Asked of the filesystem, one component at a time with `lstat`, because no listing
        a collector keeps can answer it: the skill walk skips a symlinked DIRECTORY without
        a trace, so `demo_plugin -> /tmp/x` and "no demo_plugin at all" look the same in
        every record. A component that is a symlink, a path that exists but was not
        analysed (over a cap, unreadable, not Python, under a directory the collectors
        never enter) or any error other than "no such file" means the content is there and
        unknown -- it keeps its conviction. Only a real absence moves to the WARN tier.
        Read-only: `lstat` never follows a link and never opens a file."""
        if self.root is None or target in self.sources:
            return False
        parts = target.split("/")
        if any(p in _UNREAD_DIRS for p in parts) or not self._root_verified():
            return False
        cur = str(self.root)
        for comp in parts:
            cur = os.path.join(cur, comp)
            try:
                st = os.lstat(cur)
            except (FileNotFoundError, NotADirectoryError):
                return True
            except OSError:
                return False
            if stat.S_ISLNK(st.st_mode):
                return False
        return False

    def _root_verified(self) -> bool:
        """Is `root` really the directory these files were read from? Every analysed file
        must sit under it as a regular file. A caller that fell back to the wrong directory
        (a whole home rather than the skill) fails this and gets no WARN tier at all."""
        if self._root_ok is None:
            ok = bool(self.exec_paths)
            try:
                ok = ok and stat.S_ISDIR(os.stat(str(self.root)).st_mode)
                for rel in self.exec_paths:
                    if not ok:
                        break
                    ok = stat.S_ISREG(os.lstat(os.path.join(str(self.root), rel)).st_mode)
            except (OSError, ValueError):
                ok = False
            self._root_ok = ok
        return self._root_ok


class PathFacts(_FileFacts):
    """A `_FileFacts` for ONE file with no shipped-artifact context (B-917) -- for a
    caller (skillast.py's loader-sink / staged-import checks) that needs
    `locate()`/`sole()`/`dotted()`/`literal()` on a file without an artifact to prove
    anything against (`analyze_python`'s `artifact` kwarg is optional). Built on a
    throwaway one-file `ShippedArtifact` so `.shipped()`/`.content()`/`exact_calls()`
    -- irrelevant here -- simply never find a target to claim, which is the correct,
    conservative answer when there is nothing to check membership against."""

    def __init__(self, tree: ast.AST, relpath: str) -> None:
        lone = ShippedArtifact([(relpath, "")])
        super().__init__(tree, relpath, lone, module_names=set(),
                          pathlib_tampered=_pathlib_tampers(tree))
