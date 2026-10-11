"""C-664: no raw JSON decode of a document may be added anywhere in ``clawseccheck/``.

``json.loads`` / ``json.load`` and ``ast.literal_eval`` (what ``loads_json5`` falls back to)
recurse once per nesting level, so a document nested deeper than the interpreter's stack
raises ``RecursionError`` - or, on a small thread stack, overflows the C stack - instead of
the ``ValueError`` every caller's handler expects. A file an attacker (or a corrupted state
store) can pad with brackets then crashes the whole audit, or reads as an unreadable file in a
place that should have disclosed one. The sanctioned readers live in
``clawseccheck/configloader.py``:

  * ``loads_bounded`` - refuses a document nested deeper than a fixed bound with a
    ``ValueError`` (``JSONNestingError``), for state the user owns;
  * ``loads_shallow`` - reads a document of any depth, eliding the part below a bound with a
    marker the consumer must tolerate, for third-party and agent-shaped content.

This guard AST-scans every ``clawseccheck/**/*.py`` and fails on any other decode of a
document, under any spelling:

  * ``<json alias>.loads`` / ``.load`` / ``.JSONDecoder`` / ``.raw_decode`` / ``.decoder`` /
    ``.scanner`` (and the scanner constructors, ``__dict__``), for every alias the module binds
    (``import json``, ``import json as _json``, ``import json.decoder as d``, ``j = json``,
    ``from pkg import json``);
  * names imported with ``from json import loads`` / ``load`` / ``JSONDecoder`` /
    ``decoder`` / ``scanner`` (``from json.decoder import JSONDecoder``, ...), the import and
    every use of the bound name;
  * ``getattr(json, "loads")`` (or a computed name), ``importlib.import_module("json")``,
    ``__import__("json")``, ``sys.modules["json"]``;
  * ``ast.literal_eval`` of anything that is not a constant node;
  * ``loads_json5`` (and its lenient half) used anywhere but ``configloader.py``.

``configloader.py`` is exempt as a whole (it implements the sanctioned readers). Everything
else that still calls a raw decoder is in the COUNTED allowlist ``_RAW_DECODE_ALLOWLIST``
below: each entry names module + enclosing function + canonical spelling, an exact count, and
the one-line reason the site is acceptable or a recorded residual of C-664. A NEW raw decode in
a listed function still fails (the count is exact), and an entry whose site disappeared fails
too (a stale allowlist is a hole). The scanner is exercised against synthetic modules so the
guard is shown to be able to fail.
"""
from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path

import pytest

pytestmark = pytest.mark.mechanical

_ROOT = Path(__file__).resolve().parents[1]
_PKG = _ROOT / "clawseccheck"

# The one module that implements the sanctioned readers; exempt as a whole.
_EXEMPT_MODULE = "clawseccheck/configloader.py"

# Attributes of the json module (or its submodules) that decode a document or hand out the
# machinery that does. `JSONDecodeError`, `dumps`, `dump`, `JSONEncoder` are not here.
_JSON_DECODE_ATTRS = frozenset({
    "loads", "load", "JSONDecoder", "raw_decode", "decoder", "scanner",
    "make_scanner", "py_make_scanner", "c_make_scanner", "__dict__",
})
# `from json import X` / `from json.decoder import X` / `from json.scanner import X`.
_JSON_FROM_NAMES = {
    "json": frozenset({"loads", "load", "JSONDecoder", "decoder", "scanner"}),
    "json.decoder": frozenset({"JSONDecoder"}),
    "json.scanner": frozenset({"make_scanner", "py_make_scanner", "c_make_scanner"}),
}
# The JSON5 reader and its lenient half: configloader.py only.
_JSON5_NAMES = frozenset({"loads_json5", "_loads_json5_lenient"})


def _parents(tree: ast.AST) -> dict:
    out = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            out[child] = node
    return out


def _qualname(node: ast.AST, parents: dict) -> str:
    names = []
    cur = node
    while cur in parents:
        cur = parents[cur]
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.append(cur.name)
    return ".".join(reversed(names)) or "<module>"


def _const_str(node: ast.AST) -> "str | None":
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_json_module_name(name: "str | None") -> bool:
    return name is not None and (name == "json" or name.startswith("json."))


class _Aliases:
    """Per-module name resolution, collected over the whole tree (function-local imports
    included): which names are the json / ast / importlib / sys modules, which bare names are
    a decoder imported from json, a ``literal_eval`` or a JSON5 reader."""

    def __init__(self, tree: ast.AST):
        self.json: set = set()
        self.ast: set = set()
        self.importlib: set = set()
        self.sys: set = set()
        self.json_from: dict = {}      # local name -> json attribute it was imported as
        self.literal_eval: set = set()  # local names bound to ast.literal_eval
        self.import_module: set = set()  # local names bound to importlib.import_module
        self.json5: dict = {}          # local name -> loads_json5 / _loads_json5_lenient
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    top = a.name.split(".")[0]
                    if _is_json_module_name(a.name):
                        # `import json.decoder` binds `json`; `... as d` binds the submodule.
                        self.json.add(a.asname or "json")
                    elif top == "ast":
                        self.ast.add(a.asname or "ast")
                    elif top == "importlib" and a.name == "importlib":
                        self.importlib.add(a.asname or "importlib")
                    elif top == "sys":
                        self.sys.add(a.asname or "sys")
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for a in node.names:
                    local = a.asname or a.name
                    if mod in _JSON_FROM_NAMES and a.name in _JSON_FROM_NAMES[mod]:
                        self.json_from[local] = a.name
                    if a.name == "json":
                        self.json.add(local)  # `from pkg import json` (a re-export)
                    if mod == "ast" and a.name == "literal_eval":
                        self.literal_eval.add(local)
                    if mod == "importlib" and a.name == "import_module":
                        self.import_module.add(local)
                    if a.name in _JSON5_NAMES:
                        self.json5[local] = a.name
        # `j = json` / `j = importlib.import_module("json")` / `j = __import__("json")` /
        # `j = sys.modules["json"]`: iterate to a fixpoint so chains resolve.
        changed = True
        while changed:
            changed = False
            for node in ast.walk(tree):
                if not isinstance(node, ast.Assign) or not isinstance(node.value, (
                        ast.Name, ast.Attribute, ast.Call, ast.Subscript)):
                    continue
                if not (self.is_json(node.value) or self.dynamic_json_import(node.value)):
                    continue
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name) and tgt.id not in self.json:
                        self.json.add(tgt.id)
                        changed = True

    def is_json(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.json
        if isinstance(node, ast.Attribute):
            return node.attr == "json"  # `pkg.json` / `monitor.json`: a re-exported module
        return False

    def is_ast(self, node: ast.AST) -> bool:
        return isinstance(node, ast.Name) and node.id in self.ast

    def dynamic_json_import(self, node: ast.AST) -> "str | None":
        """The spelling if *node* is a dynamic import of the json module, else None."""
        if isinstance(node, ast.Subscript):
            v = node.value
            if (isinstance(v, ast.Attribute) and v.attr == "modules"
                    and isinstance(v.value, ast.Name) and v.value.id in self.sys
                    and _is_json_module_name(_const_str(node.slice))):
                return "sys.modules['json']"
            return None
        if not isinstance(node, ast.Call) or not node.args:
            return None
        if not _is_json_module_name(_const_str(node.args[0])):
            return None
        fn = node.func
        if isinstance(fn, ast.Name) and fn.id == "__import__":
            return "__import__('json')"
        if isinstance(fn, ast.Name) and fn.id in self.import_module:
            return "import_module('json')"
        if (isinstance(fn, ast.Attribute) and fn.attr == "import_module"
                and isinstance(fn.value, ast.Name) and fn.value.id in self.importlib):
            return "import_module('json')"
        return None


def _hits(tree: ast.AST, rel: str):
    """Yield (lineno, qualname, canonical spelling, how) for every raw decode of a document."""
    if rel == _EXEMPT_MODULE:
        return
    parents = _parents(tree)
    al = _Aliases(tree)

    def at(node, spelling, how):
        return (node.lineno, _qualname(node, parents), spelling, how)

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            if node.attr in _JSON_DECODE_ATTRS and al.is_json(node.value):
                yield at(node, f"json.{node.attr}", "attribute of the json module")
            elif node.attr == "literal_eval" and al.is_ast(node.value):
                parent = parents.get(node)
                if (isinstance(parent, ast.Call) and parent.func is node and parent.args
                        and isinstance(parent.args[0], ast.Constant)):
                    continue  # literal_eval of a constant node decodes no document
                yield at(node, "ast.literal_eval", "attribute of the ast module")
            elif node.attr in _JSON5_NAMES:
                yield at(node, node.attr, "JSON5 reader outside configloader.py")
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for a in node.names:
                if mod in _JSON_FROM_NAMES and a.name in _JSON_FROM_NAMES[mod]:
                    yield at(node, f"from {mod} import {a.name}", "name imported from json")
                elif a.name in _JSON5_NAMES:
                    yield at(node, a.name, "JSON5 reader outside configloader.py")
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id in al.json_from:
                yield at(node, f"json.{al.json_from[node.id]}", "use of a name imported from json")
            elif node.id in al.literal_eval:
                parent = parents.get(node)
                if (isinstance(parent, ast.Call) and parent.func is node and parent.args
                        and isinstance(parent.args[0], ast.Constant)):
                    continue
                yield at(node, "ast.literal_eval", "use of a name imported from ast")
            elif node.id in al.json5:
                yield at(node, al.json5[node.id], "JSON5 reader outside configloader.py")
        elif isinstance(node, ast.Call):
            spelled = al.dynamic_json_import(node)
            if spelled:
                yield at(node, spelled, "dynamic import of the json module")
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id == "getattr" and len(node.args) >= 2:
                if al.is_json(node.args[0]) or al.dynamic_json_import(node.args[0]):
                    name = _const_str(node.args[1])
                    if name is None:
                        yield at(node, "getattr(json, <computed>)", "computed attribute of json")
                    elif name in _JSON_DECODE_ATTRS:
                        yield at(node, f"getattr(json, {name!r})", "getattr on the json module")
        elif isinstance(node, ast.Subscript):
            spelled = al.dynamic_json_import(node)
            if spelled:
                yield at(node, spelled, "dynamic lookup of the json module")


def scan_source(source: str, rel: str, allow: dict) -> "tuple[list[str], Counter]":
    """(problems, allowlist-use counts) for one module's source text."""
    problems = []
    used: Counter = Counter()
    for lineno, qual, spelling, how in _hits(ast.parse(source), rel):
        key = (rel, qual, spelling)
        if key in allow:
            used[key] += 1
            continue
        problems.append(
            f"{rel}:{lineno} in {qual}: raw JSON decode '{spelling}' ({how}) - read the document "
            f"with clawseccheck.configloader.loads_bounded (state the user owns) or loads_shallow "
            f"(third-party / agent-shaped content) (C-664), or, if the site is genuinely safe, "
            f"add it to _RAW_DECODE_ALLOWLIST with the reason"
        )
    return problems, used


def _reconcile(allow: dict, used: Counter) -> "list[str]":
    out = []
    for key, (expected, _reason) in allow.items():
        if used[key] != expected:
            out.append(
                f"allowlist entry {key} expects {expected} site(s) but the scan found "
                f"{used[key]} - a moved/removed decode leaves a stale hole, an extra one is a "
                f"new raw decode in the same function"
            )
    return out


def scan_package(root: Path, allow: dict) -> "list[str]":
    problems = []
    used: Counter = Counter()
    for path in sorted((root / "clawseccheck").rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        got, n = scan_source(path.read_text(encoding="utf-8"), rel, allow)
        problems += got
        used += n
    return problems + _reconcile(allow, used)


# Reason classes shared by several entries. "residual of C-664" means the site still decodes
# on the plain parser and is a known gap, not an endorsement; converting it is tracked work.
_R_USER = ("residual of C-664: user-owned file left on the plain parser because a depth limit "
           "would weaken a verdict")
_R_AGENT = ("residual of C-664: agent-shaped content that needs the shallow reader and an "
            "ELIDED-tolerant consumer")
_R_OWN_OUTPUT = "own output: round trip of the tool's own render_json/render_vet_json text"

# (repo-relative module, enclosing function qualname, canonical spelling) -> (count, reason).
# Enumerated by running the scanner over the tree (dev 9c37c85c); every reason was decided by
# reading the site, never inferred from its name.
_RAW_DECODE_ALLOWLIST: dict = {
    ("clawseccheck/adjudication/_verdicts.py", "render_judged_json", "json.loads"):
        (1, _R_OWN_OUTPUT),
    ("clawseccheck/checks/_mcp.py", "_wrapper_read_package_json", "json.loads"):
        (1, "guarded: runs only when json_nesting_exceeds(text, SHALLOW_JSON_DEPTH) is false "
            "(deeper text goes to loads_shallow); the parse_int hook needs the plain parser"),
    ("clawseccheck/cli.py", "_main", "json.loads"):
        (1, _R_OWN_OUTPUT + " (the --full merge of the pipeline keys into the audit payload)"),
    ("clawseccheck/cli.py", "_run_apply_ignore_proposals", "json.loads"):
        (1, "explicit CLI argument: the proposals file the user passed to --apply-ignore-proposals; "
            "ValueError-only handler"),
    ("clawseccheck/native.py", "_parse", "json.loads"):
        (2, "vendor subprocess stdout: the OpenClaw CLI's own audit JSON, plain and last-{...} "
            "fallback; JSONDecodeError-only handler"),
    ("clawseccheck/report.py", "render_advise_json", "json.loads"):
        (1, _R_OWN_OUTPUT),
    ("clawseccheck/watch.py", "read_heartbeat", "json.loads"):
        (1, "own data: the watcher's own heartbeat file, written by this tool with json.dumps"),
}


# --------------------------------------------------------------------------- the real tree


def test_package_has_no_unlisted_raw_json_decode():
    problems = scan_package(_ROOT, _RAW_DECODE_ALLOWLIST)
    assert not problems, "\n".join(problems)


def test_the_scan_sees_the_whole_package():
    """A control for the scan above: it must actually be reading the package (a wrong root
    would scan nothing and pass), including the subpackages, and must see the sanctioned
    readers' home and at least one real decode site."""
    files = {p.relative_to(_ROOT).as_posix() for p in _PKG.rglob("*.py")}
    for must in (_EXEMPT_MODULE, "clawseccheck/collector.py", "clawseccheck/checks/_vet.py",
                 "clawseccheck/monitordims/_memory.py"):
        assert must in files, must
    assert len(files) > 50
    # With an empty allowlist the scan must report every listed site: it is reading real code.
    found = sum(len(scan_source((_ROOT / f).read_text(encoding="utf-8"), f, {})[0])
                for f in sorted(files))
    assert found == sum(count for count, _ in _RAW_DECODE_ALLOWLIST.values()), found


def test_configloader_still_defines_the_sanctioned_readers():
    """The guard tells authors to use these two; they must exist, and the module that
    implements them is the only exempt one."""
    src = (_ROOT / _EXEMPT_MODULE).read_text(encoding="utf-8")
    defs = {n.name for n in ast.parse(src).body if isinstance(n, ast.FunctionDef)}
    assert {"loads_bounded", "loads_shallow", "loads_json5"} <= defs
    assert _EXEMPT_MODULE == "clawseccheck/configloader.py"


# -------------------------------------------------- the guard can fail (synthetic modules)

_CASES_THAT_MUST_BE_REPORTED = {
    "json.loads": "import json\ndef f(t):\n    return json.loads(t)\n",
    "json.load": "import json\ndef f(fh):\n    return json.load(fh)\n",
    "json.JSONDecoder": "import json\ndef f(t):\n    return json.JSONDecoder().decode(t)\n",
    "json.raw_decode": "import json\ndef f(t):\n    return json.JSONDecoder().raw_decode(t)\n",
    "raw_decode on a held decoder": ("import json\nD = json.JSONDecoder()\n"
                                     "def f(t):\n    return D.raw_decode(t)\n"),
    "json.decoder": "import json\ndef f(t):\n    return json.decoder.JSONDecoder().decode(t)\n",
    "json.scanner": "import json\ndef f():\n    return json.scanner.make_scanner\n",
    "json.__dict__": "import json\ndef f():\n    return json.__dict__['loads']\n",
    "an aliased import": "import json as _json\ndef f(t):\n    return _json.loads(t)\n",
    "a function-local import": "def f(t):\n    import json as j\n    return j.loads(t)\n",
    "a submodule alias": ("import json.decoder as d\ndef f(t):\n"
                          "    return d.JSONDecoder().decode(t)\n"),
    "a rebinding": "import json\nj = json\ndef f(t):\n    return j.loads(t)\n",
    "a chained rebinding": "import json\na = json\nb = a\ndef f(t):\n    return b.loads(t)\n",
    "a re-exported module": "from pkg import json\ndef f(t):\n    return json.loads(t)\n",
    "an attribute-held module": "def f(t, m):\n    return m.json.loads(t)\n",
    "a bare reference": "import json\ndef f(xs):\n    return list(map(json.loads, xs))\n",
    "from json import loads": "from json import loads\ndef f(t):\n    return loads(t)\n",
    "from json import loads as": "from json import loads as jl\ndef f(t):\n    return jl(t)\n",
    "from json import load": "from json import load\ndef f(fh):\n    return load(fh)\n",
    "from json import JSONDecoder": ("from json import JSONDecoder\n"
                                     "def f(t):\n    return JSONDecoder().decode(t)\n"),
    "from json import decoder": "from json import decoder\ndef f(t):\n    return decoder.JSONDecoder\n",
    "from json import scanner": "from json import scanner\ndef f():\n    return scanner.make_scanner\n",
    "from json.decoder import": ("from json.decoder import JSONDecoder\n"
                                 "def f(t):\n    return JSONDecoder().decode(t)\n"),
    "from json.scanner import": "from json.scanner import make_scanner\n",
    "a use of an imported name alone": ("from json import loads\n"
                                        "def f(t):\n    return loads(t)\n"),
    "getattr with a string": "import json\ndef f(t):\n    return getattr(json, 'loads')(t)\n",
    "getattr with a computed name": ("import json\ndef f(t, n):\n    return getattr(json, n)(t)\n"),
    "getattr on an alias": "import json as j\ndef f(t):\n    return getattr(j, 'load')(t)\n",
    "importlib.import_module": ("import importlib\ndef f(t):\n"
                                "    return importlib.import_module('json').loads(t)\n"),
    "import_module imported by name": ("from importlib import import_module\ndef f(t):\n"
                                       "    return import_module('json').loads(t)\n"),
    "importlib alias": ("import importlib as il\ndef f(t):\n"
                        "    return il.import_module('json.decoder')\n"),
    "__import__": "def f(t):\n    return __import__('json').loads(t)\n",
    "an assigned dynamic import": ("def f(t):\n    j = __import__('json')\n    return j.loads(t)\n"),
    "sys.modules": "import sys\ndef f(t):\n    return sys.modules['json'].loads(t)\n",
    "ast.literal_eval of text": "import ast\ndef f(t):\n    return ast.literal_eval(t)\n",
    "ast.literal_eval of a call": "import ast\ndef f(t):\n    return ast.literal_eval(t.strip())\n",
    "an aliased ast": "import ast as a\ndef f(t):\n    return a.literal_eval(t)\n",
    "literal_eval imported by name": ("from ast import literal_eval\ndef f(t):\n"
                                      "    return literal_eval(t)\n"),
    "a literal_eval reference": "import ast\ndef f(xs):\n    return list(map(ast.literal_eval, xs))\n",
    "loads_json5 by name": ("from .configloader import loads_json5\ndef f(t):\n"
                            "    return loads_json5(t)\n"),
    "loads_json5 by module": ("from . import configloader\ndef f(t):\n"
                              "    return configloader.loads_json5(t)\n"),
    "loads_json5 aliased": ("from .configloader import loads_json5 as lj\ndef f(t):\n"
                            "    return lj(t)\n"),
    "the lenient half": ("from .configloader import _loads_json5_lenient\ndef f(t):\n"
                         "    return _loads_json5_lenient(t)\n"),
    "a class method": "import json\nclass C:\n    def m(self, t):\n        return json.loads(t)\n",
    "a nested function": ("import json\ndef f():\n    def g(t):\n        return json.loads(t)\n"
                          "    return g\n"),
    "a module-level call": "import json\nDATA = json.loads('{}')\n",
}


@pytest.mark.parametrize("label", sorted(_CASES_THAT_MUST_BE_REPORTED))
def test_the_guard_reports_a_raw_decode(label):
    problems, _ = scan_source(_CASES_THAT_MUST_BE_REPORTED[label], "clawseccheck/synthetic.py", {})
    assert problems, f"the guard missed: {label}"


_CASES_THAT_MUST_PASS = {
    "json.dumps": "import json\ndef f(o):\n    return json.dumps(o)\n",
    "json.dump": "import json\ndef f(o, fh):\n    json.dump(o, fh)\n",
    "json.JSONDecodeError": ("import json\ndef f(t, g):\n    try:\n        return g(t)\n"
                             "    except json.JSONDecodeError:\n        return None\n"),
    "json.JSONEncoder": "import json\nclass E(json.JSONEncoder):\n    pass\n",
    "an import that is not used": "import json\n",
    "loads_bounded": ("from .configloader import loads_bounded\ndef f(t):\n"
                      "    return loads_bounded(t)\n"),
    "loads_bounded by module": ("from . import configloader\ndef f(t):\n"
                                "    return configloader.loads_bounded(t)\n"),
    "loads_shallow": ("from .configloader import loads_shallow\ndef f(t):\n"
                      "    return loads_shallow(t).value\n"),
    "loads_shallow json5": ("from .configloader import loads_shallow\ndef f(t):\n"
                            "    return loads_shallow(t, json5=True)\n"),
    "ast.literal_eval of a constant": "import ast\ndef f():\n    return ast.literal_eval('[1, 2]')\n",
    "literal_eval name of a constant": ("from ast import literal_eval\ndef f():\n"
                                        "    return literal_eval('[1, 2]')\n"),
    "ast.parse": "import ast\ndef f(t):\n    return ast.parse(t)\n",
    "a local function named loads": "def loads(t):\n    return t\ndef f(t):\n    return loads(t)\n",
    "a local method named loads": ("class C:\n    def loads(self, t):\n        return t\n"
                                   "    def m(self, t):\n        return self.loads(t)\n"),
    "a local function named load": "def load(t):\n    return t\ndef f(t):\n    return load(t)\n",
    "another module's loads": "import pickle\ndef f(t):\n    return pickle.loads(t)\n",
    "a local name json that is not the module": "def f(json):\n    return json.dumps({})\n",
    "a string that is not a name lookup": "def f():\n    return 'json.loads'\n",
    "getattr on another object": "def f(o):\n    return getattr(o, 'loads')\n",
    "import_module of another module": ("import importlib\ndef f():\n"
                                        "    return importlib.import_module('tomllib')\n"),
    "__import__ of another module": "def f():\n    return __import__('os')\n",
    "an unrelated json5-like name": "def loads_json5_like(t):\n    return t\ndef f(t):\n    return loads_json5_like(t)\n",
}


@pytest.mark.parametrize("label", sorted(_CASES_THAT_MUST_PASS))
def test_the_guard_accepts_the_sanctioned_and_unrelated_spellings(label):
    problems, _ = scan_source(_CASES_THAT_MUST_PASS[label], "clawseccheck/synthetic.py", {})
    assert not problems, (label, problems)


def test_configloader_is_exempt_as_a_whole_and_nothing_else_is():
    src = ("import ast\nimport json\ndef loads_json5(t):\n    return json.loads(t)\n"
           "def g(t):\n    return ast.literal_eval(t)\n")
    problems, _ = scan_source(src, _EXEMPT_MODULE, {})
    assert not problems
    problems, _ = scan_source(src, "clawseccheck/configloader_twin.py", {})
    assert problems
    problems, _ = scan_source(src, "clawseccheck/checks/configloader.py", {})
    assert problems


def test_the_guard_reports_the_exact_location_and_the_replacement():
    problems, _ = scan_source("import json\ndef f(t):\n    x = 1\n    return json.loads(t)\n",
                              "clawseccheck/synthetic.py", {})
    assert len(problems) == 1
    assert problems[0].startswith("clawseccheck/synthetic.py:4 in f:")
    assert "loads_bounded" in problems[0] and "loads_shallow" in problems[0]


# ---------------------------------------------------------------- the counted allowlist

_ALLOW_KEY = ("clawseccheck/synthetic.py", "read", "json.loads")
_ALLOW = {_ALLOW_KEY: (1, "synthetic")}
_SYNTH_ONE = "import json\ndef read(t):\n    return json.loads(t)\n"
_SYNTH_TWO = "import json\ndef read(t):\n    json.loads(t)\n    return json.loads(t)\n"


def _problems_for(source: str, allow: dict, rel: str = "clawseccheck/synthetic.py") -> "list[str]":
    """The same reconciliation scan_package performs, over one synthetic module."""
    got, used = scan_source(source, rel, allow)
    return got + _reconcile(allow, used)


def test_an_allowlisted_decode_passes_at_its_exact_count():
    assert _problems_for(_SYNTH_ONE, _ALLOW) == []


def test_a_second_decode_in_the_same_function_still_fails():
    problems = _problems_for(_SYNTH_TWO, _ALLOW)
    assert problems and any("expects 1" in p for p in problems), problems


def test_a_stale_allowlist_entry_fails():
    problems = _problems_for("import json\ndef read(t):\n    return t\n", _ALLOW)
    assert problems and any("expects 1" in p for p in problems), problems


def test_an_allowlist_entry_does_not_cover_another_function_spelling_or_module():
    other_fn = "import json\ndef other(t):\n    return json.loads(t)\n"
    other_spelling = "import json\ndef read(fh):\n    return json.load(fh)\n"
    for label, src in (("function", other_fn), ("spelling", other_spelling)):
        got, _ = scan_source(src, "clawseccheck/synthetic.py", _ALLOW)
        assert got, f"an allowlist entry leaked across {label}"
    got, _ = scan_source(_SYNTH_ONE, "clawseccheck/other_module.py", _ALLOW)
    assert got, "an allowlist entry leaked across modules"


def test_the_canonical_spelling_survives_an_alias_rename():
    """The key is the resolved spelling, so renaming `import json as _json` does not turn an
    accepted site into a stale entry plus a new violation."""
    src = "import json as _json\ndef read(t):\n    return _json.loads(t)\n"
    assert _problems_for(src, _ALLOW) == []


def test_the_real_allowlist_is_small_and_only_names_json_loads():
    """Keep the accepted set small and named: a long allowlist is how a guard becomes a
    rubber stamp. Raising these numbers needs a reason written next to the new entry, and a
    conversion to loads_bounded / loads_shallow lowers them."""
    assert len(_RAW_DECODE_ALLOWLIST) == 7
    assert sum(count for count, _ in _RAW_DECODE_ALLOWLIST.values()) == 8
    assert {spelling for (_rel, _fn, spelling) in _RAW_DECODE_ALLOWLIST} == {"json.loads"}


def test_the_real_allowlist_is_well_formed():
    """Every entry is a counted, reasoned site in a module that exists."""
    for (rel, _fn, spelling), (count, reason) in _RAW_DECODE_ALLOWLIST.items():
        assert (_ROOT / rel).is_file(), rel
        assert rel != _EXEMPT_MODULE, "configloader.py is exempt as a whole, not by entry"
        assert spelling
        assert isinstance(count, int) and count >= 1
        assert isinstance(reason, str) and reason.strip() and "\n" not in reason
