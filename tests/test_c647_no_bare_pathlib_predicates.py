"""C-647: no bare ``pathlib`` predicate may be called anywhere in ``clawseccheck/``.

Python 3.14 rewrote ``Path.exists()`` / ``is_dir()`` / ``is_file()`` / ``is_symlink()`` (and
``is_mount`` / ``is_fifo`` / ``is_socket`` / ``is_block_device`` / ``is_char_device`` /
``is_junction``) to return False for ANY OS error. The first four, and ``is_fifo`` /
``is_socket`` / ``is_block_device`` / ``is_char_device``, previously re-raised everything
except ENOENT / ENOTDIR / EBADF / ELOOP (measured under an unsearchable parent directory:
PermissionError on 3.9.25 and 3.12.3, False on 3.14.4). ``is_mount`` and ``is_junction``
never had that contract on every version: ``is_mount`` raised on 3.9.25 but returns False on
3.12.3 (it delegates to ``posixpath.ismount``), and ``is_junction`` does not exist on 3.9
and returns False on 3.12.3 (it delegates to ``posixpath.isjunction``). All ten names are
banned regardless: ``pathprobe`` defines no replacement for the six that are not in its
set of four, their error behaviour differs between interpreters, and nothing in the
package calls any of those six, so banning them costs nothing and keeps a
version-dependent answer out. Every ``except OSError`` arm that
guarded one of the first four became dead code on 3.14, and an unreadable path read as an
absent one. The fix is one leaf module,
``clawseccheck/pathprobe.py``, that reproduces the 3.9-3.12 contract on every interpreter, and
a mechanical replacement of every call. This guard is what stops a NEW bare call from
quietly reintroducing the defect on the one interpreter CI may not run.

It AST-scans every ``clawseccheck/**/*.py`` and fails on any attribute access (a call OR a
bare reference such as ``filter(Path.is_file, xs)``) named like one of the ten pathlib
predicates, plus ``getattr`` / ``hasattr`` / ``operator.methodcaller`` spellings of the same
names, except:

  (a) ``pathprobe.<name>`` for the four names ``pathprobe`` defines;
  (b) ``os.path.<name>`` / ``posixpath.<name>`` / ``ntpath.<name>`` - module functions that
      swallow every error on every interpreter, a different contract on purpose;
  (c) the explicit, COUNTED allowlist ``_NON_PATHLIB_RECEIVERS`` below: receivers that are
      not ``pathlib`` objects at all. An entry names module + enclosing function + receiver
      expression + attribute and an exact count, so a second bare call in the same function
      still fails, and an entry whose site disappeared fails too (a stale allowlist is a
      hole).

The scanner is exercised against synthetic modules so the guard is shown to be able to fail.
"""
from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path

import pytest

pytestmark = pytest.mark.mechanical

_ROOT = Path(__file__).resolve().parents[1]
_PKG = _ROOT / "clawseccheck"

_PREDICATES = frozenset({
    "exists", "is_dir", "is_file", "is_symlink", "is_mount", "is_fifo",
    "is_socket", "is_block_device", "is_char_device", "is_junction",
})

# The four names clawseccheck/pathprobe.py defines; the other six have no probe and would be
# an AttributeError at runtime, so `pathprobe.is_fifo(...)` is a violation, not an exemption.
_PROBE_NAMES = frozenset({"exists", "is_dir", "is_file", "is_symlink"})

# Module functions with the swallow-everything contract (rule b).
_OS_PATH_RECEIVERS = frozenset({"os.path", "posixpath", "ntpath"})

# (repo-relative module, enclosing function qualname, receiver source, attribute) -> count.
# Every entry is a receiver that is NOT a pathlib object, decided by reading the code.
_NON_PATHLIB_RECEIVERS = {
    # `entry` is an `os.DirEntry` from `os.scandir(cand)` (C-implemented, unchanged in 3.14).
    ("clawseccheck/checks/_mcp.py", "_colocated_skill_dirs", "entry", "is_dir"): 1,
    # `member_info` is a `zipfile.ZipInfo` from `zf.getinfo(...)`: archive metadata, no filesystem.
    ("clawseccheck/collector.py", "decompress_and_classify", "member_info", "is_dir"): 1,
    # `entry` is an `os.DirEntry` from `os.scandir(cache_dir)`; `is_file(follow_symlinks=False)`.
    ("clawseccheck/integrity.py", "_scan_for_unchecked_hash_pycs", "entry", "is_file"): 1,
    # `entry` is an `os.DirEntry` from `os.scandir(base)`; `is_file(follow_symlinks=False)`.
    ("clawseccheck/openclawdist.py", "_code_files", "entry", "is_file"): 1,
}


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


def _dotted(node: ast.AST) -> "str | None":
    """``os.path`` for an Attribute chain of plain names, else None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _hits(tree: ast.AST):
    """Yield (lineno, qualname, receiver source, name, spelling) for every predicate-named
    access that is not one of the two structural exemptions (a) and (b)."""
    parents = _parents(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in _PREDICATES:
            recv = _dotted(node.value)
            if recv == "pathprobe" and node.attr in _PROBE_NAMES:
                continue
            if recv in _OS_PATH_RECEIVERS:
                continue
            yield (node.lineno, _qualname(node, parents), ast.unparse(node.value),
                   node.attr, "attribute")
        elif isinstance(node, ast.Call):
            fn = _dotted(node.func)
            idx = {"getattr": 1, "hasattr": 1, "operator.methodcaller": 0,
                   "methodcaller": 0}.get(fn)
            if idx is None or len(node.args) <= idx:
                continue
            arg = node.args[idx]
            if (isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                    and arg.value in _PREDICATES):
                yield (node.lineno, _qualname(node, parents),
                       ast.unparse(node.args[0]) if idx else "<methodcaller>",
                       arg.value, f"{fn}() with a string")


def scan_source(source: str, rel: str, allow: dict) -> "tuple[list[str], Counter]":
    """(problems, allowlist-use counts) for one module's source text."""
    problems = []
    used: Counter = Counter()
    for lineno, qual, recv, name, how in _hits(ast.parse(source)):
        key = (rel, qual, recv, name)
        if key in allow and how == "attribute":
            used[key] += 1
            continue
        problems.append(
            f"{rel}:{lineno} in {qual}: bare pathlib predicate '{recv}.{name}' ({how}) - use "
            f"clawseccheck.pathprobe.{name}(...) (C-647), or, if the receiver is not a pathlib "
            f"object, add it to _NON_PATHLIB_RECEIVERS with the reason"
        )
    return problems, used


def scan_package(root: Path, allow: dict) -> "list[str]":
    problems = []
    used: Counter = Counter()
    for path in sorted((root / "clawseccheck").rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        got, n = scan_source(path.read_text(encoding="utf-8"), rel, allow)
        problems += got
        used += n
    for key, expected in allow.items():
        if used[key] != expected:
            problems.append(
                f"allowlist entry {key} expects {expected} site(s) but the scan found "
                f"{used[key]} - a moved/removed receiver leaves a stale hole, an extra one is "
                f"a new bare call in the same function"
            )
    return problems


# --------------------------------------------------------------------------- the real tree


def test_package_has_no_bare_pathlib_predicates():
    problems = scan_package(_ROOT, _NON_PATHLIB_RECEIVERS)
    assert not problems, "\n".join(problems)


def test_the_scan_sees_the_whole_package():
    """A control for the scan above: it must actually be reading the package (a wrong root
    would scan nothing and pass), including the subpackages, and must see pathprobe's
    callers."""
    files = {p.relative_to(_ROOT).as_posix() for p in _PKG.rglob("*.py")}
    for must in ("clawseccheck/pathprobe.py", "clawseccheck/collector.py",
                 "clawseccheck/checks/_vet.py", "clawseccheck/monitordims/_memory.py"):
        assert must in files, must
    assert len(files) > 50
    users = [f for f in files
             if "pathprobe." in (_ROOT / f).read_text(encoding="utf-8") and f != "clawseccheck/pathprobe.py"]
    assert len(users) >= 30, sorted(users)


def test_every_module_that_calls_pathprobe_imports_it():
    """A `pathprobe.is_dir(x)` in a module with no `pathprobe` import is a NameError on
    whichever rarely-run path reaches it - the type of defect a green scoped run never
    sees."""
    missing = []
    for path in sorted(_PKG.rglob("*.py")):
        if path.name == "pathprobe.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        uses = any(isinstance(n, ast.Name) and n.id == "pathprobe" for n in ast.walk(tree))
        if not uses:
            continue
        imported = any(
            isinstance(n, ast.ImportFrom) and n.level >= 1 and n.module is None
            and any(a.name == "pathprobe" and a.asname is None for a in n.names)
            for n in tree.body
        )
        if not imported:
            missing.append(path.relative_to(_ROOT).as_posix())
    assert not missing, f"uses pathprobe without a module-level `from . import pathprobe`: {missing}"


# -------------------------------------------------- the guard can fail (synthetic modules)

_CASES_THAT_MUST_BE_REPORTED = {
    "a bare call": "def f(p):\n    return p.is_dir()\n",
    "exists": "def f(p):\n    return p.exists()\n",
    "is_symlink": "def f(p):\n    return p.is_symlink()\n",
    "a call on an expression": "def f(a):\n    return (a / 'x').is_file()\n",
    "a call with an argument": "def f(p):\n    return p.is_file(follow_symlinks=False)\n",
    "a bare reference": "from pathlib import Path\ndef f(xs):\n    return list(filter(Path.is_file, xs))\n",
    "a key= reference": "from pathlib import Path\ndef f(xs):\n    return sorted(xs, key=Path.exists)\n",
    "getattr with a string": "def f(p):\n    return getattr(p, 'is_dir')()\n",
    "hasattr with a string": "def f(p):\n    return hasattr(p, 'is_file')\n",
    "methodcaller": "import operator\ndef f(xs):\n    return list(map(operator.methodcaller('is_symlink'), xs))\n",
    "is_mount": "def f(p):\n    return p.is_mount()\n",
    "is_fifo": "def f(p):\n    return p.is_fifo()\n",
    "is_socket": "def f(p):\n    return p.is_socket()\n",
    "is_block_device": "def f(p):\n    return p.is_block_device()\n",
    "is_char_device": "def f(p):\n    return p.is_char_device()\n",
    "is_junction": "def f(p):\n    return p.is_junction()\n",
    "a method on a class": "class C:\n    def m(self, p):\n        return p.is_dir()\n",
    "a nested function": "def f(p):\n    def g():\n        return p.exists()\n    return g()\n",
    "a probe the module does not define": "def f(p):\n    return pathprobe.is_fifo(p)\n",
    "another module named pathprobe": "def f(p):\n    return notpathprobe.is_dir(p)\n",
    "a lookalike receiver": "def f(p):\n    return os_path.exists(p)\n",
}


@pytest.mark.parametrize("label", sorted(_CASES_THAT_MUST_BE_REPORTED))
def test_the_guard_reports_a_bare_predicate(label):
    problems, _ = scan_source(_CASES_THAT_MUST_BE_REPORTED[label], "clawseccheck/synthetic.py", {})
    assert problems, f"the guard missed: {label}"


_CASES_THAT_MUST_PASS = {
    "pathprobe": "from . import pathprobe\ndef f(p):\n    return pathprobe.is_dir(p) or pathprobe.exists(p)\n",
    "pathprobe all four": ("from . import pathprobe\ndef f(p):\n    return [pathprobe.exists(p), "
                           "pathprobe.is_dir(p), pathprobe.is_file(p), pathprobe.is_symlink(p)]\n"),
    "os.path": "import os\ndef f(p):\n    return os.path.exists(p) or os.path.isdir(p)\n",
    "os.path.exists": "import os\ndef f(p):\n    return os.path.exists(p)\n",
    "posixpath": "import posixpath\ndef f(p):\n    return posixpath.exists(p)\n",
    "ntpath": "import ntpath\ndef f(p):\n    return ntpath.exists(p)\n",
    "a string that is not a name lookup": "def f():\n    return 'exists'\n",
    "an unrelated attribute": "def f(p):\n    return p.stat().st_mode\n",
}


@pytest.mark.parametrize("label", sorted(_CASES_THAT_MUST_PASS))
def test_the_guard_accepts_the_structural_exemptions(label):
    problems, _ = scan_source(_CASES_THAT_MUST_PASS[label], "clawseccheck/synthetic.py", {})
    assert not problems, (label, problems)


def test_the_guard_reports_the_exact_location_and_the_replacement():
    problems, _ = scan_source("def f(p):\n    x = 1\n    return p.is_dir()\n",
                              "clawseccheck/synthetic.py", {})
    assert len(problems) == 1
    assert problems[0].startswith("clawseccheck/synthetic.py:3 in f:")
    assert "pathprobe.is_dir" in problems[0]


# ---------------------------------------------------------------- the counted allowlist

_ALLOW_KEY = ("clawseccheck/synthetic.py", "walk", "entry", "is_dir")
_SYNTH_ONE = "def walk(it):\n    for entry in it:\n        if entry.is_dir():\n            pass\n"
_SYNTH_TWO = ("def walk(it):\n    for entry in it:\n        if entry.is_dir():\n            pass\n"
              "        if entry.is_dir():\n            pass\n")


def _problems_for(source: str, allow: dict) -> "list[str]":
    """The same reconciliation scan_package performs, over one synthetic module."""
    got, used = scan_source(source, "clawseccheck/synthetic.py", allow)
    for key, expected in allow.items():
        if used[key] != expected:
            got.append(f"allowlist entry {key} expects {expected} but found {used[key]}")
    return got


def test_an_allowlisted_receiver_passes_at_its_exact_count():
    assert _problems_for(_SYNTH_ONE, {_ALLOW_KEY: 1}) == []


def test_a_second_bare_call_in_the_same_function_still_fails():
    problems = _problems_for(_SYNTH_TWO, {_ALLOW_KEY: 1})
    assert problems and any("expects 1" in p for p in problems), problems


def test_a_stale_allowlist_entry_fails():
    problems = _problems_for("def walk(it):\n    return list(it)\n", {_ALLOW_KEY: 1})
    assert problems and any("expects 1" in p for p in problems), problems


def test_an_allowlist_entry_does_not_cover_another_function_or_receiver_or_attribute():
    allow = {_ALLOW_KEY: 1}
    other_fn = "def other(it):\n    for entry in it:\n        if entry.is_dir():\n            pass\n"
    other_recv = "def walk(it):\n    for p in it:\n        if p.is_dir():\n            pass\n"
    other_attr = "def walk(it):\n    for entry in it:\n        if entry.exists():\n            pass\n"
    for label, src in (("function", other_fn), ("receiver", other_recv), ("attribute", other_attr)):
        got, _ = scan_source(src, "clawseccheck/synthetic.py", allow)
        assert got, f"an allowlist entry leaked across {label}"
    got, _ = scan_source(_SYNTH_ONE, "clawseccheck/other_module.py", allow)
    assert got, "an allowlist entry leaked across modules"


def test_the_real_allowlist_is_small_and_every_entry_is_a_counted_non_pathlib_site():
    """Keep the accepted set small and named: a long allowlist is how a guard becomes a
    rubber stamp. Raising this number needs a reason written next to the new entry."""
    assert len(_NON_PATHLIB_RECEIVERS) == 4
    assert sum(_NON_PATHLIB_RECEIVERS.values()) == 4
    for (rel, _fn, recv, name), count in _NON_PATHLIB_RECEIVERS.items():
        assert (_ROOT / rel).is_file(), rel
        assert name in _PREDICATES
        assert recv.isidentifier(), recv
        assert count >= 1
