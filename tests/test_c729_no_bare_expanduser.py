"""C-729: no bare ``Path.expanduser()`` anywhere in ``clawseccheck/`` except ``pathprobe.py``
and the counted allowlist below.

``Path.expanduser()`` raises ``RuntimeError`` for a ``~user`` that names no account (and for
``~`` when neither HOME nor a passwd entry exists). Nothing on the audit path catches that, so
one config value ended the whole run with "unexpected internal error". Every call goes through
``pathprobe.expand_user`` instead; this guard stops a new bare call from reintroducing it.

It AST-scans every ``clawseccheck/**/*.py`` and fails on any attribute named ``expanduser``
(a call OR a bare reference such as ``map(Path.expanduser, xs)``), plus ``getattr`` /
``methodcaller`` spellings with a string, except ``os.path.expanduser`` (a module function that
never raises, a different contract on purpose) and the explicit, COUNTED allowlist
``_ALLOWED``: sites that catch ``RuntimeError`` on purpose and turn it into their own answer.
An entry names module + enclosing function + receiver source and an exact count, so a second
bare call in the same function still fails and an entry whose site disappeared fails too.
"""
from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path

import pytest

pytestmark = pytest.mark.mechanical

_ROOT = Path(__file__).resolve().parents[1]
_PKG = _ROOT / "clawseccheck"
_HELPER_MODULE = "clawseccheck/pathprobe.py"
_OS_PATH_RECEIVERS = frozenset({"os.path", "posixpath", "ntpath"})

# (module, enclosing function qualname, receiver source) -> count. Each one catches
# RuntimeError at the call on purpose and turns it into its own, specific answer, which the
# helper's silent fallback would replace.
_ALLOWED = {
    # The judge-verdicts reader: RuntimeError becomes UnusableInputPath("the '~user' in it
    # names no account on this machine") - B-561/B-684 decided that stays LOUD.
    ("clawseccheck/cli.py", "_read_verdicts_payload", "Path(raw_path)"): 1,
    # The up-front check for every user-typed path option (C-729 decision D): it exists to
    # find out whether the value can be expanded, so it must see the RuntimeError.
    ("clawseccheck/cli.py", "_refuse_unexpandable_paths", "Path(value)"): 1,
    # verify_chain "never raises": RuntimeError becomes CHAIN_BAD_PATH with its message.
    ("clawseccheck/monitorstore.py", "verify_chain", "Path(events_path)"): 1,
    # An environment override of the bundled skills root: an unexpandable value is skipped
    # (the root is not added), not read as a relative directory under the working directory.
    ("clawseccheck/collector.py", "_read_installed_skills", "Path(_value)"): 1,
    # A trajectory pointer target: an unexpandable name is "invalid", not resolved relative
    # to the working directory and then judged in or out of the home.
    ("clawseccheck/trajectory.py", "_resolve_pointer_target", "Path(target)"): 1,
}


def _parents(tree):
    out = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            out[child] = node
    return out


def _qualname(node, parents):
    names = []
    cur = node
    while cur in parents:
        cur = parents[cur]
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.append(cur.name)
    return ".".join(reversed(names)) or "<module>"


def _dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _hits(tree):
    parents = _parents(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "expanduser":
            if _dotted(node.value) in _OS_PATH_RECEIVERS:
                continue
            yield (node.lineno, _qualname(node, parents), ast.unparse(node.value), "attribute")
        elif isinstance(node, ast.Call):
            fn = _dotted(node.func)
            idx = {"getattr": 1, "hasattr": 1, "operator.methodcaller": 0,
                   "methodcaller": 0}.get(fn)
            if idx is None or len(node.args) <= idx:
                continue
            arg = node.args[idx]
            if isinstance(arg, ast.Constant) and arg.value == "expanduser":
                yield (node.lineno, _qualname(node, parents), "<dynamic>", f"{fn}() with a string")


def scan_source(source, rel, allow):
    problems = []
    used = Counter()
    for lineno, qual, recv, how in _hits(ast.parse(source)):
        key = (rel, qual, recv)
        if rel == _HELPER_MODULE:
            continue
        if key in allow and how == "attribute":
            used[key] += 1
            continue
        problems.append(
            f"{rel}:{lineno} in {qual}: bare '{recv}.expanduser' ({how}) - use "
            f"clawseccheck.pathprobe.expand_user(...) (C-729), or, if this site must see the "
            f"RuntimeError, add it to _ALLOWED with the reason")
    return problems, used


def scan_package(root, allow):
    problems = []
    used = Counter()
    for path in sorted((root / "clawseccheck").rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        got, n = scan_source(path.read_text(encoding="utf-8"), rel, allow)
        problems += got
        used += n
    for key, expected in allow.items():
        if used[key] != expected:
            problems.append(f"allowlist entry {key} expects {expected} site(s) but the scan "
                            f"found {used[key]} - a moved/removed site leaves a stale hole, "
                            f"an extra one is a new bare call in the same function")
    return problems


# --------------------------------------------------------------------------- the real tree


def test_package_has_no_bare_expanduser():
    problems = scan_package(_ROOT, _ALLOWED)
    assert not problems, "\n".join(problems)


def test_the_scan_sees_the_whole_package_and_the_helper_is_used():
    files = {p.relative_to(_ROOT).as_posix() for p in _PKG.rglob("*.py")}
    for must in (_HELPER_MODULE, "clawseccheck/collector.py", "clawseccheck/cli.py",
                 "clawseccheck/checks/_vet.py", "clawseccheck/monitordims/_memory.py"):
        assert must in files, must
    users = [f for f in files if f != _HELPER_MODULE
             and "pathprobe.expand_user(" in (_ROOT / f).read_text(encoding="utf-8")]
    assert len(users) >= 30, sorted(users)


def test_the_real_allowlist_is_small_and_every_entry_is_a_counted_runtimeerror_site():
    """Keep the accepted set small and named. Raising this number needs a reason next to
    the new entry."""
    assert len(_ALLOWED) == 5
    assert sum(_ALLOWED.values()) == 5
    for (rel, fn, recv), count in _ALLOWED.items():
        text = (_ROOT / rel).read_text(encoding="utf-8")
        assert f"def {fn}(" in text, (rel, fn)
        assert ".expanduser()" in text and "RuntimeError" in text, rel
        assert recv.startswith("Path(") and count >= 1


# ------------------------------------------------------ the guard can fail (synthetic modules)

_MUST_BE_REPORTED = {
    "a bare call": "def f(p):\n    return p.expanduser()\n",
    "a call on Path(...)": "from pathlib import Path\ndef f(p):\n    return Path(p).expanduser()\n",
    "a call on an expression": "def f(a):\n    return (a / 'x').expanduser()\n",
    "a bare reference": "from pathlib import Path\ndef f(xs):\n    return list(map(Path.expanduser, xs))\n",
    "getattr with a string": "def f(p):\n    return getattr(p, 'expanduser')()\n",
    "methodcaller": "import operator\ndef f(xs):\n    return list(map(operator.methodcaller('expanduser'), xs))\n",
    "a method on a class": "class C:\n    def m(self, p):\n        return p.expanduser()\n",
    "a nested function": "def f(p):\n    def g():\n        return p.expanduser()\n    return g()\n",
    "a lookalike receiver": "def f(p):\n    return os_path.expanduser(p)\n",
}


@pytest.mark.parametrize("label", sorted(_MUST_BE_REPORTED))
def test_the_guard_reports_a_bare_expanduser(label):
    problems, _ = scan_source(_MUST_BE_REPORTED[label], "clawseccheck/synthetic.py", {})
    assert problems, f"the guard missed: {label}"


_MUST_PASS = {
    "os.path.expanduser": "import os\ndef f(p):\n    return os.path.expanduser(p)\n",
    "the helper": "from . import pathprobe\ndef f(p):\n    return pathprobe.expand_user(p)\n",
    "a string": "def f():\n    return 'expanduser'\n",
}


@pytest.mark.parametrize("label", sorted(_MUST_PASS))
def test_the_guard_accepts_the_structural_exemptions(label):
    problems, _ = scan_source(_MUST_PASS[label], "clawseccheck/synthetic.py", {})
    assert not problems, (label, problems)


def test_the_helper_module_itself_is_exempt():
    problems, _ = scan_source("def f(p):\n    return p.expanduser()\n", _HELPER_MODULE, {})
    assert not problems


_KEY = ("clawseccheck/synthetic.py", "walk", "Path(v)")
_ONE = "def walk(v):\n    return Path(v).expanduser()\n"
_TWO = "def walk(v):\n    a = Path(v).expanduser()\n    return Path(v).expanduser()\n"


def _with_reconciliation(source, allow):
    got, used = scan_source(source, "clawseccheck/synthetic.py", allow)
    for key, expected in allow.items():
        if used[key] != expected:
            got.append(f"allowlist entry {key} expects {expected} but found {used[key]}")
    return got


def test_an_allowlisted_site_passes_at_its_exact_count():
    assert _with_reconciliation(_ONE, {_KEY: 1}) == []


def test_a_second_bare_call_in_the_same_function_still_fails():
    assert _with_reconciliation(_TWO, {_KEY: 1})


def test_a_stale_allowlist_entry_fails():
    assert _with_reconciliation("def walk(v):\n    return v\n", {_KEY: 1})


def test_an_allowlist_entry_does_not_cover_another_function_receiver_or_module():
    allow = {_KEY: 1}
    other_fn = "def other(v):\n    return Path(v).expanduser()\n"
    other_recv = "def walk(v):\n    return v.expanduser()\n"
    for label, src in (("function", other_fn), ("receiver", other_recv)):
        got, _ = scan_source(src, "clawseccheck/synthetic.py", allow)
        assert got, f"an allowlist entry leaked across {label}"
    got, _ = scan_source(_ONE, "clawseccheck/other_module.py", allow)
    assert got, "an allowlist entry leaked across modules"
