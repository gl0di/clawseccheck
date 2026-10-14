"""C-730: no regex in the package may take quadratic time on one long line.

A bootstrap file, a memory file or an installed skill's SKILL.md holding ONE long line made
the audit spin for minutes: a regex that starts with a `*`/`+` class (or a `^\\s*` under
re.M) retries from every start position inside the run and scans to the run's end each
time. The time is spent inside one C call, so no timeout can interrupt it.

This guard

  * collects every compiled pattern reachable as a module attribute of the package (also
    inside list / tuple / set / dict attributes) and every string-literal pattern passed to
    `re.compile/search/match/...` anywhere in the source (walked by AST);
  * is usage-aware: a pattern the code only ever calls with `.match` / `.fullmatch` is timed
    with `.match` at position 0 (one attempt), every other pattern - including one passed
    around as a value, or whose `.pattern` is spliced into another - with `finditer`;
  * times each pattern over repeated units at two sizes (relative: a pattern fails when the
    large run is both slower than ~30 ms and more than ~7 times the small one);
  * has a control (a known quadratic pattern must be caught by the same function), and
    a whole-audit acceptance on a home whose bootstrap, memory and skill files hold one
    300,000-character line.

A pattern that cannot be made linear goes in ALLOWLIST with the constant that bounds its
input at every call site (the test checks the constant exists). A pattern known to be
quadratic but not yet fixed goes in OPEN_UNDER_C730: the test then REQUIRES it to still
fail, so the entry has to be deleted the moment the pattern is fixed.
"""
import ast
import importlib
import os
import pkgutil
import re
import shutil
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

import clawseccheck

PKG = Path(clawseccheck.__file__).resolve().parent
ROOT = PKG.parent

SMALL, LARGE = 2000, 8000
SMALL_HANG_S = 0.5  # a pattern already this slow on 2,000 characters fails without the big run
UNITS = [
    "x", "a", "A", "0", "_", "/", ".", "-", " ", "\t", "\n", "[", "(", "<", "@", ":", "#",
    "a.", "a/", "a-", " \n", ".x", "x.y", "a b", "\\", "'", '"', "|", "*", "=",
    "{", "http://", "a:", "$", ",", ";", "~/", "%", "&", "+", "?", "!", "`", "a1", "x=", "/x",
    # periodic shapes: an opener that never closes, a keyword that never completes
    "<a ", "[a](x", "![", "{{ ", "then ", "; ", "x=1 ", "- ", "| ", "\n ", " \t", "#!", "//",
    "/*", '"a" ', "'a' ", "$x ", "${", "a,", "1.", "a:b", "@a ", "=\n", "a\n", "(a", "a(",
]

# {pattern name: (reason, "module.name" of the one-pass scanner that replaced it)}. A pattern
# is listed here only when it is kept as the definition a scanner is tested against and is
# never run over text itself.
ALLOWLIST: dict = {
    # Not run over file text any more: `_b59_md_links` is the one-pass scanner, and this
    # pattern is kept as the definition that scanner is tested against
    # (test_c730_regex_equivalence.py). `test_the_reference_pattern_is_not_called` holds it
    # to that.
    "_B59_MD_LINK_RE": ("reference definition only; `_b59_md_links` scans the text",
                        "clawseccheck.checks._content._b59_md_links"),
    "_B59_MD_IMG_RE": ("reference definition only; `_b59_md_images` scans the text",
                       "clawseccheck.checks._content._b59_md_images"),
    "_B59_HTML_TAG_RE": ("reference definition only; `_b59_html_tags` scans the text",
                         "clawseccheck.checks._content._b59_html_tags"),
    "_B58_HIDDEN_TAG_RE": ("reference definition only; `_b58_hidden_tags` scans the text",
                           "clawseccheck.checks._content._b58_hidden_tags"),
    "_MODEL_FILE_URL_RE": ("reference definition only; `_model_file_urls` scans the text",
                           "clawseccheck.checks._content._model_file_urls"),
    "_PB_TOK_RE": ("reference definition only; `_pb_tok_matches` tokenizes the text",
                   "clawseccheck.checks._shared._pb_tok_matches"),
}

# Patterns measured quadratic that are not fixed yet (this task's open list). Each must STILL
# fail; delete the entry when the pattern is made linear.
OPEN_UNDER_C730: dict = {}

_METHODS = {"search", "match", "fullmatch", "finditer", "findall", "sub", "subn", "split"}


def _values(v, depth=0):
    if isinstance(v, re.Pattern):
        yield v
    elif depth < 3 and isinstance(v, (list, tuple, set, frozenset)):
        for x in v:
            yield from _values(x, depth + 1)
    elif depth < 3 and isinstance(v, dict):
        for x in v.values():
            yield from _values(x, depth + 1)


def _usage():
    """{bare name: set of methods called on it, plus '<value>' when it is used any other way}."""
    uses: dict = {}
    for path in PKG.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
        as_receiver = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                v = node.value
                name = v.id if isinstance(v, ast.Name) else v.attr if isinstance(v, ast.Attribute) else None
                if name:
                    as_receiver.add(id(v))
                    uses.setdefault(name, set()).add(node.attr if node.attr in _METHODS else "<value>")
        for node in ast.walk(tree):
            if isinstance(node, (ast.Name, ast.Attribute)) and id(node) not in as_receiver:
                ctx = getattr(node, "ctx", None)
                name = node.id if isinstance(node, ast.Name) else node.attr
                if isinstance(ctx, ast.Load):
                    uses.setdefault(name, set()).add("<value>")
    return uses


def _eval_flags(node):
    if node is None:
        return 0
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "re":
        return int(getattr(re, node.attr))
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        a, b = _eval_flags(node.left), _eval_flags(node.right)
        return None if a is None or b is None else a | b
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    return None


def _assigned_at_module_level(path):
    names = set()
    for node in ast.parse(path.read_text(encoding="utf-8"), str(path)).body:
        targets = node.targets if isinstance(node, ast.Assign) else (
            [node.target] if isinstance(node, ast.AnnAssign) else [])
        names.update(t.id for t in targets if isinstance(t, ast.Name))
    return names


def collect():
    """[(name, compiled pattern, mode)] - mode is 'match' or 'finditer'.

    A pattern re-exported by another module (the `checks` aggregator, a sibling that imports
    it) is reported once, under the module whose source ASSIGNS the name.
    """
    uses = _usage()
    out, seen = [], set()
    modules = []
    for info in pkgutil.walk_packages([str(PKG)], "clawseccheck."):
        if info.name.endswith("__main__"):
            continue
        mod = importlib.import_module(info.name)
        assigned = _assigned_at_module_level(Path(mod.__file__))
        modules.append((info.name, mod, assigned))
    # defining modules first, so a pattern is named after the module that assigns it
    for defining in (True, False):
        for mod_name, mod, assigned in modules:
            for attr, val in sorted(vars(mod).items()):
                if (attr in assigned) is not defining:
                    continue
                for pat in _values(val):
                    key = (pat.pattern, pat.flags)
                    if key in seen:
                        continue
                    seen.add(key)
                    u = uses.get(attr, {"<value>"})
                    mode = "match" if u and u <= {"match", "fullmatch"} else "finditer"
                    out.append((f"{mod_name}.{attr}", pat, mode))
    for path in sorted(PKG.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "re"
                    and node.func.attr in _METHODS | {"compile"} and node.args
                    and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
                continue
            fl_node = None
            if node.func.attr in {"compile", "search", "match", "fullmatch", "finditer", "findall", "split"}:
                fl_node = node.args[1] if node.func.attr == "compile" and len(node.args) > 1 else None
                fl_node = fl_node or next((k.value for k in node.keywords if k.arg == "flags"), None)
            fl = _eval_flags(fl_node)
            if fl is None:
                continue
            try:
                pat = re.compile(node.args[0].value, fl)
            except re.error:
                continue
            key = (pat.pattern, pat.flags)
            if key in seen:
                continue
            seen.add(key)
            mode = "match" if node.func.attr in {"match", "fullmatch"} else "finditer"
            out.append((f"{path.relative_to(ROOT)}:{node.lineno}", pat, mode))
    return out


def _timed(pat, mode, text):
    t0 = time.perf_counter()
    if mode == "match":
        pat.match(text)
    else:
        for _ in pat.finditer(text):
            pass
    return time.perf_counter() - t0


def _best(pat, mode, text, n=3):
    return min(_timed(pat, mode, text) for _ in range(n))


MEASURABLE_S = 0.002    # below this a single timing says nothing about growth
IDLE_S = 0.00002        # 2,000 characters in under 20 microseconds: the engine is not even
#                         trying positions (a literal prefix that never occurs) - linear
FAST_32K_S = 0.0005     # 32,000 characters in under half a millisecond: even if that grew
#                         quadratically from here, a megabyte would cost under half a second


def _text_of(pat, unit, size):
    text = unit * (size // len(unit))
    return text.encode("latin-1") if isinstance(pat.pattern, bytes) else text


def is_quadratic(pat, mode, unit):
    """True when *pat* grows quadratically on *unit* repeated; False when it was measured
    linear; None when it never became slow enough to measure.

    Two sizes 4x apart are compared: linear costs about 4x, quadratic about 16x. WHICH two
    depends on the pattern: 2,000 against 8,000 when 2,000 characters already take a
    measurable time; otherwise 2,000 against 32,000 as a coarse first look (16x the input:
    about 16x when linear, 256x when quadratic) and, only when that looks steep, 32,000
    against 128,000 - a pattern with a small constant is invisible at 2,000 characters and
    takes minutes at a megabyte.
    """
    t2k = _timed(pat, mode, _text_of(pat, unit, 2000))
    if t2k > SMALL_HANG_S:
        return True
    if t2k < IDLE_S:
        return None
    if t2k >= MEASURABLE_S:
        t8k = _timed(pat, mode, _text_of(pat, unit, 8000))
        if t8k > 0.03 and t8k > 7 * t2k:
            return _confirm(pat, mode, unit, 8000)
        return False
    t32k = _timed(pat, mode, _text_of(pat, unit, 32000))
    if t32k < FAST_32K_S:
        return None
    if t32k > 2.0:
        return True                 # 2,000 took under 2 ms and 16x the input takes over 2 s
    if t32k <= 60 * t2k:
        return False                # 16x the input cost about 16x (quadratic would be 256x)
    t128k = _timed(pat, mode, _text_of(pat, unit, 128000))
    if t128k > 0.03 and t128k > 7 * t32k:
        return _confirm(pat, mode, unit, 128000)
    return False


def _confirm(pat, mode, unit, size):
    """One retry against a noisy machine: the size below *size* against *size* itself."""
    small = _text_of(pat, unit, size // 4)
    big = _text_of(pat, unit, size)
    t1 = _best(pat, mode, small, 3)
    t2 = _best(pat, mode, big, 2)
    return t2 > 0.03 and t2 > 7 * max(t1, 1e-6)


def quadratic_unit(pat, mode):
    for unit in UNITS:
        if is_quadratic(pat, mode, unit):
            return unit
    return None


def test_control_a_known_quadratic_pattern_is_caught():
    assert is_quadratic(re.compile(r"[\w.]*x[\w.]*"), "finditer", "a") is True


def test_control_a_linear_pattern_is_not_flagged():
    assert quadratic_unit(re.compile(r"(?<![\w.])[\w.]*x[\w.]*"), "finditer") is None


def test_usage_map_sees_match_only_and_value_uses():
    uses = _usage()
    # a pattern iterated through a loop variable (`for rx in (A, B): rx.finditer`) is a value use
    assert uses["_SECRET_PATH_RE"] >= {"search", "<value>"}
    assert uses["_B185_CONCEAL_OBJECT_SECRET_RE"] == {"match"}


def test_the_reference_patterns_are_not_called():
    """Every allowlisted pattern is there because nothing in the package runs it over text:
    no `.search` / `.match` / `.finditer` / `.sub` ... on it anywhere (reading `.pattern` to
    build another pattern is a value use)."""
    uses = _usage()
    for name in ALLOWLIST:
        assert uses.get(name, set()) <= {"<value>"}, (name, uses.get(name))


def test_allowlist_reasons_name_a_constant_that_exists():
    for name, (reason, const) in ALLOWLIST.items():
        mod_name, _, attr = const.rpartition(".")
        assert reason.strip()
        assert hasattr(importlib.import_module(mod_name), attr), f"{name}: {const} does not exist"


_COLLECTED = None


def _collected():
    global _COLLECTED
    if _COLLECTED is None:
        _COLLECTED = collect()
    return _COLLECTED


def test_collector_finds_the_patterns_this_task_is_about():
    names = {n for n, _p, _m in _collected()}
    assert "clawseccheck.checks._shared._SECRET_PATH_RE" in names
    assert len(names) > 400


def test_every_pattern_in_the_package_is_linear_time():
    bad, still_open = {}, set()
    for name, pat, mode in _collected():
        short = name.rsplit(".", 1)[-1]
        if name in ALLOWLIST or short in ALLOWLIST:
            continue
        unit = quadratic_unit(pat, mode)
        if short in OPEN_UNDER_C730 or name in OPEN_UNDER_C730:
            if unit is not None:
                still_open.add(short)
            continue
        if unit is not None:
            bad[name] = unit
    assert not bad, f"quadratic patterns (name: unit): {bad}"
    stale = {k for k in OPEN_UNDER_C730 if k not in still_open and k.rsplit(".", 1)[-1] not in still_open}
    assert not stale, f"fixed - delete from OPEN_UNDER_C730: {stale}"


# --------------------------------------------------------------------------- whole audit

_CHILD = textwrap.dedent(
    """
    import os, sys, time
    sys.path.insert(0, {root!r})
    os.environ["HOME"] = {home!r}
    from clawseccheck import audit
    t0 = time.perf_counter()
    audit(home={oc!r})
    print(time.perf_counter() - t0)
    """
)


def _home(tmp_path, unit, size, label):
    base = tmp_path / label
    oc = base / "home" / ".openclaw"
    shutil.copytree(ROOT / "fixtures" / "home_safe", oc)
    line = (unit * (size // len(unit) + 1))[:size]
    for rel in ("workspace/SOUL.md", "workspace/memory/notes.md", "skills/longline/SKILL.md"):
        p = oc / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(line, encoding="utf-8")
    for q in [oc, *oc.rglob("*")]:
        os.chmod(q, 0o700 if q.is_dir() else 0o600)
    return base / "home", oc


def _audit_seconds(tmp_path, unit, size, label, cap):
    home, oc = _home(tmp_path, unit, size, label)
    code = _CHILD.format(root=str(ROOT), home=str(home), oc=str(oc))
    try:
        res = subprocess.run([sys.executable, "-B", "-W", "ignore", "-c", code],
                             capture_output=True, text=True, timeout=cap, cwd=str(tmp_path))
    except subprocess.TimeoutExpired:
        pytest.fail(f"audit of a home with {size}-character {unit!r} lines did not finish in {cap}s")
    assert res.returncode == 0, res.stderr[-600:]
    return float(res.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize("unit", ["x", "a.", "a/"])
def test_audit_time_grows_linearly_with_one_long_line(tmp_path, unit):
    """4x the line length must cost about 4x (a quadratic regex costs 16x). Both runs are
    measured here, in child processes of the same kind; no absolute seconds are asserted
    (the kill timeout is only a net for a run that never finishes)."""
    t_small = _audit_seconds(tmp_path, unit, 75_000, "small", 240)
    t_large = _audit_seconds(tmp_path, unit, 300_000, "large", 40 * max(t_small, 1.0))
    assert t_large < 9 * t_small, (unit, t_small, t_large)
