"""C-658: no ``Path.glob`` / ``rglob`` / ``resolve`` call may be added to ``clawseccheck/``
without a recorded reason.

Three pathlib families differ between the interpreters CI runs, in the "unreadable reads as
absent" direction (measured 2026-10-05 on 3.9.25, 3.12.3, 3.14.4):

  * ``Path.glob`` / ``rglob`` over a root under an unsearchable parent raise ``PermissionError``
    on 3.9 and 3.12 and return ``[]`` on 3.14; a pattern with a literal middle segment under a
    searchable-but-not-listable directory (``agents/*/sessions/...``) finds a different answer
    on 3.12 than on 3.9 and 3.14;
  * ``Path.resolve()`` on a symlink loop raises ``RuntimeError`` on 3.9 and 3.12 and returns the
    path on 3.14; ``resolve(strict=True)`` raises ``RuntimeError`` there and ``OSError`` on 3.14.

C-647 replaced the four predicates (``exists`` / ``is_dir`` / ``is_file`` / ``is_symlink``) with
``clawseccheck/pathprobe.py``. These three APIs have no such leaf yet, and this guard is what
stops a NEW call from quietly adding another interpreter-dependent answer while that is worked
(it is the guard test of C-658; the sites below are the survey of the tree as it stood).

It AST-scans every ``clawseccheck/**/*.py`` and fails on any of these, under any spelling:

  * an attribute named ``glob`` / ``rglob`` / ``iglob`` / ``resolve`` read from ANY receiver
    (a call, with or without ``strict=``, or a bare reference such as ``map(Path.resolve,
    xs)``), plus ``getattr`` / ``hasattr`` / ``operator.methodcaller`` spellings of those names
    with a constant string;
  * the ``glob`` MODULE functions (``glob.glob`` / ``glob.iglob``), through every alias the
    module binds (``import glob as g``, ``from glob import glob as gg``, ``h = glob``). They
    swallow ``OSError`` on every interpreter, a different contract from ``Path.glob``, so they
    are counted under their own spelling ``glob.glob`` / ``glob.iglob`` and none exists today.

How a receiver is judged: by name, never by type (an AST scan cannot know a type). Every
``.glob`` / ``.rglob`` / ``.resolve`` is presumed to be a pathlib object unless its module,
enclosing function, receiver source and spelling are in the COUNTED ``_NON_PATHLIB`` list, each
decided by reading the receiver's origin. ``os.path.realpath`` is NOT flagged: it is the
sanctioned non-raising form and never reads as ``.resolve``. ``fnmatch`` has no attribute of
these names, so it is not an issue.

Everything flagged today is in the COUNTED ``_ALLOWED`` dict: each entry names module +
enclosing function + canonical spelling, an exact count, and a one-line reason drawn from a
closed set of classes (``_C_GUARDED`` / ``_C_SAME`` / ``_C_SURVEY`` / ``_C_UNCLASSIFIED``). A NEW
call in a listed function still fails (the count is exact), an entry whose site disappeared
fails too (a stale allowlist is a hole), and a ``_C_GUARDED`` entry is checked against the
code: every counted site must sit in the body of a ``try`` / ``contextlib.suppress`` of the same
function whose handler names the exception the interpreters differ by, so the reason cannot go
stale without the test noticing. The scanner is exercised against synthetic modules so the
guard is shown to be able to fail.
"""
from __future__ import annotations

import ast
import re
from collections import Counter
from pathlib import Path
from typing import NamedTuple

import pytest

pytestmark = pytest.mark.mechanical

_ROOT = Path(__file__).resolve().parents[1]
_PKG = _ROOT / "clawseccheck"

_GLOB_ATTRS = frozenset({"glob", "rglob", "iglob"})
_NAMES = _GLOB_ATTRS | {"resolve"}

_TRY_NODES = (ast.Try,) + ((ast.TryStar,) if hasattr(ast, "TryStar") else ())
_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)

# An exception handler that covers the failure the interpreters differ by.
_OS_FAMILY = frozenset({"OSError"})
_RT_FAMILY = frozenset({"RuntimeError"})
_BROAD = frozenset({"Exception", "BaseException", "<bare>"})


# ------------------------------------------------------------------------------ the scanner


class _Hit(NamedTuple):
    lineno: int
    qual: str
    spelling: str
    recv: str
    how: str
    family: str          # "glob" or "resolve"
    strict: bool         # resolve(strict=...) / resolve(<positional>)
    caught: frozenset    # exception names handled around the site, same function only


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


def _exc_names(expr: "ast.AST | None") -> set:
    if expr is None:
        return {"<bare>"}
    elts = expr.elts if isinstance(expr, ast.Tuple) else [expr]
    out = set()
    for e in elts:
        name = e.id if isinstance(e, ast.Name) else e.attr if isinstance(e, ast.Attribute) else None
        if name:
            out.add("OSError" if name in ("IOError", "EnvironmentError") else name)
    return out


def _caught(node: ast.AST, parents: dict) -> frozenset:
    """Exception names handled around *node* by a ``try`` body or ``with suppress(...)`` of the
    SAME function (a handler in a caller does not count: it is not part of this site)."""
    out: set = set()
    cur = node
    while cur in parents:
        par = parents[cur]
        if isinstance(par, _SCOPE_NODES):
            break
        if isinstance(par, _TRY_NODES) and cur in par.body:
            for h in par.handlers:
                out |= _exc_names(h.type)
        elif isinstance(par, (ast.With, ast.AsyncWith)) and cur in par.body:
            for item in par.items:
                ce = item.context_expr
                if isinstance(ce, ast.Call) and (_dotted(ce.func) or "").split(".")[-1] == "suppress":
                    for a in ce.args:
                        out |= _exc_names(a)
        cur = par
    return frozenset(out)


class _Aliases:
    """Per-module name resolution, collected over the whole tree (function-local imports
    included): which names are the ``glob`` module and which bare names are ``glob.glob`` /
    ``glob.iglob`` imported by name."""

    def __init__(self, tree: ast.AST):
        self.glob_mod: set = set()   # names bound to the glob module
        self.glob_fn: dict = {}      # local name -> "glob.glob" / "glob.iglob"
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name == "glob":
                        self.glob_mod.add(a.asname or "glob")
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for a in node.names:
                    local = a.asname or a.name
                    if mod == "glob" and a.name in ("glob", "iglob"):
                        self.glob_fn[local] = f"glob.{a.name}"
                    elif mod != "glob" and a.name == "glob":
                        self.glob_mod.add(local)  # `from pkg import glob` (a re-export)
        # `h = glob` / `f = gg`: iterate to a fixpoint so chains resolve.
        changed = True
        while changed:
            changed = False
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Name)):
                    continue
                for tgt in node.targets:
                    if not isinstance(tgt, ast.Name):
                        continue
                    if node.value.id in self.glob_mod and tgt.id not in self.glob_mod:
                        self.glob_mod.add(tgt.id)
                        changed = True
                    if node.value.id in self.glob_fn and tgt.id not in self.glob_fn:
                        self.glob_fn[tgt.id] = self.glob_fn[node.value.id]
                        changed = True

    def is_glob_module(self, node: ast.AST) -> bool:
        return isinstance(node, ast.Name) and node.id in self.glob_mod


def _strict_form(call: ast.Call) -> bool:
    """True for ``resolve(True)`` / ``resolve(strict=True)`` / ``resolve(**kw)``: the strict
    form, whose failure type differs again (RuntimeError vs OSError). ``Path.resolve`` takes at
    most one positional argument, so a call with more is some other ``resolve`` method and its
    positional arguments say nothing about strictness."""
    if len(call.args) > 1:
        return False
    if call.args:
        a = call.args[0]
        return not (isinstance(a, ast.Constant) and a.value is False)
    for kw in call.keywords:
        if kw.arg is None:
            return True
        if kw.arg == "strict":
            return not (isinstance(kw.value, ast.Constant) and kw.value.value is False)
    return False


def _hits(tree: ast.AST):
    """Yield a ``_Hit`` for every glob / rglob / iglob / resolve access, under any spelling."""
    parents = _parents(tree)
    al = _Aliases(tree)

    def make(node, spelling, recv, how, family, strict=False):
        return _Hit(node.lineno, _qualname(node, parents), spelling, recv, how, family, strict,
                    _caught(node, parents))

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in _NAMES and isinstance(node.ctx, ast.Load):
            parent = parents.get(node)
            is_call = isinstance(parent, ast.Call) and parent.func is node
            recv = ast.unparse(node.value)
            strict = False
            if node.attr in ("glob", "iglob") and al.is_glob_module(node.value):
                spelling, family, how = f"glob.{node.attr}", "glob", "function of the glob module"
            elif node.attr == "resolve":
                strict = is_call and _strict_form(parent)
                spelling = "resolve(strict)" if strict else "resolve"
                family, how = "resolve", "Path.resolve"
            else:
                spelling, family, how = node.attr, "glob", f"Path.{node.attr}"
            if not is_call:
                spelling += " (reference)"
                how += " as a reference"
            yield make(node, spelling, recv, how, family, strict)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in al.glob_fn:
            parent = parents.get(node)
            is_call = isinstance(parent, ast.Call) and parent.func is node
            spelling = al.glob_fn[node.id] + ("" if is_call else " (reference)")
            yield make(node, spelling, node.id, "use of a name imported from glob", "glob")
        elif isinstance(node, ast.Call):
            fn = _dotted(node.func)
            idx = {"getattr": 1, "hasattr": 1, "operator.methodcaller": 0,
                   "methodcaller": 0}.get(fn)
            if idx is None or len(node.args) <= idx:
                continue
            arg = node.args[idx]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value in _NAMES:
                fam = "resolve" if arg.value == "resolve" else "glob"
                recv = ast.unparse(node.args[0]) if idx else "<methodcaller>"
                short = fn.split(".")[-1]
                yield make(node, f"{short}:{arg.value}", recv, f"{fn}() with a string", fam)


def _site_key(hit: _Hit, rel: str) -> tuple:
    return (rel, hit.qual, hit.spelling)


def _nonpath_key(hit: _Hit, rel: str) -> tuple:
    return (rel, hit.qual, hit.recv, hit.spelling)


def scan_source(source: str, rel: str, allow: dict, nonpath: "dict | None" = None
                ) -> "tuple[list[str], Counter]":
    """(problems, allowlist-use counts) for one module's source text."""
    nonpath = nonpath or {}
    problems = []
    used: Counter = Counter()
    for hit in _hits(ast.parse(source)):
        npk = _nonpath_key(hit, rel)
        key = _site_key(hit, rel)
        if npk in nonpath:
            used[npk] += 1
        elif key in allow:
            used[key] += 1
        else:
            problems.append(
                f"{rel}:{hit.lineno} in {hit.qual}: uncounted '{hit.recv}.{hit.spelling}' "
                f"({hit.how}) - pathlib glob/rglob/resolve answer differently per interpreter on an "
                f"unreadable or looping path (C-658); probe the path so every Python gives the same "
                f"answer, or add the site to _ALLOWED with a reason (or to _NON_PATHLIB if the "
                f"receiver is not a pathlib object)"
            )
    return problems, used


def _reconcile(allow: dict, nonpath: dict, used: Counter) -> "list[str]":
    out = []
    for key, (expected, _reason) in allow.items():
        if used[key] != expected:
            out.append(
                f"allowlist entry {key} expects {expected} site(s) but the scan found "
                f"{used[key]} - a moved/removed call leaves a stale hole, an extra one is a new "
                f"uncounted call in the same function"
            )
    for key, (expected, _reason) in nonpath.items():
        if used[key] != expected:
            out.append(
                f"non-pathlib entry {key} expects {expected} site(s) but the scan found "
                f"{used[key]} - a moved/removed receiver leaves a stale hole"
            )
    return out


def scan_package(root: Path, allow: dict, nonpath: dict) -> "list[str]":
    problems = []
    used: Counter = Counter()
    for path in sorted((root / "clawseccheck").rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        got, n = scan_source(path.read_text(encoding="utf-8"), rel, allow, nonpath)
        problems += got
        used += n
    return problems + _reconcile(allow, nonpath, used)


def package_sites(root: Path) -> "dict[tuple, list[_Hit]]":
    """Every flagged site in the tree, keyed like ``_ALLOWED`` (nothing exempted)."""
    out: dict = {}
    for path in sorted((root / "clawseccheck").rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        for hit in _hits(ast.parse(path.read_text(encoding="utf-8"))):
            out.setdefault(_site_key(hit, rel), []).append(hit)
    return out


def _is_covered(hit: _Hit) -> bool:
    """Does a handler around *hit* name the failure the interpreters differ by? glob: an
    OSError (PermissionError on 3.9/3.12); resolve: a RuntimeError (loop on 3.9/3.12); the
    strict form: both (RuntimeError on 3.9/3.12, OSError on 3.14)."""
    os_ok = bool(hit.caught & (_OS_FAMILY | _BROAD))
    rt_ok = bool(hit.caught & (_RT_FAMILY | _BROAD))
    if hit.family == "glob":
        return os_ok
    return rt_ok and (os_ok if hit.strict else True)


# ----------------------------------------------------------------------- reason classes

# One-line reasons, from a closed set. A `_C_GUARDED` entry is verified against the code (see
# test_every_guarded_entry_really_sits_under_a_handler); the others are recorded judgments.
_C_GUARDED = "guarded by a handler in the same function: "
_C_SAME = "same outcome on every interpreter: "
_C_SURVEY = ("pre-existing unguarded: C-658 survey (interpreter-dependent on a symlink loop / "
             "unreadable parent; disclosure-only or latent, no verdict difference found)")
_C_UNCLASSIFIED = "unclassified - C-658 residual"
_CLASSES = (_C_GUARDED, _C_SAME, _C_SURVEY, _C_UNCLASSIFIED)

# (repo-relative module, enclosing function qualname, receiver source, spelling) -> (count, reason).
# Receivers that are NOT pathlib objects, decided by reading where the receiver comes from.
# Reason texts shared by several entries (each is one line).
_R_SHIPPEDEXEC = ("not pathlib: `self.resolve` is _FileFacts.resolve(e, scope, depth), shippedexec's "
                  "own AST path resolver defined in the same class, called with AST nodes, never a Path")
_R_EXISTS_GATE = ("p is probed with pathprobe.exists first (a loop reads as absent and an unreadable "
                  "parent raises, on every interpreter), so resolve() never sees a loop")
_R_IS_FILE_GATE = ("path is probed with pathprobe.is_file first (a loop reads as absent on every "
                   "interpreter), so resolve() never sees a loop")
_R_SAFE_IS_FILE_GATE = ("path is probed with _safe_is_file (a try-wrapped pathprobe.is_file that "
                        "discloses an unreadable parent) first, so resolve() never sees a loop")
_R_OWN_FILE = ("resolves this package's own __file__, which the import system already opened, so there "
               "is no loop or unreadable parent for the interpreters to differ on")
_R_ROOT_PROBED = ("the glob root is probed with pathprobe.is_dir first (raises identically on every "
                  "interpreter), so the unsearchable-parent difference cannot arise; no handler needed")
_R_LITERAL_SEGMENT = (" (glob pattern with a literal segment under a '*' match, the cell A/C shape of "
                      "the task: the answer differs between 3.12 and 3.9/3.14 and the direction of "
                      "cell C was not reproduced; also under except OSError)")
_R_VET_PLUGIN_MIXED = (" (10 sites: 5 under a RuntimeError handler, 4 under OSError/ValueError-only "
                       "handlers, 1 unguarded `dispatched_dirs = [d.resolve() for d in skill_dirs]` "
                       "that may be the looping manifest-skills site the task names; not verified)")

_NON_PATHLIB: dict = {
    ("clawseccheck/shippedexec.py", "_FileFacts._join", "self", "resolve"):
        (1, _R_SHIPPEDEXEC),
    ("clawseccheck/shippedexec.py", "_FileFacts.content", "self", "resolve"):
        (1, _R_SHIPPEDEXEC),
    ("clawseccheck/shippedexec.py", "_FileFacts.resolve", "self", "resolve"):
        (6, _R_SHIPPEDEXEC),
    ("clawseccheck/shippedexec.py", "_FileFacts.shipped", "self", "resolve"):
        (1, _R_SHIPPEDEXEC),
}

# (repo-relative module, enclosing function qualname, spelling) -> (count, reason).
# Enumerated by running the scanner over the tree (dev 8bfc9039); every reason was decided by
# reading the site and its enclosing handlers, never inferred from its name.
_ALLOWED: dict = {
    ("clawseccheck/adjudication/_verdicts.py", "_vet_run_fingerprint", "resolve"):
        (1, _C_SURVEY),
    ("clawseccheck/checks/_capability.py", "check_path_safety", "resolve"):
        (2, _C_SURVEY),
    ("clawseccheck/checks/_capability.py", "check_path_safety._flag", "resolve"):
        (1, _C_SURVEY),
    ("clawseccheck/checks/_config.py", "_c015_candidate_files._keep_file", "resolve"):
        (1, _C_SAME + _R_SAFE_IS_FILE_GATE),
    ("clawseccheck/checks/_content.py", "check_symlink_escape", "resolve"):
        (1, _C_SURVEY),
    ("clawseccheck/checks/_egress.py", "_ancestors_allow_other_access", "resolve"):
        (2, _C_GUARDED + "except (OSError, RuntimeError, ValueError)"),
    ("clawseccheck/checks/_egress.py", "_b188_collect_backups", "rglob"):
        (1, _C_GUARDED + "except OSError"),
    ("clawseccheck/checks/_egress.py", "_b188_collect_state_copies", "rglob"):
        (1, _C_GUARDED + "except OSError"),
    ("clawseccheck/checks/_egress.py", "_collect_atrest_transcripts._grab", "rglob"):
        (1, _C_GUARDED + "except OSError"),
    ("clawseccheck/checks/_egress.py", "check_browser_executable_path", "resolve"):
        (1, _C_GUARDED + "except (OSError, RuntimeError)"),
    ("clawseccheck/checks/_host.py", "_check_incident_readiness_sqlite", "resolve"):
        (1, _C_SURVEY),
    ("clawseccheck/checks/_host.py", "check_incident_readiness", "resolve"):
        (1, _C_SURVEY),
    ("clawseccheck/checks/_lifecycle.py", "_b104_user_home", "resolve"):
        (2, _C_GUARDED + "except (OSError, RuntimeError, ValueError)"),
    ("clawseccheck/checks/_lifecycle.py", "_b181_confined_path", "resolve"):
        (2, _C_SURVEY),
    ("clawseccheck/checks/_lifecycle.py", "_b33_is_this_machines_home", "resolve"):
        (3, _C_GUARDED + "except Exception"),
    ("clawseccheck/checks/_lifecycle.py", "_writable_identity_files._first_time", "resolve"):
        (1, _C_SURVEY),
    ("clawseccheck/checks/_lifecycle.py", "check_backups", "resolve"):
        (3, _C_SURVEY),
    ("clawseccheck/checks/_lifecycle.py", "check_bootstrap_write_protection._classify_file", "resolve"):
        (1, _C_SAME + _R_IS_FILE_GATE),
    ("clawseccheck/checks/_lifecycle.py", "check_clawhub_lock_verification", "resolve"):
        (1, _C_SURVEY),
    ("clawseccheck/checks/_mcp.py", "_colocated_skill_dirs", "resolve"):
        (2, _C_SURVEY),
    ("clawseccheck/checks/_mcp.py", "_wrapper_unread_manifest_kind", "glob"):
        (2, _C_GUARDED + "except OSError"),
    ("clawseccheck/checks/_mcp.py", "sweep_plugins", "resolve"):
        (1, _C_SURVEY),
    ("clawseccheck/checks/_mcp.py", "vet_plugin", "resolve"):
        (10, _C_UNCLASSIFIED + _R_VET_PLUGIN_MIXED),
    ("clawseccheck/checks/_shared.py", "_username_safe_path", "resolve"):
        (2, _C_SAME + _R_EXISTS_GATE),
    ("clawseccheck/checks/_vet.py", "_locate_plugin_root_or_reason", "glob"):
        (2, _C_GUARDED + "except OSError"),
    ("clawseccheck/cli.py", "_threat_coverage_note", "resolve"):
        (1, _C_SAME + _R_OWN_FILE),
    ("clawseccheck/collector.py", "_bootstrap_identity", "resolve"):
        (1, _C_SURVEY),
    ("clawseccheck/collector.py", "_config_workspace_dirs", "resolve"):
        (2, _C_GUARDED + "except (OSError, RuntimeError, ValueError)"),
    ("clawseccheck/collector.py", "_cron_store_key_candidates", "resolve"):
        (1, _C_SURVEY),
    ("clawseccheck/collector.py", "_list_own_engine_sources", "glob"):
        (1, _C_GUARDED + "except OSError"),
    ("clawseccheck/collector.py", "_read_installed_skills", "resolve"):
        (3, _C_GUARDED + "except (OSError, RuntimeError, ValueError)"),
    ("clawseccheck/collector.py", "_recover_escaped_config_symlink", "resolve(strict)"):
        (1, _C_GUARDED + "except (OSError, RuntimeError, ValueError)"),
    ("clawseccheck/collector.py", "audits_default_state_dir", "resolve"):
        (3, _C_GUARDED + "except (OSError, RuntimeError, ValueError)"),
    ("clawseccheck/collector.py", "audits_this_users_own_home", "resolve"):
        (2, _C_GUARDED + "except (OSError, RuntimeError, ValueError)"),
    ("clawseccheck/collector.py", "global_dotenv_paths", "resolve"):
        (2, _C_GUARDED + "except (OSError, RuntimeError, ValueError)"),
    ("clawseccheck/collector.py", "skill_load_roots", "resolve"):
        (1, _C_GUARDED + "except (OSError, RuntimeError, ValueError)"),
    ("clawseccheck/configjournal.py", "_same_config", "resolve"):
        (2, _C_GUARDED + "except (OSError, RuntimeError, ValueError)"),
    ("clawseccheck/configloader.py", "_allowed_roots", "resolve"):
        (1, _C_SURVEY),
    ("clawseccheck/configloader.py", "_allowed_roots", "resolve(strict)"):
        (1, _C_GUARDED + "except (OSError, RuntimeError, ValueError)"),
    ("clawseccheck/configloader.py", "_resolve", "resolve(strict)"):
        (1, _C_GUARDED + "except (OSError, RuntimeError, ValueError)"),
    ("clawseccheck/configloader.py", "load_openclaw_config", "resolve"):
        (1, _C_SURVEY),
    ("clawseccheck/configloader.py", "load_openclaw_config", "resolve(strict)"):
        (1, _C_GUARDED + "except (OSError, RuntimeError, ValueError)"),
    ("clawseccheck/deptree.py", "_resolve_in_package", "resolve"):
        (2, _C_SURVEY),
    ("clawseccheck/deptree.py", "find_package_root", "resolve"):
        (1, _C_SURVEY),
    ("clawseccheck/hostwatch.py", "_has_files", "glob"):
        (1, _C_GUARDED + "except OSError"),
    ("clawseccheck/hostwatch.py", "_systemd_enabled", "glob"):
        (1, _C_GUARDED + "except OSError"),
    ("clawseccheck/integrity.py", "<module>", "resolve"):
        (1, _C_SAME + _R_OWN_FILE),
    ("clawseccheck/invocation.py", "_display_path", "resolve"):
        (1, _C_GUARDED + "except (OSError, RuntimeError)"),
    ("clawseccheck/invocation.py", "_is_our_entry_script", "resolve"):
        (1, _C_SAME + _R_OWN_FILE),
    ("clawseccheck/invocation.py", "_resolve", "resolve"):
        (1, _C_SURVEY),
    ("clawseccheck/invocation.py", "_shim_beside_the_package", "resolve"):
        (1, _C_SAME + _R_OWN_FILE),
    ("clawseccheck/livetestproof.py", "_within_home", "resolve"):
        (2, _C_SURVEY),
    ("clawseccheck/logdiscovery.py", "_generic_log_sinks", "glob"):
        (1, _C_GUARDED + "except OSError"),
    ("clawseccheck/logdiscovery.py", "_transcript_sinks", "glob"):
        (1, _C_GUARDED + "except OSError"),
    ("clawseccheck/logdiscovery.py", "discover_log_sinks._add_many", "resolve"):
        (1, _C_SURVEY),
    ("clawseccheck/monitor.py", "_home_identity", "resolve"):
        (1, _C_SURVEY),
    ("clawseccheck/monitordims/_memory.py", "_snapshot_memory_files", "rglob"):
        (1, _C_SAME + _R_ROOT_PROBED),
    ("clawseccheck/monitorstore.py", "_state_path_digest", "resolve"):
        (1, _C_SURVEY),
    ("clawseccheck/report.py", "_credential_surface_map", "rglob"):
        (1, _C_SAME + _R_ROOT_PROBED),
    ("clawseccheck/report.py", "_looks_like_quarantine", "resolve"):
        (2, _C_SURVEY),
    ("clawseccheck/safeio.py", "walk_dir_safely", "resolve"):
        (2, _C_SURVEY),
    ("clawseccheck/skilldiscovery.py", "iter_discovered_skill_dirs", "resolve"):
        (2, _C_GUARDED + "except (OSError, RuntimeError, ValueError)"),
    ("clawseccheck/skillprovenance.py", "_root_identity", "resolve"):
        (2, _C_GUARDED + "except (OSError, RuntimeError, ValueError)"),
    ("clawseccheck/skillprovenance.py", "workspace_roots", "resolve"):
        (1, _C_GUARDED + "except (OSError, RuntimeError, ValueError)"),
    ("clawseccheck/trajectory.py", "_resolve_pointer_target", "resolve"):
        (1, _C_GUARDED + "except (OSError, RuntimeError, ValueError)"),
    ("clawseccheck/trajectory.py", "find_trajectory_files", "glob"):
        (2, _C_UNCLASSIFIED + _R_LITERAL_SEGMENT),
    ("clawseccheck/trajectory.py", "find_trajectory_files", "resolve"):
        (2, _C_GUARDED + "except (OSError, RuntimeError, ValueError)"),
    ("clawseccheck/trajectorystore.py", "_archive_entries", "glob"):
        (1, _C_UNCLASSIFIED + _R_LITERAL_SEGMENT),
    ("clawseccheck/trajectorystore.py", "_pointer_files", "glob"):
        (1, _C_UNCLASSIFIED + _R_LITERAL_SEGMENT),
    ("clawseccheck/trajectorystore.py", "_sqlite_dbs", "glob"):
        (1, _C_UNCLASSIFIED + _R_LITERAL_SEGMENT),
    ("clawseccheck/trajectorystore.py", "sqlite_db_paths_capped", "glob"):
        (1, _C_UNCLASSIFIED + _R_LITERAL_SEGMENT),
    ("clawseccheck/watch.py", "PollWatcher._scan", "resolve"):
        (1, _C_SURVEY),
    ("clawseccheck/watch.py", "_bounded_watch_dirs", "resolve"):
        (1, _C_SURVEY),
}


# --------------------------------------------------------------------------- the real tree


def test_package_has_no_uncounted_glob_or_resolve():
    problems = scan_package(_ROOT, _ALLOWED, _NON_PATHLIB)
    assert not problems, "\n".join(problems)


def test_the_scan_sees_the_whole_package():
    """A control for the scan above: it must actually be reading the package (a wrong root
    would scan nothing and pass), including the subpackages, and with nothing exempted it must
    report exactly the listed sites."""
    files = {p.relative_to(_ROOT).as_posix() for p in _PKG.rglob("*.py")}
    for must in ("clawseccheck/pathprobe.py", "clawseccheck/collector.py",
                 "clawseccheck/checks/_vet.py", "clawseccheck/monitordims/_memory.py",
                 "clawseccheck/trajectorystore.py", "clawseccheck/skilldiscovery.py"):
        assert must in files, must
    assert len(files) > 50
    found = sum(len(scan_source((_ROOT / f).read_text(encoding="utf-8"), f, {})[0])
                for f in sorted(files))
    listed = (sum(c for c, _ in _ALLOWED.values()) + sum(c for c, _ in _NON_PATHLIB.values()))
    assert found == listed, (found, listed)


def test_every_guarded_entry_really_sits_under_a_handler():
    """A reason that says 'guarded' is a claim about the code; it is checked, not trusted."""
    sites = package_sites(_ROOT)
    bad = []
    for key, (_count, reason) in _ALLOWED.items():
        if not reason.startswith(_C_GUARDED):
            continue
        named = set(re.findall(r"[A-Z][A-Za-z]+", reason[len(_C_GUARDED):]))
        for hit in sites.get(key, []):
            if not _is_covered(hit) or not named <= hit.caught:
                bad.append(f"{key[0]}:{hit.lineno} in {key[1]} ({key[2]}): handlers "
                           f"{sorted(hit.caught) or 'none'} do not cover it or are not the ones "
                           f"named in the reason ({sorted(named)})")
    assert not bad, "\n".join(bad)


def test_the_real_allowlist_is_well_formed():
    """Every entry is a counted, one-line, classified site in a module that exists."""
    for table in (_ALLOWED, _NON_PATHLIB):
        for key, (count, reason) in table.items():
            assert (_ROOT / key[0]).is_file(), key[0]
            assert isinstance(count, int) and count >= 1, key
            assert isinstance(reason, str) and reason.strip() and "\n" not in reason, key
    for key, (_count, reason) in _ALLOWED.items():
        assert reason.startswith(_CLASSES), (key, reason)
        assert key[2].split(" ")[0].split("(")[0].split(":")[-1] in (
            _NAMES | {"glob.glob", "glob.iglob"}), key
    for key, (_count, reason) in _NON_PATHLIB.items():
        assert reason.startswith("not pathlib: "), (key, reason)


def test_the_real_allowlist_size_is_pinned_by_reason_class():
    """Keep the accepted set named and sized: a growing allowlist is how a guard becomes a
    rubber stamp. Raising a number needs a reason written next to the new entry; a site routed
    through a probe lowers it. (entries, sites) per class, measured on dev 8bfc9039 - 20 glob /
    rglob calls and 99 resolve calls, 9 of which are shippedexec's own method."""
    entries: Counter = Counter()
    sites: Counter = Counter()
    for (_rel, _fn, _spelling), (count, reason) in _ALLOWED.items():
        cls = next(c for c in _CLASSES if reason.startswith(c))
        entries[cls] += 1
        sites[cls] += count
    assert {c: (entries[c], sites[c]) for c in _CLASSES} == {
        _C_GUARDED: (31, 48),
        _C_SAME: (9, 10),
        _C_SURVEY: (27, 36),
        _C_UNCLASSIFIED: (6, 16),
    }
    assert (len(_ALLOWED), sum(c for c, _ in _ALLOWED.values())) == (73, 110)
    assert (len(_NON_PATHLIB), sum(c for c, _ in _NON_PATHLIB.values())) == (4, 9)
    by_name: Counter = Counter()
    for (_rel, _fn, spelling), (count, _reason) in _ALLOWED.items():
        by_name[spelling] += count
    assert dict(by_name) == {"glob": 15, "rglob": 5, "resolve": 86, "resolve(strict)": 4}, by_name
    assert not [k for k in _ALLOWED if k[2].startswith("glob.")], "the glob module is unused today"


# -------------------------------------------------- the guard can fail (synthetic modules)

_CASES_THAT_MUST_BE_REPORTED = {
    "glob": "def f(p):\n    return list(p.glob('*'))\n",
    "rglob": "def f(p):\n    return list(p.rglob('*.py'))\n",
    "iglob attribute": "def f(p):\n    return list(p.iglob('*'))\n",
    "resolve": "def f(p):\n    return p.resolve()\n",
    "resolve strict keyword": "def f(p):\n    return p.resolve(strict=True)\n",
    "resolve strict False": "def f(p):\n    return p.resolve(strict=False)\n",
    "resolve strict positional": "def f(p):\n    return p.resolve(True)\n",
    "resolve on an expression": "def f(a):\n    return (a / 'x').resolve()\n",
    "resolve on a call": "from pathlib import Path\ndef f(a):\n    return Path(a).resolve()\n",
    "resolve on a class": "from pathlib import Path\ndef f():\n    return Path.cwd().resolve()\n",
    "a resolve reference": "from pathlib import Path\ndef f(xs):\n    return list(map(Path.resolve, xs))\n",
    "a key= reference": "from pathlib import Path\ndef f(xs):\n    return sorted(xs, key=Path.resolve)\n",
    "a glob reference": "from pathlib import Path\ndef f(xs):\n    return [Path.glob(x, '*') for x in xs]\n",
    "a bound-method reference": "def f(p):\n    g = p.rglob\n    return list(g('*'))\n",
    "a renamed Path": "from pathlib import Path as P\ndef f(x):\n    return P(x).resolve()\n",
    "getattr with a string": "def f(p):\n    return getattr(p, 'resolve')()\n",
    "getattr glob": "def f(p):\n    return list(getattr(p, 'glob')('*'))\n",
    "getattr rglob": "def f(p):\n    return list(getattr(p, 'rglob')('*'))\n",
    "hasattr with a string": "def f(p):\n    return hasattr(p, 'resolve')\n",
    "methodcaller": "import operator\ndef f(xs):\n    return list(map(operator.methodcaller('resolve'), xs))\n",
    "methodcaller imported": ("from operator import methodcaller\ndef f(xs):\n"
                              "    return list(map(methodcaller('rglob', '*'), xs))\n"),
    "glob.glob": "import glob\ndef f(p):\n    return glob.glob(p)\n",
    "glob.iglob": "import glob\ndef f(p):\n    return list(glob.iglob(p))\n",
    "glob module alias": "import glob as g\ndef f(p):\n    return g.glob(p)\n",
    "glob function by name": "from glob import glob\ndef f(p):\n    return glob(p)\n",
    "glob function aliased": "from glob import glob as gg\ndef f(p):\n    return gg(p)\n",
    "iglob by name": "from glob import iglob\ndef f(p):\n    return list(iglob(p))\n",
    "glob module rebinding": "import glob\nh = glob\ndef f(p):\n    return h.glob(p)\n",
    "glob function rebinding": "from glob import glob\nh = glob\ndef f(p):\n    return h(p)\n",
    "a glob function reference": "from glob import glob\ndef f(xs):\n    return list(map(glob, xs))\n",
    "a re-exported glob module": "from pkg import glob\ndef f(p):\n    return glob.glob(p)\n",
    "a function-local glob import": "def f(p):\n    import glob\n    return glob.glob(p)\n",
    "a method on a class": "class C:\n    def m(self, p):\n        return p.resolve()\n",
    "a nested function": "def f(p):\n    def g():\n        return p.resolve()\n    return g()\n",
    "a module-level call": "from pathlib import Path\nHERE = Path('.').resolve()\n",
    "a call in a comprehension": "def f(xs):\n    return [x.resolve() for x in xs]\n",
    "a call in a lambda": "def f(xs):\n    return sorted(xs, key=lambda x: x.resolve())\n",
    "an attribute chain": "def f(self):\n    return self.home.resolve()\n",
    "a call under a handler that does not cover it": (
        "def f(p):\n    try:\n        return p.resolve()\n    except KeyError:\n        return None\n"),
}


@pytest.mark.parametrize("label", sorted(_CASES_THAT_MUST_BE_REPORTED))
def test_the_guard_reports_an_uncounted_call(label):
    problems, _ = scan_source(_CASES_THAT_MUST_BE_REPORTED[label], "clawseccheck/synthetic.py", {})
    assert problems, f"the guard missed: {label}"


_CASES_THAT_MUST_PASS = {
    "os.path.realpath": "import os\ndef f(p):\n    return os.path.realpath(p)\n",
    "os.path.abspath": "import os\ndef f(p):\n    return os.path.abspath(p)\n",
    "pathprobe": "from . import pathprobe\ndef f(p):\n    return pathprobe.is_dir(p)\n",
    "an unrelated attribute": "def f(p):\n    return p.stat().st_mode\n",
    "iterdir": "def f(p):\n    return list(p.iterdir())\n",
    "fnmatch": "import fnmatch\ndef f(a, b):\n    return fnmatch.fnmatch(a, b)\n",
    "glob.escape": "import glob\ndef f(s):\n    return glob.escape(s)\n",
    "an unused glob import": "import glob\n",
    "a string that is not a name lookup": "def f():\n    return 'resolve'\n",
    "a local function named resolve": "def resolve(x):\n    return x\ndef f(x):\n    return resolve(x)\n",
    "a local function named glob": "def glob(x):\n    return x\ndef f(x):\n    return glob(x)\n",
    "a store to an attribute": "def f(o):\n    o.resolve = 1\n    o.glob = 2\n",
    "getattr on another name": "def f(o):\n    return getattr(o, 'stat')\n",
    "methodcaller of another name": ("import operator\ndef f(xs):\n"
                                     "    return list(map(operator.methodcaller('stat'), xs))\n"),
}


@pytest.mark.parametrize("label", sorted(_CASES_THAT_MUST_PASS))
def test_the_guard_accepts_the_sanctioned_and_unrelated_spellings(label):
    problems, _ = scan_source(_CASES_THAT_MUST_PASS[label], "clawseccheck/synthetic.py", {})
    assert not problems, (label, problems)


def test_the_guard_reports_the_exact_location_and_the_replacement():
    problems, _ = scan_source("def f(p):\n    x = 1\n    return p.resolve()\n",
                              "clawseccheck/synthetic.py", {})
    assert len(problems) == 1
    assert problems[0].startswith("clawseccheck/synthetic.py:3 in f:")
    assert "p.resolve" in problems[0] and "C-658" in problems[0]


def test_each_spelling_has_its_own_canonical_name():
    """The allowlist key is the spelling, so the strict form, a reference, the glob module and
    the dynamic spellings can each be counted apart from a plain call."""
    def spellings(src):
        return sorted(h.spelling for h in _hits(ast.parse(src)))
    assert spellings("def f(p):\n    return p.resolve()\n") == ["resolve"]
    assert spellings("def f(p):\n    return p.resolve(strict=True)\n") == ["resolve(strict)"]
    assert spellings("def f(p):\n    return p.resolve(strict=False)\n") == ["resolve"]
    assert spellings("def f(xs):\n    return map(Path.resolve, xs)\n") == ["resolve (reference)"]
    assert spellings("def f(p):\n    return p.glob('*'), p.rglob('*')\n") == ["glob", "rglob"]
    assert spellings("import glob as g\ndef f(p):\n    return g.glob(p), g.iglob(p)\n") == [
        "glob.glob", "glob.iglob"]
    assert spellings("from glob import glob as gg\ndef f(p):\n    return gg(p)\n") == ["glob.glob"]
    assert spellings("def f(p):\n    return getattr(p, 'resolve'), hasattr(p, 'glob')\n") == [
        "getattr:resolve", "hasattr:glob"]


def test_the_handler_walk_stops_at_the_function_boundary_and_the_handler_body():
    def caught(src):
        return [sorted(h.caught) for h in _hits(ast.parse(src))]
    guarded = "def f(p):\n    try:\n        return p.resolve()\n    except (OSError, RuntimeError):\n        return None\n"
    assert caught(guarded) == [["OSError", "RuntimeError"]]
    in_handler = ("def f(p):\n    try:\n        return 1\n    except OSError:\n"
                  "        return p.resolve()\n")
    assert caught(in_handler) == [[]]
    in_else = ("def f(p):\n    try:\n        x = 1\n    except OSError:\n        x = 2\n"
               "    else:\n        x = p.resolve()\n    return x\n")
    assert caught(in_else) == [[]]
    nested = ("def f(p):\n    try:\n        def g():\n            return p.resolve()\n"
              "        return g()\n    except Exception:\n        return None\n")
    assert caught(nested) == [[]]
    suppressed = ("import contextlib\ndef f(p):\n    with contextlib.suppress(OSError):\n"
                  "        return list(p.glob('*'))\n")
    assert caught(suppressed) == [["OSError"]]
    legacy = "def f(p):\n    try:\n        return p.resolve()\n    except IOError:\n        return None\n"
    assert caught(legacy) == [["OSError"]]


def test_the_covered_check_can_fail():
    def hit(src):
        return next(iter(_hits(ast.parse(src))))
    base = "def f(p):\n    try:\n        return {call}\n    except {exc}:\n        return None\n"
    assert _is_covered(hit(base.format(call="p.resolve()", exc="(OSError, RuntimeError)")))
    assert _is_covered(hit(base.format(call="p.resolve()", exc="Exception")))
    assert not _is_covered(hit(base.format(call="p.resolve()", exc="OSError")))  # a loop is RuntimeError
    assert not _is_covered(hit(base.format(call="p.resolve()", exc="KeyError")))
    assert not _is_covered(hit("def f(p):\n    return p.resolve()\n"))
    assert _is_covered(hit(base.format(call="list(p.glob('*'))", exc="OSError")))
    assert not _is_covered(hit(base.format(call="list(p.glob('*'))", exc="RuntimeError")))
    assert not _is_covered(hit(base.format(call="p.resolve(strict=True)", exc="RuntimeError")))
    assert not _is_covered(hit(base.format(call="p.resolve(strict=True)", exc="OSError")))
    assert _is_covered(hit(base.format(call="p.resolve(strict=True)", exc="(OSError, RuntimeError)")))


# ---------------------------------------------------------------- the counted allowlist

_ALLOW_KEY = ("clawseccheck/synthetic.py", "walk", "resolve")
_ALLOW = {_ALLOW_KEY: (1, _C_SURVEY)}
_SYNTH_ONE = "def walk(p):\n    return p.resolve()\n"
_SYNTH_TWO = "def walk(p):\n    p.resolve()\n    return p.resolve()\n"
_NP_KEY = ("clawseccheck/synthetic.py", "C.walk", "self", "resolve")
_NONPATH = {_NP_KEY: (1, "not pathlib: synthetic")}
_SYNTH_NP = "class C:\n    def walk(self):\n        return self.resolve()\n"


def _problems_for(source: str, allow: dict, nonpath: "dict | None" = None,
                  rel: str = "clawseccheck/synthetic.py") -> "list[str]":
    """The same reconciliation scan_package performs, over one synthetic module."""
    nonpath = nonpath or {}
    got, used = scan_source(source, rel, allow, nonpath)
    return got + _reconcile(allow, nonpath, used)


def test_an_allowlisted_call_passes_at_its_exact_count():
    assert _problems_for(_SYNTH_ONE, _ALLOW) == []


def test_a_second_call_in_the_same_function_still_fails():
    problems = _problems_for(_SYNTH_TWO, _ALLOW)
    assert problems and any("expects 1" in p for p in problems), problems


def test_a_stale_allowlist_entry_fails():
    problems = _problems_for("def walk(p):\n    return p\n", _ALLOW)
    assert problems and any("expects 1" in p for p in problems), problems


def test_an_allowlist_entry_does_not_cover_another_function_spelling_or_module():
    other_fn = "def other(p):\n    return p.resolve()\n"
    other_spelling = "def walk(p):\n    return p.resolve(strict=True)\n"
    other_name = "def walk(p):\n    return list(p.glob('*'))\n"
    reference = "from pathlib import Path\ndef walk(xs):\n    return list(map(Path.resolve, xs))\n"
    for label, src in (("function", other_fn), ("spelling", other_spelling),
                       ("attribute", other_name), ("reference", reference)):
        got, _ = scan_source(src, "clawseccheck/synthetic.py", _ALLOW)
        assert got, f"an allowlist entry leaked across {label}"
    got, _ = scan_source(_SYNTH_ONE, "clawseccheck/other_module.py", _ALLOW)
    assert got, "an allowlist entry leaked across modules"


def test_the_glob_module_is_counted_apart_from_path_glob():
    allow = {("clawseccheck/synthetic.py", "walk", "glob"): (1, _C_SURVEY)}
    src = "import glob\ndef walk(p):\n    return glob.glob(p)\n"
    got, _ = scan_source(src, "clawseccheck/synthetic.py", allow)
    assert got, "a glob.glob call was accepted by an entry for Path.glob"
    allow = {("clawseccheck/synthetic.py", "walk", "glob.glob"): (1, _C_SURVEY)}
    assert _problems_for(src, allow) == []


def test_a_non_pathlib_entry_is_counted_and_scoped_by_receiver():
    assert _problems_for(_SYNTH_NP, {}, _NONPATH) == []
    two = "class C:\n    def walk(self):\n        self.resolve()\n        return self.resolve()\n"
    problems = _problems_for(two, {}, _NONPATH)
    assert problems and any("expects 1" in p for p in problems), problems
    assert _problems_for("class C:\n    def walk(self):\n        return 1\n", {}, _NONPATH), (
        "a stale non-pathlib entry did not fail")
    other_recv = "class C:\n    def walk(self, p):\n        return p.resolve()\n"
    got, _ = scan_source(other_recv, "clawseccheck/synthetic.py", {}, _NONPATH)
    assert got, "a non-pathlib entry leaked to another receiver"


def test_the_canonical_spelling_survives_an_alias_rename():
    """The key is the resolved spelling, so renaming the glob import does not turn an accepted
    site into a stale entry plus a new violation."""
    allow = {("clawseccheck/synthetic.py", "walk", "glob.glob"): (1, _C_SURVEY)}
    for imp, call in (("import glob", "glob.glob(p)"), ("import glob as g", "g.glob(p)"),
                      ("from glob import glob", "glob(p)"),
                      ("from glob import glob as gg", "gg(p)")):
        src = f"{imp}\ndef walk(p):\n    return {call}\n"
        assert _problems_for(src, allow) == [], (imp, call)
