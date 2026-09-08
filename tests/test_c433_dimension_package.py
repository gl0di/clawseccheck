"""C-433 — the per-dimension package's structural contract.

`monitor.py` was 4,916 lines and its size exemption had been restated three times. Three
earlier attempts to split it were rejected for a reason that was right: `snapshot()` builds
a dimension and `diff()` compares it, so a split BY FUNCTION separates the two halves that
must always change together. `clawseccheck/monitordims/` is the split that works — one
module per dimension, owning both halves.

These are the invariants that make that arrangement hold. Every one of them is a property a
future change could break silently, which is why they are asserted rather than documented:

  * the arms live in the package, not back in `monitor.py`;
  * every package name stays importable from `clawseccheck.monitor` (46 test modules and
    several siblings import from there);
  * the dependency runs ONE WAY — a dimension module importing `monitor` while `monitor`
    imports the arm is a cycle, and it is the reason the supporting names moved DOWN;
  * no `__all__` anywhere in the package (§3.1-a) — tests import privates by name;
  * `pyproject.toml` lists the subpackage, or it is importable in dev and missing from the
    wheel.

The BEHAVIOUR of the move (identical alerts and notes across the split) is proven elsewhere:
by the whole existing monitor suite, which ran unchanged against the split code, and by
`test_c433_host_arm_extracted.py` for the individual arms.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from clawseccheck import monitor

REPO_ROOT = Path(__file__).resolve().parent.parent
PKG = REPO_ROOT / "clawseccheck"
DIMS = PKG / "monitordims"

#: Every module in the package except the aggregator and the shared leaf. Globbed, so a
#: dimension added later is covered without an edit here — a hand-written list is a second
#: place to remember, and forgetting an entry would silently narrow every guard below.
_DIMENSION_FILES = sorted(
    p for p in DIMS.glob("_*.py") if p.name != "_shared.py"
)


def _top_level_names(path: Path) -> set:
    out = set()
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    out.add(t.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            out.add(node.target.id)
    return out


def test_the_package_exists_and_holds_more_than_one_dimension():
    """Anti-vacuity. Every guard below iterates this list, so an empty or one-entry glob
    would make the whole file pass while asserting nothing."""
    assert DIMS.is_dir()
    assert len(_DIMENSION_FILES) >= 10, [p.name for p in _DIMENSION_FILES]


def test_no_diff_arm_is_left_in_monitor():
    """The arms live with their dimension.

    This is the invariant the task is actually about. `monitor.py` keeps the orchestration —
    `snapshot()`, `diff_with_notes()`' preamble and its list of calls — and nothing that
    compares one dimension. A new arm written inline is exactly how the file grew to 4,916
    lines the first time.
    """
    strays = sorted(
        n for n in _top_level_names(PKG / "monitor.py")
        if re.match(r"^_(diff|note)_", n)
    )
    assert not strays, (
        "these dimension arms are defined in monitor.py rather than in monitordims/: "
        f"{strays}. Put each next to its dimension's signature builder — that pairing is "
        "the whole point of the split (CLAUDE.md §3)."
    )


def test_every_arm_in_the_package_is_reachable_from_monitor():
    """The re-export contract, name by name.

    `monitor` is the import site every consumer already uses. A name that moved into the
    package and was not re-exported breaks an import that has nothing to do with this
    refactor, and it breaks it at collection time rather than in a comparison.
    """
    missing = []
    for path in _DIMENSION_FILES + [DIMS / "_shared.py"]:
        for name in _top_level_names(path):
            # Dunders are module machinery, not moved code. Without this, a stray
            # `__all__` would be reported here as "failed to re-export", which is true but
            # is not what went wrong — `test_no_module_declares_all` names that correctly.
            if name.startswith("__"):
                continue
            if not hasattr(monitor, name):
                missing.append(f"{path.name}:{name}")
    assert not missing, (
        "moved into monitordims/ but no longer importable from clawseccheck.monitor: "
        f"{sorted(missing)}"
    )


def test_at_least_the_known_arms_are_present():
    """A named floor under the globbed guard above.

    Without it, deleting a dimension module would make `test_no_diff_arm_is_left_in_monitor`
    and the re-export guard BOTH pass — nothing strayed, nothing failed to re-export — while
    a whole dimension stopped being compared.
    """
    for name in ("_diff_host_monitors", "_diff_channels", "_diff_plugins",
                 "_diff_skill_provenance", "_diff_host_persist", "_diff_openclaw_install",
                 "_diff_mcp_servers", "_diff_mcp_detail", "_diff_native_findings",
                 "_diff_check_transitions", "_diff_vanished_checks", "_diff_behavioral",
                 "_diff_score", "_diff_skills_added", "_diff_skills_common",
                 "_diff_bootstrap_changed", "_diff_gateway_bind_moved",
                 "_diff_config_journal"):
        assert callable(getattr(monitor, name, None)), f"{name} is not reachable"


def test_the_pre_split_import_surface_is_intact():
    """Every name importable from `clawseccheck.monitor` before the split still is.

    A SUBSET assertion against `tests/monitor_public_api.txt`, which was captured from the
    tree immediately before C-433 moved the dimensions out. `test_every_arm_in_the_package_
    is_reachable_from_monitor` above checks the other direction — that what MOVED came
    back — and it cannot see this failure: a name that was in `monitor.py` and is now in
    neither place is absent from both sides of that comparison.

    It is not hypothetical. The first aggregator dropped ten names this way — `FAIL`,
    `PASS`, `WARN`, the four `PROV_*` provenance helpers and three leaf aliases — every one
    of them because nothing in tests/ happened to import it, which is exactly the condition
    under which no other test would have noticed either.
    """
    manifest = REPO_ROOT / "tests" / "monitor_public_api.txt"
    pinned = [ln.strip() for ln in manifest.read_text(encoding="utf-8").splitlines()
              if ln.strip() and not ln.startswith("#")]
    assert len(pinned) > 100, "the manifest looks truncated, not the module"
    missing = sorted(n for n in pinned if not hasattr(monitor, n))
    assert not missing, (
        f"no longer importable from clawseccheck.monitor: {missing}\n"
        "Re-export them (see monitordims/__init__.py), or — if the removal is deliberate — "
        "delete them from tests/monitor_public_api.txt in the same change and say why."
    )


def test_the_dependency_runs_one_way():
    """A dimension module must not import `monitor` or `monitorstore`.

    The supporting names (`NOTE_*`, `_h`, `_num`, `_dim`/`_both_dims`/`_frontier`,
    `_DIMENSION_NAME_CAP`) moved DOWN into `_shared.py` precisely so this holds. Importing
    them back up would be a cycle, and Python would report it as an unrelated
    partially-initialised-module error at some other import site.
    """
    offenders = []
    for path in _DIMENSION_FILES + [DIMS / "_shared.py", DIMS / "__init__.py"]:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                # level 2 == `from ..x import`, i.e. out of the package into clawseccheck
                if node.level == 2 and node.module in ("monitor", "monitorstore"):
                    offenders.append(f"{path.name} -> {node.module}")
            elif isinstance(node, ast.Import):
                for a in node.names:
                    if a.name.endswith(("clawseccheck.monitor", "clawseccheck.monitorstore")):
                        offenders.append(f"{path.name} -> {a.name}")
    assert not offenders, (
        f"monitordims/ imports back up into the monitor module: {offenders}. That is a "
        "cycle; move the name it needs down into monitordims/_shared.py instead."
    )


def test_the_shared_leaf_imports_nothing_from_the_package():
    """`_shared.py` is the leaf every dimension module may import, so it must not import
    any of them — otherwise the ordering it exists to remove comes straight back."""
    tree = ast.parse((DIMS / "_shared.py").read_text(encoding="utf-8"))
    pkg_imports = [
        n.module for n in ast.walk(tree)
        if isinstance(n, ast.ImportFrom) and n.level and n.module
    ]
    assert not pkg_imports, f"_shared.py must be a leaf, it imports {pkg_imports}"


@pytest.mark.parametrize("path", _DIMENSION_FILES + [DIMS / "_shared.py", DIMS / "__init__.py"],
                         ids=lambda p: p.name)
def test_no_module_declares_all(path):
    """§3.1-a, the `checks/` package rule, for the same reason: tests and siblings import
    underscore-prefixed helpers and regex constants by name, and a narrow `__all__` would
    hide every one of them."""
    assert "__all__" not in _top_level_names(path), (
        f"{path.name} declares __all__ — see CLAUDE.md §3.1-a"
    )


def test_pyproject_ships_the_subpackage():
    """`packages` is an EXPLICIT list. A subpackage missing from it imports fine from a
    source checkout and is simply absent from the built wheel, which no test that runs in
    the source tree can notice."""
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert '"clawseccheck.monitordims"' in text, (
        "add clawseccheck.monitordims to pyproject.toml's `packages` (CLAUDE.md §3.1-b)"
    )


def test_every_dimension_module_carries_a_docstring_saying_which_dimension():
    """The module map in CLAUDE.md §3 lists these by name; the file itself has to say what
    it owns, or the split degrades into sixteen files nobody can route a change to."""
    for path in _DIMENSION_FILES:
        doc = ast.get_docstring(ast.parse(path.read_text(encoding="utf-8")))
        assert doc and len(doc.splitlines()[0]) > 20, f"{path.name} has no useful docstring"
