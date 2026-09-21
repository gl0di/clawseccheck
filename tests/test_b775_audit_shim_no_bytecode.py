"""B-775 — running the skill wrote `__pycache__` into its own ClawHub install, making it
un-updatable.

`audit.py` is the documented way to run a ClawHub-installed skill (SKILL.md tells the
agent to run `python3 {baseDir}/audit.py`), and it imports the `clawseccheck` package
straight out of the ClawHub-managed install directory
(`~/.openclaw/workspace/skills/clawseccheck/`) via a `sys.path.insert` + plain import.
Without `sys.dont_write_bytecode = True` set *before* that import, CPython writes
`__pycache__/*.pyc` next to the sources on every run — which changes the installed file
tree, and OpenClaw's own updater refuses `openclaw skills update clawseccheck` with "has
local file changes" until a `--force` that reverts on the very next run.

Two tests here are end-to-end, not traces: they actually run `audit.py` as a real
subprocess against a copy of the package on disk (the shape OpenClaw's updater actually
diffs), rather than asserting against the source text alone.

**Scope decision on `-m clawseccheck` and the `clawseccheck` console script** (the task's
own test plan asked this to be covered or explicitly ruled out):

* The pip/pipx console script (`clawseccheck = "clawseccheck.cli:main"`, pyproject.toml)
  resolves against a pip/pipx *site-packages* install, a different filesystem location
  from any ClawHub-managed skill directory — `collector.py::_is_own_source`'s own
  docstring already establishes "the pipx route creates no skill dir at all". It
  structurally cannot write into `~/.openclaw/workspace/skills/clawseccheck/` and is out
  of scope for that reason, not because it was skipped.

* `python -m clawseccheck`, if run with cwd inside the ClawHub skill directory (nothing
  stops a user from doing this instead of the documented `audit.py` invocation), CAN
  reach the same directory — but cannot be *fully* protected by any guard our own code
  adds, and `test_m_flag_cannot_be_fully_guarded_from_inside_the_package` below measures
  why rather than asserting it: `python -m pkg` runs via `runpy`, which imports
  `pkg/__init__.py` (and everything IT eagerly imports — here, effectively the whole
  package; see `clawseccheck/__init__.py`'s own import block) *before* a single line of
  `pkg/__main__.py` executes. There is no hook point inside the package that runs before
  that implicit import, so a same-process `sys.dont_write_bytecode` guard is structurally
  too late for most of it. Measured below: even the earliest possible placement (the
  literal first line of `__main__.py`) still leaves ~79% of the package's `.pyc` files
  written. `openclaw skills update`'s refusal reproduces at ANY nonzero file-tree
  drift, so a partial guard would not change the user-facing outcome and is not added —
  it would just be a comment claiming protection this code cannot deliver. The real
  mitigation for that invocation shape is process-level (`PYTHONDONTWRITEBYTECODE=1` /
  `python3 -B -m clawseccheck`) or, simpler: use the documented `audit.py` entry point,
  which this file's other tests confirm is fully clean.

Offline; every subprocess call reads only files this test controls under `tmp_path`.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_HOME_SAFE = _REPO / "fixtures" / "home_safe"


def _copy_install_tree(dest: Path) -> Path:
    """A minimal copy of what a ClawHub install of this skill looks like on disk:
    the `clawseccheck` package plus the `audit.py` shim, nothing else needed to run it.
    """
    import shutil

    # ignore=__pycache__: the checked-out repo this test runs from typically already
    # has stray caches from prior interpreter runs (this suite runs under more than one
    # Python version -- see CLAUDE.md's 3.9/3.12 gate) -- those are an artifact of this
    # dev checkout, not of the install this test simulates, and must not be copied in as
    # a false "before" baseline.
    shutil.copytree(
        _REPO / "clawseccheck", dest / "clawseccheck",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    shutil.copy2(_REPO / "audit.py", dest / "audit.py")
    return dest


def _pyc_files(root: Path) -> set:
    return {p.relative_to(root).as_posix() for p in root.rglob("*.pyc")}


# ─────────────────────────────────────────────────────────────── the guard is present

def test_dont_write_bytecode_set_before_package_import():
    """The guard must exist, and must run BEFORE `clawseccheck` is ever imported — a
    guard added after the import is a no-op (the import has already happened). Asserted
    against the source text so a future edit that reorders these two lines fails this
    test rather than silently reopening the bug.
    """
    src = (_REPO / "audit.py").read_text(encoding="utf-8")
    guard_pos = src.find("sys.dont_write_bytecode = True")
    import_pos = src.find("from clawseccheck.cli import main")
    assert guard_pos != -1, "audit.py no longer sets sys.dont_write_bytecode"
    assert import_pos != -1, "audit.py no longer imports clawseccheck.cli.main the expected way"
    assert guard_pos < import_pos, (
        "sys.dont_write_bytecode is set AFTER the package import — too late to have "
        "any effect; it must precede `from clawseccheck.cli import main`"
    )


# ───────────────────────────────────────────────────────── the actual DoD, end-to-end

def test_audit_shim_version_leaves_the_install_tree_byte_identical(tmp_path):
    """The cheapest possible invocation (`--version`) must add nothing to the tree —
    this is the one a user is likeliest to run first after installing.
    """
    install = _copy_install_tree(tmp_path / "install")
    before = _pyc_files(install)
    assert before == set(), "test setup: a clean copy must start with zero .pyc files"

    result = subprocess.run(
        [sys.executable, "audit.py", "--version"],
        cwd=install, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr

    after = _pyc_files(install)
    assert after == set(), (
        f"`audit.py --version` wrote {len(after)} .pyc file(s) into the install tree: "
        f"{sorted(after)[:5]} -- this is exactly what makes "
        "`openclaw skills update clawseccheck` refuse with \"has local file changes\""
    )


def test_full_audit_run_leaves_the_install_tree_byte_identical(tmp_path):
    """A real, full audit run (not just --version) -- the shape OpenClaw's updater
    actually diffs against the recorded install manifest.
    """
    install = _copy_install_tree(tmp_path / "install")
    before = _pyc_files(install)
    assert before == set()

    result = subprocess.run(
        [sys.executable, "audit.py", "--home", str(_HOME_SAFE), "--no-deptree"],
        cwd=install, capture_output=True, text=True, timeout=120,
    )
    assert result.returncode in (0, 1), result.stderr  # 0/1 are both "ran to completion"

    after = _pyc_files(install)
    assert after == set(), (
        f"a full audit run wrote {len(after)} .pyc file(s) into the install tree: "
        f"{sorted(after)[:5]}"
    )


# ───────────────────────────────────────── the -m scope decision, measured not asserted

def test_m_flag_cannot_be_fully_guarded_from_inside_the_package(tmp_path):
    """Grounds the scope decision in the module docstring: even the EARLIEST possible
    same-process guard (the literal first line of `__main__.py`, before its own `from
    .cli import main`) cannot prevent `python -m clawseccheck` from writing bytecode for
    most of the package, because `runpy` already imported `clawseccheck/__init__.py`
    (and everything it eagerly imports) before any of the package's own code — including
    a guard in `__main__.py` -- gets to run.

    This does NOT test the shipped `__main__.py` (which is deliberately left unguarded,
    for the reason above -- a partial guard changes nothing about the actual refusal,
    which fires on any nonzero drift). It builds a throwaway copy with the earliest
    possible guard added, to measure the ceiling of what an in-package fix could ever
    achieve for this entry point -- so if a future change makes this measurement 0 (e.g.
    a CPython behavior change, or `clawseccheck/__init__.py` stops eagerly importing the
    whole package), this test starts failing and is the signal to revisit the scope
    decision instead of leaving it stale.
    """
    install = _copy_install_tree(tmp_path / "install")
    main_py = install / "clawseccheck" / "__main__.py"
    original = main_py.read_text(encoding="utf-8")
    main_py.write_text("import sys\nsys.dont_write_bytecode = True\n" + original, encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--version"],
        cwd=install, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr

    after = _pyc_files(install)
    # Non-vacuity: if this ever reads 0, the ceiling moved and the scope decision in
    # this module's docstring (and B-775's Pulse comment) needs re-measuring, not a
    # silent pass.
    assert after, (
        "the earliest possible in-package guard produced ZERO .pyc files for `python -m "
        "clawseccheck` -- the scope decision documented at the top of this file assumed "
        "this is structurally impossible to fully prevent; that assumption no longer "
        "holds, re-measure and consider guarding __main__.py for real"
    )
