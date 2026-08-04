"""deptree — bounded, read-only enumeration of an installed npm dependency tree.

Layer 1 leaf module (imports only stdlib + ``safeio``, per CLAUDE.md §3): it walks a
``node_modules`` directory, parses each package's own manifest, and reports the
install-lifecycle hooks it declares together with the in-package file each hook would
actually run. It renders no verdict — ``checks/_lifecycle.py``'s B349 is the consumer,
exactly as ``sockets.py`` is the read-only source B340 reasons over.

WHY THIS EXISTS (F-167). Every content scanner in this package deliberately steps around
a dependency tree: the plugin walk prunes ``node_modules`` by name, and a skill's tree is
walked as ordinary content under a file cap that a real tree blows past. So the one
directory a compromised transitive dependency actually lives in is the one nothing
reasons about. B42 already recognises a ``preinstall``/``postinstall`` hook — it just
never looks here.

WHAT IT DOES NOT DO, and why the boundary is permanent:

  * **No network, ever** (Golden Rule #1). This module cannot ask a registry whether a
    version is known-bad, and no future revision of it may. Every signal is derived from
    bytes already on disk.
  * **No root manifest.** Only packages *inside* ``node_modules`` are enumerated. A
    package's own top-level hooks are its vendor's installer — measured on a clean box
    (2026-08-04) OpenClaw's own root manifest declares two, and flagging a vendor's own
    installer would be a false positive on every single install.
  * **No verdict on the hook alone.** Measured on the same box: of 380 packages in
    OpenClaw's tree, 3 declare an install-lifecycle hook and all 3 are benign. A rule
    keyed on the hook's presence would therefore start life with three false positives,
    which is three more than Golden Rule #5 permits for a FAIL. The hook is the cheap
    half of a conjunction; the consumer supplies the other half.

TARGET RESOLUTION IS THE FALSE-POSITIVE-CRITICAL PART. Of those same 3 real hooks, only
ONE runs a file that lives in its own package (``protobufjs`` → ``scripts/postinstall``).
The other two — ``node-gyp-build`` (a bin contributed by a *dependency*) and
``echo 'preinstall: no-op'`` (a shell builtin) — have no in-package target at all.
"No resolvable target" is therefore the COMMON case, not the exceptional one, and it
must produce *no finding* rather than noise: a hook this module cannot resolve is a hook
whose bytes we never read, and a checker must not claim anything about bytes it never
read. Resolution is deliberately narrow — only an explicit ``node <file>`` invocation
resolves, and only to a real regular file inside that package's own directory.
"""
from __future__ import annotations

import json
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from .safeio import walk_dir_safely

# Bounds. OpenClaw's real tree measured 380 packages and ClawHub's 39 (2026-08-04), so
# these leave generous headroom while still refusing to walk an unbounded tree. A cap
# that is HIT is disclosed (`truncated`), never silently absorbed — see GR#4.
MAX_PACKAGES = 2000
MAX_MANIFEST_BYTES = 512_000
MAX_TARGET_BYTES = 2_000_000

# The three npm phases that execute during an install. `prepare`/`prepublish` are
# deliberately excluded: they run for a package being *published or developed*, not for
# one being consumed as a dependency, so including them would widen the surface without
# widening the threat.
INSTALL_PHASES = ("preinstall", "install", "postinstall")

# Directories that never contain a dependency's own manifest. `.bin` holds symlinks to
# executables (walk_dir_safely already refuses to follow them, but pruning saves budget).
_PRUNE_DIRS = frozenset({".bin", ".cache", "__pycache__", ".git"})

# Extensions node will append when resolving a bare path (`node scripts/postinstall`).
_NODE_EXTS = ("", ".js", ".mjs", ".cjs")

# Interpreter basenames whose next non-flag argument is a script path we can resolve.
# Deliberately NOT `sh`/`bash`/`npx`: those take a command, not necessarily a file in
# this package, and guessing would manufacture a target we never verified.
_NODE_BINS = frozenset({"node", "nodejs"})


@dataclass(frozen=True)
class LifecycleHook:
    """One declared install-lifecycle hook, and the in-package files it would run.

    `targets` is empty whenever the command is not a resolvable `node <file>` form —
    which is the common case on real trees. An empty `targets` means "we did not read
    any bytes for this hook", never "the hook is fine".
    """

    package: str
    relpath: str
    phase: str
    command: str
    targets: tuple = ()


@dataclass
class DepTreeScan:
    """Result of one bounded dependency-tree walk.

    `truncated` is True when the package cap was reached before the tree was fully
    walked — the caller MUST degrade its verdict rather than report a clean tree.
    """

    root: Path | None = None
    packages: int = 0
    hooks: tuple = ()
    truncated: bool = False
    unreadable: int = 0
    errors: list = field(default_factory=list)

    @property
    def scanned(self) -> bool:
        """True when a real tree was walked (a missing tree is not a clean tree)."""
        return self.root is not None


# How far above the resolved executable to look for the owning package.json. The two
# real layouts measured on this box need 1 and 2 levels
# (`<root>/openclaw.mjs`, `<root>/bin/clawdhub.js`); 6 is slack, not a guess.
_ROOT_SEARCH_DEPTH = 6


def find_package_root(binary_name: str, *, which=None) -> "Path | None":
    """Locate an installed npm package's root directory from its executable on PATH.

    Nothing in this package could previously do this — ``checks/_config.py``'s
    ``_names_openclaw_install()`` only RECOGNISES a path handed to it from elsewhere
    (a kernel-resolved ``/proc/<pid>/exe``); it cannot find one. B349 needs the root
    itself, because the measurement that motivated it found every real dependency tree
    on a live box under the npm global root, and none under any skill or plugin
    directory. A check scoped away from that root would scan nothing and report clean.

    Resolution is PATH-based and subprocess-free — ``shutil.which`` by default, with
    the same injectable-resolver contract ``hostwatch.detect(which=...)`` already uses
    so tests never touch the real PATH.

    **The soundness gate is the name check.** Following the symlink chain lands on a
    script somewhere inside a package; walking up until a ``package.json`` appears
    would happily attribute a neighbouring or parent package. So the manifest's own
    ``name`` must EQUAL *binary_name* before the directory is accepted. Without that,
    a shadowed or renamed binary earlier on PATH would silently redirect the whole scan
    to an unrelated tree — and the check would report on it as though it were OpenClaw's.
    Returns None when nothing on PATH resolves to a package that names itself correctly;
    the caller must treat that as UNKNOWN, never as a clean tree.
    """
    resolver = which if which is not None else _default_which()
    try:
        found = resolver(binary_name)
    except OSError:
        return None
    if not found:
        return None
    try:
        cur = Path(found).resolve().parent
    except OSError:
        return None
    for _ in range(_ROOT_SEARCH_DEPTH):
        data = _read_manifest(cur / "package.json")
        if data is not None and data.get("name") == binary_name:
            return cur
        if cur.parent == cur:
            break
        cur = cur.parent
    return None


def _default_which():
    """Deferred so importing this leaf never costs a `shutil` import it may not use."""
    import shutil

    return shutil.which


def find_dep_tree(package_root) -> "Path | None":
    """Return `package_root/node_modules` when it is a real directory, else None.

    Never follows a symlinked `node_modules`: a symlink here would let a target point
    the walk at an arbitrary subtree outside the package we think we are auditing.
    """
    try:
        nm = Path(package_root) / "node_modules"
        if nm.is_symlink() or not nm.is_dir():
            return None
        return nm
    except OSError:
        return None


def _read_manifest(path: Path) -> "dict | None":
    """Parse one `package.json`, bounded. Returns None on any read/parse failure."""
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            return None
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


def resolve_hook_targets(command: str, pkg_dir: Path) -> tuple:
    """Files inside *pkg_dir* that *command* would run via an explicit `node <file>`.

    Narrow on purpose (see the module docstring). A token is a candidate only when the
    PREVIOUS meaningful token is a node interpreter, so `node-gyp-build` — whose own
    basename is not `node` — never resolves, and `echo 'preinstall: no-op'` never does
    either. Shell operators (`&&`, `;`, `|`) simply end one command and begin another,
    so a chained `node a.js && node b.js` yields both without this having to understand
    shell grammar.

    A candidate must resolve, without traversing a symlink and without escaping
    *pkg_dir*, to an existing regular file. Anything else is dropped: a path we cannot
    confirm on disk is not a target, it is a guess.
    """
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:  # unbalanced quotes — not something to guess at
        return ()
    out: list = []
    expect_script = False
    for tok in tokens:
        if tok in ("&&", "||", ";", "|", "&"):
            expect_script = False
            continue
        if not expect_script:
            expect_script = Path(tok).name in _NODE_BINS
            continue
        if tok.startswith("-"):  # a node flag, not the script
            continue
        expect_script = False
        resolved = _resolve_in_package(tok, pkg_dir)
        if resolved is not None and resolved not in out:
            out.append(resolved)
    return tuple(out)


def _resolve_in_package(candidate: str, pkg_dir: Path) -> "Path | None":
    """Resolve *candidate* to a real regular file confined to *pkg_dir*, or None."""
    if not candidate or candidate.startswith("-"):
        return None
    for ext in _NODE_EXTS:
        p = pkg_dir / (candidate + ext)
        try:
            if p.is_symlink() or not p.is_file():
                continue
            # Confinement: a `../../..` target must never escape the package we are
            # attributing the finding to.
            real, base = p.resolve(), pkg_dir.resolve()
            if real == base or base not in real.parents:
                continue
            return p
        except OSError:
            continue
    return None


def read_target(path: Path) -> "str | None":
    """Read a hook target's source, bounded. None when unreadable or oversized."""
    try:
        if path.stat().st_size > MAX_TARGET_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def scan_dep_tree(nm_root, *, max_packages: int = MAX_PACKAGES) -> DepTreeScan:
    """Walk one `node_modules` tree and collect every install-lifecycle hook.

    Read-only and bounded: symlinks are never followed (`walk_dir_safely`), only
    `package.json` files spend the file budget (`keep_file`), noise directories are
    pruned BEFORE they can starve the budget (`prune_dir`), and a budget actually hit
    sets `truncated` so the caller cannot mistake a partial walk for a clean tree.
    """
    result = DepTreeScan()
    if nm_root is None:
        return result
    root = Path(nm_root)
    if not root.is_dir():
        return result
    result.root = root

    capped: list = []
    files = walk_dir_safely(
        root,
        exclude_pycache=True,
        exclude_vcs=True,
        max_files=max_packages,
        prune_dir=lambda parts: bool(parts) and parts[-1] in _PRUNE_DIRS,
        keep_file=lambda p: p.name == "package.json",
        capped=capped,
    )
    result.truncated = bool(capped)

    hooks: list = []
    for manifest in sorted(files):
        pkg_dir = manifest.parent
        data = _read_manifest(manifest)
        if data is None:
            result.unreadable += 1
            continue
        result.packages += 1
        scripts = data.get("scripts")
        if not isinstance(scripts, dict):
            continue
        try:
            relpath = str(pkg_dir.relative_to(root))
        except ValueError:  # pragma: no cover — walk_dir_safely confines to root
            relpath = pkg_dir.name
        name = data.get("name")
        if not isinstance(name, str) or not name:
            name = pkg_dir.name
        for phase in INSTALL_PHASES:
            command = scripts.get(phase)
            if not isinstance(command, str) or not command.strip():
                continue
            hooks.append(
                LifecycleHook(
                    package=name,
                    relpath=relpath,
                    phase=phase,
                    command=command[:200],
                    targets=resolve_hook_targets(command, pkg_dir),
                )
            )
    result.hooks = tuple(hooks)
    return result
