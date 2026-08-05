"""deptree — bounded, read-only enumeration of an installed npm dependency tree.

Layer 1 leaf module (imports only stdlib + ``safeio``, per CLAUDE.md §3): it walks a
``node_modules`` directory, parses each package's own manifest, and reports the two ways
a package there can run code at install time — the install-lifecycle hooks it declares,
and the command-expansions in its ``binding.gyp`` build config — together with the
in-package file each would actually run. It renders no verdict —
``checks/_lifecycle.py``'s B349 is the consumer, exactly as ``sockets.py`` is the
read-only source B340 reasons over.

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

WHY ``binding.gyp`` IS ENUMERATED TOO (B-447). Reading only ``scripts`` was a false
negative, not a scoping choice. The node-gyp supply-chain worm executes with **no
lifecycle script at all**: its tarballs declare no ``preinstall``/``install``/
``postinstall``/``prepare``, and execution comes instead from GYP's own command-expansion
syntax inside the build config — ``"sources": ["<!(node index.js && echo stub.c)"]`` runs
while node-gyp is merely *configuring*, long before any compiler starts. npm invokes
node-gyp on its own for any package shipping a ``binding.gyp`` with no prebuilt binary,
so the file's mere presence is the trigger. A scanner that enumerates lifecycle scripts
is exactly the script-focused monitoring that shape was built to walk past.

Two boundaries keep that from becoming a false-positive engine. **Only the package
root's ``binding.gyp``** is read — that is where npm's automatic ``node-gyp configure``
looks; a nested one is not auto-invoked, and reporting it would manufacture a finding the
installer never triggers. And **the same narrow resolver** decides what has bytes to
read, so the overwhelmingly common honest idiom (``<!(node -e "require('nan')")`` — an
inline expression, no file) resolves to nothing and is never assessed, exactly as
``node-gyp-build`` is not. What is NOT followed, and is stated rather than implied: GYP's
own ``includes`` directive can pull in a ``.gypi`` carrying further expansions. Following
it is its own change with its own adversarial pass.
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

# A build config is a small hand-written file; real ones measured on this box are under
# 4 KB. The per-file expansion cap stops a hostile config from turning one package into
# an unbounded amount of work — a config that hits it has already earned attention.
MAX_GYP_BYTES = 256_000
MAX_GYP_EXPANSIONS = 40

# Bounds on the SCAN itself, not just its output. A `binding.gyp` arrives from an
# untrusted package in the user's own tree, so it is adversarial input to this scanner:
# a file of nothing but unbalanced `<!(` markers would make every one of them scan to
# EOF, which is quadratic and is a denial-of-service on the audit rather than a finding.
# The window is what bounds a single scan; the marker cap bounds how many can be tried.
# 4 KB is far above any real command (the longest measured on this box is 47 bytes).
MAX_GYP_COMMAND_BYTES = 4096
MAX_GYP_MARKERS = 2000

# node-gyp's default build config, at the package root. See the module docstring for why
# only this path is read and no nested or `gypfile`-redirected one is.
GYP_FILENAME = "binding.gyp"

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


@dataclass(frozen=True)
class BuildDirective:
    """One GYP command-expansion in a package's root `binding.gyp`.

    Same contract as `LifecycleHook`: an empty `targets` means the expansion runs
    something whose bytes we never read (an inline `node -e` expression, a `python`
    probe, a `pkg-config` call), never that it is fine. Unlike a lifecycle hook this
    needs no `phase` — npm triggers it on the file's existence alone.
    """

    package: str
    relpath: str
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
    build_directives: tuple = ()
    # Packages whose `binding.gyp` could not be fully examined, already rendered as
    # "<package> (<relpath>): <reason>". Each entry is a place the walk fell short, and
    # the consumer must degrade to UNKNOWN for it rather than let it read as clean.
    gyp_capped: tuple = ()
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


def extract_gyp_commands(
    text: str, *, max_expansions: int = MAX_GYP_EXPANSIONS, capped=None
) -> tuple:
    """Every `<!(...)` / `<!@(...)` command-expansion body in a GYP file, in order.

    GYP is not JSON — it permits comments, single quotes and trailing commas — so this
    deliberately does NOT parse the file. It only locates the expansion syntax, because
    that is the only part whose meaning we need and the only part a parser could get
    wrong in a way that loses a real one.

    Paren matching is balanced-depth rather than a lazy regex: real commands nest parens
    (`<!(node -p "require('x').include")`), and stopping at the first `)` would truncate
    the command into something we never actually saw. An expansion whose parens never
    balance yields nothing and scanning resumes after it — we cannot say where such a
    command ends, and a guess would be a fabricated finding (GR#4).

    Each scan is bounded to `MAX_GYP_COMMAND_BYTES` ahead and the number of markers tried
    to `MAX_GYP_MARKERS`, so the total work is linear in the file rather than quadratic in
    the number of unbalanced markers a hostile package chooses to ship.

    A BOUND THAT IS HIT IS DISCLOSED, NEVER ABSORBED. Every bound here is also an evasion
    if it fails silently: the package author writes the `binding.gyp`, so padding it with
    2,000 decoy `<!` markers ahead of the real expansion — or spacing one command past the
    scan window — would evict the real command from a budget and leave a clean PASS behind.
    So *capped* (a list, the same out-parameter idiom `safeio.walk_dir_safely` uses) gets a
    reason appended, and B349 turns that into UNKNOWN naming the package rather than a
    verdict over bytes it never read. An expansion whose parens simply never balance is NOT
    a cap: that config is malformed for node-gyp too, so there is no command to have missed.
    """
    out: list = []
    i, n = 0, len(text)
    markers = 0
    while i < n:
        if len(out) >= max_expansions:
            _note_cap(capped, "expansion cap reached — the rest of the build config was not examined")
            break
        if markers >= MAX_GYP_MARKERS:
            _note_cap(capped, "command-marker budget exhausted — the rest of the build config was not examined")
            break
        start = text.find("<!", i)
        if start < 0:
            break
        markers += 1
        cur = start + 2
        if cur < n and text[cur] == "@":  # `<!@(...)` — expands to a list, runs the same
            cur += 1
        if cur >= n or text[cur] != "(":
            i = start + 2
            continue
        window = min(n, cur + MAX_GYP_COMMAND_BYTES)
        depth, end = 0, -1
        for pos in range(cur, window):
            char = text[pos]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    end = pos
                    break
        if end < 0:
            if window < n:  # stopped at the window, not at a malformed end-of-file
                _note_cap(capped, "a command ran past the scan window and was not examined")
            i = cur + 1
            continue
        body = text[cur + 1:end].strip()
        if body and not _is_commented_out(text, start):
            out.append(body)
        i = end + 1
    return tuple(out)


def _note_cap(capped, reason: str) -> None:
    if capped is not None and reason not in capped:
        capped.append(reason)


def _is_commented_out(text: str, marker: int) -> bool:
    """True when the `<!` at *marker* sits after an unquoted `#` on its own line.

    GYP takes `#` to end-of-line as a comment, and every real build config measured on
    this box uses them. Without this, a commented-out expansion was lifted out as a live
    command and its target read and judged — a verdict about a file the installer would
    never run (found by the B-447 C-135 pass, reproduced end-to-end as a wrong UNKNOWN on
    an honest package).

    Scoped to the SINGLE line rather than tracking quote state across the whole file. A
    file-wide scanner that loses its place could swallow a real expansion silently, which
    is the one failure this must not have; GYP strings do not span lines, so a per-line
    decision is both accurate and blast-radius-free. A `#` INSIDE a string
    (`"sources": ["#<!(...)"]`) is correctly not a comment.
    """
    line_start = text.rfind("\n", 0, marker) + 1
    quote = ""
    escaped = False
    for ch in text[line_start:marker]:
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif quote:
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == "#":
            return True
    return False


def _gyp_directives(pkg_dir: Path, name: str, relpath: str) -> tuple:
    """Command-expansions in *pkg_dir*'s root `binding.gyp`, and any reason we fell short.

    Returns `(directives, capped_notes)`. Reached for EVERY package, including one
    declaring no `scripts` at all — which is precisely the shape of the worm this exists
    for (B-447).

    Every early return here is a place a hostile package could hide behind, so each one
    reports itself: an oversized build config, an unreadable one, and a SYMLINKED one
    (node-gyp reads through the symlink; we refuse to, because a link can point the walk
    outside the package we would attribute the finding to) all yield a note the consumer
    turns into UNKNOWN. Silently returning nothing would let a 257 KB `binding.gyp` buy a
    clean PASS.
    """
    gyp = pkg_dir / GYP_FILENAME
    notes: list = []
    try:
        if gyp.is_symlink():  # before exists(): a broken link must not read as absent
            return [], ["build config is a symlink and was not followed"]
        if not gyp.is_file():
            return [], notes
        if gyp.stat().st_size > MAX_GYP_BYTES:
            return [], ["build config is too large to examine"]
        raw = gyp.read_bytes()
        # A NUL byte means this is not UTF-8 text -- in practice UTF-16/UTF-32, which
        # node-gyp reads fine and which `errors="replace"` turns into `<\x00!\x00(`, so
        # every expansion vanishes and the package reads as clean. That silent PASS is
        # exactly what GR#4 forbids, so it is disclosed instead of decoded hopefully.
        if b"\x00" in raw:
            return [], ["build config is not UTF-8 text and was not examined"]
        text = raw.decode("utf-8", errors="replace")
    except OSError:
        return [], ["build config could not be read"]
    commands = extract_gyp_commands(text, capped=notes)
    directives = [
        BuildDirective(
            package=name,
            relpath=relpath,
            command=command[:200],
            targets=resolve_hook_targets(command, pkg_dir),
        )
        for command in commands
    ]
    return directives, notes


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
    directives: list = []
    gyp_capped: list = []
    for manifest in sorted(files):
        pkg_dir = manifest.parent
        data = _read_manifest(manifest)
        if data is None:
            result.unreadable += 1
            continue
        result.packages += 1
        try:
            relpath = str(pkg_dir.relative_to(root))
        except ValueError:  # pragma: no cover — walk_dir_safely confines to root
            relpath = pkg_dir.name
        name = data.get("name")
        if not isinstance(name, str) or not name:
            name = pkg_dir.name

        # Before the `scripts` guard on purpose (B-447): a package declaring no scripts
        # at all used to `continue` straight past everything below, and that is exactly
        # the manifest the node-gyp worm ships.
        pkg_directives, pkg_capped = _gyp_directives(pkg_dir, name, relpath)
        directives.extend(pkg_directives)
        gyp_capped.extend(f"{name} ({relpath}): {reason}" for reason in pkg_capped)

        scripts = data.get("scripts")
        if not isinstance(scripts, dict):
            continue
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
    result.build_directives = tuple(directives)
    result.gyp_capped = tuple(gyp_capped)
    return result
