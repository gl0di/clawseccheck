"""F-174 — the installed OpenClaw package, as an identity and an integrity marker.

Read-only, stdlib only, no subprocess and no network. A LEAF: it imports `deptree` for the
one thing that module already does well (locate an installed npm package root from PATH,
name-verified against its own manifest) and nothing else from the package. It renders no
verdict — `monitor.py` is the consumer, the same leaf->consumer split `sockets.py`->B340,
`deptree.py`->B349 and `configjournal.py`->B77 already use.

**Why this exists.** B33 ("known-vulnerable OpenClaw version gate", HIGH) and C4 read
`meta.lastTouchedVersion` out of `openclaw.json` — a string the agent writes about itself.
A swapped `npm install` of openclaw is the top of the supply chain and nothing anywhere
compared it against the artifact actually on disk. On the maintainer's machine the two
happen to agree (`2026.7.1-2` in both), which is the expected state and exactly why the
disagreement is worth watching for.

**What each digest can and cannot catch**, because a field called "integrity" that covers
less than its name suggests is the failure this project keeps removing:

* `manifest_sha256` — `package.json`. Moves on a version change, a `bin`/`main`/`exports`
  rewrite, or a dependency-range edit. Instant (116 KB on the real install).
* `lock_sha256` — `npm-shrinkwrap.json`, else `package-lock.json`. Moves when the resolved
  dependency SET moves, which a version bump alone need not do. Instant (133 KB).
* `code_sha256` — the executable surface: everything under `dist/` plus the top-level entry
  scripts. This is the one that catches a swapped build with an untouched `package.json` —
  the actual attack — and it is the only one with a real cost. Measured on the real install:
  7,716 files, 77.8 MB, **0.27-0.32 s** over three consecutive runs, against a `--monitor`
  run of roughly 7.8 s. That is affordable; a `node_modules` sweep would not be, which is
  why the tree below stops at the package root's own code.

**Budget is a security property.** A monitor slow enough to be annoying gets switched off,
so the walk is bounded by file count and by bytes, and a walk that hit a bound says so
(`code_capped`) instead of returning a digest that quietly covers part of the tree. A
partial digest presented as a whole one would be a clean verdict about an unexamined
surface.

Symlinks inside the tree are skipped rather than followed: a link planted in `dist/` could
otherwise pull an arbitrary file into the digest (harmless on its own) or, worse, make the
walk wander outside the package root. Skipping is recorded in `notes`.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from .deptree import find_package_root

# Bounds on the code walk. Roughly 2.5x the real install (7,716 files / 77.8 MB), so an
# ordinary OpenClaw never approaches them and a pathological tree cannot hang a scheduled
# run. Deliberately generous rather than tight: a cap that fires in normal use produces a
# permanent "could not inspect it all" note, which teaches the reader to ignore the line.
MAX_CODE_FILES = 20_000
MAX_CODE_BYTES = 300 * 1024 * 1024

# The executable surface, in the order it is walked. `dist/` is where the built code lives;
# the entry scripts are what `npm` wired into PATH. `node_modules/` is deliberately absent —
# it is `deptree.py`'s subject, it is far larger than the budget above, and its install-time
# execution surface is already covered by B349.
_CODE_DIRS = ("dist", "bin")
_CODE_FILE_SUFFIXES = (".mjs", ".js", ".cjs")

_LOCK_NAMES = ("npm-shrinkwrap.json", "package-lock.json")


@dataclass
class InstallInfo:
    """What one installed npm package looks like from outside. All fields are safe to
    persist and to render: no absolute path is carried.

    `root` is deliberately NOT stored — an install path is machine-specific detail that
    would land in a drift baseline and, through it, in the event journal and any report the
    user pastes into an issue. `root_name` (the final directory component) is enough to say
    *which* package this is.
    """

    root_name: str = ""
    version: str = ""
    manifest_sha256: str = ""
    lock_sha256: str = ""
    lock_name: str = ""
    code_sha256: str = ""
    code_files: int = 0
    code_bytes: int = 0
    code_capped: bool = False
    notes: tuple = ()

    def as_dimension(self) -> dict:
        """The snapshot shape. Sorted keys by construction (a dict literal in JSON is
        canonicalised by `snapshot_reference`), and every value is a str/int/bool so it
        survives a JSON round-trip unchanged."""
        return {
            "name": self.root_name,
            "version": self.version,
            "manifest_sha256": self.manifest_sha256,
            "lock_sha256": self.lock_sha256,
            "lock_name": self.lock_name,
            "code_sha256": self.code_sha256,
            "code_files": self.code_files,
            "code_capped": self.code_capped,
        }


def _digest_file(p: Path) -> str:
    """sha256 of one file's bytes, or ``""`` when it cannot be read.

    ``""`` rather than a raised error, and rather than a digest of nothing: an unreadable
    manifest must read as "no value recorded this run" so the consumer's presence guard
    skips the comparison, not as a value that differs from last time.
    """
    try:
        return hashlib.sha256(p.read_bytes()).hexdigest()
    except OSError:
        return ""


def _read_version(root: Path) -> str:
    """The `version` string out of the package manifest, or ``""``."""
    try:
        manifest = json.loads((root / "package.json").read_text(encoding="utf-8",
                                                                errors="replace"))
    except (OSError, ValueError):
        return ""
    version = manifest.get("version") if isinstance(manifest, dict) else None
    return version if isinstance(version, str) else ""


def _code_files(root: Path) -> "list[str]":
    """Every file on the executable surface as a POSIX-style RELATIVE path, sorted, with
    symlinks excluded.

    Sorted so the digest is stable across filesystems that return directory entries in
    arbitrary order — an unsorted walk would produce a different value for a byte-identical
    install, which is the same false-drift shape the F-173 baseline reference had to remove.

    `os.walk` over strings rather than `Path.rglob`, and relative paths built by slicing
    rather than by `Path.relative_to`. Not premature: measured on the real install (7,717
    files, 77.8 MB) the pathlib version took 0.89 s of a ~7.8 s monitor run, of which only
    ~0.3 s was reading bytes — the rest was `Path` object churn and 7,717 `relative_to`
    calls. The rewrite is ~0.35 s. Budget is a security property here: a monitor slow
    enough to be annoying gets switched off.

    `followlinks` is left at its default False, and each entry is checked with `islink`
    anyway — the first stops the walk wandering outside the package root through a linked
    directory, the second keeps a linked FILE out of the digest.
    """
    base = str(root)
    prefix = len(base) + 1
    out: list[str] = []
    for name in _CODE_DIRS:
        d = os.path.join(base, name)
        if not os.path.isdir(d) or os.path.islink(d):
            continue
        for dirpath, dirnames, filenames in os.walk(d, followlinks=False):
            dirnames[:] = [x for x in dirnames
                           if not os.path.islink(os.path.join(dirpath, x))]
            for f in filenames:
                full = os.path.join(dirpath, f)
                if not os.path.islink(full):
                    out.append(full[prefix:].replace(os.sep, "/"))
    try:
        for entry in os.scandir(base):
            if (entry.is_file(follow_symlinks=False)
                    and os.path.splitext(entry.name)[1] in _CODE_FILE_SUFFIXES):
                out.append(entry.name)
    except OSError:
        pass
    return sorted(out)


def _digest_code(root: Path, *, max_files: int = MAX_CODE_FILES,
                 max_bytes: int = MAX_CODE_BYTES) -> "tuple[str, int, int, bool]":
    """``(digest, files, bytes, capped)`` over the executable surface.

    The RELATIVE PATH is folded into the digest alongside the bytes, so moving a file
    without changing its contents still moves the value — a rename inside `dist/` is a real
    change to what runs, and a content-only digest would call it identical.
    """
    rels = _code_files(root)
    capped = len(rels) > max_files
    if capped:
        rels = rels[:max_files]
    base = str(root)
    h = hashlib.sha256()
    total = 0
    for rel in rels:
        try:
            with open(os.path.join(base, rel), "rb") as fh:
                data = fh.read()
        except OSError:
            # One unreadable file must not void the whole digest, but it must not be
            # silently equivalent to an absent one either: the path still goes in.
            h.update(f"{rel}\0<unreadable>\0".encode())
            continue
        total += len(data)
        if total > max_bytes:
            capped = True
            break
        h.update(f"{rel}\0{len(data)}\0".encode())
        h.update(data)
    return h.hexdigest(), len(rels), total, capped


def describe_install(binary_name: str = "openclaw", *, which=None,
                     max_files: int = MAX_CODE_FILES,
                     max_bytes: int = MAX_CODE_BYTES) -> "InstallInfo | None":
    """The installed package behind *binary_name*, or None when it cannot be located.

    None, not an empty InstallInfo: "OpenClaw is not installed via a package manager we can
    see" and "it is installed and looks like this" are different facts, and a consumer that
    got an empty record for the first would report every field as having disappeared the
    day the install became visible.
    """
    root = find_package_root(binary_name, which=which)
    if root is None:
        return None
    notes: list[str] = []
    lock_name, lock_digest = "", ""
    for name in _LOCK_NAMES:
        candidate = root / name
        if candidate.is_file():
            lock_name, lock_digest = name, _digest_file(candidate)
            break
    if not lock_name:
        notes.append("no lock file in the package root")
    code_digest, files, size, capped = _digest_code(root, max_files=max_files,
                                                    max_bytes=max_bytes)
    if capped:
        notes.append("the code tree was larger than this run inspects")
    if not files:
        notes.append("no executable surface found in the package root")
    return InstallInfo(
        root_name=root.name,
        version=_read_version(root),
        manifest_sha256=_digest_file(root / "package.json"),
        lock_sha256=lock_digest,
        lock_name=lock_name,
        code_sha256=code_digest if files else "",
        code_files=files,
        code_bytes=size,
        code_capped=capped,
        notes=tuple(notes),
    )


# Version strings carrying one of these tokens are not ordered by this module. npm's own
# pre-release convention puts them after a `-`, where a naive digit scan reads `1.0.0-rc1`
# as (1,0,0,1) and therefore as NEWER than `1.0.0` — which would report an upgrade to a
# release build as a DOWNGRADE, the loudest thing this comparison can say, on the strength
# of a parsing artefact. The real install's `2026.7.1-2` carries no such token and orders
# fine; a build that does simply gets "changed" instead of a direction.
_PRERELEASE_TOKENS = ("rc", "alpha", "beta", "dev", "pre", "next", "canary", "nightly",
                      "snapshot")

_ORDER_UP = "up"
_ORDER_DOWN = "down"
_ORDER_UNKNOWN = "unknown"


def _numeric_parts(version: str) -> "tuple | None":
    """Every digit run in *version* as a tuple of ints, or None when it cannot be ordered.

    None — not an empty tuple — for a version with no digits or with a pre-release token:
    a caller that treated "unorderable" as "equal" would silently stop reporting real moves.
    """
    # Semver build metadata (everything after `+`) is explicitly NOT part of the ordering,
    # and a digit scan that keeps it reads `1.2.3+build7` as (1,2,3,7) — strictly greater
    # than `1.2.3`, so a rebuild of the identical version would report as an upgrade and,
    # in the other direction, as a rollback. Caught by its own test rather than by review.
    base = version.split("+", 1)[0]
    lowered = base.lower()
    if any(tok in lowered for tok in _PRERELEASE_TOKENS):
        return None
    import re  # noqa: PLC0415 — deferred so importing this leaf never costs it unused
    parts = re.findall(r"\d+", base)
    if not parts:
        return None
    return tuple(int(p) for p in parts)


def compare_versions(old: str, new: str) -> str:
    """``"up"`` / ``"down"`` / ``"unknown"`` — never a bool.

    A downgrade is the signal that matters most and is invisible today in both the check and
    the monitor, so it is worth ordering these at all. But a WRONG direction is worse than
    none: "your agent runtime was rolled back to a known-vulnerable build" is the loudest
    sentence this dimension can produce, and it must never come from a parsing artefact.
    Anything this function cannot order confidently returns ``"unknown"``, and the caller
    reports a bare "changed" for that — always true, and enough for the user to act on.
    """
    if not old or not new or old == new:
        return _ORDER_UNKNOWN
    a, b = _numeric_parts(old), _numeric_parts(new)
    if a is None or b is None:
        return _ORDER_UNKNOWN
    if b > a:
        return _ORDER_UP
    if b < a:
        return _ORDER_DOWN
    # Equal numerics, different strings — e.g. `1.2.3` vs `1.2.3+build`. Real difference,
    # no defensible direction.
    return _ORDER_UNKNOWN


def self_reported_version(config: "dict | None") -> str:
    """OpenClaw's own claim about which version last wrote the config
    (`meta.lastTouchedVersion`), or ``""``.

    Grounded against the real config, where it reads `2026.7.1-2` alongside a
    `lastTouchedAt` timestamp. It is a SELF-REPORT: it says which build last saved settings,
    not which build is installed now. The two disagreeing is the interesting state — a
    downgrade leaves the config stamped with the newer version — and neither one alone can
    show it, which is the whole reason both are recorded.
    """
    if not isinstance(config, dict):
        return ""
    meta = config.get("meta")
    if not isinstance(meta, dict):
        return ""
    value = meta.get("lastTouchedVersion")
    return value if isinstance(value, str) else ""
