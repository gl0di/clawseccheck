"""Self-integrity verification for the ClawSecCheck engine source.

Computes a deterministic SHA-256 digest over all ``clawseccheck/*.py`` files so
users can detect whether the package was tampered with after a trusted release.

Pure stdlib, no network, read-only.

Usage (programmatic)::

    from clawseccheck.integrity import package_digest
    combined, per_file = package_digest()
    print(combined)   # 64-char hex string

Usage (CLI)::

    clawseccheck --verify-self
"""
from __future__ import annotations

import hashlib
from pathlib import Path

# The directory that contains this file *is* the clawseccheck package.
_PKG_DIR = Path(__file__).resolve().parent

# Regenerated local artifacts that are NOT part of the shipped engine source: lint /
# type / test caches and VCS metadata. They are gitignored (never published), so a clean
# install lacks them — but a dev/CI checkout (or any tree where ruff/pytest/mypy has run)
# does, and folding them into the digest makes it environment-dependent and irreproducible
# (B-069: a `.ruff_cache/<ver>/<key>` filename varies by ruff version). Excluded here so
# the digest covers only shipped source and matches across dev and clean installs.
# Scoped to integrity on purpose: the untrusted-content scanners (collector vetting / C015)
# deliberately do NOT skip these — a payload could hide in a skill's .git/ or cache dir.
# (``__pycache__`` is already dropped upstream by ``walk_dir_safely(exclude_pycache=True)``.)
_NON_SOURCE_DIRS = frozenset(
    {"__pycache__", ".ruff_cache", ".mypy_cache", ".pytest_cache", ".git"}
)


def package_digest(pkg_dir: Path | None = None) -> tuple[str, dict[str, str]]:
    """Return ``(combined_hex, per_file_map)`` for **every** file in the package tree.

    The combined digest is a SHA-256 hash computed over the **sorted** sequence
    of ``relpath:sha256hex`` pairs (sorted by relative path so the result is
    independent of filesystem enumeration order).  This makes the digest stable
    across identical file trees on any platform.

    The scan is a recursive walk that hashes *all* file types — not just
    top-level ``*.py``.  A flat ``iterdir()`` over ``*.py`` was blind to added
    foreign files (``.so`` / ``.pth`` / data) and to nested subpackage modules,
    so a tamperer could drop a malicious file and still get an unchanged digest.
    Recursing over every file means adding *or* nesting any file changes the
    digest.  Regenerated local artifacts are excluded (``_NON_SOURCE_DIRS``):
    ``__pycache__`` (compiled ``.pyc`` vary by interpreter), plus lint/type/test
    caches (``.ruff_cache`` / ``.mypy_cache`` / ``.pytest_cache``) and ``.git`` —
    all gitignored, regenerated, and not part of the shipped source, so including
    them would make the digest environment-dependent (B-069).

    Note: self-integrity computed from inside the artifact is advisory — a
    modified ``integrity.py`` can print anything.  An out-of-band signature is the
    real anchor; this only proves "this file set's bytes are unchanged AND nothing
    was added/nested."

    Parameters
    ----------
    pkg_dir:
        Directory to scan (defaults to the real ``clawseccheck/`` package directory).
        Exposed as a parameter so tests can supply a controlled set of files.

    Returns
    -------
    combined_hex : str
        64-character lowercase SHA-256 hex string over the sorted per-file digests.
    per_file : dict[str, str]
        ``{relpath: sha256hex}`` mapping, keyed by POSIX relative path from the
        package root (so nested files are distinguishable), sorted by path.
    """
    if pkg_dir is None:
        pkg_dir = _PKG_DIR
    from .safeio import walk_dir_safely
    files = [p for p in walk_dir_safely(pkg_dir, exclude_pycache=True) if p.is_file()]

    per_file: dict[str, str] = {}
    for path in files:
        rel = path.relative_to(pkg_dir)
        # Skip regenerated local artifacts (lint/type/test caches, VCS metadata) so the
        # digest stays reproducible across a dev/CI checkout vs a clean install (B-069).
        if _NON_SOURCE_DIRS.intersection(rel.parts):
            continue
        per_file[rel.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()

    # Combine: hash the sorted sequence of "relpath:digest\n" lines for stability.
    combined = hashlib.sha256(
        "".join(f"{name}:{digest}\n" for name, digest in sorted(per_file.items())).encode()
    ).hexdigest()

    return combined, per_file
