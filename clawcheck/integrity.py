"""Self-integrity verification for the ClawCheck engine source.

Computes a deterministic SHA-256 digest over all ``clawcheck/*.py`` files so
users can detect whether the package was tampered with after a trusted release.

Pure stdlib, no network, read-only.

Usage (programmatic)::

    from clawcheck.integrity import package_digest
    combined, per_file = package_digest()
    print(combined)   # 64-char hex string

Usage (CLI)::

    clawcheck --verify-self
"""
from __future__ import annotations

import hashlib
from pathlib import Path

# The directory that contains this file *is* the clawcheck package.
_PKG_DIR = Path(__file__).resolve().parent


def package_digest(pkg_dir: Path | None = None) -> tuple[str, dict[str, str]]:
    """Return ``(combined_hex, per_file_map)`` for all ``*.py`` files in the package.

    The combined digest is a SHA-256 hash computed over the **sorted** sequence
    of ``filename:sha256hex`` pairs (sorted by filename so the result is
    independent of filesystem enumeration order).  This makes the digest stable
    across identical file trees on any platform.

    Parameters
    ----------
    pkg_dir:
        Directory to scan (defaults to the real ``clawcheck/`` package directory).
        Exposed as a parameter so tests can supply a controlled set of files.

    Returns
    -------
    combined_hex : str
        64-character lowercase SHA-256 hex string over the sorted per-file digests.
    per_file : dict[str, str]
        ``{filename: sha256hex}`` mapping, keyed by plain filename (no directory
        component) sorted by name.
    """
    if pkg_dir is None:
        pkg_dir = _PKG_DIR

    py_files = sorted(p for p in pkg_dir.iterdir() if p.suffix == ".py" and p.is_file())

    per_file: dict[str, str] = {}
    for path in py_files:
        content = path.read_bytes()
        per_file[path.name] = hashlib.sha256(content).hexdigest()

    # Combine: hash the sorted sequence of "name:digest\n" lines for stability.
    combined = hashlib.sha256(
        "".join(f"{name}:{digest}\n" for name, digest in sorted(per_file.items())).encode()
    ).hexdigest()

    return combined, per_file
