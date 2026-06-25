"""Symlink-safe local file writes for ClawSecCheck's own ~/.clawseccheck store.

ClawSecCheck only ever writes to its own private directory, but a hostile local
process (or a lost first-run race) could pre-plant a symlink at one of those
paths and turn the next write into an arbitrary-file overwrite as the invoking
user.  These helpers close that hole:

  * directories are created with mode 0700 **at creation time** (no transient
    world-readable window from umask), and refused if they are a symlink;
  * files are opened with ``O_NOFOLLOW`` so a symlinked final component makes the
    open fail (ELOOP) instead of being followed, and created with mode 0600 at
    creation time.

Pure stdlib, no network, owner-only. ``O_NOFOLLOW`` is POSIX; on platforms that
lack it the flag degrades to 0 (best effort) — the same platforms also lack the
symlink-attack surface this guards against.
"""
from __future__ import annotations

import os
from pathlib import Path

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def secure_dir(path: Path) -> None:
    """Create *path* (a directory) mode 0700, refusing to use it if it is a symlink.

    ``mkdir(mode=0o700)`` sets the mode atomically at creation (subject to umask,
    which never *adds* bits), so there is no world-readable window of the kind a
    plain ``mkdir(parents=True)`` + later ``chmod`` leaves open.
    """
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise OSError(f"refusing to use symlinked directory: {path}")
    try:  # tighten in case the dir pre-existed with looser perms (POSIX only)
        path.chmod(0o700)
    except (OSError, NotImplementedError):
        pass


def _open_owner_only(path: Path, extra_flags: int) -> int:
    """``os.open`` the path WRONLY|CREAT|O_NOFOLLOW|extra, mode 0600.

    O_NOFOLLOW makes the open fail with OSError(ELOOP) if the final path
    component is a symlink — so a planted symlink can never be clobbered.
    """
    flags = os.O_WRONLY | os.O_CREAT | _NOFOLLOW | extra_flags
    return os.open(path, flags, 0o600)


def secure_write_text(path: Path, data: str) -> None:
    """Overwrite *path* with *data*, refusing to follow a symlinked target."""
    fd = _open_owner_only(path, os.O_TRUNC)
    try:
        os.write(fd, data.encode("utf-8"))
    finally:
        os.close(fd)
    try:  # belt-and-suspenders; creation mode already 0600 (POSIX only)
        path.chmod(0o600)
    except (OSError, NotImplementedError):
        pass


def secure_append_text(path: Path, data: str) -> None:
    """Append *data* to *path*, refusing to follow a symlinked target."""
    fd = _open_owner_only(path, os.O_APPEND)
    try:
        os.write(fd, data.encode("utf-8"))
    finally:
        os.close(fd)
    try:  # belt-and-suspenders; creation mode already 0600 (POSIX only)
        path.chmod(0o600)
    except (OSError, NotImplementedError):
        pass


def is_safe_tar_member(base_dir: Path, member_name: str) -> bool:
    try:
        # Resolve absolute path without writing to disk
        target_path = Path(base_dir / member_name).resolve()
        # Ensure target path resides within the base directory
        return base_dir.resolve() in target_path.parents or base_dir.resolve() == target_path
    except (OSError, ValueError):
        return False


def walk_dir_safely(
    base_dir: Path,
    exclude_pycache: bool = False,
    max_files: int | None = None,
) -> list[Path]:
    """Recursively walk base_dir, skipping symlinks and any file that escapes base_dir.
    
    If exclude_pycache is True, ignores directories or files containing "__pycache__".
    If max_files is provided, stop after that many regular files are collected.
    """
    try:
        root = base_dir.resolve()
    except OSError:
        return []

    out = []
    for dirpath, dirnames, filenames in os.walk(base_dir, topdown=True, followlinks=False):
        # Deterministic traversal
        if exclude_pycache:
            dirnames[:] = [d for d in sorted(dirnames) if "__pycache__" not in (Path(dirpath) / d).parts]
        else:
            dirnames.sort()

        filenames = sorted(filenames)
        for filename in filenames:
            p = Path(dirpath) / filename

            if exclude_pycache and "__pycache__" in p.parts:
                continue
            if p.is_symlink():
                continue

            try:
                real = p.resolve()
                if root != real and root not in real.parents:  # escaped the base dir
                    continue
            except OSError:
                continue

            out.append(p)
            if max_files is not None and len(out) >= max_files:
                return out
    return out
