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

Pure stdlib, no network. These hardening guarantees hold on **POSIX only**
(Linux, macOS): ``O_NOFOLLOW`` and ``chmod`` are POSIX facilities.

**Windows caveat (C-160):** on Windows both primitives degrade — ``O_NOFOLLOW``
resolves to ``0`` (the symlink-clobber guard is a no-op; Windows *does* have
symlinks/junctions, so this is a real gap, not an absent surface) and ``chmod``
does not set NTFS ACLs (the ``0o600``/``0o700`` modes are best-effort and the
store is **not** owner-restricted). The read-only audit itself still works on
Windows; only this local-store hardening is unavailable there. This is disclosed
in the README rather than silently assumed away — the tool must not claim a
security property it cannot deliver on a platform it advertises.
"""
from __future__ import annotations

import os
import tempfile
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
    """Atomically overwrite *path* with *data* (temp-file + fsync + os.replace).

    Writing straight onto the destination (O_TRUNC then os.write) left a truncated,
    corrupt file if the process died mid-write — crash, power loss, or ENOSPC. For the
    monitor's ``state.json`` a corrupt read is swallowed as "no state", which silently
    reset the baseline to first-run and hid real config drift (B-107). We now write to a
    sibling temp file, fsync it, then ``os.replace`` it onto the destination, so a reader
    ever only sees the old complete file or the new complete file — never a partial write.

    Symlink-safety is preserved and, if anything, stronger than the previous O_NOFOLLOW
    open: ``os.replace`` renames onto the destination *name* — it never writes *through* a
    symlink planted at that path (the symlink is replaced, its target left untouched). The
    temp file is created fresh and unique by ``mkstemp`` (mode 0600, O_EXCL — there is
    nothing to follow) inside the destination's own directory, so the replace is a
    same-filesystem atomic rename.
    """
    path = Path(path)
    # Preserve the B-007 refuse-on-symlink contract the old O_NOFOLLOW open enforced: a
    # planted symlink at the destination is a tamper signal, and callers/tests expect an
    # OSError rather than a silent write. (os.replace below is the hard backstop — it never
    # writes *through* a symlink even if one is planted after this check, so the victim is
    # safe regardless; this check just keeps the loud, tested refusal for the common case.)
    if path.is_symlink():
        raise OSError(f"refusing to write through symlinked target: {path}")
    parent = path.parent
    fd, tmp_name = tempfile.mkstemp(dir=parent, prefix="." + path.name + ".", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        try:
            os.write(fd, data.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)  # atomic on the same filesystem
    except BaseException:
        # Any failure before the replace lands (write / fsync / replace, or an interrupt)
        # must leave no partial temp behind — the destination keeps its previous content.
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    try:  # best-effort: persist the rename itself across power loss (POSIX dirs only)
        dir_fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass
    try:  # belt-and-suspenders; mkstemp already created the temp 0600 (POSIX only)
        path.chmod(0o600)
    except (OSError, NotImplementedError):
        pass


def secure_append_text(path: Path, data: str) -> None:
    """Append *data* to *path*, refusing to follow a symlinked target.

    C-177: if the file already has content that does NOT end in a newline —
    e.g. a crash truncated the previous write mid-line — a leading ``\\n`` is
    written first. Without this, the new line gets silently concatenated onto
    the dangling truncated line with no separator, turning one recoverable
    truncated record into a permanent unparseable merged line.
    """
    needs_leading_newline = False
    try:
        with path.open("rb") as rf:
            rf.seek(0, os.SEEK_END)
            if rf.tell() > 0:
                rf.seek(-1, os.SEEK_END)
                needs_leading_newline = rf.read(1) != b"\n"
    except OSError:
        pass  # file doesn't exist yet (or unreadable) — nothing to guard

    fd = _open_owner_only(path, os.O_APPEND)
    try:
        if needs_leading_newline:
            os.write(fd, b"\n")
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


_VCS_DIR_NAMES = (".git", ".hg", ".svn")


def walk_dir_safely(
    base_dir: Path,
    exclude_pycache: bool = False,
    exclude_vcs: bool = False,
    max_files: int | None = None,
    skips: list | None = None,
) -> list[Path]:
    """Recursively walk base_dir, skipping symlinks and any file that escapes base_dir.

    If exclude_pycache is True, ignores directories or files containing "__pycache__".
    If exclude_vcs is True, ignores directories or files under a ".git", ".hg", or ".svn"
    directory (VCS metadata is not skill/config content — B-125).
    If max_files is provided, stop after that many regular files are collected.
    If `skips` (a list) is provided, each skipped symlink or path-escape is appended to it as
    a (path, reason) tuple so a caller can surface the drop instead of losing it silently
    (F-061) — the default (None) keeps the original behaviour for existing callers.
    """
    try:
        root = base_dir.resolve()
    except OSError:
        return []

    out = []
    for dirpath, dirnames, filenames in os.walk(base_dir, topdown=True, followlinks=False):
        # Deterministic traversal
        if exclude_pycache or exclude_vcs:
            def _keep(d: str, _dirpath: str = dirpath) -> bool:
                parts = (Path(_dirpath) / d).parts
                if exclude_pycache and "__pycache__" in parts:
                    return False
                if exclude_vcs and any(vcs in parts for vcs in _VCS_DIR_NAMES):
                    return False
                return True

            dirnames[:] = [d for d in sorted(dirnames) if _keep(d)]
        else:
            dirnames.sort()

        filenames = sorted(filenames)
        for filename in filenames:
            p = Path(dirpath) / filename

            if exclude_pycache and "__pycache__" in p.parts:
                continue
            if exclude_vcs and any(vcs in p.parts for vcs in _VCS_DIR_NAMES):
                continue
            if p.is_symlink():
                if skips is not None:
                    try:
                        tgt = os.readlink(p)
                    except OSError:
                        tgt = "?"
                    skips.append((str(p), f"symlink -> {tgt}"))
                continue

            try:
                real = p.resolve()
                if root != real and root not in real.parents:  # escaped the base dir
                    if skips is not None:
                        skips.append((str(p), f"path-escape -> {real}"))
                    continue
            except OSError:
                continue

            out.append(p)
            if max_files is not None and len(out) >= max_files:
                return out
    return out
