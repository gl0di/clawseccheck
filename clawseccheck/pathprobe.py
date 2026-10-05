"""Existence and file-type probes that tell "not there" from "could not look" - the same
answer on every Python (C-647).

ClawSecCheck separates two states that read alike: a path that is not there (a normal,
silent outcome) and a path it could not look at (an unreadable parent, an over-long name,
an I/O error). The second must reach a finding as UNKNOWN or a disclosed gap, never as a
quiet "nothing here" - a missing look must not turn into a clean verdict.

A call site gets there one of two ways, and this module does not choose for it. It
catches the error itself - ``try: p.is_dir() except OSError: <disclose the gap>`` - or it
lets the error propagate. Out of a check, ``checks.run_all`` turns an uncaught exception
into one UNKNOWN finding for that check; out of anything else on the command-line path,
``cli.main``'s last-resort handler prints a one-line error to stderr and exits 1
(``--debug`` re-raises with the traceback); a caller of the library sees the ``OSError``
itself. None of the three reads as clean. Not every call site catches: many rely on
propagation, and whether a given ``except OSError`` arm discloses the gap or deliberately
treats it as best-effort is that call site's own decision. What this module guarantees is
only that the error is raised at all (the rest of this docstring), so that whichever route
applies is live. It does not check what a handler does with it.

That works only if the probe RAISES on a path it could not look at. ``pathlib.Path`` does
on 3.9 and 3.12 (both measured): ``exists()`` / ``is_dir()`` / ``is_file()`` / ``is_symlink()``
return False for ENOENT, ENOTDIR, EBADF and ELOOP (plus three Windows error codes) and for
``ValueError``, and re-raise every other ``OSError`` (EACCES, ENAMETOOLONG, EIO, ...).
Python 3.14 rewrote them to delegate to ``os.path.*`` / to catch every ``OSError``, so
on 3.14 they return False for ANY OS error (measured on 3.14.4: a path under a directory
with mode 000 reads as absent). Every ``except OSError`` arm guarding such a call became
dead code and the audit reported clean about content it never read.

These four functions re-implement that contract (pathlib 3.12's ``_ignore_error``,
constants copied verbatim) on top of ``os.stat`` / ``os.lstat``, so the answer is identical
on every interpreter by construction. They deliberately do NOT ask which Python they run
on: a version guard would be exactly the unmeasured branch this module exists to remove
(3.13 in particular has not been measured here).

Contract, identical on every interpreter, for a ``str`` or ``os.PathLike``:

* ``os.stat(p)`` (``os.lstat(p)`` for :func:`is_symlink`), then the ``stat.S_IS*`` test;
* an ``OSError`` whose ``errno`` is ENOENT / ENOTDIR / EBADF / ELOOP, or whose
  ``winerror`` is 21 / 123 / 1921  -> ``False``;
* any other ``OSError`` (EACCES, ENAMETOOLONG, EIO, ...)  -> re-raised unchanged, so the
  caller's ``except OSError`` is live again;
* ``ValueError`` (an embedded NUL byte)  -> ``False``.

A Layer-1 leaf: stdlib imports only, imports nothing from this package. Read-only; no
network. Not a drop-in for ``os.path.exists`` and friends - those swallow every error on
every interpreter, which is the opposite contract.
"""
from __future__ import annotations

import errno
import os
import stat

# Copied from CPython 3.12's pathlib (``_IGNORED_ERRNOS`` / ``_IGNORED_WINERRORS``), not
# paraphrased: the point is to reproduce that contract exactly.
_WINERROR_NOT_READY = 21  # drive exists but is not accessible
_WINERROR_INVALID_NAME = 123  # bpo-35306
_WINERROR_CANT_RESOLVE_FILENAME = 1921  # broken symlink pointing to itself

# EBADF - guard against macOS `stat` throwing EBADF
_IGNORED_ERRNOS = (errno.ENOENT, errno.ENOTDIR, errno.EBADF, errno.ELOOP)

_IGNORED_WINERRORS = (
    _WINERROR_NOT_READY,
    _WINERROR_INVALID_NAME,
    _WINERROR_CANT_RESOLVE_FILENAME,
)


def _ignore_error(exc: BaseException) -> bool:
    """True for the OS errors that mean "the path is not there" (pathlib's own set)."""
    return (getattr(exc, "errno", None) in _IGNORED_ERRNOS
            or getattr(exc, "winerror", None) in _IGNORED_WINERRORS)


def _mode(p: "str | os.PathLike[str]", *, follow: bool) -> "int | None":
    """``st_mode`` of *p*, or None when the path is not there.

    Raises the original ``OSError`` for anything that is not a "not there" error.
    """
    try:
        st = os.stat(p) if follow else os.lstat(p)
    except OSError as exc:
        if not _ignore_error(exc):
            raise
        return None
    except ValueError:
        # Non-encodable path (an embedded NUL byte).
        return None
    return st.st_mode


def exists(p: "str | os.PathLike[str]") -> bool:
    """Whether *p* exists, following symlinks (a dangling link is not there)."""
    return _mode(p, follow=True) is not None


def is_dir(p: "str | os.PathLike[str]") -> bool:
    """Whether *p* is a directory, following symlinks."""
    mode = _mode(p, follow=True)
    return mode is not None and stat.S_ISDIR(mode)


def is_file(p: "str | os.PathLike[str]") -> bool:
    """Whether *p* is a regular file, following symlinks."""
    mode = _mode(p, follow=True)
    return mode is not None and stat.S_ISREG(mode)


def is_symlink(p: "str | os.PathLike[str]") -> bool:
    """Whether *p* is itself a symlink (``lstat``; the target is never consulted)."""
    mode = _mode(p, follow=False)
    return mode is not None and stat.S_ISLNK(mode)
