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

:func:`walk_segments` is the same idea for ``Path.glob``, whose answer on a directory that is
searchable but not listable (mode 111 / 311) follows the interpreter (C-682). It expands a
pattern of literal and ``*``-style segments with ``os.lstat`` / ``os.scandir`` only, so a file
is FOUND whenever the path to it is traversable and a listing is needed only for a ``*``
segment.

A Layer-1 leaf: stdlib imports only, imports nothing from this package. Read-only; no
network. Not a drop-in for ``os.path.exists`` and friends - those swallow every error on
every interpreter, which is the opposite contract.
"""
from __future__ import annotations

import errno
import fnmatch
import os
import stat
from collections.abc import Iterator
from pathlib import Path

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


def _gap(exc: OSError, errors: "list | None") -> None:
    """A directory that had to be listed could not be: raise it, or record it in *errors*.

    "Not there" errors (:func:`_ignore_error`) are silent either way.
    """
    if _ignore_error(exc):
        return
    if errors is None:
        raise exc
    errors.append(exc)


def _walk(base: Path, segs: "tuple[str, ...]", errors: "list | None") -> "Iterator[Path]":
    seg, rest = segs[0], segs[1:]
    if any(c in seg for c in "*?["):
        try:
            it = os.scandir(base)
        except OSError as exc:
            _gap(exc, errors)
            return
        except ValueError:
            return
        with it:
            while True:
                try:
                    entry = next(it)
                except StopIteration:
                    return
                except OSError as exc:
                    _gap(exc, errors)
                    return
                if not fnmatch.fnmatchcase(entry.name, seg):
                    continue
                if rest:
                    yield from _walk(base / entry.name, rest, errors)
                else:
                    yield base / entry.name
        return
    child = base / seg
    if rest:
        yield from _walk(child, rest, errors)
        return
    try:
        os.lstat(child)
    except OSError as exc:
        if _ignore_error(exc):
            return
        # The parent is not searchable. Whether the name exists is then a question for its
        # listing: a listable parent (mode 444) answers it honestly (found only if the name is
        # there, so the consumer's own open fails loudly); one that is neither searchable nor
        # listable (mode 000) leaves existence UNKNOWN, which is a gap, never a found path.
        try:
            names = os.listdir(base)
        except OSError as lexc:
            _gap(lexc, errors)
            return
        except ValueError:
            return
        if seg not in names:
            return
    except ValueError:
        return
    yield child


def walk_segments(root: "str | os.PathLike[str]", segments: "list[str] | tuple[str, ...]",
                  *, errors: "list | None" = None) -> "Iterator[Path]":
    """Expand *segments* below *root*; the same result on every Python (C-682).

    Each segment is a literal name or an fnmatch pattern (``*``, ``?``, ``[...]``; ``*``
    matches dotfiles, as ``Path.glob`` does). A literal segment needs only execute permission
    on the directories before it; a pattern segment needs the directory listed. The last
    segment matches files and directories alike, and a dangling symlink counts as present.

    * "Not there" (:func:`_ignore_error`: ENOENT, ENOTDIR, ELOOP, ...) is silent.
    * A directory that must be listed but cannot be (EACCES, EIO, ...) raises its
      ``OSError``, unless *errors* is a list: then it is appended there and the walk
      continues with the remaining directories, so one unlistable agent directory does not
      hide the others.
    * A literal last segment under a parent that is not searchable (EACCES) is decided by
      listing that parent: found only if the name is listed (so opening it fails where the
      caller can say so); if the parent cannot be listed either, existence is UNKNOWN and is
      an unlistable-directory gap (raised, or appended to *errors*), never a found path.

    Yields lazily, in ``os.scandir`` order.
    """
    segs = tuple(segments)
    if not segs:
        return iter(())
    return _walk(Path(root), segs, errors)


def expand_user(path: "str | os.PathLike[str]") -> Path:
    """``Path(path).expanduser()``, except that an unresolvable ``~`` is left as written (C-729).

    ``Path.expanduser`` raises ``RuntimeError`` - not ``OSError`` - when ``~name`` names no
    account on this machine, and for ``~`` / ``~/x`` when neither ``HOME`` nor a passwd
    entry exists. Nothing on the audit path catches that, so one config value such as
    ``agents.defaults.workspace: "~nosuchuser/x"`` ended the whole run with "unexpected
    internal error". The platform itself expands only ``~``, ``~/`` and ``~\\`` and reads
    ``~name/x`` as an ordinary relative path (see ``collector._expand_user_path``), so the
    unexpanded path is both what OpenClaw would use and a path that is simply not there.

    Identical to ``Path(path).expanduser()`` for every input that does not raise today.
    A path the USER typed on the command line must not take this fallback (an output flag
    would create a directory literally named ``~name``); ``cli`` refuses those up front.
    """
    p = Path(path)
    try:
        return p.expanduser()
    except RuntimeError:
        return p
