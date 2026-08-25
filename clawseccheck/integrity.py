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

import errno
import hashlib
import os
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

# The three note kinds `package_digest` reports through its `notes` channel. Carried as an
# explicit field rather than encoded in the message text, because the caller has to branch
# on it (an uncovered path is disclosed and still digested; an unreadable one means the
# digest covers less than the tree and the CLI must exit non-zero) and prefix-matching a
# human sentence is exactly the kind of coupling that breaks when the sentence is reworded.
NOTE_SYMLINK = "symlink"
NOTE_PATH_ESCAPE = "path-escape"
NOTE_UNREADABLE = "unreadable"
NOTE_VANISHED = "vanished"
# B-608: presence-only disclosure of a PEP 552 *unchecked-hash* .pyc found directly
# inside a real (non-symlink) ``__pycache__``. Never enters `per_file`/`combined` — see
# `_pyc_header_flags` and `_scan_for_unchecked_hash_pycs` below for why this is safe to
# report without becoming environment-dependent (B-069).
NOTE_UNCHECKED_PYC = "unchecked-pyc"

# The first 8 bytes of a PEP 552 .pyc: a 4-byte magic number (interpreter/version
# dependent — never read here) followed by a 4-byte little-endian bit field. Bit 0 set
# means "hash-based" rather than the default "timestamp-based"; bit 1, meaningful only
# when bit 0 is set, means "check the hash against source on import". flags == 0b01 is
# therefore the *unchecked*-hash pyc: hash-based, but NOT checked against source before
# Python imports it — the PEP 552 surface this note exists to disclose. Verified against
# this box's own interpreter: a default `py_compile.compile()` call and a normal
# `import` both always write flags == 0 (timestamp-based); producing flags == 1 requires
# passing `invalidation_mode=PycInvalidationMode.UNCHECKED_HASH` explicitly, which no
# ordinary build/test/install step does.
_PYC_HEADER_LEN = 8
_PYC_UNCHECKED_HASH_FLAGS = 0b01


def _pyc_header_flags(path: Path) -> int | None:
    """Return the PEP 552 flags field of a ``.pyc``, or ``None`` if it can't be read.

    Reads only the first 8 bytes (magic + flags) — never the code object, and never the
    trailing mtime/size-or-source-hash field either — so nothing content- or
    interpreter-dependent from this file ever reaches a caller. A file too short to hold
    a flags field, or one that cannot be opened, is simply unclassifiable: this is a
    best-effort signal, not a pyc validator.

    B-608 follow-up (2026-08-25): the "cannot be opened" branch is a
    genuine UNKNOWN, not a confirmed-benign, and it is silent by a deliberate, narrower
    argument than the "too short to hold a header" branch above — those two are NOT the
    same claim. A truncated file is provably inert: Python's own loader requires the full
    header to accept a ``.pyc`` at all, so a file this short cannot be executed as an
    unchecked-hash pyc either, whoever tries to import it. An ``OSError`` here (e.g.
    permission denied) carries no such proof — the bytes behind it are unknown, not
    absent. It stays silent anyway because ``--verify-self`` and the package's own
    ``import`` both run as the invoking OS user on this single-user local CLI: a ``.pyc``
    this call cannot open is, on that same principal, also a ``.pyc`` Python cannot open
    to execute — unreadable-to-audit implies unreadable-to-run, not "invisible attack".
    That equivalence is the actual precondition, not an oversight; it would NOT hold
    under privilege separation (an auditor running as a lower-priv user than the process
    that later imports the package), which this tool does not assume. Emitting a
    distinct disclosure for this branch would need a new note kind whose header wording
    cli.py owns (`clawseccheck/cli.py`'s verify_self block matches `NOTE_UNCHECKED_PYC`
    to text that asserts a *confirmed* detection) — reusing that kind here would
    overclaim an unread file as a found one. See
    ``tests/test_b608_pyc_read_error_is_unknown_not_clean.py`` for the pinned behavior
    and the escalation this leaves open.
    """
    try:
        with path.open("rb") as fh:
            header = fh.read(_PYC_HEADER_LEN)
    except OSError:
        return None
    if len(header) < _PYC_HEADER_LEN:
        return None
    return int.from_bytes(header[4:8], "little")


def _scan_for_unchecked_hash_pycs(cache_dir: Path, rel: str, found: dict) -> None:
    """Record PEP 552 unchecked-hash ``.pyc`` filenames found directly inside cache_dir.

    Only the immediate contents of ``cache_dir`` are listed — a real ``__pycache__``
    never nests subdirectories, so there is nothing to recurse into. Entries are
    followed for classification but never for listing (``is_file(follow_symlinks=False)``
    excludes a symlinked ``.pyc``, matching the walk's own no-follow rule elsewhere in
    this module) — a symlink pointing here is a separate, already-covered surface
    (``NOTE_SYMLINK`` on the directory itself, or on the link if it names a file).
    """
    try:
        entries = list(os.scandir(cache_dir))
    except OSError:
        return
    names = []
    for entry in entries:
        if not entry.name.endswith(".pyc"):
            continue
        try:
            if not entry.is_file(follow_symlinks=False):
                continue
        except OSError:
            continue
        if _pyc_header_flags(Path(entry.path)) == _PYC_UNCHECKED_HASH_FLAGS:
            names.append(entry.name)
    if names:
        found[rel] = sorted(names)


def _link_target(path: Path) -> str:
    try:
        return os.readlink(path)
    except OSError:
        return "?"


def _relpath(raw: str, pkg_dir: Path) -> str:
    """Best-effort POSIX relpath for a path safeio reported as an absolute string."""
    try:
        return Path(raw).relative_to(pkg_dir).as_posix()
    except ValueError:
        return raw


def package_digest(
    pkg_dir: Path | None = None,
    notes: list | None = None,
) -> tuple[str, dict[str, str]]:
    """Return ``(combined_hex, per_file_map)`` for **every** entry in the package tree.

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

    **What is NOT covered, stated plainly.** The excluded directories above are excluded
    by *content*: nothing inside ``__pycache__`` / ``.ruff_cache`` / ``.mypy_cache`` /
    ``.pytest_cache`` / ``.git`` is hashed, so a symlink *inside* one of them is not seen
    either and does not move the digest.  (The excluded *entry itself* is covered whatever
    it is — a directory symlink through ``_observe_dir``, a file or dangling symlink
    through ``skips`` — so only what is nested inside a REAL one is out of reach.)  That is
    a real residual, not a claim of coverage:
    a PEP 552 *unchecked-hash* ``.pyc`` planted inside a genuine ``__pycache__`` is
    imported without validating its source. Removing the exclusion is not the fix — it is
    what B-069 reverted, because ``.pyc`` bytes vary by interpreter and a dev checkout
    would stop matching a clean install.

    **B-608: presence of an unchecked-hash ``.pyc`` is disclosed, without reading it into
    the digest.** A real ``__pycache__`` is scanned (never descended into by the digest
    walk, only peeked at) for ``.pyc`` files whose PEP 552 flags field is exactly
    ``0b01`` — hash-based but *not* checked against source on import, i.e. code Python
    will run without comparing it to the ``.py`` it claims to come from. Only the 4-byte
    flags field is read (never the interpreter-dependent magic number, never the code
    object), so this cannot make ``combined`` vary by interpreter or toolchain the way
    hashing ``.pyc`` bytes did (B-069) — the finding is reported via ``notes`` as
    ``NOTE_UNCHECKED_PYC`` and never enters ``per_file``. An ordinary stale or
    cross-version ``.pyc`` is timestamp-based (flags ``0``) and never trips this: a
    default ``py_compile.compile()`` call and a normal ``import`` both always write
    flags ``0``; an unchecked-hash pyc requires an explicit
    ``invalidation_mode=PycInvalidationMode.UNCHECKED_HASH`` opt-in that no ordinary
    build/test/install step performs.

    **Symlinks are covered by name and target, never by followed content** (B-590).
    Until then the walk dropped them silently — ``walk_dir_safely`` skips a symlink,
    and with no ``skips`` list passed the drop left no trace, so ``ln -s
    /outside/evil.py clawseccheck/extra_link.py`` produced a byte-identical
    ``combined`` over a tree that had grown an importable module.  A symlinked
    *directory* was worse and invisible to that channel too: ``os.walk`` lists it
    but never descends, so it yielded no files and no skip entry, and an entire
    importable subpackage could be attached without moving the digest.  Both now
    enter ``per_file`` keyed by their relative path, with the digest taken over
    ``kind:target`` — the same shape git uses for a symlink blob.  So the map's
    value is "sha256 of this path's bytes" for a real file and "sha256 of what this
    link is and points at" for a link; the ``notes`` channel below is what tells
    them apart.  Following the link and hashing the target is deliberately **not**
    done: it would let a link to a legitimate outside file leave the digest
    unchanged, and it re-opens the escape-the-base-dir hole ``walk_dir_safely``
    closes on purpose.  Verified on this project's own installs — the git index carries
    no ``120000`` entries and ``find -type l`` over the ClawHub-installed copy is empty —
    so on a real clawseccheck tree this adds nothing to ``per_file`` and ``combined`` is
    unchanged.  Note that "no symlinks in a package directory" is NOT true of Python
    packaging in general (Debian's ``python3-babel`` and ``python3-netaddr`` both ship
    in-package symlinks), which is why a disclosed entry is worth a look rather than
    proof of tampering.

    **A path that cannot be read is an error, not a gap.**  ``read_bytes()`` used to
    be unguarded, so ``chmod 000`` on one module aborted the whole command with a
    generic "unexpected internal error (PermissionError)" that named nothing — and an
    unreadable *directory* was quietly worse: ``os.walk``'s ``onerror`` discarded it,
    the subtree's files simply left ``per_file``, and the digest changed with no
    statement of why.  Both are now collected.  If the caller passed ``notes`` they
    are reported through it and the caller rules on them; if it did not, they raise a
    named ``OSError``.  Opt-in has to mean opt-in — the alternative is that the CI job
    which signs ``SHA256SUMS.txt`` silently signs a digest over a tree it failed to
    read part of (the same reasoning as ``safeio._note_unlistable``).

    ``ENOENT`` is excluded from all of that and reported as ``NOTE_VANISHED`` instead: a
    path that disappeared between the walk listing it and this code reaching it is an
    update or an rsync running alongside the scan, not a hidden file, and it neither
    raises nor sets a non-zero exit.

    Parameters
    ----------
    pkg_dir:
        Directory to scan (defaults to the real ``clawseccheck/`` package directory).
        Exposed as a parameter so tests can supply a controlled set of files.
    notes:
        Optional list. When provided, every entry the digest could not cover as
        ordinary file content is appended to it as a ``(kind, relpath, detail)``
        triple, where `kind` is one of ``NOTE_SYMLINK`` / ``NOTE_PATH_ESCAPE`` /
        ``NOTE_UNREADABLE`` / ``NOTE_VANISHED`` / ``NOTE_UNCHECKED_PYC``. Default ``None``
        keeps the previous signature working for existing callers, except that an
        unreadable path now raises a message that names it instead of an unnamed
        ``PermissionError``.
        ``NOTE_PATH_ESCAPE`` is defensive: ``walk_dir_safely`` can emit a path escape, but
        reaching one here requires a symlinked parent, which ``_observe_dir`` now prunes
        first, so it is handled rather than relied upon.
        ``NOTE_UNCHECKED_PYC`` (B-608) is a pure disclosure: unlike the other four kinds
        it never enters ``per_file`` at all, so it cannot move ``combined`` — it names the
        ``__pycache__`` directory and the unchecked-hash ``.pyc`` filenames found inside
        it, for a caller that wants to surface the signal without affecting
        reproducibility.

    Returns
    -------
    combined_hex : str
        64-character lowercase SHA-256 hex string over the sorted per-file digests.
    per_file : dict[str, str]
        ``{relpath: sha256hex}`` mapping, keyed by POSIX relative path from the
        package root (so nested files are distinguishable), sorted by path.

    Note: self-integrity computed from inside the artifact is advisory — a
    modified ``integrity.py`` can print anything.  An out-of-band signature is the
    real anchor; this only proves "this file set's bytes are unchanged AND nothing
    was added/nested."
    """
    if pkg_dir is None:
        pkg_dir = _PKG_DIR
    from .safeio import walk_dir_safely

    # relpath -> reason, for entries inside the tree that exist but whose *content* the
    # digest does not read: symlinks (file or directory) and path escapes.
    uncovered: dict[str, tuple[str, str]] = {}
    # (relpath, reason) for entries that should have been readable and were not.
    unreadable: list[tuple[str, str]] = []
    # (relpath, reason) for entries that ceased to exist mid-walk. Kept apart from
    # `unreadable` on safeio's own instruction: it records ENOENT and EACCES through one
    # channel and says the split "is the caller's to make" — EACCES means the path is
    # there and deliberately unlistable, ENOENT means it went away between the walk
    # listing it and this code reaching it. That is ordinary churn on a live machine (an
    # update or an rsync running during the scan); an adversarial pass hit a real,
    # unpatched race that produced 180 of them in one run, every one of which the first
    # version of this code reported as "made unreadable to the auditing user" with a
    # non-zero exit. An accusation on a benign race is exactly the false alarm Golden
    # Rule #5 forbids.
    vanished: list[tuple[str, str]] = []
    # relpath of a real (non-symlink) __pycache__ dir -> sorted unchecked-hash .pyc
    # filenames found directly inside it (B-608). Deliberately separate from `uncovered`:
    # entries in `uncovered` are hashed into `per_file` (that is what moves `combined`
    # for a symlink), and this must NOT — it is presence-only disclosure, never digested.
    unchecked_pyc: dict[str, list[str]] = {}

    def _observe_dir(rel_parts) -> bool:
        """Record a symlinked subdirectory, which no other channel of the walk sees.

        ``prune_dir`` is the walk's only view of a *directory* entry:
        ``os.walk(followlinks=False)`` lists a symlinked directory but never descends,
        so it contributes no files, and ``walk_dir_safely``'s ``skips`` list classifies
        only *filenames*. Returning True prunes it — a no-op for traversal, since the
        walk was never going to descend, and it states the intent so a future
        ``followlinks`` change cannot start following it by accident.

        The symlink test runs BEFORE the ``_NON_SOURCE_DIRS`` skip, and this ordering is
        the whole point: ``__pycache__`` is excluded because its *contents* vary by
        interpreter (B-069), which is a statement about bytes, not about the directory
        entry itself. A symlinked ``__pycache__`` is an arbitrary-code-execution surface —
        a PEP 552 *unchecked-hash* ``.pyc`` is imported without validating its source, so
        a link pointing at an attacker-controlled cache runs their code while every
        ``.py`` on disk stays untouched and the digest never moves. Naming the link costs
        no reproducibility (no content is hashed either way) and is the difference between
        covering that surface and not. The excluded dirs are pruned here rather than via
        ``exclude_pycache=``, because that flag is applied *before* ``prune_dir`` is
        consulted and so hid ``__pycache__`` from this observer entirely.
        """
        d = pkg_dir.joinpath(*rel_parts)
        try:
            is_link = d.is_symlink()
        except OSError:
            is_link = False
        if is_link:
            uncovered[Path(*rel_parts).as_posix()] = (NOTE_SYMLINK, _link_target(d))
            return True
        if rel_parts[-1] == "__pycache__":
            # B-608: a real __pycache__ is about to be pruned (its contents are never
            # read into the digest — B-069). Before pruning, peek at just the PEP 552
            # flags byte of each .pyc directly inside it, so a planted unchecked-hash
            # pyc is at least disclosed even though it stays outside `combined`.
            _scan_for_unchecked_hash_pycs(d, Path(*rel_parts).as_posix(), unchecked_pyc)
        return bool(_NON_SOURCE_DIRS.intersection(rel_parts))

    skips: list = []
    unreadable_dirs: list = []
    files = [
        p
        for p in walk_dir_safely(
            pkg_dir,
            skips=skips,
            prune_dir=_observe_dir,
            unreadable_dirs=unreadable_dirs,
        )
        if p.is_file()
    ]

    per_file: dict[str, str] = {}
    for path in files:
        rel = path.relative_to(pkg_dir)
        # Skip regenerated local artifacts (lint/type/test caches, VCS metadata) so the
        # digest stays reproducible across a dev/CI checkout vs a clean install (B-069).
        if _NON_SOURCE_DIRS.intersection(rel.parts):
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            reason = exc.strerror or str(exc)
            if exc.errno == errno.ENOENT:
                vanished.append((rel.as_posix(), reason))
            else:
                unreadable.append((rel.as_posix(), reason))
            continue
        per_file[rel.as_posix()] = hashlib.sha256(data).hexdigest()

    # Symlinked *files* and path escapes, which the walk reports through `skips`.
    #
    # No `_NON_SOURCE_DIRS` filter here, deliberately. `skips` only ever holds symlinks and
    # path escapes, and the excluded directories are pruned above, so nothing NESTED inside
    # one can reach this loop — the only entry the name filter could ever drop is one whose
    # own name IS `__pycache__` / `.git` / a cache dir, i.e. exactly the attack. A symlink
    # to a FILE, and a dangling symlink, are both classified by `os.walk` as filenames
    # rather than dirnames, so they arrive here instead of at `_observe_dir`; the first
    # version filtered them out and left the docstring claiming a symlinked `__pycache__`
    # was covered when only the resolves-to-a-directory case was. Found by the second
    # adversarial pass. A real cache directory is a directory and never reaches this loop.
    for raw, reason in skips:
        rel = _relpath(raw, pkg_dir)
        kind = NOTE_PATH_ESCAPE if reason.startswith("path-escape") else NOTE_SYMLINK
        _, _, target = reason.partition("->")
        uncovered[rel] = (kind, target.strip() or reason)

    for raw, reason, exc_errno in unreadable_dirs:
        rel = _relpath(raw, pkg_dir)
        if _NON_SOURCE_DIRS.intersection(Path(rel).parts):
            continue
        if exc_errno == errno.ENOENT:
            vanished.append((rel, reason))
        else:
            unreadable.append((rel, reason))

    # An uncovered entry still moves the digest: it is keyed by its own relative path, so
    # adding, removing, renaming or repointing one changes `combined`. The link's target
    # is never followed (see the docstring); only what the link *is* gets hashed.
    for rel, (kind, target) in uncovered.items():
        per_file[rel] = hashlib.sha256(f"{kind}:{target}".encode()).hexdigest()

    if unreadable and notes is None:
        named = ", ".join(name for name, _ in sorted(unreadable)[:3])
        more = "" if len(unreadable) <= 3 else f" (and {len(unreadable) - 3} more)"
        raise OSError(
            f"package_digest: {len(unreadable)} path(s) under {pkg_dir} could not be "
            f"read — {named}{more}; integrity cannot be established over this tree. "
            f"Pass notes=[] to receive this as a disclosure instead of an exception."
        )

    if notes is not None:
        for rel, (kind, target) in sorted(uncovered.items()):
            notes.append((kind, rel, target))
        for rel, reason in sorted(unreadable):
            notes.append((NOTE_UNREADABLE, rel, reason))
        for rel, reason in sorted(vanished):
            notes.append((NOTE_VANISHED, rel, reason))
        # B-608: disclosure only — never folded into `uncovered`/`per_file` above, so it
        # cannot move `combined`.
        for rel, names in sorted(unchecked_pyc.items()):
            shown = ", ".join(names[:3])
            more = "" if len(names) <= 3 else f" (and {len(names) - 3} more)"
            detail = f"{len(names)} unchecked-hash .pyc: {shown}{more}"
            notes.append((NOTE_UNCHECKED_PYC, rel, detail))

    # Combine: hash the sorted sequence of "relpath:digest\n" lines for stability.
    combined = hashlib.sha256(
        "".join(f"{name}:{digest}\n" for name, digest in sorted(per_file.items())).encode()
    ).hexdigest()

    return combined, per_file
