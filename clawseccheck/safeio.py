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
import posixpath
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


def _write_all(fd: int, data: bytes) -> None:
    """Write *every* byte of *data* to *fd*, looping over short writes.

    A single ``os.write`` may write fewer bytes than requested WITHOUT raising —
    e.g. when the filesystem fills mid-write (ENOSPC/EDQUOT can return a short
    count). An unchecked single write would then fsync+replace a truncated file
    onto the destination, silently reproducing the B-107 corruption the atomic
    write exists to prevent (B-167). Loop until the buffer is fully drained.
    """
    mv = memoryview(data)
    written = 0
    total = len(mv)
    while written < total:
        n = os.write(fd, mv[written:])
        if n <= 0:  # pragma: no cover - defensive; POSIX os.write won't return 0 for a non-empty buffer
            raise OSError("os.write made no progress")
        written += n


def secure_write_bytes(path: Path, data: bytes) -> None:
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
            _write_all(fd, data)
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


def secure_write_text(path: Path, data: str) -> None:
    """Atomically overwrite *path* with *data* (UTF-8) — see `secure_write_bytes`."""
    secure_write_bytes(path, data.encode("utf-8"))


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
            _write_all(fd, b"\n")
        _write_all(fd, data.encode("utf-8"))
    finally:
        os.close(fd)
    try:  # belt-and-suspenders; creation mode already 0600 (POSIX only)
        path.chmod(0o600)
    except (OSError, NotImplementedError):
        pass


def is_safe_tar_member(base_dir: Path, member_name: str) -> bool:
    """True when an archive member's DECLARED NAME stays inside the extraction root.

    B-747: this is answered LEXICALLY, and never against the filesystem. The previous
    version did ``Path(base_dir / member_name).resolve()``, which follows symlinks that
    happen to exist on disk — so it answered "where would this land given the current
    state of this machine", not "does this name escape". Those are different questions,
    and the second is the one an archive scan is asking: nothing is being extracted.

    What that cost, measured end to end through ``--vet-skill``: a skill holding an
    ordinary editable checkout beside its own built wheel —

        mypkg -> ../src/mypkg          (a symlink, benign)
        mypkg-1.0-py3-none-any.whl     (members: mypkg/__init__.py, ...dist-info/...)

    read ``DO-NOT-INSTALL`` with "Archive path traversal detected:
    mypkg-1.0-py3-none-any.whl::mypkg/__init__.py". ``mypkg/__init__.py`` is the most
    ordinary path in Python packaging, and the collision is not bad luck: for a Python
    package the source directory and the wheel's top-level package have the SAME NAME by
    construction. Removing the symlink alone restored ``CAUTION``, which is how the cause
    was isolated. A false-positive FAIL on a benign skill is the Golden Rule #5 class.

    Deliberately NOT fixed by checking whether ``base_dir`` contains symlinks: that treats
    the symptom. Resolving at all is the defect here.

    ``base_dir`` is retained in the signature and read by nothing — that is the point of
    the change, not an oversight: the answer must not depend on what is on disk, so there
    is nothing for it to contribute. Kept so the two collector call sites and any future
    one keep expressing "member, relative to this root", and so a reader who expects the
    root to matter meets this sentence.

    A name is unsafe if it escapes on ANY platform this tool runs on, which is why the
    backslash is folded to a separator before the check. SKILL.md declares
    ``os: [darwin, linux, win32]``, and on Windows the predicate this replaced joined and
    normalised through ``ntpath``, so ``..\\..\\evil`` landed outside the root and WAS
    flagged. A first draft of this function used ``posixpath`` unconditionally and called
    that a "pre-existing false negative preserved" — which was true on POSIX and FALSE on
    Windows, where it silently dropped detection on twelve shapes (``..\\..\\evil``,
    ``sub\\..\\..\\evil``, ``\\evil``, ``C:/evil``, ``C:\\evil``, UNC ``\\\\srv\\share\\evil``,
    ``\\\\?\\C:\\evil`` …). ``C:/evil`` contains no backslash at all, so the disclosure did not
    even gesture at it. Caught by this change's own C-135 pass; modelled with
    ``ntpath.normpath(ntpath.join(...))``, which is what ``Path.resolve()`` degrades to
    there.

    The cost of folding is a false POSITIVE on a POSIX file literally named
    ``..\\..\\evil`` — a legal but bizarre filename that escapes on Windows anyway. For a
    security predicate that is the right direction, and it does not touch the ordinary
    case: ``dir\\file.txt`` folds to ``dir/file.txt`` and stays safe, as the battery pins.

    One pre-existing FALSE NEGATIVE genuinely is preserved rather than silently changed,
    and is filed on its own: the tar branch checks only ``member.name``, never
    ``member.linkname``, so a link member with a traversing target and a safe name is
    invisible to both this predicate and the one it replaces.

    KNOWN AND ACCEPTED, with its mitigation stated exactly: a skill can ship both halves of
    an escape itself — a real symlink ``data -> ../outside`` beside an archive member
    ``data/payload.txt``. The old predicate caught that as a traversal; this one cannot,
    because it is statically indistinguishable from the benign case above (the wheel's own
    ``mypkg -> ../src/mypkg`` escapes the skill directory too, so even "does the symlink
    point outside?" does not separate them). What covers it, MEASURED rather than assumed —
    an earlier draft of this paragraph claimed a WARN always fires and that was wrong:

      * symlink escaping the HOME  -> B87 WARNs, "Skill/workspace symlink escapes the
        tree: workspace/skills/demo/data -> /…". The dangerous half is disclosed; only the
        archive-member FAIL is gone.
      * symlink escaping only the SKILL DIRECTORY but staying inside the home -> B87 PASSes
        and B13 PASSes. That case is genuinely silent, and it is the residual this trade
        buys. It is the milder half — extraction lands elsewhere inside the user's own
        OpenClaw home rather than at an arbitrary host path — but it is not nothing, and it
        is filed rather than papered over.

    Verified against the predicate it replaces over a 32-shape battery on a clean base
    directory — where the old one was correct — with zero disagreements, plus the shapes
    that only differ once a symlink exists.
    """
    try:
        name = str(member_name)
    except Exception:  # pragma: no cover - a member name that will not stringify
        return False
    # A NUL cannot appear in a legitimate path and breaks downstream C-level calls.
    if "\x00" in name:
        return False
    # Fold the Windows separator before any judgement — see the docstring: a name that
    # escapes on a supported platform is unsafe on every one of them.
    name = name.replace("\\", "/")
    # A drive-qualified name ("C:/evil", "C:evil") is rooted on Windows and is never a
    # legitimate archive member; posixpath cannot see it as absolute.
    if len(name) >= 2 and name[1] == ":" and name[0].isalpha():
        return False
    # Absolute ("/etc/passwd", "//etc/passwd", UNC "//srv/share/x") escapes by definition.
    if posixpath.isabs(name):
        return False
    # Purely textual `..` collapse. "a/b/../../../c" -> "../c"; "foo/.." -> "."; "./" -> ".".
    normalised = posixpath.normpath(name)
    return normalised == "." or not (
        normalised == ".." or normalised.startswith("../")
    )


_VCS_DIR_NAMES = (".git", ".hg", ".svn")


def walk_dir_safely(
    base_dir: Path,
    exclude_pycache: bool = False,
    exclude_vcs: bool = False,
    max_files: int | None = None,
    skips: list | None = None,
    prune_dir=None,
    keep_file=None,
    capped: list | None = None,
    unreadable_dirs: list | None = None,
) -> list[Path]:
    """Recursively walk base_dir, skipping symlinks and any file that escapes base_dir.

    If exclude_pycache is True, ignores directories or files containing "__pycache__".
    If exclude_vcs is True, ignores directories or files under a ".git", ".hg", or ".svn"
    directory (VCS metadata is not skill/config content — B-125).
    If max_files is provided, stop after that many regular files are collected.
    If `skips` (a list) is provided, each skipped symlink or path-escape is appended to it as
    a (path, reason) tuple so a caller can surface the drop instead of losing it silently
    (F-061) — the default (None) keeps the original behaviour for existing callers.

    If `prune_dir` is provided, it is called as ``prune_dir(rel_parts)`` for every
    subdirectory the walk is about to descend into, where `rel_parts` is that
    subdirectory's path components *relative to* `base_dir` (e.g. ``("workspace",
    "skills")``). Returning True prunes the whole subdirectory — its files never reach
    `keep_file`/`max_files` at all. This lets a caller exclude a bulk/noise subtree
    (e.g. a vendored cache dir) *before* it can consume the `max_files` budget, instead
    of filtering it out of the result afterward (B-244: a post-hoc filter still lets an
    excluded subtree starve real files below it in the walk order).

    If `keep_file` is provided, it is called as ``keep_file(path)`` for every candidate
    file (already past the symlink/escape/prune checks); only files for which it
    returns True are collected and counted against `max_files` — so a file the caller
    was always going to discard doesn't spend budget either (B-244).

    If `capped` (a list) is provided and the walk stops early because `max_files` was
    reached before the directory tree was fully traversed, a single sentinel (True) is
    appended to it — so a caller can tell "genuinely truncated, more of the tree was
    never reached" apart from "walked everything and it just happened to total
    <= max_files files" (GR#4: no silent completeness claim over a capped scan).

    If `unreadable_dirs` (a list) is provided, a subdirectory that could not be listed is
    appended to it as a ``(path, reason, errno)`` triple instead of vanishing. `os.walk`'s default
    ``onerror=None`` **discards** that error, so an unreadable directory produced no files,
    no `skips` entry and no `capped` sentinel — the subtree simply did not exist as far as
    every caller was concerned (B-549). That is the same fail-open B-458 closed for an
    unreadable *file*, one level up and strictly worse: a file hides one file, a directory
    hides an unbounded subtree. Measured through `--vet-skill` before this parameter
    existed: a skill with `chmod 000` on a subdirectory containing a `curl | sh` payload
    reported `INSTALL` / `Danger PASS "no malware signature or known-bad indicator"` /
    exit 0, with nothing in `--json` either.

    The `errno` is carried because the caller has to tell two very different facts apart and
    only it can: ``EACCES``/``EPERM`` means the subtree is there and deliberately unlistable
    (the defect above), while ``ENOENT`` means it ceased to exist between `os.walk` listing it
    and descending into it — ordinary churn on a live machine, not something hidden. This
    layer records both and rules on neither; that split is `collect_skill_files`'s to make.

    Default `None` keeps the previous behaviour for every existing caller, so opting in is
    per-call-site — the same additive discipline as `skips` and `capped`.
    """
    try:
        root = base_dir.resolve()
    except OSError:
        return []

    out = []

    def _on_walk_error(exc: OSError) -> None:
        if unreadable_dirs is not None:
            unreadable_dirs.append((str(getattr(exc, "filename", "") or base_dir),
                                    exc.strerror or str(exc), exc.errno))

    # dirpath -> [first entry, its OSError, how many entries in that directory failed]
    _unlistable: dict = {}

    def _note_unlistable(dirpath: str, entry: str, exc: OSError) -> None:
        """An entry inside a listed directory that could not even be classified.

        Re-raises when the caller did not opt in. Opt-in has to mean opt-in: before B-551
        this OSError propagated, and swallowing it here would have converted a loud crash
        into a silent drop at the **16** other call sites that never asked for the channel —
        a fail-open introduced by the fix for a fail-open, and the exact opposite of the
        "byte-identical for every existing caller" claim this parameter is documented with.
        Caught by the independent adversarial pass, not by review or by any gate.
        """
        if unreadable_dirs is None:
            raise exc
        seen = _unlistable.get(dirpath)
        if seen is None:
            _unlistable[dirpath] = [entry, exc, 1]
        else:
            seen[2] += 1

    def _flush_unlistable() -> None:
        """One record per directory, but the record says how many entries it stands for.

        The first version emitted one record and stopped counting, so a directory holding
        three unreadable entries reported ``(1 path(s))`` and named only the first — and
        because the walk yields `sorted(filenames)`, an attacker picks which one that is by
        naming it. The disclosure still fired, but it understated the gap and pointed at a
        file of the attacker's choosing. Counting costs nothing and the sentence stops
        being a decoy.
        """
        if unreadable_dirs is None:
            return
        for entry, exc, count in _unlistable.values():
            reason = exc.strerror or str(exc)
            if count > 1:
                reason = f"{reason} ({count} entries in this directory)"
            unreadable_dirs.append((entry, reason, exc.errno))

    for dirpath, dirnames, filenames in os.walk(
        base_dir, topdown=True, followlinks=False, onerror=_on_walk_error
    ):
        # Deterministic traversal
        if exclude_pycache or exclude_vcs or prune_dir is not None:
            rel_dirpath = os.path.relpath(dirpath, base_dir)

            def _keep(d: str, _dirpath: str = dirpath, _rel: str = rel_dirpath) -> bool:
                parts = (Path(_dirpath) / d).parts
                if exclude_pycache and "__pycache__" in parts:
                    return False
                if exclude_vcs and any(vcs in parts for vcs in _VCS_DIR_NAMES):
                    return False
                if prune_dir is not None:
                    rel_parts = (d,) if _rel == "." else Path(_rel).parts + (d,)
                    if prune_dir(rel_parts):
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
            try:
                is_link = p.is_symlink()
            except OSError as exc:
                # B-551: `os.walk` succeeded here — `opendir` needs only `r`, which a `0444`
                # directory grants — so `onerror` never fired and the `unreadable_dirs`
                # channel above stayed empty. But without `x` on the parent, `stat` fails for
                # EVERY entry, so `Path.is_symlink()` (which re-raises anything outside
                # ENOENT/ENOTDIR/EBADF/ELOOP) threw straight out of this function before any
                # bookkeeping ran. Measured: `--vet-skill` died with "unexpected internal
                # error (PermissionError)" and no dossier at all, while the audit path caught
                # it per-skill and printed `B13 PASS | Scanned 1 installed skill(s); no
                # shell-exec / exfiltration / obfuscation patterns found` on a home holding
                # two, with the unscanned one absent from the inventory entirely.
                #
                # Recorded once per directory, not once per entry: with no `x` every sibling
                # fails identically, so a per-entry record would emit one line per file while
                # saying the same thing. The dedup is keyed on the directory rather than
                # skipping the rest of it, so a genuine single-entry failure (a race, a name
                # the filesystem rejects) still drops only that entry.
                _note_unlistable(dirpath, str(p), exc)
                continue
            if is_link:
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
            except OSError as exc:
                # The same silent drop one line later, and reachable independently: a file
                # that resolves through a directory the walk may not search.
                _note_unlistable(dirpath, str(p), exc)
                continue

            if keep_file is not None and not keep_file(p):
                continue

            # B-244 round 2: only report a genuine truncation. The cap must not fire
            # merely because `out` reached `max_files` — that also happens when the
            # walk had EXACTLY `max_files` candidates and nothing beyond them, which
            # is a complete scan, not a capped one. So the budget check runs BEFORE
            # appending: `p` itself is the first candidate the walk found *beyond*
            # the already-full budget, i.e. positive proof more of the tree exists,
            # and it is reported as capped without being counted into `out`.
            if max_files is not None and len(out) >= max_files:
                if capped is not None:
                    capped.append(True)
                _flush_unlistable()
                return out
            out.append(p)
    _flush_unlistable()
    return out
