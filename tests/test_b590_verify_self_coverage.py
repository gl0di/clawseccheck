"""B-590 — ``--verify-self`` must not report a clean digest over a tree it never read.

Four defects, all reproduced against the pre-fix tree before this file existed:

* a symlinked **file** dropped into the package was skipped by ``walk_dir_safely`` with no
  ``skips`` list to record it, so ``combined`` was byte-identical over a tree that had
  grown an importable module;
* a symlinked **directory** was invisible to that channel too — ``os.walk`` lists it and
  never descends, so it produced no files and no skip entry — attaching a whole importable
  subpackage without moving the digest;
* an unreadable **file** hit an unguarded ``read_bytes()`` and aborted the command with
  ``unexpected internal error (PermissionError)``, naming nothing;
* an unreadable **directory** was discarded by ``os.walk``'s default ``onerror``, so its
  subtree simply left the per-file map with no statement of why.

Two ways of making a path unreadable are used on purpose. The injected ones (patching
``Path.read_bytes`` / ``os.scandir`` for exactly one path) are uid-independent and never
skip, so coverage does not vanish when the suite runs as root; the ``chmod 000`` ones prove
the same handler fires on a real filesystem and skip only for root. Every injected test
asserts the injection actually took, so none can pass vacuously.

Offline, read-only, stdlib only; writes nothing outside ``tmp_path``.
"""
from __future__ import annotations

import errno
import hashlib
import os
import pathlib
from pathlib import Path

import pytest

from clawseccheck.cli import main
from clawseccheck.integrity import (
    NOTE_SYMLINK,
    NOTE_UNREADABLE,
    NOTE_VANISHED,
    package_digest,
)

REPO = Path(__file__).resolve().parents[1]

_ROOT_SKIP = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores the read bit"
)


def _pkg(tmp_path: Path) -> Path:
    """A minimal package tree: one top-level module and one nested one."""
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "a.py").write_text("# a\n", encoding="utf-8")
    (pkg / "sub").mkdir()
    (pkg / "sub" / "b.py").write_text("# b\n", encoding="utf-8")
    return pkg


def _outside(tmp_path: Path) -> Path:
    out = tmp_path / "outside"
    out.mkdir()
    (out / "evil.py").write_text("PWNED = True\n", encoding="utf-8")
    return out


def _deny_read(monkeypatch, target: Path):
    """Make exactly one file raise PermissionError from read_bytes(), whatever the uid."""
    real = pathlib.Path.read_bytes

    def fake(self):
        if self == target:
            raise PermissionError(13, "Permission denied", str(target))
        return real(self)

    monkeypatch.setattr(pathlib.Path, "read_bytes", fake)


def _deny_scandir(monkeypatch, target: Path):
    """Make exactly one directory unlistable, whatever the uid.

    ``os.walk`` calls ``os.scandir(top)`` and routes the OSError to ``onerror``, which is
    the channel ``walk_dir_safely(unreadable_dirs=...)`` reports through.
    """
    real = os.scandir

    def fake(path=".", *a, **kw):
        if Path(path) == target:
            raise PermissionError(13, "Permission denied", str(target))
        return real(path, *a, **kw)

    monkeypatch.setattr(os, "scandir", fake)


# ---------------------------------------------------------------------------
# The clean tree must be untouched by all of this
# ---------------------------------------------------------------------------

def test_clean_tree_digest_and_notes_are_unchanged(tmp_path):
    """A tree with no symlinks and no unreadable paths must digest exactly as before.

    The pin is the documented algorithm itself — sha256 over the sorted
    ``relpath:sha256hex`` lines — so this fails if the symlink handling ever starts
    contributing a row (or a second section) on a tree that has no symlinks in it. That
    is what keeps every shipped ``SHA256SUMS.txt`` and every user's prior ``--verify-self``
    output comparable across this change.
    """
    pkg = _pkg(tmp_path)
    notes: list = []
    combined, per_file = package_digest(pkg_dir=pkg, notes=notes)

    assert notes == []
    assert sorted(per_file) == ["a.py", "sub/b.py"]
    manual = hashlib.sha256(
        "".join(f"{n}:{d}\n" for n, d in sorted(per_file.items())).encode()
    ).hexdigest()
    assert combined == manual


# ---------------------------------------------------------------------------
# Defect 1a — symlinked file
# ---------------------------------------------------------------------------

def test_symlinked_file_changes_the_digest_and_is_named(tmp_path):
    pkg = _pkg(tmp_path)
    out = _outside(tmp_path)
    before, _ = package_digest(pkg_dir=pkg)

    os.symlink(out / "evil.py", pkg / "extra_link.py")
    notes: list = []
    after, per_file = package_digest(pkg_dir=pkg, notes=notes)

    assert after != before, "a symlinked module must not leave the digest unchanged"
    assert notes == [(NOTE_SYMLINK, "extra_link.py", str(out / "evil.py"))]
    # It is in the map (that is what moves the digest), keyed by its relative path.
    assert "extra_link.py" in per_file
    assert len(per_file["extra_link.py"]) == 64


def test_removing_the_symlink_restores_the_baseline_digest(tmp_path):
    """The disclosure is not a one-way ratchet: the digest tracks the tree's real state."""
    pkg = _pkg(tmp_path)
    out = _outside(tmp_path)
    before, _ = package_digest(pkg_dir=pkg)

    link = pkg / "extra_link.py"
    os.symlink(out / "evil.py", link)
    assert package_digest(pkg_dir=pkg)[0] != before
    link.unlink()

    assert package_digest(pkg_dir=pkg)[0] == before


def test_repointing_a_symlink_changes_the_digest(tmp_path):
    """Same name, different target — the target is part of what is hashed."""
    pkg = _pkg(tmp_path)
    out = _outside(tmp_path)
    (out / "other.py").write_text("# other\n", encoding="utf-8")

    link = pkg / "extra_link.py"
    os.symlink(out / "evil.py", link)
    first, _ = package_digest(pkg_dir=pkg)
    link.unlink()
    os.symlink(out / "other.py", link)
    second, _ = package_digest(pkg_dir=pkg)

    assert first != second


def test_symlink_target_contents_are_not_followed(tmp_path):
    """C-135: hashing the *target's bytes* would be the tempting wrong fix.

    Following the link would let a link to a legitimate outside file leave the digest
    unchanged while the real file lives outside the scanned tree, and it re-opens the
    escape-the-base-dir hole ``walk_dir_safely`` closes deliberately. So editing the
    target must NOT move the digest — and the note is what tells the user the contents
    were never read, rather than the digest quietly implying they were.
    """
    pkg = _pkg(tmp_path)
    out = _outside(tmp_path)
    os.symlink(out / "evil.py", pkg / "extra_link.py")

    notes: list = []
    before, _ = package_digest(pkg_dir=pkg, notes=notes)
    (out / "evil.py").write_text("PWNED = 'changed'\n", encoding="utf-8")
    after, _ = package_digest(pkg_dir=pkg)

    assert after == before
    assert notes == [(NOTE_SYMLINK, "extra_link.py", str(out / "evil.py"))]


# ---------------------------------------------------------------------------
# Defect 1b — symlinked directory (strictly worse: a whole importable subpackage)
# ---------------------------------------------------------------------------

def test_symlinked_directory_changes_the_digest_and_is_named(tmp_path):
    pkg = _pkg(tmp_path)
    evil = tmp_path / "evil_pkg"
    evil.mkdir()
    (evil / "__init__.py").write_text("PWNED = True\n", encoding="utf-8")
    (evil / "payload.py").write_text("# payload\n", encoding="utf-8")
    before, _ = package_digest(pkg_dir=pkg)

    os.symlink(evil, pkg / "evil_sub")
    notes: list = []
    after, per_file = package_digest(pkg_dir=pkg, notes=notes)

    assert after != before, "a symlinked subpackage must not leave the digest unchanged"
    assert notes == [(NOTE_SYMLINK, "evil_sub", str(evil))]
    # The subtree's files are NOT walked — one row for the link itself, nothing under it.
    assert "evil_sub" in per_file
    assert not any(n.startswith("evil_sub/") for n in per_file)


def test_real_excluded_dirs_still_do_not_move_the_digest(tmp_path):
    """B-069 regression pin: a genuine ``__pycache__`` / cache dir must stay invisible.

    Their CONTENTS are excluded because ``.pyc`` bytes vary by interpreter and cache
    filenames vary by tool version, so folding them in made ``--verify-self``
    environment-dependent. Covering the symlink *entry* below must not quietly undo that.
    """
    pkg = _pkg(tmp_path)
    before, _ = package_digest(pkg_dir=pkg)

    for d, fname, content in [
        ("__pycache__", "a.cpython-312.pyc", b"\x00\x01compiled"),
        (".ruff_cache", "5829738269752342185", b"cachekey"),
        (".git", "HEAD", b"ref: refs/heads/main"),
        ("sub/__pycache__", "b.cpython-312.pyc", b"\x00\x01compiled"),
    ]:
        sub = pkg / d
        sub.mkdir(parents=True, exist_ok=True)
        (sub / fname).write_bytes(content)

    notes: list = []
    after, per_file = package_digest(pkg_dir=pkg, notes=notes)

    assert after == before
    assert notes == []
    assert sorted(per_file) == ["a.py", "sub/b.py"]


@pytest.mark.parametrize("name", ["__pycache__", ".ruff_cache", "sub/__pycache__"])
def test_a_symlinked_excluded_dir_is_covered(tmp_path, name):
    """An excluded directory is excluded by CONTENT; the entry itself is still covered.

    Found by the independent C-135 pass, which got arbitrary code execution past a clean
    digest: ``safeio._keep`` applies ``exclude_pycache`` BEFORE consulting ``prune_dir``,
    so the first version of this fix never saw a symlinked ``__pycache__`` at all. A PEP
    552 *unchecked-hash* ``.pyc`` is imported without validating its source, so a link
    pointing at an attacker-controlled cache runs their code while every ``.py`` on disk
    is untouched — and ``--verify-self`` printed an unchanged digest, no coverage note,
    and exit 0 over it. Hashing the link's name and target costs no reproducibility,
    because no content is read either way.
    """
    pkg = _pkg(tmp_path)
    attacker_cache = tmp_path / "attacker_cache"
    attacker_cache.mkdir()
    (attacker_cache / "a.cpython-312.pyc").write_bytes(b"\x00pwned")
    before, _ = package_digest(pkg_dir=pkg)

    os.symlink(attacker_cache, pkg / name)
    notes: list = []
    after, _per_file = package_digest(pkg_dir=pkg, notes=notes)

    assert after != before
    assert notes == [(NOTE_SYMLINK, name, str(attacker_cache))]


def test_symlink_inside_an_excluded_dir_is_the_documented_residual(tmp_path):
    """A KNOWN gap, pinned so it stays known rather than being rediscovered as a surprise.

    Nothing inside an excluded directory is read, so a symlink in there is not seen and
    does not move the digest. Closing it would mean walking the excluded dirs, which is
    what B-069 reverted. This test exists to record the limit — ``docs/USAGE.md`` states
    it to the user under "The known residual" — NOT to bless it: if a later change makes
    these entries visible, that is an improvement and this test should be rewritten, not
    used as an argument against it.
    """
    pkg = _pkg(tmp_path)
    out = _outside(tmp_path)
    before, _ = package_digest(pkg_dir=pkg)

    for parent in (pkg / ".git", pkg / "__pycache__"):
        parent.mkdir()
        os.symlink(out / "evil.py", parent / "planted.py")

    notes: list = []
    after, per_file = package_digest(pkg_dir=pkg, notes=notes)

    assert after == before, "residual: contents of excluded dirs are never read"
    assert notes == []
    assert not any(".git" in n or "__pycache__" in n for n in per_file)


# ---------------------------------------------------------------------------
# Defect 2a — unreadable file
# ---------------------------------------------------------------------------

def test_unreadable_file_is_named_through_notes(tmp_path, monkeypatch):
    pkg = _pkg(tmp_path)
    _deny_read(monkeypatch, pkg / "a.py")

    notes: list = []
    _combined, per_file = package_digest(pkg_dir=pkg, notes=notes)

    assert notes == [(NOTE_UNREADABLE, "a.py", "Permission denied")]
    assert "a.py" not in per_file, "the injection must actually have taken"
    assert "sub/b.py" in per_file, "one unreadable file must not abort the whole scan"


def test_unreadable_file_raises_a_named_error_when_not_opted_in(tmp_path, monkeypatch):
    """C-135: the tempting wrong fix is to downgrade the crash to a silent skip.

    A caller that did not ask for the notes channel must still not receive a digest
    computed over a smaller tree — that is what would let the CI job sign a
    ``SHA256SUMS.txt`` over files it failed to open. It raises, and unlike the bare
    ``PermissionError`` it replaces, the message names the file.
    """
    pkg = _pkg(tmp_path)
    _deny_read(monkeypatch, pkg / "a.py")

    with pytest.raises(OSError) as excinfo:
        package_digest(pkg_dir=pkg)

    msg = str(excinfo.value)
    assert "a.py" in msg
    assert "integrity cannot be established" in msg


@_ROOT_SKIP
def test_unreadable_file_on_a_real_filesystem(tmp_path):
    """The same handler, reached through real mode bits rather than an injection."""
    pkg = _pkg(tmp_path)
    (pkg / "a.py").chmod(0o000)
    try:
        notes: list = []
        _combined, per_file = package_digest(pkg_dir=pkg, notes=notes)
        assert [n[:2] for n in notes] == [(NOTE_UNREADABLE, "a.py")]
        assert "a.py" not in per_file
    finally:
        (pkg / "a.py").chmod(0o644)


# ---------------------------------------------------------------------------
# Defect 2b — unreadable directory (hides an unbounded subtree)
# ---------------------------------------------------------------------------

def test_unreadable_directory_is_named_through_notes(tmp_path, monkeypatch):
    pkg = _pkg(tmp_path)
    _deny_scandir(monkeypatch, pkg / "sub")

    notes: list = []
    _combined, per_file = package_digest(pkg_dir=pkg, notes=notes)

    assert notes == [(NOTE_UNREADABLE, "sub", "Permission denied")]
    assert "sub/b.py" not in per_file, "the injection must actually have taken"
    assert "a.py" in per_file


def test_unreadable_directory_raises_when_not_opted_in(tmp_path, monkeypatch):
    pkg = _pkg(tmp_path)
    _deny_scandir(monkeypatch, pkg / "sub")

    with pytest.raises(OSError) as excinfo:
        package_digest(pkg_dir=pkg)

    assert "sub" in str(excinfo.value)


@_ROOT_SKIP
def test_unreadable_directory_on_a_real_filesystem(tmp_path):
    pkg = _pkg(tmp_path)
    (pkg / "sub").chmod(0o000)
    try:
        notes: list = []
        _combined, per_file = package_digest(pkg_dir=pkg, notes=notes)
        assert [n[0] for n in notes] == [NOTE_UNREADABLE]
        assert "sub/b.py" not in per_file
    finally:
        (pkg / "sub").chmod(0o755)


# ---------------------------------------------------------------------------
# ENOENT is churn, not an accusation
# ---------------------------------------------------------------------------

def _raise_on_read(monkeypatch, target: Path, exc: OSError):
    real = pathlib.Path.read_bytes

    def fake(self):
        if self == target:
            raise exc
        return real(self)

    monkeypatch.setattr(pathlib.Path, "read_bytes", fake)


def test_a_path_that_vanished_mid_walk_is_not_called_unreadable(tmp_path, monkeypatch):
    """C-135 found this as a live false alarm, not a hypothetical.

    ``walk_dir_safely`` records ENOENT and EACCES through one channel and says in its own
    docstring that splitting them "is the caller's to make": EACCES means the path is
    there and deliberately unlistable, ENOENT means it went away between the walk listing
    it and the read reaching it. The first version of this fix discarded the errno, so a
    genuine unpatched race — an rsync or an update running during the scan — produced 180
    notes in one measured run, every one of them worded "made unreadable to the auditing
    user" with a non-zero exit. Accusing a user of tampering for running two ordinary
    things at once is precisely the false alarm Golden Rule #5 forbids.
    """
    pkg = _pkg(tmp_path)
    _raise_on_read(monkeypatch, pkg / "a.py",
                   FileNotFoundError(errno.ENOENT, "No such file or directory"))

    notes: list = []
    _combined, per_file = package_digest(pkg_dir=pkg, notes=notes)

    assert notes == [(NOTE_VANISHED, "a.py", "No such file or directory")]
    assert "a.py" not in per_file, "the injection must actually have taken"
    assert not any(kind == NOTE_UNREADABLE for kind, _, _ in notes)


def test_a_vanished_path_does_not_raise_for_a_caller_without_notes(tmp_path, monkeypatch):
    """The CI job that signs SHA256SUMS.txt must not die because a file moved under it."""
    pkg = _pkg(tmp_path)
    _raise_on_read(monkeypatch, pkg / "a.py",
                   FileNotFoundError(errno.ENOENT, "No such file or directory"))

    _combined, per_file = package_digest(pkg_dir=pkg)  # must not raise
    assert "a.py" not in per_file


def test_permission_denied_is_still_an_unreadable_finding(tmp_path, monkeypatch):
    """The split must not have swallowed the real case along with the benign one."""
    pkg = _pkg(tmp_path)
    _raise_on_read(monkeypatch, pkg / "a.py",
                   PermissionError(errno.EACCES, "Permission denied"))

    notes: list = []
    package_digest(pkg_dir=pkg, notes=notes)
    assert notes == [(NOTE_UNREADABLE, "a.py", "Permission denied")]


def test_cli_reports_a_vanished_path_neutrally_and_exits_zero(tmp_path, monkeypatch, capsys):
    pkg = _pkg(tmp_path)
    _raise_on_read(monkeypatch, pkg / "a.py",
                   FileNotFoundError(errno.ENOENT, "No such file or directory"))
    monkeypatch.setattr("clawseccheck.integrity._PKG_DIR", pkg)

    rc = main(["--verify-self"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "INTEGRITY CANNOT BE ESTABLISHED" not in out
    assert "made unreadable to the auditing user" not in out
    assert "disappeared while the scan was running" in out
    assert "a.py" in out


# ---------------------------------------------------------------------------
# The CLI surface — what the user actually reads
# ---------------------------------------------------------------------------

def _run_verify_self(monkeypatch, capsys, pkg: Path):
    monkeypatch.setattr("clawseccheck.integrity._PKG_DIR", pkg)
    rc = main(["--verify-self"])
    return rc, capsys.readouterr().out


def test_cli_clean_tree_prints_no_coverage_or_integrity_block(tmp_path, monkeypatch, capsys):
    """No new noise on the overwhelmingly common case: a package with nothing odd in it."""
    rc, out = _run_verify_self(monkeypatch, capsys, _pkg(tmp_path))

    assert rc == 0
    assert "Coverage note" not in out
    assert "INTEGRITY CANNOT BE ESTABLISHED" not in out


def test_cli_discloses_a_symlink_by_name_and_target(tmp_path, monkeypatch, capsys):
    pkg = _pkg(tmp_path)
    out_dir = _outside(tmp_path)
    os.symlink(out_dir / "evil.py", pkg / "extra_link.py")

    rc, out = _run_verify_self(monkeypatch, capsys, pkg)

    # rc stays 0: the digest DOES cover the link (by name and target), so this is a
    # disclosure, not a failure to compute.
    assert rc == 0
    assert "Coverage note" in out
    assert "extra_link.py" in out
    assert str(out_dir / "evil.py") in out
    # The listing row must not read like an ordinary hashed file.
    row = next(ln for ln in out.splitlines() if "extra_link.py" in ln and ln.startswith("  "))
    assert "target contents NOT read" in row


def test_cli_names_an_unreadable_module_and_exits_non_zero(tmp_path, monkeypatch, capsys):
    """The filed defect: rc 1 with an empty stdout and a stderr naming nothing.

    Now the file is named, the reader is told the digest covers less than the tree, and
    rc stays non-zero — a named, loud report rather than the quiet skip C-135 warns against.
    """
    pkg = _pkg(tmp_path)
    _deny_read(monkeypatch, pkg / "a.py")

    rc, out = _run_verify_self(monkeypatch, capsys, pkg)

    assert rc == 1
    assert "INTEGRITY CANNOT BE ESTABLISHED" in out
    assert "a.py" in out
    assert "Permission denied" in out
    assert "unexpected internal error" not in out
    # It still prints a digest and the cosign guidance — the command did not abort.
    assert "combined :" in out
    assert "cosign verify-blob" in out


def test_release_listing_annotates_symlink_rows_like_the_cli(tmp_path, monkeypatch):
    """The cosign-signed SHA256SUMS.txt is a second listing of the same map.

    ``.github/workflows/clawhub-publish.yml`` promises the published file is "byte-for-byte
    the same computation" as ``--verify-self``. Once a symlink's row became a digest of the
    LINK rather than of any file's bytes, an unannotated row in that listing would be a
    false statement inside a *signed* artifact — and the two listings would have silently
    stopped matching, which is the claim the workflow's own comment makes. Nothing enforced
    it, so this derives the workflow's generator from the YAML and runs it, rather than
    trusting that someone kept a fourth copy in sync (same reasoning as
    ``test_cli_verify_self_cosign_command_matches_published_docs``).
    """
    import textwrap

    wf = (REPO / ".github" / "workflows" / "clawhub-publish.yml").read_text(encoding="utf-8")
    block = wf.split("python3 - <<'PYEOF'\n")[1].split("          PYEOF")[0]
    generator = compile(textwrap.dedent(block), "clawhub-publish.yml", "exec")

    pkg = _pkg(tmp_path)
    out = _outside(tmp_path)
    os.symlink(out / "evil.py", pkg / "extra_link.py")
    monkeypatch.setattr("clawseccheck.integrity._PKG_DIR", pkg)
    monkeypatch.chdir(tmp_path)

    exec(generator, {"__name__": "__main__"})
    published = (tmp_path / "SHA256SUMS.txt").read_text(encoding="utf-8")

    row = next(ln for ln in published.splitlines() if "extra_link.py" in ln)
    assert "symlink -> " in row
    assert "target contents NOT read" in row
    # The digest in the published row is the link digest, and it is the same one the
    # per-file map carries — the two listings are the same map, annotated the same way.
    _combined, per_file = package_digest(pkg_dir=pkg)
    assert per_file["extra_link.py"] in row


# ---------------------------------------------------------------------------
# Round 2 of the adversarial pass: the first fix covered only half of each claim
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["__pycache__", ".ruff_cache", ".git"])
@pytest.mark.parametrize("kind", ["file", "dangling"])
def test_an_excluded_name_symlinked_to_a_non_directory_is_still_covered(tmp_path, name, kind):
    """``os.walk`` classifies a symlink by what it RESOLVES to, not by its name.

    A link named ``__pycache__`` pointing at a *file* — or at nothing — lands in
    ``filenames``, so it reaches ``skips`` rather than ``prune_dir``, and the first fix
    filtered those by ``_NON_SOURCE_DIRS`` name. That filter could only ever drop an entry
    whose own name IS an excluded dir, which is exactly the attack it was meant to catch:
    round 1 closed the resolves-to-a-directory case and the docstring then claimed the
    whole thing was covered. Round 2 caught the claim.
    """
    pkg = _pkg(tmp_path)
    payload = tmp_path / "evil.pyc"
    payload.write_bytes(b"\x00pwned")
    target = payload if kind == "file" else tmp_path / "nonexistent"
    before, _ = package_digest(pkg_dir=pkg)

    os.symlink(target, pkg / name)
    notes: list = []
    after, _per_file = package_digest(pkg_dir=pkg, notes=notes)

    assert after != before
    assert notes == [(NOTE_SYMLINK, name, str(target))]


def test_a_clean_run_still_says_the_digest_is_comparable(tmp_path, monkeypatch, capsys):
    """The other half of the footer branch — the ordinary case must be unchanged."""
    monkeypatch.setattr("clawseccheck.integrity._PKG_DIR", _pkg(tmp_path))
    main(["--verify-self"])
    out = capsys.readouterr().out
    assert "Any mismatch means a source file was modified" in out
    assert "NOT comparable" not in out


@pytest.mark.parametrize("exc,marker", [
    (lambda: FileNotFoundError(errno.ENOENT, "No such file or directory"),
     "disappeared while the scan was running"),
    (lambda: PermissionError(errno.EACCES, "Permission denied"),
     "INTEGRITY CANNOT BE ESTABLISHED"),
])
def test_an_incomplete_digest_is_not_advertised_as_comparable(
        tmp_path, monkeypatch, capsys, exc, marker):
    """Two sentences on one screen told the reader opposite things.

    The footer asserted "Any mismatch means a source file was modified after that release"
    five lines under a block stating the digest covers less than the tree it names.
    Whichever the reader believed, one of them was wrong — and the damaging direction is
    believing the footer, which turns a scan that raced an ordinary `git pull` into
    evidence of tampering.
    """
    pkg = _pkg(tmp_path)
    _raise_on_read(monkeypatch, pkg / "a.py", exc())
    monkeypatch.setattr("clawseccheck.integrity._PKG_DIR", pkg)

    main(["--verify-self"])
    out = capsys.readouterr().out

    assert marker in out
    assert "NOT comparable against a trusted release digest" in out
    assert "Any mismatch means a source file was modified" not in out
