"""B-608 — disclose a PEP 552 *unchecked-hash* ``.pyc`` planted inside a real
``__pycache__``, without folding its bytes into ``combined``.

Context (see ``integrity.package_digest``'s docstring and CLAWSECCHECK-B-608): a real
``__pycache__`` is pruned from the digest walk by content (B-069 — ``.pyc`` bytes and
cache filenames vary by interpreter/tool version, so hashing them would make
``--verify-self`` environment-dependent). That is correct, but it also meant a file
*planted* inside a genuine ``__pycache__`` was completely invisible — including a PEP 552
unchecked-hash ``.pyc``, which Python imports WITHOUT validating against the ``.py`` it
claims to come from, i.e. arbitrary code execution with a byte-identical source tree and
an unchanged digest.

This file has two halves, matching the task's C-135 brief:

* the malicious case — a genuine unchecked-hash pyc (produced by
  ``py_compile.compile(..., invalidation_mode=UNCHECKED_HASH)``, PEP 552's own opt-in
  mechanism) must be disclosed via ``notes`` as ``NOTE_UNCHECKED_PYC``, and must NOT move
  ``combined``;
* the innocent controls — every shape an ORDINARY dev checkout, CI run, or stale/orphaned
  artifact produces must stay silent. This is the reproducibility-at-risk direction: a
  false positive here would fire on ordinary Python usage, not on an attack.

Offline, read-only, stdlib only; every ``.pyc`` written by this file lives under
pytest's ``tmp_path`` and is written by this test process itself (py_compile /
``import``), never copied in from anywhere else.
"""
from __future__ import annotations

import importlib
import os
import py_compile
import sys
from pathlib import Path

import pytest

from clawseccheck.integrity import (
    NOTE_SYMLINK,
    NOTE_UNCHECKED_PYC,
    package_digest,
)


def _pkg(tmp_path: Path) -> Path:
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "m.py").write_text("FLAG = 'benign'\n", encoding="utf-8")
    return pkg


# ---------------------------------------------------------------------------
# The malicious case
# ---------------------------------------------------------------------------

def test_planted_unchecked_hash_pyc_is_disclosed_and_never_moves_the_digest(tmp_path):
    pkg = _pkg(tmp_path)
    baseline, _ = package_digest(pkg_dir=pkg)

    cache = pkg / "__pycache__"
    cache.mkdir()
    py_compile.compile(
        str(pkg / "m.py"),
        cfile=str(cache / "m.cpython-312.pyc"),
        doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )

    # Opt out of the notes channel: the planted pyc must still leave `combined` and
    # `per_file` exactly as before — that is the B-069 guarantee this fix must not break.
    after_no_notes, per_file_no_notes = package_digest(pkg_dir=pkg)
    assert after_no_notes == baseline
    assert not any("__pycache__" in k for k in per_file_no_notes)

    # Opt in: the same tree now discloses the plant.
    notes: list = []
    after, per_file = package_digest(pkg_dir=pkg, notes=notes)
    assert after == baseline, "disclosure must not cost reproducibility"
    assert not any("__pycache__" in k for k in per_file), "must never enter per_file"
    assert notes == [
        (NOTE_UNCHECKED_PYC, "__pycache__", "1 unchecked-hash .pyc: m.cpython-312.pyc")
    ]


def test_nested_subpackage_pycache_is_also_covered(tmp_path):
    """The scan runs wherever `_observe_dir` sees a real `__pycache__`, not just top-level."""
    pkg = _pkg(tmp_path)
    (pkg / "sub").mkdir()
    (pkg / "sub" / "n.py").write_text("Y = 1\n", encoding="utf-8")
    cache = pkg / "sub" / "__pycache__"
    cache.mkdir()
    py_compile.compile(
        str(pkg / "sub" / "n.py"),
        cfile=str(cache / "n.cpython-312.pyc"),
        doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )

    notes: list = []
    package_digest(pkg_dir=pkg, notes=notes)
    assert notes == [
        (NOTE_UNCHECKED_PYC, "sub/__pycache__", "1 unchecked-hash .pyc: n.cpython-312.pyc")
    ]


def test_multiple_unchecked_pycs_are_all_named_and_counted(tmp_path):
    pkg = _pkg(tmp_path)
    (pkg / "n.py").write_text("Y = 1\n", encoding="utf-8")
    cache = pkg / "__pycache__"
    cache.mkdir()
    for src, name in [("m.py", "m.cpython-312.pyc"), ("n.py", "n.cpython-312.pyc")]:
        py_compile.compile(
            str(pkg / src), cfile=str(cache / name), doraise=True,
            invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
        )

    notes: list = []
    package_digest(pkg_dir=pkg, notes=notes)
    assert len(notes) == 1
    kind, rel, detail = notes[0]
    assert (kind, rel) == (NOTE_UNCHECKED_PYC, "__pycache__")
    assert detail.startswith("2 unchecked-hash .pyc: ")
    assert "m.cpython-312.pyc" in detail and "n.cpython-312.pyc" in detail


def test_symlinked_pycache_is_reported_as_symlink_not_double_counted(tmp_path):
    """A symlinked `__pycache__` is `_observe_dir`'s symlink branch (B-590), never this scan.

    The two channels must not double-report the same directory, and reading through the
    link to classify its contents would violate "never follow a symlink to content".
    """
    pkg = _pkg(tmp_path)
    real_cache = tmp_path / "attacker_cache"
    real_cache.mkdir()
    py_compile.compile(
        str(pkg / "m.py"), cfile=str(real_cache / "m.cpython-312.pyc"), doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )
    os.symlink(real_cache, pkg / "__pycache__")

    notes: list = []
    package_digest(pkg_dir=pkg, notes=notes)
    assert notes == [(NOTE_SYMLINK, "__pycache__", str(real_cache))]


def test_symlinked_pyc_file_inside_a_real_pycache_is_not_flagged(tmp_path):
    """Documents the current, narrower scope: only real files are classified.

    A `.pyc` that is itself a symlink is excluded by `is_file(follow_symlinks=False)`,
    so it stays part of the pre-existing "symlink inside an excluded dir" residual
    (see test_b590's `test_symlink_inside_an_excluded_dir_is_the_documented_residual`),
    not something this task closes. This test pins that it is silently skipped rather
    than crashing or being misclassified.
    """
    pkg = _pkg(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    py_compile.compile(
        str(pkg / "m.py"), cfile=str(outside / "evil.pyc"), doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )
    cache = pkg / "__pycache__"
    cache.mkdir()
    os.symlink(outside / "evil.pyc", cache / "m.cpython-312.pyc")

    notes: list = []
    package_digest(pkg_dir=pkg, notes=notes)
    assert notes == []


# ---------------------------------------------------------------------------
# Innocent-case controls — must ALL stay silent (the false-positive direction)
# ---------------------------------------------------------------------------

def test_ordinary_default_pyc_produces_no_note(tmp_path):
    """The overwhelmingly common case: `py_compile.compile()` with no invalidation_mode."""
    pkg = _pkg(tmp_path)
    cache = pkg / "__pycache__"
    cache.mkdir()
    py_compile.compile(str(pkg / "m.py"), cfile=str(cache / "m.cpython-312.pyc"), doraise=True)

    notes: list = []
    package_digest(pkg_dir=pkg, notes=notes)
    assert notes == []


def test_pyc_from_real_import_machinery_produces_no_note(tmp_path, monkeypatch):
    """What every ordinary `import` leaves behind — no explicit compile step at all."""
    pkg = tmp_path / "pkg2"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "mod.py").write_text("X = 1\n", encoding="utf-8")

    monkeypatch.syspath_prepend(str(tmp_path))
    importlib.import_module("pkg2.mod")
    try:
        notes: list = []
        package_digest(pkg_dir=pkg, notes=notes)
        assert notes == []
    finally:
        sys.modules.pop("pkg2.mod", None)
        sys.modules.pop("pkg2", None)


def test_stale_pyc_after_source_edit_produces_no_note(tmp_path):
    """A `.pyc` whose source was legitimately edited afterwards is not an attack."""
    pkg = _pkg(tmp_path)
    cache = pkg / "__pycache__"
    cache.mkdir()
    py_compile.compile(str(pkg / "m.py"), cfile=str(cache / "m.cpython-312.pyc"), doraise=True)
    (pkg / "m.py").write_text("FLAG = 'edited-after-compile'\n", encoding="utf-8")

    notes: list = []
    package_digest(pkg_dir=pkg, notes=notes)
    assert notes == []


def test_orphaned_pyc_with_deleted_source_produces_no_note(tmp_path):
    """A `.pyc` left behind after its `.py` was removed/renamed — common after a refactor."""
    pkg = _pkg(tmp_path)
    cache = pkg / "__pycache__"
    cache.mkdir()
    py_compile.compile(str(pkg / "m.py"), cfile=str(cache / "old.cpython-312.pyc"), doraise=True)
    (pkg / "m.py").unlink()
    (pkg / "keep.py").write_text("KEEP = 1\n", encoding="utf-8")

    notes: list = []
    package_digest(pkg_dir=pkg, notes=notes)
    assert notes == []


def test_checked_hash_pyc_produces_no_note(tmp_path):
    """Hash-based BUT checked (PEP 552 flags 0b11): Python verifies it against source

    before using it, so it is not the "trust without check" surface this note exists for.
    """
    pkg = _pkg(tmp_path)
    cache = pkg / "__pycache__"
    cache.mkdir()
    py_compile.compile(
        str(pkg / "m.py"), cfile=str(cache / "m.cpython-312.pyc"), doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH,
    )

    notes: list = []
    package_digest(pkg_dir=pkg, notes=notes)
    assert notes == []


def test_truncated_or_garbage_pyc_bytes_produce_no_note(tmp_path):
    """A half-written / corrupted `.pyc` is not classifiable — must not be guessed at."""
    pkg = _pkg(tmp_path)
    cache = pkg / "__pycache__"
    cache.mkdir()
    (cache / "m.cpython-312.pyc").write_bytes(b"\x00\x01")  # shorter than an 8-byte header

    notes: list = []
    package_digest(pkg_dir=pkg, notes=notes)
    assert notes == []


def test_multiple_ordinary_pycs_from_different_named_caches_produce_no_note(tmp_path):
    """Several ordinary pyc filenames in one cache dir (as if compiled by >1 interpreter)."""
    pkg = _pkg(tmp_path)
    cache = pkg / "__pycache__"
    cache.mkdir()
    py_compile.compile(str(pkg / "m.py"), cfile=str(cache / "m.cpython-39.pyc"), doraise=True)
    py_compile.compile(str(pkg / "m.py"), cfile=str(cache / "m.cpython-312.pyc"), doraise=True)

    notes: list = []
    package_digest(pkg_dir=pkg, notes=notes)
    assert notes == []


def test_non_pyc_files_in_pycache_are_ignored(tmp_path):
    """Only `*.pyc` entries are classified; anything else in the dir is out of scope here."""
    pkg = _pkg(tmp_path)
    cache = pkg / "__pycache__"
    cache.mkdir()
    (cache / "README").write_text("not a pyc\n", encoding="utf-8")

    notes: list = []
    package_digest(pkg_dir=pkg, notes=notes)
    assert notes == []


@pytest.mark.parametrize("name", [".ruff_cache", ".mypy_cache", ".pytest_cache", ".git"])
def test_only_pycache_is_scanned_not_the_other_excluded_dirs(tmp_path, name):
    """The B-608 scan is scoped to `__pycache__` specifically — the PEP 552 import surface.

    A file named like an unchecked-hash pyc dropped in a sibling excluded dir (e.g.
    `.ruff_cache/x.pyc`) is not on Python's import path search shape and stays part of
    the pre-existing, unrelated residual — it must not produce a note either way.
    """
    pkg = _pkg(tmp_path)
    other = pkg / name
    other.mkdir()
    py_compile.compile(
        str(pkg / "m.py"), cfile=str(other / "m.cpython-312.pyc"), doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )

    notes: list = []
    package_digest(pkg_dir=pkg, notes=notes)
    assert notes == []
