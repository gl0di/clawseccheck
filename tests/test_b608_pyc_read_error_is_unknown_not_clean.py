"""B-608 follow-up — the UNKNOWN path of the unchecked-hash .pyc scan.

``tests/test_b608_unchecked_pyc_disclosure.py`` and ``tests/test_b608_cli_disclosure.py``
already cover the main fix end to end (a planted PEP 552 unchecked-hash ``.pyc`` inside a
real ``__pycache__`` is disclosed via ``NOTE_UNCHECKED_PYC`` without moving ``combined``,
and a battery of ordinary/benign shapes stays silent). This file adds the one path the
brief calls out as missing: a ``.pyc`` whose header ``integrity._pyc_header_flags`` cannot
even read.

That is a genuine "check cannot determine state" case (Golden Rule #4), and it is
DIFFERENT from the already-covered "file too short to hold a header" case: a truncated
file is provably inert (Python's own loader needs a full header before it will run
anything), so silence there is a proven-safe classification, not a shrug. An ``OSError``
carries no such proof.

**Confirmed reproduction (independent of source review), the mechanism, and the current
answer are all pinned here:**

* Mechanism: ``_pyc_header_flags`` returns ``None`` on ``OSError`` exactly the same way
  it does for a too-short file (see the ``except OSError: return None`` branch), and
  ``_scan_for_unchecked_hash_pycs`` only ever records a name when the flags value equals
  ``0b01`` — ``None`` never matches, so an unreadable ``.pyc`` produces no entry, no note,
  and no digest movement. A quick manual check on this tree confirmed it:
  ``_pyc_header_flags`` on a chmod-000 unchecked-hash pyc returns ``None``, and
  ``package_digest(..., notes=[])`` for that tree returns ``notes == []``.
* Current, deliberate answer: **stays silent**, pinned below, for a narrower reason than
  "best effort" alone — see ``_pyc_header_flags``'s docstring in
  ``clawseccheck/integrity.py``. On this single-user local CLI, a ``.pyc`` this process
  cannot open is also a ``.pyc`` the same-user ``import`` cannot open to execute, so an
  unreadable planted file cannot achieve the "runs without the audit seeing it" outcome
  B-608 is about — UNLESS the auditor and the process that later imports the package run
  under different privileges, which this tool does not assume.
* **Escalation this file leaves open, not silently closed:** surfacing this branch as its
  own disclosure (distinct wording from a *confirmed* unchecked-hash pyc) would need a new
  note kind, and ``clawseccheck/cli.py``'s ``verify_self`` block hardcodes which note kinds
  it extracts and matches ``NOTE_UNCHECKED_PYC`` specifically to "contains a PEP 552
  unchecked-hash .pyc" wording — an unread file is not a found one, so folding this into
  that kind would overclaim. ``cli.py`` is out of this task's file ownership; the design
  decision (new note kind + cli wording, or accept the residual as documented) is left to
  the maintainer rather than guessed at here.

Offline, read-only, stdlib only. Every ``.pyc`` is written by this test process into
pytest's ``tmp_path``, and permission injection uses a monkeypatch (deterministic under
any uid, including root/CI) with a real-filesystem ``chmod`` control guarded the same way
``tests/test_b590_verify_self_coverage.py`` guards its own ``_ROOT_SKIP`` cases.
"""
from __future__ import annotations

import os
import pathlib
import py_compile
from pathlib import Path

import pytest

from clawseccheck.integrity import (
    NOTE_UNCHECKED_PYC,
    _pyc_header_flags,
    package_digest,
)

_ROOT_SKIP = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores the read bit"
)


def _pkg(tmp_path: Path) -> Path:
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "m.py").write_text("FLAG = 'benign'\n", encoding="utf-8")
    return pkg


def _deny_open(monkeypatch, target: Path):
    """Make exactly one path raise PermissionError from Path.open(), whatever the uid.

    Mirrors ``test_b590_verify_self_coverage.py``'s ``_deny_read`` helper, but patches
    ``Path.open`` because ``_pyc_header_flags`` reads via ``path.open("rb")``, not
    ``read_bytes()``.
    """
    real_open = pathlib.Path.open

    def fake_open(self, *args, **kwargs):
        if self == target:
            raise PermissionError(13, "Permission denied", str(target))
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(pathlib.Path, "open", fake_open)


# ---------------------------------------------------------------------------
# Deliverable pairing: clean fixture + bad fixture, both asserted in one place.
# ---------------------------------------------------------------------------

def test_clean_fixture_ordinary_pycache_stays_clean(tmp_path):
    """Control for the false-positive direction: nothing planted, nothing reported."""
    pkg = _pkg(tmp_path)
    cache = pkg / "__pycache__"
    cache.mkdir()
    py_compile.compile(str(pkg / "m.py"), cfile=str(cache / "m.cpython-312.pyc"), doraise=True)

    baseline, _ = package_digest(pkg_dir=pkg)
    notes: list = []
    combined, per_file = package_digest(pkg_dir=pkg, notes=notes)

    assert notes == []
    assert combined == baseline
    assert not any("__pycache__" in k for k in per_file)


def test_bad_fixture_planted_unchecked_hash_pyc_is_disclosed(tmp_path):
    """The malicious case, reproduced independently of the existing B-608 test files."""
    pkg = _pkg(tmp_path)
    clean_combined, _ = package_digest(pkg_dir=pkg)

    cache = pkg / "__pycache__"
    cache.mkdir()
    py_compile.compile(
        str(pkg / "m.py"),
        cfile=str(cache / "m.cpython-312.pyc"),
        doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )

    notes: list = []
    combined, per_file = package_digest(pkg_dir=pkg, notes=notes)

    assert combined == clean_combined, "presence-only: must not move the digest"
    assert not any("__pycache__" in k for k in per_file)
    assert notes == [
        (NOTE_UNCHECKED_PYC, "__pycache__", "1 unchecked-hash .pyc: m.cpython-312.pyc")
    ]


# ---------------------------------------------------------------------------
# The UNKNOWN path: the check genuinely cannot read the header.
# ---------------------------------------------------------------------------

def test_pyc_header_flags_returns_none_when_the_file_cannot_be_opened(tmp_path, monkeypatch):
    """Isolates the exact mechanism: OSError -> None, indistinguishable from "too short"."""
    pkg = _pkg(tmp_path)
    cache = pkg / "__pycache__"
    cache.mkdir()
    target = cache / "m.cpython-312.pyc"
    py_compile.compile(
        str(pkg / "m.py"), cfile=str(target), doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )
    _deny_open(monkeypatch, target)

    assert _pyc_header_flags(target) is None


def test_unreadable_unchecked_hash_pyc_produces_no_note_documented_unknown(tmp_path, monkeypatch):
    """The genuinely-unknown case stays silent — pinned as a deliberate, documented limit.

    This is NOT the same claim as "confirmed timestamp-based" or "confirmed checked-hash":
    those two are proven benign. This one is unproven either way, and the check still says
    nothing about it — the residual `_pyc_header_flags`'s docstring names explicitly.
    """
    pkg = _pkg(tmp_path)
    cache = pkg / "__pycache__"
    cache.mkdir()
    target = cache / "m.cpython-312.pyc"
    py_compile.compile(
        str(pkg / "m.py"), cfile=str(target), doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )
    _deny_open(monkeypatch, target)

    notes: list = []
    combined, per_file = package_digest(pkg_dir=pkg, notes=notes)

    assert notes == [], "documented residual: an unreadable pyc is not disclosed"
    assert not any("__pycache__" in k for k in per_file)
    # And package_digest must not crash or raise for this file just because a sibling
    # helper (_pyc_header_flags) hit an OSError — the digest walk itself never touches
    # __pycache__ contents, so this OSError is fully contained to the peek.
    assert isinstance(combined, str) and len(combined) == 64


def test_unreadable_pyc_does_not_suppress_a_readable_sibling_in_the_same_cache(
        tmp_path, monkeypatch):
    """One unclassifiable file must not blind the scan to a confirmed sibling."""
    pkg = _pkg(tmp_path)
    (pkg / "n.py").write_text("Y = 1\n", encoding="utf-8")
    cache = pkg / "__pycache__"
    cache.mkdir()
    blocked = cache / "m.cpython-312.pyc"
    readable = cache / "n.cpython-312.pyc"
    py_compile.compile(
        str(pkg / "m.py"), cfile=str(blocked), doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )
    py_compile.compile(
        str(pkg / "n.py"), cfile=str(readable), doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )
    _deny_open(monkeypatch, blocked)

    notes: list = []
    package_digest(pkg_dir=pkg, notes=notes)

    assert notes == [
        (NOTE_UNCHECKED_PYC, "__pycache__", "1 unchecked-hash .pyc: n.cpython-312.pyc")
    ]


@_ROOT_SKIP
def test_unreadable_pyc_on_a_real_filesystem(tmp_path):
    """Same behaviour reached through real mode bits rather than an injection."""
    pkg = _pkg(tmp_path)
    cache = pkg / "__pycache__"
    cache.mkdir()
    target = cache / "m.cpython-312.pyc"
    py_compile.compile(
        str(pkg / "m.py"), cfile=str(target), doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )
    target.chmod(0o000)
    try:
        assert _pyc_header_flags(target) is None
        notes: list = []
        package_digest(pkg_dir=pkg, notes=notes)
        assert notes == []
    finally:
        target.chmod(0o644)
