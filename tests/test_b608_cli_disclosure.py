"""B-608 (CLI wiring) — `--verify-self` must render the unchecked-hash .pyc disclosure.

`integrity.package_digest()` reports `NOTE_UNCHECKED_PYC` through its opt-in `notes`
channel, and `cli.py`'s `verify_self` branch already opts in
(`package_digest(notes=_notes)`, B-590) — but until this change nothing extracted
`NOTE_UNCHECKED_PYC` from `_notes` or printed it, so a real `--verify-self` run over a
package with a planted unchecked-hash `.pyc` produced output identical to a clean tree:
the detection worked, but the payload never reached the user. This file proves it now
does, end to end through `cli.main` — not just through `package_digest` in isolation,
which `tests/test_b608_unchecked_pyc_disclosure.py` already covers.

Non-vacuity: the malicious case and a clean-copy control run in the same style as
`tests/test_b590_verify_self_coverage.py`'s CLI section, and a clean-tree assertion runs
in the same file so a broken predicate that matches nothing cannot pass silently.

Offline, read-only, stdlib only; every `.pyc` here is written by this test process into
pytest's `tmp_path`, never copied in from anywhere else. No `Path.home()` — `_PKG_DIR` is
monkeypatched to a tmp package, the same technique `test_b590_verify_self_coverage.py`
already uses.
"""
from __future__ import annotations

import py_compile
from pathlib import Path

from clawseccheck.cli import main


def _pkg(tmp_path: Path) -> Path:
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "m.py").write_text("FLAG = 'benign'\n", encoding="utf-8")
    return pkg


def _run_verify_self(monkeypatch, capsys, pkg: Path):
    monkeypatch.setattr("clawseccheck.integrity._PKG_DIR", pkg)
    rc = main(["--verify-self"])
    return rc, capsys.readouterr().out


def test_cli_discloses_a_planted_unchecked_hash_pyc_and_exits_zero(
        tmp_path, monkeypatch, capsys):
    pkg = _pkg(tmp_path)
    cache = pkg / "__pycache__"
    cache.mkdir()
    py_compile.compile(
        str(pkg / "m.py"),
        cfile=str(cache / "m.cpython-312.pyc"),
        doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )

    rc, out = _run_verify_self(monkeypatch, capsys, pkg)

    assert rc == 0, "a disclosure, not a verdict — must not fail the command"
    assert "unchecked-hash .pyc" in out
    assert "__pycache__" in out
    assert "m.cpython-312.pyc" in out
    assert "Coverage note" in out
    # No absolute path from this machine may reach a rendered surface.
    assert str(tmp_path) not in out


def test_cli_clean_tree_prints_no_pyc_disclosure(tmp_path, monkeypatch, capsys):
    """Same run shape, nothing planted — proves the block above isn't a fixed string."""
    rc, out = _run_verify_self(monkeypatch, capsys, _pkg(tmp_path))

    assert rc == 0
    assert "unchecked-hash .pyc" not in out
    assert "Coverage note" not in out


def test_cli_ordinary_pyc_from_a_normal_compile_is_not_flagged(tmp_path, monkeypatch, capsys):
    """An everyday timestamp-based .pyc (what a normal build/test run leaves) stays silent."""
    pkg = _pkg(tmp_path)
    cache = pkg / "__pycache__"
    cache.mkdir()
    py_compile.compile(str(pkg / "m.py"), cfile=str(cache / "m.cpython-312.pyc"), doraise=True)

    rc, out = _run_verify_self(monkeypatch, capsys, pkg)

    assert rc == 0
    assert "unchecked-hash .pyc" not in out


def test_cli_disclosure_does_not_change_the_combined_digest(tmp_path, monkeypatch, capsys):
    """B-608's whole point: presence-only. The digest must be identical either way."""
    pkg = _pkg(tmp_path)
    _rc, clean_out = _run_verify_self(monkeypatch, capsys, pkg)
    clean_combined = next(ln for ln in clean_out.splitlines() if ln.startswith("combined :"))

    cache = pkg / "__pycache__"
    cache.mkdir()
    py_compile.compile(
        str(pkg / "m.py"), cfile=str(cache / "m.cpython-312.pyc"), doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )
    rc, planted_out = _run_verify_self(monkeypatch, capsys, pkg)
    planted_combined = next(ln for ln in planted_out.splitlines() if ln.startswith("combined :"))

    assert rc == 0
    assert planted_combined == clean_combined
    assert "unchecked-hash .pyc" in planted_out
