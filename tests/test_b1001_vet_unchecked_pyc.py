"""B-1001 / B398 - `--vet-skill` must look inside `__pycache__` for PEP 552 unchecked-hash pycs.

The skill walk prunes `__pycache__`, so a skill with clean `.py` sources plus a
`.pyc` whose header flags == 0b01 (imported by Python WITHOUT checking it against the
source) used to get INSTALL with "no dormant or staged code detected". Every `.pyc` here
is built at test time under tmp_path via py_compile; nothing binary is committed and the
payload is benign (it is never imported or executed by these tests).
"""
from __future__ import annotations

import os
import py_compile
from pathlib import Path

import pytest

from clawseccheck import collector
from clawseccheck.catalog import FAIL, PASS, UNKNOWN
from clawseccheck.checks import check_unchecked_hash_pyc
from clawseccheck.cli import main
from clawseccheck.collector import Context, collect_skill_files

UNCHECKED = py_compile.PycInvalidationMode.UNCHECKED_HASH
CHECKED = py_compile.PycInvalidationMode.CHECKED_HASH
TIMESTAMP = py_compile.PycInvalidationMode.TIMESTAMP


def _skill(tmp_path: Path) -> Path:
    sk = tmp_path / "sk"
    sk.mkdir()
    (sk / "SKILL.md").write_text(
        "---\nname: sk\ndescription: demo skill\n---\n# sk\n", encoding="utf-8")
    (sk / "output.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    return sk


def _pyc(sk: Path, mode, name="output.cpython-314.pyc") -> Path:
    src = sk.parent / "payload_src.py"
    src.write_text("import os\nos.system('echo x')\n", encoding="utf-8")
    cache = sk / "__pycache__"
    cache.mkdir(exist_ok=True)
    out = cache / name
    py_compile.compile(str(src), cfile=str(out), invalidation_mode=mode, doraise=True)
    return out


def _run_check(sk: Path):
    ctx = Context(home=sk.parent)
    ctx.installed_skills[sk.name] = "x"
    collect_skill_files(sk, ctx)
    return check_unchecked_hash_pyc(ctx)


def _dossier(sk: Path, capsys) -> str:
    main(["--vet-skill", str(sk)])
    return capsys.readouterr().out


def _assert_flagged(sk: Path, capsys):
    out = _dossier(sk, capsys)
    assert out.splitlines()[0].rstrip().endswith("DO-NOT-INSTALL")
    persistence = [ln for ln in out.splitlines() if ln.strip().startswith("Persistence")]
    assert persistence and "PASS" not in persistence[0]
    assert "no dormant or staged code detected" not in out


def test_clean_skill_without_pycache_passes(tmp_path):
    assert _run_check(_skill(tmp_path)).status == PASS


@pytest.mark.parametrize("mode", [TIMESTAMP, CHECKED])
def test_ordinary_pyc_is_silent(tmp_path, mode):
    sk = _skill(tmp_path)
    _pyc(sk, mode)
    assert _run_check(sk).status == PASS


def test_unchecked_hash_pyc_fails_in_check_and_dossier(tmp_path, capsys):
    sk = _skill(tmp_path)
    out = _pyc(sk, UNCHECKED)
    assert int.from_bytes(out.read_bytes()[4:8], "little") == 1  # the fixture is what it claims
    f = _run_check(sk)
    assert f.status == FAIL
    assert "__pycache__/output.cpython-314.pyc" in f.detail
    assert "delete" in f.fix.lower()
    _assert_flagged(sk, capsys)


def test_unchecked_pyc_in_nested_package_is_found(tmp_path):
    sk = _skill(tmp_path)
    nested = sk / "pkg" / "sub"
    nested.mkdir(parents=True)
    _pyc(nested.parent.parent, UNCHECKED)  # creates sk/__pycache__ ...
    os.rename(sk / "__pycache__", nested / "__pycache__")
    f = _run_check(sk)
    assert f.status == FAIL and "pkg/sub/__pycache__" in f.detail


def test_symlinked_pycache_is_unknown_not_pass(tmp_path):
    sk = _skill(tmp_path)
    real = tmp_path / "elsewhere"
    real.mkdir()
    py_compile.compile(str(sk / "output.py"), cfile=str(real / "output.cpython-314.pyc"),
                       invalidation_mode=UNCHECKED, doraise=True)
    os.symlink(real, sk / "__pycache__")
    f = _run_check(sk)
    assert f.status == UNKNOWN and "symlinked __pycache__" in f.detail


def test_symlinked_pyc_is_unknown_not_pass(tmp_path):
    sk = _skill(tmp_path)
    target = _pyc(sk, UNCHECKED, "real.cpython-314.pyc")
    os.symlink(target, target.parent / "output.cpython-314.pyc")
    target.unlink()  # leave only the symlink (dangling); it must still not read as clean
    f = _run_check(sk)
    assert f.status == UNKNOWN and "symlinked .pyc" in f.detail


def test_truncated_pyc_is_inert_and_silent(tmp_path):
    sk = _skill(tmp_path)
    (sk / "__pycache__").mkdir()
    (sk / "__pycache__" / "output.cpython-314.pyc").write_bytes(b"\x00\x00\x00")
    assert _run_check(sk).status == PASS


def test_unreadable_pyc_is_unknown(tmp_path, monkeypatch):
    sk = _skill(tmp_path)
    out = _pyc(sk, UNCHECKED)
    real_open = Path.open

    def fake_open(self, *a, **kw):
        if self == out:
            raise PermissionError(13, "denied")
        return real_open(self, *a, **kw)

    monkeypatch.setattr(Path, "open", fake_open)
    f = _run_check(sk)
    assert f.status == UNKNOWN and "could not be read" in f.detail


def test_bare_sourceless_unchecked_pyc_is_found(tmp_path):
    sk = _skill(tmp_path)
    out = _pyc(sk, UNCHECKED)
    os.rename(out, sk / "legacy.pyc")
    assert _run_check(sk).status == FAIL


def test_mutation_without_the_pyc_scan_the_dossier_is_install(tmp_path, monkeypatch, capsys):
    """Reverting the collector fix must make the end-to-end assertion fail."""
    sk = _skill(tmp_path)
    _pyc(sk, UNCHECKED)
    monkeypatch.setattr(collector, "_scan_skill_pycs", lambda base_dir, ctx: None)
    with pytest.raises(AssertionError):
        _assert_flagged(sk, capsys)
