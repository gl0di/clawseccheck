"""B-1001 / B398 - `--vet-skill` must look inside `__pycache__` for PEP 552 unchecked-hash pycs.

The skill walk prunes `__pycache__`, so a skill with clean `.py` sources plus a
`.pyc` whose header flags == 0b01 (imported by Python WITHOUT checking it against the
source) used to get INSTALL with "no dormant or staged code detected". Every `.pyc` here
is built at test time under tmp_path via py_compile; nothing binary is committed and the
payload is benign (it is never imported or executed by these tests).
"""
from __future__ import annotations

import io
import os
import py_compile
import zipfile
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


# ---- C-135 round 1 follow-ups -------------------------------------------------------

def _assert_gap_floors_dossier(sk: Path, capsys):
    """A coverage gap must reach the dossier: never INSTALL, never the affirmative PASS text."""
    out = _dossier(sk, capsys)
    head = out.splitlines()[0]
    assert "CAUTION" in head, head
    persistence = [ln for ln in out.splitlines() if ln.strip().startswith("Persistence")]
    assert persistence and "PASS" not in persistence[0]
    assert "no dormant or staged code detected" not in out
    return out


def test_pyc_count_cap_floors_the_dossier(tmp_path, monkeypatch, capsys):
    sk = _skill(tmp_path)
    _pyc(sk, UNCHECKED, "zz.cpython-314.pyc")
    for i in range(5):
        _pyc(sk, TIMESTAMP, f"pad{i}.cpython-314.pyc")
    monkeypatch.setattr(collector, "_PYC_SCAN_MAX_PYCS", 3)
    _assert_gap_floors_dossier(sk, capsys)


def test_dir_count_cap_floors_the_dossier(tmp_path, monkeypatch, capsys):
    sk = _skill(tmp_path)
    for i in range(6):
        (sk / f"d{i}").mkdir()
    monkeypatch.setattr(collector, "_PYC_SCAN_MAX_DIRS", 3)
    out = _assert_gap_floors_dossier(sk, capsys)
    assert "directory count cap" in out


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory modes")
def test_unreadable_pycache_floors_the_dossier(tmp_path, capsys):
    sk = _skill(tmp_path)
    _pyc(sk, UNCHECKED)
    cache = sk / "__pycache__"
    cache.chmod(0)
    try:
        _assert_gap_floors_dossier(sk, capsys)
    finally:
        cache.chmod(0o755)


def test_symlinked_pycache_floors_the_dossier(tmp_path, capsys):
    sk = _skill(tmp_path)
    real = tmp_path / "elsewhere"
    real.mkdir()
    os.symlink(real, sk / "__pycache__")
    _assert_gap_floors_dossier(sk, capsys)


def test_hit_and_gap_together_keep_both(tmp_path, monkeypatch):
    sk = _skill(tmp_path)
    _pyc(sk, UNCHECKED, "a.cpython-314.pyc")
    os.symlink(tmp_path, sk / "sub_link_dir")  # not a __pycache__: ignored
    other = sk / "pkg"
    other.mkdir()
    os.symlink(tmp_path, other / "__pycache__")
    f = _run_check(sk)
    assert f.status == FAIL
    assert any(e.startswith("not inspected:") and "symlinked __pycache__" in e for e in f.evidence)


def test_uppercase_pyc_suffix_is_found(tmp_path):
    sk = _skill(tmp_path)
    out = _pyc(sk, UNCHECKED)
    os.rename(out, out.with_name("OUTPUT.CPYTHON-314.PYC"))
    assert _run_check(sk).status == FAIL


def test_header_shorter_than_a_loadable_pyc_is_inert(tmp_path):
    sk = _skill(tmp_path)
    (sk / "__pycache__").mkdir()
    # flags == 1 but only 12 bytes: Python needs 16 header bytes plus a code object.
    (sk / "__pycache__" / "x.cpython-314.pyc").write_bytes(b"\x00" * 4 + (1).to_bytes(4, "little") + b"\x00" * 4)
    assert _run_check(sk).status == PASS
    (sk / "__pycache__" / "y.cpython-314.pyc").write_bytes(b"\x00" * 4 + (1).to_bytes(4, "little") + b"\x00" * 8)
    assert _run_check(sk).status == FAIL


def _zip_with(pyc_bytes: bytes, name="pkg/__pycache__/m.cpython-314.pyc") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("SKILL.md", "---\nname: sk\ndescription: d\n---\n# sk\n")
        zf.writestr(name, pyc_bytes)
    return buf.getvalue()


def test_unchecked_pyc_inside_a_bare_archive_target_fails(tmp_path, capsys):
    out = _pyc(_skill(tmp_path), UNCHECKED)
    z = tmp_path / "skill.zip"
    z.write_bytes(_zip_with(out.read_bytes()))
    f = _run_check(z)
    assert f.status == FAIL and "m.cpython-314.pyc" in f.detail
    main(["--vet-skill", str(z)])
    assert capsys.readouterr().out.splitlines()[0].rstrip().endswith("DO-NOT-INSTALL")


def test_unchecked_pyc_in_an_archive_inside_a_directory_fails(tmp_path):
    sk = _skill(tmp_path)
    out = _pyc(sk, UNCHECKED)
    data = out.read_bytes()
    out.unlink()
    (sk / "__pycache__").rmdir()
    (sk / "vendor.zip").write_bytes(_zip_with(data))
    assert _run_check(sk).status == FAIL


def test_timestamp_pyc_inside_an_archive_is_silent(tmp_path):
    out = _pyc(_skill(tmp_path), TIMESTAMP)
    z = tmp_path / "skill.zip"
    z.write_bytes(_zip_with(out.read_bytes()))
    assert _run_check(z).status == PASS


def test_long_member_name_cannot_hide_a_pyc(tmp_path):
    # The display name of a member is truncated for evidence text; the suffix test must
    # use the real name, or padding the path past the cap would hide the .pyc.
    data = _pyc(_skill(tmp_path), UNCHECKED).read_bytes()
    name = "pkg/" + "a" * (collector._UNTRUSTED_NAME_CAP + 50) + ".pyc"
    z = tmp_path / "skill.zip"
    z.write_bytes(_zip_with(data, name=name))
    assert _run_check(z).status == FAIL


def test_pyc_body_that_classifies_as_another_format_is_still_checked(tmp_path):
    # Header classification keys on the member NAME, before any content sniffing: a .pyc
    # whose body also looks like a tar (ustar magic at offset 257) must not skip it.
    data = bytearray(_pyc(_skill(tmp_path), UNCHECKED).read_bytes())
    data.extend(b"\0" * (262 - len(data)))
    data[257:262] = b"ustar"
    z = tmp_path / "skill.zip"
    z.write_bytes(_zip_with(bytes(data)))
    assert _run_check(z).status == FAIL


def test_gzip_wrapped_pyc_is_checked(tmp_path):
    import gzip

    data = _pyc(_skill(tmp_path), UNCHECKED).read_bytes()
    g = tmp_path / "m.cpython-314.pyc.gz"
    g.write_bytes(gzip.compress(data))
    assert _run_check(g).status == FAIL


@pytest.mark.parametrize("ext", ["gz", "bz2", "xz"])
def test_long_named_compressed_pyc_inside_a_zip_is_checked(tmp_path, ext):
    import bz2
    import gzip
    import lzma

    comp = {"gz": gzip.compress, "bz2": bz2.compress, "xz": lzma.compress}[ext]
    data = _pyc(_skill(tmp_path), UNCHECKED).read_bytes()
    name = "p/" + "a" * (collector._UNTRUSTED_NAME_CAP + 50) + ".pyc." + ext
    z = tmp_path / "skill.zip"
    z.write_bytes(_zip_with(comp(data), name=name))
    assert _run_check(z).status == FAIL


@pytest.mark.parametrize("wrapper_name", ["m.pyc.gz", "m.pyc.gzip", "m.pyc.bz2"])
def test_wrapper_whose_suffix_disagrees_with_its_bytes_is_checked(tmp_path, wrapper_name):
    import lzma

    data = _pyc(_skill(tmp_path), UNCHECKED).read_bytes()
    z = tmp_path / wrapper_name
    z.write_bytes(lzma.compress(data))  # xz bytes under a .gz / .gzip / .bz2 name
    assert _run_check(z).status == FAIL


def test_remediation_is_published_for_the_docs_generator():
    from clawseccheck.catalog import remediation_for
    assert remediation_for("B398")["commands"]
