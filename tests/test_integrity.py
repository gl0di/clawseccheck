"""Tests for clawcheck.integrity — self-integrity / tamper-detection digest."""
from __future__ import annotations

import hashlib

import pytest

from clawcheck.integrity import package_digest
from clawcheck.cli import main


# ---------------------------------------------------------------------------
# package_digest() — unit tests
# ---------------------------------------------------------------------------

def test_digest_is_64_hex_chars():
    combined, _ = package_digest()
    assert len(combined) == 64
    assert all(c in "0123456789abcdef" for c in combined)


def test_per_file_map_contains_py_files():
    _, per_file = package_digest()
    # Must include this very module's package files
    assert "integrity.py" in per_file
    assert "cli.py" in per_file
    assert "checks.py" in per_file
    # Every per-file entry is also a 64-char hex string
    for name, digest in per_file.items():
        assert name.endswith(".py"), f"non-py file in map: {name}"
        assert len(digest) == 64, f"bad digest length for {name}: {digest!r}"
        assert all(c in "0123456789abcdef" for c in digest)


def test_digest_is_stable_across_calls():
    """Two consecutive calls on the same unchanged source tree must agree."""
    combined1, per1 = package_digest()
    combined2, per2 = package_digest()
    assert combined1 == combined2
    assert per1 == per2


def test_digest_changes_when_file_content_changes(tmp_path):
    """Simulates tampered content: a different byte sequence produces a different digest."""
    # Build a tiny fake package directory with two .py files.
    (tmp_path / "a.py").write_text("# original a", encoding="utf-8")
    (tmp_path / "b.py").write_text("# original b", encoding="utf-8")

    combined_original, _ = package_digest(pkg_dir=tmp_path)

    # Tamper with one file.
    (tmp_path / "a.py").write_text("# TAMPERED a", encoding="utf-8")

    combined_tampered, _ = package_digest(pkg_dir=tmp_path)

    assert combined_original != combined_tampered


def test_digest_is_order_independent(tmp_path):
    """The combined digest must be the same regardless of filesystem enumeration order.

    We verify this by computing it ourselves using the documented algorithm and
    confirming it matches what package_digest() returns.
    """
    (tmp_path / "z.py").write_text("# z file", encoding="utf-8")
    (tmp_path / "a.py").write_text("# a file", encoding="utf-8")
    (tmp_path / "m.py").write_text("# m file", encoding="utf-8")

    combined, per_file = package_digest(pkg_dir=tmp_path)

    # Replicate the algorithm: sorted by name, "name:hex\n" joined, sha256.
    manual = hashlib.sha256(
        "".join(f"{n}:{d}\n" for n, d in sorted(per_file.items())).encode()
    ).hexdigest()

    assert combined == manual


def test_only_py_files_are_included(tmp_path):
    """Non-.py files (configs, binaries) must be ignored."""
    (tmp_path / "engine.py").write_text("# engine", encoding="utf-8")
    (tmp_path / "README.md").write_text("readme", encoding="utf-8")
    (tmp_path / "data.json").write_text("{}", encoding="utf-8")

    _, per_file = package_digest(pkg_dir=tmp_path)

    assert set(per_file.keys()) == {"engine.py"}


def test_empty_pkg_dir_returns_empty_map_and_valid_digest(tmp_path):
    """An empty directory should still return a valid 64-char hex digest."""
    combined, per_file = package_digest(pkg_dir=tmp_path)
    assert per_file == {}
    assert len(combined) == 64


# ---------------------------------------------------------------------------
# CLI --verify-self integration tests
# ---------------------------------------------------------------------------

def test_cli_verify_self_exits_zero(capsys):
    rc = main(["--verify-self"])
    assert rc == 0


def test_cli_verify_self_prints_combined_digest(capsys):
    main(["--verify-self"])
    out = capsys.readouterr().out
    # Must contain the "combined :" label and a 64-char hex digest.
    assert "combined" in out
    # Extract the hex value after "combined :"
    for line in out.splitlines():
        if "combined" in line and ":" in line:
            hex_part = line.split(":")[-1].strip()
            assert len(hex_part) == 64
            assert all(c in "0123456789abcdef" for c in hex_part)
            break
    else:
        pytest.fail("No 'combined' line found in --verify-self output")


def test_cli_verify_self_prints_version(capsys):
    from clawcheck import __version__
    main(["--verify-self"])
    out = capsys.readouterr().out
    assert __version__ in out


def test_cli_verify_self_lists_per_file_digests(capsys):
    main(["--verify-self"])
    out = capsys.readouterr().out
    # Each per-file line has a 64-char hex digest followed by the filename.
    found_any = False
    for line in out.splitlines():
        stripped = line.strip()
        if len(stripped) > 67 and stripped[:64].isalnum():
            # looks like "<64-hex>  <filename>"
            parts = stripped.split()
            if len(parts) == 2 and parts[1].endswith(".py"):
                assert len(parts[0]) == 64
                found_any = True
    assert found_any, "No per-file digest lines found in --verify-self output"


def test_cli_verify_self_is_deterministic(capsys):
    """Two consecutive --verify-self calls must print identical combined digests."""
    main(["--verify-self"])
    out1 = capsys.readouterr().out
    main(["--verify-self"])
    out2 = capsys.readouterr().out
    assert out1 == out2
