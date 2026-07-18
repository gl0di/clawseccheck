"""Tests for clawseccheck.integrity — self-integrity / tamper-detection digest."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from clawseccheck.integrity import package_digest
from clawseccheck.cli import main

REPO = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# package_digest() — unit tests
# ---------------------------------------------------------------------------

def test_digest_is_64_hex_chars():
    combined, _ = package_digest()
    assert len(combined) == 64
    assert all(c in "0123456789abcdef" for c in combined)


def test_per_file_map_contains_py_files():
    _, per_file = package_digest()
    # Must include this very module's package files (keyed by POSIX relpath).
    assert "integrity.py" in per_file
    assert "cli.py" in per_file
    assert "checks/__init__.py" in per_file
    # __pycache__ artifacts must never be hashed (they vary by interpreter).
    assert not any("__pycache__" in name for name in per_file)
    # Every per-file entry is a 64-char hex string.
    for name, digest in per_file.items():
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


def test_all_file_types_are_included(tmp_path):
    """Every file type is hashed — a tamperer must not be able to add a foreign
    (non-.py) file and keep a clean digest (B-008)."""
    (tmp_path / "engine.py").write_text("# engine", encoding="utf-8")
    (tmp_path / "README.md").write_text("readme", encoding="utf-8")
    (tmp_path / "data.json").write_text("{}", encoding="utf-8")

    _, per_file = package_digest(pkg_dir=tmp_path)

    assert set(per_file.keys()) == {"engine.py", "README.md", "data.json"}


def test_pycache_is_excluded(tmp_path):
    """Compiled __pycache__ artifacts must never be part of the digest."""
    (tmp_path / "engine.py").write_text("# engine", encoding="utf-8")
    cache = tmp_path / "__pycache__"
    cache.mkdir()
    (cache / "engine.cpython-312.pyc").write_bytes(b"\x00\x01compiled")

    _, per_file = package_digest(pkg_dir=tmp_path)

    assert set(per_file.keys()) == {"engine.py"}


def test_non_source_cache_dirs_are_excluded(tmp_path):
    """Regenerated local caches / VCS metadata must never enter the digest (B-069).

    A dev/CI checkout (or any tree where ruff/pytest/mypy/git has run) grows these
    dirs inside the package; folding them in made --verify-self environment-dependent.
    The digest must cover only shipped source, so planting them must not change it and
    they must not appear in the per-file map.
    """
    (tmp_path / "engine.py").write_text("# engine", encoding="utf-8")
    baseline, base_map = package_digest(pkg_dir=tmp_path)

    # Plant the realistic ruff-cache shape (the file that triggered B-069) plus the
    # other regenerated dirs, including a nested one.
    for d, fname, content in [
        (".ruff_cache", "CACHEDIR.TAG", "Signature: ruff"),
        (".ruff_cache/0.15.15", "5829738269752342185", "cachekey"),
        (".mypy_cache", "cache.json", "{}"),
        (".pytest_cache", "lastfailed", "{}"),
        (".git", "HEAD", "ref: refs/heads/main"),
    ]:
        sub = tmp_path / d
        sub.mkdir(parents=True, exist_ok=True)
        (sub / fname).write_text(content, encoding="utf-8")

    after, after_map = package_digest(pkg_dir=tmp_path)

    # None of the cache/VCS files leak into the per-file map...
    assert set(after_map.keys()) == {"engine.py"}
    assert not any(
        part in name
        for name in after_map
        for part in (".ruff_cache", ".mypy_cache", ".pytest_cache", ".git")
    )
    # ...and the combined digest is unchanged by their presence (reproducible).
    assert after == baseline
    assert after_map == base_map


def test_added_foreign_file_changes_digest(tmp_path):
    """Dropping ANY new file (even non-.py, even nested) must change the digest —
    the flat top-level *.py scan was blind to this (B-008)."""
    (tmp_path / "engine.py").write_text("# engine", encoding="utf-8")
    before, _ = package_digest(pkg_dir=tmp_path)

    # Foreign top-level file.
    (tmp_path / "_evil.txt").write_text("payload", encoding="utf-8")
    after_foreign, _ = package_digest(pkg_dir=tmp_path)
    assert after_foreign != before

    # Nested subpackage module.
    sub = tmp_path / "_sub"
    sub.mkdir()
    (sub / "deep.py").write_text("# nested", encoding="utf-8")
    after_nested, _ = package_digest(pkg_dir=tmp_path)
    assert after_nested != after_foreign


def test_nested_files_keyed_by_relpath(tmp_path):
    """Nested files are distinguishable via their POSIX relative path."""
    (tmp_path / "top.py").write_text("# top", encoding="utf-8")
    sub = tmp_path / "pkg"
    sub.mkdir()
    (sub / "mod.py").write_text("# mod", encoding="utf-8")

    _, per_file = package_digest(pkg_dir=tmp_path)

    assert "top.py" in per_file
    assert "pkg/mod.py" in per_file


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
    from clawseccheck import __version__
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


def test_cli_verify_self_points_to_signed_release_digest(capsys):
    """--verify-self must point users at the signed, out-of-band trusted digest
    (SHA256SUMS.txt on the GitHub Release, cosign-signed) instead of leaving the
    'trusted release' reference in the earlier line unresolved (CLAWSECCHECK-F-091).
    """
    from clawseccheck import __version__
    main(["--verify-self"])
    out = capsys.readouterr().out
    assert "SHA256SUMS.txt" in out
    assert "cosign" in out
    assert f"v{__version__}" in out


def test_cli_verify_self_prints_exact_cosign_verify_command(capsys):
    """CLAWSECCHECK-C-240: pointing at a signed SHA256SUMS.txt without the verification
    command itself just leaves the user (or a host agent) to guess one — which is exactly
    what let a host agent 'verify' by web-searching a checksum and reporting a fabricated
    match instead of actually checking the cosign signature. The printed command must be
    the real one: keyless/OIDC verify-blob against a bundle, scoped to this repo's identity
    and the GitHub Actions OIDC issuer — grounded against .github/workflows/clawhub-publish.yml
    (cosign sign-blob --yes --bundle SHA256SUMS.txt.bundle) and the same command already
    published in README.md / docs/USAGE.md.
    """
    main(["--verify-self"])
    out = capsys.readouterr().out
    assert "cosign verify-blob" in out
    assert "--bundle SHA256SUMS.txt.bundle" in out
    assert "--certificate-identity-regexp" in out
    assert "^https://github.com/gl0di/clawseccheck/" in out
    assert "--certificate-oidc-issuer" in out
    assert "https://token.actions.githubusercontent.com" in out
    # The full invocation ends on the digest file being verified, not just named earlier.
    assert out.rstrip().endswith("SHA256SUMS.txt")


def test_cli_verify_self_warns_web_search_checksum_is_not_verification(capsys):
    """The failure mode this task fixes: a host agent treating a web-searched checksum
    match as 'verified'. The output must say plainly that a checksum alone isn't proof —
    only running cosign is — so a host agent reading the report can't skip the signature
    check and still claim it verified anything.

    CLAWSECCHECK-C-240 adversarial follow-up: the original version of this test also
    accepted a bare "cosign" in out — an arm that was unconditionally true even before
    this feature existed (the "signed via cosign." trusted-digest line a few lines above
    already contains it), so the assertion never actually exercised the caution text and
    a semantic inversion of the advice ("a checksum you read off a web page is fine proof
    on its own; no need to run anything") passed it. There is no sound narrower substring
    match that resists an adversarial rewording of a natural-language caution, so this
    pins the literal sentence instead of a fuzzy keyword heuristic.
    """
    main(["--verify-self"])
    out = capsys.readouterr().out
    assert (
        "A checksum you just read off a web page or a chat reply proves nothing by\n"
        "itself — it could be tampered with too. Verify the cosign signature instead"
    ) in out


def test_cli_verify_self_cosign_command_matches_published_docs(capsys):
    """CLAWSECCHECK-C-240 adversarial follow-up: cli.py's printed cosign invocation is a
    fourth copy of the same command already published in README.md and docs/USAGE.md, and
    nothing enforced the three staying in sync — a change that only edited one of them (or
    that appended verification-defeating flags like --insecure-ignore-tlog /
    --insecure-ignore-sct, which silently disable Rekor transparency-log and SCT checks)
    would pass every other test in this file. Derive the expected command from the docs
    instead of restating a fifth hand-typed copy here, so the three stay provably equal.
    """

    def cosign_command_lines(text):
        lines = text.splitlines()
        start = next(i for i, ln in enumerate(lines) if "cosign verify-blob" in ln)
        collected = []
        for ln in lines[start:]:
            token = ln.strip().rstrip("\\").strip()
            collected.append(token)
            if token == "SHA256SUMS.txt":
                break
        else:
            raise AssertionError("cosign command block never reached SHA256SUMS.txt")
        return collected

    readme_cmd = cosign_command_lines((REPO / "README.md").read_text(encoding="utf-8"))
    usage_cmd = cosign_command_lines((REPO / "docs" / "USAGE.md").read_text(encoding="utf-8"))

    main(["--verify-self"])
    cli_cmd = cosign_command_lines(capsys.readouterr().out)

    assert readme_cmd == usage_cmd == cli_cmd
    assert not any("insecure" in line for line in cli_cmd)


def test_cli_verify_self_cosign_guidance_is_unconditional():
    """--verify-self's cosign guidance is static text describing an out-of-band
    verification step, not a PASS/FAIL/UNKNOWN check verdict (it isn't a `check_*`
    finding and never enters CATALOG/CHECKS) — so there is no UNKNOWN state to cover:
    the command is always printed the same way, deterministically, regardless of
    local config or environment. This test pins that (no state can suppress it).
    """
    import io
    import contextlib

    buf1, buf2 = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(buf1):
        main(["--verify-self"])
    with contextlib.redirect_stdout(buf2):
        main(["--verify-self"])
    assert "cosign verify-blob" in buf1.getvalue()
    assert buf1.getvalue() == buf2.getvalue()
