"""Tests for collector.py hardening items H1 and H6.

H1: symlinked skill directories are skipped (no directory-symlink escape).
H6: per-skill file count is capped at _MAX_FILES_PER_SKILL.
"""
import bz2
import gzip
import io
import lzma
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from clawseccheck.checks import check_installed_skills, vet_skill
from clawseccheck.collector import (
    Context,
    _MAX_FILES_PER_SKILL,
    _read_installed_skills,
    _read_skill_text,
    collect,
    collect_skill_files,
    read_skill_python,
)


def _make_skill(base: Path, name: str, extra_text: str = "clean skill content") -> Path:
    """Create a minimal valid skill directory under base/skills/<name>/."""
    sd = base / "skills" / name
    sd.mkdir(parents=True, exist_ok=True)
    (sd / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: test\n---\n{extra_text}\n"
    )
    return sd


# ---------------------------------------------------------------------------
# H1 — symlinked skill directory is skipped
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks only")
def test_symlinked_skill_dir_is_skipped(tmp_path):
    """A directory symlink under skills/ must not be followed during skill discovery.

    Setup: skills/realskill (real dir with SKILL.md) and skills/evil -> <other_tmp>
    where other_tmp contains its own SKILL.md and a secret-ish file.
    Expected: only 'realskill' appears in ctx.installed_skills; 'evil' is absent.
    """
    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text("{}")

    # Real skill
    _make_skill(home, "realskill", "does something safe")

    # Target directory that the symlink will point at (outside home)
    evil_target = tmp_path / "outside"
    evil_target.mkdir()
    (evil_target / "SKILL.md").write_text("---\nname: evil\n---\nrm -rf /")
    (evil_target / "secret.md").write_text("password=hunter2")

    # Create a directory symlink: home/skills/evil -> evil_target
    evil_link = home / "skills" / "evil"
    evil_link.symlink_to(evil_target)

    ctx = collect(home)

    assert "realskill" in ctx.installed_skills, "real skill must be collected"
    assert "evil" not in ctx.installed_skills, (
        "symlinked skill directory must be skipped (H1)"
    )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks only")
def test_symlinked_skill_dir_skipped_via_read_installed_skills(tmp_path):
    """Lower-level check: _read_installed_skills directly must skip directory symlinks."""
    home = tmp_path / "home"
    home.mkdir()

    _make_skill(home, "goodskill")

    other = tmp_path / "other"
    other.mkdir()
    (other / "SKILL.md").write_text("---\nname: trap\n---\nmalicious")

    (home / "skills" / "trap").symlink_to(other)

    ctx = Context(home=home)
    _read_installed_skills(home, ctx)

    assert "goodskill" in ctx.installed_skills
    assert "trap" not in ctx.installed_skills, (
        "_read_installed_skills must not follow directory symlinks (H1)"
    )


# ---------------------------------------------------------------------------
# H6 — per-skill file-count cap
# ---------------------------------------------------------------------------

def test_file_count_cap_limits_files_read(tmp_path):
    """_read_skill_text must stop after _MAX_FILES_PER_SKILL files have been appended.

    Create one skill dir with _MAX_FILES_PER_SKILL + 50 tiny .md files.
    Assert that the returned text contains at most _MAX_FILES_PER_SKILL
    '# file:' markers (i.e. the loop broke before reading all files).
    """
    skill_dir = tmp_path / "bigskill"
    skill_dir.mkdir()

    total_files = _MAX_FILES_PER_SKILL + 50
    for i in range(total_files):
        (skill_dir / f"note_{i:04d}.md").write_text(f"note {i}\n")

    result = _read_skill_text(skill_dir)

    file_markers = result.count("# file:")
    assert file_markers <= _MAX_FILES_PER_SKILL, (
        f"_read_skill_text read {file_markers} files but cap is {_MAX_FILES_PER_SKILL} (H6)"
    )
    assert file_markers > 0, "at least some files should have been read"


def test_file_count_cap_exact_boundary(tmp_path):
    """At exactly _MAX_FILES_PER_SKILL files the cap is not exceeded."""
    skill_dir = tmp_path / "exactskill"
    skill_dir.mkdir()

    for i in range(_MAX_FILES_PER_SKILL):
        (skill_dir / f"f_{i:04d}.md").write_text("x\n")

    result = _read_skill_text(skill_dir)
    file_markers = result.count("# file:")

    assert file_markers <= _MAX_FILES_PER_SKILL, (
        f"Expected at most {_MAX_FILES_PER_SKILL} files, got {file_markers}"
    )


def test_file_count_cap_does_not_affect_small_skill(tmp_path):
    """A skill with fewer than _MAX_FILES_PER_SKILL files is read completely."""
    skill_dir = tmp_path / "smallskill"
    skill_dir.mkdir()
    n = 5
    for i in range(n):
        (skill_dir / f"doc_{i}.md").write_text(f"content {i}\n")

    result = _read_skill_text(skill_dir)
    file_markers = result.count("# file:")

    assert file_markers == n, (
        f"All {n} files should be read when under the cap, got {file_markers}"
    )


# ---------------------------------------------------------------------------
# B-014 — deeply-nested openclaw.json must degrade, not crash with RecursionError
# ---------------------------------------------------------------------------

def test_deeply_nested_config_degrades_gracefully(tmp_path):
    """A pathologically deep JSON config overflows json.loads' C recursion limit;
    collect() must record an error and keep going, not propagate RecursionError."""
    depth = 100_000
    deep = "[" * depth + "]" * depth
    (tmp_path / "openclaw.json").write_text(deep, encoding="utf-8")

    ctx = collect(tmp_path)  # must not raise

    assert ctx.config == {}
    assert any("openclaw.json" in e for e in ctx.errors)


# ---------------------------------------------------------------------------
# B-016 — non-dict top-level openclaw.json must degrade, not raise AttributeError
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "body, kind",
    [
        ("[]", "list"),
        ("[1,2,3]", "list"),
        ('"juststring"', "str"),
        ("123", "int"),
        ("12.5", "float"),
        ("true", "bool"),
        ("null", "NoneType"),
    ],
)
def test_non_dict_config_degrades_gracefully(tmp_path, body, kind):
    """Valid JSON whose top level is not an object (list/scalar) must not crash.

    Pre-fix, collect() assigned the parsed value straight to ctx.config and every
    later cfg.get() raised `AttributeError: '<type>' object has no attribute 'get'`.
    collect() must instead leave ctx.config == {} and record a clear malformed note.
    """
    (tmp_path / "openclaw.json").write_text(body, encoding="utf-8")

    ctx = collect(tmp_path)  # must not raise

    assert ctx.config == {}, f"non-dict {kind} top-level must degrade to empty config"
    assert ctx.config_mode is None, "config_mode must not be set for a malformed config"
    assert any("expected a JSON object" in e for e in ctx.errors), (
        f"expected a 'malformed ... expected a JSON object' note, got {ctx.errors}"
    )
    assert any(kind in e for e in ctx.errors), (
        f"error note should name the actual type {kind!r}, got {ctx.errors}"
    )


def test_dict_config_still_parses(tmp_path):
    """Control: a well-formed JSON object is parsed and recorded as before."""
    (tmp_path / "openclaw.json").write_text('{"gateway": {}}', encoding="utf-8")

    ctx = collect(tmp_path)

    assert ctx.config == {"gateway": {}}
    assert not any("expected a JSON object" in e for e in ctx.errors)


def test_full_audit_on_non_dict_config_does_not_crash(tmp_path):
    """End-to-end: auditing a home whose openclaw.json is a list must not raise.

    Mirrors the reported bug (exit-1 traceback). audit() must complete and return a
    numeric score, treating the config as absent rather than crashing on cfg.get().
    """
    from clawseccheck import audit

    (tmp_path / "openclaw.json").write_text("[1, 2, 3]", encoding="utf-8")

    ctx, findings, score = audit(tmp_path)  # must not raise

    assert isinstance(score.score, (int, float))
    assert ctx.config == {}


# ---------------------------------------------------------------------------
# Content-Classified Collector & Archive Extraction Tests (CLAWSECCHECK-F-010/011)
# ---------------------------------------------------------------------------

def test_archive_decompression_zip(tmp_path):
    """Verify that a ZIP file in a skill directory is decompressed in-memory and read."""
    home = tmp_path / "home"
    sd = _make_skill(home, "zipskill", "initial text")
    
    # Create a zip archive with a python file
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("nested.py", "print('hello zip')\n")
    (sd / "archive.zip").write_bytes(bio.getvalue())
    
    ctx = Context(home=home)
    py_files = read_skill_python(sd, ctx)
    
    assert any(name == "archive.zip::nested.py" and content == "print('hello zip')\n" for name, content in py_files)
    assert not ctx.limit_hits
    assert not ctx.path_traversal_violations


def test_archive_decompression_tar(tmp_path):
    """Verify that a tar file in a skill directory is decompressed in-memory."""
    home = tmp_path / "home"
    sd = _make_skill(home, "tarskill", "initial text")
    
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w") as tf:
        tarinfo = tarfile.TarInfo(name="nested.py")
        content = b"print('hello tar')\n"
        tarinfo.size = len(content)
        tf.addfile(tarinfo, io.BytesIO(content))
    (sd / "archive.tar").write_bytes(bio.getvalue())
    
    ctx = Context(home=home)
    py_files = read_skill_python(sd, ctx)
    
    assert any(name == "archive.tar::nested.py" and content == "print('hello tar')\n" for name, content in py_files)


def test_archive_decompression_gzip(tmp_path):
    """Verify that a gzip file in a skill directory is decompressed."""
    home = tmp_path / "home"
    sd = _make_skill(home, "gzskill", "initial text")
    
    gz_bytes = gzip.compress(b"print('hello gzip')\n")
    (sd / "code.py.gz").write_bytes(gz_bytes)
    
    ctx = Context(home=home)
    py_files = read_skill_python(sd, ctx)
    
    assert any(name == "code.py" and content == "print('hello gzip')\n" for name, content in py_files)


def test_archive_decompression_bz2(tmp_path):
    """Verify that a bzip2 file in a skill directory is decompressed."""
    home = tmp_path / "home"
    sd = _make_skill(home, "bz2skill", "initial text")
    
    bz_bytes = bz2.compress(b"print('hello bz2')\n")
    (sd / "code.py.bz2").write_bytes(bz_bytes)
    
    ctx = Context(home=home)
    py_files = read_skill_python(sd, ctx)
    
    assert any(name == "code.py" and content == "print('hello bz2')\n" for name, content in py_files)


def test_archive_decompression_xz(tmp_path):
    """Verify that an xz file in a skill directory is decompressed."""
    home = tmp_path / "home"
    sd = _make_skill(home, "xzskill", "initial text")
    
    xz_bytes = lzma.compress(b"print('hello xz')\n")
    (sd / "code.py.xz").write_bytes(xz_bytes)
    
    ctx = Context(home=home)
    py_files = read_skill_python(sd, ctx)
    
    assert any(name == "code.py" and content == "print('hello xz')\n" for name, content in py_files)


def test_archive_safety_bounds_limits(tmp_path):
    """Verify safety limits: recursion depth, decompression size, etc."""
    home = tmp_path / "home"
    sd = _make_skill(home, "limitskill", "initial text")
    
    # 1. Depth limit: .zip inside .zip inside .zip inside .zip (depth > 3)
    # We can create a nested zip structure
    def make_nested_zip(inner_bytes, inner_name, outer_name):
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w") as zf:
            zf.writestr(inner_name, inner_bytes)
        return bio.getvalue()
        
    depth5_bytes = b"print('nested')"
    depth5_bytes = make_nested_zip(depth5_bytes, "d5.py", "d4.zip")
    depth5_bytes = make_nested_zip(depth5_bytes, "d4.zip", "d3.zip")
    depth5_bytes = make_nested_zip(depth5_bytes, "d3.zip", "d2.zip")
    depth5_bytes = make_nested_zip(depth5_bytes, "d2.zip", "d1.zip")
    
    (sd / "nested.zip").write_bytes(depth5_bytes)
    
    ctx = Context(home=home)
    _read_skill_text(sd, ctx)
    
    assert any("Depth limit hit" in hit for hit in ctx.limit_hits)


def test_path_traversal_unsafe_tar_member(tmp_path):
    """Verify path traversal member in archive aborts extraction and records traversal violation."""
    home = tmp_path / "home"
    sd = _make_skill(home, "traversalskill", "initial text")
    
    # Create zip with absolute or relative traversal path
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("../../../outside.py", "print('traversal')\n")
    (sd / "evil.zip").write_bytes(bio.getvalue())
    
    ctx = Context(home=home)
    _read_skill_text(sd, ctx)
    
    assert any("evil.zip::../../../outside.py" in v for v in ctx.path_traversal_violations)
    
    # Verify B13 check reports this as SKILL_ARCHIVE_PATH_TRAVERSAL
    ctx.installed_skills = {"traversalskill": "initial text"}
    finding = check_installed_skills(ctx)
    assert finding.status == "SKILL_ARCHIVE_PATH_TRAVERSAL"


def test_extension_mismatch(tmp_path):
    """Verify that file extension and magic mismatch raises warning but not FAIL."""
    home = tmp_path / "home"
    sd = _make_skill(home, "mismatchskill", "initial text")
    
    # Write PE header inside a .py file
    (sd / "fake.py").write_bytes(b"MZ\x90\x00\x03\x00\x00\x00")
    
    ctx = Context(home=home)
    _read_skill_text(sd, ctx)
    
    assert any("fake.py: MISMATCH_EXTENSION" in m for m in ctx.mismatches)
    
    # Verify B13 check reports this as WARN
    ctx.installed_skills = {"mismatchskill": "initial text"}
    finding = check_installed_skills(ctx)
    assert finding.status == "WARN"


def test_polyglot_detection(tmp_path):
    """Verify that polyglot structure raises warning."""
    home = tmp_path / "home"
    sd = _make_skill(home, "polyglotskill", "initial text")
    
    # Create PNG header with embedded ZIP signature at non-zero offset
    poly_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20 + b"PK\x03\x04" + b"\x00" * 10
    (sd / "polyglot.png").write_bytes(poly_bytes)
    
    ctx = Context(home=home)
    _read_skill_text(sd, ctx)
    
    assert any("polyglot.png: POLYGLOT_DETECTED" in p for p in ctx.polyglots)
    
    # Verify B13 check reports this as WARN
    ctx.installed_skills = {"polyglotskill": "initial text"}
    finding = check_installed_skills(ctx)
    assert finding.status == "WARN"


def test_file_manifest_statuses(tmp_path):
    home = tmp_path / "home"
    sd = _make_skill(home, "manifestskill", "initial text")
    
    # 1. Normal Python file
    (sd / "code.py").write_text("print('hello')\n")
    
    # 2. Normal text file
    (sd / "doc.txt").write_text("plain text\n")
    
    # 3. Binary file (non-archive)
    (sd / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 20)
    
    # 4. ZIP archive with normal files
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("nested.py", "print('nested python')\n")
        zf.writestr("nested.txt", "nested text\n")
    (sd / "archive.zip").write_bytes(bio.getvalue())
    
    ctx = Context(home=home)
    collect_skill_files(sd, ctx)
    
    assert ctx.file_manifest["code.py"] == "scanned-ast"
    assert ctx.file_manifest["doc.txt"] == "scanned-text"
    assert ctx.file_manifest["SKILL.md"] == "scanned-text"
    assert ctx.file_manifest["image.png"] == "binary-strings"
    assert ctx.file_manifest["archive.zip"] == "decoded"
    assert ctx.file_manifest["archive.zip::nested.py"] == "scanned-ast"
    assert ctx.file_manifest["archive.zip::nested.txt"] == "scanned-text"


def test_file_manifest_limits_and_safety(tmp_path):
    home = tmp_path / "home"
    sd = _make_skill(home, "limitsskill", "initial text")
    
    # 1. Oversized normal file (>200,000 bytes)
    (sd / "huge.txt").write_bytes(b"a" * 200001)
    
    # 2. Oversized archive (>10MB)
    (sd / "huge.zip").write_bytes(b"PK\x03\x04" + b"a" * (10 * 1024 * 1024 + 1))
    
    # 3. Path traversal member
    bio_traversal = io.BytesIO()
    with zipfile.ZipFile(bio_traversal, "w") as zf:
        zf.writestr("../../../evil.txt", "evil")
    (sd / "traversal.zip").write_bytes(bio_traversal.getvalue())
    
    # 4. Recursion depth limit hit
    def make_nested_zip(inner_bytes, inner_name):
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w") as zf:
            zf.writestr(inner_name, inner_bytes)
        return bio.getvalue()
    d4_bytes = make_nested_zip(b"print('depth')", "d4.py")
    d3_bytes = make_nested_zip(d4_bytes, "d3.zip")
    d2_bytes = make_nested_zip(d3_bytes, "d2.zip")
    d1_bytes = make_nested_zip(d2_bytes, "d1.zip")
    (sd / "nested.zip").write_bytes(d1_bytes)
    
    # 5. Max file limit hit (>500 files)
    bio_many = io.BytesIO()
    with zipfile.ZipFile(bio_many, "w") as zf:
        for i in range(501):
            zf.writestr(f"file_{i}.txt", "content")
    (sd / "many.zip").write_bytes(bio_many.getvalue())
    
    # 6. Cumulative size limit hit (>20MB)
    bio_cum = io.BytesIO()
    with zipfile.ZipFile(bio_cum, "w") as zf:
        for i in range(150):
            zf.writestr(f"big_{i}.txt", "a" * 150000)
    (sd / "cumulative.zip").write_bytes(bio_cum.getvalue())
    
    # 7. Max expansion ratio limit hit (>100x)
    import os
    bio_ratio = io.BytesIO()
    with zipfile.ZipFile(bio_ratio, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for i in range(10):
            zf.writestr(f"ratio_{i}.txt", b"a" * 150000)
        zf.writestr("padding.bin", os.urandom(12000))
    ratio_bytes = bio_ratio.getvalue()
    (sd / "ratio.zip").write_bytes(ratio_bytes)
    
    ctx = Context(home=home)
    collect_skill_files(sd, ctx)
    
    assert ctx.file_manifest["huge.txt"] == "capped(size)"
    assert ctx.file_manifest["huge.zip"] == "capped(size)"
    assert ctx.file_manifest["traversal.zip::../../../evil.txt"] == "unsafe-path"
    assert ctx.file_manifest["nested.zip::d1.zip::d2.zip::d3.zip"] == "capped(depth)"
    assert ctx.file_manifest["many.zip"] == "capped(files)"
    assert ctx.file_manifest["cumulative.zip"] == "capped(size)"
    assert ctx.file_manifest["ratio.zip"] == "capped(ratio)"


def test_vet_skill_early_context(tmp_path):
    home = tmp_path / "home"
    sd = _make_skill(home, "vet_early", "clean skill content")
    (sd / "code.py").write_text("print('hello')\n")
    
    finding = vet_skill(sd)
    assert hasattr(finding, "ctx")
    assert finding.ctx is not None
    assert finding.ctx.file_manifest["code.py"] == "scanned-ast"
