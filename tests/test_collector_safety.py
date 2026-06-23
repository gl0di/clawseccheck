"""Tests for collector.py hardening items H1 and H6.

H1: symlinked skill directories are skipped (no directory-symlink escape).
H6: per-skill file count is capped at _MAX_FILES_PER_SKILL.
"""
import sys
from pathlib import Path

import pytest

from clawseccheck.collector import (
    Context,
    _MAX_FILES_PER_SKILL,
    _read_installed_skills,
    _read_skill_text,
    collect,
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
