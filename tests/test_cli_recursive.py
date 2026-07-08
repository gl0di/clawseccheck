"""Tests for --vet-all / --recursive flag (F-009).

Covers:
- vet_all() finds skills that have SKILL.md, skips dirs without one
- empty skills/ dir returns 0 with a helpful message
- missing skills/ dir returns 0 gracefully
- aggregate summary is printed
- exit code is 0 when all found skills are clean
"""
from pathlib import Path


from clawseccheck.cli import main, vet_all


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_CLEAN_MD = """\
# Word Counter
Count the words in a file the user names. Ask before reading other files.
"""


def _make_skill(base: Path, name: str, content: str = _CLEAN_MD) -> Path:
    """Create a skill directory with a SKILL.md under base/skills/."""
    skill_dir = base / "skills" / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(content, encoding="utf-8")
    return skill_dir


# ---------------------------------------------------------------------------
# vet_all() unit tests
# ---------------------------------------------------------------------------

def test_vet_all_finds_skills_with_skillmd(tmp_path, capsys):
    """vet_all picks up skill_a and skill_b; ignores skill_c (no SKILL.md)."""
    _make_skill(tmp_path, "skill_a")
    _make_skill(tmp_path, "skill_b")
    # skill_c has a directory but no SKILL.md — must be skipped
    (tmp_path / "skills" / "skill_c").mkdir(parents=True, exist_ok=True)

    vet_all(tmp_path, ascii_only=True)
    out = capsys.readouterr().out

    assert "skill_a" in out
    assert "skill_b" in out
    assert "skill_c" not in out


def test_vet_all_clean_skills_return_0(tmp_path, capsys):
    """All-clean skills must yield exit code 0."""
    _make_skill(tmp_path, "alpha")
    _make_skill(tmp_path, "beta")

    rc = vet_all(tmp_path, ascii_only=True)
    assert rc == 0


def test_vet_all_prints_aggregate_summary(tmp_path, capsys):
    """After per-skill output, an 'Aggregate summary' section must appear."""
    _make_skill(tmp_path, "mskill")

    vet_all(tmp_path, ascii_only=True)
    out = capsys.readouterr().out

    assert "Aggregate summary" in out
    assert "skill(s) checked" in out


def test_vet_all_empty_skills_dir_returns_0(tmp_path, capsys):
    """An existing but empty skills/ dir returns 0 with a helpful message."""
    (tmp_path / "skills").mkdir()

    rc = vet_all(tmp_path, ascii_only=True)
    out = capsys.readouterr().out

    assert rc == 0
    assert "No skills found" in out


def test_vet_all_missing_skills_dir_returns_0(tmp_path, capsys):
    """When skills/ doesn't exist at all, returns 0 with a helpful message."""
    # tmp_path has no 'skills' subdirectory
    rc = vet_all(tmp_path, ascii_only=True)
    out = capsys.readouterr().out

    assert rc == 0
    assert "No skills directory found" in out


def test_vet_all_section_header_per_skill(tmp_path, capsys):
    """Each discovered skill gets its own '=== <name> ===' section header."""
    _make_skill(tmp_path, "checker")

    vet_all(tmp_path, ascii_only=True)
    out = capsys.readouterr().out

    assert "=== checker ===" in out


# ---------------------------------------------------------------------------
# CLI integration tests (main() via --vet-all / --recursive)
# ---------------------------------------------------------------------------

def test_cli_vet_all_flag(tmp_path, capsys):
    """--vet-all wires through main() and prints skill names."""
    _make_skill(tmp_path, "myskill")

    rc = main(["--vet-all", "--home", str(tmp_path), "--ascii"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "myskill" in out


def test_cli_recursive_alias(tmp_path, capsys):
    """--recursive is a recognized alias for --vet-all."""
    _make_skill(tmp_path, "rskill")

    rc = main(["--recursive", "--home", str(tmp_path), "--ascii"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "rskill" in out


def test_cli_vet_all_missing_home_returns_0(tmp_path, capsys):
    """--vet-all with a home dir that has no skills/ returns 0 gracefully."""
    rc = main(["--vet-all", "--home", str(tmp_path), "--ascii"])
    out = capsys.readouterr().out

    assert rc == 0
    # Must print something helpful rather than crashing
    assert out.strip()


def test_cli_vet_all_skips_dir_without_skillmd(tmp_path, capsys):
    """Directories without SKILL.md are skipped by --vet-all."""
    _make_skill(tmp_path, "has_md")
    (tmp_path / "skills" / "no_md").mkdir(parents=True, exist_ok=True)

    main(["--vet-all", "--home", str(tmp_path), "--ascii"])
    out = capsys.readouterr().out

    assert "has_md" in out
    assert "no_md" not in out


# ---------------------------------------------------------------------------
# B-147: discovery across all of collector.SKILL_DIRS, not just home/skills/
# ---------------------------------------------------------------------------

def _make_skill_under(base: Path, rel_dir: str, name: str, content: str = _CLEAN_MD) -> Path:
    """Create a skill directory with a SKILL.md under base/<rel_dir>/<name>."""
    skill_dir = base / rel_dir / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(content, encoding="utf-8")
    return skill_dir


def test_vet_all_finds_skills_under_workspace_skills_only(tmp_path, capsys):
    """B-147: a skill installed only under workspace/skills/ (the real common
    OpenClaw location — no legacy home/skills/ dir at all) must still be found
    and vetted; previously vet_all() hardcoded home/skills/ and would report
    'no skills directory found', vetting zero skills."""
    _make_skill_under(tmp_path, "workspace/skills", "ws_only_skill")
    assert not (tmp_path / "skills").exists()

    rc = vet_all(tmp_path, ascii_only=True)
    out = capsys.readouterr().out

    assert "ws_only_skill" in out
    assert "Aggregate summary" in out
    assert rc == 0


def test_vet_all_still_finds_legacy_home_skills(tmp_path, capsys):
    """Regression: the original home/skills/ path must still be discovered
    alongside the newer SKILL_DIRS locations."""
    _make_skill(tmp_path, "legacy_skill")

    vet_all(tmp_path, ascii_only=True)
    out = capsys.readouterr().out

    assert "legacy_skill" in out


def test_vet_all_finds_skills_across_multiple_skill_dirs(tmp_path, capsys):
    """Skills spread across two different SKILL_DIRS entries are all found and
    vetted in a single --vet-all run."""
    _make_skill(tmp_path, "legacy_skill")
    _make_skill_under(tmp_path, "workspace/skills", "ws_skill")
    _make_skill_under(tmp_path, ".agents/skills", "agents_skill")

    vet_all(tmp_path, ascii_only=True)
    out = capsys.readouterr().out

    assert "legacy_skill" in out
    assert "ws_skill" in out
    assert "agents_skill" in out
    assert "3 skill(s) checked" in out


def test_vet_all_dedups_same_skill_reachable_via_two_skill_dirs(tmp_path, capsys):
    """If two SKILL_DIRS entries resolve to the same on-disk skill (e.g. one is
    a symlinked alias of the other), it must be vetted once, not twice."""
    _make_skill_under(tmp_path, "workspace/skills", "shared_skill")
    # home/skills is a symlink alias of home/workspace/skills, so the same
    # skill directory is reachable via two different SKILL_DIRS entries.
    (tmp_path / "skills").symlink_to(tmp_path / "workspace" / "skills")

    vet_all(tmp_path, ascii_only=True)
    out = capsys.readouterr().out

    assert out.count("=== shared_skill ===") == 1
    assert "1 skill(s) checked" in out
