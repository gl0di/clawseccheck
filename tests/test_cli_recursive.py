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
