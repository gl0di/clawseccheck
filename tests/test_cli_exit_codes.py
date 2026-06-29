"""Exit-code contracts for CLI operational failures (CLAWSECCHECK-B-054).

Verifies:
- --badge/--html/--sarif/--save on an unwritable path → rc != 0, file absent.
- --vet on a non-existent target → rc != 0.
- --vet on a valid skill target that yields PASS or UNKNOWN → rc == 0.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import Finding
from clawseccheck.cli import main

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
VULN = str(FIXTURES / "home_vuln")
BASE = ["--no-native", "--no-history"]


def _no_parent_path(tmp_path: Path, suffix: str) -> Path:
    """Return a path whose parent directory does not exist, so any write raises OSError."""
    return tmp_path / "no_such_dir" / ("output" + suffix)


# ---------------------------------------------------------------------------
# Artifact-writer failures: OSError on write → rc != 0 and file absent
# ---------------------------------------------------------------------------

def test_badge_write_failure_returns_nonzero(tmp_path, capsys):
    out = _no_parent_path(tmp_path, ".svg")
    rc = main(["--home", VULN] + BASE + ["--badge", str(out)])
    assert rc != 0
    assert not out.exists()


def test_badge_write_failure_emits_message(tmp_path, capsys):
    out = _no_parent_path(tmp_path, ".svg")
    main(["--home", VULN] + BASE + ["--badge", str(out)])
    assert "could not write badge" in capsys.readouterr().out


def test_html_write_failure_returns_nonzero(tmp_path, capsys):
    out = _no_parent_path(tmp_path, ".html")
    rc = main(["--home", VULN] + BASE + ["--html", str(out)])
    assert rc != 0
    assert not out.exists()


def test_html_write_failure_emits_message(tmp_path, capsys):
    out = _no_parent_path(tmp_path, ".html")
    main(["--home", VULN] + BASE + ["--html", str(out)])
    assert "could not write HTML report" in capsys.readouterr().out


def test_sarif_write_failure_returns_nonzero(tmp_path, capsys):
    out = _no_parent_path(tmp_path, ".sarif")
    rc = main(["--home", VULN] + BASE + ["--sarif", str(out)])
    assert rc != 0
    assert not out.exists()


def test_sarif_write_failure_emits_message(tmp_path, capsys):
    out = _no_parent_path(tmp_path, ".sarif")
    main(["--home", VULN] + BASE + ["--sarif", str(out)])
    assert "could not write SARIF" in capsys.readouterr().out


def test_save_write_failure_returns_nonzero(tmp_path, capsys):
    out = _no_parent_path(tmp_path, ".txt")
    rc = main(["--home", VULN] + BASE + ["--save", str(out)])
    assert rc != 0
    assert not out.exists()


def test_save_write_failure_emits_message(tmp_path, capsys):
    out = _no_parent_path(tmp_path, ".txt")
    main(["--home", VULN] + BASE + ["--save", str(out)])
    assert "could not save report" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# --vet: non-existent target → rc != 0
# ---------------------------------------------------------------------------

def test_vet_nonexistent_target_returns_nonzero(tmp_path, capsys):
    nonexistent = tmp_path / "no_such_skill_dir"
    rc = main(["--vet", str(nonexistent)])
    assert rc != 0


def test_vet_nonexistent_target_emits_hint(tmp_path, capsys):
    nonexistent = tmp_path / "no_such_skill_dir"
    main(["--vet", str(nonexistent)])
    out = capsys.readouterr().out
    # vet_skill emits the "could not assess" verdict for the missing path
    assert "could not assess" in out or "no skill found" in out


# ---------------------------------------------------------------------------
# --vet: valid target → rc == 0 (for both PASS and UNKNOWN assessments)
# ---------------------------------------------------------------------------

def test_vet_valid_skill_md_pass_returns_zero(tmp_path, capsys):
    """A benign SKILL.md returns PASS from vet_skill → rc == 0.

    The SKILL.md is placed in a named subdirectory so vet_skill uses that
    directory name (not the pytest tmp-dir name) as the skill name — the
    tmp-dir name contains 'test' which is edit-distance 2 from 'pytest' and
    would trigger the typosquat WARN check, changing rc to 1.
    """
    skill_parent = tmp_path / "clawsc_demo"
    skill_parent.mkdir()
    skill = skill_parent / "SKILL.md"
    skill.write_text(
        "---\nname: clawsc-demo\nversion: 0.1.0\n---\nThis is a safe skill.\n",
        encoding="utf-8",
    )
    rc = main(["--vet", str(skill)])
    assert rc == 0


def test_vet_valid_skill_dir_pass_returns_zero(tmp_path, capsys):
    """A benign skill directory returns PASS from vet_skill → rc == 0."""
    skill_dir = tmp_path / "safe_skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\nname: safe-skill\nversion: 0.1.0\n---\nThis is a safe skill.\n",
        encoding="utf-8",
    )
    rc = main(["--vet", str(skill_dir)])
    assert rc == 0


def test_vet_valid_target_unknown_returns_zero(tmp_path, monkeypatch, capsys):
    """Valid target that vets to UNKNOWN (inconclusive) must return rc == 0.

    UNKNOWN on an existing path is a legitimate audit result, not an
    operational failure — only a missing/unusable target returns rc != 0.
    """
    skill = tmp_path / "SKILL.md"
    skill.write_text("---\nname: test\nversion: 0.1.0\n---\n", encoding="utf-8")

    def _fake_vet_unknown(path: str) -> Finding:  # noqa: ARG001
        return Finding(
            id="B13",
            title="Installed skill / plugin safety",
            severity="HIGH",
            status="UNKNOWN",
            detail="scanning limits exceeded",
            fix="Reduce skill archive size.",
            framework="Supply Chain / ClawHavoc",
        )

    monkeypatch.setattr("clawseccheck.cli.vet_skill", _fake_vet_unknown)
    rc = main(["--vet", str(skill)])
    assert rc == 0


def test_vet_nonexistent_target_unknown_returns_nonzero(tmp_path, monkeypatch, capsys):
    """Non-existent target with UNKNOWN status must return rc != 0.

    Confirms the distinction: UNKNOWN + no path == failure; UNKNOWN + path exists == 0.
    """
    nonexistent = tmp_path / "ghost_skill.md"

    def _fake_vet_unknown(path: str) -> Finding:  # noqa: ARG001
        return Finding(
            id="B13",
            title="Installed skill / plugin safety",
            severity="HIGH",
            status="UNKNOWN",
            detail="no skill found at ghost_skill.md",
            fix="Point --vet at a skill dir or SKILL.md.",
            framework="Supply Chain / ClawHavoc",
        )

    monkeypatch.setattr("clawseccheck.cli.vet_skill", _fake_vet_unknown)
    rc = main(["--vet", str(nonexistent)])
    assert rc != 0


# ---------------------------------------------------------------------------
# Sanity: successful writes still return rc == 0
# ---------------------------------------------------------------------------

def test_badge_successful_write_returns_zero(tmp_path, capsys):
    out = tmp_path / "badge.svg"
    rc = main(["--home", VULN] + BASE + ["--badge", str(out)])
    assert rc == 0
    assert out.is_file()


def test_html_successful_write_returns_zero(tmp_path, capsys):
    out = tmp_path / "report.html"
    rc = main(["--home", VULN] + BASE + ["--html", str(out)])
    assert rc == 0
    assert out.is_file()


def test_sarif_successful_write_returns_zero(tmp_path, capsys):
    out = tmp_path / "report.sarif"
    rc = main(["--home", VULN] + BASE + ["--sarif", str(out)])
    assert rc == 0
    assert out.is_file()


def test_save_successful_write_returns_zero(tmp_path, capsys):
    out = tmp_path / "report.txt"
    rc = main(["--home", VULN] + BASE + ["--save", str(out)])
    assert rc == 0
    assert out.is_file()
