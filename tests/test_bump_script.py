"""Tests for scripts/bump.py — the lock-step version bumper.

Exercises the version math, the Conventional-Commits level suggestion, and an
end-to-end write against temp copies of the four version sources (never the real
repo files). Offline, stdlib.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_BUMP_PATH = Path(__file__).resolve().parent.parent / "scripts" / "bump.py"
_spec = importlib.util.spec_from_file_location("clawseccheck_bump", _BUMP_PATH)
bump = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bump)


# ---- version math ----------------------------------------------------------


@pytest.mark.parametrize("cur,level,expected", [
    ("1.8.2", "patch", "1.8.3"),
    ("1.8.2", "minor", "1.9.0"),
    ("1.8.2", "major", "2.0.0"),
    ("0.30.0", "patch", "0.30.1"),
    ("9.9.9", "major", "10.0.0"),
])
def test_next_version(cur, level, expected):
    assert bump._next_version(cur, level) == expected


# ---- Conventional-Commits level suggestion ---------------------------------


@pytest.mark.parametrize("commits,expected", [
    (["fix: a", "docs: b"], "patch"),
    (["feat: a", "fix: b"], "minor"),
    (["feat(ci)!: drop py38"], "major"),
    (["refactor: x\n\nBREAKING CHANGE: y"], "major"),
    (["chore: nothing notable"], "patch"),
    ([], "patch"),
    (["feat: a", "feat: b", "fix: c"], "minor"),
])
def test_suggest_level(commits, expected):
    assert bump._suggest_level(commits) == expected


# ---- end-to-end write against temp sources ---------------------------------


def _seed(tmp_path: Path):
    init = tmp_path / "clawseccheck" / "__init__.py"
    init.parent.mkdir(parents=True)
    init.write_text('__version__ = "1.8.2"\n__released__ = "2026-06-23"\n', encoding="utf-8")
    skill = tmp_path / "SKILL.md"
    skill.write_text("---\nname: clawseccheck\nversion: 1.8.2\n---\n", encoding="utf-8")
    chg = tmp_path / "CHANGELOG.md"
    chg.write_text("# Changelog\n\n## [1.8.2] — 2026-06-23\n\nold entry\n", encoding="utf-8")
    return init, skill, chg


def _point_module_at(monkeypatch, tmp_path, init, skill, chg):
    monkeypatch.setattr(bump, "ROOT", tmp_path)
    monkeypatch.setattr(bump, "INIT", init)
    monkeypatch.setattr(bump, "SKILL", skill)
    monkeypatch.setattr(bump, "CHANGELOG", chg)


def test_bump_patch_updates_all_four_sources(tmp_path, monkeypatch):
    init, skill, chg = _seed(tmp_path)
    _point_module_at(monkeypatch, tmp_path, init, skill, chg)

    rc = bump.main(["patch", "--date", "2026-07-01"])
    assert rc == 0

    assert '__version__ = "1.8.3"' in init.read_text()
    assert '__released__ = "2026-07-01"' in init.read_text()
    assert "version: 1.8.3" in skill.read_text()
    chg_text = chg.read_text()
    # New stub inserted ABOVE the old entry.
    assert chg_text.index("## [1.8.3] — 2026-07-01") < chg_text.index("## [1.8.2]")
    assert "old entry" in chg_text  # previous content preserved


def test_dry_run_writes_nothing(tmp_path, monkeypatch, capsys):
    init, skill, chg = _seed(tmp_path)
    _point_module_at(monkeypatch, tmp_path, init, skill, chg)
    before = (init.read_text(), skill.read_text(), chg.read_text())

    rc = bump.main(["minor", "--dry-run"])
    assert rc == 0
    assert (init.read_text(), skill.read_text(), chg.read_text()) == before
    assert "dry-run" in capsys.readouterr().out


def test_set_rejects_bad_semver(tmp_path, monkeypatch):
    init, skill, chg = _seed(tmp_path)
    _point_module_at(monkeypatch, tmp_path, init, skill, chg)
    with pytest.raises(SystemExit):
        bump.main(["--set", "1.8"])


def test_refuses_same_version(tmp_path, monkeypatch):
    init, skill, chg = _seed(tmp_path)
    _point_module_at(monkeypatch, tmp_path, init, skill, chg)
    with pytest.raises(SystemExit):
        bump.main(["--set", "1.8.2"])


def test_bad_date_rejected(tmp_path, monkeypatch):
    init, skill, chg = _seed(tmp_path)
    _point_module_at(monkeypatch, tmp_path, init, skill, chg)
    with pytest.raises(SystemExit):
        bump.main(["patch", "--date", "not-a-date"])
