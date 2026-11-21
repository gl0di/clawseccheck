"""C-809 - no file named SKILL.md is tracked under fixtures/.

Skill catalogs index every file named exactly ``SKILL.md`` in a public repository as an
installable skill, and on 2026-11-20 one listed about 200 of these deliberately unsafe test
fixtures under this repository's publisher. The content lives in ``tests/fixture_skill_md/``
and ``tests/_fixtureskills.py`` writes it back, gitignored, before the suite reads the corpus.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import _fixtureskills as fs

REPO = Path(__file__).resolve().parent.parent


def _git_ls(*args) -> "list[str]":
    try:
        out = subprocess.run(["git", "ls-files", "-z", *args], cwd=REPO, capture_output=True,
                             check=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        pytest.skip(f"git unavailable: {exc}")
    return [p for p in out.decode("utf-8", "surrogateescape").split("\0") if p]


def test_no_skill_md_is_tracked_outside_the_root_skill():
    tracked = [p for p in _git_ls() if Path(p).name.lower() == "skill.md" and p != "SKILL.md"]
    assert tracked == [], (
        "a SKILL.md other than the root skill is tracked; catalogs would list it as an "
        f"installable skill. Move it to tests/fixture_skill_md/ as SKILL.md.fixture: {tracked}")


def test_the_generated_files_are_ignored_by_git():
    probe = "fixtures/clean_x/skills/y/SKILL.md"
    out = subprocess.run(["git", "check-ignore", "-q", "--no-index", probe], cwd=REPO,
                         capture_output=True, timeout=60)
    assert out.returncode == 0, f"{probe} is not gitignored"


def test_every_source_is_materialized_byte_for_byte():
    srcs = fs.sources()
    assert len(srcs) >= 300  # 365 on 2026-11-20; a collapse here means the mirror moved
    for src in srcs:
        dst = fs.target_for(src)
        assert dst.is_file(), dst
        assert dst.read_bytes() == src.read_bytes(), dst


def test_every_source_sits_inside_a_fixture_home_and_the_mirror_holds_no_skill_md():
    for src in fs.sources():
        rel = src.parent.relative_to(fs.MIRROR)
        # >= 1: a --vet fixture is itself a skill directory (fixtures/bad_b42_gyp_inline_action/SKILL.md)
        assert len(rel.parts) >= 1, f"{src}: a mirror source must sit inside a fixture"
        assert not (src.parent / "SKILL.md").exists(), "a real SKILL.md slipped into the mirror"


def test_a_fixture_home_made_only_of_skill_md_files_is_recreated(tmp_path, monkeypatch):
    """43 fixture homes held nothing but SKILL.md files, so git keeps no directory for them
    and a fresh clone lacks the whole home; materialize() must create the path."""
    mirror = tmp_path / "mirror" / "bad_only_skill" / "skills" / "x"
    mirror.mkdir(parents=True)
    (mirror / fs.SOURCE_NAME).write_text("---\nname: x\n---\n", encoding="utf-8")
    corpus = tmp_path / "fixtures"
    corpus.mkdir()
    monkeypatch.setattr(fs, "MIRROR", tmp_path / "mirror")
    monkeypatch.setattr(fs, "FIXTURES", corpus)
    monkeypatch.setattr(fs, "_tracked_skill_md", lambda: set())
    assert fs.materialize() == 1
    assert (corpus / "bad_only_skill" / "skills" / "x" / "SKILL.md").read_text() == "---\nname: x\n---\n"


def test_materialize_is_idempotent_and_restores_a_changed_file():
    src = fs.sources()[0]
    dst = fs.target_for(src)
    assert fs.materialize() == 0
    original = dst.read_bytes()
    try:
        dst.write_bytes(b"tampered")
        assert fs.materialize() == 1
        assert dst.read_bytes() == original
    finally:
        if dst.read_bytes() != original:
            dst.write_bytes(original)
