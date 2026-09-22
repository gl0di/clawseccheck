"""Tests for scripts/bump.py — the lock-step version bumper.

Exercises the version math, the Conventional-Commits level suggestion, and an
end-to-end write against temp copies of the four version sources (never the real
repo files). Offline, stdlib.
"""
from __future__ import annotations

import importlib.util
import subprocess
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
    (["fix!: x"], "major"),
    (["refactor: x\n\nBREAKING CHANGE: y"], "major"),
    (["refactor: x\n\nBREAKING-CHANGE: y"], "major"),
    (["chore: nothing notable"], "patch"),
    ([], "patch"),
    (["feat: a", "feat: b", "fix: c"], "minor"),
])
def test_suggest_level(commits, expected):
    assert bump._suggest_level(commits) == expected


def test_suggest_level_ignores_bare_prose_mention_of_breaking_change():
    """CLAWSECCHECK-B-858: a commit body that merely *talks about* the marker must not
    itself be read as one -- including when line-wrapping alone puts the words at the
    start of a line, as happened in this project's own commit 33d78af. A regression to
    the old bare-substring check (`"BREAKING CHANGE" in c`) turns this red."""
    commits = [
        "fix: resolve bump.py --suggest's release base against main, not HEAD\n\n"
        "Also disclose explicitly when zero `!:`/\n"
        "BREAKING CHANGE markers are found, rather than letting their absence\n"
        "silently read as \"nothing breaking shipped\" -- an absent signal is not\n"
        "a measured negative."
    ]
    assert bump._suggest_level(commits) == "patch"


# ---- dev->main release-base resolution (C-493) -----------------------------
#
# A release tag lands on a merge commit in `main`; `dev` never contains it (the
# project's own dev->main flow — routine work lands on dev, main only moves at release
# time and dev never merges it back). `git describe --tags --abbrev=0` run bare on dev
# therefore walks dev's OWN ancestry and can land on a stale tag a later release already
# superseded — measured on the real repo as 438 commits counted vs. the correct 410.


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def _make_dev_main_repo(tmp_path: Path) -> "tuple[Path, list[str]]":
    """A repo shaped exactly like the reported defect: `dev` branches off `main`, a
    release is cut by merging `dev` into `main` and tagging that merge commit, and `dev`
    then keeps moving forward WITHOUT ever merging `main` back — so the tag is not an
    ancestor of dev's tip. Returns `(repo, subjects_of_the_post_release_commits)`."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    (repo / "f.txt").write_text("0\n", encoding="utf-8")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-q", "-m", "chore: init")

    _git(repo, "checkout", "-q", "-b", "dev")
    for i in range(1, 4):
        (repo / "f.txt").write_text(f"{i}\n", encoding="utf-8")
        _git(repo, "add", "f.txt")
        _git(repo, "commit", "-q", "-m", f"feat: pre-release change {i}")

    _git(repo, "checkout", "-q", "main")
    _git(repo, "merge", "-q", "--no-ff", "-m", "Merge dev for v1.0.0 release", "dev")
    _git(repo, "tag", "v1.0.0")

    _git(repo, "checkout", "-q", "dev")
    shipped_subjects = []
    for i in range(4, 7):
        (repo / "f.txt").write_text(f"{i}\n", encoding="utf-8")
        _git(repo, "add", "f.txt")
        subject = f"fix: post-release change {i}"
        _git(repo, "commit", "-q", "-m", subject)
        shipped_subjects.append(subject)
    return repo, shipped_subjects


def test_bare_git_describe_cannot_see_the_tag_on_this_repo_shape(tmp_path):
    """Confirms the repro itself: a bare `git describe` from dev's own HEAD cannot find
    the release tag at all on this topology, because dev never contains the merge commit
    it landed on. Without this, the fix below could be "passing" against a shape that
    never actually reproduced the bug."""
    repo, _ = _make_dev_main_repo(tmp_path)
    result = subprocess.run(
        ["git", "describe", "--tags", "--abbrev=0"],
        cwd=repo, capture_output=True, text=True,
    )
    assert result.returncode != 0, (
        "git describe found the tag from dev's own ancestry -- this repo shape does not "
        "reproduce the defect, so the fix isn't actually being exercised below"
    )


def test_resolve_release_base_finds_the_tag_via_main(tmp_path, monkeypatch):
    repo, _ = _make_dev_main_repo(tmp_path)
    monkeypatch.setattr(bump, "ROOT", repo)

    tag, ref = bump._resolve_release_base()
    assert tag == "v1.0.0"
    assert ref == "main"


def test_commits_since_last_tag_counts_only_whats_not_yet_released(tmp_path, monkeypatch):
    repo, shipped_subjects = _make_dev_main_repo(tmp_path)
    monkeypatch.setattr(bump, "ROOT", repo)

    commits, base_tag, compared_against = bump._commits_since_last_tag()
    assert base_tag == "v1.0.0"
    assert compared_against == "main"
    # Newest-first from `git log`; compare as a set so ordering isn't over-specified.
    assert {c.splitlines()[0] for c in commits} == set(shipped_subjects)
    assert len(commits) == 3  # NOT the 6 total commits on dev (init excluded either way)


def test_resolve_release_base_falls_back_to_head_with_no_main_branch(tmp_path, monkeypatch):
    """A repo with no dev->main split at all (the old, still-correct case): no `main`
    and no `origin/main` to try, so it falls back to describing bare HEAD."""
    repo = tmp_path / "solo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "trunk")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    (repo / "f.txt").write_text("0\n", encoding="utf-8")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-q", "-m", "chore: init")
    _git(repo, "tag", "v0.1.0")
    (repo / "f.txt").write_text("1\n", encoding="utf-8")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-q", "-m", "fix: a")

    monkeypatch.setattr(bump, "ROOT", repo)
    tag, ref = bump._resolve_release_base()
    assert tag == "v0.1.0"
    assert ref == "HEAD"


def test_resolve_release_base_returns_none_with_no_tags_at_all(tmp_path, monkeypatch):
    repo = tmp_path / "no_tags"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "trunk")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    (repo / "f.txt").write_text("0\n", encoding="utf-8")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-q", "-m", "chore: init")

    monkeypatch.setattr(bump, "ROOT", repo)
    tag, ref = bump._resolve_release_base()
    assert tag is None
    assert ref == "HEAD"


# ---- --suggest output: relabeled base + the "no markers found" disclosure --


def test_suggest_prints_the_resolved_base_and_relabeled_count(tmp_path, monkeypatch, capsys):
    init, skill, chg, threat = _seed(tmp_path)
    _point_module_at(monkeypatch, tmp_path, init, skill, chg, threat)
    monkeypatch.setattr(
        bump, "_commits_since_last_tag",
        lambda: (["feat!: drop py38"], "v1.8.2", "main"),
    )

    rc = bump.main(["--suggest"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "compared against: v1.8.2  (resolved via main)" in out
    assert "commits not in v1.8.2: 1" in out
    assert "suggested bump: major" in out
    # A real breaking marker was found -- the "no markers" disclosure must NOT appear.
    assert "no `!:` or `BREAKING CHANGE:` markers found" not in out


def test_suggest_discloses_when_no_breaking_markers_are_found(tmp_path, monkeypatch, capsys):
    init, skill, chg, threat = _seed(tmp_path)
    _point_module_at(monkeypatch, tmp_path, init, skill, chg, threat)
    monkeypatch.setattr(
        bump, "_commits_since_last_tag",
        lambda: (["feat: a", "fix: b"], "v1.8.2", "main"),
    )

    rc = bump.main(["--suggest"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "suggested bump: minor" in out
    assert (
        "no `!:` or `BREAKING CHANGE:` markers found in 2 commit(s) -- a major bump "
        "will not be suggested even if one is warranted." in out
    )


def test_suggest_handles_no_tags_found_at_all(tmp_path, monkeypatch, capsys):
    init, skill, chg, threat = _seed(tmp_path)
    _point_module_at(monkeypatch, tmp_path, init, skill, chg, threat)
    monkeypatch.setattr(
        bump, "_commits_since_last_tag",
        lambda: (["chore: nothing"], None, "HEAD"),
    )

    rc = bump.main(["--suggest"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "compared against: no tags found -- considering all of HEAD's history" in out
    assert "commits: 1" in out


# ---- end-to-end write against temp sources ---------------------------------


def _seed(tmp_path: Path):
    init = tmp_path / "clawseccheck" / "__init__.py"
    init.parent.mkdir(parents=True)
    init.write_text('__version__ = "1.8.2"\n__released__ = "2026-06-23"\n', encoding="utf-8")
    skill = tmp_path / "SKILL.md"
    skill.write_text("---\nname: clawseccheck\nversion: 1.8.2\n---\n", encoding="utf-8")
    chg = tmp_path / "CHANGELOG.md"
    chg.write_text("# Changelog\n\n## [1.8.2] — 2026-06-23\n\nold entry\n", encoding="utf-8")
    threat = tmp_path / "docs" / "THREAT_COVERAGE.md"
    threat.parent.mkdir(parents=True)
    threat.write_text("# Threat coverage matrix\n\nUpdated 2026-06-23 for v1.8.2.\n", encoding="utf-8")
    return init, skill, chg, threat


def _point_module_at(monkeypatch, tmp_path, init, skill, chg, threat):
    monkeypatch.setattr(bump, "ROOT", tmp_path)
    monkeypatch.setattr(bump, "INIT", init)
    monkeypatch.setattr(bump, "SKILL", skill)
    monkeypatch.setattr(bump, "CHANGELOG", chg)
    monkeypatch.setattr(bump, "THREAT_COVERAGE", threat)


def test_every_bump_target_path_is_redirected_into_tmp(tmp_path, monkeypatch):
    """Guard the isolation itself.

    `bump.py` writes to module-level Path constants. `_point_module_at` redirects them at
    tmp_path — but only the ones it knows about. Adding a new target to bump.py without
    adding it here makes the suite write into the REAL repo: that is exactly how a full
    run started stamping "Updated 2026-07-01 for v1.8.3" into the working tree's
    docs/THREAT_COVERAGE.md. Tests must write nothing outside tmp_path, so enumerate the
    module's write targets and prove every one of them was redirected.
    """
    seeded = _seed(tmp_path)
    _point_module_at(monkeypatch, tmp_path, *seeded)

    targets = {
        name: value
        for name, value in vars(bump).items()
        if isinstance(value, Path) and name.isupper()
    }
    assert targets, "expected bump.py to expose its write targets as module-level Paths"

    escaped = {
        name: str(path) for name, path in targets.items()
        if tmp_path not in path.parents and path != tmp_path
    }
    assert not escaped, (
        "these bump.py paths still point at the real repo — add them to _point_module_at "
        f"(and seed them in _seed): {escaped}"
    )


def test_bump_patch_updates_all_four_sources(tmp_path, monkeypatch):
    init, skill, chg, threat = _seed(tmp_path)
    _point_module_at(monkeypatch, tmp_path, init, skill, chg, threat)

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
    init, skill, chg, threat = _seed(tmp_path)
    _point_module_at(monkeypatch, tmp_path, init, skill, chg, threat)
    before = (init.read_text(), skill.read_text(), chg.read_text())

    rc = bump.main(["minor", "--dry-run"])
    assert rc == 0
    assert (init.read_text(), skill.read_text(), chg.read_text()) == before
    assert "dry-run" in capsys.readouterr().out


def test_set_rejects_bad_semver(tmp_path, monkeypatch):
    init, skill, chg, threat = _seed(tmp_path)
    _point_module_at(monkeypatch, tmp_path, init, skill, chg, threat)
    with pytest.raises(SystemExit):
        bump.main(["--set", "1.8"])


def test_refuses_same_version(tmp_path, monkeypatch):
    init, skill, chg, threat = _seed(tmp_path)
    _point_module_at(monkeypatch, tmp_path, init, skill, chg, threat)
    with pytest.raises(SystemExit):
        bump.main(["--set", "1.8.2"])


def test_bad_date_rejected(tmp_path, monkeypatch):
    init, skill, chg, threat = _seed(tmp_path)
    _point_module_at(monkeypatch, tmp_path, init, skill, chg, threat)
    with pytest.raises(SystemExit):
        bump.main(["patch", "--date", "not-a-date"])
