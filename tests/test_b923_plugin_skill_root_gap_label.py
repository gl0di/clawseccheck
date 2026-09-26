"""B-923 — a plugin skill-root discovery gap must name the PLUGIN, not the fixed "skills" leaf.

``collector.config_plugin_load_paths`` resolves ``plugins.load.paths`` entries, and
``collector._read_installed_skills`` unconditionally appends a literal ``/skills`` before
handing each one to the discovery walk (F-119: a path-loaded plugin bundles its skills
under ``<plugin>/skills/``). When that root cannot be stat'd/read/listed (a locked
directory, most commonly), ``skilldiscovery.iter_discovered_skill_dirs`` used to label the
gap with the ROOT's own basename — which, for every plugin-loaded root, is always the
literal string "skills", never the plugin's own name. Two different failing plugin roots
in the same run then rendered as the SAME ambiguous "skills" subject, with nothing to tell
them apart (CLAWSECCHECK-B-923).

Disclosure-only: the detection/verdict logic (UNKNOWN, a domain-tagged ``limit_hits``
entry, ``check_installed_skills``'s coverage-gap branch) was already correct before this
fix. Only the human-readable label changes.

Offline, read-only, stdlib only. Writes nothing outside ``tmp_path``.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from clawseccheck.checks import check_installed_skills
from clawseccheck.collector import collect
from clawseccheck.skilldiscovery import _discovery_gap_label, iter_discovered_skill_dirs

_POSIX_ONLY = pytest.mark.skipif(
    os.name != "posix", reason="POSIX permission bits only"
)
_SKIP_ROOT = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores the read bit"
)


@pytest.fixture
def unlock():
    """Restore directory modes even when an assertion fails (mirrors test_b549's fixture),
    so a red test never leaves an unreadable directory behind for the next one."""
    locked: list[Path] = []
    yield locked.append
    for d in locked:
        try:
            d.chmod(0o755)
        except OSError:
            pass


# --------------------------------------------------------------------- the bad fixture

@_POSIX_ONLY
@_SKIP_ROOT
def test_two_distinct_locked_plugin_roots_are_distinguishable(tmp_path, unlock):
    """The core repro: two different plugin directories, each bundling a locked
    ``skills/`` directory, must render as two DIFFERENT subjects — never the same bare
    "skills" twice."""
    plugin1 = tmp_path / "myplugin1"
    plugin2 = tmp_path / "myplugin2"
    (plugin1 / "skills").mkdir(parents=True)
    (plugin2 / "skills").mkdir(parents=True)
    os.chmod(plugin1 / "skills", 0o000)
    os.chmod(plugin2 / "skills", 0o000)
    unlock(plugin1 / "skills")
    unlock(plugin2 / "skills")

    hits1: list = []
    hits2: list = []
    list(iter_discovered_skill_dirs(plugin1 / "skills", allow_symlink_entries=False,
                                     limit_hits=hits1))
    list(iter_discovered_skill_dirs(plugin2 / "skills", allow_symlink_entries=False,
                                     limit_hits=hits2))

    assert hits1 and hits2, (hits1, hits2)
    assert any("myplugin1" in h for h in hits1), hits1
    assert any("myplugin2" in h for h in hits2), hits2
    # Neither collapses to the bare, ambiguous "skills" subject the bug reported.
    assert not any("'skills/" in h for h in hits1), hits1
    assert not any("'skills/" in h for h in hits2), hits2


@_POSIX_ONLY
@_SKIP_ROOT
def test_two_distinct_locked_plugin_roots_end_to_end_through_b13(tmp_path, unlock):
    """Same repro, through the real collector + B13 (``check_installed_skills``) —
    the consumer the fix actually needs to help. One real skill is present so the
    generic coverage-gap branch (not the empty-roster early return) is the one that
    renders the two gaps."""
    home = tmp_path / ".openclaw"
    good_skill = home / "skills" / "good-skill"
    good_skill.mkdir(parents=True)
    (good_skill / "SKILL.md").write_text(
        "---\nname: good-skill\ndescription: An ordinary helper.\n---\nHelper.\n",
        encoding="utf-8",
    )

    plugin1 = tmp_path / "myplugin1"
    plugin2 = tmp_path / "myplugin2"
    (plugin1 / "skills").mkdir(parents=True)
    (plugin2 / "skills").mkdir(parents=True)
    (home / "openclaw.json").write_text(json.dumps({
        "plugins": {"load": {"paths": [str(plugin1), str(plugin2)]}},
    }), encoding="utf-8")

    os.chmod(plugin1 / "skills", 0o000)
    os.chmod(plugin2 / "skills", 0o000)
    unlock(plugin1 / "skills")
    unlock(plugin2 / "skills")

    ctx = collect(home)
    finding = check_installed_skills(ctx)

    assert finding.status == "UNKNOWN", finding.detail
    assert "myplugin1" in finding.detail, finding.detail
    assert "myplugin2" in finding.detail, finding.detail
    assert "'skills/" not in finding.detail, finding.detail


# ------------------------------------------------------------- the extraDirs regression guard

@_POSIX_ONLY
@_SKIP_ROOT
def test_extra_dirs_shape_label_is_unchanged(tmp_path, unlock):
    """``skills.load.extraDirs`` roots: the configured path's own basename IS a real,
    distinguishing directory name (e.g. "extra") — the fix must not touch this shape."""
    extra = tmp_path / "extra"
    extra.mkdir()
    os.chmod(extra, 0o000)
    unlock(extra)

    hits: list = []
    list(iter_discovered_skill_dirs(extra, allow_symlink_entries=False, limit_hits=hits))

    assert hits
    assert any("extra" in h for h in hits), hits


def test_discovery_gap_label_unit_extra_dirs_shape_unchanged():
    """Unit-level pin on the helper directly: a genuinely distinguishing root basename
    passes through unchanged, at depth 0 and below."""
    assert _discovery_gap_label(Path("/tmp/extra"), 0) == "extra"
    assert _discovery_gap_label(Path("/tmp/some-skill"), 1) == "some-skill"


# --------------------------------------------------------------------------- edge cases

def test_discovery_gap_label_falls_back_to_parent_for_the_skills_leaf():
    """The core rule, isolated: basename "skills" at depth 0 -> parent's name."""
    assert _discovery_gap_label(Path("/tmp/myplugin1/skills"), 0) == "myplugin1"
    assert _discovery_gap_label(Path("/tmp/myplugin2/skills"), 0) == "myplugin2"


def test_discovery_gap_label_only_special_cases_depth_zero():
    """A DEEPER node literally named "skills" (an unusual, but real, user-chosen skill
    directory name) is NOT the plugin-loader convention this fix targets, and already
    carries distinguishing context from the walk — must not be rewritten to its parent."""
    assert _discovery_gap_label(Path("/tmp/root/skills"), 1) == "skills"


def test_discovery_gap_label_degenerate_plugin_dir_itself_named_skills():
    """Edge case (per the task's own suggestion): a plugin directory that is ITSELF named
    "skills" (``plugins.load.paths: [".../skills"]``, resolving to ``.../skills/skills``).
    The parent's name is ALSO "skills", so the fallback cannot disambiguate this one
    degenerate shape -- accepted, not chased further (see the helper's own docstring):
    the result is the same "skills" the un-fixed code already produced, never worse."""
    assert _discovery_gap_label(Path("/tmp/skills/skills"), 0) == "skills"


@_POSIX_ONLY
@_SKIP_ROOT
def test_degenerate_plugin_dir_named_skills_does_not_crash(tmp_path, unlock):
    """Same edge case, live: must not raise, and stays a (sensibly accepted, documented)
    ambiguous "skills" rather than crashing or mislabeling."""
    weird_plugin = tmp_path / "skills"
    weird_root = weird_plugin / "skills"
    weird_root.mkdir(parents=True)
    os.chmod(weird_root, 0o000)
    unlock(weird_root)

    hits: list = []
    list(iter_discovered_skill_dirs(weird_root, allow_symlink_entries=False, limit_hits=hits))

    assert hits
    assert any("'skills/" in h for h in hits), hits


@_POSIX_ONLY
@_SKIP_ROOT
def test_standard_skills_root_gap_also_benefits_from_the_parent_fallback(tmp_path, unlock):
    """Not just plugins.load.paths: any load root whose basename is the SKILL_DIRS
    convention ("skills", "workspace/skills", "workspace-home/skills") is equally
    non-distinguishing on its own -- a path that ends in "/skills" for a reason OTHER
    than the plugin-loader convention. The fallback improves this shape too, harmlessly."""
    home = tmp_path / ".openclaw"
    skills_root = home / "skills"
    skills_root.mkdir(parents=True)
    os.chmod(skills_root, 0o000)
    unlock(skills_root)

    hits: list = []
    list(iter_discovered_skill_dirs(skills_root, allow_symlink_entries=False, limit_hits=hits))

    assert hits
    assert any(".openclaw" in h for h in hits), hits


# --------------------------------------------------------------------------- the clean fixture

def test_discovery_stays_quiet_and_unlabeled_on_a_healthy_plugin_root(tmp_path):
    """Golden Rule #5: an ordinary, fully-readable plugin skills root gains no gap
    disclosure at all, and the population is found normally."""
    plugin_skills = tmp_path / "myplugin" / "skills" / "bundled-skill"
    plugin_skills.mkdir(parents=True)
    (plugin_skills / "SKILL.md").write_text(
        "---\nname: bundled-skill\ndescription: An ordinary bundled helper.\n---\nHelper.\n",
        encoding="utf-8",
    )

    hits: list = []
    found = list(iter_discovered_skill_dirs(
        tmp_path / "myplugin" / "skills", allow_symlink_entries=False, limit_hits=hits))

    assert hits == [], hits
    assert [d.name for d, _t in found] == ["bundled-skill"]
