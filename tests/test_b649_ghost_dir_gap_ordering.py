"""CLAWSECCHECK-B-649 fix round 1, defect 1: a home whose ONLY skill-shaped directory
has a broken manifest (a dangling `SKILL.md` symlink, or a FIFO) must not read as "no
installed skills, nothing to report" from `check_installed_skill_content_coverage`
(B395).

Before this fix, B395 tested `not ctx.installed_skills` BEFORE `gaps`: a sole ghost
directory leaves `ctx.installed_skills` empty (discovery's fall-through never yields
it — see `iter_discovered_skill_dirs`'s own docstring in skilldiscovery.py) while
`ctx.skill_coverage_gaps` is populated via `collector._note_unreadable_manifest`, so
the check fell into the "nothing to check" UNKNOWN — non-degraded, and worded as if
there were no skills at all — instead of the degraded one. That directly contradicts
`check_installed_skills` (B13), which for the identical state says "...could not be
assessed... This is not the same as having no skills installed" (see
`checks/_vet.py::check_installed_skills`'s own `unassessed` branch).

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import os
from pathlib import Path

from clawseccheck.checks import check_installed_skill_content_coverage
from clawseccheck.collector import collect


def _mkhome(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir(parents=True)
    (home / "openclaw.json").write_text('{"gateway": {"bind": "127.0.0.1"}}', encoding="utf-8")
    return home


def _skill(skills: Path, name: str, *, dangling: bool = False, fifo: bool = False) -> Path:
    d = skills / name
    d.mkdir(parents=True)
    if dangling:
        (d / "SKILL.md").symlink_to("__missing__.md")
    elif fifo:
        os.mkfifo(d / "SKILL.md")
    else:
        (d / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: A helper skill.\n---\nHelper.\n",
            encoding="utf-8",
        )
    return d


# --------------------------------------------------------------- 1. the repro itself

def test_sole_ghost_dir_is_degraded_not_nothing_to_report(tmp_path):
    """The exact reproduction: `ghost` is the ONLY skill-shaped directory, and its own
    `SKILL.md` is a dangling symlink. `installed_skills` is empty, but a real gap was
    recorded — B395 must not claim there is nothing to report."""
    home = _mkhome(tmp_path)
    skills = home / "workspace" / "skills"
    _skill(skills, "ghost", dangling=True)

    ctx = collect(home)
    # Non-vacuity: the ghost dir really did leave installed_skills empty while still
    # recording a gap — otherwise this test would not be exercising the ordering bug.
    assert ctx.installed_skills == {}
    assert "ghost" in ctx.skill_coverage_gaps

    b395 = check_installed_skill_content_coverage(ctx)
    assert b395.status == "UNKNOWN", b395.detail
    assert b395.engine_degraded is True
    assert "ghost" in b395.detail, b395.detail
    # The old "nothing to check" phrasing must not survive under the new status.
    assert "there is no" not in b395.detail, b395.detail
    assert "No installed third-party skills found" not in b395.detail, b395.detail


def test_sole_fifo_manifest_dir_is_also_degraded(tmp_path):
    """Same fall-through, the other adversarial shape (`_exists_as_entry` is
    `lstat`-only, so a FIFO takes the identical path as a dangling symlink)."""
    home = _mkhome(tmp_path)
    skills = home / "workspace" / "skills"
    _skill(skills, "pipedream", fifo=True)

    ctx = collect(home)
    assert ctx.installed_skills == {}
    assert "pipedream" in ctx.skill_coverage_gaps

    b395 = check_installed_skill_content_coverage(ctx)
    assert b395.status == "UNKNOWN", b395.detail
    assert b395.engine_degraded is True
    assert "pipedream" in b395.detail, b395.detail


# --------------------------------------------------------- 2. positive control (PASS)

def test_clean_single_skill_still_passes(tmp_path):
    """Control: an ordinary, fully readable skill must still PASS — the reordering
    must not turn every run degraded."""
    home = _mkhome(tmp_path)
    skills = home / "workspace" / "skills"
    _skill(skills, "goodskill")

    ctx = collect(home)
    assert sorted(ctx.installed_skills) == ["goodskill"]
    assert ctx.skill_coverage_gaps == {}

    b395 = check_installed_skill_content_coverage(ctx)
    assert b395.status == "PASS", b395.detail
    assert b395.engine_degraded is False


# ------------------------------------------------- 3. the UNKNOWN, non-degraded path

def test_genuinely_no_skills_stays_non_degraded_unknown(tmp_path):
    """Control: a home with NO skill-shaped directory at all (no ghost, no gap) must
    keep the honest "nothing to check" UNKNOWN — `engine_degraded` stays False,
    matching B13's own "No installed third-party skills found" branch (B-661)."""
    home = _mkhome(tmp_path)
    (home / "workspace" / "skills").mkdir(parents=True)

    ctx = collect(home)
    assert ctx.installed_skills == {}
    assert ctx.skill_coverage_gaps == {}

    b395 = check_installed_skill_content_coverage(ctx)
    assert b395.status == "UNKNOWN", b395.detail
    assert b395.engine_degraded is False
    assert "No installed third-party skills found to inspect" in b395.detail, b395.detail


# ---------------------------------------------- 4. gap survives beside a real skill

def test_ghost_beside_a_readable_sibling_is_still_degraded(tmp_path):
    """The gap must still surface when `installed_skills` is NON-empty too — the fix
    must not accidentally depend on the population being empty."""
    home = _mkhome(tmp_path)
    skills = home / "workspace" / "skills"
    _skill(skills, "goodskill")
    _skill(skills, "ghost", dangling=True)

    ctx = collect(home)
    assert sorted(ctx.installed_skills) == ["goodskill"]
    assert "ghost" in ctx.skill_coverage_gaps

    b395 = check_installed_skill_content_coverage(ctx)
    assert b395.status == "UNKNOWN", b395.detail
    assert b395.engine_degraded is True
    assert "ghost" in b395.detail, b395.detail
