"""B-521 (item 3) -- `--vet-all` must disclose a self-excluded skill the way the text
inventory (report.py, B-507) already does.

`sweep_installed_skills`/`vet_all` read straight off `ctx.installed_skill_dirs`, which
already excludes ClawSecCheck's own content-verified install (B-265) -- so the sweep
table and its "N skill(s) checked" tally were silently short by one, with no trace of
why, while `report.py`'s text inventory correctly named the exclusion
("N installed - M self-excluded"). This file pins the fix (SkillSweep.self_excluded_skills
+ its disclosure line, reusing report.py's exact wording) and adds the cross-surface
assertion the task calls out: for one home, `--sbom`'s skills + self_excluded_skills,
the text inventory's roster, and `--vet-all`'s roster must all agree on the same two
populations -- one real skill, one withheld skill.

Offline, read-only, stdlib only; everything is built under pytest's tmp_path. The
self-exclusion fixture carries the real engine markers (`_OWN_ENGINE_MARKERS`) in a
`checks/` dir, per B-265 -- a directory merely NAMED clawseccheck is not excluded.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.cli import _sweep_summary_lines, main, sweep_installed_skills, vet_all
from clawseccheck.collector import _OWN_ENGINE_MARKERS, collect
from clawseccheck.report import build_inventory
from clawseccheck.sbom import build_sbom


def _cfg(home: Path) -> None:
    home.mkdir(parents=True, exist_ok=True)
    cfg = home / "openclaw.json"
    cfg.write_text('{"gateway": {"bind": "127.0.0.1"}}', encoding="utf-8")
    cfg.chmod(0o600)


def _skill_md(d: Path, name: str) -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: A helper skill.\n---\n\nDoes something local.\n",
        encoding="utf-8",
    )


def _write_own_engine(skill_dir: Path) -> None:
    """A genuine, content-verified ClawSecCheck install under `skill_dir` (B-265) --
    same idiom as tests/test_b507_skills_disclosure.py's `_write_own_engine`."""
    _skill_md(skill_dir, "clawseccheck")
    checks = skill_dir / "checks"
    checks.mkdir(parents=True, exist_ok=True)
    (checks / "_engine.py").write_text("\n".join(_OWN_ENGINE_MARKERS), encoding="utf-8")


def _two_skill_home(tmp_path: Path) -> Path:
    """2 skills on disk: the genuine own install (self-excluded) + 1 real skill --
    the exact reproduction shape the task describes."""
    home = tmp_path / ".openclaw"
    _cfg(home)
    _write_own_engine(home / "skills" / "clawseccheck")
    _skill_md(home / "skills" / "notes-helper", "notes-helper")
    return home


# ------------------------------------------------------------- SkillSweep itself

def test_sweep_carries_the_self_excluded_name(tmp_path):
    home = _two_skill_home(tmp_path)
    ctx = collect(home)
    sweep = sweep_installed_skills(home, narrate=False, ctx=ctx)
    assert sweep.self_excluded_skills == ["clawseccheck"]
    # the real skill is still swept normally
    assert [n for n, _s, _e in sweep.rows] == ["notes-helper"]


def test_summary_lines_disclose_the_exclusion(tmp_path):
    home = _two_skill_home(tmp_path)
    ctx = collect(home)
    sweep = sweep_installed_skills(home, narrate=False, ctx=ctx)
    lines = _sweep_summary_lines(sweep, ascii_only=True)
    text = "\n".join(lines)
    assert "1 skill(s) checked" in text
    assert "clawseccheck" in text
    assert "not graded" in text or "self-excluded" in text


# ---------------------------------------------------------------- end-to-end --vet-all

def test_vet_all_cli_discloses_the_exclusion(tmp_path, capsys):
    home = _two_skill_home(tmp_path)
    rc = vet_all(home, ascii_only=True)
    out = capsys.readouterr().out
    assert rc == 0
    assert "notes-helper" in out
    assert "1 skill(s) checked" in out
    assert "clawseccheck" in out, "the self-excluded skill must be named, not silently dropped"
    assert "not graded" in out or "self-excluded" in out


def test_vet_all_via_main_cli_discloses_the_exclusion(tmp_path, capsys):
    """Same as above through the real `--vet-all` CLI entry point (main()), matching
    the reproduction the task describes end to end."""
    home = _two_skill_home(tmp_path)
    rc = main(["--vet-all", "--home", str(home), "--ascii"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "1 skill(s) checked" in out
    assert "clawseccheck" in out
    assert "not graded" in out or "self-excluded" in out


# --------------------------------------------------------- cross-surface agreement

def test_sbom_text_inventory_and_vet_all_agree_on_the_same_two_populations(tmp_path, capsys):
    """The deliverable the task asks for: one home, three surfaces, one shared fact --
    1 real skill + 1 self-excluded skill. No surface may silently drop the withheld one
    from its own accounting, and no surface may invent a different total."""
    home = _two_skill_home(tmp_path)
    ctx = collect(home)

    # Surface 1: --sbom (machine BOM, B-521 item 1/2)
    bom = build_sbom(ctx)
    sbom_real = {s["name"] for s in bom["skills"]}
    sbom_excluded = set(bom["self_excluded_skills"])
    assert bom["complete"] is False  # something was withheld

    # Surface 2: text inventory (report.py, B-507 -- already correct)
    inv = build_inventory([], ctx)
    inv_real = {s["name"] for s in inv["skills"]}
    inv_excluded = set(inv["self_excluded"])

    # Surface 3: --vet-all (this fix)
    sweep = sweep_installed_skills(home, narrate=False, ctx=ctx)
    vetall_real = {n for n, _s, _e in sweep.rows}
    vetall_excluded = set(sweep.self_excluded_skills)

    expected_real = {"notes-helper"}
    expected_excluded = {"clawseccheck"}

    assert sbom_real == inv_real == vetall_real == expected_real
    assert sbom_excluded == inv_excluded == vetall_excluded == expected_excluded

    # And the same fact reaches the actual --vet-all stdout, not just the dataclass.
    rc = main(["--vet-all", "--home", str(home), "--ascii"])
    out = capsys.readouterr().out
    assert rc == 0
    for name in expected_real | expected_excluded:
        assert name in out
