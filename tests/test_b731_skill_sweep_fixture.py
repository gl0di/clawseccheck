"""B-731 — a shipped fixture HOME that actually carries installed skills.

Both canonical reference homes (``fixtures/home_safe`` / ``fixtures/home_vuln``) have no
``skills/`` directory at all, so any regression test built around them (a byte-identical
``--full`` snapshot, a doc-stat regen, ...) never renders the per-skill SKILL SWEEP
narration `cli.sweep_installed_skills` prints inline during the walk (``cli.py``'s
``_emit`` calls around the loop) — the single most order-sensitive block in the human
report. A comparison built only from those two homes would report PASS while a regression
in that whole block went unnoticed, because there was nothing to notice: "a negative needs
a positive control."

``fixtures/home_skills`` closes that gap: same minimal ``openclaw.json`` / ``SOUL.md`` as
``home_safe`` (so nothing about the REST of the audit is a new unknown), plus
``workspace-home/skills/`` carrying two installed skills side by side in ONE home —

* ``clean-skill`` — a bare, inert skill (byte-identical to ``fixtures/clean_b104_wired``'s
  ``alpha``), so the sweep's SAFE-verdict rendering is exercised too, not just the FAIL one;
* ``evil-fetch-skill`` — byte-identical to the already-shipped, already-reviewed
  ``fixtures/bad_b13_runtime_fetch/skills/evil-fetch-skill``, which trips a known
  content-ring signal (a runtime-external-fetch-instruction directive, OWASP AST05) via
  B13 (``check_installed_skills``) — reused rather than invented, so this fixture adds no
  new attack-content surface for a C-135 pass to have to clear, and no secret-shaped value
  is needed at all (Golden Rule #3 is a non-issue here).

This file pins that ONE home's ``--full`` run renders both skills' narration together and
sets ``has_fail`` — the combination the two existing single-skill fixtures
(``clean_b104_wired`` all-safe, ``bad_b13_runtime_fetch`` all-dangerous) never exercise
together on their own. It does not re-pin the whole SKILL SWEEP contract — that is
``tests/test_f149_full_skill_sweep.py``'s job — only that a fixture HOME exists where the
section actually has content, and locks its shape so it cannot silently go back to empty.

Offline, read-only; nothing written outside ``capsys``.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.cli import main
from clawseccheck.collector import collect
from clawseccheck.cli import sweep_installed_skills

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
HOME = str(FIXTURES / "home_skills")

BASE = ["--no-native", "--no-host", "--no-history", "--ascii", "--seed", "b731"]
SECTION = "CLAWSECCHECK SKILL SWEEP"


def _skill_sweep_section(out: str) -> str:
    """Same extraction idiom as test_f149_full_skill_sweep.py's own helper — every
    section banner is bordered by a line of 60 '=' both above and below its title."""
    rest = out.split(SECTION, 1)[1]
    _, _, body = rest.partition("=" * 60)
    return body.split("=" * 60, 1)[0]


def test_fixture_carries_exactly_the_two_intended_skills():
    """Guards the fixture's own shape, independent of any check logic: if a future edit
    to this fixture silently drops or renames a skill dir, this fails before any assertion
    below has a chance to pass for the wrong reason."""
    ctx = collect(FIXTURES / "home_skills")
    assert set(ctx.installed_skills) == {"clean-skill", "evil-fetch-skill"}


def test_sweep_is_complete_and_reports_one_fail_one_safe():
    home = FIXTURES / "home_skills"
    ctx = collect(home)
    sweep = sweep_installed_skills(home, narrate=False, ctx=ctx)
    assert sweep.complete is True
    assert sweep.has_fail is True
    by_status: dict[str, int] = {}
    for _target, finding in sweep.vet_targets():
        by_status[finding.status] = by_status.get(finding.status, 0) + 1
    assert by_status.get("FAIL") == 1
    assert by_status.get("PASS") == 1


def test_full_renders_both_skills_in_one_sweep_section(capsys):
    rc = main(["--home", HOME] + BASE + ["--full"])
    out = capsys.readouterr().out
    assert rc == 0
    section = _skill_sweep_section(out)
    assert "clean-skill" in section
    assert "evil-fetch-skill" in section
    assert "DANGEROUS" in section
    assert "Evidence:" in section
    assert "2 skill(s) checked | 1 safe | 0 suspicious | 1 dangerous" in section


def test_full_exit_code_reacts_to_the_dangerous_skill_in_this_home(capsys):
    rc = main(["--home", HOME] + BASE + ["--full", "--exit-code"])
    capsys.readouterr()
    assert rc == 1


def test_full_json_carries_both_targets_structurally(capsys):
    rc = main(["--home", HOME] + BASE + ["--full", "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == 0
    sweep = doc["skill_sweep"]
    assert sweep["worst"] == "FAIL"
    assert sweep["truncated"] is False
    assert sweep["counts"]["total"] == 2
    assert sweep["counts"]["fails"] == 1
    assert sweep["counts"]["safe"] == 1
    names = {t["name"] for t in sweep["targets"]}
    assert names == {"clean-skill", "evil-fetch-skill"}
