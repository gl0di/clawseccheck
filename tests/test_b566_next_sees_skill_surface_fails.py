"""B-566 — --next must not be blind to a FAIL no rule happens to name.

The rule set keyed on 7 of 188 catalog checks, so a run could carry a skills-surface
FAIL and produce no next step at all. The measured case was B181 — "installed skill
file(s) no longer match the SHA-256 digests ClawHub recorded" — a possible-compromise
indicator that the command whose whole job is "what should I do now" had nothing to
say about, on a run that also showed A1 CRITICAL and B55 HIGH.

The trigger is now derived from the catalog's own `surface` slug, so a new
skills-surface check inherits its next step without a new rule. These tests pin the
close, the calibration that keeps it from becoming noise, and the doctrine it must
stay inside.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import BY_ID, FAIL, WARN, Finding
from clawseccheck.guide import _surface_failed, suggest_actions
from clawseccheck.scoring import ScoreResult

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _score():
    return ScoreResult(score=80, grade="B", capped=False,
                       raw_score=80, failed_critical=0, failed_high=0)


def _f(fid, status, **kw):
    meta = BY_ID[fid]
    return Finding(fid, meta.title, meta.severity, status,
                   f"{fid} detail", "fix it", meta.framework, **kw)


def _ids(findings):
    return {a.id for a in suggest_actions(findings, _score())}


# --------------------------------------------------------------- the defect
def test_b181_fail_now_produces_a_next_step():
    """The filed case: a skills-surface FAIL that no id-keyed rule references."""
    assert BY_ID["B181"].surface == "skills"
    assert "vet_skills" in _ids([_f("B181", FAIL)])


def test_the_close_is_not_special_cased_to_b181():
    """Any skills-surface FAIL reaches it — that is the point of deriving from surface.

    A per-id rule would have to be added for each new check, which is exactly how the
    trigger set froze at 7 in the first place.
    """
    skills_checks = [m.id for m in BY_ID.values() if m.surface == "skills"]
    assert len(skills_checks) > 20, "surface slug changed — this test is no longer meaningful"
    for cid in skills_checks[:10]:
        assert "vet_skills" in _ids([_f(cid, FAIL)]), cid


# --------------------------------------------------------------- calibration
def test_a_skills_surface_warn_alone_does_not_trigger_it():
    """FAIL-only, deliberately.

    Measured over 40 fixtures: the B13-keyed trigger fires on 22; adding every
    skills-surface FAIL *or* WARN takes it to 35, which makes the action near-universal
    and costs a prioritised list the signal it exists to carry. FAIL alone takes it to 24.
    """
    warn_only = _f("B181", WARN)
    assert not _surface_failed([warn_only], "skills")
    assert "vet_skills" not in _ids([warn_only])


def test_b13s_own_trigger_is_unchanged():
    """B13 still reaches the action at WARN, as it always did.

    The surface term only ADDS; nothing that reached this action before may stop
    reaching it.
    """
    assert "vet_skills" in _ids([_f("B13", WARN)])
    assert "vet_skills" in _ids([_f("B13", FAIL)])


def test_a_suppressed_fail_does_not_resurface_as_an_action():
    """The user said they did not want to be told; an action would route around that."""
    assert "vet_skills" not in _ids([_f("B181", FAIL, suppressed=True)])


def test_a_non_skills_fail_does_not_trigger_the_skill_action():
    """B55 is a tools-surface FAIL — real, but vetting skills is not its next step."""
    assert BY_ID["B55"].surface == "tools"
    assert not _surface_failed([_f("B55", FAIL)], "skills")


# --------------------------------------------------------------- doctrine
def test_no_action_is_ever_remediation():
    """Reports-only (F-074) — the widening must not smuggle in a fix instruction."""
    for a in suggest_actions([_f("B181", FAIL)], _score()):
        assert a.command.startswith("clawseccheck"), a.command
        for banned in ("reinstall", "delete ", "rm ", "chmod", "uninstall"):
            assert banned not in f"{a.title} {a.command} {a.why}".lower(), (a.id, banned)


def test_a_run_whose_fail_no_rule_references_still_produces_a_coherent_list():
    """Pins that --next is never silently empty — true today, and easy to break."""
    actions = suggest_actions([_f("B55", FAIL)], _score())
    assert actions, "next-actions list went empty"
    assert all(a.title and a.command and a.why for a in actions)


# --------------------------------------------------------------- the promise
def test_usage_no_longer_routes_the_fix_question_at_next():
    """C-125 doc grounding: the row promised a per-finding list --next cannot produce.

    USAGE.md's own next row says the tool never answers "fix this for me", so the two
    rows contradicted each other. The question now points at the report's lead line,
    which genuinely answers it.
    """
    usage = (FIXTURES.parent / "docs" / "USAGE.md").read_text(encoding="utf-8")
    row = [ln for ln in usage.splitlines()
           if ln.startswith("| \"What's the single most important thing to fix?\"")]
    assert len(row) == 1, "the routing row moved — re-ground this test"
    assert "`--next`" not in row[0]
    assert "lead line" in row[0] or "most urgent" in row[0]


def test_help_and_functions_describe_further_checks_not_actions():
    """--help and --functions both overstated what --next derives from the result."""
    cli = (FIXTURES.parent / "clawseccheck" / "cli.py").read_text(encoding="utf-8")
    palette = (FIXTURES.parent / "clawseccheck" / "palette.py").read_text(encoding="utf-8")
    assert "print recommended next actions based on the audit result" not in cli
    assert "which further ClawSecCheck checks are worth running" in cli
    assert "recommended actions from the result" not in palette
