"""B93 (F-103, L1-6) — a confusable/mixed-script character in a skill's trigger DESCRIPTION
(e.g. Cyrillic-а for Latin a) can register as a near-duplicate trigger for preferential
routing while looking identical to a human reader. F-022 already covers homoglyphs in the
skill NAME; this covers the description text. Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.checks import UNKNOWN, WARN, check_trigger_homoglyph, vet_skill
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_CYRILLIC_A = "а"  # Cyrillic small letter a — visually identical to Latin 'a'


def _blob(description: str) -> str:
    return f"# file: SKILL.md\n---\nname: x\ndescription: {description}\n---\n"


def test_unknown_when_no_installed_skills():
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {}
    f = check_trigger_homoglyph(ctx)
    assert f.status == UNKNOWN


def test_confusable_description_warns():
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {"x": _blob(f'Use when the user says "reset p{_CYRILLIC_A}ssword"')}
    f = check_trigger_homoglyph(ctx)
    assert f.status == WARN, f.detail


def test_plain_ascii_description_passes():
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {"x": _blob('Use when the user says "reset password"')}
    f = check_trigger_homoglyph(ctx)
    assert f.status != WARN


# --- vet-level: B93 surfaces as WARN on the bad fixture, PASS on the clean one ---

def test_vet_bad_trigger_homoglyph_is_warn():
    skill_dir = FIXTURES / "bad_b93_trigger_homoglyph" / "skills" / "helper"
    f = vet_skill(skill_dir)
    assert any(x.id == "B93" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])])


def test_vet_clean_plain_trigger_b93_passes():
    skill_dir = FIXTURES / "clean_b93_plain_trigger" / "skills" / "helper"
    f = vet_skill(skill_dir)
    assert not any(
        x.id == "B93" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])]
    )
