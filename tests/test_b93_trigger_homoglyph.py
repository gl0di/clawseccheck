"""B93 (F-103, L1-6) — a confusable/mixed-script character in a skill's frontmatter NAME or
trigger DESCRIPTION (e.g. Cyrillic-а for Latin a) reads identical to a human but is a distinct
identity: the NAME leg (F-118) is a skill-impersonation surface; the DESCRIPTION leg can
register as a near-duplicate trigger for preferential routing. F-022 covers NAME typosquats by
EDIT DISTANCE (a different mechanism); this covers homoglyphs in both. Offline, read-only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.checks import UNKNOWN, WARN, check_trigger_homoglyph, vet_skill
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_CYRILLIC_A = "а"  # Cyrillic small letter a — visually identical to Latin 'a'


def _blob(description: str) -> str:
    return f"# file: SKILL.md\n---\nname: x\ndescription: {description}\n---\n"


def _blob_named(name: str, description: str = "A normal helper skill.") -> str:
    return f"# file: SKILL.md\n---\nname: {name}\ndescription: {description}\n---\n"


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


def test_whole_script_non_latin_description_is_not_flagged():
    # regression: a whole-script Cyrillic/Greek description is legitimate i18n, not
    # homoglyph masking (ClawRange anti-FP anchor i18n_not_confusable) — must stay clean
    # even though the individual letters fold to ASCII confusables.
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {
        "x": _blob("Многоязычный навык для ведения истории обслуживания любого актива.")
    }
    f = check_trigger_homoglyph(ctx)
    assert f.status != WARN, f.detail


# --- F-118: the frontmatter NAME leg (skill impersonation) ---

def test_confusable_name_warns():
    """F-118: a Cyrillic-in-ASCII homoglyph in the skill NAME ('clаwstealth') is a distinct
    identity that impersonates a trusted skill -> WARN."""
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {"x": _blob_named("cl" + _CYRILLIC_A + "wstealth")}
    f = check_trigger_homoglyph(ctx)
    assert f.status == WARN, f.detail
    assert "NAME" in f.detail


def test_plain_ascii_name_passes():
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {"x": _blob_named("clawstealth")}
    assert check_trigger_homoglyph(ctx).status != WARN


def test_whole_script_non_latin_name_is_not_flagged():
    """F-118 anti-FP: a whole-script non-Latin skill name is legitimate i18n, not
    impersonation — the confusable-in-ascii gate spares it."""
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {"x": _blob_named("Помощник")}
    assert check_trigger_homoglyph(ctx).status != WARN


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
