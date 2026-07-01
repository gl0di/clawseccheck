"""F-048: the pre-install --vet path must run the full skill-content security ring
(SKILL_CONTENT_RING), not just check_installed_skills (B13).

These tests assert the ring fires **through vet_skill()** — the pre-install entry
point — for every content check whose signal lives in skill text, and that clean
skills stay silent (golden rule #5: zero false-positive FAILs). The ring is a single
source of truth shared with the full-audit CHECKS list so the two engines can't drift.

Two firing shapes are exercised:
  * native skill fixtures whose payload already lives in a skills/<name>/ dir (B61, B62);
  * "relocated payload" fixtures whose real bootstrap (SOUL.md) trigger text is moved
    verbatim into a synthetic skill's SKILL.md — the trigger is real fixture content,
    just placed where a pre-install skill would carry it (B59, B60, B63, B64, B65, B66,
    B74, C074).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, WARN
from clawseccheck.checks import (
    CHECKS,
    SKILL_CONTENT_RING,
    check_agent_snooping,
    check_capability_intent_mismatch,
    vet_skill,
)

_REPO = Path(__file__).resolve().parent.parent
_FIX = _REPO / "fixtures"


def _ids(finding) -> set[str]:
    """All check ids surfaced by a vet result: the primary plus any ring findings."""
    return {finding.id} | {r.id for r in getattr(finding, "ring_findings", [])}


# --------------------------------------------------------------------------- #
# Single source of truth: the ring the full audit runs IS the ring --vet runs. #
# --------------------------------------------------------------------------- #
def test_ring_is_registered_in_full_audit_checks():
    """Every SKILL_CONTENT_RING member is the same function object in CHECKS, so the
    full audit and --vet can never run different versions of these checks (anti-drift)."""
    assert SKILL_CONTENT_RING, "ring is empty"
    for chk in SKILL_CONTENT_RING:
        assert chk in CHECKS, f"{chk.__name__} is in the ring but missing from CHECKS"


def test_ring_covers_the_headline_checks():
    """The two most-wanted pre-install signals — cross-agent snooping (B61) and
    declared-vs-actual capability mismatch (B62) — are in the shared ring."""
    assert check_agent_snooping in SKILL_CONTENT_RING
    assert check_capability_intent_mismatch in SKILL_CONTENT_RING


# --------------------------------------------------------------------------- #
# Native skill fixtures: the ring fires through vet_skill().                   #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "skill_rel, expect_id",
    [
        ("bad_b61_agent_snoop/skills/snooper", "B61"),
        ("bad_b62_cap_mismatch/skills/md_formatter", "B62"),
    ],
)
def test_native_skill_fixture_fires_ring_via_vet(skill_rel, expect_id):
    f = vet_skill(str(_FIX / skill_rel))
    assert f.status in (FAIL, WARN), f"{skill_rel} vetted {f.status}, expected FAIL/WARN"
    assert expect_id in _ids(f), f"{expect_id} did not fire via vet for {skill_rel}"


# --------------------------------------------------------------------------- #
# Relocated-payload fixtures: real SOUL.md trigger text moved into a SKILL.md. #
# --------------------------------------------------------------------------- #
_RELOCATED = [
    ("bad_b59_md_image_exfil", "B59"),
    ("bad_b60_self_replication", "B60"),
    ("bad_b63_silent_action", "B63"),
    ("bad_b63_silent_bare", "B63"),
    ("bad_b64_fail", "B64"),
    ("bad_b65_conditional_trigger", "B65"),
    ("bad_b66_persona", "B66"),
    ("bad_b74_false_provenance", "B74"),
    ("bad_c074_image_attr_injection", "C074"),
]


@pytest.mark.parametrize("fixture, expect_id", _RELOCATED)
def test_relocated_payload_fires_ring_via_vet(fixture, expect_id, tmp_path):
    """Move the fixture's real bootstrap payload into a skill's SKILL.md and confirm the
    corresponding ring check fires through vet_skill (it would not have, pre-F-048)."""
    payload = (_FIX / fixture / "workspace-home" / "SOUL.md").read_text(
        encoding="utf-8", errors="replace"
    )
    skill = tmp_path / "reloc_skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: reloc\ndescription: helper\n---\n" + payload, encoding="utf-8"
    )
    f = vet_skill(str(skill))
    assert f.status in (FAIL, WARN), f"{fixture} vetted {f.status}, expected FAIL/WARN"
    assert expect_id in _ids(f), f"{expect_id} did not fire via vet for relocated {fixture}"


# --------------------------------------------------------------------------- #
# Golden rule #5: clean skills stay silent through vet (zero false-positive).  #
# --------------------------------------------------------------------------- #
def _clean_skill_dirs() -> list[Path]:
    return sorted({p.parent for p in _FIX.glob("clean_*/**/SKILL.md")})


@pytest.mark.parametrize("skill_dir", _clean_skill_dirs(), ids=lambda p: p.parent.parent.name)
def test_clean_skill_stays_silent_via_vet(skill_dir):
    """No clean fixture may FAIL or WARN when vetted — including from a newly-wired ring
    check. UNKNOWN/PASS are allowed; FAIL/WARN is a false positive and fails the build."""
    f = vet_skill(str(skill_dir))
    assert f.status not in (FAIL, WARN), (
        f"{skill_dir.relative_to(_FIX)} vetted {f.status} "
        f"(ring={[r.id for r in getattr(f, 'ring_findings', [])]}) — false positive"
    )
