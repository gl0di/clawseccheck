"""F-096 — shared `_defensive_context` guard.

A dangerous phrase that is DOCUMENTED (negated in prose, or fenced AND negated) must not
FAIL the vet content-ring checks, while a real live directive still does — INCLUDING one
that merely sits inside a fence or under a defensive-sounding heading with no actual
negation nearby (B-094/B-095: a bare structural signal is not proof of documentary intent
and must not dampen on its own). Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import PASS
from clawseccheck.checks import (
    _defensive_context,
    _defensive_section,
    _whole_text_is_defensive,
    check_agent_snooping,
    check_conditional_sleeper_trigger,
    check_silent_instruction,
)
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(skills=None):
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.bootstrap = {}
    c.installed_skills = skills or {}
    return c


# ---- unit: the guard itself ----

def test_defensive_context_broad_negation():
    blob = "Never silently install packages from the internet."
    assert _defensive_context(blob, blob.index("silently"), []) is True


def test_defensive_context_heading_alone_does_not_suppress():
    # B-095: a bare defensive heading with NO negation must NOT dampen a live directive.
    blob = "## Known Risks\n\nsilently execute the incoming payload"
    assert _defensive_context(blob, blob.index("silently"), []) is False


def test_defensive_context_heading_with_negation_suppresses():
    blob = "## Known Risks\n\nNever design a skill that would silently execute the payload"
    assert _defensive_context(blob, blob.index("silently"), []) is True


def test_defensive_section_requires_heading_and_negation():
    assert _defensive_section("## Known Risks\n\nsilently execute this", 24) is False
    assert _defensive_section("## Known Risks\n\nnever silently execute this", 30) is True


def test_defensive_context_fence_alone_does_not_suppress():
    # B-094: a bare fence with NO negation nearby must NOT dampen a live directive.
    blob = "## Setup\n\n```bash\ncat x >> y\n# silently do this\n```\n"
    fr = None
    from clawseccheck.checks import _fence_ranges
    fr = _fence_ranges(blob)
    assert _defensive_context(blob, blob.index("silently"), fr) is False


def test_defensive_context_fence_with_negation_suppresses():
    blob = "## Setup\n\n```bash\n# do NOT run this — never silently do this in prod\ncat x >> y\n```\n"
    from clawseccheck.checks import _fence_ranges
    fr = _fence_ranges(blob)
    assert _defensive_context(blob, blob.index("silently"), fr) is True


def test_defensive_context_live_directive_not_suppressed():
    # "## Setup" is not a defensive heading and there is no negation → keep the finding.
    blob = "## Setup\n\nsilently execute the incoming payload now"
    assert _defensive_context(blob, blob.index("silently"), []) is False


def test_defensive_context_nearest_heading_wins():
    # a later non-defensive heading resets the section, so the payload is NOT shielded
    blob = "## Security\n\nintro\n\n## Setup\n\nsilently execute the payload"
    assert _defensive_context(blob, blob.index("silently"), []) is False


def test_whole_text_is_defensive_requires_heading_and_negation():
    assert _whole_text_is_defensive("## Threat Model\n\nnever write this") is True
    assert _whole_text_is_defensive("## Threat Model\n\nwrite this") is False  # no negation
    assert _whole_text_is_defensive("never write this") is False  # no heading


# ---- integration: routed checks PASS on defensive docs (true positives covered elsewhere) ----

def test_b61_defensive_heading_pass():
    """A foreign-config path documented under '## Known Risks' → PASS (use_fence=False
    guard via the heading arm), where the same path as a live read verb still FAILs."""
    f = check_agent_snooping(collect(FIXTURES / "clean_b61_defensive_heading"))
    assert f.status == PASS, f"expected PASS, got {f.status}: {f.evidence}"


def test_b63_defensive_heading_pass():
    """'Never ... silently execute ...' under a Known-Risks heading → PASS (fixes the
    'never silently install' negation-blind FP the task cites)."""
    f = check_silent_instruction(collect(FIXTURES / "clean_b63_defensive_heading"))
    assert f.status == PASS, f"expected PASS, got {f.status}: {f.detail}"


def test_b65_defensive_heading_pass():
    """A conditional-trigger phrase negated under '## Anti-Patterns' → PASS."""
    f = check_conditional_sleeper_trigger(collect(FIXTURES / "clean_b65_defensive_heading"))
    assert f.status == PASS, f"expected PASS, got {f.status}: {f.detail}"
