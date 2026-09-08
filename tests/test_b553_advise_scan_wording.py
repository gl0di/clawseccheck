"""B-553: two false-cause sentences, fixed as a wording reword — never a suppression.

Limb (a) — ``report.py``'s ``render_advise``: the CAUTION fallback (fired when
``_advise_reasons`` found no FAIL/WARN finding to name) used to print a generic
"assessment is inconclusive (UNKNOWN)" even when the real cause was already known:
``_situational_coverage_notes(profile)`` names exactly what could not be assessed, and
that fact is rendered 12 lines below in the "Not assessed" block. The fix names it in
the CAUTION sentence too, instead of leaving the reader with "not enough signal" alone
when a concrete reason exists. The generic sentence stays as the fallback when
``coverage_notes`` really is empty — nothing about the UNKNOWN convention or the verdict
itself moves.

Limb (b) — ``cli.py``'s ``_discovery_gap_note``/``_discovery_gap_suffix``: both used to
assert "skill discovery was incomplete" for every entry of
``limit_hits_for(ctx, LIMIT_DOMAIN_SKILL)``. That domain is not discovery-only —
``collector.py`` tags ~40 CONTENT-scan reasons with the same domain (per-skill file
caps, unreadable files, oversize archives, the archive-expansion family), so for those
the sentence is false: discovery completed and one target's *content* was truncated.
The fix rewords both call sites to the true superset ("could not cover everything —
discovery or content") rather than asserting a specific, sometimes-wrong cause. The
underlying reason string(s) are still carried verbatim — no finding, and no reason, is
ever dropped.
"""
from __future__ import annotations

from types import SimpleNamespace

from clawseccheck.catalog import UNKNOWN, Finding
from clawseccheck.cli import SkillSweep, _discovery_gap_note, _discovery_gap_suffix
from clawseccheck.report import render_advise


def _f(fid: str, status: str, detail: str = "detail", evidence=None) -> Finding:
    return Finding(fid, "t", "MEDIUM", status, detail, "fix", "Skill Trust", False,
                    evidence or [])


def _profile(*findings, target="thing", target_type="skill", overall_status=UNKNOWN):
    return SimpleNamespace(
        target=target, target_type=target_type, overall_status=overall_status,
        findings=list(findings),
    )


# ---------------------------------------------------------------------------
# Limb (a): render_advise's CAUTION fallback
# ---------------------------------------------------------------------------

def test_caution_with_a_coverage_note_names_it_instead_of_the_generic_line():
    """No FAIL/WARN finding to explain the verdict, but a real "coverage: ..." note
    exists -- the sentence must point at "Not assessed" rather than claim there is
    simply "not enough signal"."""
    profile = _profile(
        _f("VET-COVERAGE", UNKNOWN, evidence=["coverage: archive extraction was capped"]),
    )
    out = render_advise(profile, ascii_only=True)
    assert "part of this target could not be assessed" in out
    assert "Not assessed" in out
    # The old generic fallback must not ALSO appear -- one true sentence, not two.
    assert "not enough signal to say INSTALL" not in out


def test_caution_with_no_coverage_note_keeps_the_generic_fallback():
    """Negative control: no findings at all (coverage_notes is empty) -- the pre-existing
    generic sentence is still the right one, and must not regress."""
    profile = _profile()
    out = render_advise(profile, ascii_only=True)
    assert "not enough signal to say INSTALL" in out
    assert "part of this target could not be assessed" not in out


def test_coverage_note_is_not_suppressed_it_is_still_in_not_assessed():
    """The reworded sentence must not make the underlying gap harder to find -- the
    literal coverage text still appears in the "Not assessed" block, verbatim."""
    profile = _profile(
        _f("VET-COVERAGE", UNKNOWN, evidence=["coverage: archive extraction was capped"]),
    )
    out = render_advise(profile, ascii_only=True)
    assert "archive extraction was capped" in out


# ---------------------------------------------------------------------------
# Limb (b): cli.py's two skill-scan-gap wording sites
# ---------------------------------------------------------------------------

def test_discovery_gap_note_does_not_claim_discovery_for_a_content_reason():
    """A reason shaped like the ~40 CONTENT-scan tags LIMIT_DOMAIN_SKILL also carries
    (a per-skill file cap here) must not be narrated as "skill discovery was
    incomplete" -- that would name the wrong cause."""
    note = _discovery_gap_note(["only the first 3 file(s) of this skill were scanned"])
    assert "skill discovery was incomplete" not in note.lower()
    assert "could not cover everything (discovery or content)" in note
    # The reason itself is still carried -- reworded, never dropped.
    assert "only the first 3 file(s) of this skill were scanned" in note


def test_discovery_gap_suffix_does_not_claim_discovery_for_a_content_reason():
    sweep = SkillSweep(
        home_dir=None, checked_dirs=[],
        discovery_incomplete_reasons=["ZIP decompression failed in bundle.zip"],
    )
    suffix = _discovery_gap_suffix(sweep)
    assert "Skill discovery was incomplete" not in suffix
    assert "could not cover everything (discovery or content)" in suffix
    assert "ZIP decompression failed in bundle.zip" in suffix


def test_discovery_gap_suffix_empty_when_no_gap():
    """Non-vacuity: the reworded suffix must stay empty on the pre-existing
    gap-free path, exactly like before."""
    sweep = SkillSweep(home_dir=None, checked_dirs=[])
    assert _discovery_gap_suffix(sweep) == ""


def test_discovery_gap_note_and_suffix_use_the_same_wording():
    """The task's 'fix both call sites together, do not diverge' requirement --
    both narrations describe the same underlying signal and must agree."""
    reasons = ["a genuine reason"]
    note = _discovery_gap_note(reasons)
    sweep = SkillSweep(home_dir=None, checked_dirs=[], discovery_incomplete_reasons=reasons)
    suffix = _discovery_gap_suffix(sweep)
    assert "could not cover everything (discovery or content)" in note
    assert "could not cover everything (discovery or content)" in suffix
