"""Guard 2/2 (B0, staged BEFORE the ``Finding.not_applicable`` migration): flipping a
finding's (future) ``not_applicable`` flag must never move the score, the grade, or the
``project()`` what-if projection -- by construction, not by convention.

WHY THIS IS STRUCTURAL, NOT INCIDENTAL (see ``scoring.py:249-253``): ``compute()``
already filters its scored set on ``f.scored``, ``f.status``, ``f.suppressed``, and
``f.severity`` -- it has never read a ``not_applicable`` attribute, and a not-applicable
finding is defined to keep ``status == UNKNOWN`` (already excluded from the denominator
via the ``f.status not in (UNKNOWN, ...)`` filter). So neither the score nor the grade
can move when the flag is added and set, PROVIDED the scoring engine is never taught to
read it. This file makes that "provided" load-bearing, in two layers:

1. VALUE-LEVEL (``test_*_neutral_on_the_corpus`` below): for every fixture in the real
   corpus, ``compute(findings, ctx) == compute([flip(f) for f in findings], ctx)``, and
   the same for ``project()``/``grade_for()``. ``flip()`` is
   ``dataclasses.replace(f, not_applicable=False)`` once the field exists; TODAY, before
   B2 adds it, ``Finding`` has no such field and that call would raise, so ``flip()``
   detects the field's absence and falls back to a plain ``dataclasses.replace(f)`` (a
   structural no-op copy). That makes this assertion trivially true right now (there is
   nothing to flip yet) -- intentionally. Once ``Finding.not_applicable`` lands, ``flip``
   starts doing real work with ZERO changes to this test file, and the assertion becomes
   a genuine, load-bearing proof that the new field is inert to scoring for every shape
   in the real fixture corpus, not just whatever the implementer happened to hand-check.

2. SOURCE-LEVEL (``test_not_applicable_absent_from_scoring_engine`` below): the
   identifier ``not_applicable`` must appear ZERO times in the ``FAIL_CAPS`` /
   ``compute`` / ``_runtime_cap_signal`` region of ``scoring.py`` -- the exact region
   value-level equality above can prove neutral for the CURRENT fixture corpus, but
   can never prove neutral for every possible future input. This closes that gap
   structurally: if a later change ever teaches the scoring engine to branch on the
   flag, this guard turns red before a single test fixture needs to catch it. Idiom
   mirrors ``tests/test_limit_hit_domains.py``'s AST-based mechanical guard
   (``test_every_limit_hits_writer_in_the_package_is_tagged``): parse the real source,
   don't grep/keyword-match it.
"""
from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck import scoring
from clawseccheck.catalog import Finding

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
_SCORING_PATH = Path(__file__).resolve().parent.parent / "clawseccheck" / "scoring.py"

# True once Finding.not_applicable exists (B2+); False today. See module docstring.
_HAS_NOT_APPLICABLE = "not_applicable" in {f.name for f in dataclasses.fields(Finding)}


def _flip(f: Finding) -> Finding:
    """``dataclasses.replace(f, not_applicable=False)`` once the field exists; a plain
    structural copy (``dataclasses.replace(f)``) today, before it does. Same call site
    either way -- this is the one place that needs to change, if anywhere, once B2
    lands, and even then only to flip ``True`` cases meaningfully (this file's job is
    to prove ``False`` is a no-op, which is the neutral/default value)."""
    if _HAS_NOT_APPLICABLE:
        return dataclasses.replace(f, not_applicable=False)
    return dataclasses.replace(f)


# Not a real fixture home -- see tests/test_finding_fingerprint_manifest.py's own
# _NOT_A_FIXTURE for why fixtures/conftest.py's __pycache__/ sibling must be excluded.
_NOT_A_FIXTURE = {"__pycache__"}


def _corpus_targets() -> list[Path]:
    """Mirrors tests/test_finding_fingerprint_manifest.py's / test_b315's own corpus
    discovery so every full-corpus structural guard in this suite exercises the
    identical set of fixture homes."""
    homes = sorted(
        d for d in FIXTURES.iterdir()
        if d.is_dir() and not d.name.startswith(".") and d.name not in _NOT_A_FIXTURE
    )
    targets: list[Path] = []
    for h in homes:
        targets.append(h)
        nested = h / "openclaw_home"
        if nested.is_dir():
            targets.append(nested)
    return targets


CORPUS = _corpus_targets()


def test_corpus_is_non_empty():
    assert len(CORPUS) >= 400, "expected the full fixtures/ corpus (480+ homes)"


def test_flip_is_a_real_no_op_today():
    """Documents the field's current absence directly, so a reader of a red run
    immediately knows whether B2 has landed yet without inspecting catalog.py."""
    assert _HAS_NOT_APPLICABLE is False, (
        "Finding.not_applicable already exists -- _flip() now performs a REAL flip, "
        "and the corpus tests below just became load-bearing (see module docstring). "
        "If that's expected (B2 landed), this assertion should be updated/removed as "
        "part of that same change; if not, something added the field prematurely."
    )


# ---------------------------------------------------------------------------------------
# 1. VALUE-LEVEL: for every fixture, flipping every finding's not_applicable flag must
# not move compute()/project()/grade_for() by even one point. Parametrized per fixture
# (matches tests/test_finding_fingerprint_manifest.py's / test_b315's full-corpus style)
# so a future real regression names exactly which fixture broke neutrality.
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("home", CORPUS, ids=lambda p: str(p.relative_to(FIXTURES)))
def test_score_is_neutral_to_not_applicable_on_the_corpus(home):
    ctx, findings, _ = audit(home)
    flipped = [_flip(f) for f in findings]

    original = scoring.compute(findings, ctx)
    result = scoring.compute(flipped, ctx)
    assert result == original, (
        f"{home.name}: scoring.compute() changed after flipping not_applicable=False "
        f"on every finding -- {original!r} != {result!r}. The scoring engine must "
        "never read Finding.not_applicable (see this file's module docstring)."
    )
    assert scoring.grade_for(result.score) == scoring.grade_for(original.score)

    original_proj = scoring.project(findings, ctx)
    proj = scoring.project(flipped, ctx)
    assert proj == original_proj, (
        f"{home.name}: scoring.project() changed after flipping not_applicable=False "
        f"on every finding -- {original_proj!r} != {proj!r}."
    )


# ---------------------------------------------------------------------------------------
# 2. SOURCE-LEVEL: the mechanical guard. Idiom mirrors
# tests/test_limit_hit_domains.py's test_every_limit_hits_writer_in_the_package_is_tagged
# -- parse the real AST, extract the exact source segment for each named region, and
# assert the identifier is nowhere inside it.
# ---------------------------------------------------------------------------------------

def _region_source(tree: ast.Module, source: str, name: str) -> str:
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(source, node)
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in node.targets
        ):
            return ast.get_source_segment(source, node)
    raise AssertionError(
        f"{name!r} not found as a top-level def/assignment in scoring.py -- this "
        "guard's target moved or was renamed; update the region name above"
    )


def test_not_applicable_absent_from_scoring_engine():
    """MECHANICAL GUARD. ``FAIL_CAPS``/``compute``/``_runtime_cap_signal`` are the
    exact region ``scoring.compute()`` (module docstring, ``scoring.py:249-253``)
    reads to build the scored set and apply caps. Neutrality must stay structural --
    ``not_applicable`` is never read there, full stop -- never enforced by a new
    conditional that happens to be correct today. If a later change teaches this
    region to branch on the flag, this test turns red before any corpus fixture would
    need to catch the drift.
    """
    source = _SCORING_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    offenders = []
    for name in ("FAIL_CAPS", "compute", "_runtime_cap_signal"):
        segment = _region_source(tree, source, name)
        if "not_applicable" in segment:
            offenders.append(name)
    assert not offenders, (
        f"scoring.py region(s) {offenders} reference 'not_applicable' -- the scoring "
        "engine must stay structurally blind to the flag (status/scored already "
        "exclude it); see this file's module docstring."
    )
