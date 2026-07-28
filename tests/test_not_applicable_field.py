"""F-138 (B1) — ``Finding.not_applicable`` field + ``_surface_absent`` predicate.

Plumbing only: nothing in this change EMITS ``not_applicable=True`` yet (that starts
with B2/F-139). What is pinned here is the field's own contract, so a later migrating
check can rely on it without re-deriving the rules:

* default ``False`` — an unaware/legacy caller gets the ordinary UNKNOWN posture;
* ``__post_init__`` NORMALIZES rather than raises — ``not_applicable`` can only be
  ``True`` alongside ``status == UNKNOWN``, and ``dataclasses.replace()`` (which
  re-invokes ``__post_init__``) re-normalizes on any later status change;
* the flag must never be derivable from ``detail`` text — B4's own UNKNOWN finding
  literally contains the phrase "not applicable" and stays ``False`` regardless.

Offline, read-only.
"""
from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN, Finding
from clawseccheck.checks._shared import (
    _custom,
    _finding,
    _skill_corpus_complete,
    _surface_absent,
)
from clawseccheck.checks import check_sandbox
from clawseccheck.collector import Context, LIMIT_DOMAIN_CRON, note_limit

PKG = Path(__file__).resolve().parent.parent / "clawseccheck"
FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _minimal_finding(**overrides) -> Finding:
    kwargs = dict(
        id="B999", title="t", severity="LOW", status=PASS, detail="d", fix="f",
        framework="fw",
    )
    kwargs.update(overrides)
    return Finding(**kwargs)


# ---------------------------------------------------------------------------
# Default + construction
# ---------------------------------------------------------------------------

def test_default_is_false():
    assert _minimal_finding().not_applicable is False


def test_finding_helper_passes_through_at_unknown():
    f = _finding("B1", UNKNOWN, "d", "f", not_applicable=True)
    assert f.not_applicable is True


def test_finding_helper_default_omitted_is_false():
    f = _finding("B1", UNKNOWN, "d", "f")
    assert f.not_applicable is False


def test_custom_helper_passes_through_at_unknown():
    f = _custom("B1", "LOW", UNKNOWN, "d", "f", not_applicable=True)
    assert f.not_applicable is True


# ---------------------------------------------------------------------------
# __post_init__ invariant: not_applicable=True only survives at status UNKNOWN
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("status", [PASS, WARN, FAIL])
def test_post_init_normalizes_non_unknown_status(status):
    f = _minimal_finding(status=status, not_applicable=True)
    assert f.not_applicable is False, (
        "not_applicable=True must self-correct to False at any status other than UNKNOWN"
    )


def test_post_init_keeps_true_at_unknown():
    f = _minimal_finding(status=UNKNOWN, not_applicable=True)
    assert f.not_applicable is True


def test_post_init_never_raises_on_untrusted_combination():
    # __post_init__ NORMALIZES, never raises — a caller bug must not crash the audit.
    for status in (PASS, WARN, FAIL, UNKNOWN):
        _minimal_finding(status=status, not_applicable=True)  # must not raise


def test_dataclasses_replace_renormalizes():
    """dataclasses.replace() re-invokes __post_init__ — mirrors
    adjudication._escalate_finding()'s UNKNOWN -> WARN escalation, which must clear a
    stale not_applicable with no separate guard at the call site."""
    f = _minimal_finding(status=UNKNOWN, not_applicable=True)
    assert f.not_applicable is True
    escalated = dataclasses.replace(f, status=WARN)
    assert escalated.not_applicable is False


def test_dataclasses_replace_keeps_true_when_status_stays_unknown():
    f = _minimal_finding(status=UNKNOWN, not_applicable=True)
    same = dataclasses.replace(f, detail="new detail")
    assert same.not_applicable is True


# ---------------------------------------------------------------------------
# JSON: always present, always a bool
# ---------------------------------------------------------------------------

def test_json_key_present_and_bool_on_every_finding():
    ctx, findings, score = audit(home=str(FIXTURES / "home_safe"), include_native=False)
    assert findings, "home_safe produced no findings — nothing to check the key on"
    from clawseccheck.report import render_json
    import json
    doc = json.loads(render_json(findings, score, ctx=ctx))
    for f in doc["findings"]:
        assert "not_applicable" in f
        assert isinstance(f["not_applicable"], bool)


# ---------------------------------------------------------------------------
# Corpus invariant: no finding a real audit produces violates the __post_init__ rule
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("home", ["home_safe", "home_vuln"])
def test_corpus_no_finding_violates_the_unknown_only_invariant(home):
    """Vacuously true today (no emitter sets not_applicable=True yet) — pins the
    invariant structurally so it stays true once B2/F-139 adds the first emitter."""
    _ctx, findings, _score = audit(home=str(FIXTURES / home), include_native=False)
    violations = [f.id for f in findings if f.not_applicable and f.status != UNKNOWN]
    assert not violations, (
        f"finding(s) with not_applicable=True at a non-UNKNOWN status: {violations}"
    )


# ---------------------------------------------------------------------------
# The phrase "not applicable" in detail text is NOT the same thing as the field —
# B4 proves it: it uses the exact phrase and must NOT set the field.
# ---------------------------------------------------------------------------

def test_b4_not_applicable_phrase_does_not_set_the_field():
    ctx = Context(home=Path("/nonexistent"), config={})
    f = check_sandbox(ctx)
    assert f.status == UNKNOWN
    assert "not applicable" in f.detail
    assert f.not_applicable is False, (
        "B4's UNKNOWN finding literally says 'not applicable' in its detail text but "
        "has no not_applicable=True emitter — the field must never be inferred from "
        "detail wording."
    )


# ---------------------------------------------------------------------------
# _surface_absent / _skill_corpus_complete predicates
# ---------------------------------------------------------------------------

def test_surface_absent_false_when_config_not_found():
    ctx = Context(home=Path("/tmp"), config_found=False)
    assert _surface_absent(ctx, LIMIT_DOMAIN_CRON) is False


def test_surface_absent_false_when_config_parse_error():
    ctx = Context(home=Path("/tmp"), config_found=True, config_parse_error=True)
    assert _surface_absent(ctx, LIMIT_DOMAIN_CRON) is False


def test_surface_absent_false_when_domain_limit_hit():
    ctx = Context(home=Path("/tmp"), config_found=True, config_parse_error=False)
    note_limit(ctx.limit_hits, LIMIT_DOMAIN_CRON, "hit the cron scan cap")
    assert _surface_absent(ctx, LIMIT_DOMAIN_CRON) is False


def test_surface_absent_false_on_untagged_limit_hit():
    """Golden Rule #4: an untagged limit hit must count against EVERY domain, not just
    a named one — dropping it would turn 'cannot tell if the scan was complete' into a
    convenient clean answer."""
    ctx = Context(home=Path("/tmp"), config_found=True, config_parse_error=False)
    ctx.limit_hits.append("some untagged truncation note")
    assert _surface_absent(ctx, LIMIT_DOMAIN_CRON) is False


def test_surface_absent_true_when_locus_read_completely():
    ctx = Context(home=Path("/tmp"), config_found=True, config_parse_error=False)
    assert _surface_absent(ctx, LIMIT_DOMAIN_CRON) is True


def test_surface_absent_ignores_a_different_domains_limit_hit():
    ctx = Context(home=Path("/tmp"), config_found=True, config_parse_error=False)
    note_limit(ctx.limit_hits, "plugin", "hit the plugin scan cap")
    assert _surface_absent(ctx, LIMIT_DOMAIN_CRON) is True


def test_skill_corpus_complete_true_by_default():
    ctx = Context(home=Path("/tmp"))
    assert _skill_corpus_complete(ctx) is True


def test_skill_corpus_complete_false_when_frontier_partial():
    ctx = Context(home=Path("/tmp"), skills_frontier_partial=True)
    assert _skill_corpus_complete(ctx) is False


def test_skill_corpus_complete_false_when_skills_capped():
    ctx = Context(home=Path("/tmp"), skills_capped_count=3)
    assert _skill_corpus_complete(ctx) is False


# ---------------------------------------------------------------------------
# AST guard — no not_applicable= call site may derive its value from detail text or a
# string-literal comparison. Modeled on test_limit_hit_domains.py's
# test_every_limit_hits_writer_in_the_package_is_tagged.
# ---------------------------------------------------------------------------

def _contains_detail_or_literal_derivation(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute) and sub.attr == "detail":
            return True
        if isinstance(sub, ast.Compare):
            for operand in (sub.left, *sub.comparators):
                if isinstance(operand, ast.Constant) and isinstance(operand.value, str):
                    if "not applicable" in operand.value.lower():
                        return True
    return False


def _not_applicable_kwarg_offenders() -> list[str]:
    offenders = []
    for path in sorted(PKG.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for kw in node.keywords:
                if kw.arg != "not_applicable":
                    continue
                if _contains_detail_or_literal_derivation(kw.value):
                    offenders.append(f"{path.relative_to(PKG)}:{node.lineno}")
    return offenders


def test_no_call_site_derives_not_applicable_from_detail_text():
    offenders = _not_applicable_kwarg_offenders()
    assert not offenders, (
        "not_applicable= must be a computed predicate (e.g. _surface_absent(...)), "
        "never derived from detail text or a string-literal comparison — B4 proves the "
        "phrase 'not applicable' already appears in unrelated detail text: "
        + ", ".join(offenders)
    )


def test_ast_guard_detects_a_synthetic_violation():
    """Anti-vacuity: prove the detector above would actually catch a real offender,
    not just pass happily because nothing calls the pattern yet."""
    src = (
        "def f(x):\n"
        "    return g(not_applicable=('not applicable' in x.detail))\n"
    )
    tree = ast.parse(src)
    call = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call) and any(k.arg == "not_applicable" for k in n.keywords)
    )
    kw = next(k for k in call.keywords if k.arg == "not_applicable")
    assert _contains_detail_or_literal_derivation(kw.value)
