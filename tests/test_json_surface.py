"""Tests for F-031: surface/coverage/projection wired into --json output.

Verifies:
- Every finding in --json output has a "surface" key (valid slug or "").
- Top-level "coverage" block has the expected structure.
- Top-level "projection" block has the expected structure.
- Existing --json keys are still present (back-compat).
- --card output does NOT contain coverage or projection.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import SURFACES
from clawseccheck.cli import main

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
VULN = str(FIXTURES / "home_vuln")
SAFE = str(FIXTURES / "home_safe")
BASE = ["--no-native", "--no-history"]

_VALID_SURFACES = frozenset(SURFACES) | {""}


def _json_doc(home: str, capsys) -> dict:
    main(["--home", home] + BASE + ["--json"])
    return json.loads(capsys.readouterr().out)


# ---------------------------------------------------------------------------
# surface field on each finding
# ---------------------------------------------------------------------------

def test_json_findings_have_surface_key_on_vuln(capsys):
    doc = _json_doc(VULN, capsys)
    assert "findings" in doc
    assert len(doc["findings"]) > 0
    for f in doc["findings"]:
        assert "surface" in f, f"finding {f.get('id')} missing 'surface'"


def test_json_findings_have_surface_key_on_safe(capsys):
    doc = _json_doc(SAFE, capsys)
    for f in doc["findings"]:
        assert "surface" in f, f"finding {f.get('id')} missing 'surface'"


def test_json_findings_surface_is_valid_slug_or_empty(capsys):
    """surface must be one of the 14 catalog SURFACES slugs or empty string."""
    doc = _json_doc(VULN, capsys)
    for f in doc["findings"]:
        assert f["surface"] in _VALID_SURFACES, (
            f"finding {f.get('id')} has unknown surface {f['surface']!r}"
        )


def test_json_findings_surface_is_string(capsys):
    doc = _json_doc(VULN, capsys)
    for f in doc["findings"]:
        assert isinstance(f["surface"], str), (
            f"finding {f.get('id')} surface is not a str: {f['surface']!r}"
        )


def test_json_known_finding_has_expected_surface(capsys):
    """Spot-check: B1 (Secrets in plaintext) must be surface='secrets'."""
    doc = _json_doc(VULN, capsys)
    b1 = next((f for f in doc["findings"] if f["id"] == "B1"), None)
    if b1 is not None:
        assert b1["surface"] == "secrets"


# ---------------------------------------------------------------------------
# coverage top-level block
# ---------------------------------------------------------------------------

def test_json_has_coverage_key(capsys):
    doc = _json_doc(VULN, capsys)
    assert "coverage" in doc


def test_json_coverage_has_surfaces(capsys):
    doc = _json_doc(VULN, capsys)
    cov = doc["coverage"]
    assert "surfaces" in cov
    assert isinstance(cov["surfaces"], dict)


def test_json_coverage_has_families(capsys):
    doc = _json_doc(VULN, capsys)
    cov = doc["coverage"]
    assert "families" in cov
    assert isinstance(cov["families"], dict)


def test_json_coverage_has_gaps(capsys):
    doc = _json_doc(VULN, capsys)
    cov = doc["coverage"]
    assert "gaps" in cov
    gaps = cov["gaps"]
    assert "not_checkable" in gaps
    assert "roadmap" in gaps
    assert isinstance(gaps["not_checkable"], list)
    assert isinstance(gaps["roadmap"], list)


def test_json_coverage_has_summary(capsys):
    doc = _json_doc(VULN, capsys)
    cov = doc["coverage"]
    assert "summary" in cov
    summary = cov["summary"]
    for key in ("checked", "partial", "not_checkable", "roadmap"):
        assert key in summary, f"coverage.summary missing key {key!r}"
        assert isinstance(summary[key], int)


def test_json_coverage_surfaces_have_state_and_counts(capsys):
    doc = _json_doc(VULN, capsys)
    for slug, info in doc["coverage"]["surfaces"].items():
        assert "state" in info, f"coverage.surfaces[{slug}] missing 'state'"
        assert info["state"] in ("checked", "partial"), (
            f"coverage.surfaces[{slug}].state = {info['state']!r}"
        )
        assert "counts" in info, f"coverage.surfaces[{slug}] missing 'counts'"
        counts = info["counts"]
        for k in ("pass", "warn", "fail", "unknown"):
            assert k in counts, f"coverage.surfaces[{slug}].counts missing {k!r}"
            assert isinstance(counts[k], int)


def test_json_coverage_families_have_required_fields(capsys):
    doc = _json_doc(VULN, capsys)
    for fam, info in doc["coverage"]["families"].items():
        assert "surfaces" in info, f"coverage.families[{fam}] missing 'surfaces'"
        assert "counts" in info, f"coverage.families[{fam}] missing 'counts'"
        assert "worst" in info, f"coverage.families[{fam}] missing 'worst'"
        assert info["worst"] in ("fail", "warn", "pass", "unknown"), (
            f"coverage.families[{fam}].worst = {info['worst']!r}"
        )


def test_json_coverage_summary_checked_plus_partial_equals_surface_count(capsys):
    """checked + partial must equal the number of bucket surfaces (13)."""
    doc = _json_doc(VULN, capsys)
    summary = doc["coverage"]["summary"]
    total = summary["checked"] + summary["partial"]
    # 13 bucket surfaces (trifecta excluded)
    assert total == 13, f"checked({summary['checked']}) + partial({summary['partial']}) = {total}, expected 13"


# ---------------------------------------------------------------------------
# projection top-level block
# ---------------------------------------------------------------------------

def test_json_has_projection_key(capsys):
    doc = _json_doc(VULN, capsys)
    assert "projection" in doc


def test_json_projection_has_current(capsys):
    doc = _json_doc(VULN, capsys)
    proj = doc["projection"]
    assert "current" in proj
    current = proj["current"]
    assert "score" in current and isinstance(current["score"], int)
    assert "grade" in current and isinstance(current["grade"], str)


def test_json_projection_current_score_matches_top_level(capsys):
    """projection.current.score must equal top-level score."""
    doc = _json_doc(VULN, capsys)
    assert doc["projection"]["current"]["score"] == doc["score"]


def test_json_projection_has_top1(capsys):
    """top1 is a dict or null."""
    doc = _json_doc(VULN, capsys)
    proj = doc["projection"]
    assert "top1" in proj
    # top1 may be null (no fixable FAILs) or a dict
    assert proj["top1"] is None or isinstance(proj["top1"], dict)


def test_json_projection_top1_has_required_keys_when_present(capsys):
    doc = _json_doc(VULN, capsys)
    top1 = doc["projection"]["top1"]
    if top1 is not None:
        for key in ("finding_id", "projected_score", "projected_grade", "delta"):
            assert key in top1, f"projection.top1 missing {key!r}"


def test_json_projection_has_cumulative(capsys):
    doc = _json_doc(VULN, capsys)
    proj = doc["projection"]
    assert "cumulative" in proj
    cum = proj["cumulative"]
    for key in ("projected_score", "projected_grade", "delta"):
        assert key in cum, f"projection.cumulative missing {key!r}"


def test_json_projection_on_safe_fixture(capsys):
    """Projection must be present on safe fixture too (no FAIL -> top1=null)."""
    doc = _json_doc(SAFE, capsys)
    assert "projection" in doc
    proj = doc["projection"]
    assert "current" in proj
    assert "cumulative" in proj


# ---------------------------------------------------------------------------
# Back-compat: existing --json keys still present
# ---------------------------------------------------------------------------

def test_json_backcompat_existing_keys_present(capsys):
    doc = _json_doc(VULN, capsys)
    for key in ("score", "grade", "capped", "raw_score", "trifecta",
                "findings", "next_actions", "capability_graph",
                "secret_reachability", "intentAttestationRequests",
                "scan_receipt"):
        assert key in doc, f"back-compat: top-level key {key!r} missing from --json"


def test_json_backcompat_finding_existing_keys_present(capsys):
    doc = _json_doc(VULN, capsys)
    for f in doc["findings"][:5]:  # check first 5 to keep test fast
        for key in ("id", "title", "severity", "status", "detail", "fix",
                    "framework", "confidence", "suppressed", "owasp",
                    "remediation", "evidence"):
            assert key in f, f"back-compat: finding key {key!r} missing (id={f.get('id')})"


# ---------------------------------------------------------------------------
# --card does NOT contain coverage/projection
# ---------------------------------------------------------------------------

def test_card_does_not_contain_coverage(capsys):
    main(["--home", VULN] + BASE + ["--card"])
    out = capsys.readouterr().out
    assert "coverage" not in out


def test_card_does_not_contain_projection(capsys):
    main(["--home", VULN] + BASE + ["--card"])
    out = capsys.readouterr().out
    assert "projection" not in out
