"""Tests for clawseccheck/coverage.py (F-029: Dashboard coverage engine).

Verifies:
- All 13 bucket surfaces present in output; "trifecta" absent.
- checked vs partial surface states.
- 7-family roll-up via FAMILY_OF.
- Static not_checkable gaps (3 grounded entries); roadmap empty.
- Determinism: two calls produce identical results; output order stable.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from clawseccheck.catalog import (
    BY_ID, FAIL, FAMILY_OF, HIGH, PASS, UNKNOWN, WARN,
    Finding,
)
from clawseccheck.coverage import (
    _BUCKET_SURFACES, _FAMILY_ORDER, _FAMILY_SURFACES,
    coverage,
)


# ── Fixture helpers ───────────────────────────────────────────────────────────

def _f(check_id: str, status: str) -> Finding:
    """Create a minimal Finding for check_id with the given status."""
    meta = BY_ID[check_id]
    return Finding(
        id=check_id,
        title=meta.title,
        severity=meta.severity,
        status=status,
        detail="test",
        fix="test",
        framework=meta.framework,
        scored=meta.scored,
    )


def _all_unknown() -> list[Finding]:
    """One UNKNOWN finding per CATALOG entry (complete run, everything UNKNOWN)."""
    return [
        Finding(
            id=meta.id, title=meta.title, severity=meta.severity,
            status=UNKNOWN, detail="test", fix="test",
            framework=meta.framework, scored=meta.scored,
        )
        for meta in BY_ID.values()
    ]


# ── 13 buckets present / trifecta excluded ────────────────────────────────────

def test_all_13_bucket_surfaces_in_output():
    """All 13 bucket surface slugs must appear in coverage()["surfaces"]."""
    result = coverage([])
    assert set(result["surfaces"].keys()) == set(_BUCKET_SURFACES)


def test_trifecta_excluded_from_surfaces():
    """'trifecta' must not appear as a key in coverage()['surfaces']."""
    result = coverage([])
    assert "trifecta" not in result["surfaces"]


def test_surfaces_count_is_exactly_13():
    result = coverage([])
    assert len(result["surfaces"]) == 13


# ── Surface state: checked vs partial ─────────────────────────────────────────

def test_empty_findings_all_surfaces_partial():
    """With no findings, every surface is 'partial' (nothing confirmed)."""
    result = coverage([])
    for slug, info in result["surfaces"].items():
        assert info["state"] == "partial", f"surface {slug!r} expected partial, got {info['state']!r}"


def test_all_unknown_findings_all_surfaces_partial():
    """If every check returns UNKNOWN, every surface is 'partial'."""
    result = coverage(_all_unknown())
    for slug, info in result["surfaces"].items():
        assert info["state"] == "partial", (
            f"surface {slug!r}: all-UNKNOWN should yield partial, got {info['state']!r}"
        )


def test_fail_finding_marks_surface_checked():
    """A single FAIL finding for a surface causes that surface to be 'checked'."""
    # B2 maps to "gateway"
    assert BY_ID["B2"].surface == "gateway"
    result = coverage([_f("B2", FAIL)])
    assert result["surfaces"]["gateway"]["state"] == "checked"


def test_pass_finding_marks_surface_checked():
    """A PASS finding also marks the surface as 'checked'."""
    assert BY_ID["B1"].surface == "secrets"
    result = coverage([_f("B1", PASS)])
    assert result["surfaces"]["secrets"]["state"] == "checked"


def test_warn_finding_marks_surface_checked():
    """A WARN finding marks the surface as 'checked'."""
    assert BY_ID["B3"].surface == "tools"
    result = coverage([_f("B3", WARN)])
    assert result["surfaces"]["tools"]["state"] == "checked"


def test_unknown_only_finding_keeps_surface_partial():
    """A single UNKNOWN finding for a surface — surface stays 'partial'."""
    assert BY_ID["B50"].surface == "host"
    result = coverage([_f("B50", UNKNOWN)])
    assert result["surfaces"]["host"]["state"] == "partial"


def test_mixed_unknown_and_fail_marks_checked():
    """If one finding is FAIL and another is UNKNOWN for the same surface, state is 'checked'."""
    assert BY_ID["B2"].surface == "gateway"
    assert BY_ID["B11"].surface == "gateway"
    result = coverage([_f("B2", FAIL), _f("B11", UNKNOWN)])
    assert result["surfaces"]["gateway"]["state"] == "checked"


def test_surface_counts_accumulate_correctly():
    """Counts for a surface aggregate all findings of that surface."""
    # B1, B9, B19 all map to "secrets"
    assert BY_ID["B1"].surface == "secrets"
    assert BY_ID["B9"].surface == "secrets"
    assert BY_ID["B19"].surface == "secrets"
    result = coverage([
        _f("B1", PASS),
        _f("B9", FAIL),
        _f("B19", UNKNOWN),
    ])
    counts = result["surfaces"]["secrets"]["counts"]
    assert counts["pass"] == 1
    assert counts["fail"] == 1
    assert counts["unknown"] == 1
    assert counts["warn"] == 0


def test_unrelated_surface_unaffected():
    """A finding on 'secrets' does not change 'gateway' counts."""
    result = coverage([_f("B1", FAIL)])
    gateway_counts = result["surfaces"]["gateway"]["counts"]
    assert all(v == 0 for v in gateway_counts.values())


# ── 7-family roll-up ──────────────────────────────────────────────────────────

def test_all_7_families_present():
    """coverage()['families'] must contain exactly the 7 dashboard family slugs."""
    result = coverage([])
    expected = {"exposure", "privilege", "supply_chain", "content_integrity",
                "secrets", "detection", "automation"}
    assert set(result["families"].keys()) == expected


def test_family_surfaces_match_family_of():
    """Each family's 'surfaces' list must match FAMILY_OF for that family."""
    result = coverage([])
    for fam, info in result["families"].items():
        expected = [s for s in _BUCKET_SURFACES if FAMILY_OF[s] == fam]
        assert info["surfaces"] == expected, (
            f"family {fam!r}: surfaces mismatch: got {info['surfaces']!r}, "
            f"expected {expected!r}"
        )


def test_finding_rolled_up_to_correct_family():
    """A finding in 'gateway' (exposure family) must appear in the 'exposure' family counts."""
    assert BY_ID["B2"].surface == "gateway"
    assert FAMILY_OF["gateway"] == "exposure"
    result = coverage([_f("B2", FAIL)])
    exposure = result["families"]["exposure"]
    assert exposure["counts"]["fail"] == 1


def test_finding_in_tools_rolls_up_to_privilege():
    """A finding in 'tools' (privilege family) must appear in 'privilege' counts."""
    assert BY_ID["B3"].surface == "tools"
    assert FAMILY_OF["tools"] == "privilege"
    result = coverage([_f("B3", WARN)])
    privilege = result["families"]["privilege"]
    assert privilege["counts"]["warn"] == 1


def test_finding_in_bootstrap_rolls_up_to_content_integrity():
    assert BY_ID["B6"].surface == "bootstrap"
    assert FAMILY_OF["bootstrap"] == "content_integrity"
    result = coverage([_f("B6", PASS)])
    assert result["families"]["content_integrity"]["counts"]["pass"] == 1


def test_finding_in_mcp_rolls_up_to_supply_chain():
    assert BY_ID["B15"].surface == "mcp"
    assert FAMILY_OF["mcp"] == "supply_chain"
    result = coverage([_f("B15", FAIL)])
    assert result["families"]["supply_chain"]["counts"]["fail"] == 1


def test_family_worst_fail():
    """Worst state is 'fail' when any member surface has a FAIL finding."""
    result = coverage([_f("B2", FAIL)])
    assert result["families"]["exposure"]["worst"] == "fail"


def test_family_worst_warn():
    """Worst state is 'warn' when no FAIL but at least one WARN."""
    result = coverage([_f("B3", WARN)])
    assert result["families"]["privilege"]["worst"] == "warn"


def test_family_worst_pass():
    """Worst state is 'pass' when findings are PASS only."""
    result = coverage([_f("B1", PASS)])
    assert result["families"]["secrets"]["worst"] == "pass"


def test_family_worst_unknown():
    """Worst state is 'unknown' when all findings are UNKNOWN."""
    result = coverage(_all_unknown())
    for fam, info in result["families"].items():
        assert info["worst"] == "unknown", (
            f"family {fam!r}: expected worst='unknown', got {info['worst']!r}"
        )


def test_family_aggregates_across_member_surfaces():
    """Family counts sum across all member surfaces (exposure = gateway + channels + sessions)."""
    assert FAMILY_OF["gateway"] == "exposure"
    assert FAMILY_OF["channels"] == "exposure"
    assert FAMILY_OF["sessions"] == "exposure"
    result = coverage([
        _f("B2", FAIL),    # gateway → exposure
        _f("B30", PASS),   # channels → exposure
        _f("B38", WARN),   # sessions → exposure
    ])
    counts = result["families"]["exposure"]["counts"]
    assert counts["fail"] == 1
    assert counts["pass"] == 1
    assert counts["warn"] == 1


# ── Static gaps ───────────────────────────────────────────────────────────────

def test_gaps_not_checkable_has_3_entries():
    """The static not_checkable list must have exactly 3 grounded entries."""
    result = coverage([])
    assert len(result["gaps"]["not_checkable"]) == 3


def test_gaps_not_checkable_contains_egress_allowlist():
    result = coverage([])
    assert "outbound egress allowlist" in result["gaps"]["not_checkable"]


def test_gaps_not_checkable_contains_talk_surface():
    result = coverage([])
    assert "talk.* surface" in result["gaps"]["not_checkable"]


def test_gaps_not_checkable_contains_per_agent_allowlist():
    result = coverage([])
    assert "per-agent tool allowlist" in result["gaps"]["not_checkable"]


def test_gaps_roadmap_empty():
    """No roadmap entries are hardcoded at this time."""
    result = coverage([])
    assert result["gaps"]["roadmap"] == []


def test_summary_not_checkable_count():
    result = coverage([])
    assert result["summary"]["not_checkable"] == 3


def test_summary_roadmap_count():
    result = coverage([])
    assert result["summary"]["roadmap"] == 0


# ── Summary counts ────────────────────────────────────────────────────────────

def test_summary_empty_findings_all_partial():
    result = coverage([])
    assert result["summary"]["checked"] == 0
    assert result["summary"]["partial"] == 13


def test_summary_checked_increments_per_surface():
    """Each surface with a non-UNKNOWN finding increments 'checked'."""
    # Two distinct surfaces: gateway (B2) and secrets (B1)
    result = coverage([_f("B2", FAIL), _f("B1", PASS)])
    assert result["summary"]["checked"] == 2
    assert result["summary"]["partial"] == 11  # 13 - 2


def test_summary_checked_plus_partial_always_13():
    """checked + partial always equals 13 (the total number of bucket surfaces)."""
    for findings in (
        [],
        [_f("B2", FAIL)],
        _all_unknown(),
        [_f("B2", PASS), _f("B1", WARN), _f("B3", FAIL)],
    ):
        result = coverage(findings)
        total = result["summary"]["checked"] + result["summary"]["partial"]
        assert total == 13, f"checked+partial={total}, expected 13 for {[f.id for f in findings]}"


# ── Determinism ───────────────────────────────────────────────────────────────

def test_deterministic_identical_calls():
    """Two calls with the same findings produce identical dicts."""
    findings = [_f("B2", FAIL), _f("B1", PASS), _f("B50", UNKNOWN)]
    r1 = coverage(findings)
    r2 = coverage(findings)
    assert r1 == r2


def test_deterministic_surface_order():
    """Surfaces appear in the canonical _BUCKET_SURFACES order."""
    result = coverage([])
    assert list(result["surfaces"].keys()) == list(_BUCKET_SURFACES)


def test_deterministic_family_order():
    """Families appear in the canonical _FAMILY_ORDER order."""
    result = coverage([])
    assert list(result["families"].keys()) == list(_FAMILY_ORDER)


def test_deterministic_family_surfaces_order():
    """Member surfaces within each family follow _BUCKET_SURFACES order."""
    result = coverage([])
    for fam, info in result["families"].items():
        expected = list(_FAMILY_SURFACES[fam])
        assert info["surfaces"] == expected, (
            f"family {fam!r}: surface order mismatch"
        )


def test_deterministic_not_checkable_order():
    """not_checkable list order is stable across calls."""
    r1 = coverage([])
    r2 = coverage([_f("B2", FAIL)])
    assert r1["gaps"]["not_checkable"] == r2["gaps"]["not_checkable"]


# ── Edge cases ────────────────────────────────────────────────────────────────

def test_unknown_finding_id_silently_ignored():
    """Findings with id not in BY_ID (e.g. MCP-VET) are skipped without error."""
    extra = Finding(
        id="MCP-VET", title="vet", severity=HIGH, status=FAIL,
        detail="d", fix="f", framework="fw",
    )
    # No exception; the unknown id has no surface assignment so it doesn't affect coverage.
    result = coverage([extra])
    assert result["summary"]["checked"] == 0


def test_trifecta_finding_not_counted_as_bucket():
    """A1 (trifecta surface) must not appear in surfaces or count toward summary."""
    assert BY_ID["A1"].surface == "trifecta"
    result = coverage([_f("A1", FAIL)])
    assert "trifecta" not in result["surfaces"]
    assert result["summary"]["checked"] == 0


def test_counts_keys_always_present():
    """Every surface counts dict always has all four keys: pass/warn/fail/unknown."""
    result = coverage([])
    for slug, info in result["surfaces"].items():
        assert set(info["counts"].keys()) == {"pass", "warn", "fail", "unknown"}, (
            f"surface {slug!r} counts dict missing keys"
        )
