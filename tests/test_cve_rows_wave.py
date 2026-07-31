"""P1-cve-rows — two upstream advisories added to B33's _KNOWN_ADVISORIES table
(clawseccheck/checks/_lifecycle.py). Both independently verified against upstream
(osv.dev + the GitHub Security Advisory pages) before being added — see task
comments for the fetch evidence; not re-derived here.

CVE-2026-27488 (GHSA-w45g-5746-x9fp) — OpenClaw cron webhook delivery
(src/gateway/server-cron.ts) called fetch() directly with no SSRF policy checks.
Confirmed via the vendor security advisory: "openclaw npm package versions
<= 2026.2.17" affected, fixed in 2026.2.19. Version-only row — no config-field
surface exists for this (the vulnerable code path has no policy toggle to audit).

CVE-2026-62223 (GHSA-ww99-rc68-x2pj, aka GHSA-hx85-fgcw-9vrc) — device-pair
approval feature let lower-trust callers bypass authorization checks. Confirmed
via osv.dev: "OpenClaw before 2026.5.18", fixed 2026.5.18. Shares its date with
the already-present CVE-2026-53810 / GHSA-3c6j-hq33-3jv4 rows (max_vuln
(2026, 5, 17), fixed "2026.5.18"), so the boundary tuple follows that existing
precedent for a same-day fix.

Each row is exercised through the real check_known_vulns() function (not by
re-asserting the table literal): below its max_vulnerable_version_tuple fires
(this id present in detail/evidence), at its own fixed_version_str the row no
longer contributes (id absent — mirrors test_b33.py's existing per-row
boundary-clears assertion, since later table rows may still legitimately keep
the overall verdict FAIL), and an unparseable/missing version yields UNKNOWN,
never a fake PASS/FAIL.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN
from clawseccheck.checks import _KNOWN_ADVISORIES, check_known_vulns
from clawseccheck.collector import Context


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def _ver_ctx(version_str: str | None) -> Context:
    if version_str is None:
        return _ctx({})
    return _ctx({"meta": {"lastTouchedVersion": version_str}})


# ---------------------------------------------------------------------------
# Table sanity — both new rows present with the exact verified boundary.
# ---------------------------------------------------------------------------

def test_cve_2026_27488_row_present_with_verified_boundary():
    table = {row[0]: (row[1], row[2]) for row in _KNOWN_ADVISORIES}
    assert "CVE-2026-27488" in table
    assert table["CVE-2026-27488"] == ((2026, 2, 17), "2026.2.19")


def test_cve_2026_62223_row_present_with_verified_boundary():
    table = {row[0]: (row[1], row[2]) for row in _KNOWN_ADVISORIES}
    assert "CVE-2026-62223" in table
    assert table["CVE-2026-62223"] == ((2026, 5, 17), "2026.5.18")


def test_no_row_boundary_lands_on_its_own_fix_base_for_the_new_rows():
    """Same guard as test_b33.py's existing rule, re-checked for the two new
    rows specifically: max_vuln must never equal the base tuple of its own
    fixed_version_str (that shape would FAIL an already-fixed install)."""
    from clawseccheck.checks import _parse_version

    for ghsa, max_vuln, fixed_ver, _desc in _KNOWN_ADVISORIES:
        if ghsa in ("CVE-2026-27488", "CVE-2026-62223"):
            assert _parse_version(fixed_ver) != max_vuln


# ---------------------------------------------------------------------------
# CVE-2026-27488 — cron webhook SSRF (max_vuln (2026, 2, 17), fixed "2026.2.19")
# ---------------------------------------------------------------------------

def test_cve_2026_27488_below_boundary_fires():
    """2026.2.10 < max_vuln (2026, 2, 17) -> FAIL, citing this advisory."""
    result = check_known_vulns(_ver_ctx("2026.2.10"))
    assert result.status == FAIL
    assert "CVE-2026-27488" in result.detail
    assert "CVE-2026-27488" in result.evidence


def test_cve_2026_27488_at_max_vuln_boundary_fires():
    """2026.2.17 == max_vuln -> FAIL, citing this advisory (inclusive <=)."""
    result = check_known_vulns(_ver_ctx("2026.2.17"))
    assert result.status == FAIL
    assert "CVE-2026-27488" in result.detail
    assert "CVE-2026-27488" in result.evidence


def test_cve_2026_27488_fixed_version_clears_this_row():
    """At 2026.2.19 (this row's own fixed_version_str) the row itself must no
    longer be cited — even though the overall verdict may still be FAIL due to
    later, unrelated table rows (that is correct behavior, not this row's)."""
    result = check_known_vulns(_ver_ctx("2026.2.19"))
    assert "CVE-2026-27488" not in result.detail
    assert "CVE-2026-27488" not in result.evidence


# ---------------------------------------------------------------------------
# CVE-2026-62223 — device-pair authorization bypass
# (max_vuln (2026, 5, 17), fixed "2026.5.18")
# ---------------------------------------------------------------------------

def test_cve_2026_62223_below_boundary_fires():
    """2026.5.10 < max_vuln (2026, 5, 17) -> FAIL, citing this advisory."""
    result = check_known_vulns(_ver_ctx("2026.5.10"))
    assert result.status == FAIL
    assert "CVE-2026-62223" in result.detail
    assert "CVE-2026-62223" in result.evidence


def test_cve_2026_62223_at_max_vuln_boundary_fires():
    """2026.5.17 == max_vuln -> FAIL, citing this advisory (inclusive <=)."""
    result = check_known_vulns(_ver_ctx("2026.5.17"))
    assert result.status == FAIL
    assert "CVE-2026-62223" in result.detail
    assert "CVE-2026-62223" in result.evidence


def test_cve_2026_62223_fixed_version_clears_this_row():
    """At 2026.5.18 (this row's own fixed_version_str) the row itself must no
    longer be cited — the overall verdict may still legitimately FAIL because
    of later, unrelated table rows."""
    result = check_known_vulns(_ver_ctx("2026.5.18"))
    assert "CVE-2026-62223" not in result.detail
    assert "CVE-2026-62223" not in result.evidence


def test_cve_2026_62223_shares_boundary_with_existing_e059_rows():
    """CVE-2026-62223 shares its (max_vuln, fixed_version) pair with the
    already-present CVE-2026-53810 / GHSA-3c6j-hq33-3jv4 rows — all three fire
    together at the same boundary version, per the existing same-day-fix
    precedent in the table."""
    result = check_known_vulns(_ver_ctx("2026.5.17"))
    assert result.status == FAIL
    assert "CVE-2026-62223" in result.evidence
    assert "CVE-2026-53810" in result.evidence
    assert "GHSA-3c6j-hq33-3jv4" in result.evidence


# ---------------------------------------------------------------------------
# Undetectable version -> UNKNOWN, never a fake PASS/FAIL, for either new row.
# ---------------------------------------------------------------------------

def test_undetectable_version_yields_unknown_not_a_fake_verdict():
    result = check_known_vulns(_ver_ctx("nightly"))
    assert result.status == UNKNOWN
    assert result.status not in (PASS, FAIL)
    assert "CVE-2026-27488" not in result.detail
    assert "CVE-2026-62223" not in result.detail
    assert result.evidence == []


def test_missing_version_yields_unknown_not_a_fake_verdict():
    result = check_known_vulns(_ver_ctx(None))
    assert result.status == UNKNOWN
    assert "CVE-2026-27488" not in result.detail
    assert "CVE-2026-62223" not in result.detail
    assert result.evidence == []


# ---------------------------------------------------------------------------
# Sanity: a version past every advisory in the (unchanged) newest boundary
# still PASSes overall — the two additions don't push the table's ceiling.
# ---------------------------------------------------------------------------

def test_version_past_every_advisory_still_passes_overall():
    result = check_known_vulns(_ver_ctx("2026.6.6"))
    assert result.status == PASS
    assert "CVE-2026-27488" not in result.detail
    assert "CVE-2026-62223" not in result.detail
