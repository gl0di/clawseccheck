"""B33 — Known-vulnerable OpenClaw version gate tests.

Logic under test (check_known_vulns + _parse_version):
- UNKNOWN  when meta.lastTouchedVersion is absent or cannot be parsed to >= 2
           integer components.
- FAIL     when the parsed version tuple <= ANY known advisory's
           max_vulnerable_version_tuple. B-332: ALL matching rows are reported (not
           just the first table match) — the `fix` names the HIGHEST fixed_version
           across every match, since that is the only version that actually clears
           the finding in one upgrade.
- PASS     when the parsed version is past all known advisory fixes.

Confirmed advisories seeded in _KNOWN_ADVISORIES:
  GHSA-g8p2-7wf7-98mq — OpenClaw/clawdbot <= 2026.1.28 vulnerable,
  fixed in 2026.1.29.  No CVE assigned.
  GHSA-mc68-q9jw-2h3v — OpenClaw <= 2026.1.28 vulnerable (Docker sandbox
  authenticated command injection via unsafe PATH handling), fixed in 2026.1.29.
  GHSA-g6q9-8fvw-f7rf — OpenClaw <= 2026.2.13 vulnerable (Gateway tool SSRF via
  unvalidated gatewayUrl override), fixed in 2026.2.14.
  GHSA-cv7m-c9jx-vg7q — OpenClaw <= 2026.2.13 vulnerable (Browser upload path
  traversal via Playwright setInputFiles), fixed in 2026.2.14.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, UNKNOWN
from clawseccheck.checks import _parse_version, check_known_vulns
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
# _parse_version unit tests (edge cases)
# ---------------------------------------------------------------------------

def test_parse_version_standard_three_component():
    assert _parse_version("2026.1.29") == (2026, 1, 29)


def test_parse_version_two_component():
    assert _parse_version("2026.1") == (2026, 1)


def test_parse_version_strips_dev_suffix():
    assert _parse_version("2026.1.28-dev") == (2026, 1, 28)


def test_parse_version_strips_beta_suffix():
    assert _parse_version("2026.2.9-beta") == (2026, 2, 9)


def test_parse_version_strips_rc_suffix():
    assert _parse_version("2026.3.0-rc1") == (2026, 3, 0)


def test_parse_version_strips_numeric_correction_suffix():
    """B-264: a hyphenated correction release ("2026.7.1-2", observed live in
    package.json/lastTouchedVersion) truncates identically to its base version —
    _parse_version cannot distinguish a correction release from its base."""
    assert _parse_version("2026.7.1-2") == (2026, 7, 1)
    assert _parse_version("2026.7.1-2") == _parse_version("2026.7.1")


def test_parse_version_four_components():
    assert _parse_version("2026.1.28.1") == (2026, 1, 28, 1)


def test_parse_version_single_component_returns_none():
    """A single integer is too ambiguous — must return None."""
    assert _parse_version("2026") is None


def test_parse_version_nightly_string_returns_none():
    assert _parse_version("nightly") is None


def test_parse_version_empty_string_returns_none():
    assert _parse_version("") is None


def test_parse_version_words_only_returns_none():
    assert _parse_version("latest") is None


def test_parse_version_leading_v_prefix_returns_none():
    """A leading 'v' like 'v2026.1.28' has no leading digit -> returns None."""
    assert _parse_version("v2026.1.28") is None


def test_parse_version_whitespace_stripped():
    assert _parse_version("  2026.1.29  ") == (2026, 1, 29)


# ---------------------------------------------------------------------------
# UNKNOWN cases
# ---------------------------------------------------------------------------

def test_b33_missing_version_field_unknown():
    """meta.lastTouchedVersion absent -> UNKNOWN."""
    assert check_known_vulns(_ctx({})).status == UNKNOWN


def test_b33_empty_meta_block_unknown():
    """meta block present but lastTouchedVersion not set -> UNKNOWN."""
    assert check_known_vulns(_ctx({"meta": {}})).status == UNKNOWN


def test_b33_unparseable_version_nightly_unknown():
    """Unparseable version string 'nightly' -> UNKNOWN (never PASS)."""
    result = check_known_vulns(_ver_ctx("nightly"))
    assert result.status == UNKNOWN


def test_b33_unparseable_version_words_unknown():
    """Unparseable version string 'latest-dev' -> UNKNOWN."""
    result = check_known_vulns(_ver_ctx("latest-dev"))
    assert result.status == UNKNOWN


def test_b33_single_integer_version_unknown():
    """Single-component version '2026' is too ambiguous -> UNKNOWN."""
    result = check_known_vulns(_ver_ctx("2026"))
    assert result.status == UNKNOWN


# ---------------------------------------------------------------------------
# FAIL cases — affected by GHSA-g8p2-7wf7-98mq (<= 2026.1.28)
# ---------------------------------------------------------------------------

def test_b33_version_2026_1_20_fails():
    """2026.1.20 < 2026.1.28 -> FAIL (within vulnerable range)."""
    result = check_known_vulns(_ver_ctx("2026.1.20"))
    assert result.status == FAIL
    assert "GHSA-g8p2-7wf7-98mq" in result.detail


def test_b33_version_2026_1_28_fails():
    """2026.1.28 == max vulnerable version -> FAIL (boundary: <= is vulnerable)."""
    result = check_known_vulns(_ver_ctx("2026.1.28"))
    assert result.status == FAIL
    assert "GHSA-g8p2-7wf7-98mq" in result.detail


def test_b33_fail_names_ghsa_not_cve():
    """FAIL detail must cite the GHSA id for the earliest advisory (GHSA-g8p2-7wf7-98mq
    has no CVE assigned). B-332: at the oldest vulnerable version, EVERY matched
    advisory is named, including later ones that DO carry a CVE id — so unlike before
    this fix, "CVE" legitimately appears in the detail too."""
    result = check_known_vulns(_ver_ctx("2026.1.20"))
    assert result.status == FAIL
    assert "GHSA-g8p2-7wf7-98mq" in result.detail


def test_b33_fail_names_fixed_version():
    """B-332: FAIL fix text must mention the HIGHEST fixed version across every
    matched advisory (2026.6.6, CVE-2026-62195's fix) — not just the first table
    row's fixed version (2026.1.29) — since only the highest actually clears the
    finding in a single upgrade."""
    result = check_known_vulns(_ver_ctx("2026.1.28"))
    assert result.status == FAIL
    assert "2026.6.6" in result.fix
    assert "2026.1.29" not in result.fix


def test_b33_fail_evidence_contains_ghsa():
    """FAIL evidence list must include the GHSA id."""
    result = check_known_vulns(_ver_ctx("2026.1.28"))
    assert result.status == FAIL
    assert "GHSA-g8p2-7wf7-98mq" in result.evidence


def test_b33_version_with_dev_suffix_at_boundary_fails():
    """2026.1.28-dev strips to (2026, 1, 28) -> FAIL (still vulnerable)."""
    result = check_known_vulns(_ver_ctx("2026.1.28-dev"))
    assert result.status == FAIL


def test_b33_version_earlier_minor_fails():
    """2026.0.9 < (2026, 1, 28) -> FAIL."""
    result = check_known_vulns(_ver_ctx("2026.0.9"))
    assert result.status == FAIL


# ---------------------------------------------------------------------------
# B-059 regression: root-level lastTouchedVersion alias
# Some OpenClaw builds record the version at the config root, not under meta. B33 read
# meta.lastTouchedVersion only, so a root-alias build silently returned UNKNOWN and
# skipped the CVE gate. It now mirrors C4: meta.lastTouchedVersion or lastTouchedVersion.
# ---------------------------------------------------------------------------

def test_b33_root_alias_affected_version_fails():
    """Root-level lastTouchedVersion in the vulnerable range -> FAIL (was UNKNOWN)."""
    result = check_known_vulns(_ctx({"lastTouchedVersion": "2026.1.20"}))
    assert result.status == FAIL
    assert "GHSA-g8p2-7wf7-98mq" in result.detail


def test_b33_root_alias_safe_version_passes():
    """Root-level lastTouchedVersion past all known-advisory fixes -> PASS."""
    assert check_known_vulns(_ctx({"lastTouchedVersion": "2026.6.6"})).status == PASS


def test_b33_meta_takes_precedence_over_root_alias():
    """When both are set, meta.lastTouchedVersion wins (mirrors C4's `meta or root`)."""
    cfg = {"meta": {"lastTouchedVersion": "2026.1.20"}, "lastTouchedVersion": "2026.2.9"}
    assert check_known_vulns(_ctx(cfg)).status == FAIL  # meta (affected) wins


def test_b33_neither_meta_nor_root_unknown():
    """Neither meta nor root version set -> UNKNOWN."""
    assert check_known_vulns(_ctx({"gateway": {}})).status == UNKNOWN


# ---------------------------------------------------------------------------
# PASS cases — past all known advisory fixes
# ---------------------------------------------------------------------------

def test_b33_version_2026_1_29_fixed_for_earlier_advisories_but_fails_newer():
    """2026.1.29 fixes GHSA-g8p2/-mc68 but is still <= 2026.2.13 -> FAIL
    against GHSA-g6q9-8fvw-f7rf / GHSA-cv7m-c9jx-vg7q."""
    result = check_known_vulns(_ver_ctx("2026.1.29"))
    assert result.status == FAIL


def test_b33_version_2026_2_9_fails_newer_advisories():
    """2026.2.9 > 2026.1.28 but <= 2026.2.13 -> FAIL (Gateway SSRF / browser upload)."""
    result = check_known_vulns(_ver_ctx("2026.2.9"))
    assert result.status == FAIL


def test_b33_version_2026_2_14_fixed_for_original_four_but_fails_e059_additions():
    """2026.2.14 fixes the original 4 advisories but the E-059 sweep (2026-07-22)
    added several more with boundaries past it -> still FAIL."""
    result = check_known_vulns(_ver_ctx("2026.2.14"))
    assert result.status == FAIL


def test_b33_version_much_newer_passes():
    """2027.1.0 far past any known advisory -> PASS."""
    result = check_known_vulns(_ver_ctx("2027.1.0"))
    assert result.status == PASS


def test_b33_pass_detail_includes_version():
    """PASS detail should mention the installed version string."""
    result = check_known_vulns(_ver_ctx("2026.6.6"))
    assert result.status == PASS
    assert "2026.6.6" in result.detail


@pytest.mark.parametrize("version_str,expected_status", [
    ("2026.1.20", FAIL),
    ("2026.1.28", FAIL),
    ("2026.1.29", FAIL),  # fixed for GHSA-g8p2/-mc68 but now in GHSA-g6q9/-cv7m range
    ("2026.2.9",  FAIL),  # still <= 2026.2.13 -> hits GHSA-g6q9-8fvw-f7rf / GHSA-cv7m-c9jx-vg7q
    ("2026.2.14", FAIL),  # fixed for the original 4 but now hits an E-059 addition
    ("2026.6.6",  PASS),  # past every advisory in the table, including E-059's newest
    ("nightly",   UNKNOWN),
    (None,        UNKNOWN),
])
def test_b33_parametrized_version_status(version_str, expected_status):
    """Parametrized sweep covering all outcome branches."""
    result = check_known_vulns(_ver_ctx(version_str))
    assert result.status == expected_status


# ---------------------------------------------------------------------------
# New advisories (S1): GHSA-mc68-q9jw-2h3v, GHSA-g6q9-8fvw-f7rf, GHSA-cv7m-c9jx-vg7q
# ---------------------------------------------------------------------------

def test_b33_ghsa_mc68_docker_sandbox_injection_fails_at_boundary():
    """2026.1.28 <= max_vuln (2026, 1, 28) for GHSA-mc68-q9jw-2h3v -> FAIL.

    B-332: both GHSA-g8p2 and GHSA-mc68 share this boundary/fix, and BOTH (plus every
    other matched advisory) are now named in detail — not just whichever came first
    in table order."""
    result = check_known_vulns(_ver_ctx("2026.1.28"))
    assert result.status == FAIL
    assert "GHSA-g8p2-7wf7-98mq" in result.detail
    assert "GHSA-mc68-q9jw-2h3v" in result.detail


def test_b33_ghsa_g6q9_gateway_ssrf_fails_at_2026_2_0():
    """2026.2.0 <= 2026.2.13 -> FAIL, naming GHSA-g6q9-8fvw-f7rf (Gateway SSRF) among
    the matched advisories. B-332: `fix` targets the HIGHEST fixed version across ALL
    matches (2026.6.6), not GHSA-g6q9's own fixed version (2026.2.14) — upgrading only
    to 2026.2.14 would still leave every later advisory in the table unfixed."""
    result = check_known_vulns(_ver_ctx("2026.2.0"))
    assert result.status == FAIL
    assert "GHSA-g6q9-8fvw-f7rf" in result.detail
    assert "2026.6.6" in result.fix


def test_b33_ghsa_g6q9_boundary_2026_2_13_fails():
    """2026.2.13 == max_vuln boundary for GHSA-g6q9-8fvw-f7rf -> FAIL."""
    result = check_known_vulns(_ver_ctx("2026.2.13"))
    assert result.status == FAIL
    assert "GHSA-g6q9-8fvw-f7rf" in result.detail


def test_b33_ghsa_cv7m_browser_upload_traversal_shares_boundary():
    """GHSA-cv7m-c9jx-vg7q also bounds at 2026.2.13/fixed 2026.2.14; both it and
    GHSA-g6q9-8fvw-f7rf are present in the table and (B-332) neither is skipped in the
    actual check output for a version in their shared range."""
    ids = {ghsa for ghsa, *_ in __import__(
        "clawseccheck.checks", fromlist=["_KNOWN_ADVISORIES"]
    )._KNOWN_ADVISORIES}
    assert "GHSA-cv7m-c9jx-vg7q" in ids
    assert "GHSA-g6q9-8fvw-f7rf" in ids

    result = check_known_vulns(_ver_ctx("2026.2.13"))
    assert result.status == FAIL
    assert "GHSA-cv7m-c9jx-vg7q" in result.detail
    assert "GHSA-g6q9-8fvw-f7rf" in result.detail
    assert "GHSA-mc68-q9jw-2h3v" in ids


def test_b33_ghsa_g6q9_fixed_version_2026_2_14_fixed_but_not_past_e059_additions():
    """2026.2.14 == fixed version for GHSA-g6q9/-cv7m but the E-059 sweep added
    advisories with later boundaries -> still FAIL."""
    result = check_known_vulns(_ver_ctx("2026.2.14"))
    assert result.status == FAIL


def test_b33_version_2026_6_6_passes_all_advisories():
    """Past every known advisory fix, including the E-059 sweep's newest
    (CVE-2026-62195, fixed 2026.6.6) -> PASS."""
    result = check_known_vulns(_ver_ctx("2026.6.6"))
    assert result.status == PASS


def test_b33_known_advisories_table_has_twenty_three_entries():
    """The ClawRadar sweep 2026-07-22 appended 19 fetch-confirmed advisories to
    the existing 4 -> 23 total."""
    from clawseccheck.checks import _KNOWN_ADVISORIES
    assert len(_KNOWN_ADVISORIES) == 23


def test_b33_does_not_add_unverified_cve_2026_25593():
    """Recon explicitly marks CVE-2026-25593 UNVERIFIED — must not be shipped."""
    from clawseccheck.checks import _KNOWN_ADVISORIES
    ghsa_ids = {ghsa for ghsa, *_ in _KNOWN_ADVISORIES}
    assert "GHSA-2026-25593" not in ghsa_ids
    for ghsa, *_ in _KNOWN_ADVISORIES:
        assert "25593" not in ghsa


# ---------------------------------------------------------------------------
# B-264: hyphenated correction-release version pin (e.g. "2026.7.1-2", observed
# live in ~/.npm-global's package.json and the real ~/.openclaw/openclaw.json
# lastTouchedVersion). No _KNOWN_ADVISORIES entry currently shares a base tuple
# with a correction release, so this is a latent-guard pin, not a behavior change:
# it documents today's (correct) PASS and the boundary shape a future advisory
# must not collide with (see the correction-release warning above the
# _KNOWN_ADVISORIES table in clawseccheck/checks/_lifecycle.py).
# ---------------------------------------------------------------------------

def test_b33_correction_release_suffix_passes_current_table():
    """"2026.7.1-2" is past every current advisory fix -> PASS (no live FP).

    ⚠️ If a future advisory legitimately covers <= 2026.7.x this WILL go red. Do NOT
    simply bump the version literal to make it pass — that silently discards the guard.
    A red here means the new advisory's boundary may split a correction-release family;
    re-read the warning above _KNOWN_ADVISORIES and pick a boundary that does not, or
    change the comparator.
    """
    result = check_known_vulns(_ver_ctx("2026.7.1-2"))
    assert result.status == PASS


def test_b33_correction_release_at_vulnerable_boundary_fails():
    """"2026.2.13-2" truncates to (2026, 2, 13) == max_vuln for GHSA-g6q9/-cv7m
    -> FAIL, same as its base version "2026.2.13"."""
    result = check_known_vulns(_ver_ctx("2026.2.13-2"))
    assert result.status == FAIL
    assert result.status == check_known_vulns(_ver_ctx("2026.2.13")).status


def test_b33_correction_release_past_boundary_passes():
    """"2026.6.6-2" truncates to (2026, 6, 6), past all known-advisory fixes
    (including the E-059 sweep's newest) -> PASS, same as its base "2026.6.6"."""
    result = check_known_vulns(_ver_ctx("2026.6.6-2"))
    assert result.status == PASS
    assert result.status == check_known_vulns(_ver_ctx("2026.6.6")).status


# ---------------------------------------------------------------------------
# ClawRadar sweep 2026-07-22 — 19 fetch-confirmed advisories,
# each individually re-verified (direct advisory-page fetch, not just a listing
# page) for a precise affected-version-range + fixed-version pair before being
# added here. Every one is version-only: no groundable openclaw.json config-field
# surface exists for any of them (confirmed against the recon oracle), so B33's
# existing version-gate mechanism is the correct and only safe way to track them.
# ---------------------------------------------------------------------------

_E059_ADVISORIES = [
    ("GHSA-gv46-4xfq-jv58", (2026, 2, 13), "2026.2.14"),
    ("GHSA-pv58-549p-qh99", (2026, 2, 13), "2026.2.14"),
    ("CVE-2026-32045", (2026, 2, 20), "2026.2.21"),
    ("CVE-2026-32013", (2026, 2, 24), "2026.2.25"),
    ("GHSA-6rmx-gvvg-vh6j", (2026, 3, 2), "2026.3.7"),
    ("GHSA-5jvj-hxmh-6h6j", (2026, 3, 24), "2026.3.25"),
    ("CVE-2026-43584", (2026, 4, 9), "2026.4.10"),
    ("GHSA-8372-7vhw-cm6q", (2026, 4, 13), "2026.4.14"),
    ("GHSA-v8cx-933x-r976", (2026, 4, 24), "2026.4.25"),
    ("GHSA-jvm4-4j77-39p6", (2026, 4, 27), "2026.4.29"),
    ("GHSA-w4v6-g3wm-w36c", (2026, 4, 28), "2026.4.29"),
    ("GHSA-xr4f-mjxj-w6w5", (2026, 5, 3), "2026.5.4"),
    ("GHSA-w5ww-7chg-mxcq", (2026, 5, 5), "2026.5.6"),
    ("GHSA-77q5-rr5v-x43q", (2026, 5, 6), "2026.5.7"),
    ("GHSA-j472-gf56-x589", (2026, 5, 7), "2026.5.12"),
    ("CVE-2026-53810", (2026, 5, 17), "2026.5.18"),
    ("GHSA-3c6j-hq33-3jv4", (2026, 5, 17), "2026.5.18"),
    ("CVE-2026-62218", (2026, 5, 26), "2026.5.27"),
    ("CVE-2026-62195", (2026, 6, 5), "2026.6.6"),
]


@pytest.mark.parametrize("ident,max_vuln,fixed_ver", _E059_ADVISORIES)
def test_b33_e059_advisory_present_with_exact_boundary(ident, max_vuln, fixed_ver):
    """Each E-059 advisory is present verbatim with its confirmed boundary — a
    direct membership check sidesteps the "which one fires first" ambiguity that
    shared/overlapping boundaries create for a black-box FAIL-message assertion."""
    from clawseccheck.checks import _KNOWN_ADVISORIES
    table = {row[0]: (row[1], row[2]) for row in _KNOWN_ADVISORIES}
    assert ident in table, f"{ident} missing from _KNOWN_ADVISORIES"
    assert table[ident] == (max_vuln, fixed_ver)


@pytest.mark.parametrize("ident,max_vuln,fixed_ver", _E059_ADVISORIES)
def test_b33_e059_advisory_boundary_version_fails(ident, max_vuln, fixed_ver):
    """At-or-below every E-059 advisory's max_vuln, the gate FAILs (possibly citing
    an earlier table entry with an overlapping/lower boundary — correctness only
    requires SOME advisory to fire, not that this exact one wins list order)."""
    version_str = ".".join(str(x) for x in max_vuln)
    result = check_known_vulns(_ver_ctx(version_str))
    assert result.status == FAIL


def test_b33_e059_version_past_the_last_advisory_passes():
    """2026.6.6 (CVE-2026-62195's own fix) is the highest boundary in the table
    -> PASS, since nothing later can still match."""
    result = check_known_vulns(_ver_ctx("2026.6.6"))
    assert result.status == PASS


def test_b33_e059_version_before_the_last_advisory_fails():
    """2026.6.5 <= CVE-2026-62195's max_vuln -> FAIL."""
    result = check_known_vulns(_ver_ctx("2026.6.5"))
    assert result.status == FAIL
    assert "CVE-2026-62195" in result.detail


def test_b33_no_advisory_boundary_lands_on_its_own_fix_base():
    """Mechanized half of the correction-release rule: no row may set max_vuln to the
    base tuple of its own fixed version.

    That combination means the fix shipped in a correction release of the boundary
    version, and since _parse_version collapses "X-N" onto "X", the already-fixed
    build would FAIL (GR#5 false positive) with the self-contradicting remediation
    "upgrade to >= <the version you are on>".

    NOTE — this pins only direction (a) of the rule. Direction (b), a regression
    INTRODUCED in a correction release, produces a row that satisfies this assertion
    and still false-FAILs the clean base version; it is not derivable from the table
    alone, so it stays a prose rule. See the warning above _KNOWN_ADVISORIES.
    """
    from clawseccheck.checks import _KNOWN_ADVISORIES
    for ghsa, max_vuln, fixed_ver, _desc in _KNOWN_ADVISORIES:
        assert _parse_version(fixed_ver) != max_vuln, (
            f"{ghsa}: max_vuln {max_vuln} equals the base tuple of fixed version "
            f"{fixed_ver!r} — a correction-release fix cannot be expressed in this "
            f"table; see the warning above _KNOWN_ADVISORIES"
        )


# ---------------------------------------------------------------------------
# B-332: "B33 reports only the oldest matching advisory — its remediation leaves
# the user vulnerable for 17 more upgrades". Fixed by collecting ALL matching
# rows instead of returning on the first.
# ---------------------------------------------------------------------------

def test_b33_treadmill_closed_in_one_step():
    """From the oldest vulnerable version, `fix` must name the HIGHEST fixed_version
    across every matched advisory — not the first table row's — so applying it in a
    SINGLE step reaches PASS. Before B-332, following the advice took 17 sequential
    upgrades (each fix pointing only to the next-oldest advisory's fix)."""
    from clawseccheck.checks import _KNOWN_ADVISORIES

    oldest = check_known_vulns(_ver_ctx("2026.1.28"))
    assert oldest.status == FAIL

    matched = [row for row in _KNOWN_ADVISORIES if (2026, 1, 28) <= row[1]]
    assert len(matched) == len(_KNOWN_ADVISORIES)  # sanity: the oldest version matches all rows
    highest_fixed = max(
        (fixed_ver for _ghsa, _max_vuln, fixed_ver, _desc in matched),
        key=lambda v: _parse_version(v),
    )
    assert highest_fixed == "2026.6.6"
    assert highest_fixed in oldest.fix

    result = check_known_vulns(_ver_ctx(highest_fixed))
    assert result.status == PASS


def test_b33_evidence_contains_every_matched_advisory_or_shows_truncation():
    """evidence must contain every applicable advisory id, or an explicit
    "showing N of M" note in detail when the evidence cap truncates the list."""
    from clawseccheck.checks import _KNOWN_ADVISORIES

    result = check_known_vulns(_ver_ctx("2026.1.28"))
    assert result.status == FAIL

    matched_ids = [ghsa for ghsa, max_vuln, _fv, _d in _KNOWN_ADVISORIES if (2026, 1, 28) <= max_vuln]
    total = len(matched_ids)
    assert total == len(_KNOWN_ADVISORIES)

    if total > len(result.evidence):
        # Truncated: every id actually shown must be a real match, and detail must
        # disclose how many were dropped rather than silently omitting them.
        assert len(result.evidence) < total
        assert f"showing {len(result.evidence)} of {total}" in result.detail
        for gid in result.evidence:
            assert gid in matched_ids
    else:
        # Not truncated: every matched id must be present.
        for gid in matched_ids:
            assert gid in result.evidence


def test_b33_evidence_not_truncated_for_small_match_set():
    """A version matching only one advisory must not trigger truncation wording."""
    result = check_known_vulns(_ver_ctx("2026.6.5"))
    assert result.status == FAIL
    assert result.evidence == ["CVE-2026-62195"]
    assert "showing" not in result.detail


def test_b33_per_row_boundary_advisory_not_named_at_own_fixed_version():
    """Per-row boundary correctness (verified in the B-332 report; now pinned as a
    regression test): for every row in the table, the advisory id must NOT appear in
    the check's output once the installed version reaches that row's own
    fixed_version_str — 0 leaks, regardless of whether OTHER (later) advisories still
    make the overall verdict FAIL."""
    from clawseccheck.checks import _KNOWN_ADVISORIES

    for ghsa, _max_vuln, fixed_ver, _desc in _KNOWN_ADVISORIES:
        result = check_known_vulns(_ver_ctx(fixed_ver))
        assert ghsa not in result.detail, (
            f"{ghsa} still named in detail at its own fixed version {fixed_ver}"
        )
        assert ghsa not in result.evidence, (
            f"{ghsa} still present in evidence at its own fixed version {fixed_ver}"
        )


def test_b33_fix_never_names_a_fixed_version_still_vulnerable_to_a_match():
    """Applying `fix`'s target version must never leave ANY matched advisory open —
    i.e. the named fixed version must itself PASS the check (sanity sweep across a
    spread of vulnerable starting versions, not just the oldest)."""
    for version_str in ("2026.1.20", "2026.2.9", "2026.3.1", "2026.5.1", "2026.6.5"):
        result = check_known_vulns(_ver_ctx(version_str))
        assert result.status == FAIL
        # Extract the ">= X" target named in fix and confirm it PASSes.
        import re as _re
        m = _re.search(r">=\s*(\S+?)\s+to remediate", result.fix)
        assert m, f"could not find upgrade target in fix text: {result.fix!r}"
        target = m.group(1)
        assert check_known_vulns(_ver_ctx(target)).status == PASS, (
            f"fix target {target!r} for {version_str} does not clear the finding"
        )
