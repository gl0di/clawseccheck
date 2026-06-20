"""B33 — Known-vulnerable OpenClaw version gate tests.

Logic under test (check_known_vulns + _parse_version):
- UNKNOWN  when meta.lastTouchedVersion is absent or cannot be parsed to >= 2
           integer components.
- FAIL     when the parsed version tuple <= a known advisory's
           max_vulnerable_version_tuple (names the GHSA id, not a CVE).
- PASS     when the parsed version is past all known advisory fixes.

Confirmed advisory seeded in _KNOWN_ADVISORIES:
  GHSA-g8p2-7wf7-98mq — OpenClaw/clawdbot <= 2026.1.28 vulnerable,
  fixed in 2026.1.29.  No CVE assigned.
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
    """FAIL detail must cite the GHSA id; no CVE was assigned."""
    result = check_known_vulns(_ver_ctx("2026.1.20"))
    assert result.status == FAIL
    assert "GHSA-g8p2-7wf7-98mq" in result.detail
    assert "CVE" not in result.detail


def test_b33_fail_names_fixed_version():
    """FAIL fix text must mention the fixed version 2026.1.29."""
    result = check_known_vulns(_ver_ctx("2026.1.28"))
    assert result.status == FAIL
    assert "2026.1.29" in result.fix


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
# PASS cases — past all known advisory fixes
# ---------------------------------------------------------------------------

def test_b33_version_2026_1_29_passes():
    """2026.1.29 == first fixed version -> PASS (boundary: > max_vuln)."""
    result = check_known_vulns(_ver_ctx("2026.1.29"))
    assert result.status == PASS


def test_b33_version_2026_2_9_passes():
    """2026.2.9 > 2026.1.28 -> PASS."""
    result = check_known_vulns(_ver_ctx("2026.2.9"))
    assert result.status == PASS


def test_b33_version_2026_1_30_passes():
    """2026.1.30 > 2026.1.28 -> PASS."""
    result = check_known_vulns(_ver_ctx("2026.1.30"))
    assert result.status == PASS


def test_b33_version_much_newer_passes():
    """2027.1.0 far past any known advisory -> PASS."""
    result = check_known_vulns(_ver_ctx("2027.1.0"))
    assert result.status == PASS


def test_b33_pass_detail_includes_version():
    """PASS detail should mention the installed version string."""
    result = check_known_vulns(_ver_ctx("2026.2.9"))
    assert result.status == PASS
    assert "2026.2.9" in result.detail


@pytest.mark.parametrize("version_str,expected_status", [
    ("2026.1.20", FAIL),
    ("2026.1.28", FAIL),
    ("2026.1.29", PASS),
    ("2026.2.9",  PASS),
    ("nightly",   UNKNOWN),
    (None,        UNKNOWN),
])
def test_b33_parametrized_version_status(version_str, expected_status):
    """Parametrized sweep covering all outcome branches."""
    result = check_known_vulns(_ver_ctx(version_str))
    assert result.status == expected_status
