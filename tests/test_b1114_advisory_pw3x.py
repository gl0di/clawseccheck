"""B-1114 - B33 against GHSA-pw3x-g8v8-fvj2, the first advisory published as TWO ranges.

Published 2026-11-19 on the vendor repository endpoint (`gh api
/repos/openclaw/openclaw/security-advisories/GHSA-pw3x-g8v8-fvj2`), high, CWE-863: "OpenClaw
delegation could skip approval for restricted agents". Ranges on the core npm package:

    >= 2026.9.2,  < 2026.10.33   patched 2026.10.33 (extended-stable)
    >= 2026.11.1, < 2026.11.4    patched 2026.11.4

One table row spans both (max_vulnerable 2026.11.3, first vulnerable 2026.9.2); the stretch
between them, [2026.10.33, 2026.11.1), is `_ADVISORY_RANGE_GAPS`. The extended-stable 2026.9
line (9.33+) is inside the first range but was not examined, so it is UNKNOWN by the existing
rule - never a guessed FAIL or PASS.

The ranges are checked here by a comparator written in THIS file, not by the check's matcher.
Hermetic: the version comes from the config stamp of a home that is not this machine's.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, UNKNOWN
from clawseccheck.checks import _KNOWN_ADVISORIES, _lifecycle, _parse_version, check_known_vulns
from clawseccheck.collector import Context

_ID = "GHSA-pw3x-g8v8-fvj2"
_PUBLISHED_RANGES = (((2026, 9, 2), (2026, 10, 33)), ((2026, 11, 1), (2026, 11, 4)))


def _published(version: str) -> bool:
    p = _parse_version(version)
    return any(lo <= p < hi for lo, hi in _PUBLISHED_RANGES)


def _ctx(version: str) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = {"meta": {"lastTouchedVersion": version}}
    return c


def test_the_row_encodes_the_published_advisory():
    rows = {r[0]: r for r in _KNOWN_ADVISORIES}
    row = rows[_ID]
    assert len(row) == 4, "version-only: no config condition was grounded"
    assert row[1] == (2026, 11, 3)
    assert row[2] == "2026.11.4"
    assert row[3] == "OpenClaw delegation could skip approval for restricted agents"
    assert _lifecycle._ADVISORY_FIRST_VULNERABLE[_ID] == (2026, 9, 2)
    assert _lifecycle._ADVISORY_RANGE_GAPS == {_ID: (((2026, 10, 33), (2026, 11, 1)),)}
    assert _ID not in _lifecycle._EXTENDED_STABLE_NOT_AFFECTED


@pytest.mark.parametrize("version", [
    "2026.9.2", "2026.9.8", "2026.10.1", "2026.10.9", "2026.10.32", "2026.11.1", "2026.11.3",
])
def test_a_build_inside_a_published_range_fails_naming_the_advisory(version):
    assert _published(version)
    f = check_known_vulns(_ctx(version))
    assert f.status == FAIL, f.detail
    assert _ID in f.evidence
    assert "2026.11.4" in f.fix


@pytest.mark.parametrize("version", ["2026.10.33", "2026.10.33-1", "2026.10.34", "2026.11.4",
                                     "2026.11.5", "2026.11.6"])
def test_a_patched_build_passes(version):
    assert not _published(version)
    f = check_known_vulns(_ctx(version))
    assert f.status == PASS, f.detail


def test_below_the_first_vulnerable_build_the_advisory_is_not_named():
    f = check_known_vulns(_ctx("2026.9.1"))
    assert f.status == FAIL  # GHSA-5x6q-wg56-rxg8 still reaches 2026.9.1
    assert _ID not in f.evidence
    # ...but the fix target clears every row in one step, this one included
    assert "2026.11.4" in f.fix


@pytest.mark.parametrize("version", ["2026.9.33", "2026.9.37"])
def test_the_unexamined_extended_stable_9_line_is_unknown_not_a_guess(version):
    assert _published(version)  # numerically inside the first published range
    f = check_known_vulns(_ctx(version))
    assert f.status == UNKNOWN, f.detail


def test_the_gap_only_trims_this_row():
    """A gap is per advisory: it must not clear another row that reaches the same build."""
    gaps = _lifecycle._ADVISORY_RANGE_GAPS
    assert set(gaps) == {_ID}
    for ident, spans in gaps.items():
        row = next(r for r in _KNOWN_ADVISORIES if r[0] == ident)
        for lo, hi in spans:
            assert lo < hi
            assert _lifecycle._ADVISORY_FIRST_VULNERABLE[ident] < lo <= row[1]


def test_the_gap_is_a_positive_control():
    """Without the gap, the patched extended-stable build would not PASS."""
    saved = dict(_lifecycle._ADVISORY_RANGE_GAPS)
    try:
        _lifecycle._ADVISORY_RANGE_GAPS.clear()
        assert check_known_vulns(_ctx("2026.10.33")).status != PASS
    finally:
        _lifecycle._ADVISORY_RANGE_GAPS.update(saved)
    assert check_known_vulns(_ctx("2026.10.33")).status == PASS


def test_a_beta_of_the_extended_stable_fix_reads_as_patched_like_c662c():
    """C-135 note (2026-11-20): `2026.10.33-beta.1` sits below 10.33 under semver, but
    `_parse_version` reads a prerelease as its release, which is the owner ruling C-662(c) for a
    beta of the newest fix. The gap carries that same reading to the extended-stable fix line.
    Theoretical today: no 10.33 prerelease is published. It was also clear before B-1114."""
    assert check_known_vulns(_ctx("2026.10.33-beta.1")).status == PASS
