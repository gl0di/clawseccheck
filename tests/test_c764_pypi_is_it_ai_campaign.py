"""C-764: the PyPI 2026-10-is-it-ai campaign (kam193 / OpenSSF, GHSA type=malware).

The first pypi records in the IOC dataset. Name-level is correct: the advisory text says
every version of both packages was uploaded with malicious intent, so there is no
legitimate release for a version-blind name record to FAIL (contrast C-750).

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import pytest

from clawseccheck import iocdb
from clawseccheck.catalog import FAIL, UNKNOWN
from clawseccheck.checks import vet_source


@pytest.mark.parametrize("target", [
    "pypi:skills-analyzer",
    "pypi:skills-analyzer==0.1.1",  # the release the advisory names as carrying the code
    "pypi:is-it-ai",
    "pypi:is-it-ai==0.1.3",
])
def test_vet_source_fails_both_campaign_packages_at_any_version(target):
    f = vet_source(target)
    assert f.status == FAIL, f.detail
    assert "known-compromised" in f.detail


@pytest.mark.parametrize("target", [
    "pypi:requests",
    "pypi:skills-analyzer-pro",  # a longer name is not the record
    "pypi:is-it",
    "npm:is-it-ai",  # the record is scoped to pypi
])
def test_vet_source_leaves_neighbouring_names_unknown(target):
    assert vet_source(target).status == UNKNOWN


def test_the_records_cite_their_advisories():
    by_name = {r["value"]: r for r in iocdb.SOURCES if r["type"] == "pypi"}
    assert by_name["skills-analyzer"]["source_url"].endswith("GHSA-r92r-m9r8-78vj")
    assert by_name["is-it-ai"]["source_url"].endswith("GHSA-76h8-w3px-47hx")
    assert {r["first_seen"] for r in by_name.values()} == {"2026-10-31"}
    assert iocdb.validate_dataset() == []
