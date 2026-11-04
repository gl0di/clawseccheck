"""C-765: npm persona-ai-sdk (GHSA-2v69-q2gc-qm5j, OSV MAL-2026-18463).

Name-level: every release ever published under the name came from one account and the
only real one (1.0.0) is the flagged malware, so no clean release can FAIL (C-750). The
advisory publishes no behaviour, and the record says so rather than inventing one.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import pytest

from clawseccheck import iocdb
from clawseccheck.catalog import FAIL, UNKNOWN
from clawseccheck.checks import vet_source


@pytest.mark.parametrize("target", ["npm:persona-ai-sdk", "npm:persona-ai-sdk@1.0.0",
                                    "npm:persona-ai-sdk@0.0.0-stage"])
def test_vet_source_fails_persona_ai_sdk_at_any_version(target):
    f = vet_source(target)
    assert f.status == FAIL, f.detail
    assert "known-compromised" in f.detail


@pytest.mark.parametrize("target", ["npm:persona-ai", "npm:persona-ai-sdk-core",
                                    "pypi:persona-ai-sdk"])
def test_vet_source_leaves_neighbouring_names_unknown(target):
    assert vet_source(target).status == UNKNOWN


def test_the_record_publishes_no_invented_behaviour():
    rec = next(r for r in iocdb.SOURCES if r["value"] == "persona-ai-sdk")
    assert rec["type"] == "npm" and rec["first_seen"] == "2026-11-02"
    assert rec["source_url"] == "https://github.com/advisories/GHSA-2v69-q2gc-qm5j"
    assert "no behaviour published" in rec["note"]
