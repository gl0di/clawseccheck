"""B-094 / B-095 — a bare fence or a bare defensive-sounding heading must not, on its own,
suppress a real B63 silent-instruction finding. Both were confirmed live-fire bypasses
against v3.9.0: the exact literal trigger phrase B63 is built to catch survived verbatim
inside a ```fence``` (B-094) or under a "## Known Risks" heading (B-095), reading Grade
A/SAFE. Dampening now requires the structural signal to co-occur with an actual negation
(_negation_context for fences, _BROAD_NEGATION_RE in scope for headings). Offline,
read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS
from clawseccheck.checks import check_silent_instruction
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def test_b094_fenced_secrecy_still_fails():
    f = check_silent_instruction(collect(FIXTURES / "bad_b63_fenced_bypass"))
    assert f.status == FAIL, f"B-094 regressed: expected FAIL, got {f.status}: {f.detail}"
    assert any("without telling" in e for e in (f.evidence or [])), f.evidence


def test_b095_defensive_heading_secrecy_still_fails():
    f = check_silent_instruction(collect(FIXTURES / "bad_b63_heading_bypass"))
    assert f.status == FAIL, f"B-095 regressed: expected FAIL, got {f.status}: {f.detail}"
    assert any("silently read" in e for e in (f.evidence or [])), f.evidence


def test_clean_b63_defensive_heading_still_passes():
    f = check_silent_instruction(collect(FIXTURES / "clean_b63_defensive_heading"))
    assert f.status == PASS, f"expected PASS, got {f.status}: {f.detail}"
