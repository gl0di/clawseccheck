"""C034 — anti-FP guard rails for OpenClaw non-vulnerabilities by design."""
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.catalog import FAIL, WARN

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.mark.parametrize(
    "fixture_name",
    [
        "clean_c034_loopback_no_hsts",
        "clean_c034_sessionkey",
        "clean_c034_autoapprovecidrs",
        "clean_c034_operator_readpath",
        "clean_c034_prompt_injection_only",
    ],
)
def test_c034_nonvuln_invariants_produce_no_fail(fixture_name):
    _, findings, _ = audit(FIXTURES / fixture_name, include_native=False)
    fails = [f"{f.id}: {f.detail}" for f in findings if f.status == FAIL]
    assert not fails, f"{fixture_name} unexpectedly produced FAIL findings: {fails}"


def test_c034_prompt_injection_only_stays_warn_or_below():
    _, findings, _ = audit(FIXTURES / "clean_c034_prompt_injection_only", include_native=False)
    by_id = {f.id: f for f in findings}
    assert by_id["B26"].status == WARN
    assert by_id["B2"].status != FAIL
