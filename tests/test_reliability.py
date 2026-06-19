"""Reliability corpus: guard checks against regressions.

- clean_* fixtures must produce zero FAIL findings (WARNs are acceptable).
- bad_* fixtures must produce a FAIL on the specific check under test.

All audits use include_native=False (default) so the suite is fully offline
and deterministic.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawcheck import audit
from clawcheck.catalog import FAIL

RELIABILITY = Path(__file__).resolve().parent.parent / "fixtures" / "reliability"

# ---------------------------------------------------------------------------
# Clean fixtures: known-good configs that must NOT produce any FAIL.
# The grade must also not be "F" (a WARN-only config can still score well).
# ---------------------------------------------------------------------------

CLEAN_FIXTURES = [
    "clean_loopback_minimal",
    "clean_token_auth_with_channels",
    "clean_multimodal_workstation",
]


@pytest.mark.parametrize("fixture_name", CLEAN_FIXTURES)
def test_clean_fixture_has_no_fail(fixture_name: str) -> None:
    """A well-configured setup must not produce any false-positive FAIL findings."""
    _, findings, score = audit(RELIABILITY / fixture_name)
    fail_findings = [f for f in findings if f.status == FAIL]
    assert fail_findings == [], (
        f"Clean fixture '{fixture_name}' produced unexpected FAIL(s): "
        + ", ".join(f"{f.id} ({f.detail[:80]})" for f in fail_findings)
    )


@pytest.mark.parametrize("fixture_name", CLEAN_FIXTURES)
def test_clean_fixture_grade_is_not_f(fixture_name: str) -> None:
    """A well-configured setup must not receive a failing grade."""
    _, _, score = audit(RELIABILITY / fixture_name)
    assert score.grade != "F", (
        f"Clean fixture '{fixture_name}' received grade F (score={score.score})"
    )


# ---------------------------------------------------------------------------
# Bad fixtures: deliberately broken configs — each must produce the expected FAIL.
# ---------------------------------------------------------------------------

BAD_FIXTURES = [
    # (fixture_dir_name, expected_check_id_that_must_FAIL)
    ("bad_b1_inline_password", "B1"),
    ("bad_b2_open_gateway", "B2"),
    ("bad_b3_wildcard_elevated", "B3"),
    ("bad_b4_exec_no_sandbox", "B4"),
]


@pytest.mark.parametrize("fixture_name,expected_id", BAD_FIXTURES)
def test_bad_fixture_triggers_expected_fail(fixture_name: str, expected_id: str) -> None:
    """A config with a known-bad pattern must produce a FAIL on the targeted check."""
    _, findings, _ = audit(RELIABILITY / fixture_name)
    by_id = {f.id: f for f in findings}
    target = by_id.get(expected_id)
    assert target is not None, (
        f"Bad fixture '{fixture_name}': check {expected_id} not present in findings"
    )
    assert target.status == FAIL, (
        f"Bad fixture '{fixture_name}': check {expected_id} expected FAIL, "
        f"got {target.status} — possible false negative. Detail: {target.detail}"
    )
