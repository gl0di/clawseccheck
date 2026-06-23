"""§5 gate: zero false-positive FAILs across the clean-config corpus.

CLAUDE.md §5 forbids spurious FAILs on real/clean OpenClaw configs. Until now
that law was held only by manual pre-release checking. This test operationalizes
it: every fixture home designated *clean* must yield zero FAIL findings from a
full audit. Drop in a clean fixture named ``clean_*`` (or rely on the canonical
``home_safe``) and it is automatically enrolled in the gate — no edit here.

Read-only and offline: it runs the real ``audit()`` over the pinned fixtures
(``conftest.py`` chmods every ``openclaw.json`` to 0o600 so at-rest checks are
deterministic).
"""
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.catalog import FAIL

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _clean_homes():
    """Discover the clean-config corpus by convention.

    Members: the canonical ``home_safe`` plus every ``fixtures/clean_*`` dir.
    ``bad_*`` / ``home_vuln`` / partial non-home fixtures are excluded — only
    configs that are *meant* to be clean belong in a zero-FAIL gate.
    """
    homes = []
    safe = FIXTURES / "home_safe"
    if safe.is_dir():
        homes.append(safe)
    homes += sorted(p for p in FIXTURES.glob("clean_*") if p.is_dir())
    return homes


CLEAN_HOMES = _clean_homes()


def test_clean_corpus_is_non_empty():
    # A renamed/emptied corpus must fail loudly, not let the gate pass vacuously.
    assert CLEAN_HOMES, (
        "no clean-config fixtures found — the §5 FP gate would be vacuous; "
        "expected home_safe and/or fixtures/clean_*"
    )


@pytest.mark.parametrize("home", CLEAN_HOMES, ids=lambda p: p.name)
def test_no_false_positive_fail_on_clean_config(home):
    _, findings, _ = audit(home)
    fails = [f.id for f in findings if f.status == FAIL]
    assert not fails, (
        f"§5 violation: clean fixture {home.name!r} produced FAIL(s): {fails}. "
        "Either the fixture isn't actually clean, or a check has a false positive — "
        "fix the check, don't whitelist the FAIL."
    )
