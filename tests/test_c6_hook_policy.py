"""C6 (C-052) — advisory UNKNOWN for the pre-v2026.6.10 hook-composition tool-policy drop.

Runtime evaluation-order bug, no static config field, so C6 is an honest UNKNOWN nudge —
never a FAIL. UNKNOWN fires only when the recorded version predates v2026.6.10 AND a tool
policy (tools.exec.mode / tools.elevated.allowFrom) is configured; everything else PASSes
(no UNKNOWN flood).

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN
from clawseccheck.checks import check_hook_policy_bypass
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def test_old_version_with_exec_mode_is_unknown():
    cfg = {"meta": {"lastTouchedVersion": "2026.6.9"}, "tools": {"exec": {"mode": "ask"}}}
    f = check_hook_policy_bypass(_ctx(cfg))
    assert f.status == UNKNOWN
    assert any("2026.6.9" in e for e in f.evidence)


def test_old_version_with_elevated_allowfrom_is_unknown():
    cfg = {"meta": {"lastTouchedVersion": "2026.5.20"},
           "tools": {"elevated": {"allowFrom": {"telegram": ["user-1"]}}}}
    assert check_hook_policy_bypass(_ctx(cfg)).status == UNKNOWN


def test_old_version_without_policy_passes():
    # No tool policy that could be dropped -> no nudge (no UNKNOWN flood).
    cfg = {"meta": {"lastTouchedVersion": "2026.6.9"}}
    assert check_hook_policy_bypass(_ctx(cfg)).status == PASS


def test_fixed_version_passes():
    cfg = {"meta": {"lastTouchedVersion": "2026.6.10"}, "tools": {"exec": {"mode": "ask"}}}
    assert check_hook_policy_bypass(_ctx(cfg)).status == PASS


def test_newer_version_passes():
    cfg = {"meta": {"lastTouchedVersion": "2026.7.1"}, "tools": {"exec": {"mode": "ask"}}}
    assert check_hook_policy_bypass(_ctx(cfg)).status == PASS


def test_absent_version_passes_no_flood():
    cfg = {"tools": {"exec": {"mode": "ask"}}}
    assert check_hook_policy_bypass(_ctx(cfg)).status == PASS


def test_unparseable_version_passes():
    cfg = {"meta": {"lastTouchedVersion": "nightly"}, "tools": {"exec": {"mode": "ask"}}}
    assert check_hook_policy_bypass(_ctx(cfg)).status == PASS


def test_never_fails_even_with_dangerous_policy():
    cfg = {"meta": {"lastTouchedVersion": "2026.1.1"},
           "tools": {"exec": {"mode": "full"}, "elevated": {"allowFrom": {"telegram": ["*"]}}}}
    assert check_hook_policy_bypass(_ctx(cfg)).status == UNKNOWN  # advisory, not FAIL



def test_bad_fixture_unknown():
    assert check_hook_policy_bypass(collect(FIXTURES / "bad_c6_hook_policy_oldver")).status == UNKNOWN


def test_clean_fixture_passes():
    assert check_hook_policy_bypass(collect(FIXTURES / "clean_c6_hook_policy_fixedver")).status == PASS
