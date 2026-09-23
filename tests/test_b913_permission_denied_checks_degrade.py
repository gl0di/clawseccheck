"""CLAWSECCHECK-B-913: six checks raised an unguarded PermissionError on a chmod-000

workspace (or ``.agents``) dir, which ``run_all`` degraded to a generic ``ERR:<check>``
UNKNOWN — losing the specific "could not read X" the check would otherwise disclose.

``Path.is_dir()``/``is_file()``/``.exists()`` need EXECUTE (search) permission on the
path's own PARENT directory, not just its ancestors further up — B-303 fixed this for
the collector's own bootstrap-scanning walk (``collector._safe_is_dir``/
``_safe_is_file``); this task closes six SIBLING call sites that did their own,
unguarded, re-scan of the same class of path instead of going through those helpers:

    check_secrets_at_rest_home          (checks/_config.py)   -- skip-root existence check
    check_bootstrap_write_protection    (checks/_lifecycle.py) -- B20
    check_log_threat_hunt               (checks/_egress.py)    -- B164, via logdiscovery
    check_memory_reconsumption_injection(checks/_lifecycle.py) -- B180, same logdiscovery site
    check_clawhub_lock_verification     (checks/_lifecycle.py) -- B135
    check_declared_skill_reconciliation (checks/_lifecycle.py) -- B158

Each test below reproduces the exact repro from the task: a scratch home with
``workspace/skills/x/`` created, then ``workspace`` (or, for the C015-only variant,
``.agents``) made non-traversable. Every test restores the mode in a ``finally`` so a
red assertion never leaves a chmod-000 directory behind for pytest's own tmp_path
cleanup.

Root ignores the read/execute bit entirely, so the repro cannot reproduce as uid 0 —
mirrors the skip pattern already used by test_b303_unreadable_home.py /
test_b683_unreadable_target_not_an_internal_error.py.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clawseccheck.checks import (  # noqa: E402
    check_bootstrap_write_protection,
    check_clawhub_lock_verification,
    check_declared_skill_reconciliation,
    check_log_threat_hunt,
    check_memory_reconsumption_injection,
    check_secrets_at_rest_home,
    run_all,
)
from clawseccheck.collector import collect  # noqa: E402

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX permission bits only"
)
_SKIP_ROOT = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores the read bit"
)


def _home_with_locked_workspace(tmp_path):
    """The task's own repro: a home with `workspace/skills/x/`, then `workspace`
    made non-traversable."""
    home = tmp_path / "home"
    (home / "workspace" / "skills" / "x").mkdir(parents=True)
    (home / "openclaw.json").write_text(
        '{"gateway": {"bind": "127.0.0.1"}}', encoding="utf-8"
    )
    os.chmod(home / "workspace", 0o000)
    return home


def _home_with_locked_agents(tmp_path):
    """The task's second repro: `.agents` (not `workspace`) made non-traversable —
    only check_secrets_at_rest_home reads a `.agents/skills` skip-root, so this is the
    control that the OTHER five checks are unaffected by an unrelated permission gap."""
    home = tmp_path / "home"
    (home / ".agents" / "skills" / "x").mkdir(parents=True)
    (home / "openclaw.json").write_text(
        '{"gateway": {"bind": "127.0.0.1"}}', encoding="utf-8"
    )
    os.chmod(home / ".agents", 0o000)
    return home


# ---------------------------------------------------------------------------
# One test per check: the literal repro, driving the check function directly.
# ---------------------------------------------------------------------------

@_SKIP_ROOT
def test_check_secrets_at_rest_home_survives_chmod000_workspace(tmp_path):
    home = _home_with_locked_workspace(tmp_path)
    try:
        ctx = collect(home)
        finding = check_secrets_at_rest_home(ctx)  # must not raise
    finally:
        os.chmod(home / "workspace", 0o755)

    assert finding.status == "UNKNOWN", (finding.status, finding.detail)
    assert "workspace" in finding.detail
    assert "could not read" in finding.detail.lower()


@_SKIP_ROOT
def test_check_bootstrap_write_protection_survives_chmod000_workspace(tmp_path):
    home = _home_with_locked_workspace(tmp_path)
    try:
        ctx = collect(home)
        finding = check_bootstrap_write_protection(ctx)  # must not raise
    finally:
        os.chmod(home / "workspace", 0o755)

    assert finding.status == "UNKNOWN", (finding.status, finding.detail)
    assert "workspace" in finding.detail
    assert "could not read" in finding.detail.lower()


@_SKIP_ROOT
def test_check_log_threat_hunt_survives_chmod000_workspace(tmp_path):
    home = _home_with_locked_workspace(tmp_path)
    try:
        ctx = collect(home)
        finding = check_log_threat_hunt(ctx)  # must not raise
    finally:
        os.chmod(home / "workspace", 0o755)

    assert finding.status == "UNKNOWN", (finding.status, finding.detail)
    assert "memory" in finding.detail
    assert "could not read" in finding.detail.lower()


@_SKIP_ROOT
def test_check_memory_reconsumption_injection_survives_chmod000_workspace(tmp_path):
    home = _home_with_locked_workspace(tmp_path)
    try:
        ctx = collect(home)
        finding = check_memory_reconsumption_injection(ctx)  # must not raise
    finally:
        os.chmod(home / "workspace", 0o755)

    assert finding.status == "UNKNOWN", (finding.status, finding.detail)
    assert "memory" in finding.detail
    assert "could not read" in finding.detail.lower()


@_SKIP_ROOT
def test_check_clawhub_lock_verification_survives_chmod000_workspace(tmp_path):
    home = _home_with_locked_workspace(tmp_path)
    try:
        ctx = collect(home)
        finding = check_clawhub_lock_verification(ctx)  # must not raise
    finally:
        os.chmod(home / "workspace", 0o755)

    assert finding.status == "UNKNOWN", (finding.status, finding.detail)
    assert "lock.json" in finding.detail
    assert "could not check" in finding.detail.lower()


@_SKIP_ROOT
def test_check_declared_skill_reconciliation_survives_chmod000_workspace(tmp_path):
    home = _home_with_locked_workspace(tmp_path)
    try:
        ctx = collect(home)
        finding = check_declared_skill_reconciliation(ctx)  # must not raise
    finally:
        os.chmod(home / "workspace", 0o755)

    assert finding.status == "UNKNOWN", (finding.status, finding.detail)
    assert "lock.json" in finding.detail
    assert "could not check" in finding.detail.lower()


# ---------------------------------------------------------------------------
# The .agents-only control: check_secrets_at_rest_home is the ONLY one of the six that
# reads a `.agents/skills` skip-root, so this must not disturb the other five.
# ---------------------------------------------------------------------------

@_SKIP_ROOT
def test_check_secrets_at_rest_home_survives_chmod000_agents(tmp_path):
    home = _home_with_locked_agents(tmp_path)
    try:
        ctx = collect(home)
        finding = check_secrets_at_rest_home(ctx)  # must not raise
    finally:
        os.chmod(home / ".agents", 0o755)

    assert finding.status == "UNKNOWN", (finding.status, finding.detail)
    assert ".agents" in finding.detail
    assert "could not read" in finding.detail.lower()


# ---------------------------------------------------------------------------
# End-to-end: run_all() over the whole audit must show zero ERR findings in either
# scenario, and each of the six sites must degrade to its own named UNKNOWN, never the
# generic "ERR:<check> ... unexpected internal error" run_all() falls back to.
# ---------------------------------------------------------------------------

_SIX_CHECK_IDS = ("C015", "B20", "B164", "B180", "B135", "B158")


@_SKIP_ROOT
def test_run_all_chmod000_workspace_no_err_and_all_six_unknown(tmp_path):
    home = _home_with_locked_workspace(tmp_path)
    try:
        ctx = collect(home)
        findings = run_all(ctx)  # must not raise
    finally:
        os.chmod(home / "workspace", 0o755)

    err = [f for f in findings if str(f.id).startswith("ERR")]
    assert not err, [(f.id, f.detail) for f in err]

    by_id = {f.id: f for f in findings}
    for check_id in _SIX_CHECK_IDS:
        assert by_id[check_id].status == "UNKNOWN", (check_id, by_id[check_id].status)


@_SKIP_ROOT
def test_run_all_chmod000_agents_no_err_and_only_c015_unknown(tmp_path):
    home = _home_with_locked_agents(tmp_path)
    try:
        ctx = collect(home)
        findings = run_all(ctx)  # must not raise
    finally:
        os.chmod(home / ".agents", 0o755)

    err = [f for f in findings if str(f.id).startswith("ERR")]
    assert not err, [(f.id, f.detail) for f in err]

    by_id = {f.id: f for f in findings}
    assert by_id["C015"].status == "UNKNOWN", by_id["C015"].detail
    assert ".agents" in by_id["C015"].detail
    # B20/B164/B180/B135/B158 never touch `.agents` — an unrelated permission gap there
    # must not read as a permission problem THEY hit (they may still be UNKNOWN/PASS
    # for their own unrelated "nothing configured" reasons on this minimal home; what
    # must not happen is one of them blaming `.agents`).
    for check_id in ("B20", "B164", "B180", "B135", "B158"):
        assert "could not read" not in by_id[check_id].detail.lower(), (
            check_id, by_id[check_id].detail,
        )
        assert "could not check" not in by_id[check_id].detail.lower(), (
            check_id, by_id[check_id].detail,
        )
