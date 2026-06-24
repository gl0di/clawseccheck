"""B48 / NC-7 regression: the dangerous docker break-glass trio is detected by
check_dangerous_overrides (B48) — and reported exactly ONCE.

Grounded fields (docs.openclaw.ai/gateway/security — the "dangerously*" schema accordion;
see the docker/sandbox section of the internal openclaw-schema-recon.md):
  agents.defaults.sandbox.docker.dangerouslyAllowReservedContainerTargets
  agents.defaults.sandbox.docker.dangerouslyAllowExternalBindSources
  agents.defaults.sandbox.docker.dangerouslyAllowContainerNamespaceJoin

B48 has owned the whole "dangerously*" registry (gateway + per-agent) since v1.8.0, so the
trio is already a FAIL there. v1.11.0 briefly also detected it in check_sandbox (B4),
double-reporting the same finding; that duplicate was reverted in v1.11.1. These tests pin
the trio to B48 ONLY and guard against the duplicate ever returning.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS
from clawseccheck.checks import check_dangerous_overrides, check_sandbox
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_TRIO = (
    "dangerouslyAllowReservedContainerTargets",
    "dangerouslyAllowExternalBindSources",
    "dangerouslyAllowContainerNamespaceJoin",
)


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def _sandbox(**docker_flags) -> dict:
    """A safe-everything-else sandbox config; only the passed docker flags vary."""
    docker = {"network": "bridge"}
    docker.update(docker_flags)
    return {
        "agents": {
            "defaults": {
                "sandbox": {
                    "mode": "non-main",
                    "workspaceAccess": "ro",
                    "docker": docker,
                }
            }
        }
    }


# ---------------------------------------------------------------------------
# B48 owns the trio
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("flag", _TRIO)
def test_single_trio_flag_true_fails_b48(flag):
    f = check_dangerous_overrides(_ctx(_sandbox(**{flag: True})))
    assert f.status == FAIL
    assert any(flag in line for line in f.evidence), (
        f"B48 must surface {flag}; got {f.evidence}"
    )


def test_all_three_trio_flags_fail_b48_with_three_lines():
    f = check_dangerous_overrides(_ctx(_sandbox(**{flag: True for flag in _TRIO})))
    assert f.status == FAIL
    for flag in _TRIO:
        assert any(flag in line for line in f.evidence), f"missing B48 evidence for {flag}"


def test_trio_absent_passes_b48():
    f = check_dangerous_overrides(_ctx(_sandbox()))
    assert f.status == PASS


# ---------------------------------------------------------------------------
# De-dup guard: B4 (check_sandbox) must NOT also report the trio
# ---------------------------------------------------------------------------

def test_sandbox_check_does_not_report_trio():
    """check_sandbox (B4) must not fire on the trio — B48 owns it (no double-report)."""
    f = check_sandbox(_ctx(_sandbox(**{flag: True for flag in _TRIO})))
    assert f.status == PASS, "B4 must PASS on a trio-only config (B48 owns the trio)"
    for line in f.evidence or []:
        assert "dangerouslyAllow" not in line, (
            f"B4 re-reported a dangerouslyAllow* flag (duplicate of B48): {line!r}"
        )


def test_full_audit_reports_trio_exactly_once():
    """Across the whole audit, the trio must appear in exactly one check's evidence."""
    from clawseccheck import audit
    _, findings, _ = audit(FIXTURES / "bad_b48_docker_trio", include_native=False)
    reporting = [
        f.id for f in findings
        if any("dangerouslyAllow" in (e or "") for e in (f.evidence or []))
    ]
    assert reporting == ["B48"], (
        f"trio must be reported once, by B48 only; got {reporting}"
    )


# ---------------------------------------------------------------------------
# Fixtures on disk
# ---------------------------------------------------------------------------

def test_bad_fixture_fails_b48():
    f = check_dangerous_overrides(collect(FIXTURES / "bad_b48_docker_trio"))
    assert f.status == FAIL
    assert any("dangerouslyAllow" in line for line in f.evidence)


def test_clean_fixture_passes_b48():
    f = check_dangerous_overrides(collect(FIXTURES / "clean_b48_docker_trio"))
    assert f.status == PASS


def test_bad_fixture_sandbox_check_passes():
    """The bad fixture's sandbox is otherwise safe — B4 PASSes, only B48 FAILs."""
    f = check_sandbox(collect(FIXTURES / "bad_b48_docker_trio"))
    assert f.status == PASS
