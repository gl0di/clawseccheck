"""B-024 regression: a real defaults sandbox risk (docker.sock / network=host /
workspaceAccess=rw) must FAIL even when agents.defaults.sandbox.mode is unset and
exec is enabled — it must NOT be downgraded to the softer 'mode not set' WARN.

Before the fix, the `mode is None and exec` WARN returned ahead of the `if ev:` FAIL,
masking a container-escape-class signal.
"""
from pathlib import Path

from clawseccheck.catalog import FAIL, WARN
from clawseccheck.checks import check_sandbox
from clawseccheck.collector import Context


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.include_host = True
    return c


def test_network_host_with_mode_unset_and_exec_is_fail_not_warn():
    cfg = {
        "agents": {"defaults": {"sandbox": {"docker": {"network": "host"}}}},
        "tools": {"allow": ["exec"]},
    }
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL
    assert "network=host" in "; ".join(f.evidence)


def test_docker_sock_bind_with_mode_unset_and_exec_is_fail():
    cfg = {
        "agents": {"defaults": {"sandbox": {"docker": {
            "binds": ["/var/run/docker.sock:/var/run/docker.sock"]}}}},
        "tools": {"allow": ["exec"]},
    }
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL
    assert "docker.sock" in "; ".join(f.evidence)


def test_workspace_rw_with_mode_unset_and_exec_is_fail():
    cfg = {
        "agents": {"defaults": {"sandbox": {"workspaceAccess": "rw"}}},
        "tools": {"allow": ["exec"]},
    }
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL


def test_mode_unset_exec_but_no_evidence_still_warns():
    # No defaults docker.* risk and no per-agent override -> the soft WARN is still correct.
    cfg = {"tools": {"allow": ["exec"]}}
    f = check_sandbox(_ctx(cfg))
    assert f.status == WARN
    assert "mode not set" in f.detail
