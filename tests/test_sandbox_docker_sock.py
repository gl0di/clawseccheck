"""B4 enhancement tests: docker.sock bind and workspaceAccess=rw.

Grounded fields (docs.openclaw.ai):
  agents.defaults.sandbox.docker.binds        — list of host:container bind strings
  agents.defaults.sandbox.workspaceAccess     — "none" | "ro" | "rw"

Binding /var/run/docker.sock hands host control to the sandbox (container
escape).  workspaceAccess="rw" lets the sandboxed agent write back to the
mounted workspace.

These tests verify:
  1. docker.sock in binds -> B4 FAIL with docker.sock evidence line.
  2. workspaceAccess="rw" -> flagged in evidence.
  3. A clean sandbox (mode set, no docker.sock, workspaceAccess ro/none)
     does NOT produce FAIL from these new conditions.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS
from clawseccheck.checks import check_sandbox
from clawseccheck.collector import Context


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


# ---------------------------------------------------------------------------
# docker.sock in binds -> FAIL with explicit evidence
# ---------------------------------------------------------------------------

def test_b4_docker_sock_bind_fails():
    cfg = {
        "agents": {
            "defaults": {
                "sandbox": {
                    "mode": "non-main",
                    "docker": {
                        "binds": ["/var/run/docker.sock:/var/run/docker.sock"]
                    },
                }
            }
        }
    }
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL


def test_b4_docker_sock_evidence_mentions_docker_sock():
    cfg = {
        "agents": {
            "defaults": {
                "sandbox": {
                    "mode": "non-main",
                    "docker": {
                        "binds": ["/var/run/docker.sock:/var/run/docker.sock"]
                    },
                }
            }
        }
    }
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL
    evidence_blob = " ".join(f.evidence)
    assert "docker.sock" in evidence_blob


def test_b4_docker_sock_evidence_mentions_host_control():
    cfg = {
        "agents": {
            "defaults": {
                "sandbox": {
                    "mode": "non-main",
                    "docker": {
                        "binds": ["/var/run/docker.sock:/var/run/docker.sock"]
                    },
                }
            }
        }
    }
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL
    evidence_blob = " ".join(f.evidence)
    assert "host control" in evidence_blob


def test_b4_docker_sock_substring_match_on_path_variant():
    # Any bind entry containing "docker.sock" should be caught regardless of prefix.
    cfg = {
        "agents": {
            "defaults": {
                "sandbox": {
                    "mode": "all",
                    "docker": {
                        "binds": ["/run/docker.sock:/run/docker.sock", "/data:/data"]
                    },
                }
            }
        }
    }
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL
    assert "docker.sock" in " ".join(f.evidence)


def test_b4_docker_sock_fix_mentions_removing_bind():
    cfg = {
        "agents": {
            "defaults": {
                "sandbox": {
                    "mode": "non-main",
                    "docker": {
                        "binds": ["/var/run/docker.sock:/var/run/docker.sock"]
                    },
                }
            }
        }
    }
    f = check_sandbox(_ctx(cfg))
    assert "docker.sock" in f.fix


# ---------------------------------------------------------------------------
# workspaceAccess="rw" -> flagged in evidence
# ---------------------------------------------------------------------------

def test_b4_workspace_access_rw_fails():
    cfg = {
        "agents": {
            "defaults": {
                "sandbox": {
                    "mode": "non-main",
                    "workspaceAccess": "rw",
                }
            }
        }
    }
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL


def test_b4_workspace_access_rw_in_evidence():
    cfg = {
        "agents": {
            "defaults": {
                "sandbox": {
                    "mode": "non-main",
                    "workspaceAccess": "rw",
                }
            }
        }
    }
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL
    evidence_blob = " ".join(f.evidence)
    assert "workspaceAccess=rw" in evidence_blob


def test_b4_workspace_access_rw_fix_mentions_none_or_ro():
    cfg = {
        "agents": {
            "defaults": {
                "sandbox": {
                    "mode": "non-main",
                    "workspaceAccess": "rw",
                }
            }
        }
    }
    f = check_sandbox(_ctx(cfg))
    # Fix text should guide the user toward "none" or "ro"
    assert "none" in f.fix or "ro" in f.fix


# ---------------------------------------------------------------------------
# Clean sandbox: mode set, no docker.sock, workspaceAccess ro/none -> no FAIL
# ---------------------------------------------------------------------------

def test_b4_clean_sandbox_mode_set_no_docker_sock_passes():
    # No binds at all (generic binds always trigger the existing "exposes host paths"
    # evidence line regardless of docker.sock); workspaceAccess ro is safe.
    cfg = {
        "agents": {
            "defaults": {
                "sandbox": {
                    "mode": "non-main",
                    "docker": {
                        "network": "bridge",
                    },
                    "workspaceAccess": "ro",
                }
            }
        }
    }
    f = check_sandbox(_ctx(cfg))
    assert f.status == PASS


def test_b4_workspace_access_ro_does_not_fail():
    cfg = {
        "agents": {
            "defaults": {
                "sandbox": {
                    "mode": "all",
                    "workspaceAccess": "ro",
                }
            }
        }
    }
    f = check_sandbox(_ctx(cfg))
    assert f.status == PASS


def test_b4_workspace_access_none_does_not_fail():
    cfg = {
        "agents": {
            "defaults": {
                "sandbox": {
                    "mode": "all",
                    "workspaceAccess": "none",
                }
            }
        }
    }
    f = check_sandbox(_ctx(cfg))
    assert f.status == PASS


def test_b4_binds_without_docker_sock_does_not_add_docker_sock_evidence():
    # Generic binds (not docker.sock) still produce a generic evidence line,
    # but must NOT add the docker.sock-specific escape warning.
    cfg = {
        "agents": {
            "defaults": {
                "sandbox": {
                    "mode": "non-main",
                    "docker": {
                        "binds": ["/home/user/workspace:/workspace:ro"],
                    },
                }
            }
        }
    }
    f = check_sandbox(_ctx(cfg))
    # Generic binds still trigger the general evidence (existing behaviour).
    assert f.status == FAIL
    # But no docker.sock-specific escape evidence must be present.
    for ev_line in f.evidence:
        assert "docker.sock" not in ev_line
        assert "host control" not in ev_line
        assert "container escape" not in ev_line
