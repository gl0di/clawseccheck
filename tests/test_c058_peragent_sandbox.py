"""C-058: B4 — per-agent sandbox override detection.

agents.list[N].sandbox.* can silently re-expose the host even when
agents.defaults.sandbox is safe. check_sandbox now detects these overrides
and reports a definite FAIL with attributed evidence strings.

Grounded fields (docs.openclaw.ai):
  agents.list[N].sandbox.mode            — "off" | "non-main" | "all"
  agents.list[N].sandbox.docker.network  — "host" | "bridge"
  agents.list[N].sandbox.docker.binds    — list of bind strings
  agents.list[N].sandbox.workspaceAccess — "none" | "ro" | "rw"
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from clawseccheck.catalog import FAIL, PASS
from clawseccheck.checks import check_sandbox
from clawseccheck.collector import Context
from clawseccheck.i18n import tp

_HEBREW = re.compile(r"[֐-׿]")
FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.include_host = True
    return c


def _safe_defaults() -> dict:
    """agents.defaults.sandbox with a safe mode — the baseline that per-agent overrides trump."""
    return {"agents": {"defaults": {"sandbox": {"mode": "all"}}}}


# ---------------------------------------------------------------------------
# per-agent sandbox.mode=off with SAFE defaults -> FAIL
# ---------------------------------------------------------------------------

def test_peragent_mode_off_with_safe_defaults_fails():
    cfg = {
        "agents": {
            "defaults": {"sandbox": {"mode": "all"}},
            "list": [{"name": "Gary", "sandbox": {"mode": "off"}}],
        }
    }
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL


def test_peragent_mode_off_evidence_contains_agent_name():
    cfg = {
        "agents": {
            "defaults": {"sandbox": {"mode": "all"}},
            "list": [{"name": "Gary", "sandbox": {"mode": "off"}}],
        }
    }
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL
    ev_blob = " ".join(f.evidence)
    assert "Gary" in ev_blob


def test_peragent_mode_off_evidence_mentions_sandbox_mode_off():
    cfg = {
        "agents": {
            "defaults": {"sandbox": {"mode": "all"}},
            "list": [{"name": "Gary", "sandbox": {"mode": "off"}}],
        }
    }
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL
    ev_blob = " ".join(f.evidence)
    assert "sandbox.mode=off" in ev_blob


# ---------------------------------------------------------------------------
# per-agent docker.network=host -> FAIL, evidence mentions network=host
# ---------------------------------------------------------------------------

def test_peragent_docker_network_host_fails():
    cfg = {
        "agents": {
            "defaults": {"sandbox": {"mode": "all"}},
            "list": [
                {"name": "NetAgent", "sandbox": {"docker": {"network": "host"}}}
            ],
        }
    }
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL


def test_peragent_docker_network_host_evidence():
    cfg = {
        "agents": {
            "defaults": {"sandbox": {"mode": "all"}},
            "list": [
                {"name": "NetAgent", "sandbox": {"docker": {"network": "host"}}}
            ],
        }
    }
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL
    ev_blob = " ".join(f.evidence)
    assert "network=host" in ev_blob or "network" in ev_blob


# ---------------------------------------------------------------------------
# per-agent docker.binds with docker.sock mount -> FAIL, evidence mentions docker.sock
# ---------------------------------------------------------------------------

def test_peragent_docker_sock_fails():
    cfg = {
        "agents": {
            "defaults": {"sandbox": {"mode": "all"}},
            "list": [
                {
                    "name": "SockAgent",
                    "sandbox": {
                        "docker": {
                            "binds": ["/var/run/docker.sock:/var/run/docker.sock"]
                        }
                    },
                }
            ],
        }
    }
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL


def test_peragent_docker_sock_evidence_mentions_docker_sock():
    cfg = {
        "agents": {
            "defaults": {"sandbox": {"mode": "all"}},
            "list": [
                {
                    "name": "SockAgent",
                    "sandbox": {
                        "docker": {
                            "binds": ["/var/run/docker.sock:/var/run/docker.sock"]
                        }
                    },
                }
            ],
        }
    }
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL
    ev_blob = " ".join(f.evidence)
    assert "docker.sock" in ev_blob


# ---------------------------------------------------------------------------
# per-agent workspaceAccess=rw -> FAIL
# ---------------------------------------------------------------------------

def test_peragent_workspace_rw_fails():
    cfg = {
        "agents": {
            "defaults": {"sandbox": {"mode": "all"}},
            "list": [
                {"name": "WriterAgent", "sandbox": {"workspaceAccess": "rw"}}
            ],
        }
    }
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL


def test_peragent_workspace_rw_evidence():
    cfg = {
        "agents": {
            "defaults": {"sandbox": {"mode": "all"}},
            "list": [
                {"name": "WriterAgent", "sandbox": {"workspaceAccess": "rw"}}
            ],
        }
    }
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL
    ev_blob = " ".join(f.evidence)
    assert "workspaceAccess=rw" in ev_blob


# ---------------------------------------------------------------------------
# clean per-agent (mode non-main) + safe defaults -> PASS
# ---------------------------------------------------------------------------

def test_peragent_safe_mode_passes():
    cfg = {
        "agents": {
            "defaults": {"sandbox": {"mode": "all"}},
            "list": [
                {"name": "SafeAgent", "sandbox": {"mode": "non-main"}}
            ],
        }
    }
    f = check_sandbox(_ctx(cfg))
    assert f.status == PASS


# ---------------------------------------------------------------------------
# no agents.list at all -> behaves as before (mode "all" + no list -> PASS)
# ---------------------------------------------------------------------------

def test_no_agents_list_safe_defaults_passes():
    cfg = {"agents": {"defaults": {"sandbox": {"mode": "all"}}}}
    f = check_sandbox(_ctx(cfg))
    assert f.status == PASS


def test_no_agents_list_per_agent_path_does_not_fire():
    """With no agents.list, the per-agent evidence helper must return empty."""
    from clawseccheck.checks import _peragent_sandbox_evidence
    cfg = {"agents": {"defaults": {"sandbox": {"mode": "all"}}}}
    assert _peragent_sandbox_evidence(cfg) == []


# ---------------------------------------------------------------------------
# unnamed agent (no "name") whose sandbox.mode=off -> FAIL, evidence contains "<unnamed>"
# ---------------------------------------------------------------------------

def test_unnamed_agent_mode_off_fails():
    cfg = {
        "agents": {
            "defaults": {"sandbox": {"mode": "all"}},
            "list": [{"sandbox": {"mode": "off"}}],
        }
    }
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL


def test_unnamed_agent_evidence_contains_unnamed_placeholder():
    cfg = {
        "agents": {
            "defaults": {"sandbox": {"mode": "all"}},
            "list": [{"sandbox": {"mode": "off"}}],
        }
    }
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL
    ev_blob = " ".join(f.evidence)
    assert "<unnamed>" in ev_blob


# ---------------------------------------------------------------------------
# New FAIL detail is localized to Hebrew
# ---------------------------------------------------------------------------

def test_peragent_fail_detail_localized_he():
    cfg = {
        "agents": {
            "defaults": {"sandbox": {"mode": "all"}},
            "list": [{"name": "Gary", "sandbox": {"mode": "off"}}],
        }
    }
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL
    assert _HEBREW.search(tp(f.detail, "he")), (
        f"C-058 FAIL detail not localized to Hebrew: {f.detail!r}"
    )


# ---------------------------------------------------------------------------
# Fixture-based: load real JSON fixtures and assert expected verdicts
# ---------------------------------------------------------------------------

def _load_fixture(name: str) -> Context:
    path = FIXTURES / name / "openclaw.json"
    cfg = json.loads(path.read_text())
    return _ctx(cfg)


def test_fixture_bad_b4_peragent_sandbox_fails():
    f = check_sandbox(_load_fixture("bad_b4_peragent_sandbox"))
    assert f.status == FAIL, f"Expected FAIL from bad fixture, got {f.status}: {f.detail}"


def test_fixture_clean_b4_peragent_sandbox_passes():
    f = check_sandbox(_load_fixture("clean_b4_peragent_sandbox"))
    assert f.status == PASS, f"Expected PASS from clean fixture, got {f.status}: {f.detail}"
