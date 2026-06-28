"""B45 — per-agent privilege separation (trifecta decomposition).

ATTESTED + advisory: reads the attested agent roster and classifies each agent's
trifecta legs. Tool names are chosen to classify unambiguously:
  web_fetch     -> untrusted input
  postgres_query-> sensitive data
  shell_exec    -> outbound/exec
"""
from pathlib import Path

from clawseccheck.checks import check_agent_separation
from clawseccheck.collector import Context


def _ctx(attestation=None):
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.attestation = attestation or {}
    return c


# ---- no roster attested -> UNKNOWN, guides to --attest ----
def test_b45_no_roster_unknown(tmp_path):
    r = check_agent_separation(_ctx())
    assert r.id == "B45"
    assert r.status == "UNKNOWN"
    assert "--attest" in f"{r.detail} {r.fix}"


def test_b45_junk_roster_unknown():
    # agents present but unusable -> attested_agents() yields [] -> UNKNOWN (not a fake PASS)
    r = check_agent_separation(_ctx({"agents": "not-a-list"}))
    assert r.status == "UNKNOWN"


# ---- one agent holds all three legs -> WARN, names the agent ----
def test_b45_single_agent_all_legs_warns():
    att = {"agents": [
        {"name": "mono", "tools": ["web_fetch", "postgres_query", "shell_exec"]},
    ]}
    r = check_agent_separation(_ctx(att))
    assert r.status == "WARN"
    assert any("mono" in e for e in r.evidence)


# ---- legs split one-per-agent -> PASS ----
def test_b45_separated_agents_pass():
    att = {"agents": [
        {"name": "reader", "tools": ["web_fetch"]},
        {"name": "vault", "tools": ["postgres_query"]},
        {"name": "sender", "tools": ["shell_exec"]},
    ]}
    r = check_agent_separation(_ctx(att))
    assert r.status == "PASS"


# ---- union has all three legs but NO single agent does -> PASS (real separation) ----
def test_b45_union_complete_but_no_single_agent_pass():
    att = {"agents": [
        {"name": "front", "tools": ["web_fetch", "postgres_query"]},  # input+sensitive = 2/3
        {"name": "actor", "tools": ["shell_exec"]},                   # outbound = 1/3
    ]}
    r = check_agent_separation(_ctx(att))
    assert r.status == "PASS"


# ---- the PASS is honest: it says it is NOT a guarantee ----
def test_b45_pass_carries_not_a_guarantee_caveat():
    att = {"agents": [
        {"name": "reader", "tools": ["web_fetch"]},
        {"name": "actor", "tools": ["shell_exec"]},
    ]}
    r = check_agent_separation(_ctx(att))
    assert r.status == "PASS"
    assert "not a safety guarantee" in r.detail.lower()


# ---- advisory: never scored, regardless of status ----
def test_b45_is_not_scored():
    for att in (
        {},
        {"agents": [{"name": "mono", "tools": ["web_fetch", "postgres_query", "shell_exec"]}]},
        {"agents": [{"name": "reader", "tools": ["web_fetch"]}]},
    ):
        assert check_agent_separation(_ctx(att)).scored is False


# ---- advisory confidence is ATTESTED (self-report, not a config fact) ----
def test_b45_confidence_is_attested():
    att = {"agents": [{"name": "mono", "tools": ["web_fetch", "postgres_query", "shell_exec"]}]}
    assert check_agent_separation(_ctx(att)).confidence == "ATTESTED"


# ---- B45 never FAILs (a self-declared roster is advisory only) ----
def test_b45_never_fails():
    att = {"agents": [{"name": "mono", "tools": ["web_fetch", "postgres_query", "shell_exec"]}]}
    assert check_agent_separation(_ctx(att)).status != "FAIL"


# ---- he report: the WARN evidence bullet is translated, the agent name is preserved ----
