"""B47 — cross-agent trifecta reassembly over the delegation graph + RISK-11.

Tool names classify unambiguously (same as test_b45):
  web_fetch -> untrusted input · postgres_query -> sensitive data · shell_exec -> outbound
"""
from pathlib import Path


from clawseccheck.checks import check_agent_separation, check_delegation_reassembly
from clawseccheck.collector import Context
from clawseccheck.risk import risk_paths


def _ctx(attestation=None):
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.attestation = attestation or {}
    return c


_ROSTER = [
    {"name": "researcher", "tools": ["web_fetch"]},      # untrusted input
    {"name": "vault", "tools": ["postgres_query"]},      # sensitive data
    {"name": "sender", "tools": ["shell_exec"]},         # outbound
]


def _att(edges):
    return {"agents": _ROSTER, "delegation": edges}


def _risk_ids(att):
    return [p.id for p in risk_paths(_ctx(att), [])]


# ---- no roster or no edges -> UNKNOWN ----
def test_b47_no_edges_unknown():
    r = check_delegation_reassembly(_ctx({"agents": _ROSTER}))
    assert r.id == "B47"
    assert r.status == "UNKNOWN"
    assert "--attest" in f"{r.detail} {r.fix}"


def test_b47_no_roster_unknown():
    r = check_delegation_reassembly(_ctx({"delegation": [{"from": "a", "to": "b", "returns": "raw"}]}))
    assert r.status == "UNKNOWN"


# ---- untrusted agent reaches secrets + outbound via raw edges -> WARN + RISK-11 ----
def test_b47_raw_reassembly_warns():
    att = _att([
        {"from": "researcher", "to": "vault", "returns": "raw"},
        {"from": "researcher", "to": "sender", "returns": "raw"},
    ])
    r = check_delegation_reassembly(_ctx(att))
    assert r.status == "WARN"
    assert any("researcher" in e for e in r.evidence)
    assert "RISK-11" in _risk_ids(att)


# ---- the entire reachable subgraph is walled (schema) -> PASS with caveat, no RISK-11 ----
def test_b47_all_walls_pass_with_caveat():
    att = _att([
        {"from": "researcher", "to": "vault", "returns": "schema"},
        {"from": "researcher", "to": "sender", "returns": "schema"},
    ])
    r = check_delegation_reassembly(_ctx(att))
    assert r.status == "PASS"
    assert "not a runtime guarantee" in r.detail.lower()
    assert "RISK-11" not in _risk_ids(att)


# ---- a filtered (sieve) edge is not a wall -> WARN ----
def test_b47_filtered_edge_warns():
    att = _att([
        {"from": "researcher", "to": "vault", "returns": "filtered"},
        {"from": "researcher", "to": "sender", "returns": "schema"},
    ])
    assert check_delegation_reassembly(_ctx(att)).status == "WARN"


# ---- an undeclared (unknown) edge is not a wall -> WARN ----
def test_b47_unknown_edge_warns():
    att = _att([
        {"from": "researcher", "to": "vault", "returns": "unknown"},
        {"from": "researcher", "to": "sender", "returns": "schema"},
    ])
    assert check_delegation_reassembly(_ctx(att)).status == "WARN"


# ---- full trifecta not reachable across the graph -> PASS, no RISK-11 ----
def test_b47_not_reachable_pass():
    # researcher reaches vault (sensitive) but no outbound agent in reach
    att = {"agents": [_ROSTER[0], _ROSTER[1]],
           "delegation": [{"from": "researcher", "to": "vault", "returns": "raw"}]}
    r = check_delegation_reassembly(_ctx(att))
    assert r.status == "PASS"
    assert "RISK-11" not in _risk_ids(att)


# ---- multi-hop reassembly (researcher -> mid -> vault, researcher -> sender) ----
def test_b47_multi_hop_reassembly_warns():
    att = {"agents": _ROSTER + [{"name": "mid", "tools": []}],
           "delegation": [
               {"from": "researcher", "to": "mid", "returns": "raw"},
               {"from": "mid", "to": "vault", "returns": "raw"},
               {"from": "researcher", "to": "sender", "returns": "raw"},
           ]}
    assert check_delegation_reassembly(_ctx(att)).status == "WARN"


# ---- advisory: never scored, never FAIL, ATTESTED confidence ----
def test_b47_is_advisory():
    att = _att([{"from": "researcher", "to": "vault", "returns": "raw"},
                {"from": "researcher", "to": "sender", "returns": "raw"}])
    r = check_delegation_reassembly(_ctx(att))
    assert r.scored is False
    assert r.confidence == "ATTESTED"
    assert r.status != "FAIL"


# ---- RISK-11 needs attestation: absent on a bare config ----
def test_risk11_absent_without_attestation():
    assert "RISK-11" not in _risk_ids({})


# ---- B-151 regression: a monolithic agent (holds all 3 legs itself, zero outgoing
# delegation edges) must NOT be reported as a cross-agent B47/RISK-11 reassembly just
# because an UNRELATED delegation edge exists elsewhere in the roster — even a fully
# walled (schema-return) edge between two other agents. That is B45's territory
# exclusively (one agent = the whole trifecta, no privilege separation).
def test_b47_monolithic_agent_with_unrelated_edge_is_unknown_not_warn():
    att = {
        "agents": [
            {"name": "solo", "tools": ["web_fetch", "postgres_query", "shell_exec"]},
        ],
        "delegation": [{"from": "ghost1", "to": "ghost2", "returns": "schema"}],
    }
    r = check_delegation_reassembly(_ctx(att))
    # "solo" has no outgoing edge at all, so no chain was ever traversed for it, and
    # ghost1/ghost2 are not in the attested agent roster (not untrusted-input agents
    # with legs known) — nothing reachable → PASS (edges exist, but not reachable),
    # never WARN, and never RISK-11.
    assert r.status != "WARN"
    assert "RISK-11" not in _risk_ids(att)


def test_b47_monolithic_agent_with_unrelated_edge_any_tier_never_warns():
    for tier in ("schema", "filtered", "raw", "unknown"):
        att = {
            "agents": [
                {"name": "solo", "tools": ["web_fetch", "postgres_query", "shell_exec"]},
            ],
            "delegation": [{"from": "ghost1", "to": "ghost2", "returns": tier}],
        }
        r = check_delegation_reassembly(_ctx(att))
        assert r.status != "WARN", f"tier={tier} produced a false WARN"
        assert "RISK-11" not in _risk_ids(att), f"tier={tier} produced a false RISK-11"


def test_b47_monolithic_agent_no_edges_still_unknown():
    # Control: no delegation edges at all -> UNKNOWN (unchanged behavior).
    att = {"agents": [
        {"name": "solo", "tools": ["web_fetch", "postgres_query", "shell_exec"]},
    ]}
    r = check_delegation_reassembly(_ctx(att))
    assert r.status == "UNKNOWN"


def test_b45_still_warns_on_monolithic_agent_regardless_of_b47_fix():
    # B45 must still correctly WARN on the monolithic case — this bug's fix lives
    # entirely inside _reassembly() (B47/RISK-11's engine); B45 never calls it.
    att = {
        "agents": [
            {"name": "solo", "tools": ["web_fetch", "postgres_query", "shell_exec"]},
        ],
        "delegation": [{"from": "ghost1", "to": "ghost2", "returns": "schema"}],
    }
    r = check_agent_separation(_ctx(att))
    assert r.status == "WARN"
    assert any("solo" in e for e in r.evidence)


# ---- he report: B47 WARN evidence prose is translated, the chain (data) is preserved ----
