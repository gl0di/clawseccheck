"""B47 — cross-agent trifecta reassembly over the delegation graph + RISK-11.

Tool names classify unambiguously (same as test_b45):
  web_fetch -> untrusted input · postgres_query -> sensitive data · shell_exec -> outbound
"""
from pathlib import Path

from clawseccheck.checks import check_delegation_reassembly
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
