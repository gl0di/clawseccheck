"""attested_delegation() — tolerant parser for the delegation graph (B47/RISK-11)."""
from clawseccheck.attest import attested_delegation, template


# ---- junk / absent -> [] ----
def test_attested_delegation_empty_on_non_dict():
    assert attested_delegation(None) == []
    assert attested_delegation("x") == []


def test_attested_delegation_empty_when_absent_or_wrong_type():
    assert attested_delegation({"agents": []}) == []
    assert attested_delegation({"delegation": {"from": "a"}}) == []
    assert attested_delegation({"delegation": "researcher->main"}) == []


# ---- well-formed edges normalized ----
def test_attested_delegation_parses_edges():
    att = {"delegation": [
        {"from": "researcher", "to": "main", "returns": "schema"},
        {"from": "main", "to": "sender", "returns": "raw"},
    ]}
    assert attested_delegation(att) == [
        {"from": "researcher", "to": "main", "returns": "schema"},
        {"from": "main", "to": "sender", "returns": "raw"},
    ]


# ---- unrecognized / missing returns -> "unknown" ----
def test_attested_delegation_normalizes_returns():
    att = {"delegation": [
        {"from": "a", "to": "b", "returns": "weird"},
        {"from": "a", "to": "c"},
        {"from": "a", "to": "d", "returns": "SCHEMA"},   # case-folded
    ]}
    out = attested_delegation(att)
    assert out[0]["returns"] == "unknown"
    assert out[1]["returns"] == "unknown"
    assert out[2]["returns"] == "schema"


# ---- non-dict edges / blank endpoints dropped ----
def test_attested_delegation_drops_bad_edges():
    att = {"delegation": [
        "a->b", 7,
        {"from": "", "to": "b", "returns": "raw"},
        {"from": "a", "to": "  ", "returns": "raw"},
        {"to": "b", "returns": "raw"},                   # no from
        {"from": "a", "to": "b", "returns": "raw"},      # the only good one
    ]}
    assert attested_delegation(att) == [{"from": "a", "to": "b", "returns": "raw"}]


# ---- the --ask template advertises the delegation block ----
def test_template_includes_delegation_block():
    tpl = template()
    assert tpl["delegation"] == []
    assert "delegation" in tpl["_questions"]
