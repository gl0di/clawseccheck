"""attested_agents() — tolerant parser for the multi-agent roster (B45)."""
from clawseccheck.attest import attested_agents, template


# ---- junk / absent -> [] ----
def test_attested_agents_empty_on_non_dict():
    assert attested_agents(None) == []
    assert attested_agents("nope") == []
    assert attested_agents([1, 2, 3]) == []


def test_attested_agents_empty_when_key_absent():
    assert attested_agents({"tools": ["x"]}) == []


def test_attested_agents_empty_when_not_a_list():
    assert attested_agents({"agents": {"name": "x"}}) == []
    assert attested_agents({"agents": "researcher"}) == []


# ---- well-formed roster is normalized ----
def test_attested_agents_parses_roster():
    att = {"agents": [
        {"name": "reader", "tools": ["web_fetch", "read_file"]},
        {"name": "vault", "tools": ["postgres_query"]},
    ]}
    out = attested_agents(att)
    assert out == [
        {"name": "reader", "tools": ["web_fetch", "read_file"]},
        {"name": "vault", "tools": ["postgres_query"]},
    ]


# ---- non-dict entries are skipped ----
def test_attested_agents_skips_non_dict_entries():
    att = {"agents": ["just a string", 42, {"name": "ok", "tools": ["x"]}]}
    out = attested_agents(att)
    assert out == [{"name": "ok", "tools": ["x"]}]


# ---- missing / blank name falls back to a positional label ----
def test_attested_agents_missing_name_is_positional():
    att = {"agents": [{"tools": ["web_fetch"]}, {"name": "  ", "tools": []}]}
    out = attested_agents(att)
    assert out[0]["name"] == "agent[0]"
    assert out[1]["name"] == "agent[1]"


# ---- non-string / empty tools are dropped, missing tools -> [] ----
def test_attested_agents_drops_non_string_tools():
    att = {"agents": [{"name": "a", "tools": ["ok", 7, "", None, "  ", "fine"]}]}
    out = attested_agents(att)
    assert out[0]["tools"] == ["ok", "fine"]


def test_attested_agents_missing_tools_is_empty_list():
    att = {"agents": [{"name": "a"}]}
    out = attested_agents(att)
    assert out == [{"name": "a", "tools": []}]


def test_attested_agents_tools_not_a_list_is_empty():
    att = {"agents": [{"name": "a", "tools": "web_fetch"}]}
    out = attested_agents(att)
    assert out == [{"name": "a", "tools": []}]


# ---- the --ask template advertises the agents block ----
def test_template_includes_agents_block():
    tpl = template()
    assert tpl["agents"] == []
    assert "agents" in tpl["_questions"]
