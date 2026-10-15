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
def test_attested_agents_non_dict_entries_make_the_roster_unusable():
    # C-714: all or nothing - a roster with an unusable entry reads as no roster.
    att = {"agents": ["just a string", 42, {"name": "ok", "tools": ["x"]}]}
    assert attested_agents(att) == []
    assert attested_agents({"agents": [{"name": "ok", "tools": ["x"]}]}) == [
        {"name": "ok", "tools": ["x"]}]


# ---- C-714: an entry that does not validate is dropped, never repaired ----
def test_attested_agents_missing_or_blank_name_is_dropped():
    att = {"agents": [{"tools": ["web_fetch"]}, {"name": "  ", "tools": []}]}
    assert attested_agents(att) == []


def test_attested_agents_non_string_tool_drops_the_entry():
    att = {"agents": [{"name": "a", "tools": ["ok", 7, "fine"]}]}
    assert attested_agents(att) == []


def test_attested_agents_blank_tool_name_drops_the_entry():
    # a blank tool name (empty, whitespace, or only zero-width / control characters) is not a
    # verb: the entry's inventory is unreadable, so it is dropped, not trimmed (C-714)
    for blank in ("", "  ", "\u200b", "\x00"):
        assert attested_agents({"agents": [{"name": "a", "tools": ["ok", blank]}]}) == []


def test_attested_agents_missing_tools_drops_the_entry():
    assert attested_agents({"agents": [{"name": "a"}]}) == []


def test_attested_agents_tools_not_a_list_drops_the_entry():
    assert attested_agents({"agents": [{"name": "a", "tools": "web_fetch"}]}) == []


# ---- the --ask template advertises the agents block ----
def test_template_includes_agents_block():
    tpl = template()
    assert tpl["agents"] == []
    assert "agents" in tpl["_questions"]
