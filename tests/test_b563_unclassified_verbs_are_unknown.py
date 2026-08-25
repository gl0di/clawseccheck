"""B-563 — an unrecognised verb name must not count DOWN to a clean separation verdict.

B45/B47 derive each trifecta leg from substring hints and get back a bool, so a verb
name no hint matches records False on all three legs. Every consumer reads that as
"this agent does not hold that capability", when what happened is "this name was not
recognised" — the unknown makes the verdict SAFER, which is the fail-open shape Golden
Rule #4 forbids.

The user-visible harm is one report contradicting itself: on the real roster of the
agent running this repo, A1 says "Active legs 3/3" and B43 WARNs "holds exec (Bash)"
while B45/B47 green-tick privilege separation in the same run.

These tests pin the CONTRADICTION and the guarantee that the fix costs nothing else:
a positive finding (WARN) is never weakened, and PASS stays reachable.
"""
from pathlib import Path

from clawseccheck import attest
from clawseccheck.checks import (
    _unclassified_leg_verbs,
    check_agent_separation,
    check_delegation_reassembly,
)
from clawseccheck.collector import Context

# The roster the --ask template asks an agent to report: its REAL verb names. Answering
# honestly is exactly what used to produce the false PASS.
REAL_ROSTER = ["Read", "Write", "Edit", "Bash", "WebFetch", "Grep", "Glob", "Task"]


def _ctx(attestation=None):
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.attestation = attestation or {}
    return c


# ---------------------------------------------------------------- the helper
def test_unrecognised_verbs_are_reported():
    assert _unclassified_leg_verbs(REAL_ROSTER) == ["Write", "Edit", "Grep", "Glob", "Task"]


def test_a_reversible_verb_is_not_called_unknown():
    """`Read` holds no leg AND the blast-radius taxonomy places it as REVERSIBLE.

    That is genuinely leg-free, not unrecognised. Listing it would push almost every
    real roster to UNKNOWN and cost the check the ability to say anything at all.
    """
    assert _unclassified_leg_verbs(["Read"]) == []
    assert attest.classify_verb("Read") == "REVERSIBLE"


def test_the_taxonomys_own_hint_words_are_all_classifiable():
    assert _unclassified_leg_verbs(["web", "secret", "exec"]) == []


def test_non_string_entries_never_surface_as_a_verb_name():
    # attested_agents already drops these upstream; this keeps a stray entry from any
    # other caller out of a user-facing evidence line as a verb literally named "None".
    assert _unclassified_leg_verbs([None, 42, "Bash"]) == []


# ---------------------------------------------------------------- B45
def test_b45_real_roster_is_unknown_not_pass():
    """The filed defect. Was PASS "privilege separation is met"."""
    att = {"agents": [{"name": "main", "tools": REAL_ROSTER}]}
    r = check_agent_separation(_ctx(att))
    assert r.id == "B45"
    assert r.status == "UNKNOWN"
    assert any("Write" in e for e in r.evidence)


def test_b45_does_not_contradict_the_blast_radius_classifier():
    """B43 and B45 read the same roster with two different taxonomies.

    If `classify_tools` places a verb as EXEC, B45 must not turn round and report a
    clean privilege-separation PASS over that same roster — that pair of sentences in
    one report is what B-563 was filed for.
    """
    att = {"agents": [{"name": "main", "tools": REAL_ROSTER}]}
    assert "Bash" in attest.classify_tools(REAL_ROSTER).get("EXEC", [])
    assert check_agent_separation(_ctx(att)).status != "PASS"


def test_b45_still_warns_when_an_agent_holds_all_three_legs():
    """An unclassifiable verb must never SUPPRESS a positive finding.

    Evidence of harm outranks incompleteness: the UNKNOWN branch is reached only after
    the WARN branch has declined.
    """
    att = {"agents": [
        {"name": "mono", "tools": ["web_fetch", "postgres_query", "shell_exec", "Glob"]},
    ]}
    r = check_agent_separation(_ctx(att))
    assert r.status == "WARN"
    assert any("mono" in e for e in r.evidence)


def test_b45_pass_is_still_reachable():
    """A fully classifiable roster below all-three legs still PASSes.

    Without this the fix would be vacuous — an UNKNOWN that swallows every input says
    no more than the PASS it replaced.
    """
    att = {"agents": [
        {"name": "reader", "tools": ["web_fetch"]},
        {"name": "vault", "tools": ["postgres_query"]},
        {"name": "sender", "tools": ["shell_exec"]},
    ]}
    assert check_agent_separation(_ctx(att)).status == "PASS"


def test_b45_an_unclassifiable_verb_never_improves_the_verdict():
    """Adding an unrecognised verb to a roster may only weaken confidence, never raise it."""
    base = {"agents": [{"name": "a", "tools": ["web_fetch"]},
                       {"name": "b", "tools": ["postgres_query"]},
                       {"name": "c", "tools": ["shell_exec"]}]}
    assert check_agent_separation(_ctx(base)).status == "PASS"
    widened = {"agents": [{"name": "a", "tools": ["web_fetch", "Glob"]},
                          {"name": "b", "tools": ["postgres_query"]},
                          {"name": "c", "tools": ["shell_exec"]}]}
    assert check_agent_separation(_ctx(widened)).status == "UNKNOWN"


# ---------------------------------------------------------------- B47
def _delegated(tools_main):
    return {
        "agents": [{"name": "main", "tools": tools_main},
                   {"name": "researcher", "tools": ["web_fetch"]}],
        "delegation": [{"from": "researcher", "to": "main", "returns": "raw"}],
    }


def test_b47_real_roster_is_unknown_not_pass():
    r = check_delegation_reassembly(_ctx(_delegated(REAL_ROSTER)))
    assert r.id == "B47"
    assert r.status == "UNKNOWN"
    assert any("Write" in e for e in r.evidence)


def test_b47_pass_is_still_reachable():
    """A classifiable graph that genuinely does not reassemble still PASSes."""
    att = {
        "agents": [{"name": "reader", "tools": ["web_fetch"]},
                   {"name": "vault", "tools": ["postgres_query"]}],
        "delegation": [{"from": "vault", "to": "reader", "returns": "raw"}],
    }
    assert check_delegation_reassembly(_ctx(att)).status == "PASS"
