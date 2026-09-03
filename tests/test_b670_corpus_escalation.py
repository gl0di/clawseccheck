"""B-670 corpus coverage — the escalation shape, on a shipped fixture pair.

`tests/test_b670_fs_confined_per_scope.py` proves the fix through synthetic in-memory
configs. It does not touch the corpus, and the corpus matters here for a specific
reason the B-670 handoff named directly: `tests/finding_fingerprint_manifest.txt` and
`scripts/fleet_fp_gate.py` sweep `fixtures/`, not hand-built dicts — a fix with zero
corpus fixture of its shape is invisible to both, "zero movement across the fixture
corpus" in the handoff's own words. `fixtures/bad_b283_fs_per_agent_optout` was the
closest existing shape (a global `tools.fs.workspaceOnly: true` beside a per-agent
`false`) but declares no open-ingress channel, so B55 there is WARN by an unrelated
path (no channel => no FAIL branch at all) and never exercises the escalation this
task adds.

This pair supplies exactly the missing combination: global filesystem confinement ON,
a per-agent `tools.fs.workspaceOnly: false` escape, an open-ingress channel, and an
explicit filesystem-write grant — the four ingredients `check_fs_write_exposure` (B55)
needs to escalate WARN -> FAIL once a scope is shown to be BOTH unconfined AND
inheriting the global write grant unchanged (`toolpolicy.
unconfined_scopes_inheriting_global_tools`).

Also the first corpus fixture pair to use the 2026.8.1+ `agents.entries` RECORD roster
shape rather than the legacy `agents.list` ARRAY (measured: no other shipped fixture
declares `agents.entries` at all) — grounded per B-699/collector.py's `agent_roster()`,
which reads `agents.entries` directly (not through `dig()`), and per the 2026.8.2
schema's requirement that a multi-agent roster carry an ownership marker, satisfied
here the same way `test_b670_fs_confined_per_scope.py` satisfies it: one entry marked
`"default": True`.

The pair is a controlled comparison, not two unrelated configs: they differ in exactly
one fact, the escaping agent `"w"`'s own `tools.fs.workspaceOnly` — `false` (bad) vs.
`true` (clean, so `w` inherits confinement rather than escaping it). Everything else
byte-identical (diffed in the test below).
"""
import json
from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, WARN
from clawseccheck.checks import check_fs_write_exposure
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
BAD = FIXTURES / "bad_b670_fs_confined_per_agent_escape"
CLEAN = FIXTURES / "clean_b670_fs_confined_per_agent_escape"


def _b55(home: Path):
    return check_fs_write_exposure(collect(home))


def test_the_pair_differs_in_exactly_one_fact():
    """The controlled-comparison contract: everything but `w`'s own
    `tools.fs.workspaceOnly` is byte-identical between the two fixtures."""
    bad = json.loads((BAD / "openclaw.json").read_text(encoding="utf-8"))
    clean = json.loads((CLEAN / "openclaw.json").read_text(encoding="utf-8"))
    assert bad["agents"]["entries"]["w"]["tools"]["fs"]["workspaceOnly"] is False
    assert clean["agents"]["entries"]["w"]["tools"]["fs"]["workspaceOnly"] is True
    bad["agents"]["entries"]["w"]["tools"]["fs"]["workspaceOnly"] = None
    clean["agents"]["entries"]["w"]["tools"]["fs"]["workspaceOnly"] = None
    assert bad == clean, "the fixtures must differ in nothing else"


def test_the_per_agent_escape_escalates_to_fail():
    """The escalation this task exists to put on the corpus: a global fs.workspaceOnly
    confinement with a per-agent escape, an open channel, and an explicit write grant
    together produce a B55 FAIL — the shape `bad_b283_fs_per_agent_optout` cannot reach
    because it declares no open-ingress channel."""
    f = _b55(BAD)
    assert f.status == FAIL
    assert any("agents.entries.w" in e for e in (f.evidence or [])), (
        "the evidence must name the escaping scope by its agents.entries path")


def test_the_clean_twin_stays_a_warn_not_a_fail():
    """The control: with the single fact flipped back (the agent also confined), B55
    must NOT escalate — it downgrades to WARN with the confinement claim, same as
    `test_genuine_confinement_still_downgrades_to_warn` in the synthetic-config test."""
    f = _b55(CLEAN)
    assert f.status == WARN
    assert any("confined to the workspace" in e for e in (f.evidence or []))


@pytest.mark.parametrize("home", [BAD, CLEAN])
def test_both_fixtures_are_readable_agents_entries_rosters(home):
    """Structural: both fixtures actually exercise the `agents.entries` record shape
    (not `agents.list`), so this pair is real coverage for that roster shape too."""
    cfg = json.loads((home / "openclaw.json").read_text(encoding="utf-8"))
    assert "entries" in cfg["agents"]
    assert "list" not in cfg["agents"]
    assert set(cfg["agents"]["entries"]) == {"main", "w"}
