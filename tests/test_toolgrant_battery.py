"""S1 — the differential battery for ``clawseccheck.toolgrant.granted()``.

Written BEFORE the module it exercises (an approved two-step design: S1 battery, then S2
port). That order is not cosmetic — a battery written after the module it grades tends to
get curve-fit to whatever the module already does and stops being an independent oracle.
This file's data was captured by RUNNING the real OpenClaw resolver, with no
``clawseccheck.toolgrant`` import anywhere near the generation step.

WHAT IT COVERS. Two populations, both replayed offline from ``tests/data/toolgrant_battery.json``:

* **the fixture corpus** — every ``fixtures/*/openclaw.json`` that parses as plain JSON to a
  non-empty dict × every scope the config declares (the global surface, plus each entry of
  its agent roster) × the tool family ``{read, write, edit, apply_patch, exec, automations}``,
  one parametrized case per ``(fixture, scope, tool)``. This includes, as a subset, the nine
  ``fixtures/toolscope_case1..9`` edge fixtures the S0 precondition task built and
  ``tests/test_toolscope_per_scope_grants.py`` already documents (its docstring's vendor table
  matches this battery's rows for those nine labels exactly). The case count is derived from
  the data at import time (``test_battery_is_a_real_corpus_sweep``), never hand-typed.
* **synthetic configs** (``"synthetic": true`` rows, config embedded in the row) — every
  ``group:*`` as an allow and a deny, every profile with and without ``alsoAllow``, the alias
  spellings and both roster shapes. No fixture config names a ``group:*`` entry at all
  (measured: 0 of 575), so the corpus alone graded a stale group table GREEN: against 2026.9.5,
  522 of 6,688 cells disagreed and none of them was in the six-tool family the corpus
  exercises. Group and profile ids are taken from the vendor when the battery is generated,
  so a new group is swept the day it appears.

TWO TOOL SETS. The six-tool family is parametrized per cell (a failure names one cell).
``EXTENDED_TOOLS`` — ``gateway``, ``plugins``, ``ls``, ``openclaw``, ``pdf`` — is checked one
test per tool over every row, and the synthetic rows are checked one test per tool. Making
those 4,173 further cells parametrized cases would have been the same assertion with a longer
log, and the suite's test-count claims in the docs (``tests/test_doc_facts.py``) move with
every case.
The extended set is what a profile-table re-ground actually changes: ``gateway`` and
``plugins`` entered default profiles, ``ls`` had drifted, ``openclaw`` and ``pdf`` were
catalog entries the port had never been asked about.

HOW IT IS GENERATED. ``tests/_toolgrantoracle.py`` — committed, deterministic, and runnable::

    python3.12 tests/_toolgrantoracle.py --write    # regenerate (needs node + the installed dist)
    python3.12 tests/_toolgrantoracle.py --check    # is the pinned data still what the vendor says?

It executes ``resolveConfiguredToolPolicies`` and ``isToolAllowedByPolicies`` from the
installed dist, and resolves ``agentTools`` the way ``resolveEffectiveToolPolicy`` does (its
own three lines). The first battery came from a one-shot script that was never kept, so it
could not be re-run on the next OpenClaw build; that is why this one is a module. Bundle
filenames are content-hashed and rotate every release, so the generator locates each symbol
by the line that declares it, not by name (see its docstring).

Grounded on the installed **openclaw@2026.9.5** (regenerated 2026-09-19). Re-running the
generator's replay over the previous 536-row, 3,354-cell battery against 2026.9.5 changed
zero cells: the tables moved, the family's verdicts did not. The pinned file keeps the first
capture's layout (sorted keys, ``indent=1``); only the ROW ORDER changed (now sorted by
label). The diff is large because rows and tools were ADDED -- five more tools on the 536
original rows, 39 fixtures added since, and 96 synthetic rows -- not because any of the 3,354
original cells changed, and not because it was re-serialised.

``sandboxMode`` IS FIXED TO ``null`` THROUGHOUT. ``granted(cfg, tool, scope)`` answers only
the declared tool-POLICY question, the same way ``clawseccheck/toolpolicy.py`` keeps
"is a tool granted" separate from "is the session sandbox-contained"
(``resolveSandboxToolPolicyForAgent`` is a third, independent AND-ed layer the real
resolver only pushes when ``sandboxMode === "all"``) — that is a distinct axis this task
does not port, so the battery never exercises it.

WHAT THIS FILE DOES NOT DO: it does not adjudicate whether a check's current verdict is
right (that is ``tests/test_toolscope_per_scope_grants.py``'s documented job for the four
consumer checks), and it does not ground the profile/group/alias TABLES against the
installed dist — ``tests/test_toolgrant_dist_grounding.py`` does that, whole-table, against a
fresh execution.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
DATA = Path(__file__).resolve().parent / "data" / "toolgrant_battery.json"

TOOL_FAMILY = ("read", "write", "edit", "apply_patch", "exec", "automations")
EXTENDED_TOOLS = ("gateway", "plugins", "ls", "openclaw", "pdf")
ALL_TOOLS = TOOL_FAMILY + EXTENDED_TOOLS

_EDGE_CASE_LABELS = frozenset({
    "toolscope_case1_empty_default",
    "toolscope_case2_allow_write_implies_apply_patch",
    "toolscope_case3_allow_apply_patch_asymmetric",
    "toolscope_case4_per_agent_allow_narrows_only",
    "toolscope_case5_per_agent_alsoallow_no_profile",
    "toolscope_case6_per_agent_alsoallow_widens_with_profile",
    "toolscope_case7_per_agent_alsoallow_replaces_global",
    "toolscope_case8_agents_defaults_tools_no_roster",
    "toolscope_case9_agents_defaults_tools_ignored_with_roster",
})


def _load_battery() -> list:
    return json.loads(DATA.read_text(encoding="utf-8"))


BATTERY = _load_battery()

# One (fixture label, scope, tool, expected bool) tuple per vendor-measured assertion of the
# six-tool family over the FIXTURE corpus. Synthetic rows and the extended tools are asserted
# in aggregate below (see the module docstring for why).
CORPUS_ROWS = [row for row in BATTERY if not row.get("synthetic")]
SYNTHETIC_ROWS = [row for row in BATTERY if row.get("synthetic")]

CASES: list = []
for _row in CORPUS_ROWS:
    for _tool in TOOL_FAMILY:
        for _scope, _expected in _row["results"][_tool].items():
            CASES.append((_row["label"], _scope, _tool, _expected))


def _config_cache() -> dict:
    """Fixture rows are read from ``fixtures/``; synthetic rows carry their config."""
    cache = {}
    for row in BATTERY:
        if "cfg" in row:
            cache[row["label"]] = row["cfg"]
            continue
        path = FIXTURES / row["label"] / "openclaw.json"
        cache[row["label"]] = json.loads(path.read_text(encoding="utf-8"))
    return cache


_CONFIGS = _config_cache()


# --------------------------------------------------------------------- data invariants
# These hold regardless of whether clawseccheck.toolgrant exists yet — they are checks on
# the BATTERY, not on the module it will grade.

def test_battery_is_a_real_corpus_sweep():
    """Enough rows, enough scopes, and both answers present (a constant function must fail
    this the same way tests/test_b666_read_reach.py polices its own table)."""
    assert len(CORPUS_ROWS) >= 500, len(CORPUS_ROWS)
    assert len(CASES) >= 3000, len(CASES)
    answers = {c[3] for c in CASES}
    assert answers == {True, False}, answers
    assert sum(1 for c in CASES if c[3]) >= 500
    assert sum(1 for c in CASES if not c[3]) >= 500


def test_no_duplicate_case_keys():
    keys = [(label, scope, tool) for label, scope, tool, _ in CASES]
    assert len(keys) == len(set(keys))


def test_every_fixture_row_has_a_readable_non_empty_config():
    for row in BATTERY:
        cfg = _CONFIGS[row["label"]]
        assert isinstance(cfg, dict) and cfg, row["label"]


def test_every_row_covers_the_full_tool_family():
    for row in BATTERY:
        assert set(row["results"]) == set(ALL_TOOLS), row["label"]


def test_the_generator_and_this_file_agree_on_the_tool_family():
    """Two literals for one fact: this file states its expectation independently, and the
    generator's own constants must equal it, or a regeneration would silently change what is
    pinned."""
    import _toolgrantoracle as oracle

    assert oracle.TOOL_FAMILY == TOOL_FAMILY
    assert oracle.EXTENDED_TOOLS == EXTENDED_TOOLS
    assert oracle.BATTERY_TOOLS == ALL_TOOLS


def test_every_row_declares_the_global_scope():
    for row in BATTERY:
        for tool in TOOL_FAMILY:
            assert "global" in row["results"][tool], (row["label"], tool)


def test_the_nine_edge_case_fixtures_are_all_present():
    labels = {row["label"] for row in BATTERY}
    missing = _EDGE_CASE_LABELS - labels
    assert not missing, missing


def test_edge_case_rows_match_the_documented_vendor_table():
    """Spot-check against the hand-verified table already committed in
    tests/test_toolscope_per_scope_grants.py's docstring (case 6/7/8/9 — the four
    discrepancy cases the whole precondition task exists to surface)."""
    by_label = {row["label"]: row for row in BATTERY}

    case6 = by_label["toolscope_case6_per_agent_alsoallow_widens_with_profile"]
    assert case6["results"]["write"] == {"global": False, "main": False, "helper": True}
    assert case6["results"]["apply_patch"] == {"global": False, "main": False, "helper": True}

    case7 = by_label["toolscope_case7_per_agent_alsoallow_replaces_global"]
    assert case7["results"]["read"] == {"global": False, "main": False, "helper": True}
    assert case7["results"]["write"] == {"global": True, "main": True, "helper": False}

    case8 = by_label["toolscope_case8_agents_defaults_tools_no_roster"]
    assert case8["agents"] == []
    assert case8["results"]["write"] == {"global": True}
    assert case8["results"]["read"] == {"global": False}

    case9 = by_label["toolscope_case9_agents_defaults_tools_ignored_with_roster"]
    for tool in TOOL_FAMILY:
        assert case9["results"][tool] == {"global": True, "main": True}, tool


def test_synthetic_rows_are_present_and_self_contained():
    assert len(SYNTHETIC_ROWS) >= 60, len(SYNTHETIC_ROWS)
    for row in SYNTHETIC_ROWS:
        assert row["label"].startswith("synthetic/"), row["label"]
        assert isinstance(row["cfg"], dict) and row["cfg"], row["label"]
        assert not (FIXTURES / row["label"]).exists(), row["label"]


def test_synthetic_rows_exercise_both_answers_for_every_tool():
    """A tool whose pinned answer is constant grades nothing: a port that always said
    True (or False) for it would pass. Every tool must be seen granted AND refused."""
    for tool in ALL_TOOLS:
        answers = {v for row in SYNTHETIC_ROWS for v in row["results"][tool].values()}
        assert answers == {True, False}, (tool, answers)


def test_synthetic_rows_reach_every_group_and_profile_the_port_carries():
    """The pinned data must track the tables it grades: a group or profile in
    toolgrant.py with no synthetic row is a table entry no offline test can see."""
    import clawseccheck.toolgrant as tg

    labels = {row["label"] for row in SYNTHETIC_ROWS}
    for group in tg._CORE_TOOL_GROUPS:
        assert f"synthetic/group/{group}/allow" in labels, group
        assert f"synthetic/group/{group}/deny" in labels, group
    for profile in tg._CORE_TOOL_PROFILES:
        assert f"synthetic/profile/{profile}" in labels, profile


# ------------------------------------------------------------- the acceptance gate
# A plain import. This block used to swallow ImportError and skip the gate "until S2 exists";
# S2 has shipped, and a guard that can turn itself off on a renamed module while the run stays
# green is exactly the failure this whole file exists to prevent.
import clawseccheck.toolgrant as toolgrant  # noqa: E402


def _case_id(case) -> str:
    label, scope, tool, expected = case
    return f"{label}/{scope}/{tool}={expected}"


def _mismatches(rows, tool):
    out = []
    for row in rows:
        cfg = _CONFIGS[row["label"]]
        for scope, expected in row["results"][tool].items():
            if toolgrant.granted(cfg, tool, scope) is not expected:
                out.append(f"{row['label']}/{scope}: the vendor says {expected}")
    return out


@pytest.mark.parametrize("label,scope,tool,expected", CASES, ids=[_case_id(c) for c in CASES])
def test_matches_the_installed_runtime(label, scope, tool, expected):
    cfg = _CONFIGS[label]
    assert toolgrant.granted(cfg, tool, scope) is expected


@pytest.mark.parametrize("tool", EXTENDED_TOOLS)
def test_extended_tool_matches_the_installed_runtime(tool):
    """gateway/plugins/ls/openclaw/pdf over every fixture AND every synthetic row."""
    wrong = _mismatches(BATTERY, tool)
    assert not wrong, f"{len(wrong)} cell(s) disagree for {tool!r}, first: {wrong[:8]}"


@pytest.mark.parametrize("tool", TOOL_FAMILY)
def test_family_tool_matches_the_installed_runtime_on_synthetic_configs(tool):
    """The per-cell gate above is corpus-only; this is the same claim over the configs built
    to reach every group, profile and alias."""
    wrong = _mismatches(SYNTHETIC_ROWS, tool)
    assert not wrong, f"{len(wrong)} cell(s) disagree for {tool!r}, first: {wrong[:8]}"
