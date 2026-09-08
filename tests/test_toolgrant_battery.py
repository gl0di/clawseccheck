"""S1 — the differential battery for ``clawseccheck.toolgrant.granted()``.

Written BEFORE the module it exercises (an approved two-step design: S1 battery, then S2
port). That order is not cosmetic — a battery written after the module it grades tends to
get curve-fit to whatever the module already does and stops being an independent oracle.
This file's data was captured by RUNNING the real OpenClaw resolver, with no
``clawseccheck.toolgrant`` import anywhere near the generation step.

WHAT IT COVERS. Every ``fixtures/*/openclaw.json`` that parses to a non-empty dict (536 of
686 fixture directories — 5 declare an empty/blank config, 2 are deliberately unparseable
JSON used by other tests) × every scope the config declares (the global surface, plus each
entry of its agent roster) × the tool family ``{read, write, edit, apply_patch, exec,
automations}`` — **3354** ``(fixture, scope, tool) -> bool`` assertions in total (see
``test_battery_is_a_real_corpus_sweep`` — that count is derived from the data at import
time, not hand-typed, so it cannot drift silently). This includes, as a subset, the nine
``fixtures/toolscope_case1..9`` edge fixtures the S0 precondition task built and
``tests/test_toolscope_per_scope_grants.py`` already documents (its docstring's vendor
table matches this battery's rows for those nine labels exactly — spot-checked by hand
while building this file).

HOW IT WAS GENERATED. A one-shot node script imported exactly the symbols
``tests/test_b666_read_reach.py``'s own oracle already uses —
``resolveConfiguredToolPolicies`` (dist ``agent-tools.policy-CRukL5lS.js``, the function
``granted()`` in ``clawseccheck/toolgrant.py`` ports) and ``isToolAllowedByPolicies`` (dist
``tool-policy-match-DS7InkLt.js``) — plus ``resolveAgentConfig`` / ``listAgentEntries`` /
``hasAgentRosterProperty`` (dist ``agent-scope-config-CUiGBd59.js``) to resolve
``agentTools`` exactly the way ``resolveEffectiveToolPolicy`` does (its own lines 236-238),
then walked every fixture directory, parsed its config, and for each non-empty one called::

    granted(cfg, tool, sandboxMode=null)                       # scope: "global"
    granted(cfg, agentId, tool, sandboxMode=null)               # scope: each roster id

Grounded on the installed **openclaw@2026.9.1**. Module filenames are content-hashed and
rotate every release — on a re-ground, relocate the five symbols above by NAME
(``grep -rl 'resolveConfiguredToolPolicies' dist/*.js`` etc.), not by re-using this
docstring's filenames blind. The result was written verbatim to
``tests/data/toolgrant_battery.json`` (sorted for a readable diff) — that file is the
pinned, offline battery; this module needs neither node nor the dist to run.

``sandboxMode`` IS FIXED TO ``null`` THROUGHOUT. ``granted(cfg, tool, scope)`` answers only
the declared tool-POLICY question, the same way ``clawseccheck/toolpolicy.py`` keeps
"is a tool granted" separate from "is the session sandbox-contained"
(``resolveSandboxToolPolicyForAgent`` is a third, independent AND-ed layer the real
resolver only pushes when ``sandboxMode === "all"``) — that is a distinct axis this task
does not port, so the battery never exercises it.

WHAT THIS FILE DOES NOT DO: it does not adjudicate whether a check's current verdict is
right (that is ``tests/test_toolscope_per_scope_grants.py``'s documented job for the four
consumer checks) and it is not itself the module under test's implementation — S2 is a
separate, later change to ``clawseccheck/toolgrant.py``. Until that module exists (or
while it disagrees with a row here), the parametrized test below is EXPECTED to fail/error
— that is the acceptance gate S2 must turn green, not a defect in this file.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
DATA = Path(__file__).resolve().parent / "data" / "toolgrant_battery.json"

TOOL_FAMILY = ("read", "write", "edit", "apply_patch", "exec", "automations")

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

# One (fixture label, scope, tool, expected bool) tuple per vendor-measured assertion.
CASES: list = []
for _row in BATTERY:
    for _tool, _per_scope in _row["results"].items():
        for _scope, _expected in _per_scope.items():
            CASES.append((_row["label"], _scope, _tool, _expected))


def _config_cache() -> dict:
    cache = {}
    for row in BATTERY:
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
    assert len(BATTERY) >= 500, len(BATTERY)
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
        assert set(row["results"]) == set(TOOL_FAMILY), row["label"]


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


# ------------------------------------------------------------- the acceptance gate (S2)
# Skipped, not failed, until clawseccheck.toolgrant exists. A module-level
# ``pytest.importorskip`` would skip the WHOLE FILE's collection (including the
# data-invariant tests above, which must keep running with no module present) — so the
# import is guarded by hand and only the parametrized gate below is conditionally skipped.
try:
    import clawseccheck.toolgrant as toolgrant
except ImportError:
    toolgrant = None


def _case_id(case) -> str:
    label, scope, tool, expected = case
    return f"{label}/{scope}/{tool}={expected}"


@pytest.mark.skipif(toolgrant is None, reason="S2 (clawseccheck.toolgrant) not built yet")
@pytest.mark.parametrize("label,scope,tool,expected", CASES, ids=[_case_id(c) for c in CASES])
def test_matches_the_installed_runtime(label, scope, tool, expected):
    cfg = _CONFIGS[label]
    assert toolgrant.granted(cfg, tool, scope) is expected
