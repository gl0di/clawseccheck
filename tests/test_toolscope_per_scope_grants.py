"""toolscope_case1..9 — per-scope tool-grant fixture coverage (design-pass precondition).

A design pass swept all 630 corpus fixtures at the time and found ZERO hits for
per-agent, `agents.defaults`, per-channel, or `toolsBySender` tool grants (per_agent=0,
agents_defaults=0, per_channel=0, toolsBySender=0) — so `tests/finding_fingerprint_
manifest.txt` and `scripts/fleet_fp_gate.py`, both corpus sweeps, were structurally
blind to this whole family, and a clean corpus run proved nothing about it. The nine
`fixtures/toolscope_case*` directories this file exercises are that missing coverage:
one fixture per resolution shape, each verified against the installed OpenClaw dist
(2026.9.1) by executing its own `resolveConfiguredToolPolicies` + `isToolAllowedByPolicies`
(never by reading the dist source and guessing).

This file DOCUMENTS, it does not adjudicate. For every case it records two facts side by
side: the vendor's own answer (the differential-oracle measurement above) and this
codebase's CURRENT B44/B55/B68/B84 verdict on the same config, as measured the day this
file was written. Four of the nine disagree with the vendor outright (see the table
below) — that is the deliverable this whole precondition task exists to produce, tracked
as a follow-up fix, NOT something this file fixes. Accordingly this file never asserts
`status == <today's value>` for a check on a case where that value is the disagreement
itself — doing so would encode the gap as a pinned contract and break the moment a later
task closes it. The only assertions here are invariants that hold both BEFORE and AFTER
such a fix: each fixture parses and declares the config shape its name claims, and each
of B44/B55/B68/B84 returns a well-formed `Finding` (no crash) with a status from the
normal vocabulary.

VENDOR TABLE (dist 2026.9.1; 'global' = no per-agent override at all; 'main' = the
roster entry with no `tools` override of its own; 'helper' = the roster entry that
carries the scenario's per-agent override; T/F below is granted/not-granted):

    case                                    scope    read write edit apply_patch
    1  empty config                         global    T    T    T    T
    2  tools.allow=[write]                  global    F    T    F    T
    3  tools.allow=[apply_patch]            global    F    F    F    T
    4  global allow=[read] + agent          helper    F    F    F    F
       allow=[write] (agent allow narrows)  main/gl.  T    F    F    F
    5  global allow=[read] + agent          helper    T    F    F    F
       alsoAllow=[write] (no profile)       main/gl.  T    F    F    F
    6  global profile=minimal + agent       helper    F    T    F    T
       alsoAllow=[write] (THE widening)     main/gl.  F    F    F    F
    7  global profile=minimal,              helper    T    F    F    F
       alsoAllow=[write] + agent            main/gl.  F    T    F    T
       alsoAllow=[read] (agent REPLACES)
    8  agents.defaults.tools.allow=[write],  global    F    T    F    T
       no roster at all
    9  same as 8, but a roster IS present   global/m.  T    T    T    T  (defaults ignored
                                                                          entirely)

CURRENT VERDICT TABLE (this codebase, no `--attest`, measured the day this file was
written — B44/B84 are ATTESTED-confidence and correctly UNKNOWN throughout; that is
by design, not a gap, since neither check has any evidence to cross-check without an
attestation):

    case | B44     | B55     | B68     | vendor agreement (write-grant dimension)
    1    | UNKNOWN | UNKNOWN | UNKNOWN | DISAGREES — vendor: write=true (nothing declared
         |         |         |         | is the permissive default); checks: not
         |         |         |         | enumerable, so UNKNOWN rather than a real grant
    2    | UNKNOWN | FAIL    | WARN    | agrees
    3    | UNKNOWN | FAIL    | WARN    | agrees (apply_patch modelled as write-capable)
    4    | UNKNOWN | PASS    | WARN    | agrees (write is false everywhere incl. helper)
    5    | UNKNOWN | PASS    | WARN    | agrees (write is false everywhere incl. helper)
    6    | UNKNOWN | PASS    | PASS    | DISAGREES — vendor: helper write=true AND
         |         |         |         | apply_patch=true (reachable via the fixture's
         |         |         |         | open channel); both checks see no write grant
         |         |         |         | at all. This is the real machine's own config
         |         |         |         | shape (tools.profile + a per-agent alsoAllow)
         |         |         |         | and the highest-severity of the four.
    7    | UNKNOWN | FAIL    | WARN    | PARTIALLY DISAGREES — the FAIL verdict itself is
         |         |         |         | sound (driven by 'main', which genuinely keeps
         |         |         |         | the global write+apply_patch grant unchanged),
         |         |         |         | but B55's own evidence line names BOTH
         |         |         |         | 'agents.entries.main' AND 'agents.entries.helper'
         |         |         |         | as scopes that "inherit the global write grant
         |         |         |         | unchanged" — false for helper, whose own
         |         |         |         | alsoAllow REPLACES (not narrows) the global one
         |         |         |         | and drops write to false.
    8    | UNKNOWN | UNKNOWN | UNKNOWN | DISAGREES — vendor: write=true, because
         |         |         |         | agents.defaults.tools IS the effective policy
         |         |         |         | when no roster exists at all; neither check
         |         |         |         | reads cfg['agents']['defaults']['tools'] at any
         |         |         |         | point (only cfg['tools']), so the grant is
         |         |         |         | entirely invisible rather than merely UNKNOWN
         |         |         |         | by design.
    9    | UNKNOWN | UNKNOWN | UNKNOWN | consistent with the vendor's "ignored entirely"
         |         |         |         | -- same permissive-default ambiguity as case 1,
         |         |         |         | not a distinct new gap.

Cases 1/6/7/8 are the recorded discrepancies. Pulse tracks the follow-up fix task; this
file's job stops at proving the gap is real and reproducible on a shipped fixture, not
just in a scratch script.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    check_attestation_mismatch,  # B44
    check_declared_effective_proven,  # B84
    check_exec_applypatch_workspace,  # B68
    check_fs_write_exposure,  # B55
)
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_VALID_STATUSES = {PASS, WARN, FAIL, UNKNOWN}

CASES = [
    "toolscope_case1_empty_default",
    "toolscope_case2_allow_write_implies_apply_patch",
    "toolscope_case3_allow_apply_patch_asymmetric",
    "toolscope_case4_per_agent_allow_narrows_only",
    "toolscope_case5_per_agent_alsoallow_no_profile",
    "toolscope_case6_per_agent_alsoallow_widens_with_profile",
    "toolscope_case7_per_agent_alsoallow_replaces_global",
    "toolscope_case8_agents_defaults_tools_no_roster",
    "toolscope_case9_agents_defaults_tools_ignored_with_roster",
]

_TOOL_CHECKS = (
    check_attestation_mismatch,
    check_fs_write_exposure,
    check_exec_applypatch_workspace,
    check_declared_effective_proven,
)


def _cfg(name: str) -> dict:
    return json.loads((FIXTURES / name / "openclaw.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", CASES)
def test_all_nine_fixtures_exist_and_are_readable(name: str):
    home = FIXTURES / name
    assert (home / "openclaw.json").is_file(), f"{name}: missing openclaw.json"
    cfg = _cfg(name)
    assert isinstance(cfg, dict) and cfg, f"{name}: config did not parse to a non-empty dict"


@pytest.mark.parametrize("name", CASES)
def test_b44_b55_b68_b84_return_well_formed_findings(name: str):
    """Smoke invariant only: no crash, and a status from the normal vocabulary. Holds
    unchanged before AND after a future fix to the documented discrepancies above, so
    this test does not need touching when that fix lands."""
    ctx = collect(FIXTURES / name)
    for check in _TOOL_CHECKS:
        f = check(ctx)
        assert f.status in _VALID_STATUSES, f"{name}/{f.id}: unexpected status {f.status!r}"


# --------------------------------------------------------------------- fixture shape

def test_case1_declares_no_tools_or_agents_section():
    cfg = _cfg("toolscope_case1_empty_default")
    assert "tools" not in cfg
    assert "agents" not in cfg


def test_case2_allow_write_only():
    cfg = _cfg("toolscope_case2_allow_write_implies_apply_patch")
    assert cfg["tools"]["allow"] == ["write"]


def test_case3_allow_apply_patch_only():
    cfg = _cfg("toolscope_case3_allow_apply_patch_asymmetric")
    assert cfg["tools"]["allow"] == ["apply_patch"]


def test_case4_per_agent_allow_narrows_only():
    cfg = _cfg("toolscope_case4_per_agent_allow_narrows_only")
    assert cfg["tools"]["allow"] == ["read"]
    assert cfg["agents"]["entries"]["main"]["default"] is True
    assert cfg["agents"]["entries"]["helper"]["tools"]["allow"] == ["write"]


def test_case5_per_agent_alsoallow_no_profile():
    cfg = _cfg("toolscope_case5_per_agent_alsoallow_no_profile")
    assert cfg["tools"]["allow"] == ["read"]
    assert cfg["agents"]["entries"]["helper"]["tools"]["alsoAllow"] == ["write"]


def test_case6_per_agent_alsoallow_widens_with_profile():
    cfg = _cfg("toolscope_case6_per_agent_alsoallow_widens_with_profile")
    assert cfg["tools"]["profile"] == "minimal"
    assert "allow" not in cfg["tools"]
    assert "alsoAllow" not in cfg["tools"]
    assert cfg["agents"]["entries"]["helper"]["tools"]["alsoAllow"] == ["write"]


def test_case7_per_agent_alsoallow_replaces_global():
    cfg = _cfg("toolscope_case7_per_agent_alsoallow_replaces_global")
    assert cfg["tools"]["profile"] == "minimal"
    assert cfg["tools"]["alsoAllow"] == ["write"]
    assert cfg["agents"]["entries"]["helper"]["tools"]["alsoAllow"] == ["read"]


def test_case8_agents_defaults_tools_with_no_roster_at_all():
    cfg = _cfg("toolscope_case8_agents_defaults_tools_no_roster")
    assert cfg["agents"]["defaults"]["tools"]["allow"] == ["write"]
    assert "entries" not in cfg["agents"]
    assert "list" not in cfg["agents"]


def test_case9_agents_defaults_tools_with_a_roster_present():
    cfg = _cfg("toolscope_case9_agents_defaults_tools_ignored_with_roster")
    assert cfg["agents"]["defaults"]["tools"]["allow"] == ["write"]
    assert "main" in cfg["agents"]["entries"]


@pytest.mark.parametrize(
    "name",
    [
        "toolscope_case4_per_agent_allow_narrows_only",
        "toolscope_case5_per_agent_alsoallow_no_profile",
        "toolscope_case6_per_agent_alsoallow_widens_with_profile",
        "toolscope_case7_per_agent_alsoallow_replaces_global",
    ],
)
def test_two_agent_cases_use_the_entries_record_roster_shape(name: str):
    """The 2026.8.1+ shape (`fixtures/bad_b670_fs_confined_per_agent_escape` is the only
    other corpus fixture that uses it) — never the legacy `agents.list` array."""
    cfg = _cfg(name)
    assert "entries" in cfg["agents"]
    assert "list" not in cfg["agents"]
    assert set(cfg["agents"]["entries"]) == {"main", "helper"}
