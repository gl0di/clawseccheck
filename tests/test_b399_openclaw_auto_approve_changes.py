"""B399 - a standing auto-approval grant for the `openclaw` delegate tool.

`tools.openclaw.autoApproveChanges: true` (global, or per agent with the agent value
winning) lets the `openclaw` delegate tool apply config, channel, plugin, provider and
API-key changes with no human approval. The WARN needs all three of: the effective value
is true, the tool is granted to the agent by the ordinary tool policy, and the agent's
resolved sandbox mode is not exactly "all". Agent id `openclaw` never gets the tool.
Grounding: see clawseccheck/checks/_config.py::check_openclaw_auto_approve_changes.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import BY_ID, HIGH, PASS, UNKNOWN, WARN
from clawseccheck.checks import CHECKS, check_openclaw_auto_approve_changes
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_WARN_TAIL = (
    ", and the `openclaw` delegate tool is offered to those agents outside a sandbox, so a "
    "prompt-injected request in such a session can have OpenClaw apply config, channel, "
    "plugin, provider and API-key changes - including changes that run code on the Gateway "
    "host - without a human approval, even where exec and file-write tools are denied."
)
_PASS_DETAIL = (
    "No agent that can be offered the `openclaw` delegate tool has "
    "tools.openclaw.autoApproveChanges set to true, so delegated OpenClaw changes are "
    "applied automatically only under Full Access and otherwise wait for human approval."
)
_U1_DETAIL = (
    "No config was read, so whether the `openclaw` delegate tool holds a standing "
    "auto-approval grant could not be determined."
)
_U2_DETAIL = (
    "The tool policy or agent roster could not be resolved (a malformed tools block, or "
    "two agents whose ids normalize to the same id), so whether the `openclaw` delegate "
    "tool is offered with tools.openclaw.autoApproveChanges set could not be determined."
)
_U3_DETAIL = (
    "tools.openclaw.autoApproveChanges (or an agent's override) is set to a value that is "
    "not true or false, which OpenClaw's config schema rejects, so the standing delegation "
    "grant could not be determined."
)
_WARN_FIX = (
    "Set tools.openclaw.autoApproveChanges to false, and change any per-agent override "
    "(agents.entries.<id>.tools.openclaw.autoApproveChanges) that is true, so every "
    "delegated change waits for your approval. Or deny the tool (tools.deny: "
    "[\"openclaw\"]) for agents that do not need delegated setup. sandbox.mode \"all\" "
    "also removes the tool; \"non-main\" leaves each agent's main session unsandboxed. "
    "tools.fs.workspaceOnly blocks this grant only outside Full Access sessions, so do "
    "not rely on it."
)


def _f(name: str):
    return check_openclaw_auto_approve_changes(collect(FIXTURES / name))


def _ctx(cfg, tmp_path):
    return Context(home=tmp_path, config=cfg, config_found=True)


def _run(cfg, tmp_path):
    return check_openclaw_auto_approve_changes(_ctx(cfg, tmp_path))


def _grant(value):
    return {"openclaw": {"autoApproveChanges": value}}


def _warn_detail(joined: str) -> str:
    return f"tools.openclaw.autoApproveChanges is true for {joined}" + _WARN_TAIL


# ------------------------------------------------------------------ fixtures
@pytest.mark.parametrize("name", [
    "clean_b399_unset",
    "clean_b399_false",
    "clean_b399_agent_false_overrides_global",
    "clean_b399_sandbox_all",
    "clean_b399_tool_denied",
    "clean_b399_profile_coding",
    "clean_b399_only_openclaw_agent",
])
def test_clean_fixtures_pass(name):
    f = _f(name)
    assert f.status == PASS, f"{name}: expected PASS, got {f.status}: {f.detail}"
    assert f.detail == _PASS_DETAIL
    assert f.fix == (
        "No action needed. Keep tools.openclaw.autoApproveChanges unset or false unless an "
        "agent must apply OpenClaw changes unattended."
    )


@pytest.mark.parametrize("name,joined", [
    ("bad_b399_global_true", "main (global setting)"),
    ("bad_b399_agent_override_true", "ops (per-agent override)"),
    ("bad_b399_sandbox_non_main", "main (global setting)"),
    ("bad_b399_profile_coding_alsoallow", "main (global setting)"),
])
def test_bad_fixtures_warn_with_exact_detail(name, joined):
    f = _f(name)
    assert f.status == WARN, f"{name}: expected WARN, got {f.status}: {f.detail}"
    assert f.detail == _warn_detail(joined)
    assert f.fix == _WARN_FIX


def test_non_bool_fixture_is_unknown():
    f = _f("unknown_b399_non_bool")
    assert f.status == UNKNOWN, f.detail
    assert f.detail == _U3_DETAIL
    assert f.fix == (
        "Set it to true or false (false keeps delegated changes under human review), "
        "then re-run the audit."
    )


def test_agent_override_names_only_the_overriding_agent():
    f = _f("bad_b399_agent_override_true")
    assert "main" not in f.detail.split(" for ", 1)[1].split(",")[0]
    assert f.evidence == ["ops"]


def test_it_never_fails():
    for name in ("bad_b399_global_true", "bad_b399_agent_override_true",
                 "bad_b399_sandbox_non_main", "bad_b399_profile_coding_alsoallow"):
        assert _f(name).status != "FAIL", name


# ------------------------------------------------------------------ registration
def test_catalog_entry_and_registration():
    meta = BY_ID["B399"]
    assert meta.severity == HIGH
    assert meta.scored is False
    assert check_openclaw_auto_approve_changes in CHECKS


# ------------------------------------------------------------------ unknown states
def test_unreadable_config_is_unknown(tmp_path):
    f = check_openclaw_auto_approve_changes(collect(tmp_path))
    assert f.status == UNKNOWN, f.detail


def test_empty_config_is_unknown_u1(tmp_path):
    f = _run({}, tmp_path)
    assert f.status == UNKNOWN
    assert f.detail == _U1_DETAIL
    assert f.fix == "Run the audit on the host where ~/.openclaw lives."


def test_tools_openclaw_not_an_object_is_unknown_u3(tmp_path):
    f = _run({"tools": {"openclaw": True}}, tmp_path)
    assert f.status == UNKNOWN
    assert f.detail == _U3_DETAIL


def test_duplicate_normalized_ids_are_unknown_u2(tmp_path):
    cfg = {
        "tools": _grant(True),
        "agents": {"list": [{"id": "Ops"}, {"id": "ops"}]},
    }
    f = _run(cfg, tmp_path)
    assert f.status == UNKNOWN
    assert f.detail == _U2_DETAIL
    assert f.fix == (
        "Make every tools block a valid object and give each agent a distinct id, then "
        "re-run the audit."
    )


# ------------------------------------------------------------------ the three conditions
def test_denying_the_automation_group_clears_it(tmp_path):
    cfg = {"tools": {"deny": ["group:automation"], **_grant(True)}}
    assert _run(cfg, tmp_path).status == PASS


def test_denying_the_tool_by_name_clears_it(tmp_path):
    cfg = {"tools": {"deny": ["openclaw"], **_grant(True)}}
    assert _run(cfg, tmp_path).status == PASS


def test_global_true_with_no_roster_warns_as_default_agent(tmp_path):
    f = _run({"tools": _grant(True)}, tmp_path)
    assert f.status == WARN
    assert f.detail == _warn_detail("default agent (global setting)")


def test_empty_entries_with_global_true_warns_default_agent(tmp_path):
    f = _run({"tools": _grant(True), "agents": {"entries": {}}}, tmp_path)
    assert f.status == WARN
    assert f.detail == _warn_detail("default agent (global setting)")


def test_coding_profile_does_not_offer_the_tool(tmp_path):
    f = _run({"tools": {"profile": "coding", **_grant(True)}}, tmp_path)
    assert f.status == PASS


def test_per_agent_sandbox_all_overrides_defaults_off(tmp_path):
    cfg = {
        "tools": _grant(True),
        "agents": {
            "defaults": {"sandbox": {"mode": "off"}},
            "entries": {"main": {"sandbox": {"mode": "all"}}},
        },
    }
    assert _run(cfg, tmp_path).status == PASS


def test_per_agent_sandbox_off_overrides_defaults_all(tmp_path):
    cfg = {
        "tools": _grant(True),
        "agents": {
            "defaults": {"sandbox": {"mode": "all"}},
            "entries": {"main": {"sandbox": {"mode": "off"}}},
        },
    }
    f = _run(cfg, tmp_path)
    assert f.status == WARN
    assert f.detail == _warn_detail("main (global setting)")


# ------------------------------------------------------------------ resolution
def test_agent_level_null_falls_through_to_global_true(tmp_path):
    cfg = {
        "tools": _grant(True),
        "agents": {"entries": {"main": {"tools": {"openclaw": {"autoApproveChanges": None}}}}},
    }
    f = _run(cfg, tmp_path)
    assert f.status == WARN
    assert f.detail == _warn_detail("main (global setting)")


def test_agent_false_overrides_global_true(tmp_path):
    cfg = {
        "tools": _grant(True),
        "agents": {"entries": {"main": {"tools": _grant(False)}}},
    }
    assert _run(cfg, tmp_path).status == PASS


def test_agent_true_overrides_global_false(tmp_path):
    cfg = {
        "tools": _grant(False),
        "agents": {"entries": {"ops": {"tools": _grant(True)}}},
    }
    f = _run(cfg, tmp_path)
    assert f.status == WARN
    assert f.detail == _warn_detail("ops (per-agent override)")


def test_the_openclaw_agent_id_is_skipped_after_normalization(tmp_path):
    cfg = {
        "tools": _grant(True),
        "agents": {"list": [{"id": " OpenClaw "}]},
    }
    assert _run(cfg, tmp_path).status == PASS


def test_openclaw_agent_skipped_but_sibling_still_warns(tmp_path):
    cfg = {
        "tools": _grant(True),
        "agents": {"list": [{"id": " OpenClaw "}, {"id": "ops"}]},
    }
    f = _run(cfg, tmp_path)
    assert f.status == WARN
    assert f.detail == _warn_detail("ops (global setting)")


def test_legacy_agents_list_shape_warns(tmp_path):
    cfg = {"agents": {"list": [{"id": "ops", "tools": _grant(True)}]}}
    f = _run(cfg, tmp_path)
    assert f.status == WARN
    assert f.detail == _warn_detail("ops (per-agent override)")


def test_warn_beats_a_malformed_second_agent(tmp_path):
    cfg = {
        "agents": {"entries": {
            "ops": {"tools": _grant(True)},
            "qa": {"tools": {"openclaw": {"autoApproveChanges": "yes"}}},
        }},
    }
    f = _run(cfg, tmp_path)
    assert f.status == WARN
    assert f.detail == _warn_detail("ops (per-agent override)")


def test_malformed_agent_alone_is_unknown(tmp_path):
    cfg = {"agents": {"entries": {"qa": {"tools": {"openclaw": {"autoApproveChanges": 1}}}}}}
    assert _run(cfg, tmp_path).status == UNKNOWN


def test_valid_agent_value_is_not_hidden_by_a_malformed_global(tmp_path):
    cfg = {
        "tools": _grant("yes"),
        "agents": {"entries": {"main": {"tools": _grant(False)}}},
    }
    assert _run(cfg, tmp_path).status == PASS


def test_malformed_global_reaches_an_agent_with_no_own_value(tmp_path):
    cfg = {
        "tools": _grant("yes"),
        "agents": {"entries": {"main": {"tools": _grant(False)}, "ops": {}}},
    }
    assert _run(cfg, tmp_path).status == UNKNOWN


# ------------------------------------------------------------------ determinism / opaque
def test_multiple_rows_are_sorted_in_the_detail(tmp_path):
    cfg = {
        "tools": _grant(True),
        "agents": {"entries": {"zed": {}, "alpha": {"tools": _grant(True)}, "mid": {}}},
    }
    f = _run(cfg, tmp_path)
    assert f.status == WARN
    assert f.detail == _warn_detail(
        "alpha (per-agent override), mid (global setting), zed (global setting)"
    )
    assert f.evidence == ["alpha", "mid", "zed"]


def test_an_opaque_scope_is_not_skipped(tmp_path):
    cfg = {
        "tools": {**_grant(True), "byProvider": {"openai": {"deny": ["openclaw"]}}},
    }
    f = _run(cfg, tmp_path)
    assert f.status == WARN
