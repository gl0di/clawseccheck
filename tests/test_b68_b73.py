"""B68–B73: six advisory WARN-only config-fact checks.

Grounded fields (docs.openclaw.ai):
  B68 tools.exec.applyPatch.workspaceOnly   — false = apply_patch writes outside workspace
  B69 tools.exec.strictInlineEval           — false + exec enabled = inline eval ungated
  B70 gateway.auth.trustedProxy.allowLoopback — true + non-loopback bind = header-spoof surface
  B71 gateway.nodes.denyCommands             — non-exact entries are silently ineffective
  B72 agents.defaults.subagents.allowAgents  — "*" = any agent is a spawn target
  B73 discovery.mdns.mode                   — "full" + non-loopback bind = broad advertisement

All are scored=False (never move the A–F grade).
WARN only on the explicit dangerous value; default/absent → UNKNOWN or PASS.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import re
from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    check_exec_applypatch_workspace,
    check_exec_strict_inline_eval,
    check_trustedproxy_loopback,
    check_node_denycommands_ineffective,
    check_subagents_allow_agents,
    check_discovery_mdns_mode,
)
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
_HEBREW = re.compile(r"[֐-׿]")


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


# ---------------------------------------------------------------------------
# B68 — apply_patch workspace-only restriction
# ---------------------------------------------------------------------------

def test_b68_false_warns():
    f = check_exec_applypatch_workspace(
        _ctx({"tools": {"exec": {"applyPatch": {"workspaceOnly": False}}}})
    )
    assert f.status == WARN
    assert any("workspaceOnly" in e for e in f.evidence)


def test_b68_true_passes():
    f = check_exec_applypatch_workspace(
        _ctx({"tools": {"exec": {"applyPatch": {"workspaceOnly": True}}}})
    )
    assert f.status == PASS


def test_b68_unset_passes():
    # Default is safe (true); unset → PASS
    f = check_exec_applypatch_workspace(_ctx({"tools": {"profile": "minimal"}}))
    assert f.status == PASS



def test_b68_bad_fixture_warns():
    assert check_exec_applypatch_workspace(
        collect(FIXTURES / "bad_b68_applypatch_workspace")
    ).status == WARN


def test_b68_clean_fixture_passes():
    assert check_exec_applypatch_workspace(
        collect(FIXTURES / "clean_b68_applypatch_workspace")
    ).status == PASS


# ---------------------------------------------------------------------------
# B69 — exec inline-eval gate
# ---------------------------------------------------------------------------

def test_b69_false_with_exec_enabled_warns():
    f = check_exec_strict_inline_eval(
        _ctx({"tools": {"exec": {"mode": "ask", "strictInlineEval": False}}})
    )
    assert f.status == WARN
    assert any("strictInlineEval" in e for e in f.evidence)


def test_b69_true_passes():
    f = check_exec_strict_inline_eval(
        _ctx({"tools": {"exec": {"mode": "ask", "strictInlineEval": True}}})
    )
    assert f.status == PASS


def test_b69_false_with_exec_deny_passes():
    # exec mode deny → eval gate irrelevant
    f = check_exec_strict_inline_eval(
        _ctx({"tools": {"exec": {"mode": "deny", "strictInlineEval": False}}})
    )
    assert f.status == PASS


def test_b69_false_with_exec_absent_passes():
    # exec mode absent → eval gate irrelevant
    f = check_exec_strict_inline_eval(
        _ctx({"tools": {"exec": {"strictInlineEval": False}}})
    )
    assert f.status == PASS


def test_b69_unset_is_unknown():
    f = check_exec_strict_inline_eval(_ctx({"tools": {"profile": "minimal"}}))
    assert f.status == UNKNOWN



def test_b69_bad_fixture_warns():
    assert check_exec_strict_inline_eval(
        collect(FIXTURES / "bad_b69_strict_inline_eval")
    ).status == WARN


def test_b69_clean_fixture_passes():
    assert check_exec_strict_inline_eval(
        collect(FIXTURES / "clean_b69_strict_inline_eval")
    ).status == PASS


# ---------------------------------------------------------------------------
# B70 — trustedProxy allowLoopback on non-loopback bind
# ---------------------------------------------------------------------------

def test_b70_true_nonloopback_warns():
    f = check_trustedproxy_loopback(
        _ctx({"gateway": {"bind": "0.0.0.0:8080",
                          "auth": {"trustedProxy": {"allowLoopback": True}}}})
    )
    assert f.status == WARN
    assert any("allowLoopback" in e for e in f.evidence)


def test_b70_true_loopback_passes():
    f = check_trustedproxy_loopback(
        _ctx({"gateway": {"bind": "127.0.0.1:8080",
                          "auth": {"trustedProxy": {"allowLoopback": True}}}})
    )
    assert f.status == PASS


def test_b70_true_bind_unset_passes():
    # Unset bind treated as loopback — no WARN (zero-FP)
    f = check_trustedproxy_loopback(
        _ctx({"gateway": {"auth": {"trustedProxy": {"allowLoopback": True}}}})
    )
    assert f.status == PASS


def test_b70_unset_is_unknown():
    f = check_trustedproxy_loopback(_ctx({"gateway": {"bind": "0.0.0.0:8080"}}))
    assert f.status == UNKNOWN



def test_b70_bad_fixture_warns():
    assert check_trustedproxy_loopback(
        collect(FIXTURES / "bad_b70_trustedproxy_loopback")
    ).status == WARN


def test_b70_clean_fixture_passes():
    assert check_trustedproxy_loopback(
        collect(FIXTURES / "clean_b70_trustedproxy_loopback")
    ).status == PASS


# ---------------------------------------------------------------------------
# B71 — gateway.nodes.denyCommands ineffective patterns
# ---------------------------------------------------------------------------

def test_b71_space_in_entry_warns():
    f = check_node_denycommands_ineffective(
        _ctx({"gateway": {"nodes": {"denyCommands": ["system.run --foo"]}}})
    )
    assert f.status == WARN
    assert any("system.run --foo" in e for e in f.evidence)


def test_b71_glob_in_entry_warns():
    f = check_node_denycommands_ineffective(
        _ctx({"gateway": {"nodes": {"denyCommands": ["system*"]}}})
    )
    assert f.status == WARN


def test_b71_pipe_in_entry_warns():
    f = check_node_denycommands_ineffective(
        _ctx({"gateway": {"nodes": {"denyCommands": ["system.run|other"]}}})
    )
    assert f.status == WARN


def test_b71_exact_name_passes():
    f = check_node_denycommands_ineffective(
        _ctx({"gateway": {"nodes": {"denyCommands": ["system.run"]}}})
    )
    assert f.status == PASS


def test_b71_multiple_exact_names_passes():
    f = check_node_denycommands_ineffective(
        _ctx({"gateway": {"nodes": {"denyCommands": ["system.run", "files.write"]}}})
    )
    assert f.status == PASS


def test_b71_absent_is_unknown():
    f = check_node_denycommands_ineffective(_ctx({"gateway": {}}))
    assert f.status == UNKNOWN


def test_b71_empty_list_is_unknown():
    f = check_node_denycommands_ineffective(
        _ctx({"gateway": {"nodes": {"denyCommands": []}}})
    )
    assert f.status == UNKNOWN



def test_b71_bad_fixture_warns():
    assert check_node_denycommands_ineffective(
        collect(FIXTURES / "bad_b71_denycommands_ineffective")
    ).status == WARN


def test_b71_clean_fixture_passes():
    assert check_node_denycommands_ineffective(
        collect(FIXTURES / "clean_b71_denycommands_effective")
    ).status == PASS


# ---------------------------------------------------------------------------
# B72 — subagents.allowAgents wildcard
# ---------------------------------------------------------------------------

def test_b72_wildcard_defaults_warns():
    f = check_subagents_allow_agents(
        _ctx({"agents": {"defaults": {"subagents": {"allowAgents": ["*"]}}}})
    )
    assert f.status == WARN
    assert any("defaults" in e for e in f.evidence)


def test_b72_wildcard_per_agent_warns():
    cfg = {
        "agents": {
            "list": [
                {"name": "builder", "subagents": {"allowAgents": ["*"]}}
            ]
        }
    }
    f = check_subagents_allow_agents(_ctx(cfg))
    assert f.status == WARN
    assert any("builder" in e for e in f.evidence)


def test_b72_explicit_list_passes():
    f = check_subagents_allow_agents(
        _ctx({"agents": {"defaults": {"subagents": {"allowAgents": ["builder", "reviewer"]}}}})
    )
    assert f.status == PASS


def test_b72_unset_is_unknown():
    f = check_subagents_allow_agents(_ctx({"tools": {"profile": "minimal"}}))
    assert f.status == UNKNOWN



def test_b72_bad_fixture_warns():
    assert check_subagents_allow_agents(
        collect(FIXTURES / "bad_b72_subagents_wildcard")
    ).status == WARN


def test_b72_clean_fixture_passes():
    assert check_subagents_allow_agents(
        collect(FIXTURES / "clean_b72_subagents_explicit")
    ).status == PASS


# ---------------------------------------------------------------------------
# B73 — mDNS full advertisement on non-loopback bind
# ---------------------------------------------------------------------------

def test_b73_full_nonloopback_warns():
    f = check_discovery_mdns_mode(
        _ctx({"gateway": {"bind": "0.0.0.0:8080"},
              "discovery": {"mdns": {"mode": "full"}}})
    )
    assert f.status == WARN
    assert any("full" in e for e in f.evidence)


def test_b73_full_loopback_passes():
    f = check_discovery_mdns_mode(
        _ctx({"gateway": {"bind": "127.0.0.1:8080"},
              "discovery": {"mdns": {"mode": "full"}}})
    )
    assert f.status == PASS


def test_b73_minimal_passes():
    f = check_discovery_mdns_mode(
        _ctx({"gateway": {"bind": "0.0.0.0:8080"},
              "discovery": {"mdns": {"mode": "minimal"}}})
    )
    assert f.status == PASS


def test_b73_off_passes():
    f = check_discovery_mdns_mode(
        _ctx({"gateway": {"bind": "0.0.0.0:8080"},
              "discovery": {"mdns": {"mode": "off"}}})
    )
    assert f.status == PASS


def test_b73_unset_passes():
    # Default is "minimal" — PASS
    f = check_discovery_mdns_mode(_ctx({"gateway": {"bind": "0.0.0.0:8080"}}))
    assert f.status == PASS



def test_b73_bad_fixture_warns():
    assert check_discovery_mdns_mode(
        collect(FIXTURES / "bad_b73_mdns_full")
    ).status == WARN


def test_b73_clean_fixture_passes():
    assert check_discovery_mdns_mode(
        collect(FIXTURES / "clean_b73_mdns_minimal")
    ).status == PASS


# ---------------------------------------------------------------------------
# All 6 checks are registered and fire in a full audit
# ---------------------------------------------------------------------------

def test_all_six_registered_in_audit():
    from clawseccheck import audit
    # bad_b72 is a clean otherwise-loopback fixture that triggers B72 WARN only
    _, findings, _ = audit(FIXTURES / "bad_b72_subagents_wildcard", include_native=False)
    ids = {f.id for f in findings}
    expected = {"B68", "B69", "B70", "B71", "B72", "B73"}
    assert expected <= ids, f"Not all B68–B73 in audit findings: {sorted(ids)}"
