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
    # B-283 (b) widened B68 from the applyPatch sibling alone to the whole fs family, so
    # the config must declare a tool surface for the fs leg to be determinate — a bare
    # applyPatch:true with no tools.allow/tools.profile is now (honestly) UNKNOWN, pinned
    # by test_b68_fs_grants_unenumerable_unknown below. "minimal" grants no fs tool, which
    # isolates the applyPatch leg this test is about.
    f = check_exec_applypatch_workspace(
        _ctx(
            {
                "tools": {
                    "profile": "minimal",
                    "exec": {"applyPatch": {"workspaceOnly": True}},
                }
            }
        )
    )
    assert f.status == PASS


def test_b68_fs_grants_unenumerable_unknown():
    # No tools.allow / gateway.tools.allow and no tools.profile: fs grants come from
    # OpenClaw's runtime defaults, which static config cannot resolve BY THIS CHECK'S OWN
    # allow/alsoAllow/profile model. tools.fs.workspaceOnly defaults to FALSE, so claiming
    # PASS here would be a fake clean verdict (GR#4).
    #
    # CLAWSECCHECK-B-737: this used to stop at UNKNOWN because G1 (`_b68_fs_tools_granted`)
    # is the only model this check consulted. It now falls through to `_fs_scope_grants`,
    # which resolves the same config through `toolgrant.resolved_scopes` -- no tools policy
    # is declared anywhere, so the single default-agent scope has `provenance="default"`,
    # and OpenClaw's own permissive default grants every fs tool there. UNKNOWN would now
    # be the fake-ignorance verdict, not the honest one.
    f = check_exec_applypatch_workspace(
        _ctx({"tools": {"exec": {"applyPatch": {"workspaceOnly": True}}}})
    )
    assert f.status == WARN, f.detail
    assert any("permissive default" in e or "provenance=default" in e for e in f.evidence)


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


# B-409: a per-agent tools.profile that WIDENS beyond the global one (`??`-coalesced,
# not AND-ed -- agent-tools.policy-YD9HuYgO.js:94/:232) can grant fs tools B68's grant
# model was previously blind to when the global layer alone names nothing. See
# tests/test_b55.py's B-409 section for the full grounding this shares via
# _agent_profile_widenings / _b68_fs_tools_granted.
def test_b68_agent_profile_widening_warns_with_evidence():
    f = check_exec_applypatch_workspace(
        _ctx(
            {
                "tools": {"profile": "minimal"},
                "agents": {"list": [{"id": "worker", "tools": {"profile": "coding"}}]},
            }
        )
    )
    assert f.status == WARN, f.detail
    # The evidence's real shape (never matched the tracker-id-only fallback this
    # assertion used to fall back on -- see git history if the wording moves again).
    assert any("widens beyond" in e and "tools.profile" in e for e in f.evidence)


def test_b68_agent_profile_narrowing_does_not_falsely_warn_via_widening_path():
    # Global already powerful -> _agent_profile_widenings returns [] (nothing left to
    # widen into); the pre-existing global-profile grant path alone drives the verdict,
    # unchanged by this fix.
    f = check_exec_applypatch_workspace(
        _ctx(
            {
                "tools": {"profile": "coding"},
                "agents": {"list": [{"id": "reader", "tools": {"profile": "minimal"}}]},
            }
        )
    )
    assert f.status == WARN, f.detail
    # Vacuous after the widening evidence's tracker-id suffix was dropped -- assert the
    # actual phrase is absent, not a marker that no longer appears either way.
    assert not any("widens beyond" in e for e in f.evidence)


# B-942: G1 (_b68_fs_tools_granted) used to read workspace confinement at the GLOBAL
# scope only (`dig(cfg, "tools.fs.workspaceOnly")`), even for a grant G1 itself resolved
# from a SPECIFIC per-agent scope -- so an agent that grants itself write via its own
# tools.allow (or a widening tools.profile) AND declares its own
# tools.fs.workspaceOnly=true still produced a blanket WARN, because nothing ever read
# THAT agent's own confinement declaration. `_b68_scope_confined` (shared with
# `_fs_scope_grants`'s own confinement=True test, B-737) now resolves confinement per
# scope instead, mirroring exactly what that sibling residual already did for its own
# NOT-ENUMERABLE branch.
def test_b68_per_agent_workspace_only_confines_own_scoped_grant():
    # The confirmed repro: "worker"'s own tools.allow grants write (and, via B-736's
    # write=>apply_patch implication, apply_patch) but its own tools.fs.workspaceOnly
    # confines it -- no global tools.fs.workspaceOnly, no global sandbox="all". Before
    # the fix this was a blanket WARN citing "tools.fs.workspaceOnly unset"; the field
    # is not unset for this agent, it is just declared under its own scope.
    f = check_exec_applypatch_workspace(
        _ctx(
            {
                "agents": {
                    "list": [
                        {
                            "id": "worker",
                            "tools": {"allow": ["write"], "fs": {"workspaceOnly": True}},
                        }
                    ]
                }
            }
        )
    )
    assert f.status == PASS, f.detail


def test_b68_per_agent_workspace_only_confines_widened_grant():
    # Same repro through the OTHER vector the ticket named: a per-agent tools.profile
    # WIDENING (`??`-coalesced past a non-powerful global profile) instead of a direct
    # tools.allow. "worker" grants itself the full fs family via its powerful profile
    # but also declares its own tools.fs.workspaceOnly=true.
    f = check_exec_applypatch_workspace(
        _ctx(
            {
                "tools": {"profile": "minimal"},
                "agents": {
                    "list": [
                        {
                            "id": "worker",
                            "tools": {"profile": "coding", "fs": {"workspaceOnly": True}},
                        }
                    ]
                },
            }
        )
    )
    assert f.status == PASS, f.detail


def test_b68_per_agent_own_sandbox_all_also_confines_scoped_grant():
    # The composite's OTHER confinement leg: an agent's own sandbox.mode="all" (falling
    # back to agents.defaults.sandbox.mode when absent) confines it exactly like its own
    # tools.fs.workspaceOnly=true does -- `_b68_scope_confined` reads both.
    f = check_exec_applypatch_workspace(
        _ctx(
            {
                "agents": {
                    "list": [
                        {
                            "id": "worker",
                            "tools": {"allow": ["write"]},
                            "sandbox": {"mode": "all"},
                        }
                    ]
                }
            }
        )
    )
    assert f.status == PASS, f.detail


def test_b68_per_agent_grant_without_own_confinement_still_warns():
    # Control: the identical per-agent tools.allow grant, minus the agent's own
    # tools.fs.workspaceOnly declaration -- nothing confines this scope (no global
    # tools.fs.workspaceOnly, no global or per-agent sandbox="all"), so the WARN must
    # still fire. Pins that B-942 narrows the false positive without opening a false
    # negative for the genuinely-unconfined case.
    f = check_exec_applypatch_workspace(
        _ctx({"agents": {"list": [{"id": "worker", "tools": {"allow": ["write"]}}]}})
    )
    assert f.status == WARN, f.detail
    assert any("filesystem tools granted" in e for e in f.evidence)


def test_b68_mixed_agents_one_confined_one_not_still_warns():
    # A second, genuinely unconfined agent in the SAME roster must still trigger the
    # WARN even though the first agent's own grant is individually confined -- B-942's
    # fix is per-scope, not a blanket "any confinement anywhere" downgrade.
    f = check_exec_applypatch_workspace(
        _ctx(
            {
                "agents": {
                    "list": [
                        {
                            "id": "confined",
                            "tools": {"allow": ["write"], "fs": {"workspaceOnly": True}},
                        },
                        {"id": "open", "tools": {"allow": ["write"]}},
                    ]
                }
            }
        )
    )
    assert f.status == WARN, f.detail


def test_b68_malformed_confinement_values_fail_closed():
    # C-135 follow-up: `_b68_scope_confined` must never treat a malformed/non-boolean
    # confinement value as confining -- only a LITERAL `True` (workspaceOnly) or the
    # LITERAL string `"all"` (sandbox mode) counts. A schema-invalid config could never
    # reach OpenClaw's runtime with these shapes, but a static reader has to decide
    # SOMETHING, and the fail-closed choice (still WARN) is the honest one -- silently
    # reading a truthy-looking value as confinement would manufacture a PASS the vendor
    # never actually grants. Covers a representative few of the malformed shapes
    # (string "true", non-string sandbox mode, wrong-case sandbox mode "ALL") rather
    # than every combination.
    for tools in (
        {"allow": ["write"], "fs": {"workspaceOnly": "true"}},  # string, not bool
        {"allow": ["write"], "fs": {"workspaceOnly": 1}},  # int, not bool
        {"allow": ["write"], "fs": {}},  # present but empty -- no workspaceOnly key
        {"allow": ["write"], "fs": {"workspaceOnly": None}},  # explicit null
    ):
        f = check_exec_applypatch_workspace(
            _ctx({"agents": {"list": [{"id": "worker", "tools": tools}]}})
        )
        assert f.status == WARN, (tools, f.detail)

    for sandbox_mode in (1, "ALL"):  # non-string, and wrong-case literal
        f = check_exec_applypatch_workspace(
            _ctx(
                {
                    "agents": {
                        "list": [
                            {
                                "id": "worker",
                                "tools": {"allow": ["write"]},
                                "sandbox": {"mode": sandbox_mode},
                            }
                        ]
                    }
                }
            )
        )
        assert f.status == WARN, (sandbox_mode, f.detail)


def test_b68_three_agent_mixed_confinement_warns_on_the_open_one():
    # C-135 follow-up: a THIRD roster agent, confined through the OTHER vector
    # (widening tools.profile + its own workspaceOnly), alongside the existing
    # 2-agent mixed test's direct-grant-confined agent and a genuinely open one --
    # still WARNs, because at least one scope (the open one) remains unconfined.
    # No global tools.profile is set here (deliberately): setting one to make
    # "confined_widened" a real widening would also AND-narrow "open"'s own plain
    # tools.allow grant through the SAME global profile layer, which would test a
    # different thing than "one open agent among confined ones".
    f = check_exec_applypatch_workspace(
        _ctx(
            {
                "agents": {
                    "list": [
                        {
                            "id": "confined_direct",
                            "tools": {"allow": ["write"], "fs": {"workspaceOnly": True}},
                        },
                        {
                            "id": "confined_widened",
                            "tools": {"profile": "coding", "fs": {"workspaceOnly": True}},
                        },
                        {"id": "open", "tools": {"allow": ["write"]}},
                    ]
                }
            }
        )
    )
    assert f.status == WARN, f.detail


def test_b68_three_agent_all_confined_passes():
    # The all-confined counterpart: same three-agent shape, but the third agent is now
    # ALSO confined (via its own sandbox.mode="all" this time, the third confinement
    # vector) instead of left open -- every contributing scope confines itself, so the
    # verdict is PASS.
    f = check_exec_applypatch_workspace(
        _ctx(
            {
                "agents": {
                    "list": [
                        {
                            "id": "confined_direct",
                            "tools": {"allow": ["write"], "fs": {"workspaceOnly": True}},
                        },
                        {
                            "id": "confined_widened",
                            "tools": {"profile": "coding", "fs": {"workspaceOnly": True}},
                        },
                        {
                            "id": "confined_sandbox",
                            "tools": {"allow": ["write"]},
                            "sandbox": {"mode": "all"},
                        },
                    ]
                }
            }
        )
    )
    assert f.status == PASS, f.detail


def test_b68_confine_per_agent_g1_direct_call():
    # G1 itself, confinement-aware: the SAME confined-scope repro resolves to an empty
    # grant under confine_per_agent=True (still enumerable=True -- the config WAS
    # resolvable, it just resolves to "confined, nothing left unconfined"), while the
    # default (unfiltered) call -- the one B44/B55/B84 still use -- keeps reporting the
    # raw grant, unaffected by this flag.
    from clawseccheck.checks._capability import _b68_fs_tools_granted

    cfg = {
        "agents": {
            "list": [
                {"id": "worker", "tools": {"allow": ["write"], "fs": {"workspaceOnly": True}}}
            ]
        }
    }
    assert _b68_fs_tools_granted(cfg) == (["apply_patch", "write"], True)
    assert _b68_fs_tools_granted(cfg, confine_per_agent=True) == ([], True)


def test_b68_confine_per_agent_does_not_affect_b55():
    # Requirement (c): B55 never passes confine_per_agent, so the identical
    # individually-confined-scope config must still WARN there exactly as before --
    # B55's own question (is a write tool reachable at all) is orthogonal to workspace
    # confinement, which is B68's question alone.
    from clawseccheck.checks import check_fs_write_exposure

    cfg = {
        "agents": {
            "list": [
                {"id": "worker", "tools": {"allow": ["write"], "fs": {"workspaceOnly": True}}}
            ]
        }
    }
    assert check_fs_write_exposure(_ctx(cfg)).status == WARN


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


# ---- B-130: powerful tools.profile (e.g. "coding") counts as "exec active" ----
# ---- alongside tools.exec.mode, so strictInlineEval=false + profile="coding" ----
# ---- must WARN, not be treated as exec-inactive. ----

def test_b69_false_with_coding_profile_no_exec_mode_warns():
    f = check_exec_strict_inline_eval(
        _ctx({"tools": {"profile": "coding", "exec": {"strictInlineEval": False}}})
    )
    assert f.status == WARN


def test_b69_unset_with_coding_profile_no_exec_fields_is_unknown():
    # strictInlineEval itself is still unset -> UNKNOWN regardless of profile
    # (only the "is exec active" gate changed, not the field-presence check).
    f = check_exec_strict_inline_eval(_ctx({"tools": {"profile": "coding"}}))
    assert f.status == UNKNOWN


def test_b69_minimal_profile_false_no_exec_mode_passes():
    # Regression: minimal profile + no exec.mode -> exec not active -> PASS.
    f = check_exec_strict_inline_eval(
        _ctx({"tools": {"profile": "minimal", "exec": {"strictInlineEval": False}}})
    )
    assert f.status == PASS


def test_b69_coding_profile_fixture_field_still_unset_is_unknown():
    # bad_b130_coding_profile_no_exec_fields has no tools.exec.strictInlineEval at
    # all (that fixture targets B4/B8/B22, not B69) -> the field-presence check
    # (untouched by this fix) still returns UNKNOWN.
    assert check_exec_strict_inline_eval(
        collect(FIXTURES / "bad_b130_coding_profile_no_exec_fields")
    ).status == UNKNOWN


def test_b69_fixture_coding_profile_strict_inline_eval_false_warns():
    assert check_exec_strict_inline_eval(
        collect(FIXTURES / "bad_b130_coding_profile_strict_inline_eval")
    ).status == WARN


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
