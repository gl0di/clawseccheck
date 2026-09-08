"""B-666 — an OFF "sensitive data" leg must not be reported as a leg that is KNOWN off.

A1 already hedges an OFF input/outbound leg (`runtime_unknown`, B-033) and an ingress
policy the config never wrote (B-499). The third leg had no such hedge, so a config that
simply never named a data tool got a confidently-worded PASS — even though BOTH config
layers that decide whether a file-read tool can leave the workspace default to the
permissive end, so on such a config the agent really can read openclaw.json and the
credential store.

The hedge is deliberately a WARN and NOT a fourth source of the leg. Promoting it to a
leg was measured across 581 local corpus homes: 18 new CRITICAL FAILs, six of them on
`clean_*` fixtures. `test_the_hedge_never_moves_a_verdict_to_fail` is what keeps that
decision from being quietly reversed.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from clawseccheck.checks import _config, run_all
from clawseccheck.collector import Context

_SENTENCE = "Cannot determine from config: sensitive data."

# Two legs active (open channel + web fetch), no data tool named anywhere.
TWO_LEGS = {
    "channels": {"telegram": {"dmPolicy": "open"}},
    "tools": {"web": {"fetch": {"enabled": True}}},
}


def _a1(cfg, home="/nonexistent", attestation=None):
    ctx = Context(home=Path(home))
    ctx.config = cfg
    if attestation:
        ctx.attestation = attestation
    return {x.id: x for x in run_all(ctx)}["A1"]


def _merged(*layers):
    out = json.loads(json.dumps(TWO_LEGS))
    for layer in layers:
        for key, value in layer.items():
            if isinstance(value, dict) and isinstance(out.get(key), dict):
                out[key] = {**out[key], **value}
            else:
                out[key] = value
    return out


# ------------------------------------------------------------------------ it fires

def test_an_unconfined_read_tool_hedges_the_off_leg():
    a1 = _a1(TWO_LEGS)
    assert a1.status == "WARN"
    assert _SENTENCE in a1.detail
    assert "global" in a1.detail
    assert "tools.fs.workspaceOnly" in a1.fix


def test_the_hedge_names_an_exposed_agent_scope():
    cfg = _merged({"tools": {"fs": {"workspaceOnly": True}},
                   "agents": {"list": [{"id": "helper",
                                        "tools": {"fs": {"workspaceOnly": False}}}]}})
    a1 = _a1(cfg)
    assert _SENTENCE in a1.detail
    assert "agent 'helper'" in a1.detail


# ----------------------------------------------------------------------- it stays quiet

def test_workspace_confinement_clears_the_hedge():
    a1 = _a1(_merged({"tools": {"fs": {"workspaceOnly": True}}}))
    assert _SENTENCE not in a1.detail


def test_a_profile_without_a_read_tool_clears_the_hedge():
    for profile in ("minimal", "messaging"):
        a1 = _a1(_merged({"tools": {"profile": profile}}))
        assert _SENTENCE not in a1.detail, profile


def test_a_restrictive_allowlist_clears_the_hedge():
    a1 = _a1(_merged({"tools": {"allow": ["message"]}}))
    assert _SENTENCE not in a1.detail


def test_an_attestation_clears_the_hedge():
    """A declaration of the agent's real tool inventory is the one thing that resolves a
    leg the config left undeclared — the same reasoning as the B-033 thin-surface WARN."""
    a1 = _a1(TWO_LEGS, attestation={"agents": [{"name": "bot", "tools": ["chat"]}]})
    assert _SENTENCE not in a1.detail


def test_a_powerful_profile_with_gated_exec_does_not_clear_the_hedge():
    """The real-world shape this bug was found on: `profile: coding` grants the `read`
    tool, and `tools.exec.mode: "ask"` gates only EXEC — so the sensitive leg is off and
    the agent can still read every file in the home.

    Also the reason the hedge is gated on the attestation alone: `_meaningful_tool_surface`
    (which silences the B-033 thin-surface WARN) counts a powerful profile as a visible
    capability surface, so reusing it here would switch the hedge off exactly where the
    exposure is most certain.
    """
    a1 = _a1(_merged({"tools": {"profile": "coding", "exec": {"mode": "ask"}}}))
    assert "sensitive data" not in (a1.evidence or [])
    assert _SENTENCE in a1.detail


def test_a_fully_sandboxed_agent_clears_the_hedge():
    """`sandbox.mode: "all"` mounts the workspace dirs and the read-only skill overlays
    into the container and nothing else — the OpenClaw home is never mounted, so a granted
    `read` tool cannot open openclaw.json however permissive the tool policy is. Claiming
    it could is a false alarm; found by an adversarial pass over the 24 configs this hedge
    newly WARNs on, one of which (fixtures/bad_b175_workshop_sandboxed_warn) is sandboxed.
    """
    a1 = _a1(_merged({"agents": {"defaults": {"sandbox": {"mode": "all"}}}}))
    assert _SENTENCE not in a1.detail


def test_non_main_sandboxing_does_not_clear_the_hedge_for_the_main_agent():
    """"non-main" leaves the main agent unsandboxed, so the exposure is still real —
    and the main agent is the one the config declares by default."""
    a1 = _a1(_merged({"agents": {"defaults": {"sandbox": {"mode": "non-main"}}}}))
    assert _SENTENCE in a1.detail


def test_a_sandbox_mode_openclaw_does_not_recognize_clears_nothing():
    """AgentSandboxSchema is off | non-main | all. An unrecognized literal confines
    nothing, so it must not be read as containment."""
    a1 = _a1(_merged({"agents": {"defaults": {"sandbox": {"mode": "on"}}}}))
    assert _SENTENCE in a1.detail


# ------------------------------------------------------------- it cannot raise a verdict

def test_the_hedge_never_moves_a_verdict_to_fail():
    a1 = _a1(TWO_LEGS)
    assert a1.status == "WARN"
    assert sorted(a1.evidence) == ["outbound actions", "untrusted input"]
    assert "Active legs 2/3" in a1.detail


def test_a_real_three_leg_config_still_fails():
    """The hedge runs only when the leg is off; it must never soften a genuine FAIL."""
    cfg = _merged({"tools": {"allow": ["fs_read", "web", "webhook"]}})
    a1 = _a1(cfg)
    assert a1.status == "FAIL"
    assert _SENTENCE not in a1.detail


# ------------------------------------------------------------------------- the wiring

def test_a1_actually_consults_the_reach_predicate(monkeypatch):
    """Mutate the CALL SITE, not the helper: with the predicate answering "nothing is
    exposed", the WARN must disappear. A test that only exercised toolpolicy.py would
    still pass with this branch deleted."""
    monkeypatch.setattr(_config, "scopes_reaching_outside_workspace", lambda cfg: [])
    a1 = _a1(TWO_LEGS)
    assert _SENTENCE not in a1.detail

    monkeypatch.setattr(_config, "scopes_reaching_outside_workspace", lambda cfg: ["global"])
    confined = _a1(_merged({"tools": {"fs": {"workspaceOnly": True}}}))
    assert _SENTENCE in confined.detail


def test_an_unreadable_credential_store_also_hedges(tmp_path):
    """Reach and store-incompleteness are independent reasons; either one hedges."""
    home = tmp_path / "home"
    blocked = home / "credentials" / "nested"
    blocked.mkdir(parents=True)
    (blocked / "x.json").write_text("{}")
    os.chmod(blocked, 0o000)
    try:
        cfg = _merged({"tools": {"fs": {"workspaceOnly": True}}})
        a1 = _a1(cfg, home=str(home))
        assert _SENTENCE in a1.detail
        assert "could not be read in full" in a1.detail
    finally:
        os.chmod(blocked, 0o700)
