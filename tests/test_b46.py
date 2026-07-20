"""B46 — multi-agent trifecta exposure (config-only, scored, capped at WARN).

Fires when multi-agent/subagent topology combines with broad open-channel exposure and
insufficient approval gating, including a dedicated sub-case for elevated-sender
allowFrom without the full sensitive-leg being present.
"""
from pathlib import Path

from clawseccheck.checks import check_multiagent_exposure
from clawseccheck.collector import Context


def _ctx(config):
    c = Context(home=Path("/nonexistent"))
    c.config = config
    return c


# A config whose GLOBAL surface has all three trifecta legs active:
#   open DM channel  -> untrusted input
#   fs_read tool     -> sensitive data (agent-readable private data)
#   send tool        -> outbound
# (gateway.auth.password is a B1 plaintext-secret signal, NOT an A1 sensitive-data leg.)
def _full_trifecta():
    return {
        "channels": {"tg": {"dmPolicy": "open"}},
        "tools": {"allow": ["fs_read", "send_email"]},
    }


# ---- no multi-agent topology -> UNKNOWN ----
def test_b46_no_subagents_unknown():
    r = check_multiagent_exposure(_ctx(_full_trifecta()))
    assert r.id == "B46"
    assert r.status == "UNKNOWN"


# ---- subagents + full trifecta + no gate -> WARN (scored) ----
def test_b46_subagents_trifecta_no_gate_warns():
    cfg = _full_trifecta()
    cfg["agents"] = {"subagents": {"maxConcurrent": 4}}
    r = check_multiagent_exposure(_ctx(cfg))
    assert r.status == "WARN"
    assert r.scored is True


def test_b46_fires_on_agents_list_topology():
    cfg = _full_trifecta()
    cfg["agents"] = {"list": [{"name": "a"}, {"name": "b"}]}  # >1 implies delegation
    r = check_multiagent_exposure(_ctx(cfg))
    assert r.status == "WARN"


# ---- approval gate present -> PASS ----
def test_b46_gate_present_passes():
    cfg = _full_trifecta()
    cfg["agents"] = {"subagents": {"maxConcurrent": 4}}
    cfg["tools"] = {"allow": ["send_email"], "exec": {"mode": "ask"}}
    r = check_multiagent_exposure(_ctx(cfg))
    assert r.status == "PASS"


# ---- subagents but trifecta incomplete + elevated sender delegation -> WARN ----
def test_b46_incomplete_trifecta_passes():
    # subagents present, but no sensitive-data leg (no password, no db tools)
    cfg = {
        "channels": {"tg": {"dmPolicy": "open"}},
        "tools": {"allow": ["send_email"]},
        "agents": {"subagents": {"maxConcurrent": 4}},
    }
    r = check_multiagent_exposure(_ctx(cfg))
    assert r.status == "PASS"


def test_b46_elevated_only_triggers_warn_for_open_channel():
    cfg = {
        "channels": {"tg": {"dmPolicy": "open"}},
        "tools": {"allow": ["send_email"], "elevated": {"allowFrom": ["owner-111"]}},
        "agents": {"subagents": {"maxConcurrent": 4}},
    }
    r = check_multiagent_exposure(_ctx(cfg))
    assert r.status == "WARN"


# ---- partial-trifecta branch counts allowlist/paired ingress, not just open (B-057) ----
# An allowlist/paired channel is untrusted ingress (authenticated sender != trusted
# content), consistent with the trifecta input leg in _trifecta_legs(). This branch
# previously used _open_channels and silently PASSed an allowlist+elevated+subagents config.
def test_b46_allowlist_channel_with_elevated_warns():
    cfg = {
        "channels": {"tg": {"dmPolicy": "allowlist"}},  # untrusted ingress, NOT open
        "tools": {"allow": ["send_email"], "elevated": {"allowFrom": ["owner-111"]}},
        "agents": {"subagents": {"maxConcurrent": 4}},
    }
    r = check_multiagent_exposure(_ctx(cfg))
    assert r.status == "WARN"
    assert r.scored is True


def test_b46_paired_channel_with_elevated_warns():
    cfg = {
        "channels": {"tg": {"dmPolicy": "pairing"}},  # pairing is still external ingress
        "tools": {"allow": ["send_email"], "elevated": {"allowFrom": ["owner-111"]}},
        "agents": {"subagents": {"maxConcurrent": 4}},
    }
    assert check_multiagent_exposure(_ctx(cfg)).status == "WARN"


# clean control: the partial branch only fires WITH elevated sender scope — an allowlist
# channel + subagents but no elevated.allowFrom must stay PASS (the fix is not over-wide).
def test_b46_allowlist_channel_without_elevated_passes():
    cfg = {
        "channels": {"tg": {"dmPolicy": "allowlist"}},
        "tools": {"allow": ["send_email"]},  # no elevated.allowFrom
        "agents": {"subagents": {"maxConcurrent": 4}},
    }
    assert check_multiagent_exposure(_ctx(cfg)).status == "PASS"


# boundary: an owner-only channel is NOT external ingress, so the branch must not fire
# even with elevated sender scope (proves "external" means non-owner, not "any channel").
def test_b46_owner_only_channel_with_elevated_passes():
    cfg = {
        "channels": {"tg": {"dmPolicy": "owner"}},  # excluded from untrusted ingress
        "tools": {"allow": ["send_email"], "elevated": {"allowFrom": ["owner-111"]}},
        "agents": {"subagents": {"maxConcurrent": 4}},
    }
    assert check_multiagent_exposure(_ctx(cfg)).status == "PASS"


# ---- B46 is capped at WARN: it must NEVER FAIL (cannot add new FAILs on real configs) ----
def test_b46_never_fails():
    for cfg in (
        _full_trifecta(),
        {**_full_trifecta(), "agents": {"subagents": {"maxConcurrent": 4}}},
        {"agents": {"list": [{"name": "a"}, {"name": "b"}]}},
        {},
    ):
        assert check_multiagent_exposure(_ctx(cfg)).status != "FAIL"
