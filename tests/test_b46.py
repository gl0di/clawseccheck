"""B46 — multi-agent trifecta exposure (config-only, scored, capped at WARN).

Fires only on the narrow, dangerous combo: subagents/multiple agents CAN be spawned
AND all three global trifecta legs are active AND no exec approval gate exists.
"""
from pathlib import Path

from clawseccheck.checks import check_multiagent_exposure
from clawseccheck.collector import Context


def _ctx(config):
    c = Context(home=Path("/nonexistent"))
    c.config = config
    return c


# A config whose GLOBAL surface has all three trifecta legs active:
#   open DM channel        -> untrusted input
#   gateway.auth.password  -> sensitive data
#   send tool / elevated   -> outbound
def _full_trifecta():
    return {
        "channels": {"tg": {"dmPolicy": "open"}},
        "gateway": {"auth": {"password": "x"}},
        "tools": {"allow": ["send_email"]},
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


# ---- subagents but trifecta incomplete -> PASS ----
def test_b46_incomplete_trifecta_passes():
    # subagents present, but no sensitive-data leg (no password, no db tools)
    cfg = {
        "channels": {"tg": {"dmPolicy": "open"}},
        "tools": {"allow": ["send_email"]},
        "agents": {"subagents": {"maxConcurrent": 4}},
    }
    r = check_multiagent_exposure(_ctx(cfg))
    assert r.status == "PASS"


# ---- B46 is capped at WARN: it must NEVER FAIL (cannot add new FAILs on real configs) ----
def test_b46_never_fails():
    for cfg in (
        _full_trifecta(),
        {**_full_trifecta(), "agents": {"subagents": {"maxConcurrent": 4}}},
        {"agents": {"list": [{"name": "a"}, {"name": "b"}]}},
        {},
    ):
        assert check_multiagent_exposure(_ctx(cfg)).status != "FAIL"
