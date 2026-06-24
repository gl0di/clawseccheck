"""B-020: B2 gateway-exposure fix prose must name the condition that actually fired.

Previously the FAIL fix was generic boilerplate (bind/tailscale/rateLimit) — useless when
the only trigger was gateway.controlUi.allowInsecureAuth on an otherwise-loopback config.
Now the fix is assembled per-trigger, so it names the real problem.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL
from clawseccheck.checks import check_gateway
from clawseccheck.collector import Context


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


_SAFE_GATEWAY = {
    "bind": "127.0.0.1:8080",
    "auth": {"mode": "token", "token": "a-very-long-token-of-32-characters"},
}


def test_allow_insecure_auth_only_fix_is_actionable():
    cfg = {"gateway": dict(_SAFE_GATEWAY, controlUi={"allowInsecureAuth": True})}
    f = check_gateway(_ctx(cfg))
    assert f.status == FAIL
    # The fix names the ONE thing that fired...
    assert "Disable gateway.controlUi.allowInsecureAuth" in f.fix
    # ...and does NOT drag in clauses for conditions that did not fire (already-satisfied).
    assert "tailscale" not in f.fix
    assert "loopback" not in f.fix


def test_fix_lists_each_triggering_condition():
    cfg = {"gateway": {
        "bind": "0.0.0.0:8080", "auth": {"mode": "none"},
        "controlUi": {"allowInsecureAuth": True},
        "tailscale": {"mode": "funnel"},
    }}
    f = check_gateway(_ctx(cfg))
    assert f.status == FAIL
    assert "Disable gateway.controlUi.allowInsecureAuth" in f.fix
    assert "tailscale.mode" in f.fix
    assert "loopback" in f.fix  # the bind clause


def test_fix_fragments_match_evidence_count():
    # One trigger -> one fix clause (no boilerplate padding).
    cfg = {"gateway": dict(_SAFE_GATEWAY, controlUi={"allowInsecureAuth": True})}
    f = check_gateway(_ctx(cfg))
    assert len(f.fix.split("; ")) == 1
