"""B-020: B2 gateway-exposure fix prose must name the condition that actually fired.

Previously the FAIL fix was generic boilerplate (bind/tailscale/rateLimit) — useless when
the only trigger was gateway.controlUi.allowInsecureAuth on an otherwise-loopback config.
Now the fix is assembled per-trigger, so it names the real problem.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
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


# B2 returns UNKNOWN only when no config was loaded at all (empty dict).
def test_b02_empty_config_unknown():
    assert check_gateway(_ctx({})).status == UNKNOWN


def test_allow_insecure_auth_only_fix_is_actionable():
    cfg = {"gateway": dict(_SAFE_GATEWAY, controlUi={"allowInsecureAuth": True})}
    f = check_gateway(_ctx(cfg))
    assert f.status == WARN
    # The fix names the ONE thing that fired...
    assert "Disable gateway.controlUi.allowInsecureAuth" in f.fix
    # ...and does NOT drag in clauses for conditions that did not fire (already-satisfied).
    assert "tailscale" not in f.fix
    assert "loopback" not in f.fix


def test_allow_insecure_auth_alone_is_warn():
    """allowInsecureAuth alone (otherwise safe gateway) yields WARN, not FAIL."""
    cfg = {"gateway": dict(_SAFE_GATEWAY, controlUi={"allowInsecureAuth": True})}
    f = check_gateway(_ctx(cfg))
    assert f.status == WARN


def test_allow_insecure_auth_combined_with_open_channel_is_fail():
    """allowInsecureAuth + open channel together escalate to FAIL."""
    cfg = {
        "gateway": dict(_SAFE_GATEWAY, controlUi={"allowInsecureAuth": True}),
        "channels": {"telegram": {"dmPolicy": "open"}},
    }
    f = check_gateway(_ctx(cfg))
    assert f.status == FAIL
    assert "allowInsecureAuth" in f.fix
    assert "allowlist" in f.fix


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


# ---------------------------------------------------------------------------
# C-182 — a present-but-malformed `gateway` value must read UNKNOWN, never a
# fabricated PASS. `if not cfg:` only catches a whole-config-empty state; a
# malformed non-dict `gateway` value with other config present used to fall
# through every dig() lookup (which silently degrades to "absent" on a
# non-dict path segment) all the way to a confident PASS.
# ---------------------------------------------------------------------------

def test_b182_null_gateway_is_unknown_not_pass():
    f = check_gateway(_ctx({"gateway": None}))
    assert f.status == UNKNOWN


def test_b182_string_gateway_is_unknown_not_pass():
    f = check_gateway(_ctx({"gateway": "not-an-object"}))
    assert f.status == UNKNOWN


def test_b182_list_gateway_is_unknown_not_pass():
    f = check_gateway(_ctx({"gateway": [1, 2, 3]}))
    assert f.status == UNKNOWN


def test_b182_number_gateway_is_unknown_not_pass():
    f = check_gateway(_ctx({"gateway": 42}))
    assert f.status == UNKNOWN


def test_b182_malformed_gateway_alongside_other_config_still_unknown():
    """Regression guard for the exact repro: a non-empty config (other fields
    present) with a malformed gateway value must not fall through to PASS via
    the `if not cfg:` whole-config-empty escape hatch."""
    f = check_gateway(_ctx({"gateway": None, "tools": ["x"], "mcp": {"servers": {}}}))
    assert f.status == UNKNOWN


def test_b182_absent_gateway_key_still_passes():
    """Regression guard: no `gateway` key at all is a legitimately clean PASS
    (distinct from a malformed-but-present key), not swept into UNKNOWN."""
    f = check_gateway(_ctx({"tools": ["x"]}))
    assert f.status == PASS


def test_b182_well_formed_gateway_still_passes():
    f = check_gateway(_ctx({"gateway": dict(_SAFE_GATEWAY)}))
    assert f.status == PASS


def test_b182_well_formed_insecure_gateway_still_fails():
    """Regression guard: the malformed-shape guard must not swallow a real,
    well-formed-but-insecure gateway FAIL."""
    cfg = {"gateway": {"bind": "0.0.0.0:8080", "auth": {"mode": "none"}}}
    f = check_gateway(_ctx(cfg))
    assert f.status == FAIL
