"""B-529 — B50-B54/B101 must not excuse a real host gap using an unreadable config.

`_agent_is_powerful(ctx)` (clawseccheck/checks/_shared.py) is read entirely out of
ctx.config: `_enabled_tools(cfg)` and `_external_input_channels(cfg)` are both pure
`dig(cfg, ...)` reads with no attestation/host fallback (verified in-source; see
clawseccheck/checks/_shared.py around _enabled_tools/_external_input_channels). On a
config the collector positively found and positively failed to parse
(ctx.config_parse_error is True), the collector leaves ctx.config == {} (never
reassigned past collector.py's `config: dict = field(default_factory=dict)` on the
failure path) — so every dig() inside _agent_is_powerful returns None, tools == [],
and the helper answers False as a pure artifact of the file being unreadable, not
because the agent is genuinely low-privilege.

_host_finding's absent-class terminal branch (B50/B51/B52/B53/B54) and
check_host_egress_posture's default-allow terminal branch (B101) both used that False
to emit an affirmative "this agent is low-privilege, so it's less critical" PASS on
top of a real, independently-detected host gap (no IDS/audit/FIM/EDR/firewall, or a
confirmed default-allow egress policy). The fix guards only that exculpatory PASS with
_config_unreadable(cid, ctx), placed immediately before it (same idiom as B1/B11 in
_config.py) so the host-scan WARN branch above it is untouched.

The trap: a bare parse-error ctx with no host scan already returns UNKNOWN earlier
(no host / host not supported), which would pass green with or without this fix. Every
UNKNOWN-path test here supplies a host scan that reaches the terminal "absent"/
"default-allow" branch, so the assertion actually exercises the guard.

Offline, stdlib only, no Path.home() (STD-04 / B-519 isolation guard).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    check_host_audit,               # B51
    check_host_edr,                 # B53
    check_host_egress_posture,      # B101
    check_host_file_integrity,      # B52
    check_host_firewall,            # B54
    check_host_network_ids,         # B50
)
from clawseccheck.collector import Context

# check fn -> (finding id, host class key)
_HOST_FINDING_CHECKS = [
    (check_host_network_ids, "B50", "network_ids"),
    (check_host_audit, "B51", "host_audit"),
    (check_host_file_integrity, "B52", "file_integrity"),
    (check_host_edr, "B53", "edr_av"),
    (check_host_firewall, "B54", "firewall"),
]


def _ctx(*, config_parse_error, host, config=None, config_found=True):
    c = Context(home=Path("/nonexistent"))
    c.config = {} if config is None else config
    c.config_found = config_found
    c.config_parse_error = config_parse_error
    c.host = host
    return c


def _host_absent(cls: str):
    """A host scan that reached the terminal 'absent' branch for exactly one class."""
    return {
        "system": "Linux",
        "supported": True,
        "classes": {cls: {"status": "absent", "found": [], "active": None}},
    }


def _host_egress(active):
    return {
        "system": "Linux",
        "supported": True,
        "classes": {"egress_posture": {"status": "present", "found": ["x"], "active": active,
                                        "evidence": ["x"]}},
    }


# ---------------------------------------------------------------------------
# B50-B54: unreadable config + a host scan that reached "absent" -> UNKNOWN,
# never the "low-privilege" PASS.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("check_fn,cid,cls", _HOST_FINDING_CHECKS, ids=[c[1] for c in _HOST_FINDING_CHECKS])
def test_absent_class_unreadable_config_is_unknown_not_exculpatory_pass(check_fn, cid, cls):
    ctx = _ctx(config_parse_error=True, host=_host_absent(cls))
    finding = check_fn(ctx)
    assert finding.status == UNKNOWN, (
        f"{cid} returned {finding.status!r} on an unreadable config with a real host "
        f"gap — must be UNKNOWN, not a fabricated PASS/FAIL (detail: {finding.detail!r})"
    )
    assert finding.engine_degraded is True
    assert "low-privilege" not in finding.detail


def test_egress_default_allow_unreadable_config_is_unknown_not_exculpatory_pass():
    ctx = _ctx(config_parse_error=True, host=_host_egress(active=False))
    finding = check_host_egress_posture(ctx)
    assert finding.status == UNKNOWN, (
        f"B101 returned {finding.status!r} on an unreadable config with a confirmed "
        f"default-allow egress posture — must be UNKNOWN (detail: {finding.detail!r})"
    )
    assert finding.engine_degraded is True
    assert "low-privilege" not in finding.detail


# ---------------------------------------------------------------------------
# Quiet-case controls — the guard must be a strict no-op whenever the config
# genuinely parsed (or genuinely doesn't exist), so today's verdicts survive.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("check_fn,cid,cls", _HOST_FINDING_CHECKS, ids=[c[1] for c in _HOST_FINDING_CHECKS])
def test_absent_class_readable_weak_config_still_passes(check_fn, cid, cls):
    """A REAL low-privilege config (parsed fine, just declares nothing) must keep
    today's exculpatory PASS — the guard only fires on an actual parse/read failure."""
    ctx = _ctx(config_parse_error=False, host=_host_absent(cls), config={"tools": {}})
    finding = check_fn(ctx)
    assert finding.status == PASS
    assert "low-privilege" in finding.detail


@pytest.mark.parametrize("check_fn,cid,cls", _HOST_FINDING_CHECKS, ids=[c[1] for c in _HOST_FINDING_CHECKS])
def test_absent_class_readable_powerful_config_still_warns(check_fn, cid, cls):
    """A REAL high-privilege config (parsed fine) must keep today's WARN — that branch
    sits above the guard and never touches it."""
    powerful = {"tools": {"exec": {"mode": "auto"}},
                "channels": {"telegram": {"dmPolicy": "open"}}}
    ctx = _ctx(config_parse_error=False, host=_host_absent(cls), config=powerful)
    finding = check_fn(ctx)
    assert finding.status == WARN


def test_egress_default_allow_readable_weak_config_still_passes():
    ctx = _ctx(config_parse_error=False, host=_host_egress(active=False), config={"tools": {}})
    finding = check_host_egress_posture(ctx)
    assert finding.status == PASS
    assert "low-privilege" in finding.detail


def test_egress_default_allow_readable_powerful_config_still_warns():
    powerful = {"tools": {"exec": {"mode": "auto"}},
                "channels": {"telegram": {"dmPolicy": "open"}}}
    ctx = _ctx(config_parse_error=False, host=_host_egress(active=False), config=powerful)
    finding = check_host_egress_posture(ctx)
    assert finding.status == WARN


def test_no_openclaw_json_at_all_mirrors_false_negative_stays_pass():
    """Mirror of _surface_absent's documented false-negative case (_shared.py): on a
    plain non-OpenClaw machine config_found is False and config_parse_error is False
    even though ctx.config == {} — the guard must stay a strict no-op here too, exactly
    as it does for a genuinely empty, successfully-parsed config."""
    ctx = _ctx(config_parse_error=False, host=_host_absent("network_ids"), config_found=False)
    finding = check_host_network_ids(ctx)
    assert finding.status == PASS
    assert "low-privilege" in finding.detail


def test_unsupported_host_still_unknown_regardless_of_config_state():
    """The pre-existing 'no host scan' UNKNOWN branch (checked before the guard would
    even be reachable) — proves the trap: this alone would pass with or without the fix."""
    ctx = _ctx(config_parse_error=True, host=None)
    finding = check_host_network_ids(ctx)
    assert finding.status == UNKNOWN
