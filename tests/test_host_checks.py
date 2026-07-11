"""B50–B54 host-posture checks + their wiring through audit(include_host=True).

The checks read ctx.host (the hostwatch.detect result). They never FAIL: a
confirmed-absent monitor is a WARN only when the agent is high-privilege,
otherwise a PASS. An inconclusive/unsupported probe is normally UNKNOWN
(excluded from the score) — EXCEPT (B-172) for the four *visibility* classes
(network_ids/host_audit/file_integrity/edr_av): a read-only miss there is
still UNKNOWN at the detector level, but a powerful agent gets a LOW-confidence
WARN instead of a silent plain UNKNOWN, since presence was never confirmed
either. Firewall (prevention, not detection) keeps the plain-UNKNOWN behavior.
"""
from __future__ import annotations

from pathlib import Path

import clawseccheck
from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    _agent_is_powerful,
    check_host_audit,
    check_host_edr,
    check_host_egress_posture,
    check_host_file_integrity,
    check_host_firewall,
    check_host_network_ids,
)
from clawseccheck.collector import Context

_VIS = ("network_ids", "host_audit", "file_integrity", "edr_av", "firewall")

# a high-privilege agent: exec tool enabled + reachable via an open channel
_POWERFUL = {"tools": {"exec": {"mode": "auto"}},
             "channels": {"telegram": {"dmPolicy": "open"}}}
# a low-privilege agent: no exec, no open channel
_WEAK = {"tools": {}}


def _host(supported=True, **classes):
    base = {"system": "Linux", "supported": supported, "classes": {}}
    for c in _VIS:
        base["classes"][c] = classes.get(
            c, {"status": "absent", "found": [], "active": None})
    return base


def _ctx(cfg, host):
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.host = host
    return c


# ---------------------------------------------------------------------------
# agent-power gate
# ---------------------------------------------------------------------------

def test_agent_is_powerful_true_for_exec_plus_open_channel():
    assert _agent_is_powerful(_ctx(_POWERFUL, None)) is True


def test_agent_is_powerful_false_for_bare_config():
    assert _agent_is_powerful(_ctx(_WEAK, None)) is False


# ---------------------------------------------------------------------------
# status mapping
# ---------------------------------------------------------------------------

def test_present_monitor_is_pass():
    host = _host(network_ids={"status": "present", "found": ["Suricata"], "active": True})
    f = check_host_network_ids(_ctx(_POWERFUL, host))
    assert f.status == PASS
    assert "Suricata" in (f.evidence or [])


def test_absent_monitor_powerful_agent_warns():
    f = check_host_network_ids(_ctx(_POWERFUL, _host()))
    assert f.status == WARN


def test_absent_monitor_weak_agent_passes():
    f = check_host_network_ids(_ctx(_WEAK, _host()))
    assert f.status == PASS


def test_unknown_class_is_unknown():
    host = _host(firewall={"status": "unknown", "found": [], "active": None})
    f = check_host_firewall(_ctx(_POWERFUL, host))
    assert f.status == UNKNOWN


# ---------------------------------------------------------------------------
# B-172: a miss on a *visibility* class (network_ids/host_audit/file_integrity/
# edr_av) is honest UNKNOWN, never a confident "absent" — but that UNKNOWN
# still means "presence not confirmed," so a high-privilege agent still gets a
# (lower-confidence) heads-up rather than a silent plain UNKNOWN. Firewall is
# prevention, not detection, and keeps the plain-UNKNOWN behavior above.
# ---------------------------------------------------------------------------

def test_unknown_visibility_class_powerful_agent_warns():
    host = _host(network_ids={"status": "unknown", "found": [], "active": None})
    f = check_host_network_ids(_ctx(_POWERFUL, host))
    assert f.status == WARN


def test_unknown_visibility_class_weak_agent_is_unknown():
    host = _host(network_ids={"status": "unknown", "found": [], "active": None})
    f = check_host_network_ids(_ctx(_WEAK, host))
    assert f.status == UNKNOWN


def test_no_host_context_is_unknown():
    f = check_host_audit(_ctx(_POWERFUL, None))
    assert f.status == UNKNOWN


def test_unsupported_host_is_unknown():
    f = check_host_edr(_ctx(_POWERFUL, _host(supported=False)))
    assert f.status == UNKNOWN


def test_every_host_check_runs_clean_on_each_class():
    host = _host(
        host_audit={"status": "present", "found": ["auditd"], "active": True},
        file_integrity={"status": "present", "found": ["AIDE"], "active": True},
    )
    ctx = _ctx(_POWERFUL, host)
    assert check_host_audit(ctx).status == PASS
    assert check_host_file_integrity(ctx).status == PASS
    # edr/firewall still absent -> WARN under a powerful agent
    assert check_host_edr(ctx).status == WARN
    assert check_host_firewall(ctx).status == WARN


def test_host_finding_never_fails():
    """Host posture must never emit FAIL (it must not hard-cap the grade)."""
    for host in (None, _host(), _host(supported=False),
                 _host(edr_av={"status": "present", "found": ["Wazuh"], "active": None})):
        for chk in (check_host_network_ids, check_host_audit, check_host_file_integrity,
                    check_host_edr, check_host_firewall):
            assert chk(_ctx(_POWERFUL, host)).status != "FAIL"


# ---------------------------------------------------------------------------
# B101 egress posture (F-084) — NOT part of _host_finding's generic shape:
# "active" here means "resolved policy is deny (True) / allow (False) / could
# not be resolved (None)", not "is a monitor tool switched on".
# ---------------------------------------------------------------------------

def _host_egress(status="unknown", found=None, active=None, evidence=None, supported=True):
    base = _host(supported=supported)
    base["classes"]["egress_posture"] = {
        "status": status,
        "found": found or [],
        "active": active,
        "evidence": evidence if evidence is not None else (found or []),
    }
    return base


def test_egress_default_deny_is_pass():
    host = _host_egress(status="present", found=["nftables OUTPUT policy=drop"], active=True)
    f = check_host_egress_posture(_ctx(_POWERFUL, host))
    assert f.status == PASS
    assert "nftables OUTPUT policy=drop" in (f.evidence or [])


def test_egress_default_allow_powerful_agent_warns():
    host = _host_egress(status="present", found=["ufw DEFAULT_OUTGOING_POLICY=allow"], active=False)
    f = check_host_egress_posture(_ctx(_POWERFUL, host))
    assert f.status == WARN


def test_egress_default_allow_weak_agent_passes():
    host = _host_egress(status="present", found=["ufw DEFAULT_OUTGOING_POLICY=allow"], active=False)
    f = check_host_egress_posture(_ctx(_WEAK, host))
    assert f.status == PASS


def test_egress_unresolved_policy_is_unknown():
    # a firewall's coarse presence contributed evidence, but no explicit deny/allow
    # policy was resolved -> honest UNKNOWN, never a fabricated PASS/WARN.
    host = _host_egress(
        status="present", found=["firewalld active (egress policy not read — unmapped field)"],
        active=None,
    )
    f = check_host_egress_posture(_ctx(_POWERFUL, host))
    assert f.status == UNKNOWN


def test_egress_no_config_found_is_unknown():
    host = _host_egress(status="unknown", found=[], active=None)
    f = check_host_egress_posture(_ctx(_POWERFUL, host))
    assert f.status == UNKNOWN


def test_egress_no_host_context_is_unknown():
    f = check_host_egress_posture(_ctx(_POWERFUL, None))
    assert f.status == UNKNOWN


def test_egress_unsupported_host_is_unknown():
    f = check_host_egress_posture(_ctx(_POWERFUL, _host_egress(supported=False)))
    assert f.status == UNKNOWN


def test_egress_never_fails():
    for host in (None, _host_egress(), _host_egress(supported=False),
                 _host_egress(status="present", found=["x"], active=False)):
        assert check_host_egress_posture(_ctx(_POWERFUL, host)).status != "FAIL"


# ---------------------------------------------------------------------------
# wiring through audit(include_host=True)
# ---------------------------------------------------------------------------

def test_audit_include_host_populates_ctx_and_b50(monkeypatch):
    """audit() must set ctx.host BEFORE run_all so B50–B54 see it."""
    crafted = _host(network_ids={"status": "present", "found": ["Suricata"], "active": True})
    monkeypatch.setattr(clawseccheck, "_host_detect", lambda root="/", **_: crafted)
    ctx, findings, _score = clawseccheck.audit("fixtures/home_safe", include_host=True)
    assert ctx.host is crafted
    b50 = next(f for f in findings if f.id == "B50")
    assert b50.status == PASS


def test_audit_include_host_wires_b101(monkeypatch):
    crafted = _host_egress(status="present", found=["nftables OUTPUT policy=drop"], active=True)
    monkeypatch.setattr(clawseccheck, "_host_detect", lambda root="/", **_: crafted)
    _ctx_, findings, _score = clawseccheck.audit("fixtures/home_safe", include_host=True)
    b101 = next(f for f in findings if f.id == "B101")
    assert b101.status == PASS


def test_audit_without_host_flag_leaves_b50_unknown():
    _ctx_, findings, _score = clawseccheck.audit("fixtures/home_safe")
    b50 = next(f for f in findings if f.id == "B50")
    assert b50.status == UNKNOWN
