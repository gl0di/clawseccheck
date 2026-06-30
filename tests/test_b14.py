"""B14: egress surface — PASS branch removed; phantom allowlist fields no longer suppress WARN."""
from pathlib import Path

from clawseccheck.catalog import UNKNOWN, WARN
from clawseccheck.checks import check_egress
from clawseccheck.collector import Context


def _ctx(cfg, skills=()):
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.installed_skills = {s: "" for s in skills}
    return c


def test_b14_phantom_egress_field_still_warns():
    cfg = {
        "gateway": {"egress": ["example.com"]},
        "channels": {"slack": {"token": "x"}},
    }
    f = check_egress(_ctx(cfg))
    assert f.status == WARN


def test_b14_phantom_network_egress_still_warns():
    cfg = {
        "network": {"egress": ["example.com"]},
        "channels": {"email": {}},
    }
    f = check_egress(_ctx(cfg))
    assert f.status == WARN


def test_b14_unknown_when_no_surface():
    f = check_egress(_ctx({}))
    assert f.status == UNKNOWN


def test_b14_warn_with_external_skill():
    f = check_egress(_ctx({}, skills=["slack-connector"]))
    assert f.status == WARN


# B-035: B14 has NO PASS branch (by design — OpenClaw exposes no built-in egress allowlist).
# Configured restriction signals (tools.http.allow, channel allowlists) do NOT flip B14 to
# PASS; they are recorded by C014 (check_egress_inventory) instead.
# TODO(B-035): If a future OpenClaw schema adds a verifiable egress-allowlist field that
# B14 can read, add a PASS branch in check_egress and a corresponding PASS test here.

def test_b14_tools_http_allow_still_warns():
    """B-035: even with tools.http.allow set, check_egress WARNs (no PASS branch)."""
    cfg = {
        "tools": {"allow": ["exec", "http_post"], "http": {"allow": ["api.example.com"]}},
        "channels": {"slack": {"dmPolicy": "allowlist"}},
    }
    f = check_egress(_ctx(cfg))
    # Current behavior: surfaces detected → WARN regardless of restriction signals.
    assert f.status == WARN
