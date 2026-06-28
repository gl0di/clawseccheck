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
