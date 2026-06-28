"""B16: threat monitoring detection — PASS on ids-* and *-ids tool names."""
from pathlib import Path

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks import check_monitoring
from clawseccheck.collector import Context


def _ctx(skills=()):
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.installed_skills = {s: "" for s in skills}
    return c


def test_b16_pass_with_ids_prefix_skill():
    f = check_monitoring(_ctx(skills=["ids-engine"]))
    assert f.status == PASS


def test_b16_pass_with_ids_detector_skill():
    f = check_monitoring(_ctx(skills=["ids-detector"]))
    assert f.status == PASS


def test_b16_pass_with_dash_ids_suffix_skill():
    f = check_monitoring(_ctx(skills=["suricata-ids"]))
    assert f.status == PASS


def test_b16_warn_when_no_monitoring():
    f = check_monitoring(_ctx())
    assert f.status == WARN
