"""B16: threat monitoring detection — PASS on ids-* and *-ids tool names."""
from pathlib import Path

from clawseccheck.catalog import WARN
from clawseccheck.checks import check_monitoring
from clawseccheck.collector import Context


def _ctx(skills=()):
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.installed_skills = {s: "" for s in skills}
    return c


# B-501: these three used to assert PASS. A name was the sole gate, so any skill could
# claim to be the user's threat monitoring by choosing one — and one already did, in
# fixtures/bad_ownname_clawseccheck_squat. The names below are still RECOGNISED (that is
# what each case is here to pin); recognition just no longer grants a verdict.

def test_b16_ids_prefix_skill_is_a_candidate_not_a_pass():
    f = check_monitoring(_ctx(skills=["ids-engine"]))
    assert f.status == WARN
    assert "'ids-engine'" in f.detail


def test_b16_ids_detector_skill_is_a_candidate_not_a_pass():
    f = check_monitoring(_ctx(skills=["ids-detector"]))
    assert f.status == WARN
    assert "'ids-detector'" in f.detail


def test_b16_dash_ids_suffix_skill_is_a_candidate_not_a_pass():
    f = check_monitoring(_ctx(skills=["suricata-ids"]))
    assert f.status == WARN
    assert "'suricata-ids'" in f.detail


def test_b16_warn_when_no_monitoring():
    f = check_monitoring(_ctx())
    assert f.status == WARN


def test_b16_no_monitoring_skill_in_config_warns():
    """B-036: B16 WARNs when no monitoring skill/plugin is detected in any config field."""
    ctx = _ctx(skills=[])
    ctx.config = {"agents": {"defaults": {"model": {"primary": "gpt-4"}}}}
    f = check_monitoring(ctx)
    assert f.status == WARN
