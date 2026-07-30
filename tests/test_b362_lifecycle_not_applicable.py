"""B-362 (4th slice) — extend Finding.not_applicable (F-138/F-139/F-140 mechanism) to the
one genuinely-groundable config-absence UNKNOWN site found in ``checks/_lifecycle.py``:

* B5 (``check_supply_chain``) — no ``plugins`` and no ``skills`` key in openclaw.json.
  Unlike the sibling sites already migrated (B31/B26/B140/B72/B38-cluster), this locus is
  NOT config-only on the skills side: real installed skills are discovered by an
  independent disk walk into ``ctx.installed_skills``, not by an openclaw.json ``skills``
  key. So the not_applicable gate here requires the usual config-locus completeness
  (``_surface_absent``) AND the disk-locus completeness counterpart
  (``_skill_corpus_complete``) AND an empty ``ctx.installed_skills`` — otherwise a host
  with real installed skills but no ``skills`` config key would be wrongly marked
  not_applicable.

The other four candidate sites assigned in this slice (``check_install_policy_gate``,
``check_self_modification``, ``check_supply_chain``'s second UNKNOWN branch,
``check_marketplace_feed_provenance``, ``check_exec_safe_bin_trusted_dirs``) were audited
and deliberately left as plain UNKNOWN -- see the sweep commit message / task report for
why each does not qualify.

Same three-part shape as ``tests/test_f140_not_applicable_degrades.py`` /
``tests/test_b362_browser_not_applicable.py``: (1) the flag fires when the surface is
genuinely absent, (2) it degrades to False on an incomplete read (config OR disk-corpus
side), (3) it never fires falsely when the surface exists in a form the check itself
parses into a non-UNKNOWN verdict, or when real installed skills exist off the config
locus entirely.

Offline, read-only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.adjudication import build_judge_packet
from clawseccheck.catalog import UNKNOWN
from clawseccheck.checks import check_supply_chain
from clawseccheck.collector import LIMIT_DOMAIN_CONFIG, Context, note_limit
from clawseccheck.scoring import ScoreResult


def _ctx(cfg: dict, **kw) -> Context:
    defaults = dict(home=Path("/nonexistent"), config_found=True, config_parse_error=False)
    defaults.update(kw)
    c = Context(**defaults)
    c.config = cfg
    return c


def _score() -> ScoreResult:
    return ScoreResult(score=90, grade="A", capped=False, raw_score=90,
                        failed_critical=0, failed_high=0)


# ---------------------------------------------------------------------------
# B5 — check_supply_chain, first UNKNOWN branch
# ---------------------------------------------------------------------------

def test_no_plugins_no_skills_key_and_no_disk_skills_sets_not_applicable():
    f = check_supply_chain(_ctx({}))
    assert f.status == UNKNOWN
    assert f.not_applicable is True


def test_real_disk_installed_skills_never_marked_not_applicable_even_with_no_config_key():
    """Adversarial: a host can have real installed skills discovered on disk with zero
    "skills" key in openclaw.json (skills don't need to be declared in config to exist)
    -- that must never be reported not_applicable."""
    ctx = _ctx({})
    ctx.installed_skills = {"some-skill": "skill body text"}
    f = check_supply_chain(ctx)
    assert f.status == UNKNOWN
    assert f.not_applicable is False


def test_partial_skill_frontier_walk_keeps_flag_false():
    """A capped/partial installed-skill discovery walk means we cannot claim the disk
    side was read completely, even with zero skills found so far."""
    ctx = _ctx({})
    ctx.skills_frontier_partial = True
    f = check_supply_chain(ctx)
    assert f.status == UNKNOWN
    assert f.not_applicable is False


def test_skills_capped_count_keeps_flag_false():
    ctx = _ctx({})
    ctx.skills_capped_count = 3
    f = check_supply_chain(ctx)
    assert f.status == UNKNOWN
    assert f.not_applicable is False


def test_a_configured_plugins_key_never_reaches_the_absence_branch():
    """Adversarial: a real plugins/skills config key reaches the second (real, still
    UNKNOWN) branch instead -- never not_applicable."""
    f = check_supply_chain(_ctx({"plugins": {"some-plugin": {}}}))
    assert f.status == UNKNOWN
    assert f.not_applicable is False


def test_domain_tagged_limit_hit_keeps_flag_false():
    ctx = _ctx({})
    note_limit(ctx.limit_hits, LIMIT_DOMAIN_CONFIG, "hit the config scan cap")
    f = check_supply_chain(ctx)
    assert f.status == UNKNOWN
    assert f.not_applicable is False


def test_config_parse_error_keeps_flag_false():
    f = check_supply_chain(_ctx({}, config_parse_error=True))
    assert f.not_applicable is False


def test_config_not_found_keeps_flag_false():
    f = check_supply_chain(_ctx({}, config_found=False))
    assert f.not_applicable is False


def test_not_applicable_finding_excluded_from_judge_packet():
    ctx = _ctx({})
    f = check_supply_chain(ctx)
    assert f.not_applicable is True  # control
    packet = build_judge_packet(ctx, [f])
    assert packet == []
