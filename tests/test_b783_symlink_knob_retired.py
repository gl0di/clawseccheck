"""B-783: OpenClaw 2026.9.3 removed skills.workshop.allowSymlinkTargetWrites outright.

Grounded by EXECUTING the installed 2026.9.3 root schema's safeParse (2026-09-09):
skills.workshop's object holds exactly {approvalPolicy, autonomous, maxPending,
maxSkillBytes}. The vendor ships a defineLegacyConfigMigration entry
"skills.workshop.allowSymlinkTargetWrites-retired" whose message says Skill Workshop now
writes only inside its own directory, with no override — hardening, not a widening.

dig() reads raw JSON regardless of schema validity, so a stale
`"allowSymlinkTargetWrites": true` a "doctor --fix" has not yet deleted still reaches
check_skill_workshop_autonomy. Before this fix, a config that had done everything ELSE
right (autonomous authoring off, approvalPolicy "pending") still drew a WARN on a
2026.9.3 install, for a setting that build no longer reads at all — a false-WARN this
file exists to close and pin shut.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks import check_skill_workshop_autonomy
from clawseccheck.checks._shared import (
    _SCHEMA_MODERN_MIN,
    _SYMLINK_KNOB_RETIRED_MIN,
    _openclaw_generation,
    _workshop_symlink_knob,
)
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict, installed=None) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.installed_dist_version = installed
    return c


# ---------------------------------------------------------------------------
# 1. The predicate itself
# ---------------------------------------------------------------------------

def test_the_boundary_is_ge_not_gt():
    assert _workshop_symlink_knob(_ctx({}, "2026.9.3")) == "retired"


def test_past_the_boundary_stays_retired():
    for v in ("2026.9.4", "2026.10.0", "2027.1.1"):
        assert _workshop_symlink_knob(_ctx({}, v)) == "retired", v


def test_the_adjacent_measured_build_is_honoured():
    assert _workshop_symlink_knob(_ctx({}, "2026.9.2")) == "honoured"


def test_a_correction_suffix_stays_on_the_conservative_side():
    """(2026,9,2,1) < (2026,9,3) -- a correction release still HONOURS the key, which
    keeps a finding a caller might not strictly need rather than dropping one it does."""
    assert _workshop_symlink_knob(_ctx({}, "2026.9.2-1")) == "honoured"


def test_the_whole_pre_9_3_fleet_is_honoured():
    for v in ("2026.8.1", "2026.7.1-2", "2026.1.1"):
        assert _workshop_symlink_knob(_ctx({}, v)) == "honoured", v


def test_a_beta_of_the_retiring_release_is_unknown_not_retired():
    """`_numeric_parts` returns None on a pre-release (B-264) -- a beta must not be read
    as having shipped the retirement it is still testing."""
    assert _workshop_symlink_knob(_ctx({}, "2026.9.3-beta.1")) == "unknown"


def test_no_signal_at_all_is_unknown():
    assert _workshop_symlink_knob(_ctx({})) == "unknown"


# ---------------------------------------------------------------------------
# 2. Source precedence and asymmetry -- mirrors _openclaw_generation's own reasoning
# ---------------------------------------------------------------------------

def test_a_modern_stamp_can_escalate_when_nothing_is_installed():
    ctx = _ctx({"meta": {"lastTouchedVersion": "2026.9.3"}})
    assert _workshop_symlink_knob(ctx) == "retired"


def test_a_stale_stamp_does_not_prove_what_is_installed_now():
    """A config stamped 2026.9.2 proves a 2026.9.2 build once SAVED it -- not that 2026.9.2
    is installed NOW. Reading it as "honoured" is how you keep warning the very user who
    has already upgraded. This must land on "unknown", not "honoured"."""
    ctx = _ctx({"meta": {"lastTouchedVersion": "2026.9.2"}})
    assert _workshop_symlink_knob(ctx) == "unknown"


def test_installed_wins_over_a_newer_stamp():
    ctx = _ctx({"meta": {"lastTouchedVersion": "2026.9.3"}}, installed="2026.9.2")
    assert _workshop_symlink_knob(ctx) == "honoured"


def test_the_keys_own_presence_is_not_a_version_signal():
    ctx = _ctx({"skills": {"workshop": {"allowSymlinkTargetWrites": True}}})
    assert _workshop_symlink_knob(ctx) == "unknown"


# ---------------------------------------------------------------------------
# 3. The invariant that licenses leaving check_skill_workshop_autonomy's `undecidable`
#    conjunct ungated by this predicate.
# ---------------------------------------------------------------------------

def test_retired_min_is_at_or_past_schema_modern_min():
    """"retired" is only ever reachable through generation == "modern" -- both read
    installed_dist_version first, meta.lastTouchedVersion second, and this inequality is
    the reason: any version that clears _SYMLINK_KNOB_RETIRED_MIN already clears
    _SCHEMA_MODERN_MIN. Without this holding, check_skill_workshop_autonomy's
    `undecidable` conjunct (gated on generation == "unknown") could go stale silently --
    a retired verdict reachable from an "unknown" generation would need its own gate
    there, and none exists."""
    assert _SCHEMA_MODERN_MIN <= _SYMLINK_KNOB_RETIRED_MIN


def test_no_context_yields_retired_from_a_non_modern_generation():
    """The behavioural half of the invariant above, swept over every case in this file."""
    cases = [
        {}, {"meta": {"lastTouchedVersion": "2026.9.3"}}, {"meta": {"lastTouchedVersion": "2026.9.2"}},
        {"skills": {"workshop": {"allowSymlinkTargetWrites": True}}},
    ]
    installed_values = (None, "2026.9.3", "2026.9.4", "2026.9.2", "2026.9.2-1",
                        "2026.8.1", "2026.7.1-2", "2026.9.3-beta.1")
    for cfg in cases:
        for installed in installed_values:
            ctx = _ctx(cfg, installed)
            if _workshop_symlink_knob(ctx) == "retired":
                assert _openclaw_generation(ctx) == "modern", (cfg, installed)


# ---------------------------------------------------------------------------
# 4. Check-level: the headline case -- a hardened config, three builds
# ---------------------------------------------------------------------------

def _hardened_cfg():
    return {"skills": {"workshop": {"autonomous": {"mode": "off"},
                                    "approvalPolicy": "pending",
                                    "allowSymlinkTargetWrites": True}}}


def test_a_hardened_config_passes_on_2026_9_3():
    """The false-WARN this task exists to close: autonomy off, approval pending, and only
    a line the installed build no longer reads."""
    r = check_skill_workshop_autonomy(_ctx(_hardened_cfg(), "2026.9.3"))
    assert r.status == PASS
    assert "skills.workshop.allowSymlinkTargetWrites" in r.detail
    assert "2026.9.3" in r.detail
    assert "doctor --fix" in r.detail
    assert not any("allowSymlinkTargetWrites=true" in e for e in r.evidence)
    assert r.fix != "—"
    assert "skills.workshop.allowSymlinkTargetWrites" in r.fix


def test_the_control_the_same_config_still_warns_on_2026_9_2():
    """Without this, "always PASS" would satisfy the test above too."""
    r = check_skill_workshop_autonomy(_ctx(_hardened_cfg(), "2026.9.2"))
    assert r.status == WARN
    assert any("allowSymlinkTargetWrites=true" in e for e in r.evidence)
    assert "2026.9.3" not in r.detail


def test_the_hardened_config_also_warns_when_the_build_is_unknown():
    r = check_skill_workshop_autonomy(_ctx(_hardened_cfg(), None))
    assert r.status == WARN
    assert any("allowSymlinkTargetWrites=true" in e for e in r.evidence)
    # unknown-build advice is version-qualified, unlike the plain 2026.9.2 case above.
    assert "2026.9.3" in r.fix


# ---------------------------------------------------------------------------
# 5. is True vs mere presence -- a safe stale value produces no churn
# ---------------------------------------------------------------------------

def test_a_false_value_on_9_3_produces_byte_identical_detail_to_its_absence():
    with_false = {"skills": {"workshop": {"autonomous": {"mode": "off"},
                                          "approvalPolicy": "pending",
                                          "allowSymlinkTargetWrites": False}}}
    without_key = {"skills": {"workshop": {"autonomous": {"mode": "off"},
                                           "approvalPolicy": "pending"}}}
    r1 = check_skill_workshop_autonomy(_ctx(with_false, "2026.9.3"))
    r2 = check_skill_workshop_autonomy(_ctx(without_key, "2026.9.3"))
    assert r1.status == r2.status == PASS
    assert r1.detail == r2.detail
    assert r1.fix == r2.fix == "—"


# ---------------------------------------------------------------------------
# 6. Fix-text: the key must never be named on a config that does not have it
# ---------------------------------------------------------------------------

def _enabled_only_cfg():
    """Reaches the final "partial gap" WARN branch, not FAIL: mode=propose alone sets
    `enabled`, and an explicit approvalPolicy="pending" keeps `is_auto` False."""
    return {"skills": {"workshop": {"autonomous": {"mode": "propose"},
                                    "approvalPolicy": "pending"}}}


def test_fix_text_names_the_key_on_9_2_but_not_on_9_3():
    r93 = check_skill_workshop_autonomy(_ctx(_enabled_only_cfg(), "2026.9.3"))
    r92 = check_skill_workshop_autonomy(_ctx(_enabled_only_cfg(), "2026.9.2"))
    r_unknown = check_skill_workshop_autonomy(_ctx(_enabled_only_cfg(), None))
    assert "allowSymlinkTargetWrites" not in r93.fix
    assert "skills.workshop.allowSymlinkTargetWrites" in r92.fix
    assert "skills.workshop.allowSymlinkTargetWrites" in r_unknown.fix
    assert "2026.9.3" in r_unknown.fix
    assert "2026.9.3" not in r92.fix


# ---------------------------------------------------------------------------
# 7. Fixtures (CLAUDE.md §4: a clean and a warn case)
# ---------------------------------------------------------------------------

def test_the_clean_fixture_passes_with_the_retirement_note():
    r = check_skill_workshop_autonomy_from_fixture("clean_b783_workshop_symlink_retired")
    assert r.status == PASS
    assert "2026.9.3" in r.detail


def test_the_warn_fixture_still_warns_on_the_earlier_stamp():
    r = check_skill_workshop_autonomy_from_fixture("warn_b783_workshop_symlink_live")
    assert r.status == WARN


def check_skill_workshop_autonomy_from_fixture(name: str):
    from clawseccheck.collector import collect
    return check_skill_workshop_autonomy(collect(FIXTURES / name))
