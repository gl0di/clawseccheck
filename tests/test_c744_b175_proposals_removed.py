"""C-744: OpenClaw 2026.10.5 removed Skill Workshop proposals.

Measured in the 2026.10.5 dist (`skills/workshop/config.ts`, `resolveSkillWorkshopConfig`): the
runtime reads only `skills.workshop.autonomous.mode` and `maxSkillBytes`. `"off"` stays off;
`"auto"`, the retired `"propose"`, a typo and an absent key ALL resolve to `"auto"`. The schema
lost `approvalPolicy` and `maxPending` (Doctor deletes them), and `openclaw skills workshop
apply` has nothing to apply. Until this task B175 told a 2026.10.5 user to set
`approvalPolicy: "pending"` and to run `apply` -- advice for a key the build no longer reads --
and treated a stale `approvalPolicy: "pending"` as a protection.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, WARN, Finding
from clawseccheck.checks import check_skill_workshop_autonomy
from clawseccheck.checks._shared import (
    _WORKSHOP_PROPOSALS_RETIRED_MIN,
    _workshop_proposals_state,
)
from clawseccheck.collector import Context
from clawseccheck.risk import _rule_workshop_autonomy_untrusted_ingress


def _ctx(cfg: dict, installed=None) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.installed_dist_version = installed
    return c


def _ws(**workshop) -> dict:
    return {"skills": {"workshop": workshop}}


def _text(f: Finding) -> str:
    return f.detail + " || " + f.fix + " || " + " ".join(f.evidence)


# --- 1. the predicate -----------------------------------------------------------------

def test_the_boundary_is_ge_not_gt():
    assert _WORKSHOP_PROPOSALS_RETIRED_MIN == (2026, 10, 5)
    assert _workshop_proposals_state(_ctx({}, "2026.10.5")) == "retired"
    assert _workshop_proposals_state(_ctx({}, "2026.10.6")) == "retired"


def test_the_adjacent_measured_build_still_has_proposals():
    assert _workshop_proposals_state(_ctx({}, "2026.10.4")) == "honoured"
    assert _workshop_proposals_state(_ctx({}, "2026.8.1")) == "honoured"


def test_a_beta_and_no_signal_are_unknown_not_retired():
    assert _workshop_proposals_state(_ctx({}, "2026.10.5-beta.1")) == "unknown"
    assert _workshop_proposals_state(_ctx({})) == "unknown"


def test_the_config_stamp_decides_only_when_it_is_at_or_past_the_boundary():
    assert _workshop_proposals_state(
        _ctx({"meta": {"lastTouchedVersion": "2026.10.5"}})) == "retired"
    # a stamp BELOW the boundary proves a build once saved the config, not what runs now
    assert _workshop_proposals_state(
        _ctx({"meta": {"lastTouchedVersion": "2026.10.4"}})) == "unknown"


# --- 2. 2026.10.5: the default and the explicit shapes ----------------------------------

def test_the_default_is_a_fail_that_names_the_mode_and_not_the_removed_key():
    f = check_skill_workshop_autonomy(_ctx({"skills": {}}, "2026.10.5"))
    assert f.status == FAIL
    t = _text(f)
    assert "OpenClaw default, not something set here" in f.detail
    assert 'skills.workshop.autonomous.mode="auto"' in f.detail
    assert "no approval step" in f.detail
    # the whole point: no approvalPolicy reason, no `apply`, no "set approvalPolicy" advice
    assert 'approvalPolicy="auto"' not in t
    assert "workshop apply" not in t
    assert 'Set skills.workshop.approvalPolicy' not in t
    assert '"off"' in f.fix and "only switch" in f.fix


def test_mode_off_passes_and_does_not_claim_review():
    f = check_skill_workshop_autonomy(_ctx(_ws(autonomous={"mode": "off"}), "2026.10.5"))
    assert f.status == PASS
    assert "background learning is off" in f.detail
    assert "require review" not in f.detail


def test_a_leftover_pending_policy_is_called_out_as_protecting_nothing():
    f = check_skill_workshop_autonomy(
        _ctx(_ws(autonomous={"mode": "off"}, approvalPolicy="pending"), "2026.10.5"))
    assert f.status == PASS
    assert "approvalPolicy is still in the config" in f.detail
    assert "protects nothing" in f.detail


def test_the_dangerous_shape_propose_plus_pending_is_a_fail_not_a_partial_warn():
    """On 2026.10.4 this pair was review-gated (a WARN: propose creates pending proposals).
    On 2026.10.5 `propose` runs as `auto` and `pending` is not read: the agent saves skills
    on its own. This is the config the old reading would have under-called."""
    cfg = _ws(autonomous={"mode": "propose"}, approvalPolicy="pending")
    f = check_skill_workshop_autonomy(_ctx(cfg, "2026.10.5"))
    assert f.status == FAIL
    assert "'propose'" in f.detail and "runs as" in f.detail
    assert "not something set here" not in f.detail     # it WAS set; do not call it the default
    assert "protects nothing" in f.detail


def test_a_typo_mode_runs_as_auto_and_is_named():
    f = check_skill_workshop_autonomy(_ctx(_ws(autonomous={"mode": "of"}), "2026.10.5"))
    assert f.status == FAIL
    assert "'of'" in f.detail


def test_an_unreachable_tool_is_the_dormant_warn_without_the_removed_advice():
    cfg = {"tools": {"deny": ["skill_workshop"]}, "skills": {}}
    f = check_skill_workshop_autonomy(_ctx(cfg, "2026.10.5"))
    assert f.status == WARN
    assert "approvalPolicy" not in f.fix.replace("approvalPolicy setting", "")
    assert '"off"' in f.fix


# --- 3. controls: the older builds and the unknown build keep today's reading -------------

def test_2026_10_4_still_reads_propose_plus_pending_as_the_review_gated_warn():
    cfg = _ws(autonomous={"mode": "propose"}, approvalPolicy="pending")
    f = check_skill_workshop_autonomy(_ctx(cfg, "2026.10.4"))
    assert f.status == WARN
    assert 'approvalPolicy to "pending"' in f.fix


def test_2026_10_4_default_still_names_both_defaults_and_the_apply_step():
    f = check_skill_workshop_autonomy(_ctx({"skills": {}}, "2026.10.4"))
    assert f.status == FAIL
    assert 'approvalPolicy="auto"' in f.detail
    assert "workshop apply" in f.fix


def test_an_unknown_build_keeps_the_pre_10_5_pass_wording():
    f = check_skill_workshop_autonomy(
        _ctx(_ws(autonomous={"mode": "off"}, approvalPolicy="pending")))
    assert f.status == PASS
    assert "require review" in f.detail


# --- 4. RISK-26 --------------------------------------------------------------------------

def _findings(statuses: dict) -> list:
    return [Finding(id=i, title=i, severity="HIGH", status=s, detail="", fix="",
                    framework="x") for i, s in statuses.items()]


def test_risk_26_stops_naming_the_removed_setting_on_2026_10_5():
    path = _rule_workshop_autonomy_untrusted_ingress(
        _ctx({}, "2026.10.5"), _findings({"B175": FAIL, "B26": WARN}))
    assert path is not None
    assert "approvalPolicy" not in path.why or "no longer" in path.why
    assert "workshop apply" not in path.fix
    assert "the only switch" in path.fix


def test_risk_26_keeps_the_old_wording_on_2026_10_4():
    path = _rule_workshop_autonomy_untrusted_ingress(
        _ctx({}, "2026.10.4"), _findings({"B175": FAIL, "B26": WARN}))
    assert path is not None
    assert "approvalPolicy='auto'" in path.why
    assert "workshop apply" in path.fix
