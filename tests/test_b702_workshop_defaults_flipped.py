"""B-702 — the Skill Workshop defaults flipped, so an absent setting means the opposite.

Measured in each build's own runtime bundle (`src/skills/workshop/config.ts`,
`DEFAULT_CONFIG`), not read off a description::

    2026.7.1-2 (config-XlfFMqhc.js)   autonomous {enabled: false}   approvalPolicy "pending"
    2026.8.1   (config-Cjp42tXL.js)   autonomous {mode: "auto"}     approvalPolicy "auto"

B175's FAIL condition is the conjunction of those two, so on 2026.8.1 a config with no
`skills.workshop` block at all is running unattended authoring AND unattended install —
and the check used to answer PASS "autonomous authoring is disabled" about it.

The vendor's own words for the enum: *"off" keeps only the suggestion nudge, "propose"
creates pending proposals, and "auto" applies captured proposals and runs daily
scanner-gated cleanup that can rewrite or drop eligible writable skills.*

Measured distribution over the whole fixture corpus (526 homes with a config), which is
what the severity rests on rather than the worst case:

    before, every generation   518 PASS ·   5 FAIL ·   1 WARN · 2 UNKNOWN
    after,  2026.8.1                       75 FAIL · 449 WARN · 2 UNKNOWN
    after,  2026.7.x           UNCHANGED
    after,  undeterminable     518 UNKNOWN · 5 FAIL · 1 WARN · 2 PASS

75 of 526 FAIL rather than all of them because `_skill_workshop_reachable` still gates it,
and that gate mirrors the runtime's own: `prepareSkillExperienceReviewCandidate` returns
early when the mode is "off", when the session is sandboxed, and when
`isToolAllowedByPolicies("skill_workshop", …)` says no.
"""
from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_skill_workshop_autonomy
from clawseccheck.collector import Context

MODERN = "2026.8.1"
LEGACY = "2026.7.1-2"


def _ctx(config, installed=None, config_found=True):
    """A context whose config was READ. `config_found` is collector state and defaults to
    False on a hand-built Context, which is not what these cases mean: `_ctx({}, MODERN)`
    is "the user has an openclaw.json and configured nothing", not "there is no config".
    B175 distinguishes the two — an absent config cannot support a verdict about defaults —
    so the helper has to say which one it is instead of leaving it at the dataclass value.
    """
    c = Context(home=Path("/nonexistent"))
    c.config = config
    c.config_found = config_found
    c.installed_dist_version = installed
    return c


def _workshop(**kw):
    autonomous = {k: kw.pop(k) for k in ("mode", "enabled") if k in kw}
    block = dict(kw)
    if autonomous:
        block["autonomous"] = autonomous
    return {"skills": {"workshop": block}}


# ------------------------------------------------- the defect, per generation

def test_a_stock_modern_config_is_not_clean():
    """The headline. No `skills.workshop` block at all, on a build whose defaults are
    `mode: "auto"` + `approvalPolicy: "auto"`."""
    r = check_skill_workshop_autonomy(_ctx({}, MODERN))
    assert r.status == FAIL
    assert "autonomous authoring is disabled" not in (r.detail or "")


def test_the_same_stock_config_stays_clean_on_a_legacy_build():
    """The other half, and the reason this is not a blanket severity bump: on 2026.7.x the
    defaults really are off/"pending", so the verdict there must not move."""
    assert check_skill_workshop_autonomy(_ctx({}, LEGACY)).status == PASS


def test_a_stock_config_on_an_undeterminable_build_is_unknown():
    assert check_skill_workshop_autonomy(_ctx({}, None)).status == UNKNOWN


def test_the_verdict_says_the_danger_came_from_the_default():
    """A user who configured nothing must not be told they configured something."""
    detail = check_skill_workshop_autonomy(_ctx({}, MODERN)).detail or ""
    assert "DEFAULT, not something set here" in detail
    assert detail.count("DEFAULT, not something set here") == 2, (
        "both legs are defaults on a stock 2026.8.1 config; each must say so"
    )


# ------------------------------------------------- the only genuinely clean state

def test_explicitly_opting_out_is_clean_on_a_modern_build():
    cfg = _workshop(mode="off", approvalPolicy="pending")
    assert check_skill_workshop_autonomy(_ctx(cfg, MODERN)).status == PASS


@pytest.mark.parametrize("cfg", [
    _workshop(mode="off"),                        # approvalPolicy still defaults to "auto"
    _workshop(approvalPolicy="pending"),          # mode still defaults to "auto"
], ids=["mode-off-only", "pending-only"])
def test_half_an_opt_out_is_not_clean_on_a_modern_build(cfg):
    """Both defaults are dangerous, so opting out of one still leaves the other."""
    assert check_skill_workshop_autonomy(_ctx(cfg, MODERN)).status != PASS


# ------------------------------------------------- the enum the old boolean could not express

def test_auto_is_reported_as_applying_and_propose_is_not():
    """`propose` creates proposals; `auto` APPLIES them. The old boolean could not tell
    them apart, and the difference is the whole reason `auto` is worse."""
    auto = check_skill_workshop_autonomy(_ctx(_workshop(mode="auto"), MODERN))
    propose = check_skill_workshop_autonomy(
        _ctx(_workshop(mode="propose", approvalPolicy="pending"), MODERN))
    assert "AND applies them" in (auto.detail or "")
    assert "AND applies them" not in (propose.detail or "")


# ------------------------------------------------- the stale-key case

def test_a_key_the_installed_build_ignores_does_not_earn_a_clean_verdict():
    """The sharpest true positive here: someone set `autonomous.enabled: false` on 2026.7.x,
    upgraded, and silently lost the protection — 2026.8.1 does not read that key and its
    default is "auto". Reading the stale key would report exactly the safety they no
    longer have."""
    r = check_skill_workshop_autonomy(_ctx(_workshop(enabled=False), MODERN))
    assert r.status == FAIL
    assert "does not read it" in (r.detail or "")
    assert "skills.workshop.autonomous.enabled" in (r.detail or "")


def test_the_mirror_case_is_reported_too():
    """`.mode` on a 2026.7.x build is equally inert."""
    r = check_skill_workshop_autonomy(_ctx(_workshop(mode="auto"), LEGACY))
    assert r.status == PASS          # 7.x defaults apply: enabled=false, pending
    assert "does not read it" in (r.detail or "")


def test_the_spelling_decides_only_when_the_build_cannot_be_seen():
    """With no installed version, the key the user wrote is the only evidence of their
    build — `.mode` does not parse on 2026.7.x and `.enabled` does not parse on 2026.8.1."""
    assert check_skill_workshop_autonomy(
        _ctx(_workshop(mode="auto"), None)).status == FAIL
    assert check_skill_workshop_autonomy(
        _ctx(_workshop(enabled=False), None)).status == PASS


# ------------------------------------------------- advice must fit the reader's build

@pytest.mark.parametrize("installed,expected,forbidden", [
    (MODERN, 'skills.workshop.autonomous.mode to "off"',
     "skills.workshop.autonomous.enabled to false"),
    (LEGACY, "skills.workshop.autonomous.enabled to false",
     'skills.workshop.autonomous.mode to "off"'),
], ids=["modern", "legacy"])
def test_the_fix_names_the_key_this_build_accepts(installed, expected, forbidden):
    cfg = (_workshop(mode="auto", approvalPolicy="auto") if installed == MODERN
           else _workshop(enabled=True, approvalPolicy="auto"))
    fix = check_skill_workshop_autonomy(_ctx(cfg, installed)).fix or ""
    assert expected in fix
    assert forbidden not in fix


def test_the_fix_no_longer_calls_pending_the_default():
    '''"Set approvalPolicy back to the default \\"pending\\"" was true on 2026.7.x and became
    false on 2026.8.1, where the default is "auto".'''
    fix = check_skill_workshop_autonomy(_ctx({}, MODERN)).fix or ""
    assert 'the default "pending"' not in fix
    assert "OpenClaw 2026.8.1 defaults" in fix


# ------------------------------------------------- non-vacuity

def test_the_reachability_gate_still_splits_the_population():
    """75/449 rather than 526/0 is the whole reason FAIL is defensible here. If the gate
    ever stops discriminating, the severity argument collapses with it."""
    reachable = check_skill_workshop_autonomy(_ctx({}, MODERN))
    dormant = check_skill_workshop_autonomy(
        _ctx({"tools": {"profile": "minimal"}}, MODERN))
    assert reachable.status == FAIL
    assert dormant.status == WARN
    assert "not currently reachable" in (dormant.detail or "")


# ------------------------------------------------- what the C-135 pass caught

@pytest.mark.parametrize("value", ["zzz", 3, True, None, ["auto"], {"a": 1}],
                         ids=["junk-string", "int", "bool", "null", "list", "dict"])
def test_an_unrecognised_mode_resolves_to_the_build_default_not_to_off(value):
    """`readAutonomousMode(value, fallback)` keeps ONLY "off"/"propose"/"auto" and falls
    back otherwise, so a value the enum does not recognise leaves the DEFAULT in effect.

    The first version of this fix read any string as authoritative, so `mode: "zzz"`
    answered "not enabled" where the runtime answers "auto" — a false negative, and the
    dangerous direction. Found by the type-confusion pass, not by the happy-path tests.
    """
    cfg = _workshop(mode=value)
    assert check_skill_workshop_autonomy(_ctx(cfg, MODERN)).status == FAIL


@pytest.mark.parametrize("cfg", [
    {"skills": "nope"},
    {"skills": {"workshop": "nope"}},
    {"skills": {"workshop": [1]}},
    {"skills": {"workshop": {"autonomous": [1]}}},
    {"skills": {"workshop": {"autonomous": "auto"}}},
    {"skills": {"workshop": {"approvalPolicy": 7}}},
], ids=["skills-str", "workshop-str", "workshop-list", "autonomous-list",
        "autonomous-str", "policy-int"])
def test_malformed_shapes_resolve_to_the_default_without_crashing(cfg):
    """Every one of these is a shape OpenClaw itself coerces to the default. None may
    crash, and none may invent a clean verdict."""
    r = check_skill_workshop_autonomy(_ctx(cfg, MODERN))
    assert r.status == FAIL


# ------------------------------------------------- the false FAIL this change would have created

_DENY = {"tools": {"deny": ["skill_workshop"]}}


@pytest.mark.parametrize("roster,live", [
    ({"a": _DENY}, False),
    ({"a": _DENY, "b": _DENY}, False),
    ({"a": _DENY, "b": {}}, True),
    ({"a": {}, "b": {}}, True),
], ids=["one-denies", "all-deny", "one-of-two-denies", "none-deny"])
def test_the_pipeline_is_dormant_only_when_every_agent_blocks_the_tool(roster, live):
    """The runtime resolves the capability profile per session and per AGENT, so one
    agent's deny says nothing about the others — while all of them together do.

    Before B-702 this only looked at a SOLE declared agent, which was conservative in the
    safe direction while the check fired on an explicit opt-in. Firing on the 2026.8.1
    DEFAULTS turns that conservatism into a false FAIL for a fleet whose agents all deny
    the tool, and Golden Rule #5 makes a false FAIL a blocker.
    """
    cfg = {"agents": {"entries": roster}}
    r = check_skill_workshop_autonomy(_ctx(cfg, MODERN))
    assert r.status == (FAIL if live else WARN)
    assert ("not currently reachable" in (r.detail or "")) is not live


# ------------------------------------------------- the config that was never read

def test_no_config_at_all_is_unknown_not_a_high_fail():
    """B175's default leg reasons from the INSTALLED BUILD when the keys are absent. On a
    home with no openclaw.json every key is absent, so it produced a HIGH FAIL about a
    config the run never saw — the fabricated verdict test_b585_sarif_layer_state.py
    forbids, and it was firing through the real CLI (measured: failCount 1 on an empty
    directory).

    `scoring._config_blind_signal` already settles the principle: unparseable (B-306) and
    genuinely absent (B-363) are "the same real-world fact". This is that rule applied
    here, not a new one.
    """
    f = check_skill_workshop_autonomy(_ctx({}, MODERN, config_found=False))
    assert f.status == UNKNOWN
    assert "No openclaw.json was found" in (f.detail or "")


def test_the_absent_case_still_teaches_the_dangerous_default():
    """Bailing to UNKNOWN must not become silence. A reader with no config still needs the
    fact that a stock 2026.8.1 authors and installs unattended — they are just not told it
    as a verdict about a setup that was never read."""
    detail = check_skill_workshop_autonomy(_ctx({}, MODERN, config_found=False)).detail or ""
    assert "2026.8.1" in detail
    assert "unattended" in detail


def test_an_empty_config_that_WAS_read_keeps_its_fail():
    """The control, and the whole reason the guard is compound. A home with a literal `{}`
    on disk was genuinely read; those defaults really are in force there. Without this,
    "always UNKNOWN when the config is empty" satisfies the two tests above and silently
    undoes B-702 for every user whose config does not mention the workshop."""
    f = check_skill_workshop_autonomy(_ctx({}, MODERN, config_found=True))
    assert f.status == FAIL
    assert "DEFAULT, not something set here" in (f.detail or "")
