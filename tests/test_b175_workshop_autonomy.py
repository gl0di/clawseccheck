"""B175: Skill Workshop autonomous authoring + no-review install.

Real OpenClaw schema (grounded 2026-07-18, dist config-XlfFMqhc.js
resolveSkillWorkshopConfig + zod-schema-O9ml_nmo.js:1510-1516):
  skills.workshop.autonomous.enabled        bool,              default false
  skills.workshop.approvalPolicy            "pending" | "auto", default "pending"
  skills.workshop.allowSymlinkTargetWrites  bool,              default false

Spec correction: the originating bug report assumed approvalPolicy and
allowSymlinkTargetWrites were nested under .autonomous, and assumed a "manual" policy
value. Neither is true — see docs/research/openclaw-schema-recon.md §18 (workspace
root, not shipped) for the full grounding trail.

FAIL only when BOTH autonomous.enabled=true AND approvalPolicy="auto" (the full
auto-author + auto-install pipeline with zero human review at either stage). WARN when
exactly one of the three risky fields is set. PASS on the safe default. UNKNOWN only on
an unparseable/unreadable openclaw.json — never on an absent skills.workshop key, which
is a real, safe, fully-defaulted state.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_skill_workshop_autonomy
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict, parse_error: bool = False) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.config_parse_error = parse_error
    return c


# ---------------------------------------------------------------------------
# FAIL: the full auto-author + auto-install pipeline
# ---------------------------------------------------------------------------

def test_autonomous_enabled_and_approval_auto_fails():
    cfg = {"skills": {"workshop": {"autonomous": {"enabled": True}, "approvalPolicy": "auto"}}}
    r = check_skill_workshop_autonomy(_ctx(cfg))
    assert r.status == FAIL
    assert any("autonomous.enabled=true" in e for e in r.evidence)
    assert any('approvalPolicy="auto"' in e for e in r.evidence)


def test_bad_fixture_fails():
    r = check_skill_workshop_autonomy(collect(FIXTURES / "bad_b175_workshop_auto_pipeline"))
    assert r.status == FAIL


# ---------------------------------------------------------------------------
# B-239: enabled+auto but skill_workshop is unreachable -> WARN, not FAIL
#
# Grounded in openclaw 2026.7.1 dist: openclaw-tools-KulZ1cdH.js:14415 omits the
# skill_workshop tool outright for sandboxed sessions; status-message-CQq9FqoB.js:73
# makes agents.defaults.sandbox.mode=="all" unconditionally sandboxed; tool-policy-
# BHUGxE3p.js / effective-tool-policy-CRZGJ2R3.js run tools.deny/tools.allow (global
# and per-agent) as narrowing pipeline filters; tool-catalog-C8xbUFNe.js gives
# skill_workshop profiles=["coding"] only, so "minimal"/"messaging" omit it.
# ---------------------------------------------------------------------------

def test_sandboxed_fixture_warns_not_fails():
    """The PRIMARY reported case (B-239): a fully-sandboxed fleet
    (agents.defaults.sandbox.mode="all") never constructs the skill_workshop tool at
    all, so the config can't run the pipeline it superficially declares."""
    r = check_skill_workshop_autonomy(collect(FIXTURES / "bad_b175_workshop_sandboxed_warn"))
    assert r.status == WARN
    assert any("unreachable" in e for e in r.evidence)


def test_global_tools_deny_warns_not_fails():
    cfg = {
        "tools": {"deny": ["skill_workshop", "exec", "browser"]},
        "skills": {"workshop": {"autonomous": {"enabled": True}, "approvalPolicy": "auto"}},
    }
    r = check_skill_workshop_autonomy(_ctx(cfg))
    assert r.status == WARN


def test_sole_agent_strict_allowlist_warns_not_fails():
    cfg = {
        "agents": {"list": [{"id": "main", "tools": {"allow": ["read", "grep", "find", "ls"]}}]},
        "skills": {"workshop": {"autonomous": {"enabled": True}, "approvalPolicy": "auto"}},
    }
    r = check_skill_workshop_autonomy(_ctx(cfg))
    assert r.status == WARN


def test_minimal_profile_warns_not_fails():
    cfg = {
        "tools": {"profile": "minimal"},
        "skills": {"workshop": {"autonomous": {"enabled": True}, "approvalPolicy": "auto"}},
    }
    r = check_skill_workshop_autonomy(_ctx(cfg))
    assert r.status == WARN


def test_messaging_profile_warns_not_fails():
    cfg = {
        "tools": {"profile": "messaging"},
        "skills": {"workshop": {"autonomous": {"enabled": True}, "approvalPolicy": "auto"}},
    }
    r = check_skill_workshop_autonomy(_ctx(cfg))
    assert r.status == WARN


# ---------------------------------------------------------------------------
# Anti-FN guardrails: don't let the reachability gate hide a genuinely live pipeline
# ---------------------------------------------------------------------------

def test_unrecognized_profile_value_still_fails():
    """"readonly" is NOT a real tools.profile literal anywhere in the OpenClaw dist
    (register-CvPzWKo8.js SUPPORTED_TOOL_PROFILES is exactly
    {minimal, coding, messaging, full}) — an unrecognized profile string does not
    restrict the tool set at all, so it must not be treated as neutralizing."""
    cfg = {
        "tools": {"profile": "readonly"},
        "skills": {"workshop": {"autonomous": {"enabled": True}, "approvalPolicy": "auto"}},
    }
    r = check_skill_workshop_autonomy(_ctx(cfg))
    assert r.status == FAIL


def test_coding_and_full_profiles_still_fail():
    """Both real profiles that DO include skill_workshop must not be misread as
    neutralizing."""
    for profile in ("coding", "full"):
        cfg = {
            "tools": {"profile": profile},
            "skills": {"workshop": {"autonomous": {"enabled": True}, "approvalPolicy": "auto"}},
        }
        r = check_skill_workshop_autonomy(_ctx(cfg))
        assert r.status == FAIL, profile


def test_multi_agent_restriction_stays_ambiguous_and_fails():
    """A restrictive allowlist on ONE of several declared agents doesn't prove the
    tool is unreachable fleet-wide (another agent may still reach it) — stay
    conservative and keep FAIL rather than guess an unmodeled multi-agent scope."""
    cfg = {
        "agents": {
            "list": [
                {"id": "restricted", "tools": {"allow": ["read", "grep"]}},
                {"id": "unrestricted"},
            ]
        },
        "skills": {"workshop": {"autonomous": {"enabled": True}, "approvalPolicy": "auto"}},
    }
    r = check_skill_workshop_autonomy(_ctx(cfg))
    assert r.status == FAIL


def test_dangerous_baseline_no_neutralizing_signal_still_fails():
    """No sandbox, no deny/allow, no profile restriction at all -- the genuinely
    dangerous case the check exists to catch."""
    cfg = {"skills": {"workshop": {"autonomous": {"enabled": True}, "approvalPolicy": "auto"}}}
    r = check_skill_workshop_autonomy(_ctx(cfg))
    assert r.status == FAIL


# ---------------------------------------------------------------------------
# WARN: exactly one risky field set (a partial gap, not the full pipeline)
# ---------------------------------------------------------------------------

def test_autonomous_enabled_alone_warns():
    """autonomous authoring on, but approvalPolicy stays at the safe "pending" default —
    proposals are still review-gated before install."""
    cfg = {"skills": {"workshop": {"autonomous": {"enabled": True}}}}
    r = check_skill_workshop_autonomy(_ctx(cfg))
    assert r.status == WARN
    assert any("autonomous.enabled=true" in e for e in r.evidence)


def test_approval_auto_alone_warns():
    """approvalPolicy="auto" with autonomous authoring off — a manually-created proposal
    still installs without a human confirmation step."""
    cfg = {"skills": {"workshop": {"approvalPolicy": "auto"}}}
    r = check_skill_workshop_autonomy(_ctx(cfg))
    assert r.status == WARN
    assert any('approvalPolicy="auto"' in e for e in r.evidence)


def test_symlink_target_writes_alone_warns():
    cfg = {"skills": {"workshop": {"allowSymlinkTargetWrites": True}}}
    r = check_skill_workshop_autonomy(_ctx(cfg))
    assert r.status == WARN
    assert any("allowSymlinkTargetWrites=true" in e for e in r.evidence)


# ---------------------------------------------------------------------------
# PASS: safe default (disabled / explicit "pending")
# ---------------------------------------------------------------------------

def test_no_skills_key_at_all_passes():
    """An absent skills.workshop key resolves to the safe defaults per
    resolveSkillWorkshopConfig — this must be PASS, never UNKNOWN (Golden Rule #4 cuts
    both ways: an absent-but-defaulted field is a known-safe state, not an unknown one)."""
    r = check_skill_workshop_autonomy(_ctx({}))
    assert r.status == PASS


def test_autonomous_disabled_passes():
    cfg = {"skills": {"workshop": {"autonomous": {"enabled": False}}}}
    r = check_skill_workshop_autonomy(_ctx(cfg))
    assert r.status == PASS


def test_explicit_pending_policy_passes():
    """approvalPolicy explicitly set to the real, safe default literal "pending" (the
    bug report's assumed value "manual" is not a real schema literal — see recon §18.2)."""
    cfg = {"skills": {"workshop": {"autonomous": {"enabled": False}, "approvalPolicy": "pending"}}}
    r = check_skill_workshop_autonomy(_ctx(cfg))
    assert r.status == PASS


def test_unrecognized_policy_value_falls_back_to_pending_and_passes():
    """readApprovalPolicy() only special-cases the literal "auto" — any other string
    (including a typo or the report's fictional "manual") resolves to the safe default,
    never to an escalated state."""
    cfg = {"skills": {"workshop": {"approvalPolicy": "manual"}}}
    r = check_skill_workshop_autonomy(_ctx(cfg))
    assert r.status == PASS


def test_clean_fixture_disabled_passes():
    r = check_skill_workshop_autonomy(collect(FIXTURES / "clean_b175_workshop_disabled"))
    assert r.status == PASS


def test_clean_fixture_pending_reviewed_passes():
    r = check_skill_workshop_autonomy(collect(FIXTURES / "clean_b175_workshop_pending_reviewed"))
    assert r.status == PASS


# ---------------------------------------------------------------------------
# UNKNOWN: config genuinely unreadable (never a fake PASS/FAIL)
# ---------------------------------------------------------------------------

def test_unparseable_config_is_unknown():
    r = check_skill_workshop_autonomy(_ctx({}, parse_error=True))
    assert r.status == UNKNOWN
