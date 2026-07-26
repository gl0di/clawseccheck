"""B327: agents.defaults.embeddedAgent.projectSettingsPolicy trusts workspace settings.

Grounded against the installed OpenClaw dist (2026-07-25): the only real config path
is "agents.defaults.embeddedAgent.projectSettingsPolicy" -- a single global toggle,
NOT a per-agent "agents.*.embeddedAgent..." glob (agents.list[].embeddedAgent is a
separately-declared, .strict() Zod schema that only recognizes "executionContract").
See clawseccheck/checks/_agents.py's check_embedded_agent_project_settings_policy
docstring for the full grounding trail (attempt.model-diagnostic-events-CfZQM0hs.js
:91-219, sessions-D8qGY7uC.js:11067-11078/11198-11206, selection-JInn13lc.js
:12499-12505).

Severity shape (note: unlike B38/B196, this field's vendor default on ABSENCE is the
SAFE state "sanitize" -- resolveEmbeddedAgentProjectSettingsPolicy() falls back to it
for absence, a typo, or any non-matching value alike):
  - no config file at all                                        -> UNKNOWN
  - config present but unparseable                                -> UNKNOWN
  - projectSettingsPolicy == "trusted"                             -> FAIL
  - projectSettingsPolicy == "sanitize" or "ignore"                -> PASS
  - projectSettingsPolicy absent                                   -> PASS
  - projectSettingsPolicy holds an unrecognized/garbage value      -> PASS
  - embeddedAgent block present but projectSettingsPolicy absent   -> PASS
  - agents.defaults present but embeddedAgent absent               -> PASS
  - agents block entirely absent                                   -> PASS
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_embedded_agent_project_settings_policy
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _home(tmp_path: Path, config: dict | None = None) -> Path:
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    if config is not None:
        (home / "openclaw.json").write_text(json.dumps(config), encoding="utf-8")
    return home


def test_clean_fixture_passes():
    r = check_embedded_agent_project_settings_policy(
        collect(FIXTURES / "clean_b327_embedded_agent_project_settings_policy")
    )
    assert r.status == PASS
    assert "sanitize" in r.detail


def test_bad_fixture_fails():
    r = check_embedded_agent_project_settings_policy(
        collect(FIXTURES / "bad_b327_embedded_agent_project_settings_policy")
    )
    assert r.status == FAIL
    assert "trusted" in r.detail
    assert "shellCommandPrefix" in r.detail or "shellPath" in r.detail


def test_no_config_file_is_unknown(tmp_path):
    home = _home(tmp_path, config=None)
    r = check_embedded_agent_project_settings_policy(collect(home))
    assert r.status == UNKNOWN


def test_unparseable_config_is_unknown(tmp_path):
    home = _home(tmp_path)
    (home / "openclaw.json").write_text("{not valid json,,,", encoding="utf-8")
    r = check_embedded_agent_project_settings_policy(collect(home))
    assert r.status == UNKNOWN


def test_agents_block_entirely_absent_is_pass(tmp_path):
    home = _home(tmp_path, config={"tools": {"profile": "minimal"}})
    r = check_embedded_agent_project_settings_policy(collect(home))
    assert r.status == PASS


def test_agents_defaults_present_embedded_agent_absent_is_pass(tmp_path):
    home = _home(tmp_path, config={"agents": {"defaults": {"sandbox": {"mode": "all"}}}})
    r = check_embedded_agent_project_settings_policy(collect(home))
    assert r.status == PASS


def test_embedded_agent_block_present_policy_absent_is_pass(tmp_path):
    home = _home(
        tmp_path,
        config={"agents": {"defaults": {"embeddedAgent": {}}}},
    )
    r = check_embedded_agent_project_settings_policy(collect(home))
    assert r.status == PASS


def test_policy_explicit_sanitize_is_pass(tmp_path):
    home = _home(
        tmp_path,
        config={
            "agents": {
                "defaults": {"embeddedAgent": {"projectSettingsPolicy": "sanitize"}}
            }
        },
    )
    r = check_embedded_agent_project_settings_policy(collect(home))
    assert r.status == PASS
    assert "stripped" in r.detail


def test_policy_explicit_ignore_is_pass(tmp_path):
    home = _home(
        tmp_path,
        config={
            "agents": {
                "defaults": {"embeddedAgent": {"projectSettingsPolicy": "ignore"}}
            }
        },
    )
    r = check_embedded_agent_project_settings_policy(collect(home))
    assert r.status == PASS
    assert "not applied" in r.detail


def test_policy_explicit_trusted_is_fail(tmp_path):
    home = _home(
        tmp_path,
        config={
            "agents": {
                "defaults": {"embeddedAgent": {"projectSettingsPolicy": "trusted"}}
            }
        },
    )
    r = check_embedded_agent_project_settings_policy(collect(home))
    assert r.status == FAIL


def test_policy_unrecognized_string_value_is_pass_not_warn(tmp_path):
    """Adversarial edge case: a garbage/typo'd value resolves to OpenClaw's own safe
    "sanitize" fallback per resolveEmbeddedAgentProjectSettingsPolicy() -- this must
    NOT be treated the way an absent *permissive*-default field would be (WARN), since
    the fallback here is safe, not dangerous. This is the one branch most likely to be
    mis-modeled by copying the B38/B196 "absent -> WARN" precedent verbatim."""
    home = _home(
        tmp_path,
        config={
            "agents": {
                "defaults": {"embeddedAgent": {"projectSettingsPolicy": "trust-all"}}
            }
        },
    )
    r = check_embedded_agent_project_settings_policy(collect(home))
    assert r.status == PASS
    assert r.status != WARN


def test_policy_wrong_type_is_pass(tmp_path):
    """Adversarial edge case: a non-string value (e.g. boolean true, perhaps from a
    confused operator expecting a boolean toggle) also fails the resolver's strict
    string-literal equality check and falls back to the safe default -- must not FAIL."""
    home = _home(
        tmp_path,
        config={
            "agents": {"defaults": {"embeddedAgent": {"projectSettingsPolicy": True}}}
        },
    )
    r = check_embedded_agent_project_settings_policy(collect(home))
    assert r.status == PASS


def test_no_per_agent_variant_is_not_consulted(tmp_path):
    """Grounding correction: agents.list[].embeddedAgent.projectSettingsPolicy is not
    a real schema field (that per-agent schema is .strict() and only recognizes
    executionContract) -- a value planted there must not be read by this check, and
    the global default (safe "sanitize") must still govern."""
    home = _home(
        tmp_path,
        config={
            "agents": {
                "list": [
                    {
                        "name": "Gary",
                        "embeddedAgent": {"projectSettingsPolicy": "trusted"},
                    }
                ]
            }
        },
    )
    r = check_embedded_agent_project_settings_policy(collect(home))
    assert r.status == PASS


def test_evidence_is_worst_case_not_best_case(tmp_path):
    """A single global toggle set to the dangerous value must FAIL even alongside an
    otherwise hardened agents.defaults block (sandboxing on, etc.) -- the finding must
    not be diluted by unrelated hardening elsewhere in the same block."""
    home = _home(
        tmp_path,
        config={
            "agents": {
                "defaults": {
                    "sandbox": {"mode": "all"},
                    "embeddedAgent": {"projectSettingsPolicy": "trusted"},
                }
            }
        },
    )
    r = check_embedded_agent_project_settings_policy(collect(home))
    assert r.status == FAIL


def test_fix_text_names_both_safe_values(tmp_path):
    home = _home(
        tmp_path,
        config={
            "agents": {
                "defaults": {"embeddedAgent": {"projectSettingsPolicy": "trusted"}}
            }
        },
    )
    r = check_embedded_agent_project_settings_policy(collect(home))
    assert "sanitize" in r.fix
    assert "ignore" in r.fix
