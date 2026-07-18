"""B174 (B-238): security.installPolicy.* operator install gate + its exec-hook escape
flags.

Distinct from B42 (which only scans a skill's own postinstall hook CONTENT + skill-dir
perms). B174 reads the operator-facing GATE itself: security.installPolicy.{enabled,
exec:{allowInsecurePath, allowSymlinkCommand, passEnv}}, grounded against the installed
OpenClaw dist (zod-schema-O9ml_nmo.js:670, install-policy-Barp1EUw.js resolvePolicy()/
assertSecureCommandPath(), types.openclaw-CXjMEWAQ.d.ts:1597).

Severity shape (C-135 adversarial pass, zero-FP-FAIL doctrine):
  - not enabled (absent key OR enabled=false)              -> WARN (a common/deliberate
    posture on most real hosts, never positive evidence of an active vulnerability)
  - enabled + exec.allowInsecurePath/allowSymlinkCommand    -> FAIL (literal, unambiguous
    escape booleans that bypass a real path-safety check)
  - enabled + secret-shaped exec.passEnv name(s), no escape -> WARN (heuristic on an env
    var NAME, not a value -- a legitimate install-policy script may need e.g. NPM_TOKEN)
  - enabled + benign/absent exec, no danger signal          -> PASS

Offline, deterministic — builds a fake OpenClaw home under tmp_path, plus three on-disk
fixtures (fixtures/clean_b174_installpolicy_gated,
fixtures/bad_b174_installpolicy_allow_insecure_path,
fixtures/bad_b174_installpolicy_disabled).
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_install_policy_gate
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _home(tmp_path: Path, config: dict | None = None, filename: str = "openclaw.json") -> Path:
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    if config is not None:
        (home / filename).write_text(json.dumps(config), encoding="utf-8")
    return home


# ---------------------------------------------------------------------------
# On-disk fixtures
# ---------------------------------------------------------------------------

def test_clean_fixture_passes():
    r = check_install_policy_gate(collect(FIXTURES / "clean_b174_installpolicy_gated"))
    assert r.status == PASS


def test_bad_fixture_allow_insecure_path_fails():
    r = check_install_policy_gate(
        collect(FIXTURES / "bad_b174_installpolicy_allow_insecure_path")
    )
    assert r.status == FAIL
    assert any("allowInsecurePath" in e for e in r.evidence)


def test_bad_fixture_disabled_warns():
    r = check_install_policy_gate(collect(FIXTURES / "bad_b174_installpolicy_disabled"))
    assert r.status == WARN


# ---------------------------------------------------------------------------
# UNKNOWN paths — never a guess FAIL (GR#5)
# ---------------------------------------------------------------------------

def test_no_config_found_is_unknown(tmp_path):
    home = _home(tmp_path, config=None)
    r = check_install_policy_gate(collect(home))
    assert r.status == UNKNOWN


def test_unparseable_config_is_unknown(tmp_path):
    home = _home(tmp_path, config=None)
    (home / "openclaw.json").write_text("{not valid json", encoding="utf-8")
    r = check_install_policy_gate(collect(home))
    assert r.status == UNKNOWN


# ---------------------------------------------------------------------------
# WARN: not enabled (absent key vs explicit false — same real-world effect)
# ---------------------------------------------------------------------------

def test_installpolicy_key_entirely_absent_warns(tmp_path):
    home = _home(tmp_path, config={"tools": {"profile": "minimal"}})
    r = check_install_policy_gate(collect(home))
    assert r.status == WARN
    assert "not enabled" in r.detail


def test_installpolicy_enabled_false_warns(tmp_path):
    home = _home(tmp_path, config={"security": {"installPolicy": {"enabled": False}}})
    r = check_install_policy_gate(collect(home))
    assert r.status == WARN


def test_installpolicy_enabled_non_bool_truthy_still_warns(tmp_path):
    # Only a literal `true` counts (matches OpenClaw's own `policy.enabled !== true`
    # runtime check) -- a stray string/number is NOT enabled either.
    home = _home(tmp_path, config={"security": {"installPolicy": {"enabled": "yes"}}})
    r = check_install_policy_gate(collect(home))
    assert r.status == WARN


# ---------------------------------------------------------------------------
# PASS: enabled, no exec configured -> fails closed at runtime, nothing to assess
# ---------------------------------------------------------------------------

def test_enabled_with_no_exec_passes(tmp_path):
    home = _home(tmp_path, config={"security": {"installPolicy": {"enabled": True}}})
    r = check_install_policy_gate(collect(home))
    assert r.status == PASS


# ---------------------------------------------------------------------------
# FAIL: the two literal escape booleans (positive evidence)
# ---------------------------------------------------------------------------

def test_allow_insecure_path_true_fails(tmp_path):
    home = _home(tmp_path, config={"security": {"installPolicy": {
        "enabled": True,
        "exec": {
            "source": "exec",
            "command": "/opt/policy/check.sh",
            "allowInsecurePath": True,
        },
    }}})
    r = check_install_policy_gate(collect(home))
    assert r.status == FAIL
    assert any("allowInsecurePath" in e for e in r.evidence)


def test_allow_symlink_command_true_fails(tmp_path):
    home = _home(tmp_path, config={"security": {"installPolicy": {
        "enabled": True,
        "exec": {
            "source": "exec",
            "command": "/opt/policy/check.sh",
            "allowSymlinkCommand": True,
        },
    }}})
    r = check_install_policy_gate(collect(home))
    assert r.status == FAIL
    assert any("allowSymlinkCommand" in e for e in r.evidence)


def test_both_escape_flags_false_is_not_fail(tmp_path):
    home = _home(tmp_path, config={"security": {"installPolicy": {
        "enabled": True,
        "exec": {
            "source": "exec",
            "command": "/opt/policy/check.sh",
            "allowInsecurePath": False,
            "allowSymlinkCommand": False,
        },
    }}})
    r = check_install_policy_gate(collect(home))
    assert r.status == PASS


# ---------------------------------------------------------------------------
# WARN: secret-shaped passEnv name(s) — heuristic on the NAME, never FAIL
# ---------------------------------------------------------------------------

def test_secret_shaped_passenv_warns(tmp_path):
    home = _home(tmp_path, config={"security": {"installPolicy": {
        "enabled": True,
        "exec": {
            "source": "exec",
            "command": "/opt/policy/check.sh",
            "passEnv": ["PATH", "NPM_TOKEN"],
        },
    }}})
    r = check_install_policy_gate(collect(home))
    assert r.status == WARN
    assert any("NPM_TOKEN" in e for e in r.evidence)


def test_benign_passenv_names_pass(tmp_path):
    home = _home(tmp_path, config={"security": {"installPolicy": {
        "enabled": True,
        "exec": {
            "source": "exec",
            "command": "/opt/policy/check.sh",
            "passEnv": ["PATH", "HOME", "LANG"],
        },
    }}})
    r = check_install_policy_gate(collect(home))
    assert r.status == PASS


def test_escape_flag_beats_passenv_secret_still_fail(tmp_path):
    """When BOTH a FAIL-level escape flag and a WARN-level secret-passEnv are present,
    the finding surfaces at FAIL (the stronger, positive-evidence signal wins)."""
    home = _home(tmp_path, config={"security": {"installPolicy": {
        "enabled": True,
        "exec": {
            "source": "exec",
            "command": "/opt/policy/check.sh",
            "allowInsecurePath": True,
            "passEnv": ["AWS_SECRET_ACCESS_KEY"],
        },
    }}})
    r = check_install_policy_gate(collect(home))
    assert r.status == FAIL


# ---------------------------------------------------------------------------
# Never a false-positive FAIL on a merely-narrow (but safe) target list
# ---------------------------------------------------------------------------

def test_narrow_targets_list_does_not_affect_verdict(tmp_path):
    home = _home(tmp_path, config={"security": {"installPolicy": {
        "enabled": True,
        "targets": ["skill"],
        "exec": {
            "source": "exec",
            "command": "/opt/policy/check.sh",
        },
    }}})
    r = check_install_policy_gate(collect(home))
    assert r.status == PASS
