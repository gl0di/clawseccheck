"""B8 — human approval gate for destructive/outbound tools.

Verdicts:
  UNKNOWN : no destructive/outbound tool detected in config
  WARN    : destructive tool present, no approval gate
  PASS    : destructive tool present AND an approval gate is configured
  (no FAIL)
"""
from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import _has_approval_gate, check_human_approval
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


# ---- UNKNOWN: no destructive/outbound tools detectable ----

def test_b08_empty_config_unknown():
    assert check_human_approval(_ctx({})).status == UNKNOWN


def test_b08_non_destructive_tool_in_allow_unknown():
    # read_file has no overlap with OUTBOUND_TOOL_HINTS -> not counted destructive
    assert check_human_approval(_ctx({"tools": {"allow": ["read_file"]}})).status == UNKNOWN


# ---- WARN: destructive tool present, no gate ----

def test_b08_exec_mode_full_no_gate_warns():
    # mode="full" enables exec (exec_mode not None -> tools=['exec']), but 'full'
    # is NOT a gate (only deny/allowlist/ask/auto are gated).
    f = check_human_approval(_ctx({"tools": {"exec": {"mode": "full"}}}))
    assert f.status == WARN


def test_b08_exec_security_full_no_gate_warns():
    # security="full" enables exec but is not a gate ("deny"/"ask" only)
    f = check_human_approval(_ctx({"tools": {"exec": {"security": "full"}}}))
    assert f.status == WARN


def test_b08_tools_allow_exec_no_mode_set_warns():
    # exec listed in tools.allow; no tools.exec.mode/security gate -> WARN
    f = check_human_approval(_ctx({"tools": {"allow": ["exec"]}}))
    assert f.status == WARN


def test_b08_tools_allow_shell_no_gate_warns():
    # "shell" is in OUTBOUND_TOOL_HINTS; no gate
    f = check_human_approval(_ctx({"tools": {"allow": ["shell"]}}))
    assert f.status == WARN


# ---- PASS: destructive tool + explicit approval gate ----

def test_b08_exec_mode_ask_passes():
    f = check_human_approval(_ctx({"tools": {"exec": {"mode": "ask"}}}))
    assert f.status == PASS


def test_b08_exec_mode_deny_passes():
    assert check_human_approval(_ctx({"tools": {"exec": {"mode": "deny"}}})).status == PASS


def test_b08_exec_mode_allowlist_passes():
    assert check_human_approval(_ctx({"tools": {"exec": {"mode": "allowlist"}}})).status == PASS


def test_b08_exec_mode_auto_passes():
    # "auto" is documented as a gate (auto-reviewer, not ungated 'full')
    assert check_human_approval(_ctx({"tools": {"exec": {"mode": "auto"}}})).status == PASS


def test_b08_exec_security_deny_passes():
    assert check_human_approval(_ctx({"tools": {"exec": {"security": "deny"}}})).status == PASS


def test_b08_exec_security_allowlist_passes():
    # CLAWSECCHECK-B-412: tools.exec.security's real enum (grounded against the
    # installed OpenClaw dist's Zod schema) is deny/allowlist/full — "allowlist" is a
    # real, gate-providing value that was previously missing from _has_approval_gate.
    assert check_human_approval(
        _ctx({"tools": {"exec": {"security": "allowlist"}}})).status == PASS


def test_b08_exec_security_ask_is_not_a_valid_security_value_warns():
    # CLAWSECCHECK-B-412 fixture-drift fix: "ask" was NEVER a valid tools.exec.security
    # value (that enum is deny/allowlist/full; "ask" belongs to the separate
    # tools.exec.ask field). This test used to assert PASS, which was pinning the bug
    # itself. An unrecognized security string must warn exactly like "full" does
    # (test_b08_exec_security_full_no_gate_warns) — it must not be specially truthy.
    f = check_human_approval(_ctx({"tools": {"exec": {"security": "ask"}}}))
    assert f.status == WARN


def test_b08_exec_ask_field_on_miss_passes():
    # tools.exec.ask = "on-miss" is also a gate
    assert check_human_approval(
        _ctx({"tools": {"exec": {"mode": "full", "ask": "on-miss"}}})).status == PASS


def test_b08_exec_ask_field_always_passes():
    assert check_human_approval(
        _ctx({"tools": {"exec": {"mode": "full", "ask": "always"}}})).status == PASS


# ---- B-130: powerful tools.profile (e.g. "coding") is detected as exec even ----
# ---- with no explicit tools.exec.* fields set (feature-detection blind spot: ----
# ---- _enabled_tools() used to only match a literal "exec" substring in ----
# ---- tools.profile, missing "coding"). ----

def test_b08_coding_profile_no_exec_fields_warns():
    f = check_human_approval(_ctx({"tools": {"profile": "coding"}}))
    assert f.status == WARN


def test_b08_minimal_profile_stays_unknown():
    # Regression: a genuinely minimal profile must NOT be treated as exec-capable.
    f = check_human_approval(_ctx({"tools": {"profile": "minimal"}}))
    assert f.status == UNKNOWN


def test_b08_bad_fixture_coding_profile_warns():
    f = check_human_approval(collect(FIXTURES / "bad_b130_coding_profile_no_exec_fields"))
    assert f.status == WARN, f"Expected WARN, got {f.status}: {f.detail}"


def test_b08_clean_fixture_minimal_unknown():
    f = check_human_approval(collect(FIXTURES / "clean_b130_minimal_no_capability"))
    assert f.status == UNKNOWN, f"Expected UNKNOWN, got {f.status}: {f.detail}"


# ---- never FAIL ----

def test_b08_never_fail():
    for cfg in (
        {},
        {"tools": {"exec": {"mode": "full"}}},
        {"tools": {"exec": {"mode": "ask"}}},
        {"tools": {"allow": ["exec"]}},
        {"tools": {"allow": ["read_file"]}},
    ):
        assert check_human_approval(_ctx(cfg)).status != FAIL, f"unexpected FAIL for {cfg}"


# ---- CLAWSECCHECK-B-412: _has_approval_gate direct unit tests ----
#
# tools.exec.security's real Zod enum (grounded against the installed OpenClaw
# dist, zod-schema.agent-runtime-C02vY4RT.js:372-376) is deny/allowlist/full.
# "ask" was never a valid value of this field (it belongs to the separate
# tools.exec.ask field, off/on-miss/always) and must not be specially truthy.

def test_has_approval_gate_security_allowlist_alone_is_true():
    # Direct repro from the bug report: security="allowlist" with no mode and no
    # ask field must be recognized as a real gate.
    assert _has_approval_gate({"tools": {"exec": {"security": "allowlist"}}}) is True


def test_has_approval_gate_security_ask_alone_is_false():
    # "ask" is not a valid tools.exec.security value; it must be treated like any
    # other unrecognized string (e.g. "full"), not specially truthy.
    assert _has_approval_gate({"tools": {"exec": {"security": "ask"}}}) is False


def test_has_approval_gate_security_deny_alone_is_true():
    assert _has_approval_gate({"tools": {"exec": {"security": "deny"}}}) is True


def test_has_approval_gate_security_full_alone_is_false():
    assert _has_approval_gate({"tools": {"exec": {"security": "full"}}}) is False


def test_has_approval_gate_security_garbage_string_is_false():
    # Any other unrecognized security value (not one of the three real enum members)
    # must not be treated as a gate either.
    assert _has_approval_gate({"tools": {"exec": {"security": "sandbox"}}}) is False
