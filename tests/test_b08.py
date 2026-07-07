"""B8 — human approval gate for destructive/outbound tools.

Verdicts:
  UNKNOWN : no destructive/outbound tool detected in config
  WARN    : destructive tool present, no approval gate
  PASS    : destructive tool present AND an approval gate is configured
  (no FAIL)
"""
from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_human_approval
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


def test_b08_exec_security_ask_passes():
    assert check_human_approval(_ctx({"tools": {"exec": {"security": "ask"}}})).status == PASS


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
