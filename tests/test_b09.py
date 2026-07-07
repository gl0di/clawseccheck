"""B9 — sensitive-data redaction in tool output / logs (check_leak).

Verdicts:
  PASS : logging.redactSensitive == "tools"
  FAIL : logging.redactSensitive == "off"
  WARN : field absent (None) OR unexpected value
  (no UNKNOWN)
"""
from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_leak
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


# ---- PASS ----

def test_b09_redact_tools_passes():
    f = check_leak(_ctx({"logging": {"redactSensitive": "tools"}}))
    assert f.status == PASS


# ---- FAIL ----

def test_b09_redact_off_fails():
    f = check_leak(_ctx({"logging": {"redactSensitive": "off"}}))
    assert f.status == FAIL
    assert "off" in f.detail.lower() or "redact" in f.detail.lower()


# ---- WARN: field absent ----

def test_b09_field_absent_warns():
    # logging key missing entirely
    assert check_leak(_ctx({})).status == WARN


def test_b09_logging_present_but_field_absent_warns():
    # logging dict exists but redactSensitive is not set
    assert check_leak(_ctx({"logging": {}})).status == WARN


# ---- WARN: unexpected value ----

def test_b09_unexpected_value_all_warns():
    f = check_leak(_ctx({"logging": {"redactSensitive": "all"}}))
    assert f.status == WARN


def test_b09_unexpected_value_full_warns():
    assert check_leak(_ctx({"logging": {"redactSensitive": "full"}})).status == WARN


def test_b09_unexpected_value_true_warns():
    assert check_leak(_ctx({"logging": {"redactSensitive": True}})).status == WARN


# ---- never UNKNOWN ----

def test_b09_never_unknown():
    for cfg in (
        {},
        {"logging": {"redactSensitive": "tools"}},
        {"logging": {"redactSensitive": "off"}},
        {"logging": {"redactSensitive": "all"}},
        {"logging": {}},
    ):
        assert check_leak(_ctx(cfg)).status != UNKNOWN, f"unexpected UNKNOWN for {cfg}"


# ---- B-128: absent field is secure-by-default (default "tools" already redacts) ----

def test_b09_field_absent_rationale_reflects_secure_default():
    # No 'logging' key at all — clean fixture proving the corrected rationale.
    f = check_leak(_ctx({}))
    assert f.status == WARN
    detail = f.detail.lower()
    assert "already redact" in detail
    assert "not pinned" in detail
    # must not claim the default may expose secrets — that was factually backwards
    assert "may expose secrets" not in detail


def test_b09_logging_present_field_absent_rationale_reflects_secure_default():
    f = check_leak(_ctx({"logging": {}}))
    assert f.status == WARN
    assert "already redact" in f.detail.lower()


def test_b09_absent_field_severity_is_low():
    from clawseccheck.catalog import LOW
    f = check_leak(_ctx({}))
    assert f.severity == LOW


def test_b09_redact_off_severity_is_low_catalog_wide():
    # B-128 lowers the static B9 catalog severity (single severity per check); the FAIL
    # branch (genuinely risky "off") still fires as FAIL — the trigger condition, asserted
    # by test_b09_redact_off_fails above, is unchanged.
    from clawseccheck.catalog import LOW
    f = check_leak(_ctx({"logging": {"redactSensitive": "off"}}))
    assert f.status == FAIL
    assert f.severity == LOW


# ---- B-128: end-to-end clean fixture via the real collector/audit path ----

def test_b09_clean_fixture_redact_not_pinned_end_to_end():
    """clean_b9_redact_not_pinned: no logging.redactSensitive key at all — confirms the
    reworded, secure-by-default rationale and the LOW severity through the real
    collect() -> check_leak() path, not just a hand-built Context."""
    from clawseccheck.catalog import LOW
    ctx = collect(FIXTURES / "clean_b9_redact_not_pinned")
    f = check_leak(ctx)
    assert f.status == WARN
    assert f.severity == LOW
    detail = f.detail.lower()
    assert "already redact" in detail
    assert "not pinned" in detail
    assert "may expose secrets" not in detail
