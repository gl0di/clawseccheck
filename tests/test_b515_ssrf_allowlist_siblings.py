"""B-515 — B38 (check_browser_ssrf) must honour BOTH sibling allowlist keys.

The installed OpenClaw dist has two sibling keys under `browser.ssrfPolicy` and the
runtime merges them into one combined allowlist:
  - `allowedHostnames`  — current field
  - `hostnameAllowlist` — legacy/alternate field

Before this fix, B38 only ever looked at `hostnameAllowlist`, so an operator who set
only the current field (`allowedHostnames`) got a false-positive WARN claiming no
allowlist was configured. This module pins: only-new -> no warn, only-legacy -> no warn
(regression), both -> no warn, neither -> warn, empty list in either -> still warn.
"""
from pathlib import Path

from clawseccheck.catalog import WARN, PASS
from clawseccheck.checks import check_browser_ssrf
from clawseccheck.collector import Context


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def _browser_cfg(ssrf_policy: dict) -> dict:
    return {"browser": {"noSandbox": False, "ssrfPolicy": ssrf_policy}}


# ---- only the new field is set -> must NOT warn (the B-515 defect) ----

def test_only_allowed_hostnames_set_does_not_warn():
    f = check_browser_ssrf(_ctx(_browser_cfg({"allowedHostnames": ["example.com"]})))
    assert f.status == PASS, f.detail


# ---- only the legacy field is set -> must NOT warn (regression pin) ----

def test_only_legacy_hostname_allowlist_set_does_not_warn():
    f = check_browser_ssrf(_ctx(_browser_cfg({"hostnameAllowlist": ["example.com"]})))
    assert f.status == PASS, f.detail


# ---- both fields set -> must NOT warn ----

def test_both_fields_set_does_not_warn():
    f = check_browser_ssrf(_ctx(_browser_cfg({
        "allowedHostnames": ["example.com"],
        "hostnameAllowlist": ["api.myservice.io"],
    })))
    assert f.status == PASS, f.detail


# ---- neither field set -> warn ----

def test_neither_field_set_warns():
    f = check_browser_ssrf(_ctx(_browser_cfg({})))
    assert f.status == WARN
    assert "allowedHostnames" in f.detail
    assert "hostnameAllowlist" in f.detail


# ---- empty list in either field -> still warn ----

def test_empty_allowed_hostnames_still_warns():
    f = check_browser_ssrf(_ctx(_browser_cfg({"allowedHostnames": []})))
    assert f.status == WARN


def test_empty_legacy_hostname_allowlist_still_warns():
    f = check_browser_ssrf(_ctx(_browser_cfg({"hostnameAllowlist": []})))
    assert f.status == WARN


def test_both_empty_still_warns():
    f = check_browser_ssrf(_ctx(_browser_cfg({"allowedHostnames": [], "hostnameAllowlist": []})))
    assert f.status == WARN


# ---- fix strings name the current field first, legacy second ----

def test_warn_detail_and_fix_name_current_field_before_legacy():
    f = check_browser_ssrf(_ctx(_browser_cfg({})))
    assert f.status == WARN
    assert f.detail.index("allowedHostnames") < f.detail.index("hostnameAllowlist")
    assert f.fix.index("allowedHostnames") < f.fix.index("hostnameAllowlist")


# ---- end to end through the real audit, on a real fixture home ----

def test_b515_fixture_home_with_only_allowed_hostnames_passes():
    """Not a trace: goes through audit() the way a user's config does."""
    import clawseccheck

    fixtures = Path(__file__).resolve().parent.parent / "fixtures"
    home = fixtures / "clean_b515_allowed_hostnames" / "openclaw_home"
    _, findings, _ = clawseccheck.audit(str(home))
    b38 = next(f for f in findings if f.id == "B38")
    assert b38.status == PASS, f"got {b38.status} — {b38.detail}"
