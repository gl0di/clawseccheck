"""B387 (CLAWSECCHECK-F-196) — secrets.egressProxy traffic-allowlist gap.

Verdicts (check_secrets_egress_proxy, checks/_egress.py):
  PASS    : secrets.egressProxy.enabled is not true (the default), OR enabled with
            secrets.egressProxy.allowedHosts set to a list (empty = lockdown mode,
            non-empty = scoped)
  WARN    : enabled: true and allowedHosts absent/null/non-list — OpenClaw's own default
            then leaves non-sentinel proxy traffic unrestricted
  UNKNOWN : config unreadable
  (no FAIL — both allowedHosts and bypassHosts already reject a wildcard at
  config-load time, so there is no FAIL-worthy shape to catch; see the check's own
  docstring for the full grounding against the installed 2026.9.5 dist)

Re-grounds a filed task's own hypothesis and finds it backwards on two points:
  - bypassHosts cannot carry an unscoped wildcard at all (EgressProxyExactHostSchema /
    normalizeExactAllowedHost, dist/exact-hostname-B5MIU7_E.mjs, rejects any "*").
  - An EMPTY allowedHosts array is the vendor's documented LOCKDOWN mode, not an open
    allowlist — the actual gap is allowedHosts being ABSENT while enabled: true.
"""
import json
import os
from pathlib import Path

import clawseccheck.checks as C
from clawseccheck.catalog import BY_ID, FAIL, PASS, UNKNOWN, WARN
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict, parse_error: bool = False) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.config_parse_error = parse_error
    c.config_found = True
    return c


def _finding_direct(cfg: dict):
    return C.check_secrets_egress_proxy(_ctx(cfg))


def _finding_via_home(cfg: dict, tmp_path):
    """Round-trip through collect()/run_all(), matching how the real audit invokes it."""
    home = tmp_path
    path = home / "openclaw.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(path, 0o600)
    ctx = collect(home)
    return next(f for f in C.run_all(ctx) if f.id == "B387")


# ---- catalog sanity ----

def test_b387_is_catalogued_unscored_advisory():
    meta = BY_ID["B387"]
    assert meta.block == "advisory"
    assert meta.scored is False


# ---- PASS: feature off (the default) ----

def test_empty_config_passes():
    f = _finding_direct({})
    assert f.status == PASS


def test_egress_proxy_block_absent_passes():
    f = _finding_direct({"secrets": {"providers": {}}})
    assert f.status == PASS


def test_enabled_explicit_false_passes():
    f = _finding_direct({"secrets": {"egressProxy": {"enabled": False}}})
    assert f.status == PASS


def test_enabled_non_bool_truthy_is_not_treated_as_on():
    # The real schema is boolean().optional(); a non-bool value would not load through
    # OpenClaw's own config validation, so this must not be read as an affirmative "on".
    f = _finding_direct({"secrets": {"egressProxy": {"enabled": "true"}}})
    assert f.status == PASS


# ---- PASS: enabled with allowedHosts set (empty OR scoped) ----

def test_enabled_with_empty_allowlist_passes_lockdown_mode():
    """An empty allowedHosts array is the vendor's documented LOCKDOWN mode, not an
    open allowlist — must NOT warn, even though several sibling checks in this module
    treat an empty allowlist as the open/unrestricted shape for THEIR fields."""
    cfg = {"secrets": {"egressProxy": {"enabled": True, "allowedHosts": []}}}
    f = _finding_direct(cfg)
    assert f.status == PASS


def test_enabled_with_scoped_allowlist_passes():
    cfg = {
        "secrets": {
            "egressProxy": {
                "enabled": True,
                "allowedHosts": ["api.openai.com"],
                "bypassHosts": ["pinned-api.example.com"],
            }
        }
    }
    f = _finding_direct(cfg)
    assert f.status == PASS
    assert "api.openai.com" in " ".join(f.evidence)


# ---- WARN: enabled with no traffic allowlist ----

def test_enabled_with_no_allowlist_key_warns():
    f = _finding_direct({"secrets": {"egressProxy": {"enabled": True}}})
    assert f.status == WARN
    assert "can reach any host" in f.detail


def test_enabled_with_null_allowlist_warns():
    cfg = {"secrets": {"egressProxy": {"enabled": True, "allowedHosts": None}}}
    f = _finding_direct(cfg)
    assert f.status == WARN


def test_enabled_with_non_list_allowlist_warns():
    # Not a shape the real array().optional() schema would accept either, so it does
    # not enact a restriction — treated the same as absent, not as a false PASS.
    cfg = {"secrets": {"egressProxy": {"enabled": True, "allowedHosts": "api.example.com"}}}
    f = _finding_direct(cfg)
    assert f.status == WARN


def test_bypass_hosts_alone_does_not_rescue_a_missing_allowlist():
    cfg = {
        "secrets": {
            "egressProxy": {"enabled": True, "bypassHosts": ["pinned-api.example.com"]}
        }
    }
    f = _finding_direct(cfg)
    assert f.status == WARN


# ---- the disproven wildcard hypothesis: no dig()-visible shape exists to test, but the
#      docstring's grounding is pinned by the schema-layer test suite instead. A "*" in
#      bypassHosts is a config the real OpenClaw schema refuses to load at all, so this
#      check has no wildcard-shaped WARN/FAIL branch to exercise here.


# ---- config-unreadable engine-side UNKNOWN ----

def test_unparseable_config_is_engine_degraded_unknown():
    f = _finding_direct({})
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.config_parse_error = True
    f = C.check_secrets_egress_proxy(c)
    assert f.status == UNKNOWN
    assert f.engine_degraded is True


# ---- never FAIL ----

def test_never_fail():
    for cfg in (
        {},
        {"secrets": {"egressProxy": {"enabled": True}}},
        {"secrets": {"egressProxy": {"enabled": True, "allowedHosts": []}}},
        {"secrets": {"egressProxy": {"enabled": True, "allowedHosts": ["x.example.com"]}}},
        {"secrets": {"egressProxy": {"enabled": True, "bypassHosts": ["x.example.com"]}}},
    ):
        assert _finding_direct(cfg).status != FAIL, f"B387 must never return FAIL; got FAIL for {cfg}"


# ---- fixtures, round-tripped through the real audit pipeline ----

def test_the_bad_fixture_fires_and_the_clean_one_does_not():
    for name, expected in (
        ("bad_b387_egress_proxy_no_allowlist", WARN),
        ("clean_b387_egress_proxy_allowlisted", PASS),
    ):
        ctx = collect(FIXTURES / name)
        f = next(fi for fi in C.run_all(ctx) if fi.id == "B387")
        assert f.status == expected, name


def test_full_pipeline_round_trip_matches_direct_call(tmp_path):
    cfg = {"secrets": {"egressProxy": {"enabled": True}}}
    assert _finding_via_home(cfg, tmp_path).status == _finding_direct(cfg).status == WARN
