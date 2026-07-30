"""B-362 (follow-up) — check_browser_executable_path (B321)'s SECOND, still-unconverted
UNKNOWN branch: ``browser`` is a present dict but neither an ``executablePath``
(top-level or per-profile) nor an existing-session ``mcpCommand`` override is set
anywhere in it.

``tests/test_b362_browser_not_applicable.py`` already converted and pinned B321's
FIRST branch (``browser`` key entirely absent) as part of the shared browser-cluster
sweep, and explicitly flagged this second branch as out of scope for that pass (see
its own comment at the "present but empty" test). This file finishes that follow-up.
It deliberately does NOT touch the shared browser-cluster tests file, per the task's
own instruction to isolate this branch's coverage.

B321 has a THIRD UNKNOWN branch — candidates found but ``--no-host`` — which must stay
a genuine UNKNOWN (a real, resumable scan-incompleteness case, not surface absence).
That branch is pinned here as an adversarial control alongside the two converted ones.

Offline, read-only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.adjudication import build_judge_packet
from clawseccheck.catalog import UNKNOWN, WARN
from clawseccheck.checks import check_browser_executable_path
from clawseccheck.collector import LIMIT_DOMAIN_CONFIG, Context, note_limit


def _ctx(cfg: dict, **kw) -> Context:
    defaults = dict(home=Path("/nonexistent"), config_found=True, config_parse_error=False)
    defaults.update(kw)
    c = Context(**defaults)
    c.config = cfg
    return c


# ---------------------------------------------------------------------------
# 1. browser present but genuinely empty of both sub-signals -> not_applicable=True.
# ---------------------------------------------------------------------------

def test_browser_present_with_no_executablepath_or_mcpcommand_sets_not_applicable():
    f = check_browser_executable_path(_ctx({"browser": {"enabled": True}}))
    assert f.status == UNKNOWN
    assert f.not_applicable is True


def test_browser_profiles_present_but_no_executablepath_or_mcpcommand_sets_not_applicable():
    # A profile exists but declares neither sub-signal this check assesses.
    cfg = {"browser": {"profiles": {"default": {"driver": "existing-session"}}}}
    f = check_browser_executable_path(_ctx(cfg))
    assert f.status == UNKNOWN
    assert f.not_applicable is True


# ---------------------------------------------------------------------------
# 2. Adversarial control: candidates DO exist -> a different verdict entirely, never
#    this branch, so not_applicable must stay False regardless of host-scan state.
# ---------------------------------------------------------------------------

def test_executablepath_present_reaches_a_real_verdict_not_this_branch():
    cfg = {"browser": {"executablePath": "/usr/bin/chromium"}}
    f = check_browser_executable_path(_ctx(cfg, include_host=True))
    assert f.status != UNKNOWN or f.not_applicable is False


def test_mcpcommand_override_present_reaches_warn_not_this_branch():
    cfg = {
        "browser": {
            "profiles": {
                "p1": {"driver": "existing-session", "mcpCommand": "/opt/custom-mcp"}
            }
        }
    }
    f = check_browser_executable_path(_ctx(cfg))
    assert f.status == WARN
    assert f.not_applicable is False


def test_candidates_found_but_no_host_stays_real_unknown_not_not_applicable():
    """B321's THIRD UNKNOWN branch (candidates found, --no-host) is a genuine
    scan-incompleteness case, not surface absence -- must never be flagged
    not_applicable."""
    cfg = {"browser": {"executablePath": "/usr/bin/chromium"}}
    f = check_browser_executable_path(_ctx(cfg, include_host=False))
    assert f.status == UNKNOWN
    assert f.not_applicable is False


# ---------------------------------------------------------------------------
# 3. Degradation matrix -- mirrors tests/test_f140_not_applicable_degrades.py /
#    the shared browser-cluster tests.
# ---------------------------------------------------------------------------

def test_domain_tagged_limit_hit_keeps_flag_false():
    ctx = _ctx({"browser": {"enabled": True}})
    note_limit(ctx.limit_hits, LIMIT_DOMAIN_CONFIG, "hit the config scan cap")
    f = check_browser_executable_path(ctx)
    assert f.status == UNKNOWN
    assert f.not_applicable is False


def test_config_parse_error_keeps_flag_false():
    ctx = _ctx({"browser": {"enabled": True}}, config_parse_error=True)
    f = check_browser_executable_path(ctx)
    assert f.not_applicable is False


def test_config_not_found_keeps_flag_false():
    ctx = _ctx({"browser": {"enabled": True}}, config_found=False)
    f = check_browser_executable_path(ctx)
    assert f.not_applicable is False


# ---------------------------------------------------------------------------
# 4. Judge-packet exclusion (B-361's upstream fix) -- a real check output, not just
#    the synthetic Finding already covered generically by tests/test_adjudication.py.
# ---------------------------------------------------------------------------

def test_not_applicable_finding_excluded_from_judge_packet():
    ctx = _ctx({"browser": {"enabled": True}})
    f = check_browser_executable_path(ctx)
    assert f.not_applicable is True  # control: this is the case that must be excluded
    packet = build_judge_packet(ctx, [f])
    assert packet == [], (
        "a not_applicable UNKNOWN finding must never become a judge-packet item"
    )


def test_ordinary_unknown_still_reaches_judge_packet():
    """Control: the real (--no-host) UNKNOWN branch is still judge-packet-eligible."""
    ctx = _ctx({"browser": {"executablePath": "/usr/bin/chromium"}}, include_host=False)
    f = check_browser_executable_path(ctx)
    assert f.status == UNKNOWN
    assert f.not_applicable is False
    packet = build_judge_packet(ctx, [f])
    assert len(packet) == 1
