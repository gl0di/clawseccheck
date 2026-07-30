"""B-362 — extend Finding.not_applicable (F-138/F-139/F-140 mechanism) to the browser
config-absence cluster (B38/B195/B196/B321/B322/B330), all sharing one locus:
``ctx.config["browser"]``.

Grounding (dist/openclaw@2026.7.1-2, see clawseccheck/checks/_egress.py's
``_browser_surface_absent`` docstring for the full citation): OpenClaw's own
`hasExplicitBrowserIntent` treats the browser tool as configured/intended when EITHER
the top-level `browser` block OR the bundled plugin's `plugins.entries.browser` path is
present. So `not_applicable` must require BOTH to be absent -- the adversarial tests
below pin that the alternate plugin path alone is enough to keep the flag False.

Same three-part shape as tests/test_f140_not_applicable_degrades.py /
tests/test_f140_not_applicable_adversarial.py: (1) the flag fires when the surface is
genuinely absent, (2) it degrades to False on an incomplete read, (3) it never fires
falsely when the surface exists in a form the check itself doesn't parse into a
non-UNKNOWN verdict (the plugins.entries.browser alt path).

Offline, read-only.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.adjudication import build_judge_packet
from clawseccheck.catalog import UNKNOWN, Finding
from clawseccheck.checks import (
    check_browser_cdp_control_port,
    check_browser_evaluate_enabled,
    check_browser_executable_path,
    check_browser_existing_session_profile,
    check_browser_extra_args,
    check_browser_ssrf,
)
from clawseccheck.collector import LIMIT_DOMAIN_CONFIG, Context, note_limit
from clawseccheck.report import render_report
from clawseccheck.scoring import ScoreResult

_BROWSER_CHECKS = pytest.mark.parametrize(
    "check_fn",
    [
        check_browser_ssrf,
        check_browser_extra_args,
        check_browser_evaluate_enabled,
        check_browser_executable_path,
        check_browser_existing_session_profile,
        check_browser_cdp_control_port,
    ],
    ids=["B38", "B195", "B196", "B321", "B322", "B330"],
)


def _ctx(cfg: dict, **kw) -> Context:
    defaults = dict(home=Path("/nonexistent"), config_found=True, config_parse_error=False)
    defaults.update(kw)
    c = Context(**defaults)
    c.config = cfg
    return c


# ---------------------------------------------------------------------------
# 1. Absent browser config -> not_applicable=True (the fixture with the section
#    entirely absent), for every check in the cluster.
# ---------------------------------------------------------------------------

@_BROWSER_CHECKS
def test_browser_key_entirely_absent_sets_not_applicable(check_fn):
    f = check_fn(_ctx({}))
    assert f.status == UNKNOWN
    assert f.not_applicable is True


# ---------------------------------------------------------------------------
# 2. Present-but-empty ("browser": {}) -- adversarial control. `isinstance(browser,
#    dict)` is True for `{}`, so every one of these checks never reaches its "no
#    browser config" UNKNOWN branch (the one this task converted) at all -- they fall
#    through to a real verdict, OR (B321 only) a second, DIFFERENT UNKNOWN branch
#    ("browser configured but no executablePath/mcpCommand anywhere"). That second
#    branch was itself converted to not_applicable in a follow-up pass -- see
#    tests/test_b362_browser_executable_path_not_applicable.py, which pins B321's
#    updated expectation (not_applicable=True for this exact fixture) in isolation.
#    So B321 is deliberately EXCLUDED from this assertion below: for the other five,
#    present-but-empty is NOT the same case as wholly absent -- it never reaches any
#    not_applicable branch, so the flag must stay False. Pinned here so a future
#    change to any of these five checks' "isinstance(browser, dict)" gate can't
#    silently make {} start reaching a not_applicable branch unnoticed.
# ---------------------------------------------------------------------------

_BROWSER_CHECKS_EXCEPT_B321 = pytest.mark.parametrize(
    "check_fn",
    [
        check_browser_ssrf,
        check_browser_extra_args,
        check_browser_evaluate_enabled,
        check_browser_existing_session_profile,
        check_browser_cdp_control_port,
    ],
    ids=["B38", "B195", "B196", "B322", "B330"],
)


@_BROWSER_CHECKS_EXCEPT_B321
def test_browser_present_but_empty_is_not_the_absence_branch(check_fn):
    f = check_fn(_ctx({"browser": {}}))
    assert f.not_applicable is False, (
        "an empty-but-present browser block must never be reported not_applicable"
    )


def test_b321_browser_present_but_empty_now_is_its_own_not_applicable_branch():
    """B321-specific control: unlike the other five, an empty browser block DOES
    reach a (different, later-converted) not_applicable branch for this check --
    see tests/test_b362_browser_executable_path_not_applicable.py for full coverage."""
    f = check_browser_executable_path(_ctx({"browser": {}}))
    assert f.status == UNKNOWN
    assert f.not_applicable is True


# ---------------------------------------------------------------------------
# 3. Adversarial: the alternate plugins.entries.browser enablement path keeps the
#    flag False even though ctx.config["browser"] itself is absent.
# ---------------------------------------------------------------------------

@_BROWSER_CHECKS
def test_plugins_entries_browser_alt_path_keeps_flag_false(check_fn):
    ctx = _ctx({"plugins": {"entries": {"browser": {"enabled": True}}}})
    f = check_fn(ctx)
    assert f.not_applicable is False, (
        f"{check_fn.__name__}: a browser intent expressed only via "
        "plugins.entries.browser must not be reported not_applicable"
    )


# ---------------------------------------------------------------------------
# 4. Degradation matrix -- mirrors tests/test_f140_not_applicable_degrades.py.
# ---------------------------------------------------------------------------

@_BROWSER_CHECKS
def test_domain_tagged_limit_hit_keeps_flag_false(check_fn):
    ctx = _ctx({})
    note_limit(ctx.limit_hits, LIMIT_DOMAIN_CONFIG, "hit the config scan cap")
    f = check_fn(ctx)
    assert f.status == UNKNOWN
    assert f.not_applicable is False


@_BROWSER_CHECKS
def test_config_parse_error_keeps_flag_false(check_fn):
    ctx = _ctx({}, config_parse_error=True)
    f = check_fn(ctx)
    assert f.not_applicable is False


@_BROWSER_CHECKS
def test_config_not_found_keeps_flag_false(check_fn):
    ctx = _ctx({}, config_found=False)
    f = check_fn(ctx)
    assert f.not_applicable is False


# ---------------------------------------------------------------------------
# 5. Judge packet exclusion (B-361's upstream fix) -- a real check output, not just
#    the synthetic Finding already covered generically by tests/test_adjudication.py.
# ---------------------------------------------------------------------------

@_BROWSER_CHECKS
def test_not_applicable_finding_excluded_from_judge_packet(check_fn):
    ctx = _ctx({})
    f = check_fn(ctx)
    assert f.not_applicable is True  # control: this is the case B-361 needs fixed
    packet = build_judge_packet(ctx, [f])
    assert packet == [], (
        f"{check_fn.__name__}: a not_applicable UNKNOWN finding must never become a "
        "judge-packet item"
    )


def test_ordinary_unknown_browser_finding_still_reaches_judge_packet():
    """Control for the exclusion test above: an ordinary (not_applicable=False)
    UNKNOWN browser finding is still judge-packet-eligible."""
    ctx = _ctx({}, config_parse_error=True)  # degrades the flag back to False
    f = check_browser_evaluate_enabled(ctx)
    assert f.status == UNKNOWN
    assert f.not_applicable is False
    packet = build_judge_packet(ctx, [f])
    assert len(packet) == 1


# ---------------------------------------------------------------------------
# 6. report.py visibly distinguishes the two UNKNOWN sub-cases.
# ---------------------------------------------------------------------------

def _score() -> ScoreResult:
    return ScoreResult(score=90, grade="A", capped=False, raw_score=90,
                        failed_critical=0, failed_high=0)


def test_report_distinguishes_not_applicable_from_real_unknown():
    real_unknown = Finding(
        id="B999", title="Synthetic unresolved check", severity="LOW", status=UNKNOWN,
        detail="could not determine", fix="—", framework="Test", not_applicable=False,
    )
    na = Finding(
        id="B196", title="browser.evaluateEnabled", severity="LOW", status=UNKNOWN,
        detail="No browser config — evaluateEnabled not applicable.", fix="—",
        framework="Test", not_applicable=True,
    )
    out = render_report([real_unknown, na], _score())
    assert "not assessed (config can't tell)" in out
    assert "not applicable (no such surface in your config)" in out


def test_report_omits_na_line_when_no_not_applicable_findings():
    real_unknown = Finding(
        id="B999", title="Synthetic unresolved check", severity="LOW", status=UNKNOWN,
        detail="could not determine", fix="—", framework="Test", not_applicable=False,
    )
    out = render_report([real_unknown], _score())
    assert "not assessed (config can't tell)" in out
    assert "not applicable (no such surface in your config)" not in out
