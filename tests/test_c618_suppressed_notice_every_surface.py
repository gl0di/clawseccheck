"""C-618: a suppressed finding that still counts is disclosed on EVERY human surface.

`surfaced_despite_suppression` (a suppressed CRITICAL/HIGH FAIL, or a sensitive id) was wired
into the text report, the badge, SARIF and the CLI gates only. The dashboard card, the
--dashboard-findings block, HTML and PDF dropped the finding AND the fact that suppression
was the reason, and the "Most urgent" headline could say "Nothing failed outright" while a
suppressed CRITICAL still capped the grade.

The finding BODY (title, detail) stays out of those surfaces - that exclusion is pinned
elsewhere and re-pinned here. Only the one shared WARNING sentence is added.

Offline and deterministic: Findings are built directly, nothing is written.
"""
from __future__ import annotations

import re
import shutil
import subprocess

import pytest

from clawseccheck.catalog import (
    CRITICAL, FAIL, HIGH, LOW, MEDIUM, PASS, UNKNOWN, WARN, Finding,
)
from clawseccheck.layers import (
    LAYER_LIVE_BEHAVIOUR,
    LAYER_ORDER,
    LAYER_SELF_REPORT,
    STATUS_RAN,
    STATUS_UNAVAILABLE,
    LayerLedger,
    LayerState,
)
from clawseccheck.pdf import render_pdf
from clawseccheck.report import (
    _COMPACT_CHAR_BUDGET,
    _urgent_headline,
    render_dashboard,
    render_dashboard_findings,
    render_html,
    render_report,
    suppressed_notice_lines,
)
from clawseccheck.scoring import compute

_HAS_PDFTOTEXT = shutil.which("pdftotext") is not None

NOTICE = "is suppressed via .clawseccheckignore"
ARCHIVE_STATUS = "SKILL_ARCHIVE_PATH_TRAVERSAL"


def _f(id_: str, status: str = FAIL, severity: str = CRITICAL, *,
       suppressed: bool = False) -> Finding:
    f = Finding(
        id=id_,
        title=f"title {id_}",
        severity=severity,
        status=status,
        detail=f"detail {id_}",
        fix=f"fix {id_}",
        framework="Test",
    )
    f.suppressed = suppressed
    return f


def _ungraded_ledger() -> LayerLedger:
    states = {layer: LayerState(status=STATUS_RAN) for layer in LAYER_ORDER}
    states[LAYER_SELF_REPORT] = LayerState(status=STATUS_UNAVAILABLE)
    states[LAYER_LIVE_BEHAVIOUR] = LayerState(status=STATUS_UNAVAILABLE)
    return LayerLedger(states=states)


def _pdftext(findings, score) -> str:
    data = render_pdf(findings, score)
    out = subprocess.run(
        ["pdftotext", "-", "-"], input=data, capture_output=True, check=True,
    ).stdout.decode("utf-8", "replace")
    return " ".join(out.split())


def _surfaces(findings, *, with_pdf: bool = True) -> dict:
    """Every human surface that must carry the notice, graded and ungraded."""
    graded = compute(findings)
    ungraded = compute(findings, None, ledger=_ungraded_ledger())
    out = {
        "render_report": render_report(findings, graded),
        "render_dashboard": render_dashboard(findings, graded),
        "render_dashboard [ungraded]": render_dashboard(findings, ungraded),
        "render_dashboard --full": render_dashboard(findings, graded, full=True),
        "render_dashboard --full [ungraded]": render_dashboard(findings, ungraded, full=True),
        "render_dashboard --compact": render_dashboard(
            findings, graded, full=True, compact=True),
        "render_dashboard --ascii": render_dashboard(findings, graded, ascii_only=True),
        "render_dashboard_findings": render_dashboard_findings(findings),
        "render_html": render_html(findings, graded),
        "render_html [ungraded]": render_html(findings, ungraded),
    }
    if with_pdf and _HAS_PDFTOTEXT:
        out["render_pdf"] = _pdftext(findings, graded)
    return out


# --- bad: every surface carries the notice, none carries the body ---------------------

def test_every_surface_discloses_a_suppressed_critical_fail_without_its_body():
    findings = [_f("B1", suppressed=True), _f("B9", WARN, MEDIUM)]
    for name, text in _surfaces(findings).items():
        assert NOTICE in text, f"{name}: no suppression notice"
        assert "(B1)" in text, f"{name}: notice does not name the id"
        assert "detail B1" not in text, f"{name}: suppressed body leaked (detail)"
        # The title may appear ONLY inside the tagged "Most urgent" headline (ungraded
        # runs), never as a finding card of its own.
        for line in text.splitlines():
            if "title B1" in line:
                assert "(suppressed via .clawseccheckignore)" in line, (
                    f"{name}: suppressed body leaked (title): {line!r}")


def test_positive_control_the_text_report_carried_the_notice_all_along():
    # A negative asserted without a control proves nothing: the text report is the surface
    # that already worked, so the same assertion must hold there.
    findings = [_f("B1", suppressed=True), _f("B9", WARN, MEDIUM)]
    text = render_report(findings, compute(findings))
    assert f"WARNING: a CRITICAL finding (B1) {NOTICE}" in text


def test_standalone_findings_block_all_clear_still_carries_the_notice():
    out = render_dashboard_findings([_f("B2", suppressed=True)])
    assert "No high-confidence issues to fix." in out
    assert f"WARNING: a CRITICAL finding (B2) {NOTICE}" in out
    assert "title B2" not in out


def test_findings_block_notice_can_be_turned_off():
    findings = [_f("B2", suppressed=True)]
    assert NOTICE not in render_dashboard_findings(findings, suppression_notice=False)


# --- parity: no surface invents a stricter or looser rule than the text report -----------

_PARITY_CASES = {
    "critical fail, non-sensitive id": _f("B77", FAIL, CRITICAL, suppressed=True),
    "high fail": _f("B78", FAIL, HIGH, suppressed=True),
    "medium fail, non-sensitive id": _f("B79", FAIL, MEDIUM, suppressed=True),
    "low warn, non-sensitive id": _f("B80", WARN, LOW, suppressed=True),
    "sensitive id, UNKNOWN": _f("B13", UNKNOWN, HIGH, suppressed=True),
    "sensitive id, PASS": _f("B20", PASS, HIGH, suppressed=True),
    "fail-weight non-FAIL status": _f("B81", ARCHIVE_STATUS, CRITICAL, suppressed=True),
}


@pytest.mark.parametrize("case", sorted(_PARITY_CASES))
def test_every_surface_agrees_with_the_text_report(case):
    findings = [_PARITY_CASES[case]]
    surfaces = _surfaces(findings)
    expected = NOTICE in surfaces["render_report"]
    for name, text in surfaces.items():
        assert (NOTICE in text) == expected, (
            f"{case}: {name} disagrees with the text report (report says {expected})")


def test_parity_matrix_has_both_outcomes():
    # The drift guard is only a guard if some case notices and some case stays quiet.
    verdicts = {
        case: NOTICE in render_report([f], compute([f]))
        for case, f in _PARITY_CASES.items()
    }
    assert verdicts["critical fail, non-sensitive id"] is True
    assert verdicts["high fail"] is True
    assert verdicts["fail-weight non-FAIL status"] is True
    assert verdicts["medium fail, non-sensitive id"] is False
    assert verdicts["low warn, non-sensitive id"] is False


# --- clean: nothing suppressed, nothing added ---------------------------------------------

def test_no_suppression_no_notice_and_unchanged_output():
    findings = [_f("B2", FAIL, CRITICAL), _f("B9", WARN, MEDIUM), _f("B3", PASS, HIGH)]
    for name, text in _surfaces(findings).items():
        assert NOTICE not in text, name
        assert "WARNING: a " not in text, name
    assert render_dashboard_findings(findings) == render_dashboard_findings(
        findings, suppression_notice=False)
    assert suppressed_notice_lines(findings) == []


# --- headline: "Nothing failed outright" must not out-run a suppressed CRITICAL -------------

def test_headline_names_a_suppressed_critical_fail():
    head = _urgent_headline([_f("B1", suppressed=True)])
    assert head.startswith("Most urgent: CRITICAL")
    assert head.endswith("(suppressed via .clawseccheckignore)")
    assert "Nothing failed outright" not in head
    # The headline stays id-free (Layer 0); the id lives in the notice.
    assert _f("B1").id not in head.replace("title B1", "")


def test_headline_prefers_a_live_finding_on_a_severity_tie():
    live = _f("B5", FAIL, CRITICAL)
    hidden = _f("B1", FAIL, CRITICAL, suppressed=True)
    for order in ([hidden, live], [live, hidden]):
        head = _urgent_headline(order)
        assert head == "Most urgent: CRITICAL \u2014 title B5"
        assert "suppressed" not in head


def test_headline_ignores_a_suppressed_medium_fail():
    head = _urgent_headline([_f("B79", FAIL, MEDIUM, suppressed=True)])
    assert "Most urgent" not in head
    assert "suppressed" not in head
    assert head == _urgent_headline([])


def test_headline_unchanged_for_a_suppressed_warn():
    baseline = _urgent_headline([_f("B79", WARN, MEDIUM)])
    with_suppressed = _urgent_headline(
        [_f("B79", WARN, MEDIUM), _f("B80", WARN, HIGH, suppressed=True)])
    assert with_suppressed == baseline
    assert "suppressed" not in with_suppressed


# --- bounded card ------------------------------------------------------------------------

def test_forty_suppressed_criticals_stay_inside_the_card_budget():
    findings = [_f(f"X{n}", suppressed=True) for n in range(40)]
    graded = compute(findings)

    card = render_dashboard(findings, graded, full=True, compact=True)
    assert len(card) <= _COMPACT_CHAR_BUDGET
    assert len(re.findall(r"^WARNING: ", card, flags=re.M)) == 3
    assert card.count("(+37 more suppressed finding(s) that still count") == 1

    block = render_dashboard_findings(findings)
    assert len(re.findall(r"^WARNING: ", block, flags=re.M)) == 3
    assert block.count("(+37 more suppressed finding(s) that still count") == 1

    # HTML is the archival page: every one of them is listed, no "+K more".
    html = render_html(findings, graded)
    assert html.count(NOTICE) == 40
    assert "more suppressed finding(s)" not in html


def test_notice_limit_counts_the_overflow_and_never_drops_it():
    findings = [_f(f"X{n}", suppressed=True) for n in range(5)]
    assert len(suppressed_notice_lines(findings)) == 5
    bounded = suppressed_notice_lines(findings, limit=3)
    assert len(bounded) == 4
    assert bounded[-1].startswith("(+2 more suppressed finding(s)")
    assert len(suppressed_notice_lines(findings, limit=5)) == 5


def test_notice_text_is_shared_byte_for_byte_with_the_text_report():
    f = _f("B1", suppressed=True)
    (line,) = suppressed_notice_lines([f])
    assert line == (
        "WARNING: a CRITICAL finding (B1) is suppressed via .clawseccheckignore"
        " \u2014 it still counts against your real security; review your ignore list.")
    assert line in render_report([f], compute([f])).splitlines()


# --- hostile id --------------------------------------------------------------------------

_HOSTILE_ID = "B1\x1b[31m\u202e<script>"


def test_hostile_id_reaches_no_surface_raw():
    findings = [_f(_HOSTILE_ID, suppressed=True)]
    for name, text in _surfaces(findings).items():
        assert "\x1b" not in text, name
        assert "\u202e" not in text, name
        if name.startswith("render_html"):
            assert "<script>" not in text, name
        assert NOTICE in text, name


def test_hostile_id_is_escaped_in_html():
    findings = [_f(_HOSTILE_ID, suppressed=True)]
    html = render_html(findings, compute(findings))
    assert "&lt;script&gt;" in html


# --- no double notice ----------------------------------------------------------------------

def test_full_dashboard_prints_the_notice_exactly_once():
    findings = [_f("B1", suppressed=True), _f("B9", WARN, MEDIUM)]
    graded = compute(findings)
    for kwargs in ({"full": True}, {"full": True, "compact": True}):
        out = render_dashboard(findings, graded, **kwargs)
        assert out.count("WARNING: a CRITICAL finding (B1)") == 1, kwargs
