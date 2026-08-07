"""CLAWSECCHECK-C-423 — every renderer learns that a run can carry no grade.

`ScoreResult.graded` (C-422, `scoring.py`) is `False` only when a caller supplies an
explicit, INCOMPLETE `layers.LayerLedger` — no production caller does that yet, so a
real run today is unaffected; only these tests reach the ungraded path, by building a
ledger directly and threading it through `scoring.compute()`.

Hard rule under test throughout: `graded is False` means no renderer may print a real
letter or a real `/100` number, anywhere — the "Most urgent" finding (or the all-clear
sentence) leads, followed by which layers never ran. Layer/status wording comes from
`layers.describe_layer` ONLY; a renderer that phrases a layer or a status itself is
exactly the defect this module guards against.

Stdlib-only, offline, no network, nothing written outside pytest's own machinery.
"""
from __future__ import annotations

import inspect
import json

import pytest

from clawseccheck.catalog import CRITICAL, FAIL, LOW, PASS, Finding
from clawseccheck.layers import (
    LAYER_LIVE_BEHAVIOUR,
    LAYER_LOGS_TRAJECTORIES,
    LAYER_ORDER,
    LAYER_SELF_REPORT,
    STATUS_RAN,
    STATUS_UNAVAILABLE,
    LAYER_LABEL,
    STATUS_PHRASE,
    LayerLedger,
    LayerState,
    describe_layer,
)
from clawseccheck.scoring import ScoreResult, compute
from clawseccheck import report as report_module
from clawseccheck.report import (
    render_card,
    render_dashboard,
    render_html,
    render_json,
    render_monitor,
    render_report,
    render_svg,
)


# ── fixtures ─────────────────────────────────────────────────────────────────

def _f(fid: str, title: str, severity: str, status: str) -> Finding:
    return Finding(fid, title, severity, status, "detail", "fix", "framework")


# id "B1" / this exact title match the brief's own worked example verbatim, so the
# expected headline text can be pinned exactly rather than approximated.
_CRIT = _f("B1", "Lethal trifecta reachable", CRITICAL, FAIL)
_CLEAN = _f("B2", "some clean check", LOW, PASS)
FINDINGS_WITH_FAIL = [_CRIT, _CLEAN]
FINDINGS_ALL_CLEAN = [_CLEAN]

EXPECTED_HEADLINE = "Most urgent: CRITICAL — Lethal trifecta reachable  [B1]"
EXPECTED_ALL_CLEAR = "Nothing urgent found in what was checked."


def _all_ran_ledger() -> LayerLedger:
    return LayerLedger(states={layer: LayerState(status=STATUS_RAN) for layer in LAYER_ORDER})


def _ungraded_ledger() -> LayerLedger:
    """self_report + live_behaviour UNAVAILABLE — matches the brief's own worked
    example ("2 of 5 layers did not run: agent self-report (not available here),
    live behaviour test (not available here)."), so the expected sentence below is
    the literal spec text, not a paraphrase."""
    states = {layer: LayerState(status=STATUS_RAN) for layer in LAYER_ORDER}
    states[LAYER_SELF_REPORT] = LayerState(status=STATUS_UNAVAILABLE)
    states[LAYER_LIVE_BEHAVIOUR] = LayerState(status=STATUS_UNAVAILABLE)
    return LayerLedger(states=states)


def _not_checked_ledger() -> LayerLedger:
    """Every layer ran, but LOGS_TRAJECTORIES honestly discloses a coverage gap —
    graded stays True (it ran), not_checked stays non-empty (it didn't exhaust its
    subject). The exact wording from the brief's own worked example."""
    states = {layer: LayerState(status=STATUS_RAN) for layer in LAYER_ORDER}
    states[LAYER_LOGS_TRAJECTORIES] = LayerState(
        status=STATUS_RAN,
        not_reached=("79 of 132 log sinks not read", "3 plugin manifests unscanned"),
    )
    return LayerLedger(states=states)


EXPECTED_MISSING_SENTENCE = (
    "No grade yet — 2 of 5 layers did not run: "
    f"{describe_layer(LAYER_SELF_REPORT, STATUS_UNAVAILABLE)}, "
    f"{describe_layer(LAYER_LIVE_BEHAVIOUR, STATUS_UNAVAILABLE)}."
)
EXPECTED_NOT_COVERED_LINE = (
    "Not fully covered: 79 of 132 log sinks not read; 3 plugin manifests unscanned"
)


def _ungraded_score(findings=FINDINGS_WITH_FAIL) -> ScoreResult:
    return compute(findings, ledger=_ungraded_ledger())


def _graded_score(findings=FINDINGS_WITH_FAIL) -> ScoreResult:
    return compute(findings)


def _graded_score_with_not_checked(findings=FINDINGS_WITH_FAIL) -> ScoreResult:
    return compute(findings, ledger=_not_checked_ledger())


# ── 1. each surface, graded=False: no letter, no /100, headline + missing-layers ──

def test_terminal_report_ungraded_shows_headline_and_missing_layers():
    score = _ungraded_score()
    out = render_report(FINDINGS_WITH_FAIL, score)
    assert EXPECTED_HEADLINE in out
    assert EXPECTED_MISSING_SENTENCE in out
    assert "/100" not in out
    assert "Score: " not in out
    assert "Grade: " not in out


def test_json_ungraded_nulls_score_grade_raw_score_keeps_keys():
    score = _ungraded_score()
    payload = json.loads(render_json(FINDINGS_WITH_FAIL, score))
    assert "score" in payload and payload["score"] is None
    assert "grade" in payload and payload["grade"] is None
    assert "raw_score" in payload and payload["raw_score"] is None
    assert payload["graded"] is False
    assert payload["missing_layers"] == [
        {"layer": LAYER_SELF_REPORT, "status": STATUS_UNAVAILABLE},
        {"layer": LAYER_LIVE_BEHAVIOUR, "status": STATUS_UNAVAILABLE},
    ]
    assert payload["not_checked"] == []


def test_html_ungraded_shows_headline_and_missing_layers_no_letter_no_100():
    score = _ungraded_score()
    out = render_html(FINDINGS_WITH_FAIL, score)
    assert "Lethal trifecta reachable" in out
    assert "Most urgent:" in out
    assert EXPECTED_MISSING_SENTENCE in out
    assert "/100" not in out
    assert 'class="grade-badge"' not in out or ">?</div>" in out
    # no real grade letter rendered in the badge div
    assert f'>{score.grade}</div>' not in out


def test_badge_svg_ungraded_no_letter_no_100():
    score = _ungraded_score()
    out = render_svg(score, FINDINGS_WITH_FAIL)
    assert "/100" not in out
    assert "no grade yet" in out
    assert f">{score.grade} " not in out


def test_card_ungraded_no_letter_no_100():
    score = _ungraded_score()
    out = render_card(score, FINDINGS_WITH_FAIL)
    assert "/100" not in out
    assert "no grade yet" in out


def test_dashboard_ungraded_shows_headline_and_missing_layers_no_100():
    score = _ungraded_score()
    out = render_dashboard(FINDINGS_WITH_FAIL, score)
    assert EXPECTED_HEADLINE in out
    assert EXPECTED_MISSING_SENTENCE in out
    assert "/100" not in out


def test_monitor_line_ungraded_shows_missing_layers_no_100():
    score = _ungraded_score()
    out = render_monitor([], score)
    assert EXPECTED_MISSING_SENTENCE in out
    assert "/100" not in out
    assert "Grade:" not in out


# ── 2. zero findings -> the all-clear headline variant ─────────────────────────

def test_ungraded_with_zero_fail_findings_shows_all_clear_headline():
    score = _ungraded_score(FINDINGS_ALL_CLEAN)
    out = render_report(FINDINGS_ALL_CLEAN, score)
    assert EXPECTED_ALL_CLEAR in out
    assert "Most urgent:" not in out


# ── 3. graded=True with non-empty not_checked -> grade AND "Not fully covered" ──

def test_graded_with_not_checked_shows_grade_and_not_covered_line():
    score = _graded_score_with_not_checked()
    assert score.graded is True
    out = render_report(FINDINGS_WITH_FAIL, score)
    assert f"Score: {score.score}/100   Grade: {score.grade}" in out
    assert EXPECTED_NOT_COVERED_LINE in out


def test_json_graded_with_not_checked_keeps_real_values_and_not_checked_list():
    score = _graded_score_with_not_checked()
    payload = json.loads(render_json(FINDINGS_WITH_FAIL, score))
    assert payload["graded"] is True
    assert payload["score"] == score.score
    assert payload["grade"] == score.grade
    assert payload["raw_score"] == score.raw_score
    assert payload["not_checked"] == [
        "79 of 132 log sinks not read", "3 plugin manifests unscanned",
    ]
    assert payload["missing_layers"] == []


def test_dashboard_graded_with_not_checked_shows_not_covered_line():
    score = _graded_score_with_not_checked()
    out = render_dashboard(FINDINGS_WITH_FAIL, score)
    assert EXPECTED_NOT_COVERED_LINE in out


def test_html_graded_with_not_checked_shows_not_covered_line():
    score = _graded_score_with_not_checked()
    out = render_html(FINDINGS_WITH_FAIL, score)
    assert EXPECTED_NOT_COVERED_LINE in out


def test_monitor_graded_with_not_checked_shows_not_covered_line():
    score = _graded_score_with_not_checked()
    out = render_monitor([], score)
    assert EXPECTED_NOT_COVERED_LINE in out


# ── 4. regression: graded=True, empty not_checked -> byte-identical rendering ───
#
# The comparison C-422 itself guarantees: `compute(findings)` with no ledger at all
# versus `compute(findings, ledger=<all-five-ran ledger>)` must produce an EQUAL
# ScoreResult (tests/test_c422_ledger_scoring.py already pins that at the scoring
# layer) — this pins the SAME equality one layer up, at every renderer this task
# touched, as a real string comparison rather than a smoke test.

@pytest.mark.parametrize("findings", [FINDINGS_WITH_FAIL, FINDINGS_ALL_CLEAN, []])
def test_render_report_byte_identical_no_ledger_vs_complete_ledger(findings):
    without_ledger = compute(findings)
    with_complete_ledger = compute(findings, ledger=_all_ran_ledger())
    assert without_ledger == with_complete_ledger
    assert render_report(findings, without_ledger) == render_report(findings, with_complete_ledger)


@pytest.mark.parametrize("findings", [FINDINGS_WITH_FAIL, FINDINGS_ALL_CLEAN, []])
def test_render_json_byte_identical_no_ledger_vs_complete_ledger(findings):
    without_ledger = compute(findings)
    with_complete_ledger = compute(findings, ledger=_all_ran_ledger())
    assert render_json(findings, without_ledger) == render_json(findings, with_complete_ledger)


@pytest.mark.parametrize("findings", [FINDINGS_WITH_FAIL, FINDINGS_ALL_CLEAN, []])
def test_render_html_byte_identical_no_ledger_vs_complete_ledger(findings):
    without_ledger = compute(findings)
    with_complete_ledger = compute(findings, ledger=_all_ran_ledger())
    assert render_html(findings, without_ledger) == render_html(findings, with_complete_ledger)


@pytest.mark.parametrize("findings", [FINDINGS_WITH_FAIL, FINDINGS_ALL_CLEAN, []])
def test_render_dashboard_byte_identical_no_ledger_vs_complete_ledger(findings):
    without_ledger = compute(findings)
    with_complete_ledger = compute(findings, ledger=_all_ran_ledger())
    assert render_dashboard(findings, without_ledger) == render_dashboard(findings, with_complete_ledger)


@pytest.mark.parametrize("findings", [FINDINGS_WITH_FAIL, FINDINGS_ALL_CLEAN, []])
def test_render_card_byte_identical_no_ledger_vs_complete_ledger(findings):
    without_ledger = compute(findings)
    with_complete_ledger = compute(findings, ledger=_all_ran_ledger())
    assert render_card(without_ledger, findings) == render_card(with_complete_ledger, findings)


@pytest.mark.parametrize("findings", [FINDINGS_WITH_FAIL, FINDINGS_ALL_CLEAN, []])
def test_render_svg_byte_identical_no_ledger_vs_complete_ledger(findings):
    without_ledger = compute(findings)
    with_complete_ledger = compute(findings, ledger=_all_ran_ledger())
    assert render_svg(without_ledger, findings) == render_svg(with_complete_ledger, findings)


@pytest.mark.parametrize("findings", [FINDINGS_WITH_FAIL, FINDINGS_ALL_CLEAN, []])
def test_render_monitor_byte_identical_no_ledger_vs_complete_ledger(findings):
    without_ledger = compute(findings)
    with_complete_ledger = compute(findings, ledger=_all_ran_ledger())
    assert render_monitor([], without_ledger) == render_monitor([], with_complete_ledger)


# ── 5. text and --json agree about graded/not_checked/missing_layers ────────────

def test_text_and_json_agree_on_graded_state_for_the_same_run():
    score = _ungraded_score()
    text = render_report(FINDINGS_WITH_FAIL, score)
    payload = json.loads(render_json(FINDINGS_WITH_FAIL, score))

    assert payload["graded"] is score.graded is False
    assert payload["not_checked"] == list(score.not_checked)
    assert payload["missing_layers"] == [
        {"layer": layer, "status": status} for layer, status in score.missing_layers
    ]
    # the text surface names the exact same missing layers, via describe_layer
    for layer, status in score.missing_layers:
        assert describe_layer(layer, status) in text


def test_text_and_json_agree_on_graded_state_when_graded_true():
    score = _graded_score_with_not_checked()
    text = render_report(FINDINGS_WITH_FAIL, score)
    payload = json.loads(render_json(FINDINGS_WITH_FAIL, score))

    assert payload["graded"] is score.graded is True
    assert payload["not_checked"] == list(score.not_checked)
    assert payload["missing_layers"] == []
    assert "; ".join(score.not_checked) in text


# ── 6. no renderer invents a letter of its own ──────────────────────────────────

_ABSURD_GRADE = "Ω-EXTREME"


def _absurd_score() -> ScoreResult:
    # Positional construction (tail-append discipline, same as test_c422's own
    # positional test) — score, grade, capped, raw_score, failed_critical, failed_high.
    return ScoreResult(57, _ABSURD_GRADE, False, 57, 0, 0)


def test_no_renderer_hardcodes_a_fallback_grade_letter():
    score = _absurd_score()
    assert score.graded is True  # sanity: this is the ordinary graded path

    text = render_report(FINDINGS_WITH_FAIL, score)
    assert f"Grade: {_ABSURD_GRADE}" in text

    dashboard = render_dashboard(FINDINGS_WITH_FAIL, score)
    assert f"Grade {_ABSURD_GRADE}" in dashboard

    card = render_card(score, FINDINGS_WITH_FAIL)
    assert _ABSURD_GRADE in card

    monitor = render_monitor([], score)
    assert f"Grade: {_ABSURD_GRADE}" in monitor

    svg = render_svg(score, FINDINGS_WITH_FAIL)
    assert _ABSURD_GRADE in svg

    html_out = render_html(FINDINGS_WITH_FAIL, score)
    assert _ABSURD_GRADE in html_out

    payload = json.loads(render_json(FINDINGS_WITH_FAIL, score))
    assert payload["grade"] == _ABSURD_GRADE


# ── 7. no competing wording table: layer/status phrasing goes through
#      layers.describe_layer only ───────────────────────────────────────────────

# "ran"/"failed" are excluded: both are short, generic English substrings that
# collide with unrelated text already in report.py (e.g. "brand" contains "ran";
# "the write failed" is unrelated prose) — checking them would false-positive, not
# catch a real competing table. Every genuinely distinctive phrase is still checked.
_SKIP_STATUS_PHRASES = {"ran", "failed"}


def test_report_module_has_no_competing_layer_label_table():
    source = inspect.getsource(report_module)
    for layer, label in LAYER_LABEL.items():
        assert label not in source, (
            f"report.py hardcodes layer label {label!r} for {layer!r} instead of "
            "routing through layers.describe_layer"
        )


def test_report_module_has_no_competing_status_phrase_table():
    source = inspect.getsource(report_module)
    for status, phrase in STATUS_PHRASE.items():
        if phrase in _SKIP_STATUS_PHRASES:
            continue
        assert phrase not in source, (
            f"report.py hardcodes status phrase {phrase!r} for {status!r} instead of "
            "routing through layers.describe_layer"
        )
