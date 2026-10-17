"""C-737: a gradeless run whose self-report was never handed in must SAY, in the tool's own
output, that item 1 of the standard flow is unfinished and what to run next.

A real agent delivered the compact card of such a run without ever filling in the self-report
or running the judge panel. The only place that told it to was prose in SKILL.md, read many
steps earlier, and SKILL.md has no room left to say it louder. The tool knows exactly when the
self-report layer is ``not_submitted``, so every surface that prints the layer ledger adds one
line from ``layers.item1_next_step_sentence`` (the single wording table).

What it must NOT do: move a score, a grade, an exit code or a JSON key; appear on a graded run;
appear when the self-report layer is missing for another reason (declined, unavailable, failed),
where the advice would not fit; contain a non-ASCII character.
"""

from __future__ import annotations

import pytest

from _pdftext import content_text
from clawseccheck import report as report_module
from clawseccheck.catalog import CRITICAL, FAIL, LOW, PASS, Finding
from clawseccheck.layers import (
    LAYER_LIVE_BEHAVIOUR,
    LAYER_ORDER,
    LAYER_SELF_REPORT,
    LAYER_STATIC,
    STATUS_ERROR,
    STATUS_NOT_SUBMITTED,
    STATUS_RAN,
    STATUS_REFUSED,
    STATUS_UNAVAILABLE,
    LayerLedger,
    LayerState,
    item1_next_step_sentence,
)
from clawseccheck.pdf import render_pdf
from clawseccheck.report import render_dashboard, render_html, render_json, render_report
from clawseccheck.scoring import compute

SENTENCE = "Item 1 is not finished: --ask, fill in, --attest, then the judge panel."


def _f(fid, severity, status):
    return Finding(fid, f"Title {fid}", severity, status, "detail text", "fix text", "Test")


FINDINGS = [_f("B1", CRITICAL, FAIL), _f("B2", LOW, PASS)]


def _ledger(**overrides):
    states = {layer: LayerState(status=STATUS_RAN) for layer in LAYER_ORDER}
    for layer, status in overrides.items():
        states[layer] = LayerState(status=status)
    return LayerLedger(states=states)


def _score(self_report=STATUS_NOT_SUBMITTED, live=STATUS_NOT_SUBMITTED):
    return compute(FINDINGS, ledger=_ledger(
        **{LAYER_SELF_REPORT: self_report, LAYER_LIVE_BEHAVIOUR: live}))


# ----------------------------------------------------------------------- the function
def test_the_sentence_appears_only_for_a_self_report_that_was_not_submitted():
    assert item1_next_step_sentence(((LAYER_SELF_REPORT, STATUS_NOT_SUBMITTED),)) == SENTENCE
    assert item1_next_step_sentence(
        ((LAYER_LIVE_BEHAVIOUR, STATUS_NOT_SUBMITTED), (LAYER_SELF_REPORT, STATUS_NOT_SUBMITTED))
    ) == SENTENCE


@pytest.mark.parametrize("status", [STATUS_REFUSED, STATUS_UNAVAILABLE, STATUS_ERROR, STATUS_RAN])
def test_a_self_report_missing_for_another_reason_gets_no_advice(status):
    assert item1_next_step_sentence(((LAYER_SELF_REPORT, status),)) == ""


@pytest.mark.parametrize("layer", [LAYER_LIVE_BEHAVIOUR, LAYER_STATIC])
def test_another_layer_not_submitted_gets_no_advice(layer):
    assert item1_next_step_sentence(((layer, STATUS_NOT_SUBMITTED),)) == ""


@pytest.mark.parametrize("empty", [(), [], None])
def test_nothing_missing_gets_nothing(empty):
    assert item1_next_step_sentence(empty) == ""


def test_the_wording_is_ascii_and_names_the_real_flags():
    assert SENTENCE.isascii()
    for flag in ("--ask", "--attest"):
        assert flag in SENTENCE


# ---------------------------------------------------------------------- each surface
def test_the_text_report_carries_it_once_after_the_layer_definition():
    """C-704's contract stays intact: the definition sentence is directly under the headline;
    the next-step line follows the definition."""
    out = render_report(FINDINGS, _score())
    assert out.count(SENTENCE) == 1
    lines = out.splitlines()
    i = next(n for n, ln in enumerate(lines) if ln.startswith("No grade yet"))
    assert lines[i + 1].startswith("A grade needs all 5 layers of evidence")
    assert lines[i + 2] == SENTENCE


def test_the_compact_card_carries_it():
    out = render_dashboard(FINDINGS, _score(), compact=True)
    assert out.count(SENTENCE) == 1


def test_the_full_card_carries_it():
    out = render_dashboard(FINDINGS, _score(), compact=False)
    assert out.count(SENTENCE) == 1


def test_the_html_page_carries_it():
    out = render_html(FINDINGS, _score())
    assert out.count(SENTENCE) == 1


def test_the_pdf_carries_it():
    text = content_text(render_pdf(FINDINGS, _score()))
    assert "Item 1 is not finished" in text


# --------------------------------------------------------------------- what must not move
def test_a_graded_run_never_carries_it():
    graded = compute(FINDINGS)
    assert graded.graded is True
    for out in (render_report(FINDINGS, graded), render_dashboard(FINDINGS, graded, compact=True),
                render_html(FINDINGS, graded)):
        assert "Item 1 is not finished" not in out


def test_a_declined_self_report_gets_no_advice_on_any_surface():
    score = _score(self_report=STATUS_REFUSED)
    for out in (render_report(FINDINGS, score), render_dashboard(FINDINGS, score, compact=True),
                render_html(FINDINGS, score)):
        assert "Item 1 is not finished" not in out


def test_score_grade_and_json_do_not_depend_on_the_sentence():
    submitted = _score(self_report=STATUS_RAN)
    missing = _score(self_report=STATUS_NOT_SUBMITTED)
    # the same findings are scored the same way; the sentence is rendering only
    assert (submitted.score, submitted.raw_score) == (missing.score, missing.raw_score)
    assert "Item 1 is not finished" not in render_json(FINDINGS, missing)


def test_the_rendered_line_stays_ascii_when_the_surface_folds_to_ascii():
    out = render_report(FINDINGS, _score(), ascii_only=True)
    assert SENTENCE in out


def test_the_module_keeps_one_wording_table():
    """No renderer may carry its own copy of the sentence (the single-table rule)."""
    import inspect

    for mod in (report_module,):
        assert "Item 1 is not finished" not in inspect.getsource(mod)
