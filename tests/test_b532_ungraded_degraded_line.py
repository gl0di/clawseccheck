"""B-532 — the degraded-checks disclosure may not name a grade the run never gave.

C-423 taught every renderer that `graded is False` means no letter and no `/100`
anywhere. What it did not sweep is the *prose around* the number: sentences that print
no digits at all but presuppose one exists. On a real ungraded run the reader saw

    No grade yet - 3 of 5 layers did not run: ...
    [!]33 checks could not reach a reliable verdict this run (...) - this grade is
    incomplete.

three lines apart, on one screen — a page that says it withheld the grade, then refers
the reader to "this grade". The reader is left hunting for a letter that is not there,
and the second sentence reads as a bug in the first.

The fix is a reword, never a suppression (CLAUDE.md doctrine: never suppress a real
disclosure to make output look clean). "N checks could not reach a reliable verdict this
run (crashed, timed out, or hit unreadable/corrupted input)" is true whether or not the
run earned a letter, so it must print byte-identical in both branches; only the trailing
clause becomes "this run's coverage is incomplete." The wording deliberately does not
claim the degraded checks *caused* the missing grade — missing layers do that, and
inventing a causal link would be a fabricated fact in the other direction.

Four sites were proven reachable and are pinned here: the text banner, the HTML report,
the PDF, and the separate no-`openclaw.json` line that told an ungraded reader "NOT
counted against your score — the grade reflects only the N assessable check(s)". All
three renderers now take the clause from one helper
(`report._degraded_incomplete_clause`) — B-483's lesson that one sentence built from
three literals is three chances to diverge.

The graded direction is asserted just as hard: a fix that made the honest wording
unconditional would delete a true disclosure from every ordinary run.

PDF note: `render_pdf` Flate-compresses its content stream, so a raw byte search sails
past every string the PDF actually shows (the B-531 blindness). `_searchable` below
inflates first, reusing the idiom from `tests/test_b512_ungraded_writers.py`.

Stdlib-only, offline, writes nothing outside pytest's own machinery.
"""
from __future__ import annotations

import re
import zlib

import pytest

from clawseccheck.catalog import CRITICAL, FAIL, HIGH, LOW, PASS, UNKNOWN, Finding
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
from clawseccheck.report import render_html, render_report
from clawseccheck.scoring import compute

# The fact half of the disclosure — must survive verbatim in BOTH directions. Kept
# without its surrounding punctuation so the same string can be searched in the text
# banner, the HTML paragraph and the (ASCII-folded) PDF alike.
FACT = ("could not reach a reliable verdict this run (crashed, timed out, or hit "
        "unreadable/corrupted input)")
GRADE_CLAUSE = "this grade is incomplete."
COVERAGE_CLAUSE = "this run's coverage is incomplete."


def _f(fid: str, title: str, severity: str, status: str, **kw) -> Finding:
    return Finding(fid, title, severity, status, "detail", "fix", "framework", **kw)


# Two degraded checks, one per structural source scoring._degraded_signal recognises:
# the run_all wrapper's "ERR:"-prefixed UNKNOWN (crash/timeout) and a check that ran,
# kept its own id, and self-reported engine_degraded (unreadable/corrupt input).
DEGRADED_FINDINGS = [
    _f("B1", "Lethal trifecta reachable", CRITICAL, FAIL),
    _f("ERR:B7", "check crashed", HIGH, UNKNOWN),
    _f("B9", "config unreadable", HIGH, UNKNOWN, engine_degraded=True),
    _f("B2", "some clean check", LOW, PASS),
]


def _ungraded():
    """Layers 4 and 5 unavailable — the shape every ordinary run has today."""
    states = {ln: LayerState(status=STATUS_RAN) for ln in LAYER_ORDER}
    states[LAYER_SELF_REPORT] = LayerState(status=STATUS_UNAVAILABLE)
    states[LAYER_LIVE_BEHAVIOUR] = LayerState(status=STATUS_UNAVAILABLE)
    return compute(DEGRADED_FINDINGS, ledger=LayerLedger(states=states))


def _graded():
    return compute(DEGRADED_FINDINGS,
                   ledger=LayerLedger(states={ln: LayerState(status=STATUS_RAN)
                                              for ln in LAYER_ORDER}))


def _searchable(artifact) -> str:
    """The artifact as text, with any Flate-compressed stream inflated alongside it.

    Same idiom as tests/test_b512_ungraded_writers.py::_searchable — without it a PDF
    assertion silently tests nothing, because the strings live inside a deflate stream.

    One step further than that module needs: a whole SENTENCE (rather than a short
    token like ``Capped from 100``) is never contiguous in a PDF — `_PageFlow.wrapped`
    breaks it across several ``(...) Tj`` show operators, and ``(``/``)`` arrive escaped.
    So the drawn strings are also unescaped, re-joined and whitespace-collapsed; without
    that, every PDF assertion here would fail on a correct renderer.
    """
    text = artifact.decode("latin-1") if isinstance(artifact, bytes) else artifact
    if not isinstance(artifact, bytes) or b"FlateDecode" not in artifact:
        return text
    for match in re.finditer(rb"stream\r?\n(.*?)endstream", artifact, re.S):
        try:
            text += zlib.decompress(match.group(1)).decode("latin-1")
        except Exception:  # not every stream is deflate, and a bad one proves nothing
            continue
    drawn = " ".join(
        re.sub(r"\\([()\\])", r"\1", m.group(1))
        for m in re.finditer(r"\(((?:[^()\\]|\\.)*)\)\s*Tj", text)
    )
    return text + "\n" + re.sub(r"\s+", " ", drawn)


def _surfaces(score) -> dict:
    return {
        "text": render_report(DEGRADED_FINDINGS, score, ascii_only=True, color=False),
        "html": render_html(DEGRADED_FINDINGS, score),
        "pdf": _searchable(render_pdf(DEGRADED_FINDINGS, score)),
    }


# ── preconditions: without these the assertions below describe nothing ───────

def test_the_fixtures_really_are_degraded_and_differently_graded():
    ungraded, graded = _ungraded(), _graded()
    assert ungraded.graded is False and graded.graded is True
    assert ungraded.degraded_count == 2 == graded.degraded_count


@pytest.mark.parametrize("surface", ["text", "html", "pdf"])
def test_the_fact_is_stated_on_an_ungraded_run(surface):
    """The disclosure is never suppressed to tidy up an ungraded screen."""
    text = _surfaces(_ungraded())[surface]
    # The PDF folds the em dash and draws ASCII only, so search the fact alone.
    assert FACT in text, f"{surface} dropped the degraded-checks disclosure entirely"
    assert "2 checks could not reach" in text, f"{surface} lost the count"


@pytest.mark.parametrize("surface", ["text", "html", "pdf"])
def test_no_grade_clause_on_an_ungraded_run(surface):
    """The bug itself: 'this grade is incomplete' under a page saying 'No grade yet'."""
    text = _surfaces(_ungraded())[surface]
    assert GRADE_CLAUSE not in text, (
        f"{surface} refers the reader to a grade this run never printed"
    )
    assert COVERAGE_CLAUSE in text, f"{surface} lost the reworded clause"


@pytest.mark.parametrize("surface", ["text", "html", "pdf"])
def test_graded_run_keeps_the_original_sentence(surface):
    """No regression: the honest wording must not become unconditional."""
    text = _surfaces(_graded())[surface]
    assert FACT in text
    assert GRADE_CLAUSE in text, f"{surface} withheld a grade caveat it had earned"
    assert COVERAGE_CLAUSE not in text


def test_text_banner_keeps_its_debug_pointer_in_both_directions():
    """The reword replaced a clause mid-sentence — the tail must still be attached."""
    for score in (_ungraded(), _graded()):
        text = render_report(DEGRADED_FINDINGS, score, ascii_only=True, color=False)
        assert "Re-run with --debug for a crash/timeout traceback" in text


def test_ungraded_run_does_not_promise_a_causal_link_it_cannot_prove():
    """Degraded checks do not cause ungraded status — missing layers do.

    Pins the wording choice, not just the absence of the old clause: a reword that
    said "that is why this run has no grade" would satisfy every assertion above
    while stating something false.
    """
    for text in _surfaces(_ungraded()).values():
        low = text.lower()
        for phrasing in ("why this run has no grade", "why there is no grade",
                         "no grade was given"):
            assert phrasing not in low, f"fabricated causal claim: {phrasing!r}"


# ── the second proven site: the no-openclaw.json UNKNOWN explanation ─────────

def test_unknown_explanation_drops_the_score_and_grade_nouns_when_ungraded():
    text = render_report(DEGRADED_FINDINGS, _ungraded(), ascii_only=True, color=False,
                         openclaw_detected=False)
    assert "were not assessed (UNKNOWN) and are NOT counted against you" in text
    assert "these findings reflect only the" in text
    assert "counted against your score" not in text
    assert "the grade reflects only the" not in text


def test_unknown_explanation_is_unchanged_on_a_graded_run():
    text = render_report(DEGRADED_FINDINGS, _graded(), ascii_only=True, color=False,
                         openclaw_detected=False)
    assert "counted against your score" in text
    assert "the grade reflects only the" in text


# ── single source of the clause (B-483: three literals are three divergences) ─

def test_all_three_renderers_take_the_clause_from_one_helper():
    """A per-renderer literal is exactly what C-423/B-531 cost us; keep it impossible."""
    import inspect

    from clawseccheck import pdf as pdf_mod
    from clawseccheck import report as report_mod

    helper_src = inspect.getsource(report_mod._degraded_incomplete_clause)
    for mod in (report_mod, pdf_mod):
        with open(mod.__file__, encoding="utf-8") as fh:
            src = fh.read()
        for clause in (GRADE_CLAUSE, COVERAGE_CLAUSE):
            # Every occurrence in the tree must be inside the helper — anywhere else is
            # a renderer wording it for itself again.
            assert src.count(clause) == (helper_src.count(clause)
                                         if mod is report_mod else 0), (
                f"{mod.__name__} carries its own copy of {clause!r}"
            )
