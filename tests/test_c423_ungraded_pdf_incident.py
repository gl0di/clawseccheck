"""CLAWSECCHECK-C-423 — `pdf.py` and `incident.py` learn that a run can have no grade.

`ScoreResult.graded` (C-422, `scoring.py`) means no consumer may ever print a letter or
a number for an ungraded run; `not_checked` is the honesty line that applies even on a
graded run. This file pins both renderers to that contract, and pins that neither one
ever grows its own copy of `layers.py`'s wording — `layers.describe_layer` is the one
formatting site (CLAUDE.md I2b work order).

Offline, stdlib only, nothing written outside pytest's own machinery.
"""
from __future__ import annotations

import re
from pathlib import Path

from clawseccheck.catalog import FAIL, HIGH, WARN, Finding
from clawseccheck.collector import Context
from clawseccheck.incident import build_incident
from clawseccheck.layers import (
    LAYER_INSTALLED_SWEEP,
    LAYER_LABEL,
    LAYER_LIVE_BEHAVIOUR,
    LAYER_LOGS_TRAJECTORIES,
    LAYER_ORDER,
    LAYER_SELF_REPORT,
    LAYER_STATIC,
    STATUS_ERROR,
    STATUS_NOT_REACHED,
    STATUS_PHRASE,
    STATUS_RAN,
    STATUS_REFUSED,
    STATUS_SKIPPED,
    STATUS_UNAVAILABLE,
    LayerLedger,
    LayerState,
    describe_layer,
)
from clawseccheck.pdf import _CONTENT_W, _text_width, render_pdf
from clawseccheck.scoring import compute

_REPO_ROOT = Path(__file__).resolve().parent.parent

# ── helpers (mirrors tests/test_pdf.py + tests/test_c422_ledger_scoring.py house style) ──


def _finding(id_: str, status: str, severity: str = HIGH, detail: str = "detail text") -> Finding:
    return Finding(
        id=id_, title=f"Title for {id_}", severity=severity, status=status,
        detail=detail, fix="fix text", framework="Test", scored=True, evidence=[],
    )


def _ctx(home) -> Context:
    ctx = Context(home=home)
    ctx.config = {}
    ctx.installed_skills = {}
    return ctx


def _all_ran_ledger() -> LayerLedger:
    return LayerLedger(states={layer: LayerState(status=STATUS_RAN) for layer in LAYER_ORDER})


def _ledger_with(layer: str, status: str, not_reached: tuple = ()) -> LayerLedger:
    states = {lyr: LayerState(status=STATUS_RAN) for lyr in LAYER_ORDER}
    states[layer] = LayerState(status=status, not_reached=not_reached)
    return LayerLedger(states=states)


def _all_missing_ledger() -> LayerLedger:
    """Every one of the five layers incomplete, a different status each, so
    `missing_layers` is as long as it can get."""
    statuses = [STATUS_SKIPPED, STATUS_REFUSED, STATUS_UNAVAILABLE, STATUS_ERROR, STATUS_NOT_REACHED]
    return LayerLedger(states={
        layer: LayerState(status=status) for layer, status in zip(LAYER_ORDER, statuses)
    })


def _content_text(data: bytes) -> str:
    """All page content streams, decompressed and concatenated (tests/test_pdf.py's own
    helper, reproduced here rather than imported across test modules)."""
    import zlib
    out = ""
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", data, re.S):
        try:
            out += zlib.decompress(m.group(1)).decode("latin-1", "replace")
        except zlib.error:
            continue
    return out


def _tj_lines(text: str) -> list[str]:
    """Every drawn text operand, PDF-literal-unescaped, in document order."""
    return [m.replace(r"\(", "(").replace(r"\)", ")") for m in re.findall(r"\((.*?)\)\s*Tj", text)]


# ── 1. PDF ungraded: no letter, no /100, missing-layers wording present ──────────────


def test_pdf_ungraded_shows_no_letter_or_number_but_names_missing_layers():
    findings = [_finding("B1", FAIL)]
    score = compute(findings, ledger=_ledger_with(LAYER_SELF_REPORT, STATUS_UNAVAILABLE))
    assert score.graded is False

    data = render_pdf(findings, score)
    assert data.startswith(b"%PDF-1.4")
    text = _content_text(data)

    assert "/100" not in text
    assert "Security score" not in text
    assert "/F2 30" not in text  # the 30pt bold grade-letter glyph is never drawn

    assert "No grade yet - 1 of 5 layers did not run" in text
    expected = describe_layer(LAYER_SELF_REPORT, STATUS_UNAVAILABLE)
    escaped = expected.replace("(", r"\(").replace(")", r"\)")
    assert escaped in text


# ── 2. PDF graded, empty not_checked: byte-identical to today ────────────────────────
#
# "Today" = the call every existing site (including every pre-C-423 render_pdf test)
# makes: `compute(findings)` with no ledger at all. scoring.py's own C-422 guarantee is
# that an explicit COMPLETE ledger must be indistinguishable from no ledger — this
# proves the new `if score.graded:` branch in pdf.py did not silently change that.


def test_pdf_graded_empty_not_checked_is_byte_identical_to_today():
    findings = [_finding("B1", FAIL), _finding("B2", WARN)]
    default_score = compute(findings)
    complete_score = compute(findings, ledger=_all_ran_ledger())

    assert default_score.graded is True
    assert default_score.not_checked == ()
    assert complete_score == default_score

    a = render_pdf(findings, default_score)
    b = render_pdf(findings, complete_score)
    assert a == b

    text = _content_text(a)
    assert "Security score" in text
    assert "No grade yet" not in text
    assert "Not fully covered" not in text


# ── 3. PDF graded, non-empty not_checked: grade present AND "Not fully covered" ──────


def test_pdf_graded_with_not_checked_shows_grade_and_not_fully_covered_line():
    findings = [_finding("B1", FAIL)]
    ledger = _ledger_with(LAYER_STATIC, STATUS_RAN, not_reached=("79 of 132 log sinks not read",))
    score = compute(findings, ledger=ledger)
    assert score.graded is True
    assert score.not_checked == ("79 of 132 log sinks not read",)

    data = render_pdf(findings, score)
    text = _content_text(data)
    assert "Security score" in text
    assert f"{score.score}/100" in text
    assert "Not fully covered:" in text
    assert "79 of 132 log sinks not read" in text


# ── 4. a long missing_layers list wraps rather than overflows ────────────────────────


def test_pdf_long_missing_layers_list_wraps_not_overflows():
    findings = [_finding("B1", FAIL)]
    score = compute(findings, ledger=_all_missing_ledger())
    assert score.graded is False
    assert len(score.missing_layers) == 5

    missing_text = ", ".join(describe_layer(layer, status) for layer, status in score.missing_layers)
    # test setup sanity: this sentence really is longer than one line at the size the
    # PDF draws it, or wrapping would trivially "not overflow" without proving anything.
    assert _text_width(missing_text, 9.5) > _CONTENT_W

    data = render_pdf(findings, score)
    assert data.startswith(b"%PDF-1.4")
    text = _content_text(data)

    lines = _tj_lines(text)
    # every drawn line that is (a substring of) the missing-layers sentence -- picked
    # out because that sentence is long/distinctive enough that no other page content
    # coincidentally matches it for this single-finding fixture.
    candidate_lines = [ln for ln in lines if ln and ln in missing_text]
    assert len(candidate_lines) >= 2, (
        f"expected the missing-layers sentence to wrap across >=2 drawn lines, got: {candidate_lines}")
    for ln in candidate_lines:
        assert _text_width(ln, 9.5) <= _CONTENT_W + 0.5, f"line overflowed the content box: {ln!r}"
    # nothing dropped: rejoining the wrapped lines with single spaces reproduces the
    # exact original sentence (wrapping only ever breaks BETWEEN words).
    assert " ".join(candidate_lines) == missing_text


# ── 5. incident pack ungraded: graded false, score/grade None, keys present ──────────


def test_incident_ungraded_nulls_score_and_grade_keeps_keys(tmp_path):
    ctx = _ctx(tmp_path)
    findings = [_finding("B1", FAIL)]
    score = compute(findings, ledger=_ledger_with(LAYER_LIVE_BEHAVIOUR, STATUS_UNAVAILABLE))
    assert score.graded is False

    payload = build_incident(ctx, findings, score, when="2026-08-07T00:00:00")
    assert set(payload["score"]) == {"score", "grade", "graded", "not_checked", "missing_layers"}
    assert payload["score"]["graded"] is False
    assert payload["score"]["score"] is None
    assert payload["score"]["grade"] is None
    # Named object, not a positional pair — identical to --json's shape, so a reader who
    # has learned one machine surface does not have to learn a second for the same fact.
    assert payload["score"]["missing_layers"] == [
        {"layer": LAYER_LIVE_BEHAVIOUR, "status": STATUS_UNAVAILABLE}
    ]
    assert payload["score"]["not_checked"] == []


def test_incident_ungraded_pack_is_still_valid_json(tmp_path):
    """A None-valued key must round-trip through json.dumps/loads exactly as null,
    never a KeyError and never a dropped key."""
    import json
    from clawseccheck.incident import render_incident

    ctx = _ctx(tmp_path)
    findings = [_finding("B1", FAIL)]
    score = compute(findings, ledger=_ledger_with(LAYER_INSTALLED_SWEEP, STATUS_ERROR))
    out = render_incident(ctx, findings, score, when="2026-08-07T00:00:00")
    payload = json.loads(out)
    assert payload["score"]["score"] is None
    assert payload["score"]["grade"] is None
    assert payload["score"]["graded"] is False


# ── 6. incident pack graded: unchanged apart from the additive keys ──────────────────


def test_incident_graded_unchanged_apart_from_additive_keys(tmp_path):
    ctx = _ctx(tmp_path)
    findings = [_finding("B1", FAIL)]
    score = compute(findings)  # no ledger -- today's default, graded=True

    payload = build_incident(ctx, findings, score, when="2026-08-07T00:00:00")
    assert set(payload["score"]) == {"score", "grade", "graded", "not_checked", "missing_layers"}
    assert payload["score"]["score"] == score.score
    assert payload["score"]["grade"] == score.grade
    assert payload["score"]["graded"] is True
    assert payload["score"]["not_checked"] == []
    assert payload["score"]["missing_layers"] == []


def test_incident_graded_with_not_checked_carries_the_coverage_gap(tmp_path):
    ctx = _ctx(tmp_path)
    findings = [_finding("B1", FAIL)]
    ledger = _ledger_with(LAYER_LOGS_TRAJECTORIES, STATUS_RAN, not_reached=("79 of 132 log sinks not read",))
    score = compute(findings, ledger=ledger)
    assert score.graded is True

    payload = build_incident(ctx, findings, score, when="2026-08-07T00:00:00")
    assert payload["score"]["graded"] is True
    assert payload["score"]["score"] == score.score
    assert payload["score"]["grade"] == score.grade
    assert payload["score"]["not_checked"] == ["79 of 132 log sinks not read"]
    assert payload["score"]["missing_layers"] == []


# ── 7. neither file carries its own copy of a layer label or status phrase ───────────


def test_neither_file_hardcodes_layer_wording():
    pdf_text = (_REPO_ROOT / "clawseccheck" / "pdf.py").read_text(encoding="utf-8")
    incident_text = (_REPO_ROOT / "clawseccheck" / "incident.py").read_text(encoding="utf-8")

    assert "describe_layer" in pdf_text, (
        "pdf.py must format layer/status wording exclusively through layers.describe_layer")

    # STATUS_RAN's own phrase, "ran", is excluded: it is an ordinary English word that
    # legitimately appears in this file's own prose comments (e.g. "a layer that ran"),
    # so a bare substring/word match on it is not a meaningful hardcoding signal the way
    # it is for the other, distinctive multi-word phrases below.
    checked_phrases = [p for p in STATUS_PHRASE.values() if p != "ran"]
    for label in LAYER_LABEL.values():
        assert label not in pdf_text, f"pdf.py hardcodes layer label {label!r} instead of describe_layer"
        assert label not in incident_text, f"incident.py hardcodes layer label {label!r}"
    for phrase in checked_phrases:
        assert phrase not in pdf_text, f"pdf.py hardcodes status phrase {phrase!r} instead of describe_layer"
        assert phrase not in incident_text, f"incident.py hardcodes status phrase {phrase!r}"


def test_pdf_ungraded_wording_matches_describe_layer_exactly():
    """Functional half of the hard rule: the sentence actually drawn for a missing
    layer is not just "doesn't hardcode a phrase" but is byte-for-byte what
    `layers.describe_layer` returns -- for every layer/status pair, not just one."""
    findings = [_finding("B1", FAIL)]
    for layer in LAYER_ORDER:
        for status in (STATUS_SKIPPED, STATUS_REFUSED, STATUS_UNAVAILABLE, STATUS_ERROR, STATUS_NOT_REACHED):
            score = compute(findings, ledger=_ledger_with(layer, status))
            data = render_pdf(findings, score)
            text = _content_text(data)
            expected = describe_layer(layer, status)
            escaped = expected.replace("(", r"\(").replace(")", r"\)")
            assert escaped in text, f"{layer}/{status}: {expected!r} not found verbatim in the PDF"
