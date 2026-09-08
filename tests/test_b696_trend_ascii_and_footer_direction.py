"""Two things `--trend` said that were not true, both introduced or exposed by B-691.

**The footer contradicted the row three lines above it.** B-691's clause fires whenever the
uncapped pass-rate falls, which is right — but its sentence was written for one case and
applied to all of them:

    2026-08-01T09:00:00  A  90  =  [audit]  ~/.openclaw
    2026-08-02T09:00:00  D  60  v  [audit]  ~/.openclaw  (pass-rate fell 95 -> 74)

    1 run above kept or raised its score while the underlying pass-rate fell. ...

The score fell. The arrow says so on the same screen. B-691's own test pinned the flat and
the rising cases and never the falling one, so nothing exercised the contradiction.

**`--ascii` emitted a non-ASCII character.** B-691's pinned-score paragraph carried an em dash
(and so, it turned out, does the chain-provenance paragraph B-582 added before it),
and `--ascii` exists to promise pure ASCII. The guard that checks that promise —
`test_b478_b483_inert_flags.py::test_ascii_mode_emits_pure_ascii` — covers twelve modes and
`--trend` is not among them, so the one thing that would have caught it was not looking. A
sibling test now covers `--trend` there; it cannot join the parametrize because `--trend`
records unconditionally (C-251) and needs a writable path a static list cannot supply.

Adding that guard immediately found a SECOND leak, older than B-691 and not caused by it:
`_percentile_line`'s two ungraded branches compose their own prose without folding, and
`_missing_layers_sentence`'s "No grade yet — N of 5 layers…" carries two more em dashes.
`--trend` prints that line. Both now fold at their function's single exit, which is the
discipline `report.py` already uses in four places — not a per-paragraph ASCII rule, which is
the second-copy shape B-689/B-692/B-693/B-694 each turned out to be.

Offline, stdlib only, writes nothing outside tmp_path.
"""
from __future__ import annotations

import pytest

from clawseccheck.catalog import Finding
from clawseccheck.history import load, record, render_trend

_HOME = "~/.openclaw"
_VER = "3.61.0"
_FINDINGS = [Finding(id="B1", title="t", severity="HIGH", status="FAIL",
                     detail="d", fix="f", framework="x")]
_OTHER_FINDINGS = [Finding(id="B1", title="t", severity="HIGH", status="FAIL",
                           detail="d", fix="f", framework="x"),
                   Finding(id="B2", title="t", severity="HIGH", status="FAIL",
                           detail="d", fix="f", framework="x")]

_PINNED = "kept or raised"
_BOTH = "fell on both measures"


class _Score:
    def __init__(self, score, grade, raw_score, graded=True):
        self.score, self.grade, self.raw_score = score, grade, raw_score
        self.assessable, self.graded = True, graded


def _render(tmp_path, rows, *, ascii_only=True, retention=None, chain=None):
    """Through the real record() -> load() -> render_trend() path.

    `retention` and `chain` drive the two paragraphs fed by something other than the rows
    -- `rows.retention_notice`, an attribute `load()` attaches to its `HistoryRows`, and
    `render_trend`'s own `chain_status` argument -- so the parametrize below can reach
    every disclosure paragraph, not only the ones a store shape can produce.
    """
    path = str(tmp_path / "history.jsonl")
    for day, kwargs in enumerate(rows, 1):
        record(path=path, when=f"2026-08-{day:02d}T09:00:00", **kwargs)
    loaded = load(path)
    if retention is not None:
        loaded.retention_notice = retention
    return render_trend(loaded, ascii_only=ascii_only, chain_status=chain)


def _row(score, *, findings=_FINDINGS, home=_HOME, version=_VER, source="audit"):
    return dict(score=score, source=source, home=home, findings=findings, version=version)


# --------------------------------------------------- the footer matches its own rows

def test_a_run_whose_score_also_fell_is_not_told_it_kept_it(tmp_path):
    """The regression. Both figures moved down, so the pinned-score explanation is simply
    the wrong sentence — and it was rendered directly under an arrow that said so."""
    out = _render(tmp_path, [_row(_Score(90, "A", 95)), _row(_Score(60, "D", 74))])
    assert _PINNED not in out, out
    assert _BOTH in out, out
    assert "(pass-rate fell 95 -> 74)" in out, out


@pytest.mark.parametrize("second,label", [
    (_Score(49, "F", 74), "flat"),
    (_Score(74, "C", 74), "risen"),
], ids=["score-flat", "score-rose"])
def test_the_pinned_sentence_still_fires_where_it_was_right(tmp_path, second, label):
    """The controls. Splitting the footer must not silence the case B-691 existed for —
    without these, deleting the pinned paragraph outright would pass the test above."""
    out = _render(tmp_path, [_row(_Score(49, "F", 92)), _row(second)])
    assert _PINNED in out, (label, out)
    assert _BOTH not in out, (label, out)


def test_the_two_sentences_are_never_both_claimed_about_one_run(tmp_path):
    """One run, one direction. A run cannot both keep its score and have it fall."""
    out = _render(tmp_path, [_row(_Score(90, "A", 95)), _row(_Score(60, "D", 74))])
    assert (_PINNED in out) != (_BOTH in out), out


def test_a_store_with_both_kinds_says_both(tmp_path):
    """They are separate counters, not a switch: a real store can hold one of each."""
    out = _render(tmp_path, [
        _row(_Score(49, "F", 92)),
        _row(_Score(49, "F", 80)),   # pinned: score held, pass-rate fell
        _row(_Score(40, "F", 70)),   # compounded: both fell
    ])
    assert _PINNED in out and _BOTH in out, out


# ------------------------------------------------------------- --ascii means ASCII

# Inputs for the paragraphs that are NOT produced by a store shape, and the string that
# proves each paragraph reached the screen.
_EXTRA = {
    "retention": {"retention": "3 older runs were pruned to keep the store bounded."},
    "chain-provenance": {"chain": (False, "link 3 of 42")},
}
_MARKER = {
    "pinned-fall": _PINNED,
    "compounded-fall": _BOTH,
    "uncorroborated": "not compared against the underlying",
    "scope-moved": "not compared against the underlying",
    "ungraded-hole": "have no grade",
    "retention": "Not every recorded run is above",
    "chain-provenance": "Chain does not verify",
}

@pytest.mark.parametrize("rows,paragraph", [
    ([_row(_Score(49, "F", 92)), _row(_Score(49, "F", 74))], "pinned-fall"),
    ([_row(_Score(90, "A", 95)), _row(_Score(60, "D", 74))], "compounded-fall"),
    ([_row(_Score(49, "F", 92)), _row(_Score(49, "F", 74), home="~/work/.openclaw")],
     "uncorroborated"),
    ([_row(_Score(49, "F", 92)),
      _row(_Score(49, "F", 74), findings=_OTHER_FINDINGS)], "scope-moved"),
    ([_row(_Score(49, "F", 92)), _row(_Score(49, "F", 74))], "retention"),
    ([_row(_Score(49, "F", 92)), _row(_Score(49, "F", 74))], "chain-provenance"),
    ([_row(_Score(49, "F", 92)), dict(score=_Score(None, None, None, graded=False),
                                      source="audit", home=_HOME,
                                      findings=_FINDINGS, version=_VER),
      _row(_Score(49, "F", 74))], "ungraded-hole"),
])
def test_no_disclosure_paragraph_leaks_a_non_ascii_character(tmp_path, rows, paragraph):
    """Parametrised per paragraph, not once over a lucky store.

    Measured paragraph by paragraph with the fold removed, TWO of the seven carry a
    foldable character today: the pinned-score one (B-691's, the regression) and the
    chain-provenance one (B-582's, which predates it). The other five are ASCII already
    and are regression coverage for the prose, not live detectors.

    The CASES are not isolated from each other and are not meant to be — most of these
    stores render the pinned paragraph alongside their own, so five of the seven fail
    when the fold is deleted. That is why the attribution above was measured on the
    paragraphs directly rather than read off which cases went red: a case failing says
    the screen leaked, not that this paragraph did.

    Each case also asserts that its own paragraph actually rendered. Without that, a
    fixture that stopped triggering its paragraph would keep passing the ASCII assertion
    forever — the one failure mode a leak test cannot afford. Proven by removing the
    `retention` input: that case alone goes red.
    """
    out = _render(tmp_path, rows, ascii_only=True, **_EXTRA.get(paragraph, {}))
    leaked = sorted({ch for ch in out if ord(ch) > 127})
    assert not leaked, (paragraph, leaked)
    assert _MARKER[paragraph] in out, (
        "vacuous: the paragraph under test did not render", paragraph, out)


def test_the_fixture_really_exercises_the_folding(tmp_path):
    """Non-vacuity. If the unicode render carried no character needing folding, every
    assertion above would hold with the fold deleted."""
    out = _render(tmp_path, [_row(_Score(49, "F", 92)), _row(_Score(49, "F", 74))],
                  ascii_only=False)
    assert any(ord(ch) > 127 for ch in out), out


def test_the_unicode_render_is_unchanged_by_the_fix(tmp_path):
    """The fold applies only under `--ascii`. A change that folded unconditionally would
    strip the em dashes and the mascot from everybody's default output."""
    out = _render(tmp_path, [_row(_Score(49, "F", 92)), _row(_Score(49, "F", 74))],
                  ascii_only=False)
    assert "—" in out, out
    assert "·" in out or "▲" in out or "▼" in out, out


def test_ascii_and_unicode_differ_only_by_folding(tmp_path):
    """The two renders must be the same text, not two texts. A branch that composed
    different sentences per mode would drift, which is what a second ASCII rule per
    paragraph would have created."""
    from clawseccheck.textnorm import asciify
    rows = [_row(_Score(49, "F", 92)), _row(_Score(49, "F", 74))]
    ascii_out = _render(tmp_path / "a", rows, ascii_only=True)
    (tmp_path / "b").mkdir(parents=True, exist_ok=True)
    unicode_out = _render(tmp_path / "b", rows, ascii_only=False)
    # The arrow glyphs are chosen per mode by design (`^ v =` vs `▲ ▼ ·`), so compare the
    # paragraphs, which are mode-independent prose.
    a_paras = [ln for ln in ascii_out.split("\n") if _PINNED in ln]
    u_paras = [ln for ln in unicode_out.split("\n") if _PINNED in ln]
    assert a_paras and u_paras
    assert a_paras == [asciify(ln) for ln in u_paras]
