"""C-428 — the prose around a withheld grade has to be coherent too.

C-423 removed the letter and the ``/100`` from every renderer, and its tests pin
that absence. What tests of that shape structurally cannot see is whether the
paragraphs *around* the number still make sense: a report can be free of any
letter and still explain, three lines down, what "a high grade" means. Reading a
real ungraded run is what surfaced these; each one below is that read, pinned.

Three defects, all in the same family — output that presupposes a grade the run
does not have:

1. ``render_report``'s static-vs-runtime paragraph said "a high grade means
   'not statically lethal-capable'".
2. The same report's PASS-semantics paragraph opened "A clean/high-grade result".
3. ``render_card``'s box art broke open: the width was hardcoded to 39 for
   ``"A ( 95/100)"`` and ``:<39`` pads but never truncates, so the longer
   ungraded line pushed straight through the right border.

Plus ``guide.suggest_actions``, which promised "Share your grade" and "Only the
grade + score is shared" on a run whose badge renders "no grade yet".

Stdlib-only, offline, writes nothing.
"""
from __future__ import annotations

from clawseccheck.catalog import CRITICAL, FAIL, LOW, PASS, Finding
from clawseccheck.guide import suggest_actions
from clawseccheck.layers import (
    LAYER_LIVE_BEHAVIOUR,
    LAYER_ORDER,
    LAYER_SELF_REPORT,
    STATUS_RAN,
    STATUS_UNAVAILABLE,
    LayerLedger,
    LayerState,
)
from clawseccheck.report import render_card, render_report
from clawseccheck.scoring import compute


def _f(fid: str, title: str, severity: str, status: str) -> Finding:
    return Finding(fid, title, severity, status, "detail", "fix", "framework")


FINDINGS = [_f("B1", "Lethal trifecta reachable", CRITICAL, FAIL),
            _f("B2", "some clean check", LOW, PASS)]


def _graded():
    ledger = LayerLedger(states={ln: LayerState(status=STATUS_RAN) for ln in LAYER_ORDER})
    return compute(FINDINGS, ledger=ledger)


def _ungraded():
    states = {ln: LayerState(status=STATUS_RAN) for ln in LAYER_ORDER}
    states[LAYER_SELF_REPORT] = LayerState(status=STATUS_UNAVAILABLE)
    states[LAYER_LIVE_BEHAVIOUR] = LayerState(status=STATUS_UNAVAILABLE)
    return compute(FINDINGS, ledger=LayerLedger(states=states))


# ── 1 + 2: the report's own explanatory prose ────────────────────────────────

def test_ungraded_report_never_explains_what_a_grade_would_mean():
    out = render_report(FINDINGS, _ungraded(), ascii_only=True, color=False)
    assert "high grade" not in out
    assert "high-grade" not in out


def test_ungraded_report_still_carries_both_caveats_reworded():
    """The caveats are load-bearing — reword them, never drop them."""
    out = render_report(FINDINGS, _ungraded(), ascii_only=True, color=False)
    assert "a clean static result means" in out
    assert 'A clean result means "no known attack pattern matched"' in out


def test_graded_report_keeps_the_original_wording():
    out = render_report(FINDINGS, _graded(), ascii_only=True, color=False)
    assert 'a high grade means "not statically lethal-capable"' in out
    assert 'A clean/high-grade result means' in out


# ── 3: the card's box art closes on both branches ────────────────────────────

def _box_rows(card: str) -> list[str]:
    return [ln for ln in card.splitlines() if ln.startswith(("|", "│"))]


def test_ungraded_card_box_art_is_not_broken_open():
    card = render_card(_ungraded(), FINDINGS, ascii_only=True)
    rows = _box_rows(card)
    assert rows, "expected a boxed card"
    widths = {len(ln) for ln in rows}
    assert len(widths) == 1, f"card rows have ragged widths: {sorted(widths)}"
    assert all(ln.endswith(("|", "│")) for ln in rows), card


def test_ungraded_card_border_matches_its_rows():
    card = render_card(_ungraded(), FINDINGS, ascii_only=True)
    lines = [ln for ln in card.splitlines() if ln.strip()]
    top, bot = lines[0], lines[-1]
    assert len(top) == len(bot)
    assert {len(ln) for ln in _box_rows(card)} == {len(top)}


def test_graded_card_keeps_the_established_39_wide_box():
    card = render_card(_graded(), FINDINGS, ascii_only=True)
    assert {len(ln) for ln in _box_rows(card)} == {41}   # 39 + the two borders


def test_ungraded_card_counts_the_layers_that_ran_not_the_ones_that_did_not():
    """'(3/5 layers)' read as '3 of 5 ran' while counting the opposite."""
    card = render_card(_ungraded(), FINDINGS, ascii_only=True)
    assert "3/5 layers ran" in card    # 5 total, 2 unavailable
    assert "/100" not in card


# ── guide.py: next-steps must not promise a grade this run has not got ───────

def test_ungraded_next_steps_do_not_promise_a_grade():
    actions = {a.id: a for a in suggest_actions(FINDINGS, _ungraded())}
    share = actions["share_grade"]
    assert "Share your result" in share.title
    assert 'badge reads "no grade yet"' in share.why
    assert "Only graded runs plot on the trend" in actions["track_trend"].why


def test_graded_next_steps_are_unchanged():
    actions = {a.id: a for a in suggest_actions(FINDINGS, _graded())}
    assert actions["share_grade"].title == "Share your grade (safe — findings stay private)"
    assert actions["track_trend"].title == "Track your security score over time"


def test_the_do_not_redraw_instruction_survives_both_branches():
    """The host agent must attach the SVG, never regenerate it — on either branch."""
    for score in (_graded(), _ungraded()):
        why = {a.id: a for a in suggest_actions(FINDINGS, score)}["share_grade"].why
        assert "do not redraw" in why
        assert "attach grade.svg itself" in why
