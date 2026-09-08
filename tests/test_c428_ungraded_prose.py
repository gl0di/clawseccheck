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


def test_ungraded_share_advice_does_not_then_promise_to_share_a_grade():
    """The sentence AFTER the reworded one was carried over from the graded branch.

    Found by reading a real `--next` run: "This run has no grade, so the badge reads
    'no grade yet'. Only the grade + score is ever shared, never your findings." — the
    second sentence promises to share the thing the first says does not exist.

    `test_ungraded_next_steps_do_not_promise_a_grade` above could not catch it: it
    asserts the new wording is PRESENT, which says nothing about the sentence next to it.
    That gap is the whole shape of this defect family (B-518, B-520).
    """
    why = {a.id: a for a in suggest_actions(FINDINGS, _ungraded())}["share_grade"].why
    assert 'badge reads "no grade yet"' in why, "the fact itself must stay"
    assert "grade + score" not in why, (
        "the ungraded branch still claims a grade and score get shared, two words after "
        f"saying there is no grade: {why!r}")
    # The privacy assurance is load-bearing — reword it, never drop it.
    assert "never" in why and "findings" in why, (
        "the 'your findings are not in the badge' promise must survive the rewording")


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


# ── the graded branch's COMMAND, which C-428 did not reach ───────────────────
#
# C-428 corrected the ungraded branch's prose and stopped there. The graded
# branch kept promising "Share your grade" over a bare `--badge grade.svg`,
# which per B-586 never honours `--full` on its own: it opens a fresh, ungraded
# audit. Measured end to end on fixtures/home_safe — a run that printed
# "Grade A · 96/100" told the user to run that command, and the SVG it wrote
# carried aria-label="OpenClaw Security: no grade yet".
#
# The command stays runnable (a suggestion the agent is told to run must not be
# a placeholder), so the promise around it is what has to be true.

def _share(score):
    return {a.id: a for a in suggest_actions(FINDINGS, score)}["share_grade"]


def test_graded_share_step_admits_the_bare_command_carries_no_grade():
    why = _share(_graded()).why
    assert "would not carry this grade" in why
    assert "add `--badge grade.svg` to the same command that produced it" in why


def test_graded_share_step_does_not_quote_the_ungraded_badge_text():
    """tests/test_b604_dashboard_next_actions.py discriminates graded from ungraded
    by this phrase. Saying the bare command cannot carry the grade must not be done
    by quoting the ungraded badge, which would make the two blocks read alike."""
    assert "no grade" not in _share(_graded()).why.lower()


def test_graded_share_step_keeps_the_privacy_promise():
    """The load-bearing sentence C-428 protected must survive this correction."""
    why = _share(_graded()).why
    assert "never your findings" in why


def test_graded_share_step_command_stays_runnable_as_written():
    """No placeholder may reach a line the skill tells an agent to run."""
    cmd = _share(_graded()).command
    assert "--badge grade.svg" in cmd
    for placeholder in ("<", ">", "YOUR", "..."):
        assert placeholder not in cmd


def test_ungraded_share_step_is_untouched_by_the_graded_correction():
    why = _share(_ungraded()).why
    assert "This run has no grade" in why
    assert "add `--badge grade.svg` to the same command" not in why
