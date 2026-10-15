"""C-615 - the newer-than-grounded OpenClaw notice reaches EVERY report surface.

C-571 (4.3.0) added "this build's checks were last grounded against OpenClaw up to X; you
are running Y" but wired it into `render_report` only. The card (`render_dashboard`), the
HTML report and the PDF - the artifacts the skill's mandated flow actually shows the user -
printed a confident grade with no caveat, so a real gap on a newer OpenClaw could read as a
clean PASS without the reader ever seeing the warning.

The sentence now lives in ONE place (`report._grounding_gap_sentence`); each surface only
chooses where to print it. This file pins, for each surface: the notice fires on a build
strictly newer than `GROUNDED_MAX_VERSION`, stays silent on everything else (including
"we do not know" - never a fabricated gap), never moves the verdict, and carries the same
words everywhere. It also pins the `--ascii` spacing defect found in the same change
("[!]This build's..." - no space after the marker).

Offline and read-only: the installed build is injected through
`Context.installed_dist_version` (no dist is read), nothing is written.
"""
from __future__ import annotations

import html as _html
import re
from pathlib import Path

import pytest
from _pdftext import shown_strings

import clawseccheck.checks as checks
from clawseccheck import report as report_mod
from clawseccheck.collector import collect
from clawseccheck.layers import (
    LAYER_LIVE_BEHAVIOUR,
    LAYER_ORDER,
    LAYER_SELF_REPORT,
    STATUS_RAN,
    STATUS_UNAVAILABLE,
    LayerLedger,
    LayerState,
)
from clawseccheck.openclawdist import GROUNDED_MAX_VERSION
from clawseccheck.pdf import _ascii_safe, render_pdf
from clawseccheck.report import (
    _COMPACT_CHAR_BUDGET,
    _grounding_gap_line,
    _grounding_gap_sentence,
    render_dashboard,
    render_html,
    render_report,
)
from clawseccheck.scoring import compute

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_GROUNDED_STR = ".".join(str(p) for p in GROUNDED_MAX_VERSION)
_Y, _M, _P = GROUNDED_MAX_VERSION
# Derived from the ceiling so a re-grounding bump needs no edit here.
_NEWER = f"{_Y}.{_M}.{_P + 1}"
_OLDER = f"{_Y}.{_M}.{_P - 1}"

_MARKER = "grounded against OpenClaw up to"


def _ungraded_ledger():
    states = {ln: LayerState(status=STATUS_RAN) for ln in LAYER_ORDER}
    states[LAYER_SELF_REPORT] = LayerState(status=STATUS_UNAVAILABLE)
    states[LAYER_LIVE_BEHAVIOUR] = LayerState(status=STATUS_UNAVAILABLE)
    return LayerLedger(states=states)


def _run(installed, *, home="home_safe", ungraded=False):
    ctx = collect(FIXTURES / home)
    ctx.installed_dist_version = installed
    findings = checks.run_all(ctx)
    if ungraded:
        score = compute(findings, ctx=ctx, ledger=_ungraded_ledger())
    else:
        score = compute(findings, ctx=ctx)
    return ctx, findings, score


def _pdf_text(findings, score, ctx):
    # The sentence wraps over several drawn strings; collapse before searching.
    return " ".join(shown_strings(render_pdf(findings, score, ctx=ctx)).split())


# name -> renderer(findings, score, ctx, ascii_only) -> text. `ascii_only` is honoured by
# the text/card renderers; HTML and PDF have their own fixed alphabets.
_RENDERERS = {
    "text": lambda f, s, c: render_report(f, s, color=False, ctx=c),
    "card": lambda f, s, c: render_dashboard(f, s, ctx=c),
    "card_pdf_deferred": lambda f, s, c: render_dashboard(f, s, ctx=c, full=True,
                                                          pdf_path="x.pdf"),
    "card_full": lambda f, s, c: render_dashboard(f, s, ctx=c, full=True),
    "card_full_compact": lambda f, s, c: render_dashboard(f, s, ctx=c, full=True,
                                                          compact=True),
    "html": lambda f, s, c: render_html(f, s, ctx=c),
    "pdf": _pdf_text,
}


def _expected(name, ctx):
    """The sentence as this surface is entitled to print it."""
    sentence = _grounding_gap_sentence(ctx)
    assert sentence is not None
    if name == "html":
        return _html.escape(sentence)
    if name == "pdf":
        return _ascii_safe(sentence)
    return sentence


# -- BAD: the notice is present ---------------------------------------------------------

@pytest.mark.parametrize("ungraded", [False, True], ids=["graded", "ungraded"])
@pytest.mark.parametrize("name", sorted(_RENDERERS))
def test_notice_present_when_installed_is_newer(name, ungraded):
    ctx, findings, score = _run(_NEWER, ungraded=ungraded)
    assert score.graded is (not ungraded), "fixture must exercise the intended branch"
    out = _RENDERERS[name](findings, score, ctx)
    assert _expected(name, ctx) in out, f"{name} dropped the newer-than-grounded notice"
    assert f"{_MARKER} {_GROUNDED_STR}" in out
    assert f"you are running {_NEWER}" in out


# -- CLEAN / UNKNOWN: the notice is silent ----------------------------------------------

_SILENT = [
    _GROUNDED_STR,                 # exactly the ceiling
    _OLDER,                        # older
    f"{_GROUNDED_STR}-1",          # a correction release of the grounded build
    None,                          # nothing installed / --no-dist
    "2026.9",                      # too short to be a calendar release: unknown, not a gap
    "0.0.0",
    f"{_NEWER}-rc1",               # pre-release token: unorderable, never a fabricated gap
    123,                           # not even a string
]


@pytest.mark.parametrize("installed", _SILENT, ids=repr)
@pytest.mark.parametrize("name", sorted(_RENDERERS))
def test_notice_silent_unless_strictly_newer(name, installed):
    ctx, findings, score = _run(installed)
    out = _RENDERERS[name](findings, score, ctx)
    assert "grounded against" not in out
    assert "may be mis-grounded" not in out


@pytest.mark.parametrize("name", sorted(_RENDERERS))
def test_notice_silent_without_a_context(name):
    """Every pre-existing caller passes no ctx: the output must not grow a notice."""
    ctx, findings, score = _run(_NEWER)
    out = _RENDERERS[name](findings, score, None)
    assert "grounded against" not in out


# -- score invariance ---------------------------------------------------------------------

def test_the_notice_never_moves_the_verdict():
    _, _, newer = _run(_NEWER)
    _, _, ceiling = _run(_GROUNDED_STR)
    for attr in ("score", "grade", "capped", "graded", "raw_score", "degraded_count"):
        assert getattr(newer, attr) == getattr(ceiling, attr), attr


@pytest.mark.parametrize("name", ["card", "card_full", "card_full_compact", "html"])
def test_removing_the_notice_leaves_the_rest_of_the_surface_untouched(name):
    """Same findings, same score, only the installed build differs: the notice is the sole
    difference. (Findings are computed once - some checks quote the installed version in
    their own detail, which is a different, legitimate difference.)"""
    ctx, findings, score = _run(_NEWER)
    newer = _RENDERERS[name](findings, score, ctx)
    ctx.installed_dist_version = _GROUNDED_STR
    current = _RENDERERS[name](findings, score, ctx)
    if name == "html":
        stripped = re.sub(r'<p class="meta">[^<]*' + _MARKER + r'[^<]*</p>', "", newer)
    else:
        stripped = "\n".join(ln for ln in newer.splitlines() if _MARKER not in ln)
    assert stripped != newer, "the notice must have been there to remove"
    assert stripped.strip() == current.strip()


# -- one wording everywhere ---------------------------------------------------------------

def test_the_line_is_the_sentence_behind_a_marker():
    ctx, _, _ = _run(_NEWER)
    sentence = _grounding_gap_sentence(ctx)
    assert _grounding_gap_line(ctx, True) == "[!] " + sentence
    assert _grounding_gap_line(ctx, False) == "\u26a0\ufe0f " + sentence
    assert _grounding_gap_line(None, True) is None
    assert _grounding_gap_sentence(None) is None


def test_the_sentence_claims_no_position():
    """It once said 'the score below is unchanged'; the card and PDF print it above the
    findings and beside the grade, and the HTML after the badge, so 'below' was false."""
    ctx, _, _ = _run(_NEWER)
    sentence = _grounding_gap_sentence(ctx)
    assert "below" not in sentence
    assert "the score is unchanged" in sentence
    assert "checks may be mis-grounded" not in sentence  # still names no set of checks


def test_no_renderer_writes_its_own_copy_of_the_sentence():
    import inspect

    from clawseccheck import pdf as pdf_mod
    src = inspect.getsource(report_mod) + inspect.getsource(pdf_mod)
    assert src.count("were last grounded against") == 1


# -- ASCII spacing -----------------------------------------------------------------------

def test_ascii_marker_is_followed_by_a_space():
    ctx, findings, score = _run(_NEWER)
    text = render_report(findings, score, ascii_only=True, color=False, ctx=ctx)
    card = render_dashboard(findings, score, ascii_only=True, ctx=ctx)
    for out in (text, card):
        assert "[!] This build's checks" in out
        assert "[!]This build" not in out


def _boom(ctx):
    raise RuntimeError("engineered crash for the C-615 ascii-spacing pin")


def test_ascii_degraded_marker_is_followed_by_a_space(monkeypatch):
    """The same missing space sat on the degraded-checks line ('[!]3 checks ...')."""
    monkeypatch.setattr(checks, "CHECKS", list(checks.CHECKS) + [_boom])
    ctx, findings, score = _run(_NEWER)
    assert score.degraded_count >= 1
    text = render_report(findings, score, ascii_only=True, color=False, ctx=ctx)
    card = render_dashboard(findings, score, ascii_only=True, ctx=ctx)
    for out in (text, card):
        assert "could not reach a reliable verdict" in out
        assert re.search(r"\[!\]\d", out) is None
        assert re.search(r"\[!\] \d+ checks? could not reach", out)


def test_notice_precedes_the_degraded_line_in_the_text_report(monkeypatch):
    monkeypatch.setattr(checks, "CHECKS", list(checks.CHECKS) + [_boom])
    ctx, findings, score = _run(_NEWER)
    text = render_report(findings, score, color=False, ctx=ctx)
    assert text.index(_MARKER) < text.index("could not reach a reliable verdict")


# -- card budget --------------------------------------------------------------------------

@pytest.mark.parametrize("kwargs", [{}, {"full": True, "compact": True}],
                         ids=["plain", "full_compact"])
def test_the_card_still_fits_its_budget_with_the_notice(kwargs):
    ctx, findings, score = _run(_NEWER, home="home_vuln")
    out = render_dashboard(findings, score, ctx=ctx, **kwargs)
    assert len(out) <= _COMPACT_CHAR_BUDGET
    assert _MARKER in out, "the notice sits at the top of the card and is never the part cut"
