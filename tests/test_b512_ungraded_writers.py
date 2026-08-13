"""B-512 — no writer may emit a number the run withheld, in any encoding.

`ScoreResult.score` and `.grade` deliberately keep their computed values when
`graded` is False; only the *renderers* withhold them. That design puts the burden
on every consumer to opt in, and consumers were taught one at a time as each was
noticed. Seven were found that way — `report`, `pdf`, `incident`, `percentile`,
`projection`, history (B-509), the `--monitor` snapshot (B-511) — and finding the
eighth the same way is not a strategy.

So this module is deliberately NOT another per-renderer assertion. `test_c423_ungraded_render`
already covers the display dimension surface by surface. This one sweeps **every
artifact-producing surface at once**, treats each artifact as an opaque byte string,
and asserts the withheld values do not appear **anywhere in it** — displayed or not.

That distinction is the whole point, and it is not hypothetical. The HTML report
passed C-423's "no letter, no /100" check while baking the withheld score into its
own stylesheet as `width: 97%`: the bar element was correctly not rendered, the CSS
rule that sizes it was emitted anyway, and the exact number was one devtools click
away. A test that reads only what is displayed cannot see that.

The two defects this module was written for:

* `cli.py` logged `score=97 grade=A` to `--log` on a run whose report said
  "No grade yet" — the file an operator reads once the terminal has scrolled, and
  the one they paste into an issue.
* `render_html` leaked the same number through the stylesheet, as above.

**B-531 got past this module anyway, in two independent ways, and both are now closed
here** — worth recording, because a sweep that is believed comprehensive and is not is
more dangerous than no sweep:

* **It could not read the PDF.** `render_pdf` deflates its content stream once the page
  is large enough, so searching the raw bytes sailed past every string the PDF actually
  shows a reader. The premise "treat the artifact as an opaque byte string" was simply
  false for that surface. `_searchable` now inflates first.
* **It never exercised the cap path.** The fixture carries a CRITICAL FAIL and scores 9,
  while the live-test cap is a ceiling of 49 — so no cap was ever applied and the cap
  line was never emitted, in either direction. Comprehensive over SURFACES, blind on a
  PATH. `CLEAN_FINDINGS` and the capped fixtures below close that.

And `raw_score` is a third withheld number that none of the score/grade tokens covered.

Stdlib-only, offline, writes nothing outside pytest's `tmp_path`.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawseccheck.catalog import CRITICAL, FAIL, LOW, PASS, Finding
from clawseccheck.collector import Context
from clawseccheck.incident import render_incident
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
    render_card,
    render_dashboard,
    render_html,
    render_json,
    render_monitor,
    render_report,
    render_svg,
)
from clawseccheck.scoring import compute


def _f(fid: str, title: str, severity: str, status: str) -> Finding:
    return Finding(fid, title, severity, status, "detail", "fix", "framework")


FINDINGS = [_f("B1", "Lethal trifecta reachable", CRITICAL, FAIL),
            _f("B2", "some clean check", LOW, PASS)]


def _ungraded():
    """Layers 4 and 5 unavailable — the shape every ordinary run has today."""
    states = {ln: LayerState(status=STATUS_RAN) for ln in LAYER_ORDER}
    states[LAYER_SELF_REPORT] = LayerState(status=STATUS_UNAVAILABLE)
    states[LAYER_LIVE_BEHAVIOUR] = LayerState(status=STATUS_UNAVAILABLE)
    return compute(FINDINGS, ledger=LayerLedger(states=states))


def _forbidden(score) -> list[str]:
    """Every shape the withheld values have actually leaked in, or plausibly could.

    Derived from the real `ScoreResult` rather than hardcoded, so the guard keeps
    working when the fixture's arithmetic changes.
    """
    n, g, raw = score.score, score.grade, score.raw_score
    return [
        f"{n}/100",          # the report / dashboard / card / PDF shape
        f"{n}%",             # the stylesheet shape that actually leaked (B-512)
        f"score={n}",        # the --log shape that actually leaked (B-512)
        f'"score": {n}',     # JSON
        f'"score":{n}',
        f"Grade {g}",
        f"Grade: {g}",
        f"grade={g}",
        f'"grade": "{g}"',
        f'"grade":"{g}"',
        # B-531: raw_score is a THIRD withheld number, and no token above covered it.
        # The PDF printed "Capped from 100" on a run that had just said it would not
        # give a number — the pre-cap score, which is strictly larger than the one the
        # other tokens guard. A sweep keyed only on `score`/`grade` cannot see it.
        f"Capped from {raw}",
        f"capped from {raw}",
        f'"raw_score": {raw}',
        f'"raw_score":{raw}',
    ]


def _searchable(artifact) -> str:
    """The artifact as text, with any compressed stream inflated alongside it.

    B-531: `render_pdf` emits its text inside a FlateDecode content stream, so this
    module's whole premise — "treat the artifact as an opaque byte string and assert
    the withheld value does not appear ANYWHERE in it" — was not true of the PDF. A raw
    byte search sailed past every string the PDF actually shows the reader, which is why
    the sweep did not catch the ungated cap line. Inflating first is what makes the PDF
    surface as searchable as the text ones already were.
    """
    text = artifact.decode("latin-1") if isinstance(artifact, bytes) else artifact
    if not isinstance(artifact, bytes) or b"FlateDecode" not in artifact:
        return text
    import re
    import zlib

    for match in re.finditer(rb"stream\r?\n(.*?)endstream", artifact, re.S):
        try:
            text += zlib.decompress(match.group(1)).decode("latin-1")
        except Exception:  # not every stream is deflate, and a bad one proves nothing
            continue
    return text


def _assert_clean(artifact, score, surface: str) -> None:
    text = _searchable(artifact)
    hits = [tok for tok in _forbidden(score) if tok in text]
    assert not hits, (
        f"{surface} leaks the withheld score/grade as {hits!r}. The value is present "
        f"in the artifact even if it is not displayed — see this module's docstring."
    )


# ── the sweep ────────────────────────────────────────────────────────────────

def _surfaces(score, findings=None):
    """(name, artifact) for every writer that turns a ScoreResult into an artifact."""
    FINDINGS_ = FINDINGS if findings is None else findings
    return [
        ("render_report", render_report(FINDINGS_, score, ascii_only=True, color=False)),
        ("render_dashboard", render_dashboard(FINDINGS_, score, ascii_only=True)),
        ("render_card", render_card(score, FINDINGS_, ascii_only=True)),
        ("render_svg", render_svg(score, FINDINGS_)),
        ("render_html", render_html(FINDINGS_, score)),
        ("render_json", render_json(FINDINGS_, score)),
        ("render_monitor", render_monitor([], score, ascii_only=True)),
        ("render_pdf", render_pdf(FINDINGS_, score)),
        # The incident pack is a writer too, and it is the artifact most likely to be
        # handed to someone else during a real incident — so it is in the sweep, not
        # trusted because it happens to gate correctly today.
        ("render_incident", render_incident(Context(home=Path("/nonexistent")), FINDINGS_, score)),
    ]


@pytest.mark.parametrize("surface", [s[0] for s in _surfaces(_ungraded())])
def test_no_writer_leaks_the_withheld_value(surface):
    score = _ungraded()
    assert score.graded is False, "fixture must be ungraded for this to mean anything"
    artifact = dict(_surfaces(score))[surface]
    _assert_clean(artifact, score, surface)


def test_the_guard_can_actually_fail():
    """A guard that cannot fail is decoration — prove it catches the real shape.

    Feeds the sweep an artifact carrying the leak B-512 was filed for.
    """
    score = _ungraded()
    leaky = f".scorebar > i {{ width: {score.score}%; }}"
    with pytest.raises(AssertionError, match="leaks the withheld"):
        _assert_clean(leaky, score, "synthetic")


# ── the two specific regressions ─────────────────────────────────────────────

def test_html_stylesheet_does_not_size_a_bar_it_refuses_to_draw():
    """The exact B-512 leak: the bar is not rendered, the CSS that sizes it was."""
    score = _ungraded()
    html = render_html(FINDINGS, score)
    assert f"width: {score.score}%" not in html
    assert "width: 0%" in html          # rule still emitted, sized to nothing
    assert "No grade yet" in html or "no grade yet" in html.lower()


def test_log_file_states_the_missing_layers_not_a_grade(tmp_path, monkeypatch, capsys):
    """`--log PATH` wrote `score=97 grade=A` under a report saying "No grade yet"."""
    from clawseccheck.cli import main

    log = tmp_path / "audit.log"
    rc = main(["--home", "fixtures/home_safe", "--no-history", "--no-color",
               "--log", str(log)])
    assert rc in (0, 1)
    written = log.read_text(encoding="utf-8")

    out = capsys.readouterr().out
    assert "No grade yet" in out, "fixture stopped being an ungraded run"

    assert "grade=A" not in written
    assert "grade=" not in written.replace("no grade:", "")
    assert "score=" not in written
    assert "no grade:" in written and "layers did not run" in written


def test_log_file_still_carries_the_grade_on_a_graded_run():
    """Withholding must not become unconditional — the graded wording is unchanged."""
    from clawseccheck import cli as cli_mod

    src = cli_mod.__file__
    with open(src, encoding="utf-8") as fh:
        text = fh.read()
    assert 'logger.info("score=%s grade=%s", score.score, score.grade)' in text, (
        "the graded branch of the --log line was removed rather than gated"
    )


def test_json_keeps_the_keys_and_nulls_them():
    """Absence must be explicit — a consumer reading payload['score'] gets None."""
    payload = json.loads(render_json(FINDINGS, _ungraded()))
    for key in ("score", "grade", "raw_score"):
        assert key in payload, f"{key} must stay present"
        assert payload[key] is None, f"{key} must be null on an ungraded run"


# ── the graded direction, so this cannot be satisfied by withholding always ──

def _graded():
    return compute(FINDINGS,
                   ledger=LayerLedger(states={ln: LayerState(status=STATUS_RAN)
                                              for ln in LAYER_ORDER}))


@pytest.mark.parametrize("surface", ["render_report", "render_html", "render_json"])
def test_graded_run_still_states_its_number(surface):
    score = _graded()
    assert score.graded is True
    artifact = dict(_surfaces(score))[surface]
    text = artifact.decode("latin-1") if isinstance(artifact, bytes) else artifact
    assert str(score.score) in text, f"{surface} withheld a number it had earned"


# ── B-531: the cap line, on the fixture shape that actually exercises it ─────
#
# The sweep above could never have caught B-531, and the reason is worth stating: its
# fixture carries no cap at all (raw_score == score, _cap_cascade returns None), so the
# cap line was never emitted for it in either direction. Comprehensive over SURFACES,
# blind on one PATH. These fixtures close that.

# The cap is a CEILING (49), so a run that already scores below it is never capped.
# FINDINGS carries a CRITICAL FAIL and lands at 9 — which is why these fixtures need
# their own clean finding set. Getting this wrong the first time is what the
# `_really_is_capped` precondition below exists to catch.
CLEAN_FINDINGS = [_f("B2", "some clean check", LOW, PASS)]


def _capped_ungraded():
    """A live test ran and found a vulnerability; the agent self-report never arrived.

    Coherent, not contrived: layer 5 submits VULNERABLE (so the score is capped) while
    layer 4 is unavailable (so no letter is earned). raw_score 100, score 49."""
    states = {ln: LayerState(status=STATUS_RAN) for ln in LAYER_ORDER}
    states[LAYER_SELF_REPORT] = LayerState(status=STATUS_UNAVAILABLE)
    return compute(CLEAN_FINDINGS, ledger=LayerLedger(states=states),
                   live_test_vulnerable=True, live_test_reason="probe")


def _capped_graded():
    return compute(CLEAN_FINDINGS, live_test_vulnerable=True, live_test_reason="probe")


def test_the_capped_fixture_really_is_capped_and_ungraded():
    """Precondition. Without it the tests below pass by describing nothing."""
    score = _capped_ungraded()
    assert score.graded is False
    assert score.raw_score > score.score, "fixture must carry a real cap"


@pytest.mark.parametrize("surface", [s[0] for s in _surfaces(_capped_ungraded(),
                                                             CLEAN_FINDINGS)])
def test_no_writer_leaks_the_pre_cap_number_either(surface):
    score = _capped_ungraded()
    _assert_clean(dict(_surfaces(score, CLEAN_FINDINGS))[surface], score, surface)


def test_the_pdf_still_discloses_a_cap_it_did_earn():
    """The fix must be a gate, not a deletion: on a graded run the cap line is a real
    disclosure, and withholding it would hide why the number is lower than it looks."""
    score = _capped_graded()
    assert score.graded is True and score.raw_score > score.score
    assert f"Capped from {score.raw_score}" in _searchable(
        render_pdf(CLEAN_FINDINGS, score))


def test_the_inflating_search_can_see_what_a_raw_byte_search_cannot():
    """A guard that cannot fail is decoration. The PDF writer deflates its content
    stream once the page is large enough, and on exactly those artifacts a raw byte
    search finds nothing — the asymmetry that made this module blind to the PDF."""
    pdf = render_pdf(CLEAN_FINDINGS, _capped_graded())
    assert "Capped from" in _searchable(pdf), "the cap line is missing entirely"
    if b"FlateDecode" in pdf:
        assert b"Capped from" not in pdf, (
            "compressed stream, yet the text is findable raw — if that becomes true "
            "generally, _searchable's inflation step is no longer load-bearing"
        )
