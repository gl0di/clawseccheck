"""B-530 — `--dashboard --full --pdf out.pdf --trend` asked for a PDF and got no file.

**The defect.** C-374 defers the `--pdf` write out of the `--pdf` site and into the
dashboard branch, so that under `--full` the document can carry the P7-P10 pipeline
blocks (skills/plugins sweep, RISK chains, behavioural replay, second opinion). But a
rider — `--trend` / `--percentile` / `--next` — is elected over the dashboard by
`_resolve_mode`, and every rider branch returns roughly 1,200 lines ABOVE the dashboard
branch. So the deferred write was never reached: exit 0, a sparkline on stdout, and no
file anywhere. Nothing on stderr mentioned the PDF either, because `_pdf_is_produced`
excused it from the ignored-modes note in the non-`--full` case and the `--full` case
only made it back into that note as a bare "`--pdf` ignored" — a request silently
dropped, which is the B-067 class this project exists to notice in other tools.

**Measured before choosing** (probe wrapping `_resolve_runtime_caps`,
`sweep_installed_skills`, `render_pdf`, `run_behavioral`, `run_adjudication`): with any
rider present, the set of pipeline functions called is **empty**. Not one `--full` phase
had run by the time the rider returned. So the deferral was buying nothing at all on
this path — it was pure loss.

**Option implemented: write the reduced (findings-only) PDF at the `--pdf` site, and say
that it is reduced.** `_defer_pdf` gains `and _mode == "dashboard"`: defer only into the
branch that will actually run. The user gets the file they asked for. The reduction is
disclosed twice over, and neither disclosure required touching `pdf.py`:

  * the **document itself** already opens with C-423's layer-ledger page — "No grade yet
    - 3 of 5 layers did not run", naming the installed-sweep layer — and its inventory
    rows read "not scanned - run --full". A reader cannot mistake it for a complete
    audit; `test_the_reduced_pdf_discloses_its_own_scope` pins that, so a future change
    to the ledger page cannot quietly turn this into a document that looks whole.
  * a **stderr note** repeats it for the host agent, which decides what to tell the user
    about a file it may never open.

C-374's own hazard — a dashboard card describing a findings-only PDF as complete —
cannot arise here, because when a rider wins there is no card.

**Why not option 1 (keep deferring; demote `--pdf` to a plain "ignored" note).** It is
honest but it destroys a composition the user plausibly meant, and it answers "you asked
for two things" with "so you get one". The audit was already computed; refusing to spend
the ~5 KB write is a worse deal than the reduced document.

**Why not option 3 (run the `--full` pipeline for the rider, then write the complete
PDF).** Not nearly free, and incoherent. The pipeline result is not in hand at the rider
branch, so this means booting a sweep + behavioural + adjudication run
(`DEFAULT_FULL_BUDGET_S` = 2000 s ceiling on a real home) inside `--trend`, a mode that
today prints one sparkline and returns. It would also make `--full` suddenly *effective*
for a rider, but only when `--pdf` happens to also be present — contradicting the
"`--full` has no effect with `--trend`" note the very same run prints, and the invariant
`_build_layer_ledger` encodes by making `commit_full_phases` deliberately not
`bool(args.full)`.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import re
import zlib
from pathlib import Path

import pytest

from clawseccheck.cli import main

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE_HOME = FIXTURES / "home_safe"

RIDERS = ["--trend", "--percentile", "--next"]


def _run(tmp_path, *argv):
    return main([*argv, "--home", str(SAFE_HOME), "--data-dir", str(tmp_path),
                 "--no-history"])


def _pdf_text(path: Path) -> str:
    """The visible text of a PDF written by pdf.py, as one string.

    pdf.py emits classic PDF 1.4 with zlib-compressed content streams and draws every
    string as a `(...) Tj` literal, so this needs no dependency — which matters, because
    asserting the document DISCLOSES its own reduced scope is the whole point of the
    option chosen, and an assertion on the file's byte size would not be that.
    """
    raw = path.read_bytes()
    chunks = []
    for m in re.finditer(rb"stream\n(.*?)\nendstream", raw, re.S):
        try:
            chunks.append(zlib.decompress(m.group(1)).decode("latin-1"))
        except zlib.error:
            continue
    body = "\n".join(chunks)
    literals = re.findall(r"\(((?:[^()\\]|\\.)*)\)\s*Tj", body)
    return "\n".join(s.replace("\\(", "(").replace("\\)", ")") for s in literals)


# --------------------------------------------------------------- the three riders

@pytest.mark.parametrize("rider", RIDERS)
def test_a_rider_still_gets_its_pdf_written(tmp_path, capsys, rider):
    """The bug, per rider: the file asked for must exist, and the exit code must not be
    a silent 0-with-nothing-produced."""
    dest = tmp_path / "report.pdf"
    rc = _run(tmp_path, "--dashboard", "--full", "--fast", "--pdf", str(dest), rider)
    capsys.readouterr()
    assert rc == 0
    assert dest.exists(), f"{rider} lost the deferred PDF"
    assert dest.stat().st_size > 0, f"{rider} wrote an empty PDF"
    assert dest.read_bytes().startswith(b"%PDF-"), "not a PDF"


@pytest.mark.parametrize("rider", RIDERS)
def test_a_rider_says_the_pdf_was_written_and_that_it_is_reduced(tmp_path, capsys, rider):
    """The user-visible message, not just the file. Both halves are asserted: where the
    file is (so the host agent attaches it) and what it does NOT contain (so nobody reads
    a findings-only document as a completed --full audit)."""
    dest = tmp_path / "report.pdf"
    rc = _run(tmp_path, "--dashboard", "--full", "--fast", "--pdf", str(dest), rider)
    err = capsys.readouterr().err
    assert rc == 0
    assert str(dest) in err, f"the PDF was written and never mentioned: {err!r}"
    assert "attach this PDF file itself" in err, err
    assert "findings only" in err, f"the reduction was not disclosed: {err!r}"
    assert rider in err, f"the note must name what ran instead: {err!r}"
    # It is produced, so it must NOT be listed as an ignored mode — that was the wrong
    # half of the old message (B-067 in reverse: reporting a loss that no longer happens).
    assert "--pdf, --dashboard ignored" not in err, err
    assert "--dashboard ignored" in err, "the card genuinely was not rendered; say so"


@pytest.mark.parametrize("rider", RIDERS)
def test_the_reduced_pdf_discloses_its_own_scope(tmp_path, capsys, rider):
    """The guardrail on the chosen option: a document that LOOKS like a full audit but is
    not is exactly what this project exists to catch elsewhere. The disclosure is C-423's
    layer-ledger page, which pdf.py already renders off the ungraded ScoreResult — this
    test is what stops a later change from writing the reduced PDF without it."""
    dest = tmp_path / "report.pdf"
    _run(tmp_path, "--dashboard", "--full", "--fast", "--pdf", str(dest), rider)
    capsys.readouterr()
    text = _pdf_text(dest)
    assert "ClawSecCheck" in text, "extraction failed; the rest of this test is vacuous"
    assert "No grade yet" in text, text[:400]
    assert "layers did not run" in text, text[:400]
    assert "installed skills and plugins (not reached)" in text, text[:400]


# ------------------------------------------------------------------- the control

def test_no_rider_still_writes_the_deferred_full_pdf(tmp_path, capsys):
    """The regression risk. `--dashboard --full --pdf` with no rider must keep deferring
    into the dashboard branch and writing the COMPLETE document — that path works today
    and this change must not have touched it."""
    dest = tmp_path / "report.pdf"
    rc = _run(tmp_path, "--dashboard", "--full", "--fast", "--pdf", str(dest))
    cap = capsys.readouterr()
    assert rc == 0
    assert dest.exists() and dest.stat().st_size > 0, "the deferred full PDF was lost"
    assert "ClawSecCheck" in cap.out, "the dashboard card was lost"
    assert "attach this PDF file itself" in cap.out + cap.err
    # The complete document is not the reduced one, and must not carry its caveat.
    assert "findings only" not in cap.err, cap.err


def test_the_full_pdf_carries_more_than_the_reduced_one(tmp_path, capsys):
    """Deferral still buys something when the dashboard runs: same config, same flags,
    the only difference being the rider. If these ever came out equal, the deferral would
    be dead code and this whole fix would be arguing about nothing.

    The two documents also give DIFFERENT reasons for the missing sweep layer, and the
    distinction is the honest one: the deferred run skipped it on `--fast`, the rider run
    never got to it at all. Both under the same `--full --fast`, so the wording is
    tracking what happened rather than what was typed."""
    full_dest, reduced_dest = tmp_path / "full.pdf", tmp_path / "reduced.pdf"
    _run(tmp_path, "--dashboard", "--full", "--fast", "--pdf", str(full_dest))
    _run(tmp_path, "--dashboard", "--full", "--fast", "--pdf", str(reduced_dest), "--trend")
    capsys.readouterr()
    assert full_dest.stat().st_size > reduced_dest.stat().st_size
    assert "not reached" in _pdf_text(reduced_dest)
    assert "not reached" not in _pdf_text(full_dest)


# ------------------------------------------------- the same hole without --full

def test_a_rider_without_full_also_stops_writing_in_silence(tmp_path, capsys):
    """`--dashboard --pdf X --trend` (no `--full`) already wrote the file today — and said
    NOTHING about it, because the attach instruction lives in the dashboard branch the
    rider returns before. Measured on the real CLI: stderr was one line, "--dashboard
    ignored (running --trend)". Same guardrail, so it is fixed by the same note; there is
    no `--full` reduction to disclose here, so that half is correctly absent."""
    dest = tmp_path / "report.pdf"
    rc = _run(tmp_path, "--dashboard", "--pdf", str(dest), "--trend")
    err = capsys.readouterr().err
    assert rc == 0
    assert dest.exists()
    assert str(dest) in err and "attach this PDF file itself" in err, err
    assert "findings only" not in err, "there is no --full pipeline to be missing"


def test_an_earlier_mode_still_loses_the_pdf_and_still_says_so(tmp_path, capsys):
    """The boundary this change must NOT move: a mode declared before `--pdf` returns
    before the write site, so no file is produced and `--pdf` stays in the ignored note.
    Widening B-530's fix into an unconditional 'the PDF is always written' would be
    B-067 in a new place."""
    badge, dest = tmp_path / "b.svg", tmp_path / "never.pdf"
    rc = _run(tmp_path, "--badge", str(badge), "--pdf", str(dest), "--dashboard", "--trend")
    err = capsys.readouterr().err
    assert rc == 0
    assert badge.exists()
    assert not dest.exists(), "the badge branch returns before the PDF write"
    assert "--pdf" in err and "ignored (running --badge)" in err, err
