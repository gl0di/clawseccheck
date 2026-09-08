"""C-426 part B — _PRIMARY_MODES is the dispatch table, and it elects what actually runs.

The task's own test plan: *"a table-driven test that every flag reaches the same handler
it reached before the refactor. Build it from the flag list so it cannot silently miss
one."* Every selector test below is generated from ``_PRIMARY_MODES`` itself, so a mode
added to the table without a branch — or a branch added without a table entry — fails
here rather than shipping as a flag that parses and does nothing.

**Why the refactor was not a find-and-replace, recorded because the retraction that
preceded it was reasoned from the opposite assumption.** An independent pass over all 44
branches found three shapes that a mechanical `if args.X:` → `if _mode == "x":`
substitution silently breaks, each measured on the real CLI before the change:

* ``--dashboard --full --pdf`` — ``_defer_pdf`` suppresses the ``--pdf`` branch and
  control FALLS THROUGH to the dashboard, which writes the deferred PDF. Naive rewrite:
  the PDF is never written.
* ``--dashboard --pdf`` — the ``--pdf`` branch fires, writes, and then does *not* return
  (its ``return`` is gated on ``not args.dashboard``). Naive rewrite: the card is lost.
* ``--dashboard --pdf out.pdf --trend`` — the same fall-through lands on ``--trend``
  first, so the trend renders. This one was already producing a **wrong stderr note**
  before the refactor: ``note: --trend ignored (running --pdf)`` on the run where
  ``--trend`` was exactly what rendered. That is the B-276 bug class, still live, caused
  by dispatch and the note layer being two mechanisms.

All three are the same root cause — ``--pdf`` composes with ``--dashboard`` rather than
racing it (C-373/C-374) — and ``_resolve_mode`` now resolves that composition once,
up front, instead of leaving it to whichever branch happened to be next in the file.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawseccheck.cli import (
    _PRIMARY_MODES,
    _VALUE_REQUIRED_MODES,
    _pdf_is_produced,
    _resolve_mode,
    _select_primary_mode,
    main,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE_HOME = FIXTURES / "home_safe"

_NARGS_OPTIONAL = ("vet_mcp", "analyze_trajectory", "behavioral")


class _Args:
    """A stand-in for the parsed namespace: every unset attribute reads as inactive."""

    def __init__(self, **kw):
        self.__dict__.update(kw)

    def __getattr__(self, name):  # only reached for attributes never set
        return None


def _active(attr: str, kind: str) -> dict:
    return {attr: True} if kind == "bool" else {attr: "target"}


def _ids(seq):
    return [f"{a}" for a, _f, _k in seq]


# ----------------------------------------------------------- the selector, per entry

@pytest.mark.parametrize("attr,flag,kind", _PRIMARY_MODES, ids=_ids(_PRIMARY_MODES))
def test_each_flag_alone_elects_its_own_mode(attr, flag, kind):
    assert _select_primary_mode(_Args(**_active(attr, kind))) == attr


@pytest.mark.parametrize("attr,flag,kind", _PRIMARY_MODES, ids=_ids(_PRIMARY_MODES))
def test_each_flag_alone_resolves_to_its_own_mode(attr, flag, kind):
    """_resolve_mode only ever differs from the raw election for the --pdf composition,
    and --dashboard is absent here, so every entry must survive it unchanged."""
    assert _resolve_mode(_Args(**_active(attr, kind))) == attr


def test_no_flags_at_all_elects_nothing():
    assert _select_primary_mode(_Args()) is None
    assert _resolve_mode(_Args()) is None


@pytest.mark.parametrize("attr,flag,kind", _PRIMARY_MODES, ids=_ids(_PRIMARY_MODES))
def test_the_earlier_table_entry_wins_against_every_later_one(attr, flag, kind):
    """The whole point of the table being the dispatch order: for every other mode, the
    one declared first is the one elected. 44 x 43 ordered pairs, generated."""
    order = [a for a, _f, _k in _PRIMARY_MODES]
    mine = order.index(attr)
    for other, _oflag, okind in _PRIMARY_MODES:
        if other == attr:
            continue
        both = _Args(**_active(attr, kind), **_active(other, okind))
        expected = attr if mine < order.index(other) else other
        assert _select_primary_mode(both) == expected, f"{attr} vs {other}"


def test_skip_passes_the_election_to_the_next_entry():
    order = [a for a, _f, _k in _PRIMARY_MODES]
    first, second = order[0], order[1]
    kinds = {a: k for a, _f, k in _PRIMARY_MODES}
    both = _Args(**_active(first, kinds[first]), **_active(second, kinds[second]))
    assert _select_primary_mode(both) == first
    assert _select_primary_mode(both, skip={first}) == second


# --------------------------------------------------------- the --pdf composition

def test_pdf_alone_stays_a_mode():
    assert _resolve_mode(_Args(pdf="out.pdf")) == "pdf"


def test_pdf_with_dashboard_hands_the_election_to_the_dashboard():
    """Trap 1 and 2: --pdf becomes the side output and the dashboard is what renders."""
    assert _select_primary_mode(_Args(pdf="out.pdf", dashboard=True)) == "pdf"
    assert _resolve_mode(_Args(pdf="out.pdf", dashboard=True)) == "dashboard"


@pytest.mark.parametrize("rider", ["trend", "percentile", "next"])
def test_pdf_with_dashboard_and_a_rider_elects_the_rider(rider):
    """Trap 3: --trend/--percentile/--next sit between --pdf and --dashboard in the
    table, and the pre-refactor fall-through reached them first. They still win."""
    args = _Args(pdf="out.pdf", dashboard=True, **{rider: True})
    assert _resolve_mode(args) == rider


def test_a_mode_earlier_than_pdf_is_not_displaced_by_the_composition():
    """--menu beats --pdf, so the composition must not fire at all."""
    assert _resolve_mode(_Args(menu=True, pdf="out.pdf", dashboard=True)) == "menu"


# ------------------------------------------------- empty targets, generated from the table

@pytest.mark.parametrize("flag,attr", _VALUE_REQUIRED_MODES, ids=[a for _f, a in _VALUE_REQUIRED_MODES])
def test_an_empty_target_is_refused_before_any_mode_runs(flag, attr, tmp_path, capsys):
    rc = main([flag, "", "--home", str(SAFE_HOME), "--data-dir", str(tmp_path),
               "--no-history"])
    err = capsys.readouterr().err
    assert rc == 2, f"{flag} '' should be refused, got rc={rc}"
    assert f"{flag} needs a target" in err, err


@pytest.mark.parametrize("attr", _NARGS_OPTIONAL)
def test_the_nargs_optional_flags_keep_their_empty_form(attr):
    """--vet-mcp / --analyze-trajectory / --behavioral are declared nargs="?" const="",
    so an empty value is their documented "everything of this kind" form. Refusing it
    would break three working invocations."""
    assert attr not in {a for _f, a in _VALUE_REQUIRED_MODES}
    assert _select_primary_mode(_Args(**{attr: ""})) == attr


def test_an_empty_target_is_not_masked_by_an_earlier_mode(tmp_path, capsys):
    """It used to be: the check sat inside the vet family, so any mode dispatched above
    it returned first and the malformed flag was never mentioned."""
    rc = main(["--menu", "--vet", "", "--home", str(SAFE_HOME),
               "--data-dir", str(tmp_path), "--no-history"])
    assert rc == 2
    assert "--vet needs a target" in capsys.readouterr().err


# ------------------------------------------------------------- end to end on the CLI

def _run(tmp_path, *argv):
    return main([*argv, "--home", str(SAFE_HOME), "--data-dir", str(tmp_path),
                 "--no-history"])


def test_dashboard_with_pdf_writes_the_file_and_still_renders_the_card(tmp_path, capsys):
    """Trap 2, measured: the --pdf branch fires, writes, and deliberately does not
    return. Both outputs are part of the contract (C-373: the card is the chat message,
    the PDF is the attachment it points at)."""
    dest = tmp_path / "report.pdf"
    rc = _run(tmp_path, "--dashboard", "--pdf", str(dest))
    out = capsys.readouterr().out
    assert rc == 0
    assert dest.exists() and dest.stat().st_size > 0, "the PDF side output was lost"
    assert "ClawSecCheck" in out, "the dashboard card was lost"


def test_dashboard_full_with_pdf_still_writes_the_deferred_file(tmp_path, capsys):
    """Trap 1, measured: under --full the write is DEFERRED into the dashboard branch,
    so the mode that must be elected is the dashboard — not --pdf, whose own branch is
    suppressed and would otherwise take the election with it."""
    dest = tmp_path / "deferred.pdf"
    rc = _run(tmp_path, "--dashboard", "--full", "--fast", "--pdf", str(dest))
    capsys.readouterr()
    assert rc == 0
    assert dest.exists() and dest.stat().st_size > 0, "the deferred PDF was never written"


def test_dashboard_pdf_and_trend_renders_the_trend_and_does_not_lie_about_it(tmp_path, capsys):
    """Trap 3 — the live B-276-class defect this refactor removes. Before it, stderr
    said `--trend ignored (running --pdf)` on the run where --trend was what rendered."""
    dest = tmp_path / "with-trend.pdf"
    rc = _run(tmp_path, "--dashboard", "--pdf", str(dest), "--trend")
    cap = capsys.readouterr()
    assert rc == 0
    assert "Score Trend" in cap.out, cap.out[:400]
    assert "--trend ignored" not in cap.err, cap.err
    assert dest.exists(), "the PDF side output was lost"


def test_the_coherence_note_names_the_mode_that_actually_ran(tmp_path, capsys):
    """B-276's own worst case, kept as a regression.

    The direction is worth stating precisely, because it is easy to get backwards from
    the bug report alone: `--judge-packet` sits at index 38 of _PRIMARY_MODES and
    `--monitor` is last, so **--judge-packet is what runs**. The B-276 defect was the
    note claiming the opposite — "--judge-packet ignored (running --monitor)" — while
    _main() dispatched the judge packet. So the correct note names --judge-packet as the
    winner, and this asserts the exact string rather than merely that a note appeared."""
    rc = _run(tmp_path, "--monitor", "--judge-packet")
    err = capsys.readouterr().err
    assert rc in (0, 3)
    assert "--monitor ignored (running --judge-packet)" in err, err


def test_pdf_is_never_reported_as_ignored_when_it_composes(tmp_path, capsys):
    """It is produced, so calling it ignored would be the same lie in a new direction."""
    dest = tmp_path / "composed.pdf"
    _run(tmp_path, "--dashboard", "--pdf", str(dest))
    assert "--pdf ignored" not in capsys.readouterr().err


# ------------------------------------------- the exemption must not become a silent drop

@pytest.mark.parametrize(
    "attr", [a for a, _f, _k in _PRIMARY_MODES][:[a for a, _f, _k in _PRIMARY_MODES].index("pdf")]
)
def test_a_mode_earlier_than_pdf_does_not_earn_the_composition_exemption(attr):
    """Generated from the table: every mode declared before --pdf returns before the
    write site, so with `--<mode> --pdf X --dashboard` no PDF is produced and --pdf must
    stay in the ignored note. An unconditional exemption here is B-067 in a new place."""
    args = _Args(pdf="out.pdf", dashboard=True)
    assert _pdf_is_produced(args, attr) is False, attr


@pytest.mark.parametrize("attr", ["pdf", "trend", "percentile", "next", "dashboard",
                                  "dashboard_findings", "sbom", "monitor"])
def test_a_mode_at_or_after_the_write_site_does_earn_it(attr):
    assert _pdf_is_produced(_Args(pdf="out.pdf", dashboard=True), attr) is True


@pytest.mark.parametrize("rider", ["trend", "percentile", "next"])
def test_under_full_a_rider_now_gets_the_pdf_too(rider):
    """B-530, the unit-level half of the flip above. `--full` used to defer the write
    into the dashboard branch unconditionally, so a rider that beats the dashboard never
    reached it and this predicate had to answer False. The deferral is now conditioned on
    the dashboard being the elected mode, so past the ordering test the file is written
    for every mode at or after `--pdf` — with or without `--full`."""
    full = _Args(pdf="out.pdf", dashboard=True, full=True)
    assert _pdf_is_produced(full, rider) is True
    assert _pdf_is_produced(full, "dashboard") is True
    # The ordering boundary is untouched: a mode BEFORE --pdf still returns first.
    assert _pdf_is_produced(full, "badge") is False


def test_an_earlier_mode_keeps_the_side_outputs_in_the_ignored_note(tmp_path, capsys):
    """End to end: a mode that returns before the write site loses the artifacts, and the
    note has to say so.

    B-586 changed which argv demonstrates it. This was `--badge b.svg --pdf p.pdf
    --dashboard`, where the badge won the race, returned, and the PDF behind it was
    lost — the lost half being the point. `--badge`/`--html`/`--sarif` now COMPOSE with
    `--dashboard` exactly as `--pdf` does, so that argv writes both files and the rule
    needs a mode that genuinely does return early. `--risk-paths` is one, and it loses
    both.
    """
    badge, pdf = tmp_path / "b.svg", tmp_path / "p.pdf"
    rc = _run(tmp_path, "--risk-paths", "--badge", str(badge), "--pdf", str(pdf),
              "--dashboard")
    err = capsys.readouterr().err
    assert rc == 0
    assert not badge.exists() and not pdf.exists(), "--risk-paths returns before the write"
    assert "--pdf" in err and "--badge" in err, err
    assert "ignored (running --risk-paths)" in err, err


def test_the_badge_and_the_pdf_are_now_produced_together(tmp_path, capsys):
    """The other half of the same change: with `--dashboard` present neither preempts the
    other, so a run asking for both gets both. Pinned next to the boundary above so the
    two facts are read together — this is a fixed loss, not a widened exemption."""
    badge, pdf = tmp_path / "b.svg", tmp_path / "p.pdf"
    rc = _run(tmp_path, "--badge", str(badge), "--pdf", str(pdf), "--dashboard")
    capsys.readouterr()
    assert rc == 0
    assert badge.exists() and pdf.exists()


def test_a_pdf_lost_to_a_rider_is_no_longer_lost(tmp_path, capsys):
    """B-530 flipped this test, deliberately.

    It used to be `test_a_deferred_pdf_lost_to_a_rider_is_still_reported`, and it pinned
    the least-bad half of a real defect: `--full` deferred the write into the dashboard
    branch, `--trend` returned ~1,200 lines before that branch, so the file was never
    written and all C-426 could do was make sure the loss was *announced* rather than
    silent. B-530 fixed the loss itself — `_defer_pdf` now defers only when the dashboard
    is the elected mode — so both of the old assertions invert: the file exists, and
    `--pdf` leaves the ignored list because it was in fact produced.

    What must NOT be lost in the flip is the property this test was protecting: the run
    still has to SAY what happened. So the assertions below are the same shape as before
    — exit code plus a specific stderr claim — pointed at the new truth. The reduced
    (findings-only) scope of that PDF and the disclosure carried inside the document are
    covered in tests/test_b530_deferred_pdf_rider.py; kept there so this module stays
    about dispatch."""
    dest = tmp_path / "report.pdf"
    rc = _run(tmp_path, "--dashboard", "--full", "--fast", "--pdf", str(dest), "--trend")
    err = capsys.readouterr().err
    assert rc == 0
    assert dest.exists(), "--full deferred the write past --trend's return (B-530)"
    assert "--dashboard ignored (running --trend)" in err, err
    assert "--pdf" not in err.split("ignored (running --trend)")[0], (
        "--pdf was produced, so naming it ignored is the B-067 lie in reverse: " + err
    )
    assert str(dest) in err, f"the PDF was written and never mentioned: {err!r}"


def test_a_bare_run_is_unaffected_by_the_inversion(tmp_path, capsys):
    """No mode elected means the default report path, exactly as before — the part A
    contract (ungraded, but a result rather than an error) still holds."""
    rc = _run(tmp_path, "--json")
    body = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert body["graded"] is False
    assert body["grade"] is None
