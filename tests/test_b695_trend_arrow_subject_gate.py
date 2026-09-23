"""CLAWSECCHECK-B-695 — the trend arrow had no subject gate.

`render_trend` computed the arrow from `row["score"]` against the previous graded row's
score with no check that the two rows describe the same run. B-691 built exactly the gate
this needs (`_same_subject`) for its own pass-rate footnote and never wired it to the
arrow itself — the primary thing on the screen. Measured on the real renderer, a fall
across two different `--home` values (one file, one default path, per B-691's own repro)
printed a confident down arrow.

Dave's ruling (2026-09-23 backlog-sweep): when two rows are not comparable, the arrow
renders BLANK — no new glyph, the existing `▲▼·` / `^v=` set is unchanged — plus one
disclosure line naming why. A legacy row (written before B-691 added `home`/`raw_scope`/
`raw_ver`) carries none of them and counts as non-comparable, the same "presence before
equality" rule the pass-rate clause already applied. The first graded row in a store has
no predecessor at all, so it makes no claim either — blank, and never counted toward the
disclosure: there was no comparison to withhold there, only one that never applied.

Offline, stdlib only, writes nothing outside tmp_path.
"""
from __future__ import annotations

import pytest

from clawseccheck.catalog import Finding
from clawseccheck.history import load, record, render_trend

_VER = "3.61.0"
_HOME = "~/.openclaw"


class _Score:
    """A graded, assessable ScoreResult stand-in — the shape `scoring.compute` returns."""

    def __init__(self, score, grade, raw_score, assessable=True, graded=True):
        self.score, self.grade, self.raw_score = score, grade, raw_score
        self.assessable, self.graded = assessable, graded


def _findings(*ids):
    return [Finding(id=i, title="t", severity="HIGH", status="FAIL",
                    detail="d", fix="f", framework="x") for i in ids]


_SET_A = _findings("B1", "B2")
_SET_B = _findings("B1", "B2", "B3")     # a different check set -> a different scope hash


def _store(tmp_path, *rows):
    """Drive the REAL record() -> load() -> render_trend() path, same helper B-691's own
    test file uses -- a hand-built row dict cannot prove the writer and reader agree."""
    path = str(tmp_path / "history.jsonl")
    for kwargs in rows:
        record(path=path, **kwargs)
    return render_trend(load(path), ascii_only=True)


def _row(score, day, *, findings=_SET_A, version=_VER, home=_HOME, source="audit"):
    # raw_score held constant (90) across every call below: these tests are about the
    # ARROW's own subject gate, not B-691/B-696's pass-rate footnote, so the pass-rate
    # figure is kept out of the way rather than incidentally exercised.
    return dict(score=score, when=f"2026-08-{day:02d}T09:00:00", source=source,
                home=home, findings=findings, version=version)


def _row_line(out: str, date: str) -> str:
    return next(ln for ln in out.splitlines() if ln.startswith(date))


_NO_GLYPH = ("  ^  ", "  v  ", "  =  ")


def _assert_blank(line: str) -> None:
    assert not any(g in line for g in _NO_GLYPH), line


# ------------------------------------------------------------------- comparable: real arrow

def test_a_comparable_fall_still_shows_the_down_arrow(tmp_path):
    out = _store(tmp_path,
                _row(_Score(90, "A", 90), 1),
                _row(_Score(60, "D", 90), 2))
    line = _row_line(out, "2026-08-02")
    assert "  v  " in line, line
    assert "no arrow" not in out, out


def test_a_comparable_rise_still_shows_the_up_arrow(tmp_path):
    out = _store(tmp_path,
                _row(_Score(60, "D", 90), 1),
                _row(_Score(90, "A", 90), 2))
    line = _row_line(out, "2026-08-02")
    assert "  ^  " in line, line
    assert "no arrow" not in out, out


def test_a_comparable_standstill_still_shows_the_flat_glyph(tmp_path):
    out = _store(tmp_path,
                _row(_Score(80, "B", 90), 1),
                _row(_Score(80, "B", 90), 2))
    line = _row_line(out, "2026-08-02")
    assert "  =  " in line, line
    assert "no arrow" not in out, out


# --------------------------------------------------------- non-comparable: blank + disclosure

@pytest.mark.parametrize("second", [
    pytest.param(dict(home="~/work/.openclaw"), id="different-home"),
    pytest.param(dict(version="3.62.0"), id="different-version"),
    pytest.param(dict(findings=_SET_B), id="different-check-set"),
    pytest.param(dict(source="test"), id="test-tagged"),
])
def test_a_non_comparable_pair_shows_no_arrow_and_discloses_why(tmp_path, second):
    out = _store(tmp_path,
                _row(_Score(90, "A", 90), 1),
                _row(_Score(60, "D", 90), 2, **second))
    line = _row_line(out, "2026-08-02")
    _assert_blank(line)
    assert "no arrow" in out, out
    assert "1 graded run" in out, out


def test_a_non_comparable_fall_never_claims_the_wrong_direction(tmp_path):
    """The exact regression this bug was filed for: a real fall across two different
    homes used to print a confident down arrow. `history.jsonl` sits behind ONE default
    path for every `--home`, so this is not hypothetical."""
    out = _store(tmp_path,
                _row(_Score(90, "A", 90), 1),
                _row(_Score(60, "D", 90), 2, home="~/work/.openclaw"))
    line = _row_line(out, "2026-08-02")
    assert "  v  " not in line, line


def test_a_non_comparable_pair_does_not_add_a_new_glyph(tmp_path):
    """No third arrow character was invented for this -- blank means blank, not a
    question mark or any other stand-in the asciify table would need to learn."""
    out = _store(tmp_path,
                _row(_Score(90, "A", 90), 1),
                _row(_Score(60, "D", 90), 2, home="~/work/.openclaw"))
    line = _row_line(out, "2026-08-02")
    assert "60    [audit]" in line, line   # score, then straight to the [source] tag


# --------------------------------------------------------------------------- legacy rows

def test_a_legacy_row_is_not_comparable_and_the_arrow_after_it_is_blank(tmp_path):
    """A row written before B-691 carries no home/raw_scope/raw_ver at all -- `None`, not
    a string -- so it fails the gate on presence, same as an explicit subject mismatch.
    Recorded with NO `findings=`/`version=` (the 13-test-module duck-typed call shape),
    which is exactly what makes record() write none of the three fields at all."""
    path = str(tmp_path / "history.jsonl")
    record(_Score(49, "F", 92), path=path, when="2026-07-30T09:00:00", source="audit")
    record(**_row(_Score(49, "F", 90), 1), path=path)
    out = render_trend(load(path), ascii_only=True)
    line = _row_line(out, "2026-08-01")
    _assert_blank(line)
    assert "no arrow" in out, out


def test_a_store_of_only_legacy_rows_renders_discloses_once_and_does_not_crash(tmp_path):
    path = str(tmp_path / "history.jsonl")
    for day in (28, 29, 30):
        record(_Score(49, "F", 92), path=path, when=f"2026-07-{day}T09:00:00",
              source="audit")
    out = render_trend(load(path), ascii_only=True)
    assert out.count("no arrow") == 1, out            # discloses ONCE, not per row
    assert "2 graded runs" in out, out                      # rows 2 and 3 -- not row 1
    for line in out.splitlines():
        if line.startswith("2026-07-"):
            _assert_blank(line)


def test_a_legacy_gap_self_heals_once_two_comparable_runs_land(tmp_path):
    """After the legacy row, two REAL comparable runs still get a real arrow between
    THEM -- the gap does not propagate forever, and no store rewrite is needed."""
    path = str(tmp_path / "history.jsonl")
    record(_Score(49, "F", 92), path=path, when="2026-07-30T09:00:00", source="audit")
    record(**_row(_Score(49, "F", 90), 1), path=path)
    record(**_row(_Score(74, "C", 90), 2), path=path)
    out = render_trend(load(path), ascii_only=True)
    line = _row_line(out, "2026-08-02")
    assert "  ^  " in line, line


# ---------------------------------------------------------------------------- first row

def test_the_first_graded_row_in_a_fresh_store_makes_no_claim(tmp_path):
    out = _store(tmp_path, _row(_Score(90, "A", 90), 1))
    line = _row_line(out, "2026-08-01")
    _assert_blank(line)
    # Nothing to disclose -- there was no comparison to withhold, only one that never
    # applied. A lone first row must not trip the non-comparable-arrow paragraph.
    assert "no arrow" not in out, out


def test_the_first_row_is_not_counted_toward_the_disclosure(tmp_path):
    """Three rows, three different homes: two comparisons are ATTEMPTED (row 2 against
    row 1, row 3 against row 2) and both fail the gate -- the count is 2, not 3, because
    row 1 never had a predecessor to compare against in the first place."""
    out = _store(tmp_path,
                _row(_Score(90, "A", 90), 1, home="~/a"),
                _row(_Score(80, "B", 90), 2, home="~/b"),
                _row(_Score(70, "C", 90), 3, home="~/c"))
    assert "2 graded runs" in out, out


def test_the_first_row_after_ascii_folding_still_makes_no_claim():
    """--ascii and the default render agree: blank has no character for either mode to
    fold, so the row is byte-identical either way (see history.render_trend's own note
    that no new glyph exists for this state)."""
    rows = [{"date": "2026-06-19", "score": 90, "grade": "A"}]
    unicode_out = render_trend(rows, ascii_only=False)
    ascii_out = render_trend(rows, ascii_only=True)
    assert unicode_out.splitlines()[-1] == ascii_out.splitlines()[-1]
