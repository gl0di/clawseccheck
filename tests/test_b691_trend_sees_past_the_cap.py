"""A flat arrow can no longer stand for "nothing got worse" on a capped run.

`score` is pinned at a floor by the most severe open FAIL, so a run that got materially
worse records the same number. `--trend`'s whole job is a temporal claim, and it made the
wrong one:

    record(score=49 grade=F raw_score=92)   # 2026-08-01
    record(score=49 grade=F raw_score=74)   # 2026-08-02, four new HIGH FAILs
    -->  2026-08-01  F  49  =  [audit]
         2026-08-02  F  49  =  [audit]

The mirror case is worse: a CRITICAL cleared while the config went dark also printed `=`,
so a real improvement, a real regression and a genuine standstill were indistinguishable —
on the one surface a user consults precisely because they are NOT re-reading the findings.

The uncapped pass-rate still moves, and `monitordims/_score.py` has watched it since B-273
with its own measurement ("gateway auth token->none AND a standing `/bin/sh *` grant
together reported 'No new threats', 49 -> 49"). This store never did. So the DECISION is
shared — `_shared.raw_backstop`, one predicate for both — and only the wording and the
subject gate are local.

Three things this file pins that are easy to get wrong:

* **The claim is strictly one-sided.** Only a FALL is stated. `raw_score` is a rounded
  percentage over ~407 weight units, so one integer is about four of them and a WARN->FAIL
  on a LOW check costs half of one — rendering "pass-rate unchanged" would be this same bug
  one resolution step down.
* **Absent is not agreement.** A legacy row carries no figure; treating that as "nothing
  changed" would read the ARRIVAL of the baseline as a fall. It counts as not compared,
  and self-heals after two comparable runs.
* **Comparability here is stricter than the monitor's**, because the store is: `state.json`
  is single-slot and pinned to one subject, while `history.jsonl` sits behind ONE default
  path for every `--home`.

Offline, stdlib only, writes nothing outside tmp_path.
"""
from __future__ import annotations

import json
import types

import pytest

from clawseccheck.catalog import Finding
from clawseccheck.cli import _record_history_point
from clawseccheck.history import load, record, render_trend, verify
from clawseccheck.scoring import compute

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
    """Drive the REAL record() -> load() -> render_trend() path."""
    path = str(tmp_path / "history.jsonl")
    for kwargs in rows:
        record(path=path, **kwargs)
    return path, render_trend(load(path), ascii_only=True)


def _row(score, day, *, findings=_SET_A, version=_VER, home=_HOME, source="audit"):
    return dict(score=score, when=f"2026-08-{day:02d}T09:00:00", source=source,
                home=home, findings=findings, version=version)


_FELL = "pass-rate fell"
_PINNED = "kept or raised"
_NOT_COMPARED = "not compared against the underlying"


# ------------------------------------------------------------------- the regression

def test_a_pinned_score_hiding_a_falling_pass_rate_is_stated(tmp_path):
    """The headline. Both runs render `F 49`; only the pass-rate moved."""
    _path, out = _store(tmp_path,
                        _row(_Score(49, "F", 92), 1),
                        _row(_Score(49, "F", 74), 2))
    assert f"({_FELL} 92 -> 74)" in out, out
    assert _PINNED in out, out


def test_the_same_clause_fires_when_the_letter_IMPROVED(tmp_path):
    """The mirror case, and the one where today's screen misleads most: the CRITICAL
    cleared so the cap lifted and the arrow points UP, while the underlying figure fell."""
    _path, out = _store(tmp_path,
                        _row(_Score(49, "F", 92), 1),
                        _row(_Score(74, "C", 74), 2))
    assert f"({_FELL} 92 -> 74)" in out, out
    assert _PINNED in out, out


def test_an_unchanged_pass_rate_renders_exactly_as_before(tmp_path):
    """The silence control, and the reason the claim is one-sided. Without it, a change
    that always says something would pass every assertion above."""
    _path, out = _store(tmp_path,
                        _row(_Score(49, "F", 92), 1),
                        _row(_Score(49, "F", 92), 2))
    assert _FELL not in out, out
    assert _PINNED not in out and _NOT_COMPARED not in out, out


def test_a_rising_pass_rate_says_nothing(tmp_path):
    """Only a fall is sound. A rise is real information the arrow already carries, and
    stating it here would invite reading RAW_HELD as 'nothing got worse'."""
    _path, out = _store(tmp_path,
                        _row(_Score(49, "F", 74), 1),
                        _row(_Score(49, "F", 92), 2))
    assert _FELL not in out and _PINNED not in out, out


# ------------------------------------------------- what makes two rows comparable at all

@pytest.mark.parametrize("second", [
    pytest.param(dict(home="~/work/.openclaw"), id="different-home"),
    pytest.param(dict(version="3.62.0"), id="different-version"),
    pytest.param(dict(findings=_SET_B), id="different-check-set"),
    pytest.param(dict(source="test"), id="test-tagged"),
])
def test_a_fall_across_incomparable_rows_is_disclosed_not_claimed(tmp_path, second):
    """Each of these makes the two figures answers to different questions.

    `home`: `history.jsonl` sits behind one default path for every `--home`, so two rows
    can describe different machines — measured during design, seven materially different
    homes produced one identical scope hash. `version`: the hash is over check IDs while
    `raw_score` is severity-WEIGHTED, so a re-tune moves the figure with the hash
    byte-identical. `findings`: a different denominator. `source`: the suite appends
    thousands of `test`-tagged rows into the real store, and one must never corroborate
    a real run.
    """
    _path, out = _store(tmp_path,
                        _row(_Score(49, "F", 92), 1),
                        _row(_Score(49, "F", 74), 2, **second))
    assert _FELL not in out, out
    assert _NOT_COMPARED in out, out


def test_a_row_carrying_a_figure_but_no_provenance_is_not_comparable(tmp_path):
    """Presence BEFORE equality, and the case that makes it more than decoration.

    The equality clauses alone are not enough: two rows that BOTH lack `raw_ver` compare
    `None == None` as agreement, so a hand-edited or foreign-written row holding a valid
    scope hash and figure but no build would be treated as a comparable subject and could
    earn a claim. The writer is all-three-or-none, so this state cannot arise from this
    tool — which is exactly why it has to be tested rather than reasoned away: the file is
    a plain local JSONL, and `render_trend` renders rows whether or not the chain holds
    (B-582 discloses a break, it does not withhold).

    Found by mutation: removing the presence clause left all 21 other tests green, i.e. it
    was an unfalsifiable line until this case existed.
    """
    path = str(tmp_path / "history.jsonl")
    record(**_row(_Score(49, "F", 92), 1), path=path)
    record(**_row(_Score(49, "F", 74), 2), path=path)
    stripped = "\n".join(
        json.dumps({k: v for k, v in json.loads(line).items() if k != "raw_ver"})
        for line in open(path, encoding="utf-8").read().strip().split("\n"))
    open(path, "w", encoding="utf-8").write(stripped + "\n")
    rows = load(path)
    assert all(r["raw_ver"] is None and r["raw_score"] is not None for r in rows), rows
    out = render_trend(rows, ascii_only=True)
    assert _FELL not in out, out
    assert _NOT_COMPARED in out, out


def test_a_legacy_row_counts_as_not_compared_and_self_heals(tmp_path):
    """Absent is not agreement. A row written before this change carries no figure, and
    inventing one from `score` would read the ARRIVAL of the baseline as a fall.

    Then it heals: the two rows AFTER the legacy one compare normally, so the store does
    not go permanently silent — the idiom `monitordims/_score.py` states for the same
    fields.
    """
    path = str(tmp_path / "history.jsonl")
    record(_Score(49, "F", 92), path=path, when="2026-07-30T09:00:00", source="audit")
    record(**_row(_Score(49, "F", 92), 1), path=path)
    record(**_row(_Score(49, "F", 74), 2), path=path)
    out = render_trend(load(path), ascii_only=True)
    assert _NOT_COMPARED in out, out
    assert f"({_FELL} 92 -> 74)" in out, out


# ----------------------------------------------------------- what the writer records

def test_the_triple_is_written_at_the_tail_of_a_graded_row(tmp_path):
    """Key ORDER matters: the chain hash canonicalises, but the line on disk is
    `json.dumps(row)` without sort_keys, so the seven-key graded prefix must stay
    byte-identical or every future row's bytes change for no reason."""
    path = str(tmp_path / "history.jsonl")
    record(**_row(_Score(49, "F", 92), 1), path=path)
    row = json.loads(open(path, encoding="utf-8").read().strip())
    assert list(row) == ["date", "score", "grade", "ts", "home", "source", "_schema",
                         "raw_score", "raw_scope", "raw_ver", "chain_hash"], list(row)
    assert row["raw_score"] == 92 and row["raw_ver"] == _VER
    assert isinstance(row["raw_scope"], str) and row["raw_scope"]


@pytest.mark.parametrize("score,kwargs", [
    pytest.param(_Score(0, "F", 0, assessable=False), {}, id="not-assessable"),
    pytest.param(_Score(49, "F", 92), dict(findings=None), id="no-findings"),
    pytest.param(_Score(49, "F", 92), dict(version=None), id="no-version"),
    pytest.param(_Score(49, "F", None), {}, id="no-raw-score"),
    pytest.param(_Score(49, "F", True), {}, id="boolean-raw-score"),
])
def test_an_incomplete_measurement_writes_no_figure_at_all(tmp_path, score, kwargs):
    """All three keys or none. `assessable` is the sharp one: `compute([])` returns
    `assessable=False, raw_score=0, graded=True`, so a run that found nothing would
    otherwise publish `raw 0` as a measurement and two of them would read as a perfect
    standstill. The boolean case matters for the same reason it did in B-694 —
    `isinstance(True, int)` is True."""
    path = str(tmp_path / "history.jsonl")
    record(**{**_row(score, 1), **kwargs}, path=path)
    row = json.loads(open(path, encoding="utf-8").read().strip())
    for key in ("raw_score", "raw_scope", "raw_ver"):
        assert key not in row, (key, row)


def test_compute_of_nothing_really_is_unassessable():
    """Pins the premise the `assessable` gate rests on, rather than trusting my reading of
    it: if this ever starts returning `assessable=True`, the gate above stops protecting
    anything and the test that relies on it would still pass."""
    empty = compute([])
    assert empty.assessable is False and empty.raw_score == 0
    assert getattr(empty, "graded", True) is True


def test_a_duck_typed_score_neither_crashes_nor_records(tmp_path):
    """13 test modules record through an object carrying only `.score`/`.grade`. A bare
    `score.raw_score` would `AttributeError` in every one of them."""
    path = str(tmp_path / "history.jsonl")
    err = record(types.SimpleNamespace(score=49, grade="F"), path=path,
                 when="2026-08-01T09:00:00")
    assert err is None
    row = json.loads(open(path, encoding="utf-8").read().strip())
    assert "raw_score" not in row and row["score"] == 49


# ------------------------------------------------------- the file is still a hash chain

def test_a_mixed_schema_file_still_verifies(tmp_path):
    """Old rows, new rows and an ungraded row in one file. The triple sits INSIDE the
    hashed payload, so a planted figure breaks the chain the way a planted `_schema` does
    (C-162's reason)."""
    path = str(tmp_path / "history.jsonl")
    record(_Score(49, "F", 92), path=path, when="2026-07-30T09:00:00", source="audit")
    record(**_row(_Score(49, "F", 92), 1), path=path)
    record(_Score(None, None, None, graded=False), path=path,
           when="2026-08-02T09:00:00", source="audit")
    record(**_row(_Score(49, "F", 74), 3), path=path)
    assert verify(path) == (True, "OK")
    assert len(load(path)) == 4


def test_a_planted_figure_breaks_the_chain(tmp_path):
    """The other half: if the triple were outside the hashed payload, editing it would be
    invisible. Non-vacuity for the test above."""
    path = str(tmp_path / "history.jsonl")
    record(**_row(_Score(49, "F", 92), 1), path=path)
    raw = open(path, encoding="utf-8").read()
    tampered = raw.replace('"raw_score": 92', '"raw_score": 40')
    assert tampered != raw, "the fixture did not contain the field it means to tamper with"
    open(path, "w", encoding="utf-8").write(tampered)
    ok, _msg = verify(path)
    assert ok is False


# --------------------------------------------------------------- the CLI actually wires it

def test_the_cli_helper_requires_the_finding_list():
    """Undefaulted on purpose. Without the finding list the scope hash cannot be computed,
    so a defaulted `findings=None` would let a future `_mode` branch record a permanently
    uncomparable row in silence — the exact shape B-598 built this helper to prevent."""
    with pytest.raises(TypeError):
        _record_history_point(_Score(49, "F", 92), types.SimpleNamespace(), None)


def test_the_cli_helper_passes_home_findings_and_version_through(tmp_path):
    """Driven through the real helper rather than a hand-built row: a patch that changed
    `history.py` alone would be inert against every real call site, which is precisely how
    a previous 'verified' claim on this file turned out to be unattributable.

    `home` is the load-bearing one — it was passed by NO call site before this change, so
    every row ever written carries `home: None`.
    """
    path = str(tmp_path / "history.jsonl")
    args = types.SimpleNamespace(history=path, home=_HOME, no_history=False,
                                 trend=False, monitor=False)
    _record_history_point(_Score(49, "F", 92), args, None, _SET_A)
    row = json.loads(open(path, encoding="utf-8").read().strip())
    assert row["home"] == _HOME
    assert row["raw_score"] == 92
    assert isinstance(row["raw_ver"], str) and row["raw_ver"]
