"""B-578 — `--percentile`'s rank branch was unreachable from every invocation.

`graded` is True only once the five-layer ledger is complete, which only a `--full` run
reaches, and `--percentile` does not honour `--full`. So the mode's only possible answer
was "No rank yet", the bundled reference distribution was dead code, and the advice it
printed ("complete the remaining layers") told the user to do something the mode rejects.

An ungraded run now ranks the most recent COMPLETE check from local history, dated and
explicitly not attributed to this run. The one thing it must never do is rank the number
an ungraded ScoreResult still carries internally — that is the leak C-426 closed, and
these tests pin it shut from the new direction.

Every test passes an explicit history path. The suite redirects $HOME to a throwaway
directory, so the default store is empty under pytest; depending on that would make these
tests pass for a reason that has nothing to do with what they assert.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck import audit
from clawseccheck.cli import (
    _build_layer_ledger,
    _last_complete_history_row,
    _percentile_line,
)
from clawseccheck.scoring import compute

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE = FIXTURES / "home_safe"


def _bare_ledger(findings):
    class _Args:
        fast = False
    return _build_layer_ledger(_Args(), findings)


def _write_history(path: Path, rows) -> str:
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return str(path)


def _graded_row(date="2026-08-21", score=77):
    return {"date": date, "score": score, "grade": "C", "graded": True,
            "ts": f"{date}T21:17:29", "home": None, "source": "audit"}


def _ungraded_row(date="2026-08-25"):
    return {"date": date, "score": None, "grade": None, "graded": False,
            "ts": f"{date}T13:23:35", "home": None, "source": "audit"}


def _ungraded_score():
    ctx, findings, _ = audit(SAFE)
    score = compute(findings, ctx, ledger=_bare_ledger(findings))
    assert score.graded is False
    return score


# ------------------------------------------------------------------ the close
def test_an_ungraded_run_ranks_the_last_complete_check(tmp_path):
    """The filed defect: before this, no invocation could ever print a rank."""
    hist = _write_history(tmp_path / "h.jsonl", [_graded_row()])
    out = _percentile_line(_ungraded_score(), True, hist)
    assert "You score better than" in out
    assert "No rank yet" not in out


def test_the_historical_rank_carries_its_own_date_and_disowns_this_run(tmp_path):
    """It must never read as this run's result."""
    hist = _write_history(tmp_path / "h.jsonl", [_graded_row(date="2026-08-21", score=77)])
    out = _percentile_line(_ungraded_score(), True, hist)
    assert "2026-08-21" in out
    assert "77/100" in out
    assert "not this run" in out


def test_the_open_layers_are_named(tmp_path):
    """The old message said "complete the remaining layers" and named none of them —
    and in this mode that was an instruction the mode itself rejects."""
    hist = _write_history(tmp_path / "h.jsonl", [_graded_row()])
    out = _percentile_line(_ungraded_score(), True, hist)
    assert "layers did not run" in out


def test_with_no_complete_check_it_names_the_invocation_that_makes_one(tmp_path):
    hist = _write_history(tmp_path / "h.jsonl", [_ungraded_row()])
    out = _percentile_line(_ungraded_score(), True, hist)
    assert "No rank yet" in out
    assert "--full" in out


# ------------------------------------------------------------------ C-135: the leak
def test_this_runs_own_withheld_number_is_never_published(tmp_path):
    """The tempting wrong fix, pinned shut.

    An ungraded ScoreResult still carries `.score` internally. Ranking it would print,
    through a different command, exactly the figure the report deliberately withheld.
    The historical score here is deliberately different from this run's so the two
    cannot be confused.
    """
    score = _ungraded_score()
    own = score.score
    hist = _write_history(tmp_path / "h.jsonl", [_graded_row(score=77)])
    assert own != 77, "fixture drift — pick a historical score this run does not share"
    out = _percentile_line(score, True, hist)
    assert f"{own}/100" not in out
    assert "77/100" in out


def test_a_graded_run_still_ranks_its_own_score(tmp_path):
    """The opposite direction: the close must not make every run use history."""
    _, _, graded = audit(SAFE)
    assert graded.graded is True
    hist = _write_history(tmp_path / "h.jsonl", [_graded_row(score=1)])
    out = _percentile_line(graded, True, hist)
    assert "No rank yet" not in out
    assert "not this run" not in out, "a graded run must rank ITS OWN score, not history"


# ------------------------------------------------------------------ row selection
def test_an_ungraded_history_row_is_never_ranked(tmp_path):
    """`score` is present as null on a real ungraded row, so a key-membership test would
    count it as rankable. Measured on the real store: key-presence calls 4,678 of 4,678
    rows graded; `score is not None` calls 4,193 — the difference is exactly these."""
    hist = _write_history(tmp_path / "h.jsonl", [_ungraded_row()])
    assert _last_complete_history_row(hist) is None


def test_the_most_recent_complete_row_wins(tmp_path):
    hist = _write_history(tmp_path / "h.jsonl", [
        _graded_row(date="2026-08-01", score=10),
        _graded_row(date="2026-08-21", score=77),
        _ungraded_row(date="2026-08-25"),
    ])
    row = _last_complete_history_row(hist)
    assert row is not None and row["score"] == 77


def test_a_malformed_score_is_never_ranked(tmp_path):
    """`isinstance(True, int)` is True in Python, so a row carrying `"score": true`
    would otherwise rank as 1/100."""
    for bad in (True, "77", 101, -1, None, [77]):
        row = dict(_graded_row())
        row["score"] = bad
        hist = _write_history(tmp_path / f"h{type(bad).__name__}{bad!r}.jsonl", [row])
        assert _last_complete_history_row(hist) is None, bad


def test_an_unreadable_history_is_not_a_crash(tmp_path):
    """A named path that cannot be read must degrade to "nothing to rank", not raise."""
    missing = str(tmp_path / "nope" / "h.jsonl")
    assert _last_complete_history_row(missing) is None
    assert "No rank yet" in _percentile_line(_ungraded_score(), True, missing)
