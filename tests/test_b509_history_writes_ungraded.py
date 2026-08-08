"""B-509 — the writer half: a run with no grade records a row with no grade.

I4 taught every *renderer* to withhold the letter when the five-layer check was
incomplete. `history.record()` was the last writer still republishing it, so a
`--full` run printed "No grade yet -- 2 of 5 layers did not run" and, in the same
breath, appended `{"score": 97, "grade": "A"}` to history.jsonl. `--trend` then
read the phantom back as a real data point: two surfaces disagreeing about one run.

The end-to-end test below is the one that proves they now agree. The rest pin the
properties that make the row safe to write:

* a GRADED row is byte-identical to before, key order included (the chain hash is
  order-independent, the written line is not);
* an UNGRADED row omits `score`/`grade` rather than nulling them, so an older
  build's `except KeyError: continue` skips it instead of crashing on `None > int`;
* `graded` lives inside the hashed payload, so flipping it breaks the chain;
* `int(score.score)` is never evaluated on an ungraded run (it would raise a
  TypeError that record()'s `except OSError` does not catch).

Offline; writes only under pytest's tmp_path.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from clawseccheck.cli import main
from clawseccheck.history import load, record, render_trend, verify

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE = str(FIXTURES / "home_safe")


@dataclass
class _Score:
    score: object
    grade: object
    graded: bool = True


def _lines(p: Path) -> list[dict]:
    return [json.loads(ln) for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]


# ---- the end-to-end gate: report and journal agree about the same run ----

def test_full_run_without_a_grade_records_no_grade(tmp_path, capsys):
    hist = tmp_path / "h.jsonl"
    code = main(["--full", "--home", SAFE, "--history", str(hist), "--no-color"])
    out = capsys.readouterr().out

    assert code == 0
    # The run really is ungraded -- if this stops holding the rest of the test is
    # measuring nothing, so assert it rather than assume it.
    assert "No grade yet" in out

    rows = _lines(hist)
    assert len(rows) == 1
    row = rows[0]
    assert "score" not in row, f"the journal recorded a score the report withheld: {row}"
    assert "grade" not in row, f"the journal recorded a grade the report withheld: {row}"
    assert row["graded"] is False
    assert verify(str(hist)) == (True, "OK")


def test_the_recorded_ungraded_run_renders_as_no_grade_in_trend(tmp_path):
    hist = tmp_path / "h.jsonl"
    main(["--full", "--home", SAFE, "--history", str(hist), "--no-color"])
    text = render_trend(load(str(hist)))
    assert "no grade" in text
    for letter in ("A", "B", "C", "D", "F"):
        assert f"  {letter}  " not in text


# ---- I5 boundary: --trend/--percentile/--next still grade, and that is correct today ----

def test_full_trend_still_records_a_graded_row(tmp_path, capsys):
    """PINNED, and it flips in I5 (CLAWSECCHECK-C-426) -- not an oversight.

    `--trend` renders a BARE run: the CLI itself prints "note: --full has no effect
    with --trend", and a bare run is legitimately graded until I5 makes it otherwise.
    `--trend` reaches `_apply_live_test_cap` (cli.py), which has no `ledger` parameter,
    and returns before `_resolve_runtime_caps` -- the one place a ledger is built -- is
    ever called. So the writer fix above is a deliberate no-op here.

    This test exists so that hole stays visible instead of being silently assumed.
    When I5 teaches the bare path to build a ledger, this is the assertion to flip.
    """
    hist = tmp_path / "h.jsonl"
    code = main(["--full", "--trend", "--home", SAFE, "--history", str(hist), "--no-color"])
    err = capsys.readouterr().err

    assert code == 0
    assert "--full has no effect with --trend" in err
    row = _lines(hist)[-1]
    assert "score" in row and "grade" in row
    assert "graded" not in row


# ---- row shape ----

def test_graded_row_keeps_its_exact_key_order(tmp_path):
    """The chain hash canonicalizes with sort_keys, the written line does not."""
    hist = tmp_path / "h.jsonl"
    record(_Score(72, "C"), path=str(hist), when="2026-06-15", source="audit")
    assert list(_lines(hist)[0]) == [
        "date", "score", "grade", "ts", "home", "source", "_schema", "chain_hash",
    ]


def test_ungraded_row_omits_the_keys_rather_than_nulling_them(tmp_path):
    """Omission is what makes an OLDER build degrade instead of crash.

    An absent key hits load()'s `except KeyError: continue` -- the same path the
    C-250 retention marker already takes. An explicit null passes the key check,
    flows through as score=None, and the pre-B-509 render_trend's `curr > prev`
    raises TypeError on it.
    """
    hist = tmp_path / "h.jsonl"
    record(_Score(None, None, graded=False), path=str(hist), when="2026-06-15")
    row = _lines(hist)[0]
    assert "score" not in row
    assert "grade" not in row
    assert row["graded"] is False


def test_an_ungraded_run_never_evaluates_int_on_a_missing_score(tmp_path):
    """record() must not raise: its own `except` only catches OSError."""
    hist = tmp_path / "h.jsonl"
    record(_Score(None, None, graded=False), path=str(hist), when="2026-06-15")
    assert hist.is_file()


def test_a_score_object_with_no_graded_attribute_still_records(tmp_path):
    """Duck-typed callers predate ScoreResult.graded; absent means graded."""

    class _Legacy:
        score = 81
        grade = "B"

    hist = tmp_path / "h.jsonl"
    record(_Legacy(), path=str(hist), when="2026-06-15")
    row = _lines(hist)[0]
    assert row["score"] == 81
    assert row["grade"] == "B"
    assert "graded" not in row


# ---- the chain ----

def test_a_mixed_chain_verifies(tmp_path):
    hist = tmp_path / "h.jsonl"
    record(_Score(72, "C"), path=str(hist), when="2026-06-15")
    record(_Score(None, None, graded=False), path=str(hist), when="2026-06-16")
    record(_Score(90, "A"), path=str(hist), when="2026-06-17")
    record(_Score(None, None, graded=False), path=str(hist), when="2026-06-18")

    assert verify(str(hist)) == (True, "OK")
    rows = load(str(hist))
    assert [r["graded"] for r in rows] == [True, False, True, False]


def test_flipping_graded_on_disk_breaks_the_chain(tmp_path):
    """'graded' is inside the hashed payload, like '_schema'."""
    hist = tmp_path / "h.jsonl"
    record(_Score(None, None, graded=False), path=str(hist), when="2026-06-15")
    record(_Score(90, "A"), path=str(hist), when="2026-06-16")

    rows = _lines(hist)
    rows[0]["graded"] = True
    hist.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")

    ok, why = verify(str(hist))
    assert ok is False
    assert "broken" in why.lower()


def test_an_ungraded_row_appended_to_an_existing_graded_chain_verifies(tmp_path):
    """The real-world shape: a long graded history, then the rule changes."""
    hist = tmp_path / "h.jsonl"
    for i in range(20):
        record(_Score(70 + i, "C"), path=str(hist), when=f"2026-06-{i + 1:02d}")
    before = _lines(hist)

    record(_Score(None, None, graded=False), path=str(hist), when="2026-07-01")

    # The pre-existing rows keep their bytes -- there is no migration.
    assert _lines(hist)[:20] == before
    assert verify(str(hist)) == (True, "OK")
