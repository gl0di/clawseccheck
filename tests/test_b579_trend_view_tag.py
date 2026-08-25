"""B-579: looking at the trend used to degrade it — every row `--trend` recorded was
structurally ungraded, and the summary line counted its own artefact against itself.

Three bare `--trend` runs into one fresh store used to read::

    1 of 1 runs have no grade: ...
    2 of 2 runs have no grade: ...
    3 of 3 runs have no grade: ...

Each ratio was 100% wrong for the same reason: the "run" being graded was the trend
viewer's OWN row, created by the act of looking, not a check the user performed. The
more often someone checked their trend, the worse the disclosure read.

## The fix, in two parts (both required together)

1. **Tag, do not drop.** `history.record`'s `--trend` call site now passes
   `source="view"` — same "source machinery" [audit]/[test]/[dev]/[legacy] already use,
   one more value. A view row still renders, unconditionally, exactly like any other row
   (this codebase already deleted a filter that hid rows by source once — see
   `render_trend`'s own "Design note" — and re-adding one here in a different shape would
   repeat that mistake).

2. **The ratio excludes view rows AND says so.** Silently excluding them from the "N of M"
   count was tried and retracted: a reader who can see 4 rows but is told "1 of 2 have no
   grade" cannot tell whether something was filtered or miscounted. So when any row is
   excluded, a second line names exactly how many of how many rows on screen the ratio
   covers, and how many [view] rows were left out — the total in that second sentence
   always equals the number of rows actually rendered above it.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from clawseccheck.history import load as history_load
from clawseccheck.history import record as history_record
from clawseccheck.history import render_trend

REPO_ROOT = Path(__file__).resolve().parents[1]
SAFE = str(REPO_ROOT / "fixtures" / "home_safe")


class _Score:
    def __init__(self, score=50, grade="F", graded=True):
        self.score, self.grade, self.graded = score, grade, graded


def _run(tmp_path: Path, *args: str):
    """Every run gets its own fake HOME, same isolation as test_b598's _run helper —
    no subprocess here may ever touch the real machine's OpenClaw config."""
    fake_home = tmp_path / "home"
    fake_home.mkdir(exist_ok=True)
    import os
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", SAFE, *args],
        cwd=REPO_ROOT, capture_output=True, text=True,
        env={**os.environ, "HOME": str(fake_home)},
    )


# --------------------------------------------------------------- unit: history.record

def test_trend_records_source_view_via_cli(tmp_path):
    result = _run(tmp_path, "--trend", "--data-dir", str(tmp_path / "state"))
    assert result.returncode == 0
    rows = history_load(str(tmp_path / "state" / "history.jsonl"))
    assert len(rows) == 1
    assert rows[0]["source"] == "view"


# --------------------------------------------------------------- render_trend: the tag

def test_render_trend_tags_a_view_row_distinctly():
    rows = [{"date": "2026-08-10", "score": None, "grade": None, "graded": False,
            "ts": "2026-08-10T10:00:00", "home": None, "source": "view"}]
    out = render_trend(rows)
    assert "[view]" in out


# --------------------------------------------------------------- the headline case

def test_a_single_bare_trend_does_not_grade_its_own_look(tmp_path):
    """The exact regression: one bare --trend into a fresh store must not read
    "1 of 1 runs have no grade" — there is no CHECK to report on here at all."""
    result = _run(tmp_path, "--trend", "--data-dir", str(tmp_path / "state"))
    assert result.returncode == 0
    assert "[view]" in result.stdout
    assert "runs have no grade" not in result.stdout


def test_three_bare_trend_runs_never_worsen_the_ratio(tmp_path):
    data_dir = str(tmp_path / "state")
    for _ in range(3):
        result = _run(tmp_path, "--trend", "--data-dir", data_dir)
        assert result.returncode == 0
        # the defect: each successive run's OWN summary line got worse
        # ("1 of 1", "2 of 2", "3 of 3") — none of that text may appear at all now.
        assert not re.search(r"\d+ of \d+ runs have no grade", result.stdout)
    rows = history_load(str(tmp_path / "state" / "history.jsonl"))
    assert len(rows) == 3
    assert all(r["source"] == "view" for r in rows)


# --------------------------------------------------------------- reconciliation: mixed rows

def test_mixed_rows_ratio_reconciles_against_what_is_shown(tmp_path):
    """A real graded row + a real ungraded (non-view) row + two view rows: the ratio
    must count only the two real rows, and a second line must name the split so the
    numbers on screen always add up to what is rendered above them."""
    hist = tmp_path / "history.jsonl"
    history_record(_Score(60, "D", True), path=str(hist), when="2026-08-10T10:00:00", source="audit")
    history_record(_Score(None, None, False), path=str(hist), when="2026-08-11T10:00:00", source="audit")
    history_record(_Score(None, None, False), path=str(hist), when="2026-08-12T10:00:00", source="view")
    history_record(_Score(None, None, False), path=str(hist), when="2026-08-13T10:00:00", source="view")

    out = render_trend(history_load(str(hist)))
    assert "1 of 2 runs have no grade" in out
    assert "2 of 4 rows shown above are counted in that ratio" in out
    assert "the other 2 rows" in out
    # two row lines carry [view]; the reconciliation sentence names it too (3 total)
    assert out.count("[view]") == 3


def test_no_view_rows_leaves_the_ratio_and_wording_unchanged(tmp_path):
    """Backward compatibility: a history with zero view rows must render exactly as
    before B-579 — no reconciliation clause, since none is needed."""
    hist = tmp_path / "history.jsonl"
    history_record(_Score(60, "D", True), path=str(hist), when="2026-08-10T10:00:00", source="audit")
    history_record(_Score(None, None, False), path=str(hist), when="2026-08-11T10:00:00", source="audit")

    out = render_trend(history_load(str(hist)))
    assert "1 of 2 runs have no grade" in out
    assert "rows shown above are counted" not in out
