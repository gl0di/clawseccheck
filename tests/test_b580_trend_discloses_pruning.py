"""`--trend` must not claim completeness over a history retention has cut.

B-580. `render_trend`'s own docstring says "Every row is shown, always, in the order
recorded". On the real machine the history file's FIRST line is a retention marker
announcing that 1,001 older runs were pruned — and the trend mentioned it zero times,
because `load()` dropped the marker before any renderer could see it.

A trend is a claim about a shape over time, so starting silently mid-history hides exactly
the part a reader would use to judge whether things are improving: the pruned runs are the
oldest, i.e. the baseline.

The events journal takes the identical marker from the identical writer and discloses it
(C-250 folded it into `render_events`'s header). The history renderer never got the same
treatment.

**The tempting wrong fix is pinned against below.** The marker must not become a row.
`monitor._rotate_journal` shapes it without `date`/`score`/`grade` on purpose, and says why
in its own docstring: "a marker meant for a human reading the events journal must not
corrupt the trend". As a row it would also be counted in "N of M runs have no grade".

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
import subprocess
import sys

from clawseccheck.history import load as history_load

_MARKER = {
    "ts": "2026-08-08T00:49:05",
    "level": "INFO",
    "message": ("1001 older entries were pruned by retention at 2026-08-08T00:49:05 "
                "(retention cap: newest 4000 of 5000 kept)."),
    "_schema": 1,
    "retention_pruned": 1001,
    "chain_hash": "f86aad70",
}


def _row(i):
    return {"_schema": 1, "date": f"2026-08-1{i}", "score": 70 + i, "grade": "C",
            "graded": True, "ts": f"2026-08-1{i}T10:00:00", "home": "~/.openclaw",
            "source": "audit"}


def _history(tmp_path, *, with_marker: bool, name="history.jsonl"):
    p = tmp_path / name
    entries = ([_MARKER] if with_marker else []) + [_row(i) for i in range(6)]
    p.write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")
    return p


def _trend(path, tmp_path):
    out = subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--trend", "--history", str(path),
         "--data-dir", str(tmp_path / "d")],
        capture_output=True, text=True,
    )
    return out.stdout + out.stderr


def test_a_pruned_history_says_so(tmp_path):
    """The reproduction this task was filed on."""
    text = _trend(_history(tmp_path, with_marker=True), tmp_path)

    # Non-vacuity: the rows must actually have rendered, or "the disclosure is present"
    # would be true of an empty render too.
    assert "2026-08-10T10:00:00" in text, text[:400]

    assert "1001 older entries were pruned" in text, text
    assert "starts mid-history" in text, text


def test_a_history_with_no_marker_invents_no_disclosure(tmp_path):
    """The control. A sentence that appears on every trend carries no information, and an
    invented one is worse than a missing one."""
    text = _trend(_history(tmp_path, with_marker=False), tmp_path)
    assert "2026-08-10T10:00:00" in text
    assert "pruned" not in text.lower()
    assert "Not every recorded run is above" not in text


def test_the_marker_is_not_counted_as_a_run(tmp_path):
    """The wrong fix, pinned. As a row it would inflate every count that says "N runs" and
    would render as a run with no date."""
    with_m = history_load(str(_history(tmp_path, with_marker=True, name="a.jsonl")))
    without = history_load(str(_history(tmp_path, with_marker=False, name="b.jsonl")))

    assert len(with_m) == len(without) == 6, (len(with_m), len(without))
    assert all("date" in r for r in with_m)
    assert with_m.retention_pruned == 1001
    assert without.retention_pruned == 0
    assert without.retention_notice is None


def test_the_notice_rides_the_list_not_its_elements(tmp_path):
    """Why an attribute: `load()`'s other callers read `rows[-1]["date"]` and pass the list
    on. Neither can see this, so neither can mistake it for a run."""
    rows = history_load(str(_history(tmp_path, with_marker=True)))
    assert isinstance(rows, list)
    assert "1001 older entries" in (rows.retention_notice or "")
    assert not any("retention_pruned" in r for r in rows)


def test_verify_history_still_accepts_a_file_whose_first_line_is_a_marker(tmp_path):
    """The marker is chained like any other entry; surfacing it must not change that."""
    path = _history(tmp_path, with_marker=True)
    out = subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--verify-history", "--history", str(path),
         "--data-dir", str(tmp_path / "d")],
        capture_output=True, text=True,
    )
    assert "Traceback" not in (out.stdout + out.stderr)
