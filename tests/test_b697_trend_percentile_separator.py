"""CLAWSECCHECK-B-697 — `--trend`'s percentile line was glued to the footer paragraph
above it, with no blank line separating them:

    1 run above fell on both measures: the score and the underlying pass-rate. Read the
    findings for that run.
    No grade yet - 3 of 5 layers did not run: installed skills and plugins (not reached), ...

`render_trend` separates every disclosure paragraph it composes internally with a blank
line, but the percentile line is emitted by a SEPARATE `_emit` call immediately after it
in the `--trend` branch of `cli.py`, so the two calls' output landed with no separator
between them and read as one continuation paragraph.

Fixed in the CLI (a bare `_emit("")` between the two calls), not inside `render_trend` —
`render_trend`'s return value is consumed elsewhere (`--watch-log` and callers that print
it directly), and a trailing blank line baked into the function would follow it there too.
That is the second half this file pins: `render_trend`'s own return value is unchanged.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import os

from clawseccheck.cli import main
from clawseccheck.history import render_trend, load


def _write_history(path, n: int) -> None:
    rows = [
        {"date": f"2026-{(i % 12) + 1:02d}-{(i % 28) + 1:02d}",
         "ts": f"2026-{(i % 12) + 1:02d}-{(i % 28) + 1:02d}T10:00:{i % 60:02d}",
         "score": 70, "grade": "C", "graded": True, "source": "audit",
         "home": None, "raw_score": None, "raw_scope": None, "raw_ver": None}
        for i in range(n)
    ]
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def test_cli_trend_separates_the_percentile_line_with_a_blank_line(tmp_path, capsys):
    hist = tmp_path / "history.jsonl"
    _write_history(hist, 3)
    rc = main(["--trend", "--history", str(hist), "--no-native", "--no-host",
              "--no-color", "--ascii"])
    out = capsys.readouterr().out
    assert rc == 0

    lines = out.rstrip("\n").splitlines()
    # The percentile/rank line is the LAST line `--trend` prints (cli.py emits it right
    # after render_trend's own output, then returns).
    assert lines, "expected --trend to print something"
    percentile_idx = len(lines) - 1
    assert ("percentile" in lines[percentile_idx].lower()
            or "rank" in lines[percentile_idx].lower()
            or "score better than" in lines[percentile_idx].lower()
            or "No grade yet" in lines[percentile_idx]), lines[percentile_idx]
    # The mutation target: the line immediately above the percentile line must be BLANK,
    # not the tail of the footer paragraph it used to glue onto.
    assert lines[percentile_idx - 1] == "", (
        "percentile line is not preceded by a blank line: "
        f"{lines[percentile_idx - 1]!r} / {lines[percentile_idx]!r}"
    )


def test_render_trend_return_value_has_no_trailing_blank_line(tmp_path):
    """The fix belongs in cli.py, never inside render_trend -- its return value is
    consumed by other callers (e.g. --watch-log) that must not gain a trailing blank
    line they never asked for."""
    hist = tmp_path / "history.jsonl"
    _write_history(hist, 3)
    rows = load(str(hist))
    text = render_trend(rows, ascii_only=True)
    assert not text.endswith("\n"), (
        "render_trend must not grow a trailing blank line as a side effect of the "
        "cli.py --trend fix"
    )
    assert not text.endswith("\n\n")
