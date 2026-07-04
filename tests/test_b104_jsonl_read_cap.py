"""B-104: session/audit JSONL reads must be size-bounded (tail), not whole-file.

Append-only config-audit (B77) and session (B79) logs can reach GB; a whole-file
`read_text` + `.splitlines()` OOMs on long-running agents. Reads now tail the
most-recent bytes — the entries a posture check actually cares about — and drop
the possibly-partial first line (callers already skip unparseable lines).
"""
from __future__ import annotations

from clawseccheck.checks import _JSONL_SCAN_CAP, _read_jsonl_tail


def test_small_file_read_in_full(tmp_path):
    p = tmp_path / "a.jsonl"
    p.write_text('{"n":1}\n{"n":2}\n', encoding="utf-8")
    text, truncated = _read_jsonl_tail(p)
    assert truncated is False
    assert text == '{"n":1}\n{"n":2}\n'


def test_huge_file_tails_recent_and_drops_partial_line(tmp_path):
    p = tmp_path / "big.jsonl"
    filler = '{"x":"' + "A" * 200 + '"}'
    n = (_JSONL_SCAN_CAP // len(filler)) + 50
    lines = ['{"marker":"OLD"}'] + [filler] * n + ['{"marker":"NEW"}']
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")

    text, truncated = _read_jsonl_tail(p)
    assert truncated is True
    assert len(text.encode("utf-8")) <= _JSONL_SCAN_CAP
    assert '"NEW"' in text        # recent tail preserved
    assert '"OLD"' not in text    # oldest entries dropped
    assert text.startswith("{")   # partial leading line dropped → first line complete
