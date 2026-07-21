"""C-250 (low): three journal-honesty gaps, all in the same shared journal machinery
(monitor.py's ``_rotate_journal`` / ``verify_chain`` / ``_iter_jsonl``, plus the CLI's
event-verification entry point).

(a) ``_rotate_journal`` evicted up to ``_JOURNAL_MAX_LINES - _JOURNAL_KEEP`` (1002 by
    default) entries with no trace at all; ``render_events`` then printed an
    authoritative-sounding "{keep} recorded change event(s)" starting silently
    mid-history. A synthetic retention-marker entry (``retention_pruned`` key) is now
    prepended as the new oldest survivor whenever rotation triggers, and
    ``render_events`` folds it into the header instead of rendering it as one more
    anonymous line.
(b) ``verify_chain`` reported a bare "OK" over a journal holding legacy (no
    ``chain_hash``) entries, or over a tail-truncated / unparseable line — both now
    disclosed the same way an unknown-``_schema`` entry already was (C-167).
(c) ``--verify-history --history <events-path>`` already verified an events journal
    correctly (same underlying algorithm) but always said "History chain"; a new
    ``--verify-events`` flag verifies ``--events`` under the correct, discoverable name.

Read-only and offline: every test writes only under ``tmp_path``.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.cli import main
from clawseccheck.history import record as history_record
from clawseccheck.history import load as history_load
from clawseccheck.monitor import (
    SCHEMA_VERSION,
    _chain_hash,
    _rotate_journal,
    load_events,
    record_events,
    verify_chain,
)
from clawseccheck.report import render_events


def _write_raw_chain(path: Path, n: int, start: int = 0) -> None:
    """n well-formed, correctly-chained events.jsonl-shaped lines, written directly."""
    prev_hash = ""
    lines = []
    for i in range(start, start + n):
        base = {"ts": f"2026-01-01T00:{i % 60:02d}:00", "level": "INFO",
                "message": f"event-{i}", "_schema": SCHEMA_VERSION}
        ch = _chain_hash(prev_hash, base)
        lines.append(json.dumps({**base, "chain_hash": ch}))
        prev_hash = ch
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# (a) rotation disclosure — clean (no rotation) vs bad (rotation happened)
# ---------------------------------------------------------------------------

def test_clean_below_cap_journal_has_no_retention_marker(tmp_path):
    """A journal that never hit the retention cap must carry no marker at all —
    the fix must not manufacture a disclosure where nothing was ever pruned."""
    journal = tmp_path / "events.jsonl"
    _write_raw_chain(journal, 10)
    _rotate_journal(journal)  # real default caps — no-op far below them

    events = load_events(journal)
    assert len(events) == 10
    assert not any("retention_pruned" in e for e in events)

    out = render_events(events)
    assert "pruned" not in out
    assert "showing 10 event(s)" in out


def test_rotated_journal_discloses_count_and_timestamp(tmp_path):
    """Bad path: a journal that rotates must carry a marker disclosing exactly how
    many real entries were evicted, and render_events must surface it in the
    header rather than bury it as one more anonymous [i] line."""
    journal = tmp_path / "events.jsonl"
    total = 60
    _write_raw_chain(journal, total)

    _rotate_journal(journal, max_lines=50, keep=40)

    events = load_events(journal)
    assert len(events) == 41  # 40 survivors + 1 marker
    marker = events[0]
    assert marker["retention_pruned"] == 20
    assert "20" in marker["message"]
    assert "pruned by retention" in marker["message"]
    assert "ts" in marker and marker["ts"]

    out = render_events(events)
    # The marker's own disclosure text reaches the header, not a bare event count
    # that silently starts mid-history.
    assert "showing 40 event(s)" in out
    assert "20" in out and "pruned by retention" in out
    # The marker itself must not ALSO print as an ordinary [i] event line below the
    # header (it would be a confusing duplicate of the same fact).
    assert out.count("pruned by retention") == 1
    # The real survivors still render normally (the newest 40: event-20..event-59).
    assert "event-59" in out and "event-20" in out
    assert "event-19" not in out  # genuinely evicted, not merely undisclosed


def test_rotation_marker_is_tamper_evident_like_any_other_entry(tmp_path):
    """The marker participates in the hash chain normally — tampering with its
    message must break the chain like tampering with any other entry."""
    journal = tmp_path / "events.jsonl"
    _write_raw_chain(journal, 60)
    _rotate_journal(journal, max_lines=50, keep=40)

    ok, msg = verify_chain(journal)
    assert ok is True and msg == "OK"

    lines = journal.read_text(encoding="utf-8").splitlines()
    marker = json.loads(lines[0])
    marker["retention_pruned"] = 999  # tamper
    lines[0] = json.dumps(marker)
    journal.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, msg = verify_chain(journal)
    assert ok is False
    assert "broken at entry 0" in msg


def test_rotation_marker_in_history_jsonl_is_silently_skipped_by_history_load(tmp_path):
    """_rotate_journal backs history.jsonl too (history.record's own retention). The
    SAME marker shape (ts/level/message, no date/score/grade) must not corrupt a
    trend row — history.load()'s existing KeyError guard already skips anything
    missing 'date'/'score'/'grade', so this is a pre-existing, reused safety net,
    not new special-casing."""
    history = tmp_path / "history.jsonl"

    class _Score:
        def __init__(self, score, grade):
            self.score = score
            self.grade = grade

    for i in range(60):
        history_record(_Score(i % 100, "C"), path=str(history),
                        when=f"2026-01-{(i % 28) + 1:02d}")
    _rotate_journal(history, max_lines=50, keep=40)

    lines = [ln for ln in history.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 41  # 40 survivors + 1 marker, on disk

    rows = history_load(str(history))
    assert len(rows) == 40  # the marker never counts as a trend row
    assert all("score" in r for r in rows)


# ---------------------------------------------------------------------------
# (b) verify_chain honesty — clean vs bad
# ---------------------------------------------------------------------------

def test_clean_fully_chained_journal_stays_bare_ok(tmp_path):
    """A genuinely clean journal (every entry chained, nothing unparseable) must NOT
    grow a parenthetical — the fix must not manufacture noise on the happy path."""
    journal = tmp_path / "events.jsonl"
    record_events([("HIGH", "a"), ("INFO", "b")], path=journal, when="2026-01-01T00:00:00")

    ok, msg = verify_chain(journal)
    assert ok is True
    assert msg == "OK"


def test_legacy_entries_disclosed_by_count_not_bare_ok(tmp_path):
    """Bad path: entries with no chain_hash at all used to verify as a bare "OK",
    indistinguishable from a fully chain-verified file."""
    journal = tmp_path / "events.jsonl"
    legacy = [
        {"ts": "2025-01-01T00:00:00", "level": "HIGH", "message": "old 1"},
        {"ts": "2025-01-02T00:00:00", "level": "INFO", "message": "old 2"},
        {"ts": "2025-01-03T00:00:00", "level": "INFO", "message": "old 3"},
    ]
    journal.write_text("\n".join(json.dumps(e) for e in legacy) + "\n", encoding="utf-8")

    ok, msg = verify_chain(journal)
    assert ok is True
    assert msg == "OK (3 entries not chain-verified (legacy, no chain_hash))"


def test_unparseable_tail_line_disclosed_not_silently_dropped(tmp_path):
    """Bad path: a tail-truncated (mid-write-crash-shaped) final line used to be
    silently swallowed by _iter_jsonl with zero trace in the verdict."""
    journal = tmp_path / "events.jsonl"
    record_events([("HIGH", "a")], path=journal, when="2026-01-01T00:00:00")
    with open(journal, "a", encoding="utf-8") as fh:
        fh.write('{"ts": "2026-01-01T00:01:00", "level": "HIGH", "message": "cut off mid')
        # deliberately no closing quote/brace/newline — an interrupted write

    ok, msg = verify_chain(journal)
    assert ok is True
    assert msg == "OK (1 unparseable line skipped)"


def test_legacy_and_unparseable_notes_combine_in_one_disclosure(tmp_path):
    """Multiple honesty gaps in the same file combine into one parenthetical,
    semicolon-separated, in a stable order."""
    journal = tmp_path / "events.jsonl"
    legacy = {"ts": "2025-01-01T00:00:00", "level": "HIGH", "message": "old"}
    journal.write_text(json.dumps(legacy) + "\nnot even json\n", encoding="utf-8")

    ok, msg = verify_chain(journal)
    assert ok is True
    assert msg == (
        "OK (1 entry not chain-verified (legacy, no chain_hash); "
        "1 unparseable line skipped)"
    )


# ---------------------------------------------------------------------------
# (c) --verify-events: a discoverable, correctly-worded CLI entry point
# ---------------------------------------------------------------------------

def test_verify_events_clean_journal_returns_zero_and_says_events_chain(tmp_path, capsys):
    events = tmp_path / "events.jsonl"
    record_events([("HIGH", "a")], path=events, when="2026-01-01T00:00:00")

    rc = main(["--verify-events", "--events", str(events)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Events chain OK" in out
    assert "History chain" not in out


def test_verify_events_tampered_journal_returns_nonzero_and_says_broken(tmp_path, capsys):
    events = tmp_path / "events.jsonl"
    record_events([("HIGH", "a"), ("MEDIUM", "b")], path=events, when="2026-01-01T00:00:00")
    lines = [json.loads(ln) for ln in events.read_text(encoding="utf-8").splitlines() if ln.strip()]
    lines[0]["message"] = "TAMPERED"
    events.write_text("\n".join(json.dumps(e) for e in lines) + "\n", encoding="utf-8")

    rc = main(["--verify-events", "--events", str(events)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "Events chain BROKEN" in out


def test_verify_events_absent_journal_returns_zero(tmp_path, capsys):
    """No journal yet is not a failure — same graceful contract as --verify-history."""
    rc = main(["--verify-events", "--events", str(tmp_path / "nope.jsonl")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Events chain OK" in out


def test_verify_events_is_distinct_from_verify_history(tmp_path, capsys):
    """--verify-history --history <events-path> already verified an events journal
    correctly (documented pre-existing behaviour — same underlying algorithm), but
    said 'History chain'; --verify-events on the SAME file must name it correctly."""
    events = tmp_path / "events.jsonl"
    record_events([("HIGH", "a")], path=events, when="2026-01-01T00:00:00")

    rc_history_flag = main(["--verify-history", "--history", str(events)])
    out_history_flag = capsys.readouterr().out
    rc_events_flag = main(["--verify-events", "--events", str(events)])
    out_events_flag = capsys.readouterr().out

    assert rc_history_flag == 0 and rc_events_flag == 0
    assert "History chain OK" in out_history_flag
    assert "Events chain OK" in out_events_flag
