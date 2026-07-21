"""Tests for C-164 — hash-chained journal rotation (prune + re-genesis) and
streaming reads (events.jsonl / history.jsonl).

Key regression under test: naive truncation of a hash-chained journal breaks
verify_chain (the survivors' original chain_hash values point at now-deleted
history). ``_rotate_journal`` re-genesis avoids that by recomputing chain_hash
forward from prev_hash="" over the surviving entries — this suite proves that
holds for both events.jsonl (monitor.record_events) and history.jsonl
(history.record), that the schema stamp survives rotation, that sub-cap files
are left untouched, and that streaming reads work over a large file.
"""
from __future__ import annotations

import json
from pathlib import Path

import clawseccheck.monitor as monitor
from clawseccheck.history import load as history_load
from clawseccheck.history import verify as history_verify
from clawseccheck.monitor import (
    SCHEMA_VERSION,
    _chain_hash,
    _rotate_journal,
    load_events,
    record_events,
    verify_chain,
)

SMALL_MAX = 50
SMALL_KEEP = 40


def _write_raw_chain(path: Path, n: int) -> None:
    """Write n well-formed, correctly-chained events.jsonl-shaped lines directly
    (fast — bypasses per-call locking/rotation overhead of record_events)."""
    prev_hash = ""
    lines = []
    for i in range(n):
        base = {
            "ts": f"2026-01-01T00:{i % 60:02d}:00",
            "level": "INFO",
            "message": f"event-{i}",
            "_schema": SCHEMA_VERSION,
        }
        ch = _chain_hash(prev_hash, base)
        lines.append(json.dumps({**base, "chain_hash": ch}))
        prev_hash = ch
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_raw_history_chain(path: Path, n: int) -> None:
    prev_hash = ""
    lines = []
    for i in range(n):
        base = {
            "date": f"2026-01-{(i % 28) + 1:02d}",
            "score": i,
            "grade": "C",
            "_schema": SCHEMA_VERSION,
        }
        ch = _chain_hash(prev_hash, base)
        lines.append(json.dumps({**base, "chain_hash": ch}))
        prev_hash = ch
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# rotation prunes and re-genesises the chain
# ---------------------------------------------------------------------------

def test_rotation_prunes_and_rechains(tmp_path: Path) -> None:
    journal = tmp_path / "events.jsonl"
    total = SMALL_MAX + 10
    _write_raw_chain(journal, total)

    # Sanity: before rotation, this raw file already verifies OK (it's a real,
    # correctly-chained-from-genesis file) — rotation is what we're testing, not
    # chain construction.
    ok, msg = verify_chain(journal)
    assert ok is True

    _rotate_journal(journal, max_lines=SMALL_MAX, keep=SMALL_KEEP)

    lines = [ln for ln in journal.read_text(encoding="utf-8").splitlines() if ln.strip()]
    # C-250: +1 for the retention-marker entry rotation now prepends (see below) —
    # the survivor COUNT is unchanged, disclosure is additive.
    assert len(lines) == SMALL_KEEP + 1

    # Chain must verify OK post-rotation (the #1 regression: naive truncation
    # would break it since old chain_hash values point at deleted history). The
    # retention marker is itself a fully valid, fully chained entry (see below), so
    # this stays a bare "OK" — nothing about it is unknown-schema or unchained.
    ok, msg = verify_chain(journal)
    assert ok is True, f"chain broken after rotation: {msg}"
    assert msg == "OK"

    entries = [json.loads(ln) for ln in lines]

    # C-250: the retention marker is always the new OLDEST survivor, and discloses
    # exactly how many real entries this rotation evicted.
    marker = entries[0]
    assert marker["retention_pruned"] == total - SMALL_KEEP
    assert f"{total - SMALL_KEEP}" in marker["message"]
    assert "pruned by retention" in marker["message"]

    # Tail preserved: the newest `keep` REAL entries survive, right after the marker.
    kept_messages = [e["message"] for e in entries[1:]]
    expected_tail = [f"event-{i}" for i in range(total - SMALL_KEEP, total)]
    assert kept_messages == expected_tail


def test_rotation_preserves_schema(tmp_path: Path) -> None:
    journal = tmp_path / "events.jsonl"
    _write_raw_chain(journal, SMALL_MAX + 5)

    _rotate_journal(journal, max_lines=SMALL_MAX, keep=SMALL_KEEP)

    lines = [ln for ln in journal.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == SMALL_KEEP + 1  # C-250: +1 for the retention marker

    prev_hash = ""
    for ln in lines:
        entry = json.loads(ln)
        assert entry["_schema"] == SCHEMA_VERSION
        base = {k: v for k, v in entry.items() if k != "chain_hash"}
        expected = _chain_hash(prev_hash, base)
        assert entry["chain_hash"] == expected
        prev_hash = entry["chain_hash"]


def test_history_rotation_rechains(tmp_path: Path) -> None:
    history = tmp_path / "history.jsonl"
    total = SMALL_MAX + 15
    _write_raw_history_chain(history, total)

    _rotate_journal(history, max_lines=SMALL_MAX, keep=SMALL_KEEP)

    lines = [ln for ln in history.read_text(encoding="utf-8").splitlines() if ln.strip()]
    # C-250: the SAME retention marker _rotate_journal writes for events.jsonl is
    # written here too (it is the one function backing both journals) — +1 raw line.
    assert len(lines) == SMALL_KEEP + 1

    ok, msg = history_verify(str(history))
    assert ok is True, f"history chain broken after rotation: {msg}"
    assert msg == "OK"

    rows = history_load(str(history))
    # C-250: history.load()'s own {"date": obj["date"], ...} KeyError guard already
    # skips a row with no 'date'/'score'/'grade' — the marker (ts/level/message
    # only) is silently and harmlessly excluded here, so the trend's own row count
    # is UNCHANGED by this fix; only the raw on-disk line count above gained the +1.
    assert len(rows) == SMALL_KEEP
    # newest entries retained (tail preserved) — scores are the loop index i
    expected_scores = list(range(total - SMALL_KEEP, total))
    assert [r["score"] for r in rows] == expected_scores


# ---------------------------------------------------------------------------
# no-op below cap
# ---------------------------------------------------------------------------

def test_no_rotation_below_cap(tmp_path: Path) -> None:
    journal = tmp_path / "events.jsonl"
    _write_raw_chain(journal, SMALL_MAX - 1)
    before = journal.read_bytes()

    _rotate_journal(journal, max_lines=SMALL_MAX, keep=SMALL_KEEP)

    after = journal.read_bytes()
    assert after == before  # byte-identical — no spurious re-genesis

    ok, msg = verify_chain(journal)
    assert ok is True
    assert msg == "OK"


# ---------------------------------------------------------------------------
# real record_events/record integration: rotation triggers via the public API
# ---------------------------------------------------------------------------
#
# Note: _rotate_journal's max_lines/keep parameters default from the module
# globals *at function-definition time* (a plain Python default-argument
# binding, not a live read), so monkeypatching monitor._JOURNAL_MAX_LINES /
# _JOURNAL_KEEP after import does NOT change what record_events()'s internal
# `_rotate_journal(p)` call uses. To exercise the real cap without waiting for
# 5000 real appends, call _rotate_journal directly with small caps (as done in
# the tests above) — this test instead proves record_events's own call-site
# invokes rotation at all, by writing up to the *real* default cap via the
# fast raw-chain helper and then feeding it through record_events once more.

def test_record_events_triggers_rotation_via_real_default_cap(tmp_path: Path) -> None:
    journal = tmp_path / "events.jsonl"
    # Seed one line under the real cap so the file's chain is genuine, then push
    # it over the threshold with a single real record_events() call, proving
    # the call-site's own (uncustomized) _rotate_journal(p) invocation rotates.
    _write_raw_chain(journal, monitor._JOURNAL_MAX_LINES)
    assert not verify_chain(journal) == (False, "")  # sanity: still well-formed

    record_events([("INFO", "final-alert")], path=journal, when="2026-01-01T00:00:00")

    lines = [ln for ln in journal.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == monitor._JOURNAL_KEEP + 1  # C-250: +1 for the retention marker

    ok, msg = verify_chain(journal)
    assert ok is True, f"chain broken after live rotation: {msg}"

    events = load_events(journal)
    assert events[-1]["message"] == "final-alert"
    # 5001 entries existed the instant rotation triggered (the seeded MAX_LINES + the
    # one new append that pushed it over); keep=4000 survive, so 1001 were pruned.
    assert events[0]["retention_pruned"] == monitor._JOURNAL_MAX_LINES + 1 - monitor._JOURNAL_KEEP


# ---------------------------------------------------------------------------
# streaming reads over a large file
# ---------------------------------------------------------------------------

def test_streaming_load_large_file(tmp_path: Path) -> None:
    journal = tmp_path / "events.jsonl"
    total = SMALL_MAX + 50
    _write_raw_chain(journal, total)

    events = load_events(journal)
    assert len(events) == total
    assert events[0]["message"] == "event-0"
    assert events[-1]["message"] == f"event-{total - 1}"

    # limit= returns the tail
    tail = load_events(journal, limit=10)
    assert len(tail) == 10
    assert tail[-1]["message"] == f"event-{total - 1}"
