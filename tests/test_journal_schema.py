"""Tests for C-162 — the '_schema' stamp on hash-chained journal entries.

Covers history.jsonl (history.record/load), events.jsonl (monitor.record_events/
load_events), and coverage.json (ledger.record_run/load_ledger).

Key design points under test:
  - '_schema' is stamped INSIDE the hashed payload (base), so verify_chain
    authenticates it — a planted/edited _schema value breaks the chain, exactly
    like any other tampered field.
  - Loaders skip a line whose _schema is a newer major than this build
    understands (no crash, no misparse); legacy lines without _schema still load;
    lines stamped with the current SCHEMA_VERSION load normally.
  - ledger.json's reserved "_schema" key round-trips (load_ledger filters it out;
    an old-format file without it still loads unchanged).
"""
from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from types import SimpleNamespace

from clawseccheck.history import SCHEMA_VERSION as HISTORY_SCHEMA_VERSION
from clawseccheck.history import load as history_load
from clawseccheck.history import record as history_record
from clawseccheck.history import verify as history_verify
from clawseccheck.ledger import load_ledger, record_run
from clawseccheck.monitor import SCHEMA_VERSION, _chain_hash, load_events, record_events, verify_chain


def _score(score: int = 72, grade: str = "C") -> SimpleNamespace:
    return SimpleNamespace(score=score, grade=grade)


# ---------------------------------------------------------------------------
# history.jsonl
# ---------------------------------------------------------------------------

def test_history_schema_reexported_matches_monitor():
    assert HISTORY_SCHEMA_VERSION == SCHEMA_VERSION


def test_history_record_stamps_schema_inside_hashed_base(tmp_path):
    path = str(tmp_path / "history.jsonl")
    history_record(_score(), path=path, when="2026-07-01")
    line = json.loads(Path(path).read_text(encoding="utf-8").splitlines()[0])
    assert line["_schema"] == SCHEMA_VERSION

    # _schema is part of the hashed base, not appended after — recomputing the
    # chain_hash over everything except chain_hash must match.
    base = {k: v for k, v in line.items() if k != "chain_hash"}
    assert line["chain_hash"] == _chain_hash("", base)

    ok, msg = history_verify(path)
    assert ok is True
    assert msg == "OK"


def test_history_tampered_schema_breaks_chain(tmp_path):
    """Flipping _schema in a stored line proves it's part of the authenticated
    payload — verify_chain must detect it, same as tampering any other field."""
    path = tmp_path / "history.jsonl"
    history_record(_score(72, "C"), path=str(path), when="2026-07-01")
    history_record(_score(81, "B"), path=str(path), when="2026-07-02")

    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["_schema"] = 999
    lines[0] = json.dumps(tampered)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, msg = history_verify(str(path))
    assert ok is False
    assert "broken" in msg


def test_history_load_skips_unknown_future_schema_but_loads_siblings(tmp_path):
    path = tmp_path / "history.jsonl"
    good1 = {"date": "2026-07-01", "score": 70, "grade": "C", "_schema": SCHEMA_VERSION}
    future = {"date": "2026-07-02", "score": 999, "grade": "Z", "_schema": SCHEMA_VERSION + 998}
    good2 = {"date": "2026-07-03", "score": 80, "grade": "B", "_schema": SCHEMA_VERSION}
    path.write_text(
        "\n".join(json.dumps(e) for e in (good1, future, good2)) + "\n",
        encoding="utf-8",
    )
    rows = history_load(str(path))
    assert len(rows) == 2
    assert rows[0]["date"] == "2026-07-01"
    assert rows[1]["date"] == "2026-07-03"


def test_history_load_legacy_line_without_schema_still_loads(tmp_path):
    path = tmp_path / "history.jsonl"
    legacy = {"date": "2025-01-01", "score": 60, "grade": "D"}
    path.write_text(json.dumps(legacy) + "\n", encoding="utf-8")
    rows = history_load(str(path))
    assert len(rows) == 1
    assert rows[0]["date"] == "2025-01-01"


# ---------------------------------------------------------------------------
# events.jsonl
# ---------------------------------------------------------------------------

def test_events_record_stamps_schema_inside_hashed_base(tmp_path):
    path = tmp_path / "events.jsonl"
    record_events([("HIGH", "alert one")], path=path, when="2026-07-01T00:00:00")
    entry = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert entry["_schema"] == SCHEMA_VERSION

    base = {k: v for k, v in entry.items() if k != "chain_hash"}
    assert entry["chain_hash"] == _chain_hash("", base)

    ok, msg = verify_chain(path)
    assert ok is True
    assert msg == "OK"


def test_events_tampered_schema_breaks_chain(tmp_path):
    path = tmp_path / "events.jsonl"
    record_events(
        [("HIGH", "a"), ("MEDIUM", "b")], path=path, when="2026-07-01T00:00:00",
    )
    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["_schema"] = 999
    lines[0] = json.dumps(tampered)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, msg = verify_chain(path)
    assert ok is False
    assert "broken" in msg


def test_events_load_skips_unknown_future_schema_but_loads_siblings(tmp_path):
    path = tmp_path / "events.jsonl"
    good1 = {"ts": "2026-07-01T00:00:00", "level": "HIGH", "message": "a",
             "_schema": SCHEMA_VERSION}
    future = {"ts": "2026-07-02T00:00:00", "level": "HIGH", "message": "b",
              "_schema": SCHEMA_VERSION + 998}
    good2 = {"ts": "2026-07-03T00:00:00", "level": "INFO", "message": "c",
             "_schema": SCHEMA_VERSION}
    path.write_text(
        "\n".join(json.dumps(e) for e in (good1, future, good2)) + "\n",
        encoding="utf-8",
    )
    events = load_events(path)
    assert len(events) == 2
    assert events[0]["message"] == "a"
    assert events[1]["message"] == "c"


def test_events_load_legacy_line_without_schema_still_loads(tmp_path):
    path = tmp_path / "events.jsonl"
    legacy = {"ts": "2025-01-01T00:00:00", "level": "INFO", "message": "old alert"}
    path.write_text(json.dumps(legacy) + "\n", encoding="utf-8")
    events = load_events(path)
    assert len(events) == 1
    assert events[0]["message"] == "old alert"


def test_events_untampered_future_schema_still_verifies_ok(tmp_path):
    """verify_chain authenticates the whole file, including unknown-_schema lines;
    only load_events applies the skip-unknown-schema policy on top. C-167: the OK
    message now surfaces the count of such hidden-but-present lines."""
    path = tmp_path / "events.jsonl"
    record_events([("HIGH", "a")], path=path, when="2026-07-01T00:00:00")
    lines = path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    # Bump _schema and recompute its own chain_hash honestly (not "tampered" —
    # simulates a genuinely newer client writing a future-schema entry correctly).
    entry["_schema"] = SCHEMA_VERSION + 5
    base = {k: v for k, v in entry.items() if k != "chain_hash"}
    entry["chain_hash"] = _chain_hash("", base)
    path.write_text(json.dumps(entry) + "\n", encoding="utf-8")

    ok, msg = verify_chain(path)
    assert ok is True
    # C-167: still OK (the line is authenticated), but the count is surfaced so an
    # operator diffing on-disk line-count vs loaded-row-count sees the hidden row.
    assert msg == "OK (1 unknown-schema entry present)"
    # But load_events (the consumer) still refuses to misparse the unknown line.
    assert load_events(path) == []


def test_events_verify_surfaces_plural_unknown_schema_count(tmp_path):
    """C-167: with N>1 hidden-but-present lines the count pluralizes and equals the
    on-disk-lines minus loaded-rows gap — the whole point of surfacing it."""
    path = tmp_path / "events.jsonl"
    # One loadable + two honestly-chained future-schema lines.
    specs = [SCHEMA_VERSION, SCHEMA_VERSION + 5, SCHEMA_VERSION + 9]
    prev, lines = "", []
    for i, sch in enumerate(specs):
        base = {"ts": f"2026-07-0{i + 1}T00:00:00", "level": "INFO",
                "message": chr(97 + i), "_schema": sch}
        ch = _chain_hash(prev, base)
        lines.append(json.dumps({**base, "chain_hash": ch}))
        prev = ch
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, msg = verify_chain(path)
    assert ok is True
    assert msg == "OK (2 unknown-schema entries present)"
    # The surfaced count == on-disk lines (3) − loaded rows (1).
    assert len(load_events(path)) == 1


# ---------------------------------------------------------------------------
# coverage.json ledger
# ---------------------------------------------------------------------------

def test_ledger_schema_round_trip_filtered_from_view(tmp_path):
    record_run("self_test", home=str(tmp_path), today=date(2026, 7, 1))
    raw = json.loads((tmp_path / ".clawseccheck" / "coverage.json").read_text(encoding="utf-8"))
    assert "_schema" in raw

    ledger = load_ledger(str(tmp_path))
    assert "_schema" not in ledger
    assert ledger["self_test"] == "2026-07-01"


def test_ledger_old_format_file_without_schema_loads_unchanged(tmp_path):
    p = tmp_path / ".clawseccheck" / "coverage.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"self_test": "2026-06-01", "vet_mcp": "2026-06-10"}),
                 encoding="utf-8")
    ledger = load_ledger(str(tmp_path))
    assert ledger == {"self_test": "2026-06-01", "vet_mcp": "2026-06-10"}
