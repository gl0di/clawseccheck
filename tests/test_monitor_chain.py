"""Tests for tamper-evident hash-chain on the monitor event journal."""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.monitor import (
    _chain_hash,
    record_events,
    verify_chain,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _write_jsonl(path: Path, entries: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")
    path.chmod(0o600)


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------

def test_chain_genesis(tmp_path: Path) -> None:
    """First entry written by record_events carries a valid chain_hash."""
    journal = tmp_path / "events.jsonl"
    record_events([("HIGH", "first alert")], path=journal, when="2026-01-01T00:00:00")

    entries = [json.loads(ln) for ln in journal.read_text().splitlines() if ln.strip()]
    assert len(entries) == 1
    entry = entries[0]
    assert "chain_hash" in entry

    base = {k: v for k, v in entry.items() if k != "chain_hash"}
    expected = _chain_hash("", base)
    assert entry["chain_hash"] == expected

    ok, msg = verify_chain(journal)
    assert ok is True
    assert msg == "OK"


def test_chain_multi(tmp_path: Path) -> None:
    """Three entries written across two calls form a valid chain."""
    journal = tmp_path / "events.jsonl"
    record_events([("HIGH", "alert-1"), ("MEDIUM", "alert-2")], path=journal, when="2026-01-01T00:00:00")
    record_events([("INFO", "alert-3")], path=journal, when="2026-01-01T00:01:00")

    entries = [json.loads(ln) for ln in journal.read_text().splitlines() if ln.strip()]
    assert len(entries) == 3

    ok, msg = verify_chain(journal)
    assert ok is True
    assert msg == "OK"

    # Manually recompute to be sure
    prev = ""
    for entry in entries:
        base = {k: v for k, v in entry.items() if k != "chain_hash"}
        expected = _chain_hash(prev, base)
        assert entry["chain_hash"] == expected
        prev = entry["chain_hash"]


def test_chain_survives_non_utf8_byte_instead_of_wedging(tmp_path: Path) -> None:
    """C-177: a single non-UTF-8 byte in the journal (a plausible crash-mid-write
    artifact) used to raise UnicodeDecodeError from _iter_jsonl and permanently
    wedge verify_chain()/record_events() on every future call. It must now
    degrade that one garbled line gracefully, same as any other malformed line,
    and let the next record_events() append cleanly."""
    journal = tmp_path / "events.jsonl"
    record_events([("HIGH", "alert-1")], path=journal, when="2026-01-01T00:00:00")
    with open(journal, "ab") as fh:
        fh.write(b"\x00\x01\xff\xfe garbage not json \x00\n")

    ok, msg = verify_chain(journal)
    assert ok, msg

    # A subsequent write must not raise and must produce a well-formed new line.
    record_events([("MEDIUM", "alert-2")], path=journal, when="2026-01-01T00:01:00")
    lines = journal.read_bytes().split(b"\n")
    text_lines = [ln.decode("utf-8", errors="replace") for ln in lines if ln.strip()]
    parsed = 0
    for ln in text_lines:
        try:
            json.loads(ln)
            parsed += 1
        except json.JSONDecodeError:
            pass
    assert parsed == 2, f"expected 2 well-formed JSON lines, parsed {parsed} of {text_lines}"


def test_chain_broken(tmp_path: Path) -> None:
    """Tampering with the middle entry breaks the chain."""
    journal = tmp_path / "events.jsonl"
    record_events(
        [("HIGH", "a"), ("CRITICAL", "b"), ("MEDIUM", "c")],
        path=journal,
        when="2026-01-01T00:00:00",
    )

    entries = [json.loads(ln) for ln in journal.read_text().splitlines() if ln.strip()]
    # Tamper with the middle entry's message
    entries[1]["message"] = "TAMPERED"
    _write_jsonl(journal, entries)

    ok, msg = verify_chain(journal)
    assert ok is False
    assert "broken" in msg


def test_chain_legacy(tmp_path: Path) -> None:
    """Old entries without chain_hash are accepted gracefully (no error).

    C-250: this used to be a bare "OK" — indistinguishable from a fully
    chain-verified file. It now discloses the count of entries that were present
    but NOT actually chain-verified, symmetric with how an unknown-schema entry
    was already disclosed (C-167). Still (True, ...) — legacy entries are still
    accepted gracefully; only the message stopped hiding that fact.
    """
    journal = tmp_path / "events.jsonl"
    legacy = [
        {"ts": "2025-01-01T00:00:00", "level": "HIGH", "message": "old alert 1"},
        {"ts": "2025-01-02T00:00:00", "level": "INFO", "message": "old alert 2"},
    ]
    _write_jsonl(journal, legacy)

    ok, msg = verify_chain(journal)
    assert ok is True
    assert msg == "OK (2 entries not chain-verified (legacy, no chain_hash))"


def test_chain_empty(tmp_path: Path) -> None:
    """Empty file verifies as OK."""
    journal = tmp_path / "events.jsonl"
    journal.write_text("", encoding="utf-8")
    journal.chmod(0o600)

    ok, msg = verify_chain(journal)
    assert ok is True
    assert msg == "OK"


def test_chain_absent_file(tmp_path: Path) -> None:
    """Missing file verifies as OK (no journal yet)."""
    journal = tmp_path / "no_such_file.jsonl"
    ok, msg = verify_chain(journal)
    assert ok is True
    assert msg == "OK"


def test_chain_legacy_then_new(tmp_path: Path) -> None:
    """Legacy entries followed by new chained entries are verified correctly.

    C-250: the one legacy entry is disclosed by count, same as test_chain_legacy —
    a MIXED journal names how many of its entries are unverified, not "the whole
    file is legacy" (SECURITY_MODEL.md's per-entry reconciliation).
    """
    journal = tmp_path / "events.jsonl"
    # Write two legacy entries directly
    legacy = [
        {"ts": "2025-06-01T00:00:00", "level": "INFO", "message": "before chain"},
    ]
    _write_jsonl(journal, legacy)

    # Now append via record_events — chain genesis starts from "" (no prior chain_hash)
    record_events([("HIGH", "after chain")], path=journal, when="2026-06-01T00:00:00")

    ok, msg = verify_chain(journal)
    assert ok is True
    assert msg == "OK (1 entry not chain-verified (legacy, no chain_hash))"
