"""F-170 — reading OpenClaw's own config-write journal, a witness we did not author.

A snapshot diff cannot see a change that was made and put back between two runs, and it
cannot say who made one. ``~/.openclaw/logs/config-audit.jsonl`` records both.

The load-bearing property, verified against a live install before any of this was written:
the newest record's ``nextHash`` equals ``sha256(openclaw.json)`` exactly. That is what lets
a journaled write be matched to the config the audit actually read.

The property this file spends most of its effort on is the opposite one — what the module
must REFUSE to conclude. On a healthy real machine 2 of 42 chain links were already broken,
both benignly: one config edit made outside OpenClaw's own writer (which leaves no record,
so the next record's ``previousHash`` refers to bytes no journaled write produced), and two
writes sharing a ``previousHash`` (racing from a common base, or a revert then re-apply).
Log rotation gives the same shape. A tool that called any of those tampering would be wrong
on its own maintainer's machine on day one.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from clawseccheck.configjournal import (
    CHAIN_GAP,
    CHAIN_OK,
    CHAIN_UNKNOWN,
    ConfigWrite,
    chain_state,
    find_by_hash,
    journal_path,
    newest_hash,
    read_writes,
)


def _write_journal(home: Path, records) -> Path:
    path = home / "logs" / "config-audit.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def _record(prev="a" * 64, nxt="b" * 64, ts="2026-08-01T00:00:00.000Z", **over):
    rec = {
        "ts": ts, "event": "config.write", "result": "rename",
        "pid": 4242, "ppid": 1, "argv": ["/usr/local/bin/node", "/opt/openclaw/cli.js"],
        "cwd": "/home/someone/secret-project",
        "previousHash": prev, "nextHash": nxt,
        "previousBytes": 10, "nextBytes": 12,
        "changedPathCount": None, "suspicious": [],
    }
    rec.update(over)
    return rec


# ---------------------------------------------------------------- reading

def test_an_absent_journal_is_reported_as_absent_not_as_empty(tmp_path):
    """"There is no journal" and "the journal recorded nothing" are different facts, and
    a monitor that merges them reports silence as safety."""
    j = read_writes(tmp_path)
    assert j.present is False and j.writes == []


def test_records_are_read_oldest_first(tmp_path):
    _write_journal(tmp_path, [_record(ts="2026-01-01T00:00:00.000Z", nxt="1" * 64),
                              _record(ts="2026-02-01T00:00:00.000Z", prev="1" * 64,
                                      nxt="2" * 64)])
    writes = read_writes(tmp_path).writes
    assert [w.ts for w in writes] == ["2026-01-01T00:00:00.000Z", "2026-02-01T00:00:00.000Z"]


def test_junk_lines_are_counted_rather_than_fatal(tmp_path):
    path = _write_journal(tmp_path, [_record()])
    path.write_text(path.read_text() + "not json at all\n[]\n", encoding="utf-8")
    j = read_writes(tmp_path)
    assert len(j.writes) == 1
    assert j.unparsable_lines == 2, "a non-dict JSON value counts as junk too"


def test_a_huge_journal_is_tailed_and_says_so(tmp_path):
    _write_journal(tmp_path, [_record(ts=f"2026-01-{d:02d}T00:00:00.000Z")
                              for d in range(1, 29)])
    j = read_writes(tmp_path, cap=600)
    assert j.truncated is True
    assert j.writes, "the tail must still yield records"


def test_since_drops_records_at_or_before_the_cursor(tmp_path):
    _write_journal(tmp_path, [_record(ts="2026-01-01T00:00:00.000Z"),
                              _record(ts="2026-03-01T00:00:00.000Z")])
    writes = read_writes(tmp_path, since="2026-02-01T00:00:00.000Z").writes
    assert [w.ts for w in writes] == ["2026-03-01T00:00:00.000Z"]


def test_an_unreadable_journal_never_raises(tmp_path):
    path = _write_journal(tmp_path, [_record()])
    os.chmod(path, 0o000)
    try:
        j = read_writes(tmp_path)
    finally:
        os.chmod(path, 0o600)
    assert j.writes == []


# ---------------------------------------------------------------- what must not leak

def test_only_the_argv_basename_survives_and_no_path_or_cwd_does(tmp_path):
    """The journal carries absolute paths and the user's working directory. Neither is
    kept — not kept-and-carefully-avoided-later, not kept at all — because a field that
    exists is a field some future renderer will print."""
    _write_journal(tmp_path, [_record()])
    write = read_writes(tmp_path).writes[0]
    assert write.argv0 == "node"
    blob = json.dumps(write.__dict__)
    assert "/usr/local/bin" not in blob
    assert "secret-project" not in blob
    assert "cwd" not in blob


def test_a_secret_shaped_argv_is_redacted(tmp_path):
    # Assembled at runtime so no contiguous secret-shaped literal exists in this file.
    token = "sk-" + "b" * 40
    _write_journal(tmp_path, [_record(argv=[f"/tmp/{token}", "x"])])
    assert token not in read_writes(tmp_path).writes[0].argv0


def test_a_non_list_argv_is_survivable(tmp_path):
    for bad in (None, "node", 42, []):
        _write_journal(tmp_path, [_record(argv=bad)])
        assert read_writes(tmp_path).writes[0].argv0 == ""


# ---------------------------------------------------------------- the chain

def test_an_intact_chain_reads_as_intact(tmp_path):
    _write_journal(tmp_path, [_record(prev="0" * 64, nxt="1" * 64),
                              _record(prev="1" * 64, nxt="2" * 64),
                              _record(prev="2" * 64, nxt="3" * 64)])
    assert chain_state(read_writes(tmp_path).writes) == CHAIN_OK


def test_a_hand_edit_outside_openclaw_reads_as_a_gap_not_as_tampering(tmp_path):
    """The first of the two gaps observed on a real machine: an edit OpenClaw's own writer
    never made leaves no record, so the next record's previousHash refers to bytes no
    journaled write produced."""
    _write_journal(tmp_path, [_record(prev="0" * 64, nxt="1" * 64),
                              _record(prev="9" * 64, nxt="2" * 64)])
    assert chain_state(read_writes(tmp_path).writes) == CHAIN_GAP


def test_two_writes_from_one_base_read_as_a_gap(tmp_path):
    """The second real gap: both records share a previousHash — a race from a common base,
    or a revert then re-apply. Benign, and indistinguishable from the first from here."""
    _write_journal(tmp_path, [_record(prev="0" * 64, nxt="1" * 64),
                              _record(prev="0" * 64, nxt="2" * 64)])
    assert chain_state(read_writes(tmp_path).writes) == CHAIN_GAP


def test_too_little_evidence_is_unknown_rather_than_ok(tmp_path):
    """One record cannot demonstrate a chain. Reporting OK there would be the exact
    clean-verdict-about-an-unexamined-thing this project keeps having to remove."""
    _write_journal(tmp_path, [_record()])
    assert chain_state(read_writes(tmp_path).writes) == CHAIN_UNKNOWN
    assert chain_state([]) == CHAIN_UNKNOWN


def test_records_missing_hashes_do_not_manufacture_a_gap(tmp_path):
    """A record with no hashes is not evidence of a break — it is no evidence at all."""
    _write_journal(tmp_path, [_record(prev="0" * 64, nxt="1" * 64),
                              _record(previousHash=None, nextHash=None),
                              _record(prev="1" * 64, nxt="2" * 64)])
    assert chain_state(read_writes(tmp_path).writes) == CHAIN_OK


# ---------------------------------------------------------------- attribution

def test_a_digest_is_matched_to_the_write_that_produced_it(tmp_path):
    _write_journal(tmp_path, [_record(nxt="1" * 64, ts="2026-01-01T00:00:00.000Z"),
                              _record(prev="1" * 64, nxt="2" * 64, pid=777,
                                      ts="2026-02-01T00:00:00.000Z")])
    writes = read_writes(tmp_path).writes
    assert newest_hash(writes) == "2" * 64
    hit = find_by_hash(writes, "2" * 64)
    assert hit is not None and hit.pid == 777


def test_an_unjournalled_digest_matches_nothing(tmp_path):
    """The signal Phase 2 exists for: the live config was produced by a write this journal
    never recorded."""
    _write_journal(tmp_path, [_record(nxt="1" * 64)])
    assert find_by_hash(read_writes(tmp_path).writes, "f" * 64) is None
    assert find_by_hash(read_writes(tmp_path).writes, "") is None


# ---------------------------------------------------------------- the measured caveats

def test_an_absent_changed_path_count_stays_none(tmp_path):
    """It was None on all 43 records of a real install. Coercing it to 0 would turn "we
    were not told" into the claim "nothing changed"."""
    _write_journal(tmp_path, [_record(changedPathCount=None)])
    assert read_writes(tmp_path).writes[0].changed_path_count is None
    _write_journal(tmp_path, [_record(changedPathCount=3)])
    assert read_writes(tmp_path).writes[0].changed_path_count == 3


def test_suspicious_is_carried_but_empty_by_default(tmp_path):
    """Present but empty on all 43 real records — a clean baseline, and simultaneously zero
    evidence it ever fires, so nothing high-severity may rest on it alone."""
    _write_journal(tmp_path, [_record()])
    assert read_writes(tmp_path).writes[0].suspicious == ()
    _write_journal(tmp_path, [_record(suspicious=["weird"])])
    assert read_writes(tmp_path).writes[0].suspicious == ("weird",)


def test_journal_path_is_derived_not_guessed(tmp_path):
    assert journal_path(tmp_path).name == "config-audit.jsonl"
    assert journal_path(tmp_path).parent.name == "logs"


def test_the_dataclass_defaults_are_inert():
    """A default-constructed record must assert nothing — no hash, no attribution."""
    w = ConfigWrite()
    assert w.previous_hash == "" and w.next_hash == "" and w.argv0 == ""
    assert w.changed_path_count is None and w.suspicious == ()
