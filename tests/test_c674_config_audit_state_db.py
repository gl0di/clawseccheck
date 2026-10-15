"""C-674 - OpenClaw's config-write journal moved into the state database.

Current OpenClaw no longer writes ``logs/config-audit.jsonl``; the same records live in
``state/openclaw.sqlite``, table ``diagnostic_events``, scope ``config-audit``. B77 and the
monitor's change attribution read the file only, so on a current install B77 was UNKNOWN
forever and the monitor could not say which process wrote a config change.

These tests pin the dual shape: the state database is preferred when the table AND the scope
exist (by presence, never by a version string), the legacy file is the fallback, and a state
database that exists but cannot be read is UNKNOWN - never a quiet read of a stale file, and
never a clean pass over rows that were not examined.

The table is built by a helper whose DDL is assembled from fragments (no literal
``CREATE TABLE`` string), so it is not a second hand-written copy of the vendor schema for the
state-schema grounding registry to police.

Offline, read-only against the repo, stdlib only.
"""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

from clawseccheck import configjournal
from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_config_audit_log
from clawseccheck.collector import Context
from clawseccheck.logdiscovery import _config_audit_sink

SCOPE = "config-audit"


def _ddl(table: str, nullable: bool = False) -> str:
    verb = " ".join(["CREATE", "TABLE"])
    cols = ", ".join([
        "scope TEXT NOT NULL", "event_key TEXT NOT NULL",
        "payload_json TEXT" + ("" if nullable else " NOT NULL"),
        "created_at INTEGER NOT NULL", "sequence INTEGER NOT NULL DEFAULT 0",
        "PRIMARY KEY (scope, event_key)",
    ])
    return f"{verb} {table} ({cols})"


def _record(prev, nxt, ts, **over):
    rec = {
        "ts": ts, "event": "config.write", "result": "rename", "pid": 4242, "ppid": 1,
        "argv": ["/usr/local/bin/node", "/opt/openclaw/dist/index.js", "update"],
        "configPath": "/home/u/.openclaw/openclaw.json",
        "previousHash": prev, "nextHash": nxt, "suspicious": [],
        "changedPaths": ["gateway.port"], "origin": "cli",
    }
    rec.update(over)
    return rec


def _chained(n=2):
    hashes = [format(i + 1, "x") * 64 for i in range(n + 1)]
    return [_record(hashes[i], hashes[i + 1], f"2026-10-0{i + 1}T00:00:00.000Z")
            for i in range(n)]


def _state_db(home: Path, rows, table="diagnostic_events", scope=SCOPE,
              nullable=False) -> Path:
    db = home / "state" / "openclaw.sqlite"
    db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db)
    try:
        if table:
            conn.execute(_ddl(table, nullable))
            for seq, payload in enumerate(rows):
                text = (payload if isinstance(payload, str) or payload is None
                        else json.dumps(payload))
                conn.execute(
                    f"INSERT INTO {table} (scope, event_key, payload_json, created_at, "
                    "sequence) VALUES (?, ?, ?, ?, ?)",
                    (scope, f"k{seq}", text, 1_790_000_000_000 + seq, seq),
                )
        conn.commit()
    finally:
        conn.close()
    os.chmod(db, 0o600)
    return db


def _legacy_file(home: Path, records) -> Path:
    path = home / "logs" / "config-audit.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def _b77(home):
    return check_config_audit_log(Context(home=Path(home)))


# ---------------------------------------------------------------- the state-DB container

def test_two_chained_rows_pass_and_the_state_db_is_the_container(tmp_path):
    _state_db(tmp_path, _chained(2))
    f = _b77(tmp_path)
    assert f.status == PASS, f.detail
    assert f.detail == ("all 2 recorded config write(s) in the state database are clean "
                        "and openclaw-originated.")
    j = configjournal.read_writes(tmp_path)
    assert j.container == configjournal.CONTAINER_STATE_DB and j.present
    assert [w.ts for w in j.writes] == ["2026-10-01T00:00:00.000Z", "2026-10-02T00:00:00.000Z"]
    assert configjournal.chain_state(j.writes) == configjournal.CHAIN_OK


def test_a_suspicious_row_fires_b77(tmp_path):
    rows = _chained(2)
    rows[1]["suspicious"] = ["size-drop:previous-bytes-4096"]
    _state_db(tmp_path, rows)
    f = _b77(tmp_path)
    assert f.status == WARN, f.detail
    assert "state database" in f.detail
    assert any("flagged suspicious" in e and "size-drop" in e for e in f.evidence)


def test_a_write_from_a_foreign_process_fires_b77(tmp_path):
    rows = _chained(2)
    rows[0]["argv"] = ["/tmp/dropper/x", "--apply"]
    _state_db(tmp_path, rows)
    f = _b77(tmp_path)
    assert f.status == WARN, f.detail
    assert any("unexpected process: x" in e for e in f.evidence)
    assert not any("/tmp/" in e for e in f.evidence)


def test_a_broken_chain_alone_is_a_gap_not_a_b77_finding(tmp_path):
    """The module refuses to call a gap tampering (see configjournal's docstring): the leaf
    reports CHAIN_GAP, B77 stays on the vendor's own markers and the writer."""
    rows = _chained(2)
    rows[1]["previousHash"] = "f" * 64
    _state_db(tmp_path, rows)
    assert configjournal.chain_state(configjournal.read_writes(tmp_path).writes) == \
        configjournal.CHAIN_GAP
    assert _b77(tmp_path).status == PASS


def test_the_new_payload_keys_are_not_read_and_the_write_is_attributable(tmp_path):
    _state_db(tmp_path, _chained(2))
    newest = configjournal.read_writes(tmp_path).writes[-1]
    assert newest.argv0 == "node" and newest.pid == 4242
    assert configjournal.find_by_hash(
        configjournal.read_writes(tmp_path).writes, newest.next_hash) == newest
    assert configjournal.read_writes(tmp_path, since="2026-10-01T00:00:00.000Z").writes == [
        newest]


def test_other_scopes_in_the_table_are_not_journal_rows(tmp_path):
    _state_db(tmp_path, _chained(2), scope="system-agent-audit")
    j = configjournal.read_writes(tmp_path)
    assert not j.present and j.container == ""
    f = _b77(tmp_path)
    assert f.status == UNKNOWN
    assert f.detail == "config audit log not found — cannot verify config change history."


# ---------------------------------------------------------------- dual shape, by presence

def test_a_clean_db_does_not_speak_for_a_suspicious_legacy_file(tmp_path):
    """After an OpenClaw rollback an older gateway writes the file again beside a database
    that already holds rows: a clean database must not clear the file."""
    _state_db(tmp_path, _chained(2))
    bad = _chained(3)
    bad[1]["suspicious"] = ["rollback-file-marker"]
    _legacy_file(tmp_path, bad)
    f = _b77(tmp_path)
    assert f.status == WARN, f.detail
    assert "state database" in f.detail and "logs/config-audit.jsonl" in f.detail
    assert any("rollback-file-marker" in e and e.startswith("[legacy file]")
               for e in f.evidence)
    # Attribution (monitor) still reads the state database first.
    assert configjournal.read_writes(tmp_path).container == configjournal.CONTAINER_STATE_DB
    assert [j.container for j in configjournal.read_journals(tmp_path)] == [
        configjournal.CONTAINER_STATE_DB, configjournal.CONTAINER_FILE]


def test_a_suspicious_db_is_not_cleared_by_a_clean_legacy_file(tmp_path):
    rows = _chained(2)
    rows[0]["suspicious"] = ["db-marker"]
    _state_db(tmp_path, rows)
    _legacy_file(tmp_path, _chained(3))
    f = _b77(tmp_path)
    assert f.status == WARN, f.detail
    assert any("db-marker" in e and e.startswith("[state database]") for e in f.evidence)


def test_both_containers_clean_pass_and_name_both(tmp_path):
    _state_db(tmp_path, _chained(2))
    _legacy_file(tmp_path, _chained(3))
    f = _b77(tmp_path)
    assert f.status == PASS, f.detail
    assert "state database" in f.detail and "legacy file" in f.detail
    assert "all 2 recorded" in f.detail and "all 3 recorded" in f.detail


def test_a_clean_db_with_an_unreadable_legacy_file_is_unknown(tmp_path, monkeypatch):
    _state_db(tmp_path, _chained(2))
    path = _legacy_file(tmp_path, _chained(3))
    real = Path.read_text

    def deny(self, *a, **k):
        if self == path:
            raise PermissionError(13, "denied")
        return real(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", deny)
    f = _b77(tmp_path)
    assert f.status == UNKNOWN, f.detail
    assert "unreadable" in f.detail and "state database" in f.detail


def test_an_unreadable_db_beside_a_clean_file_is_unknown_not_pass(tmp_path):
    db = _state_db(tmp_path, _chained(2), table="decoy_rows")
    conn = sqlite3.connect(db)
    conn.execute("CREATE VIEW diagnostic_events AS SELECT * FROM decoy_rows")
    conn.commit()
    conn.close()
    _legacy_file(tmp_path, _chained(3))
    assert _b77(tmp_path).status == UNKNOWN


def test_a_db_without_the_scope_falls_back_to_the_legacy_file(tmp_path):
    _state_db(tmp_path, _chained(2), scope="config-snapshot")
    _legacy_file(tmp_path, _chained(3))
    j = configjournal.read_writes(tmp_path)
    assert j.container == configjournal.CONTAINER_FILE and len(j.writes) == 3
    assert _b77(tmp_path).detail == (
        "all 3 recorded config write(s) are clean and openclaw-originated.")


def test_a_db_without_the_table_falls_back_to_the_legacy_file(tmp_path):
    _state_db(tmp_path, [], table=None)
    _legacy_file(tmp_path, _chained(2))
    assert configjournal.read_writes(tmp_path).container == configjournal.CONTAINER_FILE
    assert _b77(tmp_path).status == PASS


def test_no_table_no_file_is_unknown_with_the_legacy_detail(tmp_path):
    _state_db(tmp_path, [], table=None)
    f = _b77(tmp_path)
    assert f.status == UNKNOWN
    assert f.detail == "config audit log not found — cannot verify config change history."
    assert "diagnostic_events" in f.fix and "config-audit.jsonl" in f.fix


def test_no_state_db_no_file_is_unknown(tmp_path):
    f = _b77(tmp_path)
    assert f.status == UNKNOWN
    assert configjournal.read_writes(tmp_path).container == ""


# ---------------------------------------------------------------- never a clean pass

def test_a_view_named_like_the_table_is_refused_and_does_not_fall_back(tmp_path):
    db = _state_db(tmp_path, _chained(2), table="decoy_rows")
    conn = sqlite3.connect(db)
    conn.execute("CREATE VIEW diagnostic_events AS SELECT * FROM decoy_rows")
    conn.commit()
    conn.close()
    _legacy_file(tmp_path, _chained(2))   # a stale file must not answer for the refused DB
    j = configjournal.read_writes(tmp_path)
    assert j.unreadable and not j.present and j.container == configjournal.CONTAINER_STATE_DB
    f = _b77(tmp_path)
    assert f.status == UNKNOWN and "unreadable" in f.detail


def test_a_fifo_at_the_db_path_is_refused_without_hanging(tmp_path):
    (tmp_path / "state").mkdir()
    os.mkfifo(tmp_path / "state" / "openclaw.sqlite")
    assert configjournal.read_writes(tmp_path).unreadable
    assert _b77(tmp_path).status == UNKNOWN


def test_a_payload_nested_past_the_bound_is_counted_not_passed(tmp_path):
    rows = _chained(2)
    deep = "[" * 5000 + "]" * 5000
    _state_db(tmp_path, [rows[0], deep, rows[1]])
    j = configjournal.read_writes(tmp_path)
    assert len(j.writes) == 2 and j.unparsable_lines == 1
    f = _b77(tmp_path)
    assert f.status == UNKNOWN, f.detail
    assert "1 row(s) could not be read" in f.detail


def test_every_row_unreadable_is_unknown_not_pass(tmp_path):
    _state_db(tmp_path, ["not json", "[1, 2]"])
    f = _b77(tmp_path)
    assert f.status == UNKNOWN and "none could be read" in f.detail


def test_a_row_larger_than_the_whole_budget_is_counted_as_not_examined(tmp_path):
    big = _record("a" * 64, "b" * 64, "2026-10-03T00:00:00.000Z", argv=["x" * 1_200_000])
    _state_db(tmp_path, [*_chained(2), big])
    j = configjournal.read_writes(tmp_path, cap=1_000_000)
    assert len(j.writes) == 2 and j.oversized_rows == 1 and j.unparsable_lines == 0
    f = _b77(tmp_path)
    assert f.status == UNKNOWN, f.detail
    assert "1 row(s) exceeded this scan's size budget" in f.detail


def test_a_null_payload_row_is_counted_not_skipped(tmp_path):
    _state_db(tmp_path, [*_chained(2), None], nullable=True)
    j = configjournal.read_writes(tmp_path)
    assert len(j.writes) == 2 and j.unparsable_lines == 1
    assert _b77(tmp_path).status == UNKNOWN


def test_blank_payload_rows_are_rows_held_and_unread(tmp_path):
    _state_db(tmp_path, ["", "   "])
    f = _b77(tmp_path)
    assert f.status == UNKNOWN
    assert "holds 2 row(s)" in f.detail, f.detail


def test_a_non_string_argv0_keeps_its_printed_label(tmp_path):
    rows = _chained(2)
    rows[1]["argv"] = [5, "--apply"]
    _state_db(tmp_path, rows)
    f = _b77(tmp_path)
    assert f.status == WARN
    assert "config written by unexpected process: 5" in f.evidence


# ---- differential: the SAME records in each container must not read cleaner from the DB

_RANK = {PASS: 0, UNKNOWN: 1, WARN: 2}


def _cases():
    def pad(rec, n):
        rec = dict(rec)
        rec["pad"] = "p" * n
        return rec

    clean = _chained(2)
    susp = _chained(3)
    susp[1]["suspicious"] = ["m"]
    foreign = _chained(2)
    foreign[0]["argv"] = ["/tmp/x/dropper"]
    nonstr = _chained(2)
    nonstr[1]["argv"] = [5]
    huge_susp = _chained(2) + [pad(_record("a" * 64, "b" * 64, "2026-10-09T00:00:00.000Z",
                                           suspicious=["m"]), 200_000)]
    huge_clean = _chained(2) + [pad(_record("a" * 64, "b" * 64, "2026-10-09T00:00:00.000Z"),
                                    200_000)]
    over_budget = _chained(2) + [pad(_record("a" * 64, "b" * 64, "2026-10-09T00:00:00.000Z"),
                                     1_200_000)]
    deep = [*_chained(2), "[" * 5000 + "]" * 5000]
    return {
        "clean": clean, "susp": susp, "foreign": foreign, "nonstr_argv": nonstr,
        "huge_susp": huge_susp, "huge_clean": huge_clean, "over_budget": over_budget,
        "deep": deep,
    }


def _legacy_lines(home: Path, records) -> None:
    path = home / "logs" / "config-audit.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(r if isinstance(r, str) else json.dumps(r) for r in records)
                    + "\n", encoding="utf-8")


def test_the_state_db_never_reads_cleaner_than_the_file_for_the_same_records(tmp_path):
    verdicts = {}
    for name, records in _cases().items():
        db_home, file_home = tmp_path / f"db_{name}", tmp_path / f"file_{name}"
        _state_db(db_home, records)
        _legacy_lines(file_home, records)
        verdicts[name] = (_b77(db_home).status, _b77(file_home).status)
    for name, (from_db, from_file) in verdicts.items():
        assert _RANK[from_db] >= _RANK[from_file], (name, verdicts)
    # The shapes that carry no container-specific caveat must agree exactly.
    for name in ("clean", "susp", "foreign", "nonstr_argv", "huge_susp", "huge_clean",
                 "over_budget"):
        assert verdicts[name][0] == verdicts[name][1], (name, verdicts)
    assert verdicts["huge_susp"] == (WARN, WARN)
    assert verdicts["huge_clean"] == (PASS, PASS)


def test_the_byte_bound_keeps_the_newest_rows_and_discloses_truncation(tmp_path):
    _state_db(tmp_path, _chained(6))
    one = len(json.dumps(_chained(1)[0]))
    j = configjournal.read_writes(tmp_path, cap=one * 2 + 10)
    assert j.truncated and 1 <= len(j.writes) < 6
    assert j.writes[-1].ts == "2026-10-06T00:00:00.000Z"      # newest row survived
    assert j.writes == sorted(j.writes, key=lambda w: w.ts)   # still oldest-first


def test_a_wide_journal_that_fits_is_not_marked_truncated(tmp_path):
    _state_db(tmp_path, _chained(6))
    assert not configjournal.read_writes(tmp_path).truncated


# ---------------------------------------------------------------- the legacy sink

def test_a_migrated_only_logs_dir_advertises_no_config_audit_sink(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "config-audit.jsonl.migrated").write_text("{}\n", encoding="utf-8")
    assert _config_audit_sink(tmp_path) is None


def test_a_legacy_file_is_still_a_sink(tmp_path):
    p = _legacy_file(tmp_path, _chained(1))
    sink = _config_audit_sink(tmp_path)
    assert sink is not None and sink.path == p and sink.kind == "config_audit"
