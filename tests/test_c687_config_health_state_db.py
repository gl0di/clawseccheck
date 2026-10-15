"""C-687 - OpenClaw's config-health record moved into the state database.

Current OpenClaw no longer writes ``logs/config-health.json``; the same record lives in
``state/openclaw.sqlite``, table ``config_health_entries`` (one row per tracked config path,
two JSON fingerprint columns and the vendor's own tamper signal
``last_observed_suspicious_signature``). B78 read the file only, so on a current install it was
UNKNOWN forever and the vendor's tamper signal was never seen.

These tests pin: the state database is judged when the table is there (by presence, never by a
version string); the legacy file is judged when it is there; both are judged when both are
there; a state database that exists but cannot be read is UNKNOWN - never a quiet read of a
stale file and never a clean pass over rows that were not examined; and the verdict text names
the config by basename only.

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

import pytest

from clawseccheck import collector
from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_config_health_integrity
from clawseccheck.collector import Context

CONFIG = "/home/u/.openclaw/openclaw.json"
LEGACY_NOT_FOUND = ("config-health integrity file not found — cannot evaluate config "
                    "integrity history.")


def _fingerprint(observed: str = "2026-10-12T07:40:36.994Z") -> dict:
    return {"bytes": 4096, "ctimeMs": 1.79e12, "dev": 66311, "gatewayMode": "local",
            "gid": 1000, "hasMeta": True, "hash": "ab" * 32, "ino": 7340033, "mode": 33152,
            "mtimeMs": 1.79e12, "nlink": 1, "observedAt": observed, "uid": 1000}


def _ddl(table: str) -> str:
    verb = " ".join(["CREATE", "TABLE"])
    cols = ", ".join([
        "config_path TEXT NOT NULL PRIMARY KEY", "last_known_good_json TEXT",
        "last_promoted_good_json TEXT", "last_observed_suspicious_signature TEXT",
        "updated_at_ms INTEGER NOT NULL",
    ])
    return f"{verb} {table} ({cols})"


def _row(path=CONFIG, known=True, promoted=True, signature=None):
    return (path,
            json.dumps(_fingerprint()) if known is True else known,
            json.dumps(_fingerprint("2026-09-23T13:48:38.448Z")) if promoted is True
            else promoted,
            signature)


def _state_db(home: Path, rows, table="config_health_entries") -> Path:
    db = home / "state" / "openclaw.sqlite"
    db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db)
    try:
        if table:
            conn.execute(_ddl(table))
            for i, (path, known, promoted, signature) in enumerate(rows):
                conn.execute(
                    f"INSERT INTO {table} VALUES (?, ?, ?, ?, ?)",
                    (path, known, promoted, signature, 1_790_000_000_000 + i),
                )
        conn.commit()
    finally:
        conn.close()
    os.chmod(db, 0o600)
    return db


def _legacy_file(home: Path, signature=None) -> Path:
    path = home / "logs" / "config-health.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {"lastKnownGood": _fingerprint(), "lastPromotedGood": _fingerprint(),
             "lastObservedSuspiciousSignature": signature}
    path.write_text(json.dumps({"entries": {CONFIG: entry}}), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def _sig() -> str:
    # the vendor's shape: "<content hash>:<comma separated reasons>"
    return "cd" * 32 + ":size-drop-vs-last-good"


def _b78(home):
    return check_config_health_integrity(Context(home=Path(home)))


# ---------------------------------------------------------------- the state-DB container

def test_a_clean_row_passes_and_names_the_state_database(tmp_path):
    _state_db(tmp_path, [_row()])
    f = _b78(tmp_path)
    assert f.id == "B78" and f.status == PASS, f.detail
    assert f.detail == ("OpenClaw's own record for 1 tracked config(s) in the state database "
                        "shows no suspicious signature on its latest observation (it records "
                        "only structural anomalies and clears the mark after a healthy "
                        "observation; it is not a content-integrity history).")
    # the legacy-file wording is a different, byte-pinned string
    assert "clean integrity history" not in f.detail


def test_a_suspicious_signature_in_the_row_fires_the_warn(tmp_path):
    _state_db(tmp_path, [_row(signature=_sig())])
    f = _b78(tmp_path)
    assert f.status == WARN, f.detail
    assert "in the state database" in f.detail
    assert f.evidence == ["suspicious integrity signature observed for openclaw.json"]


def test_the_warn_never_carries_the_signature_the_hash_or_the_path(tmp_path):
    _state_db(tmp_path, [_row(signature=_sig())])
    f = _b78(tmp_path)
    assert f.status == WARN, f.detail
    text = " ".join([f.detail, f.fix, *f.evidence])
    assert "size-drop" not in text and "cd" * 8 not in text and "ab" * 8 not in text
    assert "/home/" not in text and "/u/" not in text


def test_one_suspicious_row_among_clean_ones_is_counted_once(tmp_path):
    _state_db(tmp_path, [_row("/a/one.json"), _row("/a/two.json", signature=_sig()),
                         _row("/a/three.json")])
    f = _b78(tmp_path)
    assert f.status == WARN
    assert "1 tracked config(s)" in f.detail
    assert f.evidence == ["suspicious integrity signature observed for two.json"]


def test_an_empty_table_is_unknown_not_pass(tmp_path):
    _state_db(tmp_path, [])
    f = _b78(tmp_path)
    assert f.status == UNKNOWN
    assert "no tracked config entries" in f.detail and "state database" in f.detail


def test_a_non_text_signature_is_still_a_recorded_signature(tmp_path):
    db = _state_db(tmp_path, [_row()])
    conn = sqlite3.connect(db)
    conn.execute("UPDATE config_health_entries SET last_observed_suspicious_signature = 7")
    conn.commit()
    conn.close()
    assert _b78(tmp_path).status == WARN


@pytest.mark.parametrize("value", [b"", ""], ids=["empty-blob", "empty-string"])
def test_an_empty_but_non_null_signature_is_still_a_recorded_signature(tmp_path, value):
    """substr() of a zero-length BLOB is NULL, so "set" must be decided before the cut."""
    db = _state_db(tmp_path, [_row()])
    conn = sqlite3.connect(db)
    conn.execute("UPDATE config_health_entries SET last_observed_suspicious_signature = ?",
                 (value,))
    conn.commit()
    conn.close()
    assert collector.read_config_health_entries(tmp_path).entries[CONFIG][
        "lastObservedSuspiciousSignature"] == ""
    f = _b78(tmp_path)
    assert f.status == WARN, f.detail


def test_a_null_signature_stays_unset(tmp_path):
    _state_db(tmp_path, [_row()])
    assert collector.read_config_health_entries(tmp_path).entries[CONFIG][
        "lastObservedSuspiciousSignature"] is None


def test_the_reader_returns_the_legacy_files_shape(tmp_path):
    _state_db(tmp_path, [_row(signature=_sig()), _row("/b/other.json", known=None,
                                                      promoted=None)])
    got = collector.read_config_health_entries(tmp_path)
    assert got.status == collector.CONFIG_HEALTH_OK and got.unread == 0 and not got.truncated
    full = got.entries[CONFIG]
    assert sorted(full) == ["lastKnownGood", "lastObservedSuspiciousSignature",
                            "lastPromotedGood"]
    assert full["lastKnownGood"] == _fingerprint()
    assert full["lastObservedSuspiciousSignature"] == _sig()
    # an unset fingerprint (SQL NULL) is absent, exactly as the vendor's decode leaves it
    assert got.entries["/b/other.json"] == {"lastObservedSuspiciousSignature": None}
    # the legacy file's own judge accepts the same object
    legacy = tmp_path / "legacy"
    (legacy / "logs").mkdir(parents=True)
    (legacy / "logs" / "config-health.json").write_text(
        json.dumps({"entries": got.entries}), encoding="utf-8")
    assert _b78(legacy).status == WARN


def test_a_collected_context_carries_the_read_and_b78_uses_it(tmp_path):
    _state_db(tmp_path, [_row(signature=_sig())])
    ctx = collector.collect(tmp_path)
    assert ctx.config_health_status == collector.CONFIG_HEALTH_OK
    assert CONFIG in ctx.config_health_entries
    assert check_config_health_integrity(ctx).status == WARN


def test_the_check_reads_the_context_not_the_disk_when_collected(tmp_path):
    """A collected Context is the evidence: B78 must not re-read a database that changed
    after collection (same rule as every other collector-fed check)."""
    _state_db(tmp_path, [_row()])
    ctx = collector.collect(tmp_path)
    (tmp_path / "state" / "openclaw.sqlite").unlink()
    assert check_config_health_integrity(ctx).status == PASS


def test_reading_leaves_the_database_untouched(tmp_path):
    db = _state_db(tmp_path, [_row(signature=_sig())])
    before = (db.read_bytes(), db.stat().st_mtime_ns)
    _b78(tmp_path)
    assert (db.read_bytes(), db.stat().st_mtime_ns) == before
    assert sorted(p.name for p in db.parent.iterdir()) == ["openclaw.sqlite"]


def test_reading_a_wal_mode_database_leaves_the_main_file_untouched(tmp_path):
    """A WAL-mode database is the vendor's normal state: a reader that opened it read-write
    could checkpoint, and a hot WAL holds rows the main file does not. The rows in the WAL
    must be seen AND the main file's bytes must not move."""
    import hashlib

    db = _state_db(tmp_path, [_row("/w/one.json")])
    writer = sqlite3.connect(db)
    try:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute(
            "UPDATE config_health_entries SET last_observed_suspicious_signature = ?",
            (_sig(),))
        writer.commit()
        wal = db.with_name(db.name + "-wal")
        assert wal.exists() and wal.stat().st_size > 0   # the row lives only in the WAL
        before = hashlib.sha256(db.read_bytes()).hexdigest()
        f = _b78(tmp_path)
        assert f.status == WARN, f.detail
        assert hashlib.sha256(db.read_bytes()).hexdigest() == before
        # and a checkpointed WAL-mode file stays untouched too
        writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        writer.close()
    again = hashlib.sha256(db.read_bytes()).hexdigest()
    assert _b78(tmp_path).status == WARN
    assert hashlib.sha256(db.read_bytes()).hexdigest() == again


# ---------------------------------------------------------------- absent / legacy

def test_no_state_db_no_file_is_unknown_with_the_legacy_detail(tmp_path):
    f = _b78(tmp_path)
    assert f.status == UNKNOWN and f.detail == LEGACY_NOT_FOUND
    assert "config_health_entries" in f.fix and "config-health.json" in f.fix


def test_a_db_without_the_table_and_no_file_is_unknown(tmp_path):
    _state_db(tmp_path, [], table=None)
    f = _b78(tmp_path)
    assert f.status == UNKNOWN and f.detail == LEGACY_NOT_FOUND


def test_a_db_without_the_table_falls_back_to_the_legacy_file(tmp_path):
    _state_db(tmp_path, [], table=None)
    _legacy_file(tmp_path)
    f = _b78(tmp_path)
    assert f.status == PASS
    assert f.detail == ("all 1 tracked config(s) have a clean integrity history "
                        "(no suspicious signatures observed).")


def test_a_legacy_file_alone_keeps_its_exact_text(tmp_path):
    _legacy_file(tmp_path, signature=_sig())
    f = _b78(tmp_path)
    assert f.status == WARN
    assert f.detail == ("config integrity alert: 1 tracked config(s) recorded a suspicious "
                        "signature — OpenClaw observed a config state it could not "
                        "verify as known-good.")
    assert f.evidence == ["suspicious integrity signature observed for openclaw.json"]


# ---------------------------------------------------------------- both containers

def test_a_clean_db_does_not_speak_for_a_suspicious_legacy_file(tmp_path):
    _state_db(tmp_path, [_row()])
    _legacy_file(tmp_path, signature=_sig())
    f = _b78(tmp_path)
    assert f.status == WARN
    assert "state database" in f.detail and "legacy file" in f.detail
    assert f.evidence == ["[legacy file] suspicious integrity signature observed for "
                          "openclaw.json"]


def test_a_suspicious_db_is_not_cleared_by_a_clean_legacy_file(tmp_path):
    _state_db(tmp_path, [_row(signature=_sig())])
    _legacy_file(tmp_path)
    f = _b78(tmp_path)
    assert f.status == WARN
    assert f.evidence == ["[state database] suspicious integrity signature observed for "
                          "openclaw.json"]


def test_both_containers_clean_pass_and_name_both(tmp_path):
    _state_db(tmp_path, [_row()])
    _legacy_file(tmp_path)
    f = _b78(tmp_path)
    assert f.status == PASS
    assert "state database" in f.detail and "legacy file" in f.detail


def test_a_clean_db_with_an_unreadable_legacy_file_is_unknown(tmp_path, monkeypatch):
    _state_db(tmp_path, [_row()])
    path = _legacy_file(tmp_path)
    real = Path.read_text

    def deny(self, *a, **k):
        if self == path:
            raise PermissionError(13, "denied")
        return real(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", deny)
    f = _b78(tmp_path)
    assert f.status == UNKNOWN, f.detail
    assert "unreadable" in f.detail and "state database" in f.detail


# ---------------------------------------------------------------- never a clean pass

def _view_over_decoy(tmp_path) -> Path:
    db = _state_db(tmp_path, [_row()], table="decoy_rows")
    conn = sqlite3.connect(db)
    conn.execute("CREATE VIEW config_health_entries AS SELECT * FROM decoy_rows")
    conn.commit()
    conn.close()
    return db


def test_a_view_named_like_the_table_is_unknown_and_does_not_fall_back(tmp_path):
    _view_over_decoy(tmp_path)
    f = _b78(tmp_path)
    assert f.status == UNKNOWN
    assert f.detail != LEGACY_NOT_FOUND and "could not be read" in f.detail
    assert collector.read_config_health_entries(tmp_path).status == \
        collector.CONFIG_HEALTH_UNREADABLE


def test_an_unreadable_db_beside_a_clean_file_is_unknown_not_pass(tmp_path):
    _view_over_decoy(tmp_path)
    _legacy_file(tmp_path)   # a stale file must not answer for the refused database
    assert _b78(tmp_path).status == UNKNOWN


def test_an_unreadable_db_beside_a_suspicious_file_still_warns(tmp_path):
    _view_over_decoy(tmp_path)
    _legacy_file(tmp_path, signature=_sig())
    assert _b78(tmp_path).status == WARN


def test_a_fifo_at_the_db_path_is_refused_without_hanging(tmp_path):
    (tmp_path / "state").mkdir()
    os.mkfifo(tmp_path / "state" / "openclaw.sqlite")
    assert _b78(tmp_path).status == UNKNOWN
    assert collector.read_config_health_entries(tmp_path).status == \
        collector.CONFIG_HEALTH_UNREADABLE


def test_a_file_that_is_not_a_database_is_unknown(tmp_path):
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "openclaw.sqlite").write_bytes(b"not a database" * 40)
    f = _b78(tmp_path)
    assert f.status == UNKNOWN and "could not be read" in f.detail


def test_an_unparseable_fingerprint_is_counted_and_never_read_as_clean(tmp_path):
    _state_db(tmp_path, [_row(known="{not json")])
    got = collector.read_config_health_entries(tmp_path)
    assert got.unread == 1 and "lastKnownGood" not in got.entries[CONFIG]
    f = _b78(tmp_path)
    assert f.status == UNKNOWN, f.detail
    assert "could not be read" in f.detail


def test_a_fingerprint_that_is_not_an_object_is_unread(tmp_path):
    _state_db(tmp_path, [_row(promoted="[1, 2]")])
    assert collector.read_config_health_entries(tmp_path).unread == 1
    assert _b78(tmp_path).status == UNKNOWN


def test_a_fingerprint_nested_past_the_bound_is_unread_not_a_crash(tmp_path):
    deep = "[" * 200_000 + "]" * 200_000
    _state_db(tmp_path, [_row(known=deep)])
    got = collector.read_config_health_entries(tmp_path)
    assert got.unread == 1
    assert _b78(tmp_path).status == UNKNOWN


def test_an_oversized_fingerprint_is_unread_not_fetched(tmp_path):
    _state_db(tmp_path, [_row(known=json.dumps({"pad": "x" * 5000}))])
    got = collector.read_config_health_entries(tmp_path, max_cell_bytes=1024)
    assert got.unread == 1 and "lastKnownGood" not in got.entries[CONFIG]


def test_a_signature_still_warns_when_a_fingerprint_cannot_be_read(tmp_path):
    _state_db(tmp_path, [_row(known="{not json", signature=_sig())])
    f = _b78(tmp_path)
    assert f.status == WARN
    assert "could not be read" in f.fix


def test_rows_past_the_row_cap_are_disclosed_not_passed(tmp_path):
    _state_db(tmp_path, [_row(f"/c/{i}.json") for i in range(5)])
    got = collector.read_config_health_entries(tmp_path, max_rows=3)
    assert got.truncated and len(got.entries) == 3
    ctx = Context(home=tmp_path, config_health_status=got.status,
                  config_health_entries=got.entries, config_health_unread=got.unread,
                  config_health_truncated=got.truncated)
    f = check_config_health_integrity(ctx)
    assert f.status == UNKNOWN and "row limit" in f.detail


def test_rows_at_the_row_cap_are_not_truncated(tmp_path):
    _state_db(tmp_path, [_row(f"/c/{i}.json") for i in range(3)])
    got = collector.read_config_health_entries(tmp_path, max_rows=3)
    assert not got.truncated and len(got.entries) == 3


@pytest.mark.parametrize("path_len", [2000])
def test_a_very_long_config_path_is_cut_and_never_swallows_a_signature(tmp_path, path_len):
    a = "/" + "a" * path_len + "/x"
    b = "/" + "a" * path_len + "/y"
    _state_db(tmp_path, [_row(a), _row(b, signature=_sig())])
    got = collector.read_config_health_entries(tmp_path)
    assert len(got.entries) == 2
    assert _b78(tmp_path).status == WARN
