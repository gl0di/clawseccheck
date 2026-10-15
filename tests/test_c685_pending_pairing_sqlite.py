"""C-685: B138 (dangling high-scope pending device pairing) read only ``devices/pending.json``.

OpenClaw 2026.8.1 moved the pending pairing requests into the ``device_pairing_pending`` table
of ``state/openclaw.sqlite`` (the old file is left as ``pending.json.migrated``). B138 kept
looking at the file, found it absent and answered a clean PASS on every current install, even
with a high-scope request waiting in the table.

The table DDL is assembled from fragments (the repo-wide state-DDL scanner flags a contiguous
literal) and follows the column list of an installed OpenClaw 2026.10.1. Secret-shaped values
are assembled at runtime. Offline, read-only, tmp_path only.
"""
from __future__ import annotations

import json
import shutil
import sqlite3
import time
from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import BY_ID, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_pending_device_pairing_scope
from clawseccheck.collector import (
    _MAX_PAIRED_DEVICE_JSON_BYTES,
    _MAX_PENDING_PAIRINGS,
    _PENDING_PAIRING_SQLITE_SELECT,
    Context,
    collect,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
_MK = " ".join(("CREATE", "TABLE"))
_PENDING_DDL = (
    f"{_MK} device_pairing_pending (request_id TEXT NOT NULL PRIMARY KEY, "
    "device_id TEXT NOT NULL, public_key TEXT NOT NULL, display_name TEXT, platform TEXT, "
    "device_family TEXT, client_id TEXT, client_mode TEXT, browser_origin TEXT, role TEXT, "
    "roles_json TEXT, scopes_json TEXT, remote_ip TEXT, silent INTEGER, is_repair INTEGER, "
    "ts INTEGER NOT NULL, refreshed_at_ms INTEGER) STRICT"
)
_DAY_MS = 86_400_000


def _public_key() -> str:
    return "pk-" + "ssh-" + "rsa-" + ("Q" * 40)


def _row(request_id="req-1", scopes=("operator.admin",), is_repair=0, age_days=9.0, **extra):
    row = {
        "request_id": request_id,
        "device_id": extra.pop("device_id", "dev-" + request_id),
        "platform": extra.pop("platform", "linux"),
        "scopes_json": json.dumps(list(scopes)) if scopes is not None else None,
        "is_repair": is_repair,
        "ts": int(time.time() * 1000 - age_days * _DAY_MS),
    }
    row.update(extra)
    return row


def _make_state_db(home: Path, rows: list, *, ddl: str | None = _PENDING_DDL) -> Path:
    state = home / "state"
    state.mkdir(parents=True, exist_ok=True)
    db = state / "openclaw.sqlite"
    conn = sqlite3.connect(db)
    try:
        if ddl:
            conn.execute(ddl)
        for r in rows:
            conn.execute(
                "INSERT INTO device_pairing_pending (request_id, device_id, public_key, "
                "platform, role, roles_json, scopes_json, silent, is_repair, ts) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    r["request_id"], r["device_id"], r.get("public_key", _public_key()),
                    r.get("platform"), r.get("role"), r.get("roles_json"),
                    r.get("scopes_json"), r.get("silent", 0), r.get("is_repair"), r["ts"],
                ),
            )
        conn.commit()
    finally:
        conn.close()
    return db


def _legacy(home: Path, entries: dict) -> None:
    (home / "devices").mkdir(parents=True, exist_ok=True)
    (home / "devices" / "pending.json").write_text(json.dumps(entries), encoding="utf-8")


def _b138(home: Path, **ctx_fields):
    ctx = collect(home)
    for k, v in ctx_fields.items():
        setattr(ctx, k, v)
    return check_pending_device_pairing_scope(ctx)


# ---------------------------------------------------------------- the repro: bad

def test_nine_day_old_admin_repair_request_in_the_table_warns_and_names_it(tmp_path):
    _make_state_db(tmp_path, [_row("req-9day", ("operator.admin", "operator.write"), is_repair=1)])
    f = _b138(tmp_path)
    assert f.id == "B138" and f.status == WARN
    assert "req-9day" in f.detail and "isRepair=True" in f.detail
    assert "device_pairing_pending" in f.detail
    assert any("requestAgeDays=9.0" in e for e in f.evidence)


def test_the_request_age_is_evidence_only_never_in_the_hashed_detail(tmp_path):
    _make_state_db(tmp_path, [_row("req-age")])
    f = _b138(tmp_path)
    assert f.status == WARN
    assert "requestAgeDays" not in f.detail and "requestAgeDays" not in f.fix


def test_high_scope_request_without_is_repair_still_warns(tmp_path):
    _make_state_db(tmp_path, [_row("req-w", ("operator.write",), is_repair=0, age_days=0.01)])
    f = _b138(tmp_path)
    assert f.status == WARN
    assert "isRepair=False" in f.detail and "req-w" in f.detail


def test_null_is_repair_reads_as_not_a_repair(tmp_path):
    _make_state_db(tmp_path, [_row("req-n", is_repair=None)])
    assert "isRepair=False" in _b138(tmp_path).detail


# ---------------------------------------------------------------- clean

def test_table_present_and_empty_is_pass_naming_the_table(tmp_path):
    _make_state_db(tmp_path, [])
    f = _b138(tmp_path)
    assert f.status == PASS and "device_pairing_pending" in f.detail


def test_table_with_only_low_scope_requests_is_pass(tmp_path):
    _make_state_db(tmp_path, [_row("r1", ("operator.read",)), _row("r2", scopes=None)])
    f = _b138(tmp_path)
    assert f.status == PASS and "2 pending device pairing request(s)" in f.detail


# ---------------------------------------------------------------- UNKNOWN

def test_state_db_without_the_table_and_no_file_is_unknown(tmp_path):
    _make_state_db(tmp_path, [], ddl=f"{_MK} unrelated (x INTEGER)")
    f = _b138(tmp_path)
    assert f.status == UNKNOWN and "no device_pairing_pending table" in f.detail


def test_a_view_named_like_the_table_is_unknown_not_clean(tmp_path):
    db = _make_state_db(tmp_path, [], ddl=None)
    conn = sqlite3.connect(db)
    conn.execute(f"{_MK} decoy (request_id TEXT, scopes_json TEXT)")
    conn.execute("CREATE VIEW device_pairing_pending AS SELECT * FROM decoy")
    conn.commit()
    conn.close()
    f = _b138(tmp_path)
    assert f.status == UNKNOWN and "could not be reliably read" in f.detail


def test_an_unreadable_state_database_is_unknown(tmp_path):
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "openclaw.sqlite").write_bytes(b"this is not a database" * 50)
    assert _b138(tmp_path).status == UNKNOWN


def test_a_state_directory_listing_cut_short_before_the_database_is_unknown(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    for i in range(130):
        (state / f"filler-{i:03d}.txt").write_text("x", encoding="utf-8")
    f = _b138(tmp_path, config_found=True)
    assert f.status == UNKNOWN and "cut short" in f.detail


def test_a_scopes_value_that_cannot_be_read_is_never_read_as_no_scopes(tmp_path):
    _make_state_db(tmp_path, [
        _row("bad-json", scopes=None, scopes_json="{not json"),
        _row("not-a-list", scopes=None, scopes_json=json.dumps("operator.admin")),
        _row("ok", ("operator.read",)),
    ])
    f = _b138(tmp_path)
    assert f.status == UNKNOWN
    assert "bad-json" not in f.detail  # detail stays clock/ID-free; the gap is in fix
    assert "2 request(s)" in f.fix


def test_an_oversized_row_is_counted_and_degrades_a_clean_answer_to_unknown(tmp_path):
    huge = json.dumps(["x" * (_MAX_PAIRED_DEVICE_JSON_BYTES + 10)])
    _make_state_db(tmp_path, [_row("big", scopes=None, scopes_json=huge), _row("ok", ("operator.read",))])
    ctx = collect(tmp_path)
    assert ctx.pending_pairings_sqlite_dropped == 1 and "ok" in ctx.pending_pairings_sqlite
    assert check_pending_device_pairing_scope(ctx).status == UNKNOWN


def test_a_warn_stands_when_another_row_was_not_read_and_the_gap_is_disclosed(tmp_path):
    huge = json.dumps(["x" * (_MAX_PAIRED_DEVICE_JSON_BYTES + 10)])
    _make_state_db(tmp_path, [_row("big", scopes=None, scopes_json=huge), _row("hit")])
    f = _b138(tmp_path)
    assert f.status == WARN and "hit" in f.detail
    assert "Not evaluated" in f.fix and "not read" in f.fix


def test_rows_past_the_row_cap_are_counted_not_silently_cut(tmp_path):
    rows = [_row(f"r{i:04d}", ("operator.read",), age_days=1.0 + i / 10000) for i in range(_MAX_PENDING_PAIRINGS + 3)]
    _make_state_db(tmp_path, rows)
    ctx = collect(tmp_path)
    assert len(ctx.pending_pairings_sqlite) == _MAX_PENDING_PAIRINGS
    assert ctx.pending_pairings_sqlite_dropped >= 1
    assert check_pending_device_pairing_scope(ctx).status == UNKNOWN


# ---------------------------------------------------------------- never the public key

def test_the_public_key_and_remote_ip_are_never_selected_or_echoed(tmp_path):
    assert "public_key" not in _PENDING_PAIRING_SQLITE_SELECT
    assert "remote_ip" not in _PENDING_PAIRING_SQLITE_SELECT
    _make_state_db(tmp_path, [_row("req-pk")])
    ctx = collect(tmp_path)
    f = check_pending_device_pairing_scope(ctx)
    blob = json.dumps([ctx.pending_pairings_sqlite, f.detail, f.fix, f.evidence])
    assert _public_key() not in blob and "publicKey" not in blob


# ---------------------------------------------------------------- both containers

def test_legacy_file_alone_is_judged_exactly_as_before():
    f = check_pending_device_pairing_scope(Context(home=FIXTURES / "bad_b138_pending_admin_scope"))
    assert f.status == WARN and "device_pairing_pending" not in f.detail
    f = check_pending_device_pairing_scope(Context(home=FIXTURES / "clean_b138_pending_no_highscope"))
    assert f.status == PASS and "device_pairing_pending" not in f.detail


def test_legacy_file_is_still_read_when_the_state_database_has_no_table(tmp_path):
    _make_state_db(tmp_path, [], ddl=f"{_MK} unrelated (x INTEGER)")
    _legacy(tmp_path, {"r": {"deviceId": "d", "platform": "linux", "isRepair": True,
                             "scopes": ["operator.admin"]}})
    f = _b138(tmp_path)
    assert f.status == WARN and "deviceId=d platform=linux isRepair=True" in f.detail


# The exact text dev's legacy-only B138 produced for this entry (a fingerprint hashes it).
_LEGACY_ENTRY = {"r": {"deviceId": "d", "platform": "linux", "isRepair": True,
                       "scopes": ["operator.admin"]}}
_LEGACY_WARN_DETAIL = (
    "pending device pairing request(s) awaiting your approval request a high-privilege scope "
    "(operator.admin/operator.write): deviceId=d platform=linux isRepair=True."
)


def test_legacy_only_warn_text_is_pinned(tmp_path):
    _legacy(tmp_path, _LEGACY_ENTRY)
    assert _b138(tmp_path).detail == _LEGACY_WARN_DETAIL


def test_a_legacy_warn_keeps_its_exact_detail_whatever_the_table_looks_like(tmp_path):
    """Four table states beside a legacy WARN: no state database, an empty table, a clean
    table, a table that cannot be read - the finding's detail never moves."""
    cases = {
        "absent": lambda h: None,
        "empty": lambda h: _make_state_db(h, []),
        "clean": lambda h: _make_state_db(h, [_row("low", ("operator.read",))]),
        "unreadable": lambda h: (h / "state").mkdir() or (h / "state" / "openclaw.sqlite").write_bytes(b"junk" * 99),
    }
    for name, build in cases.items():
        home = tmp_path / name
        home.mkdir()
        _legacy(home, _LEGACY_ENTRY)
        build(home)
        f = _b138(home)
        assert f.status == WARN and f.detail == _LEGACY_WARN_DETAIL, name
    assert "Not fully read" in _b138(tmp_path / "unreadable").fix


def test_a_table_hit_beside_a_legacy_hit_is_appended_after_the_legacy_text(tmp_path):
    _legacy(tmp_path, _LEGACY_ENTRY)
    _make_state_db(tmp_path, [_row("tbl-hit")])
    f = _b138(tmp_path)
    assert f.status == WARN
    assert f.detail.startswith(_LEGACY_WARN_DETAIL[:-1] + "; state database: requestId=tbl-hit")


def test_a_table_only_hit_uses_the_new_table_text(tmp_path):
    _legacy(tmp_path, {"r": {"deviceId": "d", "scopes": ["operator.read"]}})
    _make_state_db(tmp_path, [_row("tbl-hit")])
    f = _b138(tmp_path)
    assert f.status == WARN and "tbl-hit" in f.detail and "device_pairing_pending" in f.detail
    assert "devices/pending.json" not in f.detail


def test_a_legacy_unknown_keeps_its_exact_detail_beside_a_clean_table(tmp_path):
    (tmp_path / "devices").mkdir()
    (tmp_path / "devices" / "pending.json").write_text("{not valid json", encoding="utf-8")
    _make_state_db(tmp_path, [])
    f = _b138(tmp_path)
    assert f.status == UNKNOWN
    assert f.detail == ("devices/pending.json present but not valid JSON \u2014 cannot evaluate "
                        "pending device pairing requests.")


def test_a_legacy_hit_in_the_file_alone_still_warns_beside_an_other_file_hit(tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    _make_state_db(other, [_row("low", ("operator.read",))])
    _legacy(other, {"r": {"deviceId": "file-dev", "scopes": ["operator.write"]}})
    f = _b138(other)
    assert f.status == WARN and "deviceId=file-dev" in f.detail


def test_both_containers_clean_is_pass_naming_both(tmp_path):
    _make_state_db(tmp_path, [_row("low", ("operator.read",))])
    _legacy(tmp_path, {"r": {"deviceId": "d", "scopes": ["operator.read"]}})
    f = _b138(tmp_path)
    assert f.status == PASS and "device_pairing_pending" in f.detail and "devices/pending.json" in f.detail


def test_a_clean_file_cannot_clear_a_table_that_was_not_read(tmp_path):
    db = _make_state_db(tmp_path, [], ddl=None)
    conn = sqlite3.connect(db)
    conn.execute(f"{_MK} decoy (request_id TEXT)")
    conn.execute("CREATE VIEW device_pairing_pending AS SELECT * FROM decoy")
    conn.commit()
    conn.close()
    _legacy(tmp_path, {})
    assert _b138(tmp_path).status == UNKNOWN


def test_a_warn_in_the_file_stands_when_the_table_was_not_read(tmp_path):
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "openclaw.sqlite").write_bytes(b"garbage" * 100)
    _legacy(tmp_path, {"r": {"deviceId": "d", "platform": "linux", "scopes": ["operator.admin"]}})
    f = _b138(tmp_path)
    assert f.status == WARN and "Not fully read" in f.fix


# ---------------------------------------------------------------- the "nothing anywhere" cell

def test_openclaw_home_with_no_store_anywhere_keeps_the_legacy_pass(tmp_path):
    f = _b138(tmp_path, config_found=True)
    assert f.status == PASS
    assert f.detail == "no devices/pending.json found — no pending device pairing requests."


def test_a_directory_that_is_not_an_openclaw_home_is_unknown_not_clean(tmp_path):
    f = _b138(tmp_path, config_found=False)
    assert f.status == UNKNOWN and "does not look like an OpenClaw home" in f.detail


# ---------------------------------------------------------------- wiring

def test_a_full_audit_reports_the_pending_request(tmp_path):
    home = tmp_path / "home"
    shutil.copytree(FIXTURES / "home_safe", home)
    _make_state_db(home, [_row("req-e2e", ("operator.admin",), is_repair=1)])
    _ctx, findings, _score = audit(str(home))
    b138 = next(f for f in findings if f.id == "B138")
    assert b138.status == WARN and "req-e2e" in b138.detail


def test_the_catalog_title_no_longer_names_only_the_retired_file():
    title = BY_ID["B138"].title
    assert "device_pairing_pending" in title or "state" in title


# ---------------------------------------------------------------- a database that is not an ordinary file

def _present_but_odd_is_unknown(home: Path, expect_fragment: str) -> None:
    for config_found in (True, False):
        f = _b138(home, config_found=config_found)
        assert f.status == UNKNOWN, config_found
        assert expect_fragment in f.detail and "not read" in f.detail


def test_a_symlinked_state_database_is_unknown_never_nothing_stored(tmp_path):
    real = tmp_path / "elsewhere"
    _make_state_db(real, [_row("req-sym")])
    home = tmp_path / "home"
    (home / "state").mkdir(parents=True)
    (home / "state" / "openclaw.sqlite").symlink_to(real / "state" / "openclaw.sqlite")
    _present_but_odd_is_unknown(home, "is a symlink")


def test_a_dangling_symlink_at_the_database_path_is_unknown(tmp_path):
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "openclaw.sqlite").symlink_to(tmp_path / "gone.sqlite")
    _present_but_odd_is_unknown(tmp_path, "is a symlink")


def test_a_directory_at_the_database_path_is_unknown(tmp_path):
    (tmp_path / "state" / "openclaw.sqlite").mkdir(parents=True)
    _present_but_odd_is_unknown(tmp_path, "is a directory")


def test_a_fifo_at_the_database_path_is_unknown_and_does_not_hang(tmp_path):
    import os

    (tmp_path / "state").mkdir()
    os.mkfifo(tmp_path / "state" / "openclaw.sqlite")
    for config_found in (True, False):
        assert _b138(tmp_path, config_found=config_found).status == UNKNOWN


def test_a_state_entry_that_is_a_file_is_unknown(tmp_path):
    (tmp_path / "state").write_text("x", encoding="utf-8")
    _present_but_odd_is_unknown(tmp_path, "state is a file")


def test_a_symlinked_state_directory_is_followed_like_the_other_readers(tmp_path):
    real = tmp_path / "elsewhere"
    _make_state_db(real, [_row("req-dir")])
    home = tmp_path / "home"
    home.mkdir()
    (home / "state").symlink_to(real / "state")
    assert _b138(home).status == WARN


def test_a_clean_legacy_file_cannot_clear_a_symlinked_database(tmp_path):
    real = tmp_path / "elsewhere"
    _make_state_db(real, [_row("req-sym")])
    home = tmp_path / "home"
    (home / "state").mkdir(parents=True)
    (home / "state" / "openclaw.sqlite").symlink_to(real / "state" / "openclaw.sqlite")
    _legacy(home, {})
    assert _b138(home).status == UNKNOWN


# ---------------------------------------------------------------- scope strings in the table

def test_scope_strings_are_trimmed_like_the_vendor_but_case_is_kept(tmp_path):
    _make_state_db(tmp_path, [_row("trim", scopes=None, scopes_json=json.dumps([" operator.admin\t"]))])
    assert _b138(tmp_path).status == WARN
    other = tmp_path / "other"
    other.mkdir()
    _make_state_db(other, [_row("case", scopes=None, scopes_json=json.dumps(["Operator.Admin"]))])
    assert _b138(other).status == PASS


def test_a_non_string_scope_element_is_unknown_not_clean(tmp_path):
    for i, raw in enumerate([[["operator.admin"]], [{"scope": "operator.admin"}], ["operator.read", 7]]):
        home = tmp_path / f"h{i}"
        home.mkdir()
        _make_state_db(home, [_row("odd", scopes=None, scopes_json=json.dumps(raw))])
        assert _b138(home).status == UNKNOWN, raw


def test_a_readable_admin_string_still_warns_beside_a_non_string_element(tmp_path):
    _make_state_db(tmp_path, [_row("mixed", scopes=None, scopes_json=json.dumps(["operator.admin", ["x"]]))])
    assert _b138(tmp_path).status == WARN


def test_known_limit_other_operator_scopes_are_not_high_here(tmp_path):
    """Pins the documented limit: only operator.admin / operator.write count as high."""
    _make_state_db(tmp_path, [_row("pairing", ("operator.pairing", "operator.approvals"))])
    assert _b138(tmp_path).status == PASS
