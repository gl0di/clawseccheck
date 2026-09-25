"""B176 follow-up (2026-09-25): OpenClaw 2026.9.6 migrates the legacy
``devices/paired.json`` store into a dedicated ``device_pairing_paired`` table in
``state/openclaw.sqlite``, leaving only an inert ``devices/paired.json.migrated``
behind. Before this fix, `check_paired_device_operator_authority` checked
``paired_path.is_file()`` on the legacy path alone -- found it absent on a migrated
install, and reported a confident PASS ("no paired devices to evaluate") even on a
machine with real, live paired devices holding standing operator.admin/write
authority. Reproduced live: this task's own machine (OpenClaw 2026.9.6) has
``devices/paired.json.migrated`` (not ``devices/paired.json``) and 2 real rows in
``device_pairing_paired``.

Grounded by DIRECT SCHEMA INSPECTION of that real, installed OpenClaw (``sqlite3
~/.openclaw/state/openclaw.sqlite ".schema device_pairing_paired"``), not decompiled
from a dist bundle -- the DDL below is copied verbatim from that output, the same
"copy the real DDL into the fixture" discipline `test_b709_subagent_runs_shapes.py`
already established for its own dual-shape table.

`collector._collect_paired_devices_sqlite` normalises each row into the SAME
per-entry dict shape the legacy ``devices/paired.json`` envelope already uses
(deviceId/platform/scopes/approvedScopes/tokens/createdAtMs/approvedAtMs/
lastSeenAtMs), so `check_paired_device_operator_authority`'s existing scope/
revoked-token evaluation loop (see ``test_b176_paired_device_authority.py`` for that
loop's own, unchanged coverage) runs identically against either source. This file
covers only what is NEW: the reader in isolation, the merge rule (legacy JSON wins
outright when present; SQLite is a fallback only when it is absent), and the
never-echo-the-token-secret contract for the new source.

Offline, read-only, stdlib only -- writes only under pytest's tmp_path, never
touches a real ``~/.openclaw``.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_paired_device_operator_authority
from clawseccheck.collector import Context, _collect_paired_devices_sqlite, collect

# DDL copied verbatim from `sqlite3 ~/.openclaw/state/openclaw.sqlite ".schema
# device_pairing_paired"` against a real, installed OpenClaw 2026.9.6 -- see this
# file's module docstring.
_DEVICE_PAIRING_PAIRED_DDL = """
CREATE TABLE IF NOT EXISTS "device_pairing_paired" (
  device_id TEXT NOT NULL PRIMARY KEY,
  public_key TEXT NOT NULL,
  display_name TEXT,
  operator_label TEXT,
  platform TEXT,
  device_family TEXT,
  client_id TEXT,
  client_mode TEXT,
  browser_origin TEXT,
  role TEXT,
  roles_json TEXT,
  scopes_json TEXT,
  approved_scopes_json TEXT,
  remote_ip TEXT,
  tokens_json TEXT,
  approved_via TEXT,
  node_surface_json TEXT,
  pending_node_surface_json TEXT,
  created_at_ms INTEGER NOT NULL,
  approved_at_ms INTEGER NOT NULL,
  last_seen_at_ms INTEGER,
  last_seen_reason TEXT
) STRICT
"""


def _token(seed: str) -> str:
    """Assembled at runtime from fragments -- Golden Rule #3 forbids a contiguous
    secret-shaped literal in source, so secret scanners stay quiet on this repo."""
    return "sk-" + "ant-" + "api03-" + (seed * 40)


def _make_state_db(state_dir: Path, rows: list[dict]) -> None:
    """Materialise a real ``state/openclaw.sqlite`` with one ``device_pairing_paired``
    table, DDL copied verbatim from the real machine. *rows* is a list of dicts with
    whatever of {device_id, platform, scopes, approved_scopes, tokens, created_at_ms,
    approved_at_ms, last_seen_at_ms} keys the case needs -- sane defaults fill the
    rest (including the NOT NULL columns this reader never selects, e.g. public_key).
    """
    state_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(state_dir / "openclaw.sqlite")
    try:
        conn.execute(_DEVICE_PAIRING_PAIRED_DDL)
        for i, row in enumerate(rows):
            conn.execute(
                "INSERT INTO device_pairing_paired "
                "(device_id, public_key, platform, scopes_json, approved_scopes_json, "
                "tokens_json, created_at_ms, approved_at_ms, last_seen_at_ms) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    row.get("device_id", f"device-{i}"),
                    row.get("public_key", f"pubkey-{i}"),
                    row.get("platform", "linux"),
                    json.dumps(row["scopes"]) if "scopes" in row else None,
                    json.dumps(row["approved_scopes"]) if "approved_scopes" in row else None,
                    json.dumps(row["tokens"]) if "tokens" in row else None,
                    row.get("created_at_ms", 1_700_000_000_000),
                    row.get("approved_at_ms", 1_700_000_000_000),
                    row.get("last_seen_at_ms"),
                ),
            )
        conn.commit()
    finally:
        conn.close()


def _migrated_home(tmp_path: Path, name: str, rows: list[dict] | None) -> Path:
    """A home shaped exactly like the real repro: ``devices/paired.json.migrated``
    (never read by this or any check), no ``devices/paired.json``, and -- when *rows*
    is not None -- a real ``device_pairing_paired`` table."""
    home = tmp_path / name
    home.mkdir(parents=True)
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    devices_dir = home / "devices"
    devices_dir.mkdir()
    (devices_dir / "paired.json.migrated").write_text("{}", encoding="utf-8")
    if rows is not None:
        _make_state_db(home / "state", rows)
    return home


# --------------------------------------------------------------------------------
# The reader in isolation
# --------------------------------------------------------------------------------


class TestPairedDevicesSqliteReader:
    def test_no_state_dir_is_undetermined(self, tmp_path):
        home = tmp_path / "h"
        home.mkdir()
        ctx = Context(home=home)
        _collect_paired_devices_sqlite(home, ctx)
        assert ctx.paired_devices_sqlite_found is False
        assert ctx.paired_devices_sqlite == {}

    def test_db_predating_the_table_is_undetermined_not_absent(self, tmp_path):
        home = tmp_path / "h"
        state = home / "state"
        state.mkdir(parents=True)
        conn = sqlite3.connect(state / "openclaw.sqlite")
        conn.execute("CREATE TABLE something_else (x TEXT)")
        conn.commit()
        conn.close()
        ctx = Context(home=home)
        _collect_paired_devices_sqlite(home, ctx)
        assert ctx.paired_devices_sqlite_found is False
        assert ctx.paired_devices_sqlite_parse_error is False

    def test_table_present_but_empty_reads_as_found_with_zero_rows(self, tmp_path):
        """The open item this task flags explicitly: a migrated-but-never-paired
        install must read as a real, confident "looked, nothing there" -- not
        undetermined, and not a parse error."""
        home = tmp_path / "h"
        _make_state_db(home / "state", [])
        ctx = Context(home=home)
        _collect_paired_devices_sqlite(home, ctx)
        assert ctx.paired_devices_sqlite_found is True
        assert ctx.paired_devices_sqlite_parse_error is False
        assert ctx.paired_devices_sqlite == {}

    def test_a_real_row_is_normalized_into_the_legacy_shape(self, tmp_path):
        home = tmp_path / "h"
        _make_state_db(home / "state", [{
            "device_id": "536776e976e67904",
            "platform": "Linux x86_64",
            "scopes": ["operator.admin", "operator.read", "operator.write"],
            "approved_scopes": ["operator.admin", "operator.read", "operator.write"],
            "tokens": {"operator": {
                "token": _token("A"), "role": "operator",
                "scopes": ["operator.admin", "operator.write"],
                "createdAtMs": 1700000000000,
            }},
            "last_seen_at_ms": 1751000000000,
        }])
        ctx = Context(home=home)
        _collect_paired_devices_sqlite(home, ctx)
        assert ctx.paired_devices_sqlite_found is True
        entry = ctx.paired_devices_sqlite["536776e976e67904"]
        assert entry["deviceId"] == "536776e976e67904"
        assert entry["platform"] == "Linux x86_64"
        assert entry["scopes"] == ["operator.admin", "operator.read", "operator.write"]
        assert entry["approvedScopes"] == ["operator.admin", "operator.read", "operator.write"]
        assert entry["lastSeenAtMs"] == 1751000000000
        assert entry["tokens"]["operator"]["role"] == "operator"
        assert entry["tokens"]["operator"]["createdAtMs"] == 1700000000000

    def test_token_secret_value_is_never_captured(self, tmp_path):
        """Defense in depth beyond the check's own never-echo logic: the collector
        itself must never let the live token secret string reach ``ctx`` at all."""
        secret = _token("B")
        home = tmp_path / "h"
        _make_state_db(home / "state", [{
            "device_id": "d1",
            "scopes": ["operator.admin"],
            "tokens": {"operator": {"token": secret, "role": "operator"}},
        }])
        ctx = Context(home=home)
        _collect_paired_devices_sqlite(home, ctx)
        entry = ctx.paired_devices_sqlite["d1"]
        assert "token" not in entry["tokens"]["operator"]
        assert secret not in json.dumps(ctx.paired_devices_sqlite)
        assert secret not in " ".join(ctx.errors)

    def test_malformed_scopes_json_does_not_crash_and_row_still_present(self, tmp_path):
        home = tmp_path / "h"
        state = home / "state"
        state.mkdir(parents=True)
        conn = sqlite3.connect(state / "openclaw.sqlite")
        conn.execute(_DEVICE_PAIRING_PAIRED_DDL)
        conn.execute(
            "INSERT INTO device_pairing_paired "
            "(device_id, public_key, scopes_json, created_at_ms, approved_at_ms) "
            "VALUES ('d1', 'pk', '{not valid json', 1700000000000, 1700000000000)"
        )
        conn.commit()
        conn.close()
        ctx = Context(home=home)
        _collect_paired_devices_sqlite(home, ctx)
        assert ctx.paired_devices_sqlite_found is True
        assert ctx.paired_devices_sqlite["d1"]["scopes"] is None

    def test_called_directly_matches_collect(self, tmp_path):
        home = tmp_path / "h"
        home.mkdir()
        (home / "openclaw.json").write_text("{}", encoding="utf-8")
        _make_state_db(home / "state", [{"device_id": "d1", "scopes": ["operator.read"]}])
        ctx = collect(home)
        assert ctx.paired_devices_sqlite_found is True
        assert "d1" in ctx.paired_devices_sqlite


# --------------------------------------------------------------------------------
# View-masquerade hardening (same B-889 shape already applied to config_machine_state
# and installed_plugin_index)
# --------------------------------------------------------------------------------


class TestViewMasqueradeHardening:
    def test_view_masquerading_as_device_pairing_paired_is_refused(self, tmp_path):
        home = tmp_path / "h"
        state = home / "state"
        state.mkdir(parents=True)
        conn = sqlite3.connect(state / "openclaw.sqlite")
        try:
            conn.execute(
                "CREATE TABLE decoy (device_id TEXT, public_key TEXT, platform TEXT, "
                "scopes_json TEXT, approved_scopes_json TEXT, tokens_json TEXT, "
                "created_at_ms INTEGER, approved_at_ms INTEGER, last_seen_at_ms INTEGER)"
            )
            conn.execute(
                "INSERT INTO decoy VALUES ('spoofed', 'pk', 'linux', "
                "'[\"operator.admin\"]', '[\"operator.admin\"]', NULL, 1, 1, NULL)"
            )
            conn.execute(
                "CREATE VIEW device_pairing_paired AS SELECT * FROM decoy"
            )
            conn.commit()
        finally:
            conn.close()

        ctx = Context(home=home)
        _collect_paired_devices_sqlite(home, ctx)
        assert ctx.paired_devices_sqlite_found is True
        assert ctx.paired_devices_sqlite_parse_error is True
        assert ctx.paired_devices_sqlite == {}
        assert any(
            "device_pairing_paired" in e and "did not resolve to a real table" in e
            for e in ctx.errors
        ), ctx.errors

    def test_a_genuine_table_still_reads_correctly_after_the_hardening(self, tmp_path):
        home = tmp_path / "h"
        _make_state_db(home / "state", [{"device_id": "d1", "scopes": ["operator.write"]}])
        ctx = Context(home=home)
        _collect_paired_devices_sqlite(home, ctx)
        assert ctx.paired_devices_sqlite_found is True
        assert ctx.paired_devices_sqlite_parse_error is False
        assert "d1" in ctx.paired_devices_sqlite


# --------------------------------------------------------------------------------
# The dual-source check: the real repro this task exists to fix
# --------------------------------------------------------------------------------


class TestB176DualSourceCheck:
    def test_the_exact_reported_defect_now_warns(self, tmp_path):
        """This task's own reproduction, shrunk to a fixture: devices/paired.json
        absent (renamed .migrated, as OpenClaw 2026.9.6 leaves it), a real paired
        device in device_pairing_paired holding a LIVE operator.admin token. Before
        this fix: a confident, unhedged PASS ("no paired devices to evaluate")."""
        home = _migrated_home(tmp_path, "h", rows=[{
            "device_id": "webchat-sqlite-device",
            "platform": "linux",
            "scopes": ["operator.admin"],
            "tokens": {"operator": {"token": _token("C"), "role": "operator"}},
            "last_seen_at_ms": 1751000000000,
        }])
        ctx = collect(home)
        finding = check_paired_device_operator_authority(ctx)
        assert finding.status == WARN, finding.detail
        assert any("webchat-sqlite-device" in e for e in finding.evidence)
        assert any("operator.admin" in e for e in finding.evidence)

    def test_migrated_install_with_only_low_scope_passes(self, tmp_path):
        """Clean-fixture control: a migrated install with a real paired device that
        holds no high-privilege scope must stay a clean PASS."""
        home = _migrated_home(tmp_path, "h", rows=[{
            "device_id": "phone-01",
            "platform": "ios",
            "approved_scopes": ["operator.read", "operator.pairing"],
        }])
        ctx = collect(home)
        finding = check_paired_device_operator_authority(ctx)
        assert finding.status == PASS, finding.detail

    def test_migrated_install_with_zero_rows_still_passes_clean(self, tmp_path):
        """The open question this task flags for review: a migrated install with the
        device_pairing_paired table present but legitimately empty (no device ever
        paired since the migration) must still report a plain, correct PASS -- not a
        new false WARN/UNKNOWN just because the table now exists."""
        home = _migrated_home(tmp_path, "h", rows=[])
        ctx = collect(home)
        finding = check_paired_device_operator_authority(ctx)
        assert finding.status == PASS, finding.detail

    def test_pre_migration_install_with_no_state_db_at_all_still_passes_clean(self, tmp_path):
        """Regression control: an install that never had either store (no
        devices/paired.json, no state DB) must behave exactly as before this fix."""
        home = tmp_path / "h"
        home.mkdir()
        (home / "openclaw.json").write_text("{}", encoding="utf-8")
        ctx = collect(home)
        finding = check_paired_device_operator_authority(ctx)
        assert finding.status == PASS, finding.detail

    def test_legacy_json_wins_outright_when_both_stores_exist(self, tmp_path):
        """Same 'legacy wins' precedent collector._collect_cron already established
        for its own JSON-vs-SQLite pair: a live (unmigrated) devices/paired.json is
        the ground truth, so a stale/decoy SQLite row must never override it."""
        home = tmp_path / "h"
        home.mkdir()
        (home / "openclaw.json").write_text("{}", encoding="utf-8")
        devices_dir = home / "devices"
        devices_dir.mkdir()
        devices_dir.joinpath("paired.json").write_text(
            json.dumps({"d1": {
                "deviceId": "json-device", "platform": "linux",
                "approvedScopes": ["operator.read"],
            }}),
            encoding="utf-8",
        )
        _make_state_db(home / "state", [{
            "device_id": "sqlite-only-device",
            "scopes": ["operator.admin"],
            "tokens": {"operator": {"token": _token("D"), "role": "operator"}},
        }])
        ctx = collect(home)
        finding = check_paired_device_operator_authority(ctx)
        # The JSON file's own (low-scope) device decides the verdict; the SQLite-only
        # high-scope device must never be consulted while the legacy file exists.
        assert finding.status == PASS, finding.detail
        assert "sqlite-only-device" not in finding.detail

    def test_revoked_token_via_sqlite_source_still_passes(self, tmp_path):
        """The SAME B-243 FP fix `test_b176_paired_device_authority.py` already pins
        for the JSON source, now exercised through the SQLite source: a device whose
        only token has been revoked holds no live authority, even though
        scopes/approvedScopes still list the historical grant."""
        home = _migrated_home(tmp_path, "h", rows=[{
            "device_id": "old-laptop",
            "platform": "linux",
            "scopes": ["operator.admin", "operator.write"],
            "approved_scopes": ["operator.admin", "operator.write"],
            "tokens": {"operator": {
                "token": _token("E"), "role": "operator",
                "createdAtMs": 1700000000000, "revokedAtMs": 1784000000000,
            }},
        }])
        ctx = collect(home)
        finding = check_paired_device_operator_authority(ctx)
        assert finding.status == PASS, finding.detail

    def test_sqlite_parse_error_reports_unknown_not_a_fake_pass(self, tmp_path):
        """A migrated install whose device_pairing_paired is present but unreadable
        (here: a masquerading view) must report UNKNOWN, never a fake PASS -- GR#4."""
        home = tmp_path / "h"
        home.mkdir()
        (home / "openclaw.json").write_text("{}", encoding="utf-8")
        devices_dir = home / "devices"
        devices_dir.mkdir()
        (devices_dir / "paired.json.migrated").write_text("{}", encoding="utf-8")
        state = home / "state"
        state.mkdir()
        conn = sqlite3.connect(state / "openclaw.sqlite")
        conn.execute("CREATE TABLE decoy (device_id TEXT)")
        conn.execute("CREATE VIEW device_pairing_paired AS SELECT * FROM decoy")
        conn.commit()
        conn.close()
        ctx = collect(home)
        finding = check_paired_device_operator_authority(ctx)
        assert finding.status == UNKNOWN, finding.detail

    def test_never_echoes_token_value_from_sqlite_source(self, tmp_path):
        secret = _token("F")
        home = _migrated_home(tmp_path, "h", rows=[{
            "device_id": "unknown-android-1",
            "platform": "android",
            "approved_scopes": ["operator.admin"],
            "tokens": {"operator": {"token": secret, "role": "operator"}},
            "last_seen_at_ms": 1784000002000,
        }])
        ctx = collect(home)
        finding = check_paired_device_operator_authority(ctx)
        assert finding.status == WARN, finding.detail
        assert secret not in finding.detail
        assert not any(secret in e for e in finding.evidence)
        assert not any("token" in e.lower() for e in finding.evidence)
