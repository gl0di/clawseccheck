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
import resource
import sqlite3
from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_paired_device_operator_authority
from clawseccheck.collector import (
    Context,
    _MAX_PAIRED_DEVICE_JSON_BYTES,
    _MAX_PAIRED_DEVICES,
    _collect_paired_devices_sqlite,
    collect,
)

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
# C-135 round 1 (2026-09-25): the size-cap hardening. A single row with a 50MB
# tokens_json string was fetched and processed whole, no cap, no truncation, no
# disclosure -- the same DoS class trajectorystore's own `length(CAST(... AS BLOB))
# <= ?` bound exists to close for trajectory_runtime_events (B-811).
# --------------------------------------------------------------------------------


class TestSizeCapHardening:
    def test_oversized_tokens_json_is_excluded_not_silently_absent(self, tmp_path):
        """The reviewer's own repro, shrunk: an oversized tokens_json must be excluded
        from the result (never parsed, never partially trusted) AND disclosed via
        ctx.errors as "present but not read" -- never silently absent as if the
        device had never existed (GR#4)."""
        oversized_tokens = json.dumps({
            "operator": {"token": "x" * (_MAX_PAIRED_DEVICE_JSON_BYTES + 1_000)}
        })
        home = tmp_path / "h"
        _make_state_db(home / "state", [{
            "device_id": "oversized-device",
            "scopes": ["operator.admin"],
            "tokens": {"operator": {"token": "irrelevant"}},
        }])
        # Overwrite with the raw oversized tokens_json directly (json.dumps of a huge
        # nested dict via _make_state_db's own dict->json.dumps path is equivalent,
        # but writing the raw string keeps this test's intent explicit).
        conn = sqlite3.connect(home / "state" / "openclaw.sqlite")
        conn.execute(
            "UPDATE device_pairing_paired SET tokens_json = ? WHERE device_id = ?",
            (oversized_tokens, "oversized-device"),
        )
        conn.commit()
        conn.close()

        ctx = Context(home=home)
        _collect_paired_devices_sqlite(home, ctx)
        assert ctx.paired_devices_sqlite_found is True
        assert ctx.paired_devices_sqlite_parse_error is False
        assert "oversized-device" not in ctx.paired_devices_sqlite
        assert any(
            "device_pairing_paired" in e and "were not read" in e for e in ctx.errors
        ), ctx.errors
        # The disclosure names a COUNT, never the oversized value itself.
        assert not any(str(_MAX_PAIRED_DEVICE_JSON_BYTES + 1_000) in e for e in ctx.errors)
        assert oversized_tokens not in " ".join(ctx.errors)

    def test_a_normal_sibling_row_is_still_read_despite_an_oversized_one(self, tmp_path):
        """Fault isolation: one oversized row must not blind the reader to every
        OTHER, well-formed row -- the same per-row isolation `_collect_subagent_runs`
        already established for its own bad rows."""
        oversized_tokens = json.dumps({"operator": {"token": "x" * (_MAX_PAIRED_DEVICE_JSON_BYTES + 1)}})
        home = tmp_path / "h"
        state = home / "state"
        _make_state_db(state, [{"device_id": "normal-device", "scopes": ["operator.write"]}])
        conn = sqlite3.connect(state / "openclaw.sqlite")
        conn.execute(
            "INSERT INTO device_pairing_paired "
            "(device_id, public_key, scopes_json, tokens_json, created_at_ms, approved_at_ms) "
            "VALUES ('oversized-device', 'pk', '[\"operator.admin\"]', ?, 1700000000000, 1700000000000)",
            (oversized_tokens,),
        )
        conn.commit()
        conn.close()

        ctx = Context(home=home)
        _collect_paired_devices_sqlite(home, ctx)
        assert "normal-device" in ctx.paired_devices_sqlite
        assert "oversized-device" not in ctx.paired_devices_sqlite

        # And the check itself still WARNs off the normal device's own high scope.
        (home / "openclaw.json").write_text("{}", encoding="utf-8")
        ctx2 = collect(home)
        finding = check_paired_device_operator_authority(ctx2)
        assert finding.status == WARN, finding.detail
        assert any("normal-device" in e for e in finding.evidence)

    def test_oversized_value_never_materializes_in_python_memory(self, tmp_path):
        """The concrete DoS proof: a 50MB tokens_json string must never be fully
        fetched into this process -- RSS growth stays far under the payload size,
        the same `resource.getrusage` proof
        `test_f187_trajectory_sqlite_corroborator.py` already uses for the SAME
        SQL-level-bound defense on a sibling table."""
        payload_bytes = 50_000_000
        oversized_tokens = json.dumps({"operator": {"token": "x" * payload_bytes}})
        home = tmp_path / "h"
        _make_state_db(home / "state", [{"device_id": "d1", "scopes": ["operator.write"]}])
        conn = sqlite3.connect(home / "state" / "openclaw.sqlite")
        conn.execute(
            "UPDATE device_pairing_paired SET tokens_json = ? WHERE device_id = 'd1'",
            (oversized_tokens,),
        )
        conn.commit()
        conn.close()
        del oversized_tokens  # drop this process's own copy before measuring

        before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        ctx = Context(home=home)
        _collect_paired_devices_sqlite(home, ctx)
        after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

        assert "d1" not in ctx.paired_devices_sqlite
        grew_kb = after - before
        # Generous ceiling: a tenth of the oversized payload. A pre-fix reader would
        # materialize the whole ~50MB string via fetchall(); the SQL-level bound
        # should keep this reader's own growth to a small, constant-ish amount.
        assert grew_kb < (payload_bytes // 1024) // 10, (
            f"RSS grew {grew_kb} KB reading a {payload_bytes // 1_000_000}MB oversized "
            "tokens_json -- looks like the value is still being materialized whole"
        )

    def test_row_count_is_capped_and_truncation_is_disclosed(self, tmp_path):
        rows = [
            {"device_id": f"device-{i:04d}", "scopes": ["operator.read"]}
            for i in range(_MAX_PAIRED_DEVICES + 1)
        ]
        home = tmp_path / "h"
        _make_state_db(home / "state", rows)
        ctx = Context(home=home)
        _collect_paired_devices_sqlite(home, ctx)
        assert ctx.paired_devices_sqlite_found is True
        assert len(ctx.paired_devices_sqlite) == _MAX_PAIRED_DEVICES
        assert any(
            f"more than {_MAX_PAIRED_DEVICES}" in e for e in ctx.errors
        ), ctx.errors

    def test_row_count_under_the_cap_is_not_flagged_as_truncated(self, tmp_path):
        rows = [
            {"device_id": f"device-{i:04d}", "scopes": ["operator.read"]}
            for i in range(3)
        ]
        home = tmp_path / "h"
        _make_state_db(home / "state", rows)
        ctx = Context(home=home)
        _collect_paired_devices_sqlite(home, ctx)
        assert len(ctx.paired_devices_sqlite) == 3
        assert not any("more than" in e for e in ctx.errors)

    def test_token_subkey_allowlist_drops_an_unknown_future_field(self, tmp_path):
        """The bundled, cheap fix: an allowlist, not a denylist. A hypothetical
        future vendor sub-field (e.g. refreshToken) must be dropped by default, not
        silently ride along just because it isn't literally named `token`."""
        home = tmp_path / "h"
        _make_state_db(home / "state", [{
            "device_id": "d1",
            "scopes": ["operator.admin"],
            "tokens": {"operator": {
                "token": "secret-value",
                "role": "operator",
                "refreshToken": "also-secret-shaped",
                "deviceFingerprint": "unexpected-future-field",
                "revokedAtMs": 1784000000000,
            }},
        }])
        ctx = Context(home=home)
        _collect_paired_devices_sqlite(home, ctx)
        survived = ctx.paired_devices_sqlite["d1"]["tokens"]["operator"]
        assert survived == {"role": "operator", "revokedAtMs": 1784000000000}
        assert "token" not in survived
        assert "refreshToken" not in survived
        assert "deviceFingerprint" not in survived


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

    def test_padded_high_scope_device_yields_unknown_not_a_silent_pass(self, tmp_path):
        """C-135 round 2's own repro: an attacker who already has write access to
        state/openclaw.sqlite pads their OWN high-scope paired device's tokens_json
        just over the size cap. Before this fix that device was silently excluded
        with only an un-consulted ctx.errors note, and the check fell through to a
        confident PASS ("no paired devices to evaluate") -- exactly the evasion this
        fix closes. The device is the ONLY row, so if it had been read whole it
        would have been a genuine WARN naming operator.admin; excluded, it must be
        UNKNOWN, never PASS."""
        padded_tokens = json.dumps({"operator": {
            "token": "irrelevant-would-never-be-echoed-anyway",
            "role": "operator",
            "padding": "x" * (_MAX_PAIRED_DEVICE_JSON_BYTES + 1_000),
        }})
        home = _migrated_home(tmp_path, "h", rows=[{
            "device_id": "attacker-padded-device",
            "platform": "linux",
            "scopes": ["operator.admin", "operator.write"],
            "tokens": {"operator": {"token": "placeholder"}},
        }])
        conn = sqlite3.connect(home / "state" / "openclaw.sqlite")
        conn.execute(
            "UPDATE device_pairing_paired SET tokens_json = ? WHERE device_id = ?",
            (padded_tokens, "attacker-padded-device"),
        )
        conn.commit()
        conn.close()

        ctx = collect(home)
        # The collector's own side of the fix: the padded row is excluded, not
        # silently trusted, and a size-cap hit is recorded where the check can see it.
        assert "attacker-padded-device" not in ctx.paired_devices_sqlite
        from clawseccheck.collector import LIMIT_DOMAIN_PAIRED, limit_hits_for
        assert limit_hits_for(ctx, LIMIT_DOMAIN_PAIRED)

        finding = check_paired_device_operator_authority(ctx)
        assert finding.status == UNKNOWN, (
            f"expected UNKNOWN once the padded high-scope device was excluded by the "
            f"size cap, got {finding.status}: {finding.detail}"
        )
        assert finding.status != PASS

    def test_padded_high_scope_device_among_low_scope_siblings_still_yields_unknown(
        self, tmp_path
    ):
        """Same evasion, but with a legitimate low-scope device also present -- so
        the padded device's exclusion does not empty ctx.paired_devices_sqlite
        outright, it only removes it from the per-entry evaluation loop. This
        exercises the SECOND verdict-by-absence branch (the final "none of the
        devices read hold high-privilege authority" PASS), not the first ("no
        devices at all")."""
        padded_tokens = json.dumps({"operator": {
            "token": "irrelevant", "padding": "x" * (_MAX_PAIRED_DEVICE_JSON_BYTES + 1_000),
        }})
        home = _migrated_home(tmp_path, "h", rows=[
            {
                "device_id": "legit-low-scope-phone",
                "platform": "ios",
                "approved_scopes": ["operator.read"],
            },
            {
                "device_id": "attacker-padded-device",
                "platform": "linux",
                "scopes": ["operator.admin"],
                "tokens": {"operator": {"token": "placeholder"}},
            },
        ])
        conn = sqlite3.connect(home / "state" / "openclaw.sqlite")
        conn.execute(
            "UPDATE device_pairing_paired SET tokens_json = ? WHERE device_id = ?",
            (padded_tokens, "attacker-padded-device"),
        )
        conn.commit()
        conn.close()

        ctx = collect(home)
        assert "legit-low-scope-phone" in ctx.paired_devices_sqlite
        assert "attacker-padded-device" not in ctx.paired_devices_sqlite

        finding = check_paired_device_operator_authority(ctx)
        assert finding.status == UNKNOWN, (
            f"expected UNKNOWN -- one low-scope device was read cleanly, but the "
            f"padded high-scope device was excluded by the size cap, got "
            f"{finding.status}: {finding.detail}"
        )
        assert finding.status != PASS

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
