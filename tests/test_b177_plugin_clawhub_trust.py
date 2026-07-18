"""B177 (B-240): OpenClaw's OWN persisted per-plugin ClawHub trust verdict.

Grounded against the installed dist: OpenClaw persists a single-row
installed_plugin_index table (index_key='installed-plugin-index') in the shared state
SQLite database, resolved to ~/.openclaw/state/openclaw.sqlite (openclaw-state-db-
DzSsA9Ji.js: resolveOpenClawStateSqlitePath -- confirmed against the real file: SQLite
3.x, table present, schema matches exactly). Its install_records_json column is a JSON
object keyed by pluginId (installed-plugin-index-store-CWgFGnm0.js); each install
record MAY carry clawhubTrustDisposition ("clean" | "review-recommended" |
"review-required" | "blocked" -- types.openclaw-CXjMEWAQ.d.ts:1308),
clawhubTrustScanStatus, clawhubTrustModerationState, clawhubTrustReasons (string[]),
clawhubTrustPending, clawhubTrustStale (installed-plugin-index-records-C_n191FN.js:
CLAWHUB_TRUST_INSTALL_RECORD_FIELDS) -- never previously read by ClawSecCheck (grep for
"clawhubTrust"/"openclaw.sqlite" across clawseccheck/ was zero hits before this).

collector._collect_plugin_trust reads it read-only (file:...?mode=ro + PRAGMA
query_only=1), symlink-safe (reuses the same walk_dir_safely(state_dir) pattern
_collect_cron already uses for the same openclaw.sqlite file), and size/entry-capped.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_plugin_clawhub_trust
from clawseccheck.collector import collect


# ---------------------------------------------------------------------------
# Fixture helper — builds a real installed_plugin_index row matching the exact
# grounded schema (13 columns) in a temp state DB.
# ---------------------------------------------------------------------------

def _make_home(tmp_path: Path, installs: dict | None, *, with_row: bool = True,
                with_table: bool = True) -> Path:
    home = tmp_path / "home"
    (home / "state").mkdir(parents=True)
    (home / "openclaw.json").write_text("{}")
    db = home / "state" / "openclaw.sqlite"
    conn = sqlite3.connect(str(db))
    if with_table:
        conn.execute(
            "CREATE TABLE installed_plugin_index ("
            "index_key TEXT PRIMARY KEY, version INTEGER, host_contract_version TEXT, "
            "compat_registry_version TEXT, migration_version INTEGER, policy_hash TEXT, "
            "generated_at_ms INTEGER, refresh_reason TEXT, install_records_json TEXT, "
            "plugins_json TEXT, diagnostics_json TEXT, warning TEXT, updated_at_ms INTEGER)"
        )
        if with_row:
            conn.execute(
                "INSERT INTO installed_plugin_index VALUES "
                "('installed-plugin-index', 1, 'v1', 'v1', 1, 'hash', 1, NULL, ?, '[]', "
                "'[]', NULL, 1)",
                (json.dumps(installs if installs is not None else {}),),
            )
    conn.commit()
    conn.close()
    return home


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# FAIL — blocked disposition
# ---------------------------------------------------------------------------

def test_blocked_disposition_fails(tmp_path):
    home = _make_home(tmp_path, {
        "evil-plugin": {
            "clawhubTrustDisposition": "blocked",
            "clawhubTrustReasons": ["malware signature match"],
        },
    })
    r = check_plugin_clawhub_trust(collect(home))
    assert r.status == FAIL
    assert any("evil-plugin" in e and "blocked" in e for e in r.evidence)


def test_blocked_wins_over_warn_entries(tmp_path):
    home = _make_home(tmp_path, {
        "evil-plugin": {"clawhubTrustDisposition": "blocked"},
        "iffy-plugin": {"clawhubTrustDisposition": "review-required"},
    })
    r = check_plugin_clawhub_trust(collect(home))
    assert r.status == FAIL


# ---------------------------------------------------------------------------
# WARN — review-required / review-recommended / pending / stale
# ---------------------------------------------------------------------------

def test_review_required_warns(tmp_path):
    home = _make_home(tmp_path, {
        "sketchy-plugin": {"clawhubTrustDisposition": "review-required"},
    })
    r = check_plugin_clawhub_trust(collect(home))
    assert r.status == WARN
    assert any("sketchy-plugin" in e for e in r.evidence)


def test_review_recommended_warns(tmp_path):
    home = _make_home(tmp_path, {
        "meh-plugin": {"clawhubTrustDisposition": "review-recommended"},
    })
    r = check_plugin_clawhub_trust(collect(home))
    assert r.status == WARN


def test_pending_with_no_disposition_warns(tmp_path):
    home = _make_home(tmp_path, {
        "new-plugin": {"clawhubTrustPending": True},
    })
    r = check_plugin_clawhub_trust(collect(home))
    assert r.status == WARN
    assert any("pending" in e.lower() for e in r.evidence)


def test_stale_clean_verdict_warns(tmp_path):
    home = _make_home(tmp_path, {
        "old-plugin": {"clawhubTrustDisposition": "clean", "clawhubTrustStale": True},
    })
    r = check_plugin_clawhub_trust(collect(home))
    assert r.status == WARN
    assert any("stale" in e.lower() for e in r.evidence)


def test_future_unknown_disposition_value_warns_not_fails(tmp_path):
    """A disposition string OpenClaw might add later that isn't "clean"/"blocked" must
    default to WARN, never FAIL and never crash (forward-compatible)."""
    home = _make_home(tmp_path, {
        "weird-plugin": {"clawhubTrustDisposition": "quarantined-pending-review"},
    })
    r = check_plugin_clawhub_trust(collect(home))
    assert r.status == WARN


# ---------------------------------------------------------------------------
# PASS
# ---------------------------------------------------------------------------

def test_clean_disposition_passes(tmp_path):
    home = _make_home(tmp_path, {
        "good-plugin": {"clawhubTrustDisposition": "clean"},
    })
    r = check_plugin_clawhub_trust(collect(home))
    assert r.status == PASS


def test_no_trust_data_at_all_passes(tmp_path):
    """Real-world common case: an installed plugin's record has no clawhubTrust* fields
    at all (installed via a path ClawHub's trust scan never touched). No adverse
    verdict was found, so this stays PASS -- but the detail text must stay honest that
    this is absence-of-bad-verdict, not a verified-clean scan."""
    home = _make_home(tmp_path, {
        "brave": {"installPath": "/x", "version": "1.0.0", "source": "npm"},
        "codex": {"installPath": "/y", "version": "2.0.0", "source": "npm"},
    })
    r = check_plugin_clawhub_trust(collect(home))
    assert r.status == PASS
    assert "no ClawHub trust data" in r.detail


def test_empty_install_records_passes(tmp_path):
    home = _make_home(tmp_path, {})
    r = check_plugin_clawhub_trust(collect(home))
    assert r.status == PASS


# ---------------------------------------------------------------------------
# UNKNOWN — absent / no table / no row / locked-or-corrupt / malformed JSON
# ---------------------------------------------------------------------------

def test_no_state_dir_at_all_is_unknown(tmp_path):
    home = tmp_path / "home"
    home.mkdir(parents=True)
    (home / "openclaw.json").write_text("{}")
    r = check_plugin_clawhub_trust(collect(home))
    assert r.status == UNKNOWN


def test_state_db_absent_is_unknown(tmp_path):
    home = tmp_path / "home"
    (home / "state").mkdir(parents=True)
    (home / "openclaw.json").write_text("{}")
    r = check_plugin_clawhub_trust(collect(home))
    assert r.status == UNKNOWN


def test_table_absent_is_unknown_not_error(tmp_path):
    """A state DB that predates the plugin index (no such table) reads the same honest
    UNKNOWN as 'not found' -- not a parse error."""
    home = _make_home(tmp_path, None, with_table=False)
    r = check_plugin_clawhub_trust(collect(home))
    assert r.status == UNKNOWN


def test_row_absent_is_unknown(tmp_path):
    home = _make_home(tmp_path, None, with_row=False)
    r = check_plugin_clawhub_trust(collect(home))
    assert r.status == UNKNOWN


def test_corrupt_db_file_is_unknown_not_crash(tmp_path):
    home = tmp_path / "home"
    (home / "state").mkdir(parents=True)
    (home / "openclaw.json").write_text("{}")
    db = home / "state" / "openclaw.sqlite"
    db.write_bytes(b"not a sqlite database at all, just garbage bytes")
    r = check_plugin_clawhub_trust(collect(home))
    assert r.status == UNKNOWN


def test_malformed_install_records_json_is_unknown(tmp_path):
    home = tmp_path / "home"
    (home / "state").mkdir(parents=True)
    (home / "openclaw.json").write_text("{}")
    db = home / "state" / "openclaw.sqlite"
    conn = sqlite3.connect(str(db))
    conn.execute(
        "CREATE TABLE installed_plugin_index ("
        "index_key TEXT PRIMARY KEY, version INTEGER, host_contract_version TEXT, "
        "compat_registry_version TEXT, migration_version INTEGER, policy_hash TEXT, "
        "generated_at_ms INTEGER, refresh_reason TEXT, install_records_json TEXT, "
        "plugins_json TEXT, diagnostics_json TEXT, warning TEXT, updated_at_ms INTEGER)"
    )
    conn.execute(
        "INSERT INTO installed_plugin_index VALUES "
        "('installed-plugin-index', 1, 'v1', 'v1', 1, 'hash', 1, NULL, ?, '[]', '[]', "
        "NULL, 1)",
        ("{not valid json",),
    )
    conn.commit()
    conn.close()
    r = check_plugin_clawhub_trust(collect(home))
    assert r.status == UNKNOWN


def test_non_dict_install_records_json_is_unknown(tmp_path):
    home = tmp_path / "home"
    (home / "state").mkdir(parents=True)
    (home / "openclaw.json").write_text("{}")
    db = home / "state" / "openclaw.sqlite"
    conn = sqlite3.connect(str(db))
    conn.execute(
        "CREATE TABLE installed_plugin_index ("
        "index_key TEXT PRIMARY KEY, version INTEGER, host_contract_version TEXT, "
        "compat_registry_version TEXT, migration_version INTEGER, policy_hash TEXT, "
        "generated_at_ms INTEGER, refresh_reason TEXT, install_records_json TEXT, "
        "plugins_json TEXT, diagnostics_json TEXT, warning TEXT, updated_at_ms INTEGER)"
    )
    conn.execute(
        "INSERT INTO installed_plugin_index VALUES "
        "('installed-plugin-index', 1, 'v1', 'v1', 1, 'hash', 1, NULL, ?, '[]', '[]', "
        "NULL, 1)",
        (json.dumps(["not", "a", "dict"]),),
    )
    conn.commit()
    conn.close()
    r = check_plugin_clawhub_trust(collect(home))
    assert r.status == UNKNOWN


# ---------------------------------------------------------------------------
# Read-only guarantee (task caution) + secret redaction
# ---------------------------------------------------------------------------

def test_check_never_writes_to_the_sqlite_file(tmp_path):
    home = _make_home(tmp_path, {
        "good-plugin": {"clawhubTrustDisposition": "clean"},
    })
    db = home / "state" / "openclaw.sqlite"
    before = _sha(db)
    check_plugin_clawhub_trust(collect(home))
    after = _sha(db)
    assert before == after, "check must never write to the shared state database"


def test_reasons_text_is_redacted(tmp_path):
    # Assembled from fragments at runtime so no contiguous secret-shaped literal exists
    # in source (secret scanners flag literals) -- same convention as test_logsafe.py.
    secret = "api_key" + "=" + "s" * 20
    home = _make_home(tmp_path, {
        "evil-plugin": {
            "clawhubTrustDisposition": "blocked",
            "clawhubTrustReasons": [f"exfil payload contained {secret}"],
        },
    })
    r = check_plugin_clawhub_trust(collect(home))
    assert r.status == FAIL
    blob = r.detail + " ".join(r.evidence)
    assert secret not in blob
    assert "<redacted>" in blob


# ---------------------------------------------------------------------------
# Malformed / non-dict individual plugin records are skipped, not crashed on
# ---------------------------------------------------------------------------

def test_non_dict_plugin_record_is_skipped(tmp_path):
    home = _make_home(tmp_path, {
        "weird": "not-a-dict",
        "good-plugin": {"clawhubTrustDisposition": "clean"},
    })
    r = check_plugin_clawhub_trust(collect(home))
    assert r.status == PASS
