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
from clawseccheck.collector import Context, collect


# ---------------------------------------------------------------------------
# Fixture helper — builds a real installed_plugin_index row matching the exact
# grounded schema (13 columns) in a temp state DB.
# ---------------------------------------------------------------------------

def _make_home(tmp_path: Path, installs: dict | None, *, with_row: bool = True,
                with_table: bool = True, plugin_ids: list | None = None) -> Path:
    """``plugin_ids`` seeds ``plugins_json`` (the installed-plugin population, OC-82's
    ``ctx.plugin_index_records``) -- defaults to ``installs``' own keys so a plugin
    carrying a trust verdict is, by default, modelled as ACTUALLY installed (the
    C-135 orphan-record downgrade only applies when it is deliberately NOT in this
    list -- see the dedicated orphan tests below, which build ``Context`` directly)."""
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
            ids = plugin_ids if plugin_ids is not None else list((installs or {}).keys())
            plugins = [{"pluginId": pid, "origin": "bundled", "enabled": True} for pid in ids]
            conn.execute(
                "INSERT INTO installed_plugin_index VALUES "
                "('installed-plugin-index', 1, 'v1', 'v1', 1, 'hash', 1, NULL, ?, ?, "
                "'[]', NULL, 1)",
                (json.dumps(installs if installs is not None else {}), json.dumps(plugins)),
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
    # Assert the CLAIM, not one phrasing of it: the finding must disclose that no
    # ClawHub trust data exists, and must not imply a verified-clean scan.
    assert "ClawHub trust data" in r.detail
    assert "not a positive clean scan" in r.detail


def test_empty_install_records_passes(tmp_path):
    home = _make_home(tmp_path, {})
    r = check_plugin_clawhub_trust(collect(home))
    assert r.status == PASS


def test_trust_only_covers_a_fraction_of_the_plugin_population(tmp_path):
    """OC-82 (dual-shape read): the trust map is only populated for plugins that carry
    an install record, while the full installed-plugin population,
    ctx.plugin_index_records, is 61. The old "N of M" wording used
    len(plugin_trust_records) as BOTH numerator and denominator, rendering the false
    "2 of 2" -- as if only two plugins were installed at all.

    ONE record here carries an explicit 'clean' disposition and one carries none. That
    matters: a plugin having an install RECORD is not the same as it having a ClawHub
    VERDICT, and an earlier version of this test conflated them -- it gave both records
    a null disposition and then asserted "2" would appear, which would only be true if
    a bare record counted as a verdict. It does not. With one real verdict the honest
    rendering is "1 of 61 ... the other 60", and the two numbers must sum to the
    population."""
    ctx = Context(home=tmp_path)
    ctx.plugin_trust_found = True
    ctx.plugin_trust_records = [
        {"plugin_id": "brave", "disposition": "clean", "reasons": [],
         "pending": None, "stale": None},
        {"plugin_id": "codex", "disposition": None, "reasons": [],
         "pending": None, "stale": None},
    ]
    ctx.plugin_index_found = True
    ctx.plugin_index_records = [
        {"plugin_id": f"plugin-{i}", "origin": "bundled", "enabled": True,
         "contracts": {}}
        for i in range(61)
    ]
    r = check_plugin_clawhub_trust(ctx)
    assert r.status == PASS
    assert "2 of 2" not in r.detail
    # One plugin carries a verdict, 61 are installed, so 60 carry none.
    assert "1 of 61" in r.detail
    assert "60" in r.detail
    # The two halves of the sentence must be arithmetically incapable of disagreeing.
    # The bug this replaced rendered "defined for only 2 of 61 -- 61 of 61 carry no
    # ClawHub trust data", which cannot both be true; a substring check on "61" alone
    # passed it happily, so assert the SUM instead of the presence of a digit.
    import re
    pairs = [(int(a), int(b)) for a, b in re.findall(r"(\d+) of (\d+)", r.detail)]
    assert pairs, r.detail
    for numerator, denominator in pairs:
        assert numerator <= denominator, r.detail
    others = [int(n) for n in re.findall(r"the other (\d+)", r.detail)]
    for with_data, population in pairs:
        for no_data in others:
            assert with_data + no_data == population, r.detail
    # Must not read as a clean-scan claim over the whole install.
    assert "positive clean scan" in r.detail


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


# ---------------------------------------------------------------------------
# C-135 (OC-82): a "blocked" verdict is qualified against ctx.plugin_index_records --
# the plugin population OpenClaw's own index says is actually installed. See
# check_plugin_clawhub_trust docstring / _mcp.py comments for the full rationale.
# ---------------------------------------------------------------------------

def test_blocked_present_in_index_still_fails(tmp_path):
    """The unchanged case: the blocked id IS in the installed-plugin index -> FAIL."""
    ctx = Context(home=tmp_path)
    ctx.plugin_trust_found = True
    ctx.plugin_trust_records = [
        {"plugin_id": "ghost", "disposition": "blocked", "reasons": [],
         "pending": None, "stale": None},
    ]
    ctx.plugin_index_found = True
    ctx.plugin_index_records = [
        {"plugin_id": "ghost", "origin": "clawhub", "enabled": True, "contracts": {}},
    ]
    r = check_plugin_clawhub_trust(ctx)
    assert r.status == FAIL
    assert any("ghost" in e and "blocked" in e for e in r.evidence)


def test_blocked_absent_from_readable_index_warns(tmp_path):
    """The C-135 repro: the blocked id is NOT in ctx.plugin_index_records, and the
    index WAS actually readable -- OpenClaw's own tolerated orphan-record state
    (installed-plugin-index-store-C3LEu6Er.js:131-136), so this downgrades to WARN,
    and the detail must name it as not currently installed."""
    ctx = Context(home=tmp_path)
    ctx.plugin_trust_found = True
    ctx.plugin_trust_records = [
        {"plugin_id": "ghost", "disposition": "blocked", "reasons": [],
         "pending": None, "stale": None},
    ]
    ctx.plugin_index_found = True
    ctx.plugin_index_parse_error = False
    ctx.plugin_index_records = []
    r = check_plugin_clawhub_trust(ctx)
    assert r.status == WARN
    assert any(
        "ghost" in e and "not" in e and "installed-plugin index" in e for e in r.evidence
    )


def test_blocked_absent_but_index_not_found_still_fails(tmp_path):
    """Missing information must never buy silence: plugin_index_found is False, so the
    "blocked" verdict cannot be corroborated as absent -- stays FAIL."""
    ctx = Context(home=tmp_path)
    ctx.plugin_trust_found = True
    ctx.plugin_trust_records = [
        {"plugin_id": "ghost", "disposition": "blocked", "reasons": [],
         "pending": None, "stale": None},
    ]
    ctx.plugin_index_found = False
    ctx.plugin_index_records = []
    r = check_plugin_clawhub_trust(ctx)
    assert r.status == FAIL
    assert any("ghost" in e and "blocked" in e for e in r.evidence)


def test_blocked_absent_but_index_parse_error_still_fails(tmp_path):
    """Same as above, via the parse-error path rather than not-found."""
    ctx = Context(home=tmp_path)
    ctx.plugin_trust_found = True
    ctx.plugin_trust_records = [
        {"plugin_id": "ghost", "disposition": "blocked", "reasons": [],
         "pending": None, "stale": None},
    ]
    ctx.plugin_index_found = True
    ctx.plugin_index_parse_error = True
    ctx.plugin_index_records = []
    r = check_plugin_clawhub_trust(ctx)
    assert r.status == FAIL
    assert any("ghost" in e and "blocked" in e for e in r.evidence)


def test_unidentifiable_index_entry_does_not_license_a_downgrade(tmp_path):
    """An index entry with no usable id must not be silently skipped when building the
    population -- it might BE the plugin being evaluated as "absent". Stays FAIL."""
    ctx = Context(home=tmp_path)
    ctx.plugin_trust_found = True
    ctx.plugin_trust_records = [
        {"plugin_id": "ghost", "disposition": "blocked", "reasons": [],
         "pending": None, "stale": None},
    ]
    ctx.plugin_index_found = True
    ctx.plugin_index_parse_error = False
    ctx.plugin_index_records = [
        {"plugin_id": None, "origin": "clawhub", "enabled": True, "contracts": {}},
    ]
    r = check_plugin_clawhub_trust(ctx)
    assert r.status == FAIL
    assert any("ghost" in e and "blocked" in e for e in r.evidence)


def test_mixed_installed_and_orphaned_blocked_fails_naming_the_installed_one(tmp_path):
    """One blocked-and-installed + one blocked-and-orphaned -> FAIL (the installed one
    still qualifies on its own), and the FAIL evidence names the installed one with
    the unqualified blocked wording. If the orphaned one is ALSO surfaced (the
    pre-existing FAIL-evidence mechanism folds in extra WARN-level context), it must
    never appear with that same unqualified 'clawhubTrustDisposition=blocked' wording
    -- that exact string is what would make it indistinguishable from a live threat."""
    ctx = Context(home=tmp_path)
    ctx.plugin_trust_found = True
    ctx.plugin_trust_records = [
        {"plugin_id": "evil-plugin", "disposition": "blocked", "reasons": [],
         "pending": None, "stale": None},
        {"plugin_id": "ghost", "disposition": "blocked", "reasons": [],
         "pending": None, "stale": None},
    ]
    ctx.plugin_index_found = True
    ctx.plugin_index_parse_error = False
    ctx.plugin_index_records = [
        {"plugin_id": "evil-plugin", "origin": "clawhub", "enabled": True,
         "contracts": {}},
    ]
    r = check_plugin_clawhub_trust(ctx)
    assert r.status == FAIL
    assert any(
        "evil-plugin: clawhubTrustDisposition=blocked" in e for e in r.evidence
    )
    assert not any("ghost: clawhubTrustDisposition=blocked" in e for e in r.evidence)
