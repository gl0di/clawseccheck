"""OC-82: ``_collect_plugin_trust`` reads TWO observed backing shapes for the persisted
installed-plugin index.

On OpenClaw 2026.8.2 the ``installed_plugin_index`` table (B177/B-292's original source)
does not exist at all -- the ``state-consolidation-v13`` migration folded it whole into a
single ``config_machine_state`` KV row: ``state_key = 'plugins.installedIndex'``,
``value_json`` decoding to ``{"index": {"installRecords": {...}, "plugins": [...]}, ...,
"revision": <int>}``. Without a reader for that row, B177 (HIGH) and B187 reported UNKNOWN
over a populated index and --full's P7 plugin sweep was gated off entirely on this build.

Grounded against the installed dist (writer
``installed-plugin-index-store-C3LEu6Er.js:63-71``, key constant
``installed-plugin-index-store-DjwtyXoa.js:10``, reader
``installed-plugin-index-record-reader-DzjNCiwT.js:57-58``) and the vendor's own shipped
``docs/reference/database-schemas.md:213,723-741``. Measured on a real machine:
``value_json`` 82,907 bytes; ``index.installRecords`` a dict (2 entries);
``index.plugins`` a list (61 entries).

Modelled on ``tests/test_b709_cron_state_db_shapes.py`` -- calls the collector function
directly against a hand-built ``Context``/SQLite fixture, offline, writing only under
pytest's ``tmp_path``.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from clawseccheck.collector import (
    LIMIT_DOMAIN_PLUGIN,
    Context,
    _collect_plugin_trust,
    _MAX_PLUGIN_TRUST_BYTES,
    limit_hits_for,
)


def _build_home(tmp_path: Path, *, modern_row=None, legacy_row=None) -> Context:
    """Materialise a fake ~/.openclaw with a state DB holding either/both shapes.

    ``modern_row``: a Python object to json.dumps into
    ``config_machine_state.value_json`` for ``state_key = 'plugins.installedIndex'``, or a
    raw string (to test malformed/oversized JSON) when passed as ``modern_row=("raw", s)``.
    ``legacy_row``: ``(install_records_json_str, plugins_json_str)`` for the old
    ``installed_plugin_index`` table.
    """
    home = tmp_path / "openclaw"
    state = home / "state"
    state.mkdir(parents=True)
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    conn = sqlite3.connect(state / "openclaw.sqlite")
    try:
        if modern_row is not None:
            conn.execute(
                "CREATE TABLE config_machine_state "
                "(state_key TEXT PRIMARY KEY, value_json TEXT, updated_at_ms INTEGER)"
            )
            if isinstance(modern_row, tuple) and modern_row[0] == "raw":
                raw = modern_row[1]
            else:
                raw = json.dumps(modern_row)
            conn.execute(
                "INSERT INTO config_machine_state VALUES (?,?,?)",
                ("plugins.installedIndex", raw, 0),
            )
        if legacy_row is not None:
            conn.execute(
                "CREATE TABLE installed_plugin_index "
                "(index_key TEXT PRIMARY KEY, install_records_json TEXT, plugins_json TEXT)"
            )
            conn.execute(
                "INSERT INTO installed_plugin_index VALUES (?,?,?)",
                ("installed-plugin-index", legacy_row[0], legacy_row[1]),
            )
        conn.commit()
    finally:
        conn.close()
    ctx = Context(home=home)
    _collect_plugin_trust(home, ctx)
    return ctx


def _modern_index(install_records=None, plugins=None, revision=1):
    obj = {"index": {"plugins": plugins if plugins is not None else []}, "revision": revision}
    if install_records is not None:
        obj["index"]["installRecords"] = install_records
    return obj


# ---------------------------------------------------------------------------------
# 1. MODERN shape A: installRecords + plugins present, valid revision.
# ---------------------------------------------------------------------------------

def test_modern_shape_extracts_trust_and_index(tmp_path):
    modern = _modern_index(
        install_records={
            "p1": {"clawhubTrustDisposition": "clean"},
        },
        plugins=[
            {"pluginId": "p1", "origin": "bundled", "enabled": True},
            {"pluginId": "p2", "origin": "global", "enabled": False},
        ],
    )
    ctx = _build_home(tmp_path, modern_row=modern)
    assert ctx.plugin_trust_found is True
    assert ctx.plugin_trust_parse_error is False
    assert len(ctx.plugin_trust_records) == 1
    assert ctx.plugin_trust_records[0]["plugin_id"] == "p1"
    assert ctx.plugin_trust_records[0]["disposition"] == "clean"

    assert ctx.plugin_index_found is True
    assert ctx.plugin_index_parse_error is False
    assert len(ctx.plugin_index_records) == 2
    ids = {r["plugin_id"] for r in ctx.plugin_index_records}
    assert ids == {"p1", "p2"}


# ---------------------------------------------------------------------------------
# 2. A "blocked" disposition survives with the SAME dict keys the legacy path produced.
# ---------------------------------------------------------------------------------

def test_blocked_disposition_same_shape_as_legacy(tmp_path):
    modern = _modern_index(
        install_records={
            "bad-plugin": {
                "clawhubTrustDisposition": "blocked",
                "clawhubTrustScanStatus": "scanned",
                "clawhubTrustModerationState": "flagged",
                "clawhubTrustReasons": ["malware-signature"],
                "clawhubTrustPending": False,
                "clawhubTrustStale": False,
            },
        },
        plugins=[{"pluginId": "bad-plugin", "origin": "global", "enabled": True}],
    )
    ctx = _build_home(tmp_path, modern_row=modern)
    assert len(ctx.plugin_trust_records) == 1
    rec = ctx.plugin_trust_records[0]
    assert rec == {
        "plugin_id": "bad-plugin",
        "disposition": "blocked",
        "scan_status": "scanned",
        "moderation_state": "flagged",
        "reasons": ["malware-signature"],
        "pending": False,
        "stale": False,
    }


# ---------------------------------------------------------------------------------
# 3. FALLBACK leg: no installRecords key, plugins[*].installRecord present.
# ---------------------------------------------------------------------------------

def test_fallback_assembles_from_plugins_installrecord(tmp_path):
    modern = _modern_index(
        install_records=None,
        plugins=[
            {
                "pluginId": "p1",
                "origin": "bundled",
                "enabled": True,
                "installRecord": {"clawhubTrustDisposition": "review-recommended"},
            },
            {"pluginId": "p2", "origin": "bundled", "enabled": True},
        ],
    )
    ctx = _build_home(tmp_path, modern_row=modern)
    assert ctx.plugin_trust_found is True
    assert ctx.plugin_trust_parse_error is False
    assert len(ctx.plugin_trust_records) == 1
    assert ctx.plugin_trust_records[0]["plugin_id"] == "p1"
    assert ctx.plugin_trust_records[0]["disposition"] == "review-recommended"
    # index side still sees both plugins regardless of the trust fallback
    assert len(ctx.plugin_index_records) == 2


# ---------------------------------------------------------------------------------
# 4. revision non-numeric (a string) -> unusable: found + parse_error, not silently
#    ignored, and NOT falling back to legacy.
# ---------------------------------------------------------------------------------

def test_non_numeric_revision_is_unusable_not_absent(tmp_path):
    modern = {
        "index": {"installRecords": {"p1": {"clawhubTrustDisposition": "clean"}},
                   "plugins": [{"pluginId": "p1"}]},
        "revision": "1",
    }
    legacy = (
        json.dumps({"legacy-plugin": {"clawhubTrustDisposition": "clean"}}),
        json.dumps([{"pluginId": "legacy-plugin", "origin": "bundled"}]),
    )
    ctx = _build_home(tmp_path, modern_row=modern, legacy_row=legacy)
    assert ctx.plugin_trust_found is True
    assert ctx.plugin_trust_parse_error is True
    assert ctx.plugin_index_found is True
    assert ctx.plugin_index_parse_error is True
    # Never fell back to the legacy row that was ALSO present.
    assert ctx.plugin_trust_records == []
    assert ctx.plugin_index_records == []


# ---------------------------------------------------------------------------------
# 5. value_json is not valid JSON -> found + parse_error.
# ---------------------------------------------------------------------------------

def test_invalid_json_value_is_unusable(tmp_path):
    ctx = _build_home(tmp_path, modern_row=("raw", "{not valid json"))
    assert ctx.plugin_trust_found is True
    assert ctx.plugin_trust_parse_error is True
    assert ctx.plugin_index_found is True
    assert ctx.plugin_index_parse_error is True
    assert ctx.plugin_trust_records == []
    assert ctx.plugin_index_records == []


# ---------------------------------------------------------------------------------
# 6. LEGACY shape only (no config_machine_state table at all) -> unchanged behaviour.
# ---------------------------------------------------------------------------------

def test_legacy_shape_unchanged(tmp_path):
    legacy = (
        json.dumps({"p1": {"clawhubTrustDisposition": "clean"}}),
        json.dumps([{"pluginId": "p1", "origin": "bundled", "enabled": True}]),
    )
    ctx = _build_home(tmp_path, modern_row=None, legacy_row=legacy)
    assert ctx.plugin_trust_found is True
    assert ctx.plugin_trust_parse_error is False
    assert ctx.plugin_trust_records == [{
        "plugin_id": "p1",
        "disposition": "clean",
        "scan_status": None,
        "moderation_state": None,
        "reasons": [],
        "pending": None,
        "stale": None,
    }]
    assert ctx.plugin_index_found is True
    assert ctx.plugin_index_parse_error is False
    assert len(ctx.plugin_index_records) == 1
    assert ctx.plugin_index_records[0]["plugin_id"] == "p1"


# ---------------------------------------------------------------------------------
# 7. BOTH shapes present -> A (modern) wins.
# ---------------------------------------------------------------------------------

def test_both_present_modern_wins(tmp_path):
    modern = _modern_index(
        install_records={"modern-plugin": {"clawhubTrustDisposition": "clean"}},
        plugins=[{"pluginId": "modern-plugin", "origin": "bundled", "enabled": True}],
    )
    legacy = (
        json.dumps({"legacy-plugin": {"clawhubTrustDisposition": "blocked"}}),
        json.dumps([{"pluginId": "legacy-plugin", "origin": "global"}]),
    )
    ctx = _build_home(tmp_path, modern_row=modern, legacy_row=legacy)
    assert len(ctx.plugin_trust_records) == 1
    assert ctx.plugin_trust_records[0]["plugin_id"] == "modern-plugin"
    assert len(ctx.plugin_index_records) == 1
    assert ctx.plugin_index_records[0]["plugin_id"] == "modern-plugin"


# ---------------------------------------------------------------------------------
# 8. NEITHER present -> both *_found False, UNKNOWN preserved, nothing invented.
# ---------------------------------------------------------------------------------

def test_neither_shape_present_stays_unknown(tmp_path):
    ctx = _build_home(tmp_path, modern_row=None, legacy_row=None)
    assert ctx.plugin_trust_found is False
    assert ctx.plugin_trust_parse_error is False
    assert ctx.plugin_index_found is False
    assert ctx.plugin_index_parse_error is False
    assert ctx.plugin_trust_records == []
    assert ctx.plugin_index_records == []


# ---------------------------------------------------------------------------------
# 9. Disclosure fires when installRecords < plugins; does NOT fire when they match.
# ---------------------------------------------------------------------------------

def test_disclosure_fires_when_install_records_short_of_plugins(tmp_path):
    modern = _modern_index(
        install_records={"p1": {"clawhubTrustDisposition": "clean"}},
        plugins=[
            {"pluginId": "p1", "origin": "bundled"},
            {"pluginId": "p2", "origin": "bundled"},
            {"pluginId": "p3", "origin": "bundled"},
        ],
    )
    ctx = _build_home(tmp_path, modern_row=modern)
    hits = limit_hits_for(ctx, LIMIT_DOMAIN_PLUGIN)
    assert any("lists 3 plugin(s)" in h and "only 1" in h for h in hits), hits


def test_disclosure_does_not_fire_when_counts_match(tmp_path):
    modern = _modern_index(
        install_records={
            "p1": {"clawhubTrustDisposition": "clean"},
            "p2": {"clawhubTrustDisposition": "clean"},
        },
        plugins=[
            {"pluginId": "p1", "origin": "bundled"},
            {"pluginId": "p2", "origin": "bundled"},
        ],
    )
    ctx = _build_home(tmp_path, modern_row=modern)
    hits = limit_hits_for(ctx, LIMIT_DOMAIN_PLUGIN)
    assert not any("only" in h and "verdict is only defined" in h for h in hits), hits


# ---------------------------------------------------------------------------------
# 10. Oversized value_json (over the byte cap) -> parse_error + disclosure, NO partial
#     parse attempted.
# ---------------------------------------------------------------------------------

def test_oversized_value_json_no_partial_parse(tmp_path):
    # A valid-JSON prefix followed by padding that pushes it over the cap, WITHOUT
    # closing the object -- if the code ever slice-then-parsed this, json.loads would
    # raise on the truncated document; if it doesn't even attempt to parse, we still see
    # parse_error=True via the byte-cap branch, and no records are invented either way.
    padding = "x" * (_MAX_PLUGIN_TRUST_BYTES + 1000)
    raw = '{"index": {"installRecords": {}, "plugins": []}, "revision": 1, "pad": "' + padding + '"}'
    assert len(raw) > _MAX_PLUGIN_TRUST_BYTES
    ctx = _build_home(tmp_path, modern_row=("raw", raw))
    assert ctx.plugin_trust_found is True
    assert ctx.plugin_trust_parse_error is True
    assert ctx.plugin_index_found is True
    assert ctx.plugin_index_parse_error is True
    assert ctx.plugin_trust_records == []
    assert ctx.plugin_index_records == []
    hits = limit_hits_for(ctx, LIMIT_DOMAIN_PLUGIN)
    assert any("exceeded the" in h and "cap" in h for h in hits), hits
