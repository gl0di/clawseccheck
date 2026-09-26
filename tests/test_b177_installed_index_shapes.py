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


def _modern_index(install_records=None, plugins=None, revision=1, index_overrides=None):
    """Build a ``{"index": {...}, "revision": ...}`` object that passes
    ``collector._plugin_index_object_is_valid`` by default -- the SAME nine ``index``
    fields the real (2026.8.2) machine carries, per B177's C-135 hardening. Pass
    ``index_overrides`` to deliberately break/omit one for a negative test.
    """
    index_obj = {
        "version": 1,
        "hostContractVersion": "2026.8.2",
        "compatRegistryVersion": "v1",
        "migrationVersion": 1,
        "policyHash": "hash",
        "generatedAtMs": 1,
        "plugins": plugins if plugins is not None else [],
        "diagnostics": [],
    }
    if install_records is not None:
        index_obj["installRecords"] = install_records
    if index_overrides:
        index_obj.update(index_overrides)
    return {"index": index_obj, "revision": revision}


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


# ---------------------------------------------------------------------------------
# 11. C-135 hardening: a row the runtime's OWN parser would reject (missing
#     policyHash, or a non-1 version) must be present-and-unusable, not trusted.
# ---------------------------------------------------------------------------------

def test_index_missing_policy_hash_is_unusable_not_trusted(tmp_path):
    modern = _modern_index(
        install_records={"p1": {"clawhubTrustDisposition": "clean"}},
        plugins=[{"pluginId": "p1"}],
        index_overrides={"policyHash": None},
    )
    ctx = _build_home(tmp_path, modern_row=modern)
    assert ctx.plugin_trust_found is True
    assert ctx.plugin_trust_parse_error is True
    assert ctx.plugin_index_found is True
    assert ctx.plugin_index_parse_error is True
    assert ctx.plugin_trust_records == []
    assert ctx.plugin_index_records == []


def test_index_wrong_version_is_unusable_not_trusted(tmp_path):
    modern = _modern_index(
        install_records={"p1": {"clawhubTrustDisposition": "clean"}},
        plugins=[{"pluginId": "p1"}],
        index_overrides={"version": 2},
    )
    ctx = _build_home(tmp_path, modern_row=modern)
    assert ctx.plugin_trust_found is True
    assert ctx.plugin_trust_parse_error is True
    assert ctx.plugin_index_found is True
    assert ctx.plugin_index_parse_error is True
    assert ctx.plugin_trust_records == []
    assert ctx.plugin_index_records == []


# ---------------------------------------------------------------------------------
# 12. B-990: view-masquerade hardening -- config_machine_state resolving to a VIEW (or
#     other non-table schema object) must be refused, not silently treated as absent
#     (which would wrongly fall through to the legacy B/C probes) and not silently
#     trusted for its spoofed content.
# ---------------------------------------------------------------------------------

class TestB990ViewMasqueradeHardening:
    """CLAWSECCHECK-B-990 -- Probe A's own ``SELECT value_json FROM config_machine_state
    WHERE state_key = ?`` ran directly against ``state/openclaw.sqlite`` without first
    checking the name resolves to a real TABLE, not a VIEW -- the identical attack shape
    ``trajectorystore._table_kind`` was hardened against for ``trajectory_runtime_events``
    (B-811), and already fixed for this file's two sibling ``config_machine_state``
    readers, ``_collect_auth_profile_store_presence`` (B-889) and
    ``_collect_config_machine_state`` (B-977). This reader reuses
    ``trajectorystore._table_kind`` verbatim via ``collector.py``'s existing
    ``_trajectorystore`` module import.

    Worse than B-889 here: that sibling only ever selected ``LENGTH(value_json)``, an
    integer, so a successful spoof could only flip a presence/length signal. This reader
    selects and RETURNS the parsed ``value_json`` CONTENT (the full
    ``plugins.installedIndex`` row), so a successful spoof can inject an attacker-chosen
    plugin trust/index record straight into ``ctx.plugin_trust_records`` /
    ``ctx.plugin_index_records`` -- and from there into B177's FAIL evidence, B187's
    tool-result-interception WARN, and the SBOM's plugin-supplier attribution -- the same
    content-injection severity class B-977 documented, not B-889's bounded presence-only
    one."""

    def test_a_view_masquerading_as_config_machine_state_is_refused(self, tmp_path):
        """The bug's own reproduction: a decoy table plus a VIEW named
        ``config_machine_state`` that projects a spoofed ``plugins.installedIndex`` row.
        Before the fix this landed straight into ``ctx.plugin_trust_found`` /
        ``ctx.plugin_index_found`` sourced from a table this reader never named, with no
        disclosure at all. After the fix the row must be refused outright -- not
        silently trusted, and not silently merged into the quieter 'table predates this
        feature' absent case (which would instead leave both ``*_found`` flags False,
        with no matching legacy table present here to fall through to)."""
        home = tmp_path / "openclaw"
        state = home / "state"
        state.mkdir(parents=True)
        (home / "openclaw.json").write_text("{}", encoding="utf-8")

        spoofed_index = json.dumps({
            "index": {
                "version": 1, "hostContractVersion": "x", "compatRegistryVersion": "v1",
                "migrationVersion": 1, "policyHash": "h", "generatedAtMs": 1,
                "installRecords": {}, "plugins": [], "diagnostics": [],
            },
            "revision": 1,
        })

        conn = sqlite3.connect(state / "openclaw.sqlite")
        try:
            conn.execute(
                "CREATE TABLE decoy_plugin_state "
                "(decoy_key TEXT, decoy_value TEXT, updated_at_ms INTEGER)"
            )
            conn.execute(
                "INSERT INTO decoy_plugin_state VALUES (?, ?, ?)",
                ("plugins.installedIndex", spoofed_index, 0),
            )
            conn.execute(
                "CREATE VIEW config_machine_state AS "
                "SELECT decoy_key AS state_key, decoy_value AS value_json "
                "FROM decoy_plugin_state"
            )
            conn.commit()
        finally:
            conn.close()

        ctx = Context(home=home)
        _collect_plugin_trust(home, ctx)

        assert ctx.plugin_trust_found is True
        assert ctx.plugin_trust_parse_error is True
        assert ctx.plugin_trust_records == []
        assert ctx.plugin_index_found is True
        assert ctx.plugin_index_parse_error is True
        assert ctx.plugin_index_records == []
        assert any(
            "config_machine_state" in e and "did not resolve to a real table" in e
            for e in ctx.errors
        ), ctx.errors

    def test_a_genuine_table_still_reads_correctly_after_the_hardening(self, tmp_path):
        """Clean-fixture control: an ordinary, honest ``config_machine_state`` TABLE
        (the real shape every fleet machine has) must still be read exactly as before --
        the hardening must not turn every legitimate Probe A read into a refusal."""
        modern = _modern_index(
            install_records={"p1": {"clawhubTrustDisposition": "clean"}},
            plugins=[{"pluginId": "p1", "origin": "bundled", "enabled": True}],
        )
        ctx = _build_home(tmp_path, modern_row=modern)
        assert ctx.plugin_trust_found is True
        assert ctx.plugin_trust_parse_error is False
        assert len(ctx.plugin_trust_records) == 1
        assert ctx.plugin_index_found is True
        assert ctx.plugin_index_parse_error is False
        assert not any(
            "did not resolve to a real table" in e for e in ctx.errors
        ), ctx.errors

    def test_absent_config_machine_state_still_falls_through_to_legacy(self, tmp_path):
        """Regression guard for the ONE structural difference from B-889/B-977: here,
        'absent' must still fall through to the legacy B/C probes, not just return
        UNDETERMINED -- the schema-kind check added above must not disturb that
        fallback. Same fixture shape as ``test_legacy_shape_unchanged`` above,
        exercised again here so the view-masquerade hardening and its boundary with
        the absent case are pinned together in one place."""
        legacy = (
            json.dumps({"p1": {"clawhubTrustDisposition": "clean"}}),
            json.dumps([{"pluginId": "p1", "origin": "bundled", "enabled": True}]),
        )
        ctx = _build_home(tmp_path, modern_row=None, legacy_row=legacy)
        assert ctx.plugin_trust_found is True
        assert ctx.plugin_trust_parse_error is False
        assert len(ctx.plugin_trust_records) == 1
        assert ctx.plugin_trust_records[0]["plugin_id"] == "p1"
        assert ctx.plugin_index_found is True
        assert ctx.plugin_index_parse_error is False
        assert not any(
            "did not resolve to a real table" in e for e in ctx.errors
        ), ctx.errors


# ---------------------------------------------------------------------------------
# 13. B-994: the SAME view-masquerade hardening, applied to Probes B/C's own table
#     (installed_plugin_index) -- unaudited by B-990, which only covered Probe A's
#     config_machine_state. Reached only once Probe A (config_machine_state) is
#     genuinely absent, since B/C are never consulted otherwise.
# ---------------------------------------------------------------------------------

class TestB994ViewMasqueradeHardening:
    """B-994 -- Probes B/C's own ``SELECT install_records_json /
    plugins_json FROM installed_plugin_index WHERE index_key = ...`` ran directly
    against ``state/openclaw.sqlite`` without ever checking that ``installed_plugin_index``
    resolves to a real TABLE, not a VIEW -- the identical attack shape B-990 closed for
    Probe A's ``config_machine_state``, left unaudited for this table specifically
    because B-990's own scope was Probe A only. Reuses
    ``trajectorystore._table_kind`` verbatim, and reuses the SAME already-open
    transaction Probe A's own ``BEGIN`` opened (no second ``BEGIN`` -- SQLite refuses a
    nested one on an already-open connection), so the TOCTOU-closing property extends
    across both probes, not just Probe A's.

    Same content-injection severity class as B-990: this reader selects and RETURNS the
    parsed ``install_records_json``/``plugins_json`` CONTENT, so a successful spoof can
    inject an attacker-chosen plugin trust/index record straight into
    ``ctx.plugin_trust_records``/``ctx.plugin_index_records`` -- and from there into
    B177's FAIL evidence, B187's tool-result-interception WARN, and the SBOM's
    plugin-supplier attribution."""

    def test_a_view_masquerading_as_installed_plugin_index_is_refused(self, tmp_path):
        """The bug's own reproduction: a decoy table plus a VIEW named
        ``installed_plugin_index`` that projects a spoofed install_records_json/
        plugins_json pair. No ``config_machine_state`` table exists at all, so Probe A
        is genuinely absent and Probes B/C are reached. Before the fix this landed
        straight into ``ctx.plugin_trust_found``/``ctx.plugin_index_found`` sourced from
        a table this reader never named, with no disclosure at all. After the fix the
        row must be refused outright -- not silently trusted, and not silently merged
        into the quieter 'table predates this feature' absent case."""
        home = tmp_path / "openclaw"
        state = home / "state"
        state.mkdir(parents=True)
        (home / "openclaw.json").write_text("{}", encoding="utf-8")

        spoofed_trust = json.dumps({"evil-plugin": {"clawhubTrustDisposition": "clean"}})
        spoofed_index = json.dumps([{"pluginId": "evil-plugin", "origin": "bundled"}])

        conn = sqlite3.connect(state / "openclaw.sqlite")
        try:
            conn.execute(
                "CREATE TABLE decoy_plugin_index "
                "(decoy_key TEXT, decoy_install_records TEXT, decoy_plugins TEXT)"
            )
            conn.execute(
                "INSERT INTO decoy_plugin_index VALUES (?, ?, ?)",
                ("installed-plugin-index", spoofed_trust, spoofed_index),
            )
            conn.execute(
                "CREATE VIEW installed_plugin_index AS "
                "SELECT decoy_key AS index_key, "
                "decoy_install_records AS install_records_json, "
                "decoy_plugins AS plugins_json "
                "FROM decoy_plugin_index"
            )
            conn.commit()
        finally:
            conn.close()

        ctx = Context(home=home)
        _collect_plugin_trust(home, ctx)

        assert ctx.plugin_trust_found is True
        assert ctx.plugin_trust_parse_error is True
        assert ctx.plugin_trust_records == []
        assert ctx.plugin_index_found is True
        assert ctx.plugin_index_parse_error is True
        assert ctx.plugin_index_records == []
        assert any(
            "installed_plugin_index" in e and "did not resolve to a real table" in e
            for e in ctx.errors
        ), ctx.errors

    def test_a_genuine_legacy_table_still_reads_correctly_after_the_hardening(self, tmp_path):
        """Clean-fixture control: an ordinary, honest ``installed_plugin_index`` TABLE
        (the real shape a pre-OC-82 or mid-migration machine has) must still be read
        exactly as before -- the hardening must not turn every legitimate Probes B/C
        read into a refusal."""
        legacy = (
            json.dumps({"p1": {"clawhubTrustDisposition": "clean"}}),
            json.dumps([{"pluginId": "p1", "origin": "bundled", "enabled": True}]),
        )
        ctx = _build_home(tmp_path, modern_row=None, legacy_row=legacy)
        assert ctx.plugin_trust_found is True
        assert ctx.plugin_trust_parse_error is False
        assert len(ctx.plugin_trust_records) == 1
        assert ctx.plugin_index_found is True
        assert ctx.plugin_index_parse_error is False
        assert not any(
            "did not resolve to a real table" in e for e in ctx.errors
        ), ctx.errors

    def test_absent_installed_plugin_index_stays_quiet_unknown(self, tmp_path):
        """Regression guard: NEITHER config_machine_state NOR installed_plugin_index
        exists at all (a state DB predating both shapes) -- the clean-slate case this
        function has always handled (test_neither_shape_present_stays_unknown above)
        must stay a quiet UNKNOWN, with no NEW disclosure introduced by this hardening.
        The `_table_kind` check must resolve 'absent' here and fall through exactly as
        the existing per-SELECT 'no such table' handling already did."""
        ctx = _build_home(tmp_path, modern_row=None, legacy_row=None)
        assert ctx.plugin_trust_found is False
        assert ctx.plugin_trust_parse_error is False
        assert ctx.plugin_index_found is False
        assert ctx.plugin_index_parse_error is False
        assert ctx.plugin_trust_records == []
        assert ctx.plugin_index_records == []
        assert not any(
            "did not resolve to a real table" in e for e in ctx.errors
        ), ctx.errors
