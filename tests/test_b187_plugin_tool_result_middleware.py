"""B187 (B-292, RT-2): non-bundled plugin declares agentToolResultMiddleware.

OpenClaw exposes a plugin contract, agentToolResultMiddleware, whose registered handlers
transform tool results at runtime (agent-tool-result-middleware-loader-BsZPH_qG.js:
loadAgentToolResultMiddlewaresForRuntime / listAgentToolResultMiddlewares). A plugin
holding this contract can rewrite ANY tool output before it reaches the model.

The sibling installed_plugin_index.plugins_json column (same row, same state DB as
B177's install_records_json) carries the full per-plugin index record, including
contributions.contracts (installed-plugin-index-N4jxqS0-.js:1241-1256
buildContributionInfo -- contract values normalized to sorted-unique STRING ids only).

THE MASS-FALSE-POSITIVE TRAP this check exists to avoid: on a real 69-plugin stock
install, 67 plugins are origin="bundled" and 47 of the 69 already contribute at least one
contract of some kind -- an ungated "a plugin declares a contract" would WARN on every
clean machine. The check MUST gate on origin != "bundled".

Two attack narratives are deliberately NOT implemented (refuted by the persisted schema,
see collector.py's _collect_plugin_trust docstring): contributions.providers carries no
baseURL field (B178 covers the real provider-baseURL surface elsewhere), and
commandAliases is normalized to the alias NAME only -- the mapping target is stripped
before persistence.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_plugin_tool_result_middleware
from clawseccheck.collector import collect


# ---------------------------------------------------------------------------
# Fixture helpers — build a real installed_plugin_index row (13-column schema, matching
# test_b177_plugin_clawhub_trust.py's grounded DDL) with a populated plugins_json array.
# ---------------------------------------------------------------------------

def _plugin_rec(plugin_id: str, *, origin: str = "bundled", enabled: bool = True,
                contracts: dict | None = None, omit_contributions: bool = False) -> dict:
    """One installed_plugin_index.plugins_json array entry, matching the grounded shape
    buildInstalledPluginIndexRecords/buildContributionInfo produce in the dist."""
    rec = {
        "pluginId": plugin_id,
        "manifestPath": f"/plugins/{plugin_id}/openclaw.plugin.json",
        "manifestHash": "deadbeef" * 4,
        "source": f"/plugins/{plugin_id}/index.js",
        "rootDir": f"/plugins/{plugin_id}",
        "origin": origin,
        "enabled": enabled,
        "startup": {
            "sidecar": False, "memory": False,
            "deferConfiguredChannelFullLoadUntilAfterListen": False,
            "agentHarnesses": [], "configPaths": [],
        },
        "compat": [],
    }
    if not omit_contributions:
        rec["contributions"] = {
            "channels": [], "channelConfigs": [], "providers": [],
            "modelCatalogProviders": [], "modelSupportPrefixes": [],
            "modelSupportPatterns": [], "autoEnableProviderIds": [],
            "commandAliases": [], "contracts": contracts or {},
        }
    return rec


def _make_home(tmp_path: Path, plugins: list | None, *, installs: dict | None = None,
                with_row: bool = True, with_table: bool = True,
                plugins_json_raw: str | None = None) -> Path:
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
            plugins_json = (
                plugins_json_raw if plugins_json_raw is not None
                else json.dumps(plugins if plugins is not None else [])
            )
            conn.execute(
                "INSERT INTO installed_plugin_index VALUES "
                "('installed-plugin-index', 1, 'v1', 'v1', 1, 'hash', 1, NULL, ?, ?, "
                "'[]', NULL, 1)",
                (json.dumps(installs if installs is not None else {}), plugins_json),
            )
    conn.commit()
    conn.close()
    return home


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# PASS — the mass-false-positive guard (GR#5)
# ---------------------------------------------------------------------------

def test_stock_install_bundled_plugins_with_contracts_no_finding(tmp_path):
    """Pins origin != "bundled" as the gate: a bundled plugin holding
    agentToolResultMiddleware itself (and several other bundled plugins holding assorted
    OTHER contracts, mirroring the real 47-of-69 stock-install shape) must NOT warn."""
    plugins = [
        _plugin_rec("active-memory", origin="bundled", contracts={}),
        _plugin_rec("web-search-core", origin="bundled",
                    contracts={"webSearchProviders": ["core"]}),
        _plugin_rec("media-core", origin="bundled",
                    contracts={"imageGenerationProviders": ["core"], "tools": ["gen"]}),
        # Even a BUNDLED plugin holding the exact contract under test must not fire --
        # bundled ships with the dist itself, not a third-party supply-chain surface.
        _plugin_rec("bundled-result-shaper", origin="bundled",
                    contracts={"agentToolResultMiddleware": ["shape"]}),
    ]
    r = check_plugin_tool_result_middleware(collect(_make_home(tmp_path, plugins)))
    assert r.status == PASS


def test_non_bundled_plugin_without_middleware_contract_no_finding(tmp_path):
    plugins = [
        _plugin_rec("brave", origin="global",
                    contracts={"webSearchProviders": ["brave"]}),
        _plugin_rec("codex", origin="global",
                    contracts={"webSearchProviders": ["codex"], "tools": ["codex_threads"]}),
    ]
    r = check_plugin_tool_result_middleware(collect(_make_home(tmp_path, plugins)))
    assert r.status == PASS


def test_empty_plugins_json_passes(tmp_path):
    r = check_plugin_tool_result_middleware(collect(_make_home(tmp_path, [])))
    assert r.status == PASS


# ---------------------------------------------------------------------------
# WARN — non-bundled plugin declares the contract
# ---------------------------------------------------------------------------

def test_non_bundled_plugin_with_middleware_warns(tmp_path):
    plugins = [
        _plugin_rec("brave", origin="global", contracts={"webSearchProviders": ["brave"]}),
        _plugin_rec("sneaky-plugin", origin="global", enabled=True,
                    contracts={"agentToolResultMiddleware": ["rewrite-results"]}),
    ]
    r = check_plugin_tool_result_middleware(collect(_make_home(tmp_path, plugins)))
    assert r.status == WARN
    assert any("sneaky-plugin" in e for e in r.evidence)
    assert any("origin=global" in e for e in r.evidence)
    # Capability disclosure wording only -- never a malice claim.
    assert "malice" not in r.detail.lower() or "not proof of malice" in r.fix.lower()
    assert "proof of malice" not in r.detail.lower()


def test_disabled_non_bundled_plugin_reflected_in_evidence(tmp_path):
    plugins = [
        _plugin_rec("dormant-plugin", origin="local", enabled=False,
                    contracts={"agentToolResultMiddleware": []}),
    ]
    r = check_plugin_tool_result_middleware(collect(_make_home(tmp_path, plugins)))
    assert r.status == WARN
    assert any("dormant-plugin" in e and "disabled" in e for e in r.evidence)


def test_evidence_capped_with_overflow_count(tmp_path):
    plugins = [
        _plugin_rec(f"rogue-{i}", origin="global",
                    contracts={"agentToolResultMiddleware": []})
        for i in range(9)
    ]
    r = check_plugin_tool_result_middleware(collect(_make_home(tmp_path, plugins)))
    assert r.status == WARN
    assert len(r.evidence) <= 6
    assert "+3 more" in r.detail


# ---------------------------------------------------------------------------
# REFUTED NARRATIVES: providers/commandAliases presence must never be treated as this
# check's business -- only agentToolResultMiddleware is examined.
# ---------------------------------------------------------------------------

def test_non_bundled_provider_or_alias_contribution_alone_does_not_warn(tmp_path):
    plugins = [
        _plugin_rec("brave", origin="global", contracts={
            "webSearchProviders": ["brave"],
        }),
        _plugin_rec("codex", origin="global", contracts={
            "webSearchProviders": ["codex"], "migrationProviders": ["codex"],
        }),
    ]
    r = check_plugin_tool_result_middleware(collect(_make_home(tmp_path, plugins)))
    assert r.status == PASS


# ---------------------------------------------------------------------------
# Malformed / partial records are skipped, not crashed on
# ---------------------------------------------------------------------------

def test_non_dict_plugin_record_is_skipped(tmp_path):
    plugins_raw = json.dumps([
        "not-a-dict",
        _plugin_rec("good-plugin", origin="global", contracts={"webSearchProviders": ["x"]}),
    ])
    home = _make_home(tmp_path, None, plugins_json_raw=plugins_raw)
    r = check_plugin_tool_result_middleware(collect(home))
    assert r.status == PASS


def test_record_missing_contributions_is_treated_as_no_contracts(tmp_path):
    plugins = [_plugin_rec("bare-plugin", origin="global", omit_contributions=True)]
    r = check_plugin_tool_result_middleware(collect(_make_home(tmp_path, plugins)))
    assert r.status == PASS


def test_record_missing_origin_is_not_treated_as_bundled(tmp_path):
    """A record with no origin field at all must not be silently exempted -- the gate is
    specifically origin != "bundled", and None != "bundled"."""
    rec = _plugin_rec("no-origin-plugin", contracts={"agentToolResultMiddleware": []})
    del rec["origin"]
    home = _make_home(tmp_path, [rec])
    r = check_plugin_tool_result_middleware(collect(home))
    assert r.status == WARN


# ---------------------------------------------------------------------------
# UNKNOWN — absent / no table / no row / locked-or-corrupt / malformed JSON
# ---------------------------------------------------------------------------

def test_no_state_dir_at_all_is_unknown(tmp_path):
    home = tmp_path / "home"
    home.mkdir(parents=True)
    (home / "openclaw.json").write_text("{}")
    r = check_plugin_tool_result_middleware(collect(home))
    assert r.status == UNKNOWN


def test_state_db_absent_is_unknown(tmp_path):
    home = tmp_path / "home"
    (home / "state").mkdir(parents=True)
    (home / "openclaw.json").write_text("{}")
    r = check_plugin_tool_result_middleware(collect(home))
    assert r.status == UNKNOWN


def test_table_absent_is_unknown_not_error(tmp_path):
    home = _make_home(tmp_path, None, with_table=False)
    r = check_plugin_tool_result_middleware(collect(home))
    assert r.status == UNKNOWN


def test_row_absent_is_unknown(tmp_path):
    home = _make_home(tmp_path, None, with_row=False)
    r = check_plugin_tool_result_middleware(collect(home))
    assert r.status == UNKNOWN


def test_corrupt_db_file_is_unknown_not_crash(tmp_path):
    home = tmp_path / "home"
    (home / "state").mkdir(parents=True)
    (home / "openclaw.json").write_text("{}")
    db = home / "state" / "openclaw.sqlite"
    db.write_bytes(b"not a sqlite database at all, just garbage bytes")
    r = check_plugin_tool_result_middleware(collect(home))
    assert r.status == UNKNOWN


def test_malformed_plugins_json_is_unknown(tmp_path):
    home = _make_home(tmp_path, None, plugins_json_raw="{not valid json")
    r = check_plugin_tool_result_middleware(collect(home))
    assert r.status == UNKNOWN


def test_non_list_plugins_json_is_unknown(tmp_path):
    """plugins_json is documented as a JSON ARRAY -- a dict (or any other non-list shape)
    is a genuine schema surprise, not a zero-plugin install."""
    home = _make_home(tmp_path, None, plugins_json_raw=json.dumps({"not": "a list"}))
    r = check_plugin_tool_result_middleware(collect(home))
    assert r.status == UNKNOWN


def test_null_plugins_json_cell_is_unknown(tmp_path):
    home = _make_home(tmp_path, None, plugins_json_raw="null")
    r = check_plugin_tool_result_middleware(collect(home))
    assert r.status == UNKNOWN


# ---------------------------------------------------------------------------
# Independence from B177 (both columns live on the same row, same connection)
# ---------------------------------------------------------------------------

def test_b187_and_b177_both_populate_from_the_same_row(tmp_path):
    from clawseccheck.checks import check_plugin_clawhub_trust

    plugins = [_plugin_rec("sneaky-plugin", origin="global",
                            contracts={"agentToolResultMiddleware": []})]
    installs = {"sneaky-plugin": {"clawhubTrustDisposition": "clean"}}
    home = _make_home(tmp_path, plugins, installs=installs)
    ctx = collect(home)
    assert check_plugin_tool_result_middleware(ctx).status == WARN
    assert check_plugin_clawhub_trust(ctx).status == PASS  # clean disposition, no relation


def test_b177_survives_plugins_json_column_being_entirely_absent(tmp_path):
    """B-292/RT-2 round 2: a table that has install_records_json (B177) populated but is
    genuinely missing the plugins_json column (an unexpected schema shape -- not one any
    known OpenClaw version ships, since the real CREATE TABLE declares both columns
    together, but not proven impossible for a hand-modified or pre-existing older table)
    must NOT blind B177's reader. A single merged SELECT previously failed as a whole on
    "no such column: plugins_json" and took ctx.plugin_trust_found down with it -- the two
    columns' reads must be independent even when one column is missing outright, not just
    when one cell's JSON is corrupt."""
    from clawseccheck.checks import check_plugin_clawhub_trust

    home = tmp_path / "home"
    (home / "state").mkdir(parents=True)
    (home / "openclaw.json").write_text("{}")
    db = home / "state" / "openclaw.sqlite"
    conn = sqlite3.connect(str(db))
    # Deliberately NO plugins_json column at all -- only install_records_json exists.
    conn.execute(
        "CREATE TABLE installed_plugin_index ("
        "index_key TEXT PRIMARY KEY, install_records_json TEXT)"
    )
    conn.execute(
        "INSERT INTO installed_plugin_index VALUES ('installed-plugin-index', ?)",
        (json.dumps({"some-plugin": {"clawhubTrustDisposition": "blocked"}}),),
    )
    conn.commit()
    conn.close()

    ctx = collect(home)
    # B177 (install_records_json) must succeed fully despite the missing sibling column.
    trust_result = check_plugin_clawhub_trust(ctx)
    assert trust_result.status == FAIL  # "blocked" disposition, read intact
    assert ctx.plugin_trust_found is True
    assert ctx.plugin_trust_parse_error is False
    # B187 (plugins_json) correctly degrades to UNKNOWN -- its own column is truly absent.
    assert check_plugin_tool_result_middleware(ctx).status == UNKNOWN


# ---------------------------------------------------------------------------
# Read-only guarantee
# ---------------------------------------------------------------------------

def test_check_never_writes_to_the_sqlite_file(tmp_path):
    plugins = [_plugin_rec("sneaky-plugin", origin="global",
                            contracts={"agentToolResultMiddleware": []})]
    home = _make_home(tmp_path, plugins)
    db = home / "state" / "openclaw.sqlite"
    before = _sha(db)
    check_plugin_tool_result_middleware(collect(home))
    after = _sha(db)
    assert before == after, "check must never write to the shared state database"
