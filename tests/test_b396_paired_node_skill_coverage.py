"""B396 -- paired-node skills outside this audit's skill content scan (coverage
disclosure).

See `clawseccheck.checks._lifecycle.check_paired_node_skill_coverage`'s own preceding
comment block and docstring for the full dist grounding (openclaw@2026.9.6,
2026-09-26). This file covers: the collector's three new columns
(role/roles_json/node_surface_json) in isolation, the five on-disk fixtures, the
modelled (>=2026.9.6) admission predicate over adversarial near-misses, the gate/deny
short-circuits, the legacy devices/paired.json + nodes/paired.json migration-merge
fold, the unmodelled (pre-2026.9.6) over-approximation, and fingerprint/privacy
hygiene.

Offline, read-only, stdlib only -- writes only under pytest's tmp_path, never touches
a real ~/.openclaw.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from clawseccheck.catalog import BY_ID, FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    CHECKS,
    _b396_admission_state,
    _b396_approved_state,
    _b396_build_modelled,
    _b396_js_truthy,
    _b396_legacy_record_valid,
    _b396_node_candidate,
    _b396_read_legacy_store,
    _b396_role_list,
    _b396_safe_int,
    _b396_surface_state,
    check_paired_device_operator_authority,
    check_paired_node_skill_coverage,
)
from clawseccheck.collector import (
    LIMIT_DOMAIN_PAIRED,
    Context,
    _MAX_PAIRED_DEVICE_JSON_BYTES,
    _collect_paired_devices_sqlite,
    collect,
    limit_hits_for,
)

# Reused rather than duplicated -- same precedent as test_f184_retired_key_config_invalid.py
# importing from test_b700_version_aware_advice (pytest puts tests/ on sys.path).
from test_b176_paired_devices_sqlite_migration import _make_state_db, _token

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_MODELLED = "2026.9.6"
_UNMODELLED = "2026.9.5"


def _cfg_home(tmp_path: Path, name: str, cfg: dict | None = None) -> Path:
    home = tmp_path / name
    home.mkdir(parents=True, exist_ok=True)
    (home / "openclaw.json").write_text(
        json.dumps(cfg if cfg is not None else {"meta": {"lastTouchedVersion": _MODELLED}}),
        encoding="utf-8",
    )
    return home


def _write_devices(home: Path, data: dict) -> None:
    d = home / "devices"
    d.mkdir(parents=True, exist_ok=True)
    (d / "paired.json").write_text(json.dumps(data), encoding="utf-8")


def _write_nodes(home: Path, data) -> None:
    d = home / "nodes"
    d.mkdir(parents=True, exist_ok=True)
    (d / "paired.json").write_text(
        data if isinstance(data, str) else json.dumps(data), encoding="utf-8"
    )


def _node_row(
    device_id="node1", platform="darwin", role="node", roles=None,
    token_role="node", revoked_at=None, node_surface=None, created=1, approved=1,
):
    tokens = {"node": {"token": _token("N"), "role": token_role}}
    if revoked_at is not None:
        tokens["node"]["revokedAtMs"] = revoked_at
    rec = {
        "deviceId": device_id, "publicKey": "REDACTED", "platform": platform,
        "clientId": "node-host", "clientMode": "node",
        "role": role, "roles": roles if roles is not None else ([role] if role else []),
        "scopes": [], "tokens": tokens,
        "createdAtMs": created, "approvedAtMs": approved,
    }
    if node_surface is not None:
        rec["nodeSurface"] = node_surface
    return rec


def _operator_row(device_id="operator1"):
    return {
        "deviceId": device_id, "publicKey": "REDACTED", "platform": "web",
        "clientId": "clawwebchat", "clientMode": "normal",
        "role": "operator", "roles": ["operator"],
        "scopes": ["operator.read"], "approvedScopes": ["operator.read"],
        "tokens": {"operator": {"token": _token("O")}},
        "createdAtMs": 1, "approvedAtMs": 1,
    }


def _sqlite_home(
    tmp_path: Path, name: str, cfg: dict | None, row: tuple | None,
    installed: "str | None" = _MODELLED,
) -> Context:
    """A home with a real device_pairing_paired row, collected via collect()."""
    home = _cfg_home(tmp_path, name, cfg)
    if row is not None:
        _make_state_db(home / "state", [])  # ensure table exists even with 0 explicit rows
        conn = sqlite3.connect(home / "state" / "openclaw.sqlite")
        conn.execute(
            "INSERT INTO device_pairing_paired "
            "(device_id, public_key, platform, role, roles_json, tokens_json, "
            "node_surface_json, created_at_ms, approved_at_ms) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            row,
        )
        conn.commit()
        conn.close()
    ctx = collect(home)
    if installed is not None:
        ctx.installed_dist_version = installed
    else:
        ctx.installed_dist_version = None
    return ctx


def _row(
    device_id="node1", platform="darwin", role="node", roles_json='["node"]',
    tokens_json=None, node_surface_json='{"commands": ["system.run"]}',
    created=1, approved=1,
):
    if tokens_json is None:
        tokens_json = json.dumps({"node": {"token": _token("N"), "role": "node"}})
    return (device_id, "REDACTED", platform, role, roles_json, tokens_json,
            node_surface_json, created, approved)


# ============================================================================
# Collector: role / roles_json / node_surface_json normalisation
# ============================================================================


class TestCollectorNormalisation:
    def test_role_roles_nodesurface_are_normalised(self, tmp_path):
        home = tmp_path / "h"
        _make_state_db(home / "state", [])
        conn = sqlite3.connect(home / "state" / "openclaw.sqlite")
        conn.execute(
            "INSERT INTO device_pairing_paired (device_id, public_key, role, "
            "roles_json, node_surface_json, created_at_ms, approved_at_ms) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("d1", "pk", "node", json.dumps(["node"]),
             json.dumps({"commands": ["system.run"], "displayName": "evil",
                         "bins": ["/bin/x"]}), 1, 1),
        )
        conn.commit()
        conn.close()
        ctx = Context(home=home)
        _collect_paired_devices_sqlite(home, ctx)
        entry = ctx.paired_devices_sqlite["d1"]
        assert entry["role"] == "node"
        assert entry["roles"] == ["node"]
        assert entry["nodeSurface"] == {"commands": ["system.run"]}
        assert "displayName" not in entry["nodeSurface"]
        assert "bins" not in entry["nodeSurface"]

    def test_null_columns_give_none(self, tmp_path):
        home = tmp_path / "h"
        _make_state_db(home / "state", [{"device_id": "d1", "scopes": ["operator.read"]}])
        ctx = Context(home=home)
        _collect_paired_devices_sqlite(home, ctx)
        entry = ctx.paired_devices_sqlite["d1"]
        assert entry["role"] is None
        assert entry["roles"] is None
        assert entry["nodeSurface"] is None
        assert entry["rolesUnparsed"] is False
        assert entry["nodeSurfaceUnparsed"] is False
        assert entry["tokensUnparsed"] is False

    def test_invalid_json_sets_unparsed_flags_tokens_unchanged(self, tmp_path):
        home = tmp_path / "h"
        _make_state_db(home / "state", [])
        conn = sqlite3.connect(home / "state" / "openclaw.sqlite")
        conn.execute(
            "INSERT INTO device_pairing_paired (device_id, public_key, roles_json, "
            "tokens_json, node_surface_json, created_at_ms, approved_at_ms) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("d1", "pk", "{not valid", "{not valid", "{not valid", 1, 1),
        )
        conn.commit()
        conn.close()
        ctx = Context(home=home)
        _collect_paired_devices_sqlite(home, ctx)
        entry = ctx.paired_devices_sqlite["d1"]
        assert entry["rolesUnparsed"] is True
        assert entry["nodeSurfaceUnparsed"] is True
        assert entry["tokensUnparsed"] is True
        assert entry["tokens"] == {}  # B176's own `tokens` shape is unchanged: {} on parse failure

    def test_node_surface_scalar_truthiness(self, tmp_path):
        home = tmp_path / "h"
        _make_state_db(home / "state", [])
        conn = sqlite3.connect(home / "state" / "openclaw.sqlite")
        for i, (raw, expected) in enumerate([('"5"', {}), ("0", None), ("null", None),
                                              ('""', None), ("true", {}), ("false", None)]):
            conn.execute(
                "INSERT INTO device_pairing_paired (device_id, public_key, "
                "node_surface_json, created_at_ms, approved_at_ms) VALUES (?, ?, ?, ?, ?)",
                (f"d{i}", "pk", raw, 1, 1),
            )
        conn.commit()
        conn.close()
        ctx = Context(home=home)
        _collect_paired_devices_sqlite(home, ctx)
        for i, (raw, expected) in enumerate([('"5"', {}), ("0", None), ("null", None),
                                              ('""', None), ("true", {}), ("false", None)]):
            assert ctx.paired_devices_sqlite[f"d{i}"]["nodeSurface"] == expected, raw

    def test_deeply_nested_json_sets_unparsed_not_a_crash(self, tmp_path):
        home = tmp_path / "h"
        _make_state_db(home / "state", [])
        nested = ("[" * 50_000) + ("]" * 50_000)  # deep enough to blow the C json decoder's stack
        assert len(nested) < _MAX_PAIRED_DEVICE_JSON_BYTES
        conn = sqlite3.connect(home / "state" / "openclaw.sqlite")
        conn.execute(
            "INSERT INTO device_pairing_paired (device_id, public_key, "
            "node_surface_json, created_at_ms, approved_at_ms) VALUES (?, ?, ?, ?, ?)",
            ("d1", "pk", nested, 1, 1),
        )
        conn.commit()
        conn.close()
        ctx = Context(home=home)
        _collect_paired_devices_sqlite(home, ctx)  # must not raise RecursionError
        entry = ctx.paired_devices_sqlite["d1"]
        assert entry["nodeSurfaceUnparsed"] is True
        assert entry["nodeSurface"] is None

    def test_oversized_role_or_nodesurface_excludes_row_and_degrades_b176(self, tmp_path):
        home = tmp_path / "h"
        _make_state_db(home / "state", [{
            "device_id": "highscope", "scopes": ["operator.admin"],
            "tokens": {"operator": {"token": _token("X")}},
        }])
        oversized = json.dumps({"commands": ["x" * (_MAX_PAIRED_DEVICE_JSON_BYTES + 10)]})
        conn = sqlite3.connect(home / "state" / "openclaw.sqlite")
        conn.execute(
            "UPDATE device_pairing_paired SET node_surface_json = ? WHERE device_id = ?",
            (oversized, "highscope"),
        )
        conn.commit()
        conn.close()
        ctx = Context(home=home)
        _collect_paired_devices_sqlite(home, ctx)
        assert "highscope" not in ctx.paired_devices_sqlite
        assert limit_hits_for(ctx, LIMIT_DOMAIN_PAIRED)

        (home / "openclaw.json").write_text("{}", encoding="utf-8")
        ctx2 = collect(home)
        b176 = check_paired_device_operator_authority(ctx2)
        assert b176.status == UNKNOWN, b176.detail  # B176 must degrade too (shared cap)
        b396 = check_paired_node_skill_coverage(ctx2)
        assert b396.status == UNKNOWN
        assert b396.engine_degraded is True

    def test_capped_state_dir_walk_degrades_both_checks(self, tmp_path):
        home = tmp_path / "h"
        state = home / "state"
        state.mkdir(parents=True)
        for i in range(150):
            (state / f"file{i:04d}.txt").write_text("x")
        (home / "openclaw.json").write_text("{}", encoding="utf-8")
        ctx = collect(home)
        assert limit_hits_for(ctx, LIMIT_DOMAIN_PAIRED)
        b176 = check_paired_device_operator_authority(ctx)
        assert b176.status == UNKNOWN, b176.detail
        b396 = check_paired_node_skill_coverage(ctx)
        assert b396.status == UNKNOWN
        assert b396.engine_degraded is True

    def test_token_secret_never_captured_via_new_columns(self, tmp_path):
        secret = _token("Z")
        home = tmp_path / "h"
        _make_state_db(home / "state", [{
            "device_id": "d1", "platform": "darwin", "scopes": [],
            "tokens": {"node": {"token": secret, "role": "node"}},
        }])
        conn = sqlite3.connect(home / "state" / "openclaw.sqlite")
        conn.execute(
            "UPDATE device_pairing_paired SET role = 'node', roles_json = '[\"node\"]', "
            "node_surface_json = '{\"commands\": [\"system.run\"]}' WHERE device_id = 'd1'"
        )
        conn.commit()
        conn.close()
        (home / "openclaw.json").write_text(
            json.dumps({"meta": {"lastTouchedVersion": _MODELLED}}), encoding="utf-8"
        )
        ctx = collect(home)
        assert secret not in json.dumps(ctx.paired_devices_sqlite)
        finding = check_paired_node_skill_coverage(ctx)
        assert finding.status == WARN, finding.detail
        assert secret not in finding.detail
        assert not any(secret in e for e in finding.evidence)


# ============================================================================
# On-disk fixtures
# ============================================================================


class TestFixtures:
    def test_bad_fixture_warns_via_the_fold(self):
        ctx = collect(FIXTURES / "bad_b396_paired_node_skills")
        f = check_paired_node_skill_coverage(ctx)
        assert f.id == "B396"
        assert f.status == WARN, f.detail
        assert any("node-studio-b396" in e for e in f.evidence)
        assert "REDACTED" not in f.detail
        assert not any(e.startswith("/") or "/home/" in e for e in f.evidence)

    def test_clean_allowskills_off_passes_gate(self):
        ctx = collect(FIXTURES / "clean_b396_allowskills_off")
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == PASS, f.detail
        assert f.pass_confidence == "verified"

    def test_clean_node_without_system_run_passes(self):
        ctx = collect(FIXTURES / "clean_b396_node_without_system_run")
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == PASS, f.detail
        assert "1 paired node record" in f.detail

    def test_clean_no_paired_node_passes(self):
        ctx = collect(FIXTURES / "clean_b396_no_paired_node")
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == PASS, f.detail
        assert "No paired node found" in f.detail

    def test_unknown_malformed_node_store_is_unknown_not_degraded(self):
        ctx = collect(FIXTURES / "unknown_b396_malformed_node_store")
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == UNKNOWN, f.detail
        assert f.engine_degraded is False

    def test_never_fails_on_any_fixture(self):
        for name in (
            "bad_b396_paired_node_skills", "clean_b396_allowskills_off",
            "clean_b396_node_without_system_run", "clean_b396_no_paired_node",
            "unknown_b396_malformed_node_store",
        ):
            ctx = collect(FIXTURES / name)
            f = check_paired_node_skill_coverage(ctx)
            assert f.status != FAIL


# ============================================================================
# SQLite, modelled (installed >= 2026.9.6)
# ============================================================================


class TestModelledSqlite:
    def test_capable_node_warns(self, tmp_path):
        ctx = _sqlite_home(tmp_path, "h", None, _row())
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == WARN, f.detail

    def test_revoked_token_passes(self, tmp_path):
        row = _row(tokens_json=json.dumps(
            {"node": {"token": _token("N"), "role": "node", "revokedAtMs": 999}}
        ))
        ctx = _sqlite_home(tmp_path, "h", None, row)
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == PASS, f.detail

    def test_operator_role_with_node_role_token_passes(self, tmp_path):
        # role/roles say operator, but SOME token entry carries role "node" with no
        # matching approved role -> admission "no" (approved_state says "no").
        row = _row(role="operator", roles_json='["operator"]',
                    tokens_json=json.dumps({"x": {"token": _token("N"), "role": "node"}}))
        ctx = _sqlite_home(tmp_path, "h", None, row)
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == PASS, f.detail

    def test_no_tokens_node_key_but_another_entry_has_role_node_passes(self, tmp_path):
        # approved_state("node") is yes (role="node"), but the ONLY live token key is
        # "operator" (no "node" key at all) -> admission state "no": tokens.node absent.
        row = _row(role="node", roles_json='["node"]',
                    tokens_json=json.dumps({"operator": {"token": _token("O"), "role": "node"}}))
        ctx = _sqlite_home(tmp_path, "h", None, row)
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == PASS, f.detail

    def test_roles_json_as_bare_string_counts_as_node(self, tmp_path):
        row = _row(role=None, roles_json='"node"')
        ctx = _sqlite_home(tmp_path, "h", None, row)
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == WARN, f.detail

    def test_surface_command_with_leading_space_still_warns(self, tmp_path):
        row = _row(node_surface_json=json.dumps({"commands": [" system.run"]}))
        ctx = _sqlite_home(tmp_path, "h", None, row)
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == WARN, f.detail  # over-approximation direction, pinned

    def test_surface_commands_as_bare_string_is_unknown(self, tmp_path):
        row = _row(node_surface_json=json.dumps({"commands": "system.run"}))
        ctx = _sqlite_home(tmp_path, "h", None, row)
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == UNKNOWN, f.detail

    def test_nodesurface_unparsed_plus_admissible_node_is_unknown(self, tmp_path):
        row = _row(node_surface_json="{not valid")
        ctx = _sqlite_home(tmp_path, "h", None, row)
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == UNKNOWN, f.detail
        assert f.engine_degraded is False

    def test_nodesurface_unparsed_plus_operator_no_node_token_passes(self, tmp_path):
        row = _row(device_id="op1", role="operator", roles_json='["operator"]',
                    tokens_json=json.dumps({"operator": {"token": _token("O")}}),
                    node_surface_json="{not valid")
        ctx = _sqlite_home(tmp_path, "h", None, row)
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == PASS, f.detail  # decisive negative (admission "no") wins

    def test_limit_hit_with_no_capable_row_read_is_unknown_degraded(self, tmp_path):
        home = _cfg_home(tmp_path, "h", None)
        _make_state_db(home / "state", [{"device_id": "low", "scopes": ["operator.read"]}])
        oversized = json.dumps({"x": "y" * (_MAX_PAIRED_DEVICE_JSON_BYTES + 10)})
        conn = sqlite3.connect(home / "state" / "openclaw.sqlite")
        conn.execute(
            "INSERT INTO device_pairing_paired (device_id, public_key, role, "
            "roles_json, tokens_json, node_surface_json, created_at_ms, approved_at_ms) "
            "VALUES ('padded', 'pk', 'node', '[\"node\"]', ?, "
            "'{\"commands\": [\"system.run\"]}', 1, 1)",
            (oversized,),
        )
        conn.commit()
        conn.close()
        ctx = collect(home)
        ctx.installed_dist_version = _MODELLED
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == UNKNOWN, f.detail
        assert f.engine_degraded is True

    def test_limit_hit_plus_a_capable_read_row_still_warns(self, tmp_path):
        home = _cfg_home(tmp_path, "h", None)
        conn_rows = [_row(device_id="capable")]
        _make_state_db(home / "state", [])
        conn = sqlite3.connect(home / "state" / "openclaw.sqlite")
        conn.execute(
            "INSERT INTO device_pairing_paired (device_id, public_key, platform, role, "
            "roles_json, tokens_json, node_surface_json, created_at_ms, approved_at_ms) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            conn_rows[0],
        )
        oversized = json.dumps({"x": "y" * (_MAX_PAIRED_DEVICE_JSON_BYTES + 10)})
        conn.execute(
            "INSERT INTO device_pairing_paired (device_id, public_key, role, "
            "roles_json, tokens_json, node_surface_json, created_at_ms, approved_at_ms) "
            "VALUES ('padded', 'pk', 'node', '[\"node\"]', ?, "
            "'{\"commands\": [\"system.run\"]}', 1, 1)",
            (oversized,),
        )
        conn.commit()
        conn.close()
        ctx = collect(home)
        ctx.installed_dist_version = _MODELLED
        assert limit_hits_for(ctx, LIMIT_DOMAIN_PAIRED)
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == WARN, f.detail  # a WARN found in what WAS read stands

    def test_sqlite_parse_error_is_unknown_not_degraded(self, tmp_path):
        home = _cfg_home(tmp_path, "h", None)
        state = home / "state"
        state.mkdir()
        conn = sqlite3.connect(state / "openclaw.sqlite")
        conn.execute("CREATE TABLE decoy (device_id TEXT)")
        conn.execute("CREATE VIEW device_pairing_paired AS SELECT * FROM decoy")
        conn.commit()
        conn.close()
        ctx = collect(home)
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == UNKNOWN, f.detail
        assert f.engine_degraded is False

    def test_gate_closed_config_with_parse_error_store_still_passes_gate_first(self, tmp_path):
        home = _cfg_home(
            tmp_path, "h",
            {"meta": {"lastTouchedVersion": _MODELLED},
             "gateway": {"nodes": {"allowSkills": False}}},
        )
        state = home / "state"
        state.mkdir()
        conn = sqlite3.connect(state / "openclaw.sqlite")
        conn.execute("CREATE TABLE decoy (device_id TEXT)")
        conn.execute("CREATE VIEW device_pairing_paired AS SELECT * FROM decoy")
        conn.commit()
        conn.close()
        ctx = collect(home)
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == PASS, f.detail
        assert f.pass_confidence == "verified"


# ============================================================================
# Deny list and allowSkills gate
# ============================================================================


class TestGateAndDeny:
    def test_canonical_deny_passes_when_modelled(self, tmp_path):
        for deny in (["system.run"], [" system.run "]):
            cfg = {"meta": {"lastTouchedVersion": _MODELLED},
                   "gateway": {"nodes": {"commands": {"deny": deny}}}}
            ctx = _sqlite_home(tmp_path, f"h{deny}", cfg, _row())
            f = check_paired_node_skill_coverage(ctx)
            assert f.status == PASS, (deny, f.detail)
            assert f.pass_confidence == "verified"

    def test_near_miss_deny_entries_still_warn(self, tmp_path):
        for i, deny in enumerate((["System.run"], ["system.run*"], ["system.run --x"])):
            cfg = {"meta": {"lastTouchedVersion": _MODELLED},
                   "gateway": {"nodes": {"commands": {"deny": deny}}}}
            ctx = _sqlite_home(tmp_path, f"h{i}", cfg, _row(device_id=f"n{i}"))
            f = check_paired_node_skill_coverage(ctx)
            assert f.status == WARN, (deny, f.detail)

    def test_deny_shortcut_not_taken_on_unmodelled_build(self, tmp_path):
        cfg = {"gateway": {"nodes": {"commands": {"deny": ["system.run"]}}}}
        ctx = _sqlite_home(tmp_path, "h", cfg, _row(), installed=_UNMODELLED)
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == WARN, f.detail

    def test_allowskills_string_false_still_warns(self, tmp_path):
        cfg = {"meta": {"lastTouchedVersion": _MODELLED},
               "gateway": {"nodes": {"allowSkills": "false"}}}
        ctx = _sqlite_home(tmp_path, "h", cfg, _row())
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == WARN, f.detail

    def test_legacy_skills_enabled_false_passes(self, tmp_path):
        cfg = {"meta": {"lastTouchedVersion": _MODELLED},
               "gateway": {"nodes": {"skills": {"enabled": False}}}}
        ctx = _sqlite_home(tmp_path, "h", cfg, _row())
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == PASS, f.detail

    def test_b386_b396_gate_consistency_matrix(self, tmp_path):
        from clawseccheck.checks import check_node_allowskills_default_on

        cases = [
            {},
            {"gateway": {"nodes": {"allowSkills": True}}},
            {"gateway": {"nodes": {"allowSkills": False}}},
            {"gateway": {"nodes": {"allowSkills": "false"}}},
            {"gateway": {"nodes": {"allowSkills": None}}},
            {"gateway": {"nodes": {"skills": {"enabled": False}}}},
            {"gateway": {"nodes": {"skills": {"enabled": True}}}},
            {"gateway": {"nodes": {"allowSkills": True, "skills": {"enabled": False}}}},
        ]
        for i, extra in enumerate(cases):
            cfg = {"meta": {"lastTouchedVersion": _MODELLED}, **extra}
            ctx = _sqlite_home(tmp_path, f"m{i}", cfg, _row(device_id=f"n{i}"))
            b386 = check_node_allowskills_default_on(ctx)
            b396 = check_paired_node_skill_coverage(ctx)
            b386_pass = b386.status == PASS
            b396_gate_pass = b396.status == PASS and (
                "OpenClaw discards every skill" in b396.detail
            )
            assert b386_pass == b396_gate_pass, (extra, b386.status, b396.detail)


# ============================================================================
# Config-locus behaviour
# ============================================================================


class TestConfig:
    def test_no_config_with_capable_node_warns_naming_no_config(self, tmp_path):
        home = tmp_path / "h"
        home.mkdir()
        _make_state_db(home / "state", [])
        conn = sqlite3.connect(home / "state" / "openclaw.sqlite")
        conn.execute(
            "INSERT INTO device_pairing_paired (device_id, public_key, platform, role, "
            "roles_json, tokens_json, node_surface_json, created_at_ms, approved_at_ms) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            _row(),
        )
        conn.commit()
        conn.close()
        ctx = collect(home)
        ctx.installed_dist_version = _MODELLED
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == WARN, f.detail
        assert "no openclaw.json" in f.detail

    def test_no_config_and_no_node_passes(self, tmp_path):
        home = tmp_path / "h"
        home.mkdir()
        ctx = collect(home)
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == PASS, f.detail

    def test_unparseable_config_is_unknown_degraded(self, tmp_path):
        home = tmp_path / "h"
        home.mkdir()
        (home / "openclaw.json").write_text("{not valid json", encoding="utf-8")
        ctx = collect(home)
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == UNKNOWN, f.detail
        assert f.engine_degraded is True


# ============================================================================
# Legacy JSON merge (devices/paired.json + nodes/paired.json, 9.6 migration fold)
# ============================================================================


class TestLegacyMerge:
    def test_devices_record_without_surface_plus_nodes_row_warns(self, tmp_path):
        home = _cfg_home(tmp_path, "h")
        _write_devices(home, {"n1": _node_row("n1")})
        _write_nodes(home, {"n1": {"commands": ["system.run"]}})
        ctx = collect(home)
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == WARN, f.detail

    def test_existing_surface_without_system_run_wins_over_fold(self, tmp_path):
        home = _cfg_home(tmp_path, "h")
        _write_devices(home, {"n1": _node_row("n1", node_surface={"commands": ["camera.list"]})})
        _write_nodes(home, {"n1": {"commands": ["system.run"]}})
        ctx = collect(home)
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == PASS, f.detail

    def test_truthy_empty_object_surface_blocks_fold(self, tmp_path):
        home = _cfg_home(tmp_path, "h")
        _write_devices(home, {"n1": _node_row("n1", node_surface={})})
        _write_nodes(home, {"n1": {"commands": ["system.run"]}})
        ctx = collect(home)
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == PASS, f.detail

    def test_orphan_nodes_row_modelled_passes(self, tmp_path):
        home = _cfg_home(tmp_path, "h")
        _write_nodes(home, {"orphan": {"commands": ["system.run"]}})
        ctx = collect(home)
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == PASS, f.detail

    def test_orphan_nodes_row_unmodelled_warns(self, tmp_path):
        home = _cfg_home(tmp_path, "h", {})
        _write_nodes(home, {"orphan": {"commands": ["system.run"]}})
        ctx = collect(home)
        ctx.installed_dist_version = _UNMODELLED
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == WARN, f.detail

    def test_invalid_s2_record_modelled_passes_unmodelled_warns(self, tmp_path):
        bad = _node_row("n1")
        del bad["publicKey"]  # migration drops a record missing publicKey
        home = _cfg_home(tmp_path, "h")
        _write_devices(home, {"n1": bad})
        _write_nodes(home, {"n1": {"commands": ["system.run"]}})
        ctx = collect(home)
        f_modelled = check_paired_node_skill_coverage(ctx)
        assert f_modelled.status == PASS, f_modelled.detail

        home2 = _cfg_home(tmp_path, "h2", {})
        _write_devices(home2, {"n1": bad})
        _write_nodes(home2, {"n1": {"commands": ["system.run"]}})
        ctx2 = collect(home2)
        ctx2.installed_dist_version = _UNMODELLED
        f_unmodelled = check_paired_node_skill_coverage(ctx2)
        assert f_unmodelled.status == WARN, f_unmodelled.detail

    def test_float_createdatms_counts_as_valid_integer(self, tmp_path):
        rec = _node_row("n1")
        rec["createdAtMs"] = 1757000000000.0
        home = _cfg_home(tmp_path, "h")
        _write_devices(home, {"n1": rec})
        _write_nodes(home, {"n1": {"commands": ["system.run"]}})
        ctx = collect(home)
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == WARN, f.detail

    def test_sqlite_wins_over_legacy_devices_json(self, tmp_path):
        home = _cfg_home(tmp_path, "h")
        _write_devices(home, {"n1": _node_row("n1", node_surface={"commands": ["system.run"]})})
        # SQLite has the SAME id but with NO system.run -> SQLite must win outright.
        _make_state_db(home / "state", [])
        conn = sqlite3.connect(home / "state" / "openclaw.sqlite")
        conn.execute(
            "INSERT INTO device_pairing_paired (device_id, public_key, platform, role, "
            "roles_json, tokens_json, node_surface_json, created_at_ms, approved_at_ms) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            _row(device_id="n1", node_surface_json=json.dumps({"commands": ["camera.list"]})),
        )
        conn.commit()
        conn.close()
        ctx = collect(home)
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == PASS, f.detail

    def test_devices_json_as_array_is_unknown(self, tmp_path):
        home = _cfg_home(tmp_path, "h")
        d = home / "devices"
        d.mkdir()
        (d / "paired.json").write_text("[]", encoding="utf-8")
        ctx = collect(home)
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == UNKNOWN, f.detail

    def test_devices_json_invalid_is_unknown(self, tmp_path):
        home = _cfg_home(tmp_path, "h")
        d = home / "devices"
        d.mkdir()
        (d / "paired.json").write_text("{not valid", encoding="utf-8")
        ctx = collect(home)
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == UNKNOWN, f.detail

    def test_devices_json_over_cap_is_unknown(self, tmp_path):
        home = _cfg_home(tmp_path, "h")
        d = home / "devices"
        d.mkdir()
        huge = json.dumps({"pad": "x" * (4 * 1024 * 1024 + 10)})
        (d / "paired.json").write_text(huge, encoding="utf-8")
        ctx = collect(home)
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == UNKNOWN, f.detail

    def test_devices_json_bad_but_capable_node_elsewhere_warns(self, tmp_path):
        home = _cfg_home(tmp_path, "h")
        d = home / "devices"
        d.mkdir()
        (d / "paired.json").write_text("{not valid", encoding="utf-8")
        _make_state_db(home / "state", [])
        conn = sqlite3.connect(home / "state" / "openclaw.sqlite")
        conn.execute(
            "INSERT INTO device_pairing_paired (device_id, public_key, platform, role, "
            "roles_json, tokens_json, node_surface_json, created_at_ms, approved_at_ms) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            _row(),
        )
        conn.commit()
        conn.close()
        ctx = collect(home)
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == WARN, f.detail


# ============================================================================
# Version gate (installed dist vs meta.lastTouchedVersion)
# ============================================================================


class TestVersionGate:
    def test_meta_2026_9_6_with_no_installed_is_modelled(self, tmp_path):
        ctx = _sqlite_home(tmp_path, "h", None, _row(), installed=None)
        assert _b396_build_modelled(ctx) is True

    def test_installed_9_5_with_meta_9_6_is_unmodelled(self, tmp_path):
        home = _cfg_home(tmp_path, "h", {"meta": {"lastTouchedVersion": _MODELLED}})
        ctx = collect(home)
        ctx.installed_dist_version = _UNMODELLED
        assert _b396_build_modelled(ctx) is False

    def test_installed_prerelease_falls_back_to_meta(self, tmp_path):
        home = _cfg_home(tmp_path, "h", {"meta": {"lastTouchedVersion": _MODELLED}})
        ctx = collect(home)
        ctx.installed_dist_version = "2026.9.6-beta.1"
        assert _b396_build_modelled(ctx) is True

    def test_unmodelled_revoked_node_still_warns_with_may_be_able_wording(self, tmp_path):
        row = _row(tokens_json=json.dumps(
            {"node": {"token": _token("N"), "role": "node", "revokedAtMs": 999}}
        ))
        ctx = _sqlite_home(tmp_path, "h", {}, row, installed=_UNMODELLED)
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == WARN, f.detail
        assert "may be able to publish" in f.detail

    def test_unmodelled_no_node_indications_passes(self, tmp_path):
        home = _cfg_home(tmp_path, "h", {})
        _write_devices(home, {"o1": _operator_row("o1")})
        ctx = collect(home)
        ctx.installed_dist_version = _UNMODELLED
        f = check_paired_node_skill_coverage(ctx)
        assert f.status == PASS, f.detail


# ============================================================================
# Hygiene: fingerprint stability, privacy, catalog wiring
# ============================================================================


class TestHygiene:
    def test_fingerprint_stable_across_runs(self):
        ctx1 = collect(FIXTURES / "bad_b396_paired_node_skills")
        ctx2 = collect(FIXTURES / "bad_b396_paired_node_skills")
        f1 = check_paired_node_skill_coverage(ctx1)
        f2 = check_paired_node_skill_coverage(ctx2)
        assert f1.detail == f2.detail
        import re
        assert not re.search(r"\b\d{10,}\b", f1.detail)  # no raw epoch-ms timestamps

    def test_no_absolute_path_in_detail_or_evidence(self, tmp_path):
        ctx = collect(FIXTURES / "bad_b396_paired_node_skills")
        f = check_paired_node_skill_coverage(ctx)
        assert str(FIXTURES) not in f.detail
        assert not any(str(FIXTURES) in e for e in f.evidence)
        assert "/home/" not in f.detail

    def test_catalog_fields(self):
        meta = BY_ID["B396"]
        assert meta.severity == "MEDIUM"
        assert meta.block == "advisory"
        assert meta.scored is False
        assert meta.confidence == "MEDIUM"
        assert meta.surface == "skills"

    def test_never_emits_fail(self, tmp_path):
        # Corpus coverage lives in test_b315; this is a direct, local sanity pin.
        for name in (
            "bad_b396_paired_node_skills", "clean_b396_allowskills_off",
            "clean_b396_node_without_system_run", "clean_b396_no_paired_node",
            "unknown_b396_malformed_node_store",
        ):
            f = check_paired_node_skill_coverage(collect(FIXTURES / name))
            assert f.status != FAIL

    def test_registered_exactly_once_after_b176(self):
        names = [getattr(c, "__name__", "") for c in CHECKS]
        count = names.count("check_paired_node_skill_coverage")
        assert count == 1
        i176 = names.index("check_paired_device_operator_authority")
        i396 = names.index("check_paired_node_skill_coverage")
        assert i396 == i176 + 1


# ============================================================================
# Small helper-level unit coverage (faithful-port sanity, not exhaustive --
# the scenario tests above already exercise these through the real check)
# ============================================================================


class TestHelpers:
    def test_js_truthy(self):
        assert _b396_js_truthy(0) is False
        assert _b396_js_truthy("") is False
        assert _b396_js_truthy(None) is False
        assert _b396_js_truthy(False) is False
        assert _b396_js_truthy({}) is True
        assert _b396_js_truthy([]) is True
        assert _b396_js_truthy("x") is True
        assert _b396_js_truthy(float("nan")) is False

    def test_role_list(self):
        assert _b396_role_list(["node", "", "  "]) == ["node"]
        assert _b396_role_list("node") == ["node"]
        assert _b396_role_list("") == []
        assert _b396_role_list(None) == []

    def test_safe_int(self):
        assert _b396_safe_int(1700000000000) is True
        assert _b396_safe_int(1700000000000.0) is True
        assert _b396_safe_int(1700000000000.5) is False
        assert _b396_safe_int("1700000000000") is False
        assert _b396_safe_int(True) is False

    def test_legacy_record_valid(self):
        assert _b396_legacy_record_valid(
            {"publicKey": "pk", "createdAtMs": 1, "approvedAtMs": 1}
        ) is True
        assert _b396_legacy_record_valid({"createdAtMs": 1, "approvedAtMs": 1}) is False
        assert _b396_legacy_record_valid("not a dict") is False

    def test_approved_state_case_sensitive(self):
        assert _b396_approved_state({"role": "Node"}) == "no"  # case matches the dist
        assert _b396_approved_state({"role": "node"}) == "yes"
        assert _b396_approved_state({"rolesUnparsed": True}) == "undet"

    def test_admission_state_decisive_negative_wins(self):
        rec = {"role": "operator", "nodeSurfaceUnparsed": True,
               "tokensUnparsed": True}
        assert _b396_admission_state(rec) == "no"

    def test_surface_state_folded_undet_propagates(self):
        rec = {}
        assert _b396_surface_state(rec, "undet") == "undet"

    def test_node_candidate_via_token_key(self):
        assert _b396_node_candidate({"tokens": {"node": {}}}) is True
        assert _b396_node_candidate({"tokens": {"operator": {}}}) is False

    def test_read_legacy_store_absent_file(self, tmp_path):
        ctx = Context(home=tmp_path)
        data, gap = _b396_read_legacy_store(ctx, "devices", "paired.json")
        assert data is None
        assert gap is None

    def test_read_legacy_store_over_cap(self, tmp_path):
        home = tmp_path
        d = home / "devices"
        d.mkdir()
        (d / "paired.json").write_text("x" * (4 * 1024 * 1024 + 100), encoding="utf-8")
        ctx = Context(home=home)
        data, gap = _b396_read_legacy_store(ctx, "devices", "paired.json")
        assert data is None
        assert "4 MB read cap" in gap
        assert str(home) not in gap
