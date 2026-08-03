"""B348 (F-161) — a plugins.load.paths entry has no matching plugins.entries record.

Grounded live on a real host: `openclaw plugins uninstall` only removes the
plugins.entries record; a plugin discoverable via plugins.load.paths keeps loading on
every gateway start regardless. Advisory only (WARN, LOW, never FAIL) — a load path
with no entries record is the normal shape of local plugin development.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_undeclared_plugin_load_path
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(home: Path, cfg: dict | None = None, *, config_found: bool = True) -> Context:
    c = Context(home=home)
    c.config = cfg if cfg is not None else {}
    c.config_found = config_found
    return c


def _write_manifest(path: Path, plugin_id: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"id": plugin_id}), encoding="utf-8")


def test_no_config_found_is_unknown(tmp_path):
    home = tmp_path / ".openclaw"
    home.mkdir()
    f = check_undeclared_plugin_load_path(_ctx(home, config_found=False))
    assert f.status == UNKNOWN


def test_no_load_paths_is_unknown(tmp_path):
    home = tmp_path / ".openclaw"
    home.mkdir()
    f = check_undeclared_plugin_load_path(_ctx(home, {}))
    assert f.status == UNKNOWN


def test_plugins_allow_set_passes_regardless_of_load_paths(tmp_path):
    # clean-1: an explicit allowlist gates reachability at a different layer.
    home = tmp_path / ".openclaw"
    plugin_dir = home / "dev-plugin"
    _write_manifest(plugin_dir / "openclaw.plugin.json", "dev-plugin")
    cfg = {
        "plugins": {
            "allow": ["dev-plugin"],
            "load": {"paths": [str(plugin_dir)]},
            "entries": {},
        }
    }
    f = check_undeclared_plugin_load_path(_ctx(home, cfg))
    assert f.status == PASS


def test_load_path_declared_in_entries_passes(tmp_path):
    # clean-2: declared state matches effective state.
    home = tmp_path / ".openclaw"
    plugin_dir = home / "dev-plugin"
    _write_manifest(plugin_dir / "openclaw.plugin.json", "dev-plugin")
    cfg = {
        "plugins": {
            "load": {"paths": [str(plugin_dir)]},
            "entries": {"dev-plugin": {}},
        }
    }
    f = check_undeclared_plugin_load_path(_ctx(home, cfg))
    assert f.status == PASS


def test_no_load_paths_configured_at_all_is_unknown(tmp_path):
    # clean-3.
    home = tmp_path / ".openclaw"
    home.mkdir()
    cfg = {"plugins": {"entries": {"something": {}}}}
    f = check_undeclared_plugin_load_path(_ctx(home, cfg))
    assert f.status == UNKNOWN


def test_undeclared_load_path_warns_with_operator_facing_consequence(tmp_path):
    # bad: plugins.allow unset, load path has a manifest, no entries record.
    home = tmp_path / ".openclaw"
    plugin_dir = home / "dev-plugin"
    _write_manifest(plugin_dir / "openclaw.plugin.json", "dev-plugin")
    cfg = {
        "plugins": {
            "load": {"paths": [str(plugin_dir)]},
            "entries": {},
        }
    }
    f = check_undeclared_plugin_load_path(_ctx(home, cfg))
    assert f.status == WARN
    assert any("dev-plugin" in e for e in f.evidence)
    assert "uninstall" in f.detail
    assert "does not stop" in f.detail or "does not" in f.detail


def test_never_fails(tmp_path):
    home = tmp_path / ".openclaw"
    plugin_dir = home / "dev-plugin"
    _write_manifest(plugin_dir / "openclaw.plugin.json", "dev-plugin")
    cfg = {"plugins": {"load": {"paths": [str(plugin_dir)]}, "entries": {}}}
    assert check_undeclared_plugin_load_path(_ctx(home, cfg)).status != "FAIL"


def test_load_path_without_manifest_is_ignored(tmp_path):
    home = tmp_path / ".openclaw"
    plugin_dir = home / "not-a-plugin"
    plugin_dir.mkdir(parents=True)
    cfg = {"plugins": {"load": {"paths": [str(plugin_dir)]}, "entries": {}}}
    f = check_undeclared_plugin_load_path(_ctx(home, cfg))
    assert f.status == UNKNOWN


def test_config_unreadable_reports_unknown_not_pass():
    ctx = Context(home=Path("/nonexistent-b348-test-home"))
    ctx.config_found = True
    ctx.config = None
    ctx.config_parse_error = True
    f = check_undeclared_plugin_load_path(ctx)
    assert f.status == UNKNOWN


def test_registered_in_audit(tmp_path):
    from clawseccheck import audit

    home = tmp_path / ".openclaw"
    plugin_dir = home / "dev-plugin"
    _write_manifest(plugin_dir / "openclaw.plugin.json", "dev-plugin")
    (home / "openclaw.json").write_text(
        json.dumps({"plugins": {"load": {"paths": [str(plugin_dir)]}, "entries": {}}}),
        encoding="utf-8",
    )
    _ctx_, findings, _score = audit(home, include_native=False)
    ids = {f.id for f in findings}
    assert "B348" in ids


def test_real_fixtures_are_unknown_not_false_positive():
    for fx in ("home_safe", "home_vuln"):
        from clawseccheck.collector import collect

        ctx = collect(FIXTURES / fx)
        assert check_undeclared_plugin_load_path(ctx).status in (UNKNOWN, PASS)
