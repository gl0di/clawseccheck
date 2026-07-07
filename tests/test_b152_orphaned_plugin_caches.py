"""B152 — on-disk plugin caches not declared in plugins.entries.

Real example: npm/projects/openclaw-brave-plugin-* and agents/main/agent/plugins/nvidia
exist on disk but are not declared in openclaw.json's plugins.entries. Two grounded
on-disk plugin-cache locations (recon Sec 11.1): ~/.openclaw/npm/projects/<wrapper>/
and agents/<agent>/agent/plugins/<name>/.

Advisory only (WARN, LOW, never FAIL) — a stale/uninstalled cache, a mid-install
artifact, or a plugin declared under a different key is not proof of malice.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_orphaned_plugin_caches
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(home: Path, cfg: dict | None = None) -> Context:
    c = Context(home=home)
    c.config = cfg or {}
    return c


def _write_manifest(path: Path, plugin_id: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"id": plugin_id, "configSchema": {"type": "object"}}), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Unit-level (synthetic tmp_path homes)
# ---------------------------------------------------------------------------

def test_no_plugin_cache_dirs_is_unknown(tmp_path):
    home = tmp_path / ".openclaw"
    home.mkdir()
    f = check_orphaned_plugin_caches(_ctx(home))
    assert f.status == UNKNOWN


def test_agent_plugins_dir_not_declared_warns(tmp_path):
    home = tmp_path / ".openclaw"
    (home / "agents" / "main" / "agent" / "plugins" / "nvidia").mkdir(parents=True)
    f = check_orphaned_plugin_caches(_ctx(home, {"plugins": {"entries": {}}}))
    assert f.status == WARN
    assert any("nvidia" in e for e in f.evidence)


def test_agent_plugins_dir_declared_passes(tmp_path):
    home = tmp_path / ".openclaw"
    (home / "agents" / "main" / "agent" / "plugins" / "nvidia").mkdir(parents=True)
    f = check_orphaned_plugin_caches(_ctx(home, {"plugins": {"entries": {"nvidia": {}}}}))
    assert f.status == PASS


def test_npm_projects_wrapper_manifest_id_used_for_comparison(tmp_path):
    home = tmp_path / ".openclaw"
    wrapper = (
        home / "npm" / "projects"
        / "openclaw-brave-plugin-abc123__openclaw-generation__brave-plugin-1.0.0-xyz"
    )
    _write_manifest(
        wrapper / "node_modules" / "@openclaw" / "brave-plugin" / "openclaw.plugin.json",
        "brave-plugin",
    )
    # Not declared -> WARN, evidence names the manifest id, not the wrapper dir name.
    f = check_orphaned_plugin_caches(_ctx(home, {"plugins": {"entries": {}}}))
    assert f.status == WARN
    assert any("brave-plugin" in e for e in f.evidence)

    # Declared under its manifest id -> PASS.
    f2 = check_orphaned_plugin_caches(
        _ctx(home, {"plugins": {"entries": {"brave-plugin": {}}}})
    )
    assert f2.status == PASS


def test_npm_projects_wrapper_without_manifest_falls_back_to_dir_name(tmp_path):
    home = tmp_path / ".openclaw"
    wrapper = home / "npm" / "projects" / "some-unresolvable-wrapper-dir"
    wrapper.mkdir(parents=True)
    f = check_orphaned_plugin_caches(_ctx(home, {"plugins": {"entries": {}}}))
    assert f.status == WARN
    assert any("some-unresolvable-wrapper-dir" in e for e in f.evidence)


def test_never_fails(tmp_path):
    home = tmp_path / ".openclaw"
    (home / "agents" / "main" / "agent" / "plugins" / "nvidia").mkdir(parents=True)
    assert check_orphaned_plugin_caches(_ctx(home, {"plugins": {"entries": {}}})).status != "FAIL"


# ---------------------------------------------------------------------------
# Fixture-level (collect())
# ---------------------------------------------------------------------------

def test_bad_fixture_warns():
    ctx = collect(FIXTURES / "bad_b152_orphaned_plugin")
    f = check_orphaned_plugin_caches(ctx)
    assert f.status == WARN
    assert any("nvidia" in e for e in f.evidence)
    assert any("brave-plugin" in e for e in f.evidence)


def test_clean_fixture_passes():
    ctx = collect(FIXTURES / "clean_b152_orphaned_plugin")
    f = check_orphaned_plugin_caches(ctx)
    assert f.status == PASS


def test_real_fixtures_are_unknown_not_false_positive():
    for fx in ("home_safe", "home_vuln"):
        ctx = collect(FIXTURES / fx)
        assert check_orphaned_plugin_caches(ctx).status == UNKNOWN


def test_registered_in_audit():
    from clawseccheck import audit
    _ctx_, findings, _score = audit(FIXTURES / "bad_b152_orphaned_plugin", include_native=False)
    ids = {f.id for f in findings}
    assert "B152" in ids
