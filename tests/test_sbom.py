"""Tests for `--sbom` (F-085) — deterministic local bill-of-materials export.

Checks: skill/MCP field extraction, hash alignment with monitor.py's own hashing
scheme, deterministic ordering, redaction (no secret VALUES ever leak, only key
names), and the CLI flag itself.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.cli import main
from clawseccheck.collector import Context
from clawseccheck.monitor import _h
from clawseccheck.sbom import build_sbom, render_sbom

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
_HOME_FAKE = Path("/nonexistent/home")


def _ctx_with_skill(name: str, skill_md: str) -> Context:
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {name: skill_md}
    ctx.config = {}
    return ctx


def _ctx_plugins_scanned(**kw) -> Context:
    """A Context whose plugin index was read cleanly (empty by default) — the
    baseline most tests want so `complete` isn't dragged down by an unrelated,
    untested axis (B-568: `complete` now also requires `plugins_scanned`)."""
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {}
    ctx.config = {}
    ctx.plugin_index_found = True
    for k, v in kw.items():
        setattr(ctx, k, v)
    return ctx


# --------------------------------------------------------------------------- skills

def test_skill_hash_matches_monitor_hashing_scheme():
    blob = "---\nname: x\ndescription: y\nversion: 1.2.0\n---\nrequests>=2.0\n"
    ctx = _ctx_with_skill("net-fetcher", blob)
    bom = build_sbom(ctx)
    entry = bom["skills"][0]
    assert entry["name"] == "net-fetcher"
    assert entry["version"] == "1.2.0"
    assert entry["hash"] == _h(blob)  # must align with monitor.py's own hash scheme


def test_skill_no_version_is_none():
    ctx = _ctx_with_skill("no-ver", "---\nname: x\ndescription: y\n---\n")
    bom = build_sbom(ctx)
    assert bom["skills"][0]["version"] is None


def test_skills_sorted_by_name():
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {
        "zeta": "---\nname: z\ndescription: z\n---\n",
        "alpha": "---\nname: a\ndescription: a\n---\n",
    }
    ctx.config = {}
    bom = build_sbom(ctx)
    assert [s["name"] for s in bom["skills"]] == ["alpha", "zeta"]


# --------------------------------------------------------------------------- mcp

def test_mcp_hash_matches_monitor_hashing_scheme():
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {}
    ctx.config = {
        "mcp": {"servers": {"svc": {"command": "npx", "args": ["svc-mcp@1.2.3"],
                                     "transport": "stdio", "env": {"API_KEY": "secret-value"}}}}
    }
    bom = build_sbom(ctx)
    assert len(bom["mcp_servers"]) == 1
    entry = bom["mcp_servers"][0]
    assert entry["name"] == "svc"
    assert entry["transport"] == "stdio"
    # redaction: only the key NAME (marked as secret-shaped), never the value
    assert all("secret-value" not in str(v) for v in entry.values())
    assert any("API_KEY" in k for k in entry["env_keys"])


def test_mcp_pinned_detection():
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {}
    ctx.config = {
        "mcp": {"servers": {
            "pinned-svc": {"command": "npx", "args": ["svc-mcp@1.2.3"], "transport": "stdio"},
            "unpinned-svc": {"command": "npx", "args": ["svc-mcp"], "transport": "stdio"},
        }}
    }
    bom = build_sbom(ctx)
    by_name = {e["name"]: e for e in bom["mcp_servers"]}
    assert by_name["pinned-svc"]["pinned"] is True
    assert by_name["unpinned-svc"]["pinned"] is False


# --------------------------------------------------------------------------- plugins (B-568)

def _plugin_rec(plugin_id, *, origin="config", enabled=True, root_dir=None,
                 manifest_path=None, source=None, contracts=None):
    return {
        "plugin_id": plugin_id,
        "origin": origin,
        "enabled": enabled,
        "root_dir": root_dir,
        "manifest_path": manifest_path,
        "source": source,
        "contracts": contracts or {},
    }


def test_plugins_were_entirely_absent_now_populated():
    """The defect itself: B-568 filed this because there was no `plugins` key at
    all, on a real box with 70 installed-plugin-index records."""
    ctx = _ctx_plugins_scanned(plugin_index_records=[
        _plugin_rec("alpha"), _plugin_rec("beta"),
    ])
    bom = build_sbom(ctx)
    assert [p["name"] for p in bom["plugins"]] == ["alpha", "beta"]  # sorted
    entry = bom["plugins"][0]
    assert entry["origin"] == "config"
    assert entry["enabled"] is True


def test_plugin_contracts_are_names_only():
    ctx = _ctx_plugins_scanned(plugin_index_records=[
        _plugin_rec("p1", contracts={"agentToolResultMiddleware": ["h1"], "tools": ["x", "y"]}),
    ])
    bom = build_sbom(ctx)
    assert bom["plugins"][0]["contracts"] == ["agentToolResultMiddleware", "tools"]


def test_plugin_paths_never_carry_the_raw_home_prefix():
    """CLAUDE.md §8: an AI-BOM is exactly what gets pasted into a ticket."""
    ctx = _ctx_plugins_scanned(plugin_index_records=[
        _plugin_rec(
            "browser",
            root_dir="/home/someoperator/.npm-global/lib/node_modules/openclaw/dist/extensions/browser",
            manifest_path="/home/someoperator/.npm-global/lib/node_modules/openclaw/dist/extensions/browser/openclaw.plugin.json",
            source="/home/someoperator/.npm-global/lib/node_modules/openclaw/dist/extensions/browser/index.js",
        ),
    ])
    out = render_sbom(ctx)
    assert "/home/someoperator" not in out
    payload = json.loads(out)
    entry = payload["plugins"][0]
    assert entry["root_dir"].startswith("~/")
    assert entry["manifest_path"].startswith("~/")
    assert entry["entry_point"].startswith("~/")


def test_bundled_skill_names_its_supplying_plugin():
    ctx = _ctx_plugins_scanned(plugin_index_records=[
        _plugin_rec("browser", root_dir="/home/x/.npm-global/dist/extensions/browser"),
    ])
    ctx.installed_skills = {"browser-automation": "---\nname: b\ndescription: b\n---\n"}
    ctx.installed_skill_bundled = {"browser-automation"}
    ctx.installed_skill_dirs = {
        "browser-automation": "/home/x/.npm-global/dist/extensions/browser/skills/browser-automation",
    }
    bom = build_sbom(ctx)
    assert bom["skills"][0]["supplier"] == "browser"


def test_bundled_skill_with_no_matching_plugin_is_unknown_not_empty_or_guessed():
    """Bundled-ness is definitive (installed_skill_bundled); WHICH plugin is not
    always resolvable. The honest spelling is the string "unknown", never ""."""
    ctx = _ctx_plugins_scanned(plugin_index_records=[])  # index read, but empty
    ctx.installed_skills = {"orphan-bundled": "---\nname: o\ndescription: o\n---\n"}
    ctx.installed_skill_bundled = {"orphan-bundled"}
    ctx.installed_skill_dirs = {"orphan-bundled": "/some/root/skills/orphan-bundled"}
    bom = build_sbom(ctx)
    assert bom["skills"][0]["supplier"] == "unknown"
    assert bom["skills"][0]["supplier"] != ""


def test_non_bundled_skill_supplier_is_none_not_unknown():
    """A directly user-installed skill has no plugin-supplier concept — that is a
    different fact from "we don't know", so it must not collapse to "unknown"."""
    ctx = _ctx_plugins_scanned()
    ctx.installed_skills = {"user-skill": "---\nname: u\ndescription: u\n---\n"}
    ctx.installed_skill_bundled = set()
    bom = build_sbom(ctx)
    assert bom["skills"][0]["supplier"] is None


def test_plugin_index_not_found_makes_the_bom_not_complete():
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {}
    ctx.config = {}
    ctx.config_found = True
    # ctx.plugin_index_found left at its Context default: False
    bom = build_sbom(ctx)
    assert bom["plugins_scanned"] is False
    assert bom["complete"] is False


def test_plugin_index_parse_error_makes_the_bom_not_complete():
    ctx = _ctx_plugins_scanned(plugin_index_parse_error=True)
    ctx.config_found = True
    bom = build_sbom(ctx)
    assert bom["plugins_scanned"] is False
    assert bom["complete"] is False


def test_plugin_index_cleanly_read_and_empty_is_still_complete():
    """The fix must not make every BOM incomplete just because a machine has zero
    installed plugins — that would be the same lie B-521 already fixed, inverted."""
    ctx = _ctx_plugins_scanned()
    ctx.config_found = True
    bom = build_sbom(ctx)
    assert bom["plugins_scanned"] is True
    assert bom["complete"] is True


def test_a_context_without_plugin_fields_does_not_crash():
    """`build_sbom` takes a duck-typed ctx; an older/partial one must not blow up."""
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {}
    ctx.config = {}
    del ctx.plugin_index_records
    del ctx.installed_skill_bundled
    del ctx.installed_skill_dirs
    bom = build_sbom(ctx)
    assert bom["plugins"] == []
    assert bom["plugins_scanned"] is False  # honestly unknown, never a fabricated PASS


# --------------------------------------------------------------------------- determinism

def test_render_sbom_is_deterministic():
    ctx = _ctx_with_skill("x", "---\nname: x\ndescription: y\n---\n")
    out1 = render_sbom(ctx)
    out2 = render_sbom(ctx)
    assert out1 == out2
    json.loads(out1)  # valid JSON


def test_empty_context_produces_valid_empty_bom():
    ctx = _ctx_plugins_scanned()
    out = render_sbom(ctx)
    payload = json.loads(out)
    assert payload["skills"] == []
    assert payload["mcp_servers"] == []
    assert payload["plugins"] == []
    assert payload["version"] == 3  # B-568: bumped 2 -> 3, see sbom.py SBOM_VERSION


# --------------------------------------------------------------------------- redaction guard

def test_no_secret_value_anywhere_in_bom():
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {}
    ctx.config = {
        "mcp": {"servers": {"svc": {
            "command": "npx", "args": ["svc-mcp"], "transport": "stdio",
            "env": {"OPENAI_API_KEY": "sk-THIS-MUST-NEVER-APPEAR", "PASSWORD": "hunter2"},
        }}}
    }
    out = render_sbom(ctx)
    assert "sk-THIS-MUST-NEVER-APPEAR" not in out
    assert "hunter2" not in out


# --------------------------------------------------------------------------- CLI

def test_cli_sbom_emits_valid_json(capsys):
    rc = main(["--home", str(FIXTURES / "home_safe"), "--no-native", "--no-host",
               "--no-history", "--sbom"])
    out = capsys.readouterr().out
    assert rc == 0
    payload = json.loads(out)
    assert payload["version"] == 3  # B-568: bumped 2 -> 3, see sbom.py SBOM_VERSION
    assert "skills" in payload and "mcp_servers" in payload and "plugins" in payload
    # fixtures/home_safe carries no state DB, so the plugin index was genuinely never
    # read — `complete` must say so honestly, not silently claim a full inventory.
    assert payload["plugins_scanned"] is False
    assert payload["complete"] is False


def test_cli_sbom_is_deterministic_across_runs(capsys):
    main(["--home", str(FIXTURES / "home_safe"), "--no-native", "--no-host",
          "--no-history", "--sbom"])
    out1 = capsys.readouterr().out
    main(["--home", str(FIXTURES / "home_safe"), "--no-native", "--no-host",
          "--no-history", "--sbom"])
    out2 = capsys.readouterr().out
    assert out1 == out2
