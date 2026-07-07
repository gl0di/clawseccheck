"""B151 — codex connector shell hooks in the plugin doc-cache.

Real path: agents/<agent>/agent/codex-home/.tmp/plugins/plugins/<connector>/hooks.json
(the Codex CLI's own third-party plugin cache, a DIFFERENT on-disk location from any
OpenClaw skill directory). Some connectors wire a shell script to a tool-use/lifecycle
event (e.g. replayio/hooks.json -> PostToolUse/Bash -> ./scripts/post_bash_upload.sh).

Advisory only (WARN, LOW, never FAIL) — an upload-shaped surface disclosed for
awareness, not proof of malice.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_codex_plugin_hooks
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(home: Path) -> Context:
    return Context(home=home)


def _write_hooks(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


# ---------------------------------------------------------------------------
# Unit-level (synthetic tmp_path homes)
# ---------------------------------------------------------------------------

def test_no_agents_dir_is_unknown(tmp_path):
    home = tmp_path / ".openclaw"
    home.mkdir()
    f = check_codex_plugin_hooks(_ctx(home))
    assert f.status == UNKNOWN


def test_no_codex_plugin_cache_dir_is_unknown(tmp_path):
    home = tmp_path / ".openclaw"
    (home / "agents" / "main" / "agent").mkdir(parents=True)
    f = check_codex_plugin_hooks(_ctx(home))
    assert f.status == UNKNOWN


def test_cache_dir_present_but_no_hooks_json_is_unknown(tmp_path):
    home = tmp_path / ".openclaw"
    cache = home / "agents" / "main" / "agent" / "codex-home" / ".tmp" / "plugins" / "plugins" / "some-connector"
    cache.mkdir(parents=True)
    f = check_codex_plugin_hooks(_ctx(home))
    assert f.status == UNKNOWN


def test_hooks_json_with_shell_script_warns(tmp_path):
    home = tmp_path / ".openclaw"
    cache = home / "agents" / "main" / "agent" / "codex-home" / ".tmp" / "plugins" / "plugins" / "replayio"
    _write_hooks(
        cache / "hooks.json",
        {"PostToolUse": {"Bash": "./scripts/post_bash_upload.sh"}, "Stop": "./scripts/stop_close_and_upload.sh"},
    )
    f = check_codex_plugin_hooks(_ctx(home))
    assert f.status == WARN
    assert any("post_bash_upload.sh" in e for e in f.evidence)


def test_hooks_json_without_shell_script_passes(tmp_path):
    home = tmp_path / ".openclaw"
    cache = home / "agents" / "main" / "agent" / "codex-home" / ".tmp" / "plugins" / "plugins" / "benign"
    _write_hooks(cache / "hooks.json", {"PostToolUse": {"Bash": "logOnly"}, "Stop": "noop"})
    f = check_codex_plugin_hooks(_ctx(home))
    assert f.status == PASS


def test_bare_sh_command_detected(tmp_path):
    home = tmp_path / ".openclaw"
    cache = home / "agents" / "main" / "agent" / "codex-home" / ".tmp" / "plugins" / "plugins" / "conn2"
    _write_hooks(cache / "hooks.json", {"Stop": "bash cleanup.sh --force"})
    f = check_codex_plugin_hooks(_ctx(home))
    assert f.status == WARN


def test_malformed_hooks_json_does_not_crash(tmp_path):
    home = tmp_path / ".openclaw"
    cache = home / "agents" / "main" / "agent" / "codex-home" / ".tmp" / "plugins" / "plugins" / "broken"
    cache.mkdir(parents=True)
    (cache / "hooks.json").write_text("{not valid json", encoding="utf-8")
    f = check_codex_plugin_hooks(_ctx(home))
    # A cache dir + hooks.json exist but nothing parseable — must never crash, never FAIL.
    assert f.status != "FAIL"


def test_never_fails(tmp_path):
    home = tmp_path / ".openclaw"
    cache = home / "agents" / "main" / "agent" / "codex-home" / ".tmp" / "plugins" / "plugins" / "replayio"
    _write_hooks(cache / "hooks.json", {"PostToolUse": {"Bash": "./scripts/upload.sh"}})
    assert check_codex_plugin_hooks(_ctx(home)).status != "FAIL"


# ---------------------------------------------------------------------------
# Fixture-level (collect())
# ---------------------------------------------------------------------------

def test_bad_fixture_warns():
    ctx = collect(FIXTURES / "bad_b151_codex_plugin_hooks")
    f = check_codex_plugin_hooks(ctx)
    assert f.status == WARN
    assert any("replayio" in e for e in f.evidence)


def test_clean_fixture_passes():
    ctx = collect(FIXTURES / "clean_b151_codex_plugin_hooks")
    f = check_codex_plugin_hooks(ctx)
    assert f.status == PASS


def test_real_fixtures_are_unknown_not_false_positive():
    for fx in ("home_safe", "home_vuln"):
        ctx = collect(FIXTURES / fx)
        assert check_codex_plugin_hooks(ctx).status == UNKNOWN


def test_registered_in_audit():
    from clawseccheck import audit
    _ctx_, findings, _score = audit(FIXTURES / "bad_b151_codex_plugin_hooks", include_native=False)
    ids = {f.id for f in findings}
    assert "B151" in ids
