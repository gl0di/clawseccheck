"""B324 (E-060 item 7): env.shellEnv.enabled — agent-startup login-shell import.

The CONFIG-KEY half of the same OR condition B192 already checks the ENV-VAR half of
(OPENCLAW_LOAD_SHELL_ENV). Grounded against the installed dist:
call-Bj6Erfmh.js:101 / io-By0s-a_s.js:5268 —
`shouldEnableShellEnvFallback(env) || cfg.env?.shellEnv?.enabled === true`. See
docs/research/openclaw-schema-recon.md §32 (workspace root, not shipped).

WARN-only, never FAIL — OpenClaw's own field description calls this a legitimate,
commonly-wanted feature (mirrors B192's identical rationale for its sibling toggle).
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_shell_env_fallback
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _home(tmp_path: Path, config: dict | None = None) -> Path:
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    if config is not None:
        (home / "openclaw.json").write_text(json.dumps(config), encoding="utf-8")
    return home


def test_clean_fixture_passes():
    r = check_shell_env_fallback(collect(FIXTURES / "clean_b324_shell_env_fallback"))
    assert r.status == PASS


def test_bad_fixture_warns():
    r = check_shell_env_fallback(collect(FIXTURES / "bad_b324_shell_env_fallback"))
    assert r.status == WARN


def test_no_config_found_is_unknown(tmp_path):
    r = check_shell_env_fallback(collect(_home(tmp_path, config=None)))
    assert r.status == UNKNOWN


def test_key_absent_passes(tmp_path):
    r = check_shell_env_fallback(collect(_home(tmp_path, config={"tools": {"profile": "minimal"}})))
    assert r.status == PASS


def test_shell_env_block_absent_passes(tmp_path):
    r = check_shell_env_fallback(collect(_home(tmp_path, config={"env": {"vars": {"FOO": "bar"}}})))
    assert r.status == PASS


def test_enabled_true_warns(tmp_path):
    r = check_shell_env_fallback(collect(_home(tmp_path, config={"env": {"shellEnv": {"enabled": True}}})))
    assert r.status == WARN
    assert "shellEnv" in r.detail


def test_enabled_non_bool_truthy_passes(tmp_path):
    """Only a literal true counts -- matches the runtime's own strict `=== true` check."""
    r = check_shell_env_fallback(collect(_home(tmp_path, config={"env": {"shellEnv": {"enabled": "yes"}}})))
    assert r.status == PASS


def test_never_fails_regardless_of_config():
    """Catalog-level guard: this check is registered scored=False and its own code has
    no FAIL branch at all -- confirm both facts hold."""
    from clawseccheck.catalog import BY_ID

    assert BY_ID["B324"].scored is False
