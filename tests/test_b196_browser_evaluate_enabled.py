"""B196 (E-060 item 3): browser.evaluateEnabled arbitrary-JS sink.

OpenClaw defaults this to true when the key is absent -- re-verified directly against
the JS bundle: config-DpWXcVmn.js:441 `const evaluateEnabled = cfg?.evaluateEnabled ??
true;`, enforced at routes-VNv3nd0n.js:1274 (an `evaluate` action 403s with
`evaluateDisabled` only when the resolved flag is false). See
docs/research/openclaw-schema-recon.md §31.1 (workspace root, not shipped).

Severity shape (mirrors B38's own absent-hostnameAllowlist WARN-not-FAIL treatment for
a permissive-by-default, non-deliberate state):
  - no browser config at all       -> UNKNOWN (browser tool not in use)
  - evaluateEnabled absent         -> WARN   (vendor default is permissive, but the
                                                operator never made an explicit choice)
  - evaluateEnabled == true        -> FAIL   (deliberate opt-in to the sink)
  - evaluateEnabled == false       -> PASS
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_browser_evaluate_enabled
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _home(tmp_path: Path, config: dict | None = None) -> Path:
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    if config is not None:
        (home / "openclaw.json").write_text(json.dumps(config), encoding="utf-8")
    return home


# ---------------------------------------------------------------------------
# On-disk fixtures
# ---------------------------------------------------------------------------

def test_clean_fixture_passes():
    r = check_browser_evaluate_enabled(collect(FIXTURES / "clean_b196_browser_evaluate_enabled"))
    assert r.status == PASS


def test_bad_fixture_fails():
    r = check_browser_evaluate_enabled(collect(FIXTURES / "bad_b196_browser_evaluate_enabled"))
    assert r.status == FAIL


# ---------------------------------------------------------------------------
# UNKNOWN: browser tool not configured at all
# ---------------------------------------------------------------------------

def test_no_browser_config_is_unknown(tmp_path):
    r = check_browser_evaluate_enabled(collect(_home(tmp_path, config={"tools": {"profile": "minimal"}})))
    assert r.status == UNKNOWN


def test_no_config_found_is_unknown(tmp_path):
    r = check_browser_evaluate_enabled(collect(_home(tmp_path, config=None)))
    assert r.status == UNKNOWN


# ---------------------------------------------------------------------------
# WARN: absent key — the vendor default is permissive but not an explicit operator choice
# ---------------------------------------------------------------------------

def test_evaluate_enabled_absent_warns(tmp_path):
    home = _home(tmp_path, config={"browser": {"noSandbox": False}})
    r = check_browser_evaluate_enabled(collect(home))
    assert r.status == WARN
    assert "defaults this to true" in r.detail


# ---------------------------------------------------------------------------
# FAIL: explicit true — a deliberate opt-in to the arbitrary-JS sink
# ---------------------------------------------------------------------------

def test_evaluate_enabled_true_fails(tmp_path):
    home = _home(tmp_path, config={"browser": {"evaluateEnabled": True}})
    r = check_browser_evaluate_enabled(collect(home))
    assert r.status == FAIL


def test_evaluate_enabled_non_bool_truthy_is_not_fail(tmp_path):
    """Only a literal `true` counts (matches OpenClaw's own `cfg?.evaluateEnabled ??
    true` nullish-coalescing check, which only treats null/undefined as "absent" --
    but a stray non-boolean value reaching the config is not a state this check should
    guess a hard FAIL for)."""
    home = _home(tmp_path, config={"browser": {"evaluateEnabled": "yes"}})
    r = check_browser_evaluate_enabled(collect(home))
    assert r.status == WARN


# ---------------------------------------------------------------------------
# PASS: explicit false
# ---------------------------------------------------------------------------

def test_evaluate_enabled_false_passes(tmp_path):
    home = _home(tmp_path, config={"browser": {"evaluateEnabled": False}})
    r = check_browser_evaluate_enabled(collect(home))
    assert r.status == PASS
