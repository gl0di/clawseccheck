"""B196 (E-060 item 3): browser.evaluateEnabled arbitrary-JS sink.

OpenClaw defaults this to true when the key is absent -- re-verified directly against
the JS bundle: config-DpWXcVmn.js:441 `const evaluateEnabled = cfg?.evaluateEnabled ??
true;`, the defaults table config-D9HgDUPt.js:103 `"browser.evaluateEnabled": true`,
and the same `?? true` resolution in sandbox-DtTssSMH.js:394,1299; enforced at
routes-VNv3nd0n.js:1274 (an `evaluate` action 403s with `evaluateDisabled` only when the
resolved flag is false). See docs/research/openclaw-schema-recon.md §31.1 (workspace
root, not shipped).

EFFECTIVE-STATE GRADING (B-331). This file previously documented and pinned a split --
absent -> WARN, explicit `true` -> FAIL -- as deliberate. That split was wrong, and this
file now pins its correction. The dist facts above prove an absent key and an explicit
`true` are byte-for-byte the SAME runtime exposure, so grading them 16 points and two
letter grades apart graded the config TEXT rather than what the machine does. Concretely
it (a) made the grade gameable by a no-op edit -- a user at C could reach A by DELETING
the `evaluateEnabled: true` line, with nothing changing on their machine, (b) inverted
the incentive by punishing the operator who writes their configuration down explicitly,
and (c) under-reported the common case, since almost nobody writes the key and so most
genuinely-exposed configs landed on the lenient rung.

Severity shape -- ONE bar for one effective state:
  - no browser config at all            -> UNKNOWN (browser tool not in use)
  - evaluateEnabled absent              -> WARN  (the sink is ON)
  - evaluateEnabled == true             -> WARN  (the SAME state, written down)
  - evaluateEnabled == any non-false    -> WARN  (cannot be confirmed disabled)
  - evaluateEnabled == false            -> PASS  (the only state that closes the sink)

WARN and not FAIL is the deliberate choice: this is the documented vendor default of a
documented feature (act:evaluate / wait --fn), so a HIGH FAIL would cap the grade of
essentially every browser-tool user for shipping defaults, and it would double-count the
reachability leg B38 already grades (ssrfPolicy.hostnameAllowlist). It also matches B38's
own treatment of a permissive-by-default open state as WARN. The sink-plus-reachability
combination belongs to the risk engine, not to a single check's severity.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_browser_evaluate_enabled
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

# Minimal but realistic base config, so audit() exercises the whole pipeline rather than
# bailing out early. The effective-state homes below differ ONLY by `browser`.
_BASE_CONFIG = {
    "gateway": {
        "bind": "127.0.0.1:8080",
        "auth": {"mode": "token", "token": "a-very-long-token-of-32-characters"},
    },
    "channels": {"telegram": {"dmPolicy": "allowlist", "groupPolicy": "allowlist"}},
    "tools": {"profile": "minimal"},
    "logging": {"redactSensitive": "tools"},
    "models": {"main": {"provider": "ollama/llama3"}},
}


def _home(tmp_path: Path, config: dict | None = None) -> Path:
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    if config is not None:
        (home / "openclaw.json").write_text(json.dumps(config), encoding="utf-8")
    return home


def _audit_browser_home(tmp_path: Path, name: str, browser: dict):
    """Audit a home whose config is _BASE_CONFIG plus the given `browser` block.

    Perms are pinned to 0600 for the same reason conftest pins the on-disk fixtures: an
    at-rest permission check must not make the score depend on the runner's umask.
    """
    home = tmp_path / name
    home.mkdir(parents=True, exist_ok=True)
    cfg = dict(_BASE_CONFIG)
    cfg["browser"] = browser
    path = home / "openclaw.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    path.chmod(0o600)
    return audit(home)


def _b196(findings):
    return next(f for f in findings if f.id == "B196")


# ---------------------------------------------------------------------------
# On-disk fixtures
# ---------------------------------------------------------------------------

def test_clean_fixture_passes():
    r = check_browser_evaluate_enabled(collect(FIXTURES / "clean_b196_browser_evaluate_enabled"))
    assert r.status == PASS


def test_bad_fixture_explicit_true_warns():
    """The bad fixture's finding still FIRES; the bar is now WARN, not FAIL (B-331)."""
    r = check_browser_evaluate_enabled(collect(FIXTURES / "bad_b196_browser_evaluate_enabled"))
    assert r.status == WARN
    assert r.status != FAIL


def test_bad_fixture_absent_key_warns():
    """Companion bad fixture: `browser` present, `evaluateEnabled` never written -- the
    commonest real shape, and the same runtime exposure as the explicit-true fixture."""
    r = check_browser_evaluate_enabled(collect(FIXTURES / "bad_b196_browser_evaluate_default"))
    assert r.status == WARN


def test_both_bad_fixtures_agree_on_disk():
    absent = check_browser_evaluate_enabled(collect(FIXTURES / "bad_b196_browser_evaluate_default"))
    explicit = check_browser_evaluate_enabled(collect(FIXTURES / "bad_b196_browser_evaluate_enabled"))
    assert absent.status == explicit.status


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
# B-331: effective state, not spelling — absent and explicit `true` are one state
# ---------------------------------------------------------------------------

def test_evaluate_enabled_absent_warns(tmp_path):
    home = _home(tmp_path, config={"browser": {"noSandbox": False}})
    r = check_browser_evaluate_enabled(collect(home))
    assert r.status == WARN
    # The text must say plainly that the vendor default leaves the sink on.
    assert "vendor default for this key is true" in r.detail
    assert "does not turn the sink off" in r.detail


def test_evaluate_enabled_true_warns_not_fails(tmp_path):
    """Explicit `true` is no longer a FAIL: it is the identical runtime state to the
    absent key, and OpenClaw ships the sink on."""
    home = _home(tmp_path, config={"browser": {"evaluateEnabled": True}})
    r = check_browser_evaluate_enabled(collect(home))
    assert r.status == WARN
    assert r.status != FAIL


def test_absent_and_explicit_true_reach_the_same_status(tmp_path):
    absent = check_browser_evaluate_enabled(
        collect(_home(tmp_path / "a", config={"browser": {"noSandbox": False}}))
    )
    explicit = check_browser_evaluate_enabled(
        collect(_home(tmp_path / "b", config={"browser": {"evaluateEnabled": True}}))
    )
    assert absent.status == explicit.status == WARN
    # Different spellings may be named differently, but both must state the one
    # effective fact: only an explicit false closes the sink.
    for r in (absent, explicit):
        assert "only an explicit false disables it" in r.detail


def test_deleting_the_key_does_not_change_the_grade(tmp_path):
    """THE GUARD that would have caught B-331.

    Absent and explicit-`true` are the same runtime exposure, so a no-op edit that only
    deletes (or adds) the line must move the score by EXACTLY zero. Before the fix this
    delta was 16 points and two letter grades (A/95 vs C/79).
    """
    _, f_absent, s_absent = _audit_browser_home(tmp_path, "absent", {"noSandbox": False})
    _, f_true, s_true = _audit_browser_home(
        tmp_path, "explicit", {"noSandbox": False, "evaluateEnabled": True}
    )

    assert _b196(f_absent).status == _b196(f_true).status
    assert s_true.score - s_absent.score == 0
    assert s_true.grade == s_absent.grade


def test_disabling_the_sink_does_improve_the_grade(tmp_path):
    """The converse of the guard above: a REAL change (closing the sink) must still be
    rewarded, so the fix cannot have been achieved by making B196 inert."""
    _, _, s_on = _audit_browser_home(tmp_path, "on", {"noSandbox": False})
    _, f_off, s_off = _audit_browser_home(
        tmp_path, "off", {"noSandbox": False, "evaluateEnabled": False}
    )
    assert _b196(f_off).status == PASS
    assert s_off.score > s_on.score


def test_evaluate_enabled_non_bool_is_warn(tmp_path):
    """Only a literal `false` closes the sink (OpenClaw's `cfg?.evaluateEnabled ?? true`
    treats null/undefined as absent). A stray non-boolean value cannot be confirmed
    disabled, so it lands on the same WARN bar rather than a guessed PASS or FAIL."""
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
