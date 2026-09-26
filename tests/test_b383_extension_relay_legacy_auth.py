"""B383 (F-195): browser.extensionRelay.allowLegacyAuth accepts legacy relay auth by
default.

New in OpenClaw 2026.8.1, re-grounded here against the installed 2026.9.5 dist (no
drift found). Field path: zod-schema-DN2u5FdA.mjs:1601-1604, nested under the existing
top-level `browser:` object. Description (schema-CwAIqZVE.mjs:766): "Temporarily
accepts legacy Bearer, Basic, and token-subprotocol relay authentication. Default: true
for one migration window."

RUNTIME DEFAULT, confirmed at two independent read sites, not just the schema
doc-comment:

  * config-Bv9CXmGW.mjs:230 (resolveBrowserConfig, the function BOTH the Gateway relay
    startup and the `openclaw browser extension` CLI call to get the resolved browser
    config): `extensionRelay: { allowLegacyAuth: cfg?.extensionRelay?.allowLegacyAuth ??
    true }`.
  * gateway-relay-route-2phSkPrI.mjs:116 (the Gateway HTTP route's own auth gate, read
    independently): `const allowLegacyAuth = getRuntimeConfig().browser?.extensionRelay
    ?.allowLegacyAuth !== false;`.

Both agree: absent and explicit `true` are the IDENTICAL runtime state -- only a literal
`false` closes the legacy path. See docs/research/openclaw-schema-recon.md §43
(workspace root, not shipped) for the full grounding record, including why
docs/tools/chrome-extension.md's "standalone daemon defaults to v2-only" claim is about
a different component and does not contradict the above for the Gateway-owned relay
this check reads.

WARN-MAX BY DESIGN, NOT FAIL-CAPABLE. This check can never emit FAIL, so CLAUDE.md
§4's C-135 adversarial-FAIL-review gate does not apply to it -- there is no FAIL branch
for an independent reviewer to try to trigger wrongly. Rationale (see
checks/_egress.py's check_browser_extension_relay_legacy_auth docstring/leading comment
for the full record):

  1. This is a vendor-declared, time-bound COMPATIBILITY default, not a state the
     operator chose -- a FAIL would fire on essentially every fresh 2026.8.1+ install.
  2. OpenClaw's own bundled audit rates the byte-identical condition `warn`, not
     `critical` (docs/gateway/security/audit-checks.md:89,
     `browser.extension_relay_legacy_auth`).
  3. The legacy path still requires the correct relay token
     (`safeEqualSecret(token, legacyToken)`, gateway-relay-route-2phSkPrI.mjs:118) -- a
     protocol-strength downgrade, not an authentication bypass.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import BY_ID, FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_browser_extension_relay_legacy_auth
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_BASE_CONFIG = {
    "gateway": {
        "bind": "127.0.0.1:8080",
        "auth": {"mode": "token", "token": "a-very-long-token-of-32-characters"},
    },
    "channels": {"telegram": {"dmPolicy": "allowlist", "groupPolicy": "allowlist"}},
    "session": {"dmScope": "per-peer"},
    "tools": {"profile": "minimal", "sessions": {"visibility": "self"}},
    "logging": {"redactSensitive": "tools"},
    "models": {"main": {"provider": "ollama/llama3"}},
}


def _home(tmp_path: Path, config: dict | None, name: str = "home") -> Path:
    home = tmp_path / name
    home.mkdir(parents=True, exist_ok=True)
    if config is not None:
        path = home / "openclaw.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        path.chmod(0o600)
    return home


def _audit_browser_home(tmp_path: Path, name: str, browser: dict):
    cfg = dict(_BASE_CONFIG)
    cfg["browser"] = browser
    return audit(_home(tmp_path, cfg, name))


def _b383(findings):
    return next(f for f in findings if f.id == "B383")


# ---------------------------------------------------------------------------
# On-disk fixtures
# ---------------------------------------------------------------------------

def test_clean_fixture_passes():
    r = check_browser_extension_relay_legacy_auth(
        collect(FIXTURES / "clean_b383_extension_relay_legacy_auth")
    )
    assert r.status == PASS


def test_bad_fixture_explicit_true_warns():
    r = check_browser_extension_relay_legacy_auth(
        collect(FIXTURES / "bad_b383_extension_relay_legacy_auth")
    )
    assert r.status == WARN
    assert r.status != FAIL


def test_bad_fixture_absent_key_warns():
    """Companion bad fixture: `browser` present, `extensionRelay` never written -- the
    commonest real shape (a fresh 2026.8.1+ install), and the same runtime state as the
    explicit-true fixture."""
    r = check_browser_extension_relay_legacy_auth(
        collect(FIXTURES / "bad_b383_extension_relay_legacy_auth_default")
    )
    assert r.status == WARN


def test_both_bad_fixtures_agree_on_disk():
    absent = check_browser_extension_relay_legacy_auth(
        collect(FIXTURES / "bad_b383_extension_relay_legacy_auth_default")
    )
    explicit = check_browser_extension_relay_legacy_auth(
        collect(FIXTURES / "bad_b383_extension_relay_legacy_auth")
    )
    assert absent.status == explicit.status == WARN


# ---------------------------------------------------------------------------
# UNKNOWN: no config / no browser surface at all
# ---------------------------------------------------------------------------

def test_no_config_found_is_unknown(tmp_path):
    r = check_browser_extension_relay_legacy_auth(collect(_home(tmp_path, config=None)))
    assert r.status == UNKNOWN


def test_no_browser_config_is_unknown(tmp_path):
    home = _home(tmp_path, config={"tools": {"profile": "minimal"}})
    r = check_browser_extension_relay_legacy_auth(collect(home))
    assert r.status == UNKNOWN


def test_config_unreadable_is_unknown(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    path = home / "openclaw.json"
    path.write_text("{not valid json", encoding="utf-8")
    path.chmod(0o600)
    r = check_browser_extension_relay_legacy_auth(collect(home))
    assert r.status == UNKNOWN
    assert r.engine_degraded is True


def test_bundled_plugin_only_browser_is_unknown_not_a_presumed_warn(tmp_path):
    """Design choice, stated explicitly for the reviewer: when browser is intended only
    through the bundled-plugin path (`plugins.entries.browser`) and no `browser` object
    exists at all to read, this check reports UNKNOWN (mirroring B38/B195/B196/B321/
    B322/B330's shared `_browser_surface_absent` idiom) rather than presuming the
    resolved `?? true` default applies. The runtime WOULD still default to true in this
    shape too -- this is a coverage-conservatism choice (UNKNOWN, never a guessed FAIL),
    not a false-FAIL risk."""
    home = _home(
        tmp_path,
        config={"plugins": {"entries": {"browser": {"enabled": True}}}},
    )
    r = check_browser_extension_relay_legacy_auth(collect(home))
    assert r.status == UNKNOWN
    assert r.not_applicable is False


# ---------------------------------------------------------------------------
# PASS: explicit false, or browser.enabled=false
# ---------------------------------------------------------------------------

def test_allow_legacy_false_passes(tmp_path):
    home = _home(tmp_path, {"browser": {"extensionRelay": {"allowLegacyAuth": False}}})
    r = check_browser_extension_relay_legacy_auth(collect(home))
    assert r.status == PASS
    assert r.pass_confidence == "verified"


def test_browser_enabled_false_passes(tmp_path):
    home = _home(
        tmp_path,
        {"browser": {"enabled": False, "extensionRelay": {"allowLegacyAuth": True}}},
    )
    r = check_browser_extension_relay_legacy_auth(collect(home))
    assert r.status == PASS
    assert r.pass_confidence == "verified"


# ---------------------------------------------------------------------------
# WARN: absent, explicit true, or any other non-`false` value -- effective-state
# equivalence, matching the runtime's own `!== false` gate exactly.
# ---------------------------------------------------------------------------

def test_allow_legacy_absent_warns(tmp_path):
    home = _home(tmp_path, {"browser": {"noSandbox": False}})
    r = check_browser_extension_relay_legacy_auth(collect(home))
    assert r.status == WARN


def test_allow_legacy_true_warns_not_fails(tmp_path):
    home = _home(tmp_path, {"browser": {"extensionRelay": {"allowLegacyAuth": True}}})
    r = check_browser_extension_relay_legacy_auth(collect(home))
    assert r.status == WARN
    assert r.status != FAIL


def test_absent_and_explicit_true_reach_the_same_status(tmp_path):
    absent = check_browser_extension_relay_legacy_auth(
        collect(_home(tmp_path / "a", {"browser": {"noSandbox": False}}))
    )
    explicit = check_browser_extension_relay_legacy_auth(
        collect(
            _home(tmp_path / "b", {"browser": {"extensionRelay": {"allowLegacyAuth": True}}})
        )
    )
    assert absent.status == explicit.status == WARN


def test_deleting_the_key_does_not_change_the_grade(tmp_path):
    """No-op-edit guard: absent and explicit-true are the same runtime exposure, so a
    no-op edit that only deletes (or adds) the line must move the score by exactly
    zero."""
    _, f_absent, s_absent = _audit_browser_home(tmp_path, "absent", {"noSandbox": False})
    _, f_true, s_true = _audit_browser_home(
        tmp_path, "explicit", {"extensionRelay": {"allowLegacyAuth": True}}
    )
    assert _b383(f_absent).status == _b383(f_true).status == WARN
    assert s_true.score == s_absent.score
    assert s_true.grade == s_absent.grade


def test_allow_legacy_non_bool_is_warn(tmp_path):
    """Only a literal `false` closes the legacy path (the runtime's own `!== false`
    gate). A stray non-boolean value cannot be confirmed disabled, so it lands on the
    same WARN bar rather than a guessed PASS."""
    home = _home(tmp_path, {"browser": {"extensionRelay": {"allowLegacyAuth": "no"}}})
    r = check_browser_extension_relay_legacy_auth(collect(home))
    assert r.status == WARN


def test_disabling_legacy_auth_improves_the_grade(tmp_path):
    """MEDIUM severity + WARN's half-weight means this single finding is too small to
    move the rounded integer `score` in every base config (it does not here) -- assert
    on the underlying weighted `earned` total instead, which the WARN->PASS transition
    always increases."""
    _, _, s_on = _audit_browser_home(tmp_path, "on", {"noSandbox": False})
    _, f_off, s_off = _audit_browser_home(
        tmp_path, "off", {"extensionRelay": {"allowLegacyAuth": False}}
    )
    assert _b383(f_off).status == PASS
    assert s_off.earned > s_on.earned
    assert s_off.score >= s_on.score


# ---------------------------------------------------------------------------
# WARN-max guard: no input this check reads can ever produce FAIL.
# ---------------------------------------------------------------------------

def test_no_input_ever_reaches_fail(tmp_path):
    shapes = [
        {"noSandbox": False},
        {"extensionRelay": {"allowLegacyAuth": True}},
        {"extensionRelay": {"allowLegacyAuth": False}},
        {"extensionRelay": {"allowLegacyAuth": "maybe"}},
        {"extensionRelay": {}},
        {"extensionRelay": "not-a-dict"},
        {"enabled": False},
        {"enabled": True, "extensionRelay": {"allowLegacyAuth": True}},
    ]
    for i, browser in enumerate(shapes):
        r = check_browser_extension_relay_legacy_auth(
            collect(_home(tmp_path / f"shape_{i}", {"browser": browser}))
        )
        assert r.status != FAIL, f"shape {browser!r} must never reach FAIL, got {r.status}"


# ---------------------------------------------------------------------------
# Catalog / metadata
# ---------------------------------------------------------------------------

def test_catalog_metadata():
    meta = BY_ID["B383"]
    assert meta.block == "hardening"
    assert meta.scored is True
    assert meta.surface == "sessions"


def test_all_three_statuses_are_reachable(tmp_path):
    reached = set()
    reached.add(
        check_browser_extension_relay_legacy_auth(collect(_home(tmp_path / "u", config={}))).status
    )
    reached.add(
        check_browser_extension_relay_legacy_auth(
            collect(_home(tmp_path / "p", {"browser": {"extensionRelay": {"allowLegacyAuth": False}}}))
        ).status
    )
    reached.add(
        check_browser_extension_relay_legacy_auth(
            collect(_home(tmp_path / "w", {"browser": {"noSandbox": False}}))
        ).status
    )
    assert reached == {UNKNOWN, PASS, WARN}
