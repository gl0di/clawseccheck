"""B323 (E-060 coverage-gap batch): env.vars.PATH / env.<KEY> catchall PATH override.

Narrowed on grounding from the epic's original "report any residual env.vars/env
catchall key OpenClaw's own blocklist doesn't already block" framing. That blocklist
(host-env-security-CWC2ZCy4.js, ~254 explicit keys + 7 prefixes + 1 regex, referenced
identically by the already-shipped B184 check) is comprehensive enough that flagging
every other residual key would false-WARN on the feature's own legitimate purpose
(arbitrary app/API-key vars) -- a Golden Rule #5 violation. The one concrete gap this
check targets is PATH itself, which does not appear in that blocklist
(config-env-vars-DlUfO5Q_.js:36-38 isBlockedConfigEnvVar / host-env-security-
CWC2ZCy4.js:5-316). See docs/research/openclaw-schema-recon.md (workspace root, not
shipped) for the full grounding notes.

WARN-only, never FAIL -- whether a config-declared PATH has any real effect depends on
a runtime fact (was the launch environment's PATH already non-empty) this static
auditor cannot observe; applyConfigEnvVars() never overwrites an already-non-empty
value, and every grounded live call site defaults to process.env.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_env_vars_path_override
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _home(tmp_path: Path, config: dict | None = None) -> Path:
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    if config is not None:
        (home / "openclaw.json").write_text(json.dumps(config), encoding="utf-8")
    return home


def test_clean_fixture_passes():
    r = check_env_vars_path_override(collect(FIXTURES / "clean_b323_env_path_override"))
    assert r.status == PASS


def test_bad_fixture_warns():
    r = check_env_vars_path_override(collect(FIXTURES / "bad_b323_env_path_override"))
    assert r.status == WARN
    assert "PATH" in r.detail


def test_no_config_found_is_unknown(tmp_path):
    r = check_env_vars_path_override(collect(_home(tmp_path, config=None)))
    assert r.status == UNKNOWN


def test_config_unparseable_is_unknown(tmp_path):
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    (home / "openclaw.json").write_text("{ not valid json", encoding="utf-8")
    r = check_env_vars_path_override(collect(home))
    assert r.status == UNKNOWN


def test_env_block_absent_passes(tmp_path):
    r = check_env_vars_path_override(collect(_home(tmp_path, config={"tools": {"profile": "minimal"}})))
    assert r.status == PASS


def test_env_vars_block_present_no_path_passes(tmp_path):
    cfg = {"env": {"vars": {"MY_APP_KEY": "some-value", "NODE_OPTIONS": "--foo"}}}
    r = check_env_vars_path_override(collect(_home(tmp_path, config=cfg)))
    assert r.status == PASS


def test_env_vars_path_literal_warns(tmp_path):
    cfg = {"env": {"vars": {"PATH": "/opt/evil/bin:/usr/bin"}}}
    r = check_env_vars_path_override(collect(_home(tmp_path, config=cfg)))
    assert r.status == WARN
    assert "env.vars.PATH" in " ".join(r.evidence)


def test_env_catchall_path_literal_warns(tmp_path):
    """The OTHER catchall shape -- env.<KEY> directly on the env object, not env.vars."""
    cfg = {"env": {"PATH": "/opt/evil/bin:/usr/bin"}}
    r = check_env_vars_path_override(collect(_home(tmp_path, config=cfg)))
    assert r.status == WARN
    assert "env.PATH" in " ".join(r.evidence)


def test_env_catchall_case_insensitive_key_warns(tmp_path):
    """normalizeEnvVarKey doesn't uppercase, but Windows env lookups are
    case-insensitive and an operator could plausibly type lowercase -- treat any
    case variant of the key as the same override intent."""
    cfg = {"env": {"vars": {"path": "/opt/evil/bin"}}}
    r = check_env_vars_path_override(collect(_home(tmp_path, config=cfg)))
    assert r.status == WARN


def test_env_shellenv_key_not_mistaken_for_catchall_path(tmp_path):
    """env.shellEnv is a named object field, not a catchall entry -- must not be
    scanned as if it were a stray key/value pair (it isn't a string value anyway,
    but this pins the exclusion explicitly)."""
    cfg = {"env": {"shellEnv": {"enabled": True}, "vars": {"SAFE_KEY": "ok"}}}
    r = check_env_vars_path_override(collect(_home(tmp_path, config=cfg)))
    assert r.status == PASS


def test_empty_string_path_value_passes(tmp_path):
    """An empty/whitespace-only value is dropped by OpenClaw's own
    isConfigRuntimeEnvVarAllowed (Boolean(value.trim())) -- never applied, so not a
    finding."""
    cfg = {"env": {"vars": {"PATH": "   "}}}
    r = check_env_vars_path_override(collect(_home(tmp_path, config=cfg)))
    assert r.status == PASS


def test_non_string_path_value_passes(tmp_path):
    """A malformed catchall entry (non-string) is silently skipped by
    collectConfigEnvVarsByTarget's typeof value !== "string" guard -- never reaches
    the process environment."""
    cfg = {"env": {"vars": {"PATH": ["not", "a", "string"]}}}
    r = check_env_vars_path_override(collect(_home(tmp_path, config=cfg)))
    assert r.status == PASS


def test_path_value_with_substitution_token_passes(tmp_path):
    """A value containing an unresolved ${...} reference is dropped by OpenClaw's own
    containsEnvVarReference() gate -- not a literal override, so not a finding.
    Adversarial near-miss: this is a plausible benign config (referencing another
    declared var) that must NOT trigger a false WARN."""
    cfg = {"env": {"vars": {"PATH": "${CUSTOM_PATH}"}}}
    r = check_env_vars_path_override(collect(_home(tmp_path, config=cfg)))
    assert r.status == PASS


def test_non_path_key_named_similarly_passes(tmp_path):
    """Adversarial near-miss: a key that merely CONTAINS "PATH" (e.g. GOPATH,
    PYTHONPATH) must not be mistaken for an exact PATH override -- GOPATH/PYTHONPATH
    are themselves already in OpenClaw's own blocklist and out of this check's scope
    entirely."""
    cfg = {"env": {"vars": {"GOPATH": "/opt/go", "MY_PATH_SUFFIX": "/opt/x"}}}
    r = check_env_vars_path_override(collect(_home(tmp_path, config=cfg)))
    assert r.status == PASS


def test_mixed_case_pseudo_token_warns(tmp_path):
    """C-135 regression: OpenClaw's real containsEnvVarReference() only treats an
    unescaped ${ALL_CAPS_NAME} as a genuine reference (env-substitution-
    CATXLg7n.js:23 ENV_VAR_NAME_PATTERN = /^[A-Z_][A-Z0-9_]*$/). A mixed-case name
    like ${systemRoot} does NOT match that pattern, so OpenClaw's own
    isConfigRuntimeEnvVarAllowed() does NOT block it -- it applies the value
    verbatim, literal ${systemRoot} text and all, including any real path segments
    elsewhere in the same string. The original naive `"${" not in value` heuristic
    treated any "${" substring as a real reference and silently skipped this --
    a false negative that would let a real /opt/evil/bin PATH entry through
    unflagged. Found and fixed in this C-135 pass."""
    cfg = {"env": {"vars": {"PATH": "${systemRoot}:/opt/evil/bin:/usr/bin"}}}
    r = check_env_vars_path_override(collect(_home(tmp_path, config=cfg)))
    assert r.status == WARN
    assert "env.vars.PATH" in " ".join(r.evidence)


def test_digit_leading_fake_token_warns(tmp_path):
    """C-135 regression: ${1BAD} is not a valid env-var name (must start with a
    letter or underscore per ENV_VAR_NAME_PATTERN) so OpenClaw does not treat it as
    a reference either -- same false-negative shape as the mixed-case case."""
    cfg = {"env": {"vars": {"PATH": "${1BAD}/opt/evil/bin"}}}
    r = check_env_vars_path_override(collect(_home(tmp_path, config=cfg)))
    assert r.status == WARN


def test_unterminated_brace_warns(tmp_path):
    """C-135 regression: a ${... with no closing brace is not a real token per
    OpenClaw's own parseEnvTokenAt (requires a matching `}`), so it is applied
    verbatim -- must be flagged, not silently skipped."""
    cfg = {"env": {"vars": {"PATH": "${OOPS/opt/evil/bin"}}}
    r = check_env_vars_path_override(collect(_home(tmp_path, config=cfg)))
    assert r.status == WARN


def test_escaped_token_with_real_segment_warns(tmp_path):
    """C-135 regression: $${FOO} is OpenClaw's escape syntax for a literal ${FOO}
    (env-substitution-CATXLg7n.js "Escape with $${}" ) -- containsEnvVarReference()
    explicitly does NOT treat it as a reference, so OpenClaw applies the whole
    string verbatim (including the literal $${FOO} text) to PATH. Any real path
    segment elsewhere in the same value is therefore also applied and must be
    flagged."""
    cfg = {"env": {"vars": {"PATH": "$${FOO}:/opt/evil/bin"}}}
    r = check_env_vars_path_override(collect(_home(tmp_path, config=cfg)))
    assert r.status == WARN


def test_genuine_uppercase_reference_still_passes(tmp_path):
    """Regression guard for the fix above: a REAL substitution reference (all-caps
    name, properly closed) must still resolve to PASS -- OpenClaw's own
    containsEnvVarReference() blocks it from ever being applied. This is the
    positive control for test_mixed_case_pseudo_token_warns et al."""
    cfg = {"env": {"vars": {"PATH": "${CUSTOM_PATH}"}}}
    r = check_env_vars_path_override(collect(_home(tmp_path, config=cfg)))
    assert r.status == PASS


def test_never_fails_regardless_of_config(tmp_path):
    """The check's own code has no FAIL branch at all -- sweep a range of shapes
    (including the WARN-triggering ones) and confirm none produce FAIL. (The
    catalog's scored=False registration is applied centrally by the orchestrator
    from this module's structured-output report, not asserted here against the
    provisional stub.)"""
    from clawseccheck.catalog import FAIL

    configs = [
        None,
        {},
        {"env": {"vars": {"PATH": "/opt/evil/bin"}}},
        {"env": {"PATH": "/opt/evil/bin"}},
        {"env": {"vars": {"path": "/opt/evil/bin"}}},
        {"env": {"vars": {"NODE_OPTIONS": "--foo"}}},
    ]
    for i, cfg in enumerate(configs):
        home = tmp_path / f"sweep{i}"
        r = check_env_vars_path_override(collect(_home(home, config=cfg)))
        assert r.status != FAIL
