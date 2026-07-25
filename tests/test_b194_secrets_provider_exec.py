"""B194 (E-060 item 1): secrets.providers.<name> with source:"exec" escape flags.

A distinct config subtree from B174 (security.installPolicy.exec) -- this command runs
on every secret RESOLVE, not just install/update, with the resolved credential in hand
once it returns. Grounded against the installed OpenClaw dist's Zod schema
(config-schema.d.ts:157-187) -- see docs/research/openclaw-schema-recon.md §31
(workspace root, not shipped).

Severity shape (mirrors B174):
  - no secrets.providers block, or none use source:"exec"    -> UNKNOWN
  - allowInsecurePath=true, no trustedDirs                   -> FAIL (unrestrained)
  - allowInsecurePath=true + trustedDirs set                 -> WARN (scoped)
  - allowSymlinkCommand=true alone                            -> WARN
  - secret-shaped passEnv name(s), no escape flag             -> WARN
  - exec provider(s) configured, no danger signal             -> PASS
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_secrets_provider_exec
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
    r = check_secrets_provider_exec(collect(FIXTURES / "clean_b194_secrets_provider_exec"))
    assert r.status == PASS


def test_bad_fixture_insecure_path_fails():
    r = check_secrets_provider_exec(
        collect(FIXTURES / "bad_b194_secrets_provider_exec_insecure_path")
    )
    assert r.status == FAIL
    assert any("allowInsecurePath" in e for e in r.evidence)


# ---------------------------------------------------------------------------
# UNKNOWN paths — never a guess FAIL (GR#5)
# ---------------------------------------------------------------------------

def test_no_config_found_is_unknown(tmp_path):
    r = check_secrets_provider_exec(collect(_home(tmp_path, config=None)))
    assert r.status == UNKNOWN


def test_no_secrets_block_is_unknown(tmp_path):
    r = check_secrets_provider_exec(collect(_home(tmp_path, config={"tools": {"profile": "minimal"}})))
    assert r.status == UNKNOWN


def test_secrets_providers_empty_is_unknown(tmp_path):
    r = check_secrets_provider_exec(collect(_home(tmp_path, config={"secrets": {"providers": {}}})))
    assert r.status == UNKNOWN


def test_env_source_provider_only_is_unknown(tmp_path):
    """An env-source (or file-source) provider has none of the exec escape surface --
    the check has nothing to assess and must not fabricate a verdict."""
    home = _home(tmp_path, config={"secrets": {"providers": {
        "vault-env": {"source": "env", "allowlist": ["VAULT_TOKEN"]},
    }}})
    r = check_secrets_provider_exec(collect(home))
    assert r.status == UNKNOWN


def test_plugin_integration_exec_variant_is_unknown(tmp_path):
    """The schema's second source:"exec" shape (pluginIntegration) has no `command`
    field and none of the writable-path/symlink escape surface this check models --
    must not be treated as a command-based exec provider."""
    home = _home(tmp_path, config={"secrets": {"providers": {
        "vault-plugin": {
            "source": "exec",
            "pluginIntegration": {"pluginId": "vault", "integrationId": "fetch"},
        },
    }}})
    r = check_secrets_provider_exec(collect(home))
    assert r.status == UNKNOWN


# ---------------------------------------------------------------------------
# PASS: exec provider(s) with no escape flag
# ---------------------------------------------------------------------------

def test_exec_provider_no_escape_flags_passes(tmp_path):
    home = _home(tmp_path, config={"secrets": {"providers": {
        "vault-exec": {"source": "exec", "command": "/opt/vault/fetch.sh"},
    }}})
    r = check_secrets_provider_exec(collect(home))
    assert r.status == PASS


def test_exec_provider_both_escape_flags_false_passes(tmp_path):
    home = _home(tmp_path, config={"secrets": {"providers": {
        "vault-exec": {
            "source": "exec",
            "command": "/opt/vault/fetch.sh",
            "allowInsecurePath": False,
            "allowSymlinkCommand": False,
        },
    }}})
    r = check_secrets_provider_exec(collect(home))
    assert r.status == PASS


# ---------------------------------------------------------------------------
# FAIL: unrestrained allowInsecurePath
# ---------------------------------------------------------------------------

def test_allow_insecure_path_no_trusted_dirs_fails(tmp_path):
    home = _home(tmp_path, config={"secrets": {"providers": {
        "vault-exec": {
            "source": "exec",
            "command": "/opt/vault/fetch.sh",
            "allowInsecurePath": True,
        },
    }}})
    r = check_secrets_provider_exec(collect(home))
    assert r.status == FAIL
    assert any("vault-exec" in e and "allowInsecurePath" in e for e in r.evidence)


def test_allow_insecure_path_names_the_specific_provider(tmp_path):
    """With multiple providers, only the dangerous one should be named -- a clean
    sibling provider must not get swept into the FAIL evidence."""
    home = _home(tmp_path, config={"secrets": {"providers": {
        "clean-exec": {"source": "exec", "command": "/opt/clean/fetch.sh"},
        "danger-exec": {
            "source": "exec",
            "command": "/opt/danger/fetch.sh",
            "allowInsecurePath": True,
        },
    }}})
    r = check_secrets_provider_exec(collect(home))
    assert r.status == FAIL
    assert any("danger-exec" in e for e in r.evidence)
    assert not any("clean-exec" in e for e in r.evidence)


# ---------------------------------------------------------------------------
# WARN: allowInsecurePath scoped by trustedDirs (residual, not unrestrained)
# ---------------------------------------------------------------------------

def test_allow_insecure_path_with_trusted_dirs_warns(tmp_path):
    home = _home(tmp_path, config={"secrets": {"providers": {
        "vault-exec": {
            "source": "exec",
            "command": "/opt/vault/fetch.sh",
            "allowInsecurePath": True,
            "trustedDirs": ["/opt/vault"],
        },
    }}})
    r = check_secrets_provider_exec(collect(home))
    assert r.status == WARN


def test_trusted_dirs_with_only_blank_entries_is_not_scoped(tmp_path):
    """A trustedDirs list of blank/whitespace strings provides no real containment --
    must be treated the same as absent (FAIL), not WARN."""
    home = _home(tmp_path, config={"secrets": {"providers": {
        "vault-exec": {
            "source": "exec",
            "command": "/opt/vault/fetch.sh",
            "allowInsecurePath": True,
            "trustedDirs": ["", "   "],
        },
    }}})
    r = check_secrets_provider_exec(collect(home))
    assert r.status == FAIL


# ---------------------------------------------------------------------------
# WARN: allowSymlinkCommand alone
# ---------------------------------------------------------------------------

def test_allow_symlink_command_alone_warns(tmp_path):
    home = _home(tmp_path, config={"secrets": {"providers": {
        "vault-exec": {
            "source": "exec",
            "command": "/opt/vault/fetch.sh",
            "allowSymlinkCommand": True,
        },
    }}})
    r = check_secrets_provider_exec(collect(home))
    assert r.status == WARN
    assert any("allowSymlinkCommand" in e for e in r.evidence)


# ---------------------------------------------------------------------------
# WARN: secret-shaped passEnv name(s) — heuristic on the NAME, never FAIL
# ---------------------------------------------------------------------------

def test_secret_shaped_pass_env_warns(tmp_path):
    home = _home(tmp_path, config={"secrets": {"providers": {
        "vault-exec": {
            "source": "exec",
            "command": "/opt/vault/fetch.sh",
            "passEnv": ["AWS_SECRET_ACCESS_KEY"],
        },
    }}})
    r = check_secrets_provider_exec(collect(home))
    assert r.status == WARN
    assert any("passEnv" in e for e in r.evidence)


def test_benign_pass_env_name_passes(tmp_path):
    home = _home(tmp_path, config={"secrets": {"providers": {
        "vault-exec": {
            "source": "exec",
            "command": "/opt/vault/fetch.sh",
            "passEnv": ["LANG", "PATH"],
        },
    }}})
    r = check_secrets_provider_exec(collect(home))
    assert r.status == PASS


def test_path_suffixed_secret_like_name_is_accepted_noise(tmp_path):
    """C-135 (2026-07-25): SECRET_KEY_RE matches on the substring "token"/"secret" with
    no suffix awareness, so a genuinely benign *_PATH/*_DIR env var name that happens to
    contain one of those words (e.g. a real HuggingFace/tokenizer cache-dir variable)
    also triggers this WARN. This is INHERITED from B174's identical passEnv heuristic
    (shipped since B-238) and is WARN-only (never FAIL), so it does not violate Golden
    Rule #5's zero-false-positive-FAIL bar. B24's MCP env/header checks use a heavier
    value-shape heuristic for this exact suffix problem (B-248) that B194 deliberately
    does NOT port in, since B194's whole point is to mirror B174's existing, accepted
    severity shape onto a new config subtree -- not to diverge from it. Pinned here so
    the noise is documented rather than rediscovered as a surprise."""
    home = _home(tmp_path, config={"secrets": {"providers": {
        "vault-exec": {
            "source": "exec",
            "command": "/opt/vault/fetch.sh",
            "passEnv": ["TIKTOKEN_CACHE_DIR"],
        },
    }}})
    r = check_secrets_provider_exec(collect(home))
    assert r.status == WARN
