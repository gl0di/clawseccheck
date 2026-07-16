"""B1 — plaintext secret detection tests.

Grounded against check_secrets (checks.py:502).

Verdict map:
- FAIL: gateway.auth.password set in config, OR hooks.token set in config,
        OR a SECRET_PATTERNS match inside a bootstrap file.
- PASS: none of the above (the perms-based _secret_paths branch requires POSIX +
        group/world-readable config_mode; we cover FAIL via the always-firing
        explicit paths and bootstrap scan, which carry no platform dependency).
No WARN or UNKNOWN path exists.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS
from clawseccheck.checks import check_secrets
from clawseccheck.collector import Context


def _ctx(
    cfg: dict, bootstrap: dict | None = None, config_mode: int | None = None
) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    if bootstrap is not None:
        c.bootstrap = bootstrap
    if config_mode is not None:
        c.config_mode = config_mode
    return c


# ---- PASS: no secrets anywhere ----

def test_b01_empty_config_and_empty_bootstrap_pass():
    assert check_secrets(_ctx({})).status == PASS


def test_b01_clean_gateway_config_pass():
    cfg = {"gateway": {"bind": "127.0.0.1:8080", "auth": {"mode": "token"}}}
    assert check_secrets(_ctx(cfg)).status == PASS


def test_b01_clean_bootstrap_pass():
    ctx = _ctx({}, bootstrap={"SOUL.md": "You are a careful, security-minded assistant."})
    assert check_secrets(ctx).status == PASS


# ---- FAIL: explicit secret paths in config (fire unconditionally, no perms dependency) ----

def test_b01_gateway_auth_password_set_fail():
    cfg = {"gateway": {"auth": {"password": "any-value"}}}
    f = check_secrets(_ctx(cfg))
    assert f.status == FAIL
    assert any("gateway.auth.password" in e for e in f.evidence)


def test_b01_hooks_token_set_fail():
    cfg = {"hooks": {"token": "any-value"}}
    f = check_secrets(_ctx(cfg))
    assert f.status == FAIL
    assert any("hooks.token" in e for e in f.evidence)


# ---- FAIL: secret pattern in bootstrap file (no perms dependency) ----

def test_b01_bootstrap_anthropic_key_pattern_fail():
    # Assembled at runtime so no contiguous secret literal exists in source.
    # Pattern: sk-ant-[a-z0-9-]{8,} (SECRET_PATTERNS[0])
    secret = "sk-" + "ant-" + "a" * 8 + "12345678"
    ctx = _ctx({}, bootstrap={"SOUL.md": f"My API key is {secret}"})
    f = check_secrets(ctx)
    assert f.status == FAIL
    assert any("SOUL.md" in e for e in f.evidence)


def test_b01_bootstrap_aws_akia_pattern_fail():
    # Assembled at runtime — AKIA prefix + 16 uppercase alphanumeric chars.
    # Pattern: AKIA[0-9A-Z]{16} (SECRET_PATTERNS[2])
    secret = "AKIA" + "IOSFODNN7EXAMPLE"
    ctx = _ctx({}, bootstrap={"AGENTS.md": f"access_key={secret}"})
    f = check_secrets(ctx)
    assert f.status == FAIL
    assert any("AGENTS.md" in e for e in f.evidence)


def test_b01_bootstrap_password_kv_pattern_fail():
    # Pattern: (?:password|secret|api_key|token)\s*[:=]\s*[^\s'"]{8,} (SECRET_PATTERNS[4])
    # Value must be >= 8 non-space chars.  Assembled so no contiguous secret literal.
    value = "hunter2" + "xx"   # 9 chars; assembled to prevent scanner match
    ctx = _ctx({}, bootstrap={"HEARTBEAT.md": f"password: {value}"})
    f = check_secrets(ctx)
    assert f.status == FAIL
    assert any("HEARTBEAT.md" in e for e in f.evidence)


# ---------------------------------------------------------------------------
# C-226: SecretRef indirection (${NAME} / $NAME / secretref-env: / __env__:) is a
# SAFER config-value shape (OpenClaw 2026.7.1) that must not be misread as an
# exposed plaintext secret. Grounded against the installed OpenClaw 2026.7.1 dist.
# ---------------------------------------------------------------------------

def _runtime_secret() -> str:
    """Assembled at runtime so no contiguous secret-shaped literal exists in source."""
    return "ghp" + "_" + "A" * 36


def test_b01_secretref_indirection_values_pass_even_with_loose_perms():
    """Every grounded SecretRef shorthand/legacy-marker/object form, sitting under a
    secret-shaped key with loose config perms, must NOT drive B1 to FAIL — this is
    exactly the branch (_secret_paths + _perms_loose) that would have false-FAILed
    pre-fix."""
    cfg = {
        "gateway": {"auth": {"token": "${OPENAI_KEY}"}},
        "providers": {"openai": {"apiKey": "$OPENAI_KEY"}},
        "hooks": {"secretToken": "secretref-env:HOOKS_TOKEN"},
        "legacy": {"apiKey": "__env__:LEGACY_TOKEN"},
        # Structured SecretRef object form — confirm it stays safe (it's a dict, not
        # a string, so _secret_paths never flags it in the first place).
        "someService": {
            "apiKey": {"source": "env", "provider": "default", "id": "OPENAI_KEY"}
        },
    }
    f = check_secrets(_ctx(cfg, config_mode=0o644))
    assert f.status == PASS


def test_b01_secretref_object_form_keys_do_not_hit_secret_key_heuristic():
    """Explicit confirmation (not assumption) that the {source, provider, id}
    SecretRef object shape's own keys never match SECRET_KEY_RE, so it can never be
    mistaken for a secret-bearing dotted path on its own account."""
    from clawseccheck.checks import _secret_paths

    cfg = {"apiKey": {"source": "env", "provider": "default", "id": "OPENAI_API_KEY"}}
    assert _secret_paths(cfg) == []


# ---- Adversarial cases (C-226 mandatory) — a reference-shaped decoy must NEVER
# ---- mask a real secret; the exclusion must stay narrow. ----

def test_b01_adversarial_decoy_reference_does_not_mask_real_secret_elsewhere():
    """Case 1: a decoy ${NAME} reference in one field and a real contiguous secret
    in ANOTHER field — the real secret must still FAIL."""
    secret = _runtime_secret()
    cfg = {
        "gateway": {"auth": {"token": "${OPENAI_KEY}"}},
        "hooks": {"token": secret},
    }
    f = check_secrets(_ctx(cfg, config_mode=0o644))
    assert f.status == FAIL


def test_b01_adversarial_appended_secret_after_reference_still_fails():
    """Case 2: ${NAME} immediately followed by appended real secret material in the
    SAME value is NOT a pure reference (something follows the closing brace) — must
    still FAIL."""
    secret = _runtime_secret()
    cfg = {"gateway": {"auth": {"token": "${OPENAI_KEY}" + secret}}}
    f = check_secrets(_ctx(cfg, config_mode=0o644))
    assert f.status == FAIL


def test_b01_adversarial_secretref_env_prefix_with_inline_blob_still_fails():
    """Case 3: 'secretref-env:' prefix followed by an inline plaintext blob (not a
    bare uppercase env-var-name token, the only shape OpenClaw itself treats as a
    real reference) must still FAIL."""
    cfg = {
        "gateway": {
            "auth": {"token": "secretref-env:actually-a-plaintext-blob-appended-here"}
        }
    }
    f = check_secrets(_ctx(cfg, config_mode=0o644))
    assert f.status == FAIL


def test_b01_adversarial_bootstrap_decoy_reference_does_not_mask_real_secret():
    """The same decoy-vs-real-secret adversarial case (Case 1), but through the
    bootstrap free-text scan path (SECRET_PATTERNS via _pattern_hits_real_secret)
    rather than the structured _secret_paths walk — a pure reference match earlier
    in the SAME text must not stop the scan from finding a real secret later in the
    same pattern's matches."""
    secret = _runtime_secret()
    text = 'apiKey: "${OPENAI_KEY}"\n' + "token: " + secret + "\n"
    f = check_secrets(_ctx({}, bootstrap={"SOUL.md": text}))
    assert f.status == FAIL
    assert any("SOUL.md" in e for e in f.evidence)


def test_b01_bootstrap_pure_reference_alone_passes():
    """A bootstrap file that only ever mentions a pure ${NAME} reference (no real
    secret anywhere) must stay PASS."""
    ctx = _ctx({}, bootstrap={"SOUL.md": 'Use apiKey: "${OPENAI_KEY}" from env.'})
    f = check_secrets(ctx)
    assert f.status == PASS
