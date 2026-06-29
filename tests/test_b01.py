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


def _ctx(cfg: dict, bootstrap: dict | None = None) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    if bootstrap is not None:
        c.bootstrap = bootstrap
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
