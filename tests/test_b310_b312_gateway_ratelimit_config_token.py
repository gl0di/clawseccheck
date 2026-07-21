"""B-310 round 2 (C-135) — B80 (gateway auth rate-limiting) must derive `mode` from a
config-supplied gateway token the same way B2's own B-312 fix derives it, not just from
an environment-supplied one.

THE DEFECT THIS CLOSES: B-312 added a config-token leg to `check_gateway` (B2) — a
config `gateway.auth.token` / `gateway.token` present with no explicit `auth.mode`,
>=24 chars, softens B2's FAIL to WARN (config-first — resolveGatewayAuth derives
`mode="token"` from the credential itself, auth-resolve-NyPBrh8F.js:34-42, read
config-FIRST at :23-24). But B-310 only ever added the ENV-credential leg to
`check_gateway_rate_limit` (B80) — it never re-derived `mode` from a config-supplied
token, so a config-token-authenticated gateway with no `gateway.auth.rateLimit` fell
through to the same "does not rely on a brute-forceable secret" PASS as a genuinely
unauthenticated one, even though B2 already (correctly) recognizes that identical
config as authenticated. Fixed by sharing `_gateway_config_token` between B2 and B80 so
the two checks cannot independently drift on what "authenticated by config" means.

STRENGTH BAR AND PRECEDENCE mirror B2/B-312 exactly: >=24 chars, config-first (a config
token, present at ANY length, is what OpenClaw actually authenticates with — the
environment is only ever consulted when no config token exists at all). A sub-bar
config token is B2's exposed/guessable-secret FAIL territory, not B80's
"authenticated-but-unthrottled" concern — treated the same as no credential at all,
exactly mirroring the pre-existing weak-env-credential leg (B-310).

Secret-shaped values are assembled at runtime from fragments/repeats so no realistic
contiguous secret-looking literal exists in the source (project rule §2.3).

Offline, read-only, stdlib only. Nothing is written outside tmp_path.
"""
from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, WARN
from clawseccheck.checks import check_gateway, check_gateway_rate_limit
from clawseccheck.collector import collect

TOKEN_VAR = "OPENCLAW_GATEWAY_" + "TOKEN"
_ENV_STRONG = "k" * 12 + "3" + "cr" + "3t" + "9" * 12  # 27 chars, >=24
_CFG_STRONG = "s" * 30
_CFG_WEAK = "weak"


def _home(root: Path, cfg: dict, *, unit_lines: str = "") -> Path:
    home = root / ".openclaw"
    home.mkdir(exist_ok=True)
    (home / "openclaw.json").write_text(json.dumps(cfg), encoding="utf-8")
    unit_dir = root / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True, exist_ok=True)
    (unit_dir / "openclaw-gateway.service").write_text(
        "[Unit]\nDescription=OpenClaw Gateway\n\n"
        "[Service]\nExecStart=/usr/bin/openclaw gateway run\nRestart=always\n"
        + unit_lines
        + "\n[Install]\nWantedBy=default.target\n",
        encoding="utf-8",
    )
    return home


def _blob(f) -> str:
    return " ".join([f.detail, f.fix, *(f.evidence or [])])


# ---------------------------------------------------------------------------
# The headline fix — config-token-authenticated gateway, no rate limit -> no longer a
# silent PASS
# ---------------------------------------------------------------------------

def test_config_token_without_ratelimit_is_no_longer_a_silent_pass(tmp_path):
    """THE ROUND-2 FIX. B2 correctly WARNs this exact config as authenticated
    (B-312); B80 must now agree it is authenticated and assess rate limiting for it,
    instead of silently PASSing as though no credential exists at all."""
    cfg = {"gateway": {"bind": "0.0.0.0", "auth": {"token": _CFG_STRONG}}}
    ctx = collect(_home(tmp_path, cfg))
    b2 = check_gateway(ctx)
    b80 = check_gateway_rate_limit(ctx)
    assert b2.status == WARN
    assert b80.status == WARN
    assert "brute-forced" in b80.detail
    assert "config-supplied gateway.auth.token" in _blob(b80)
    assert _CFG_STRONG not in _blob(b80)


def test_config_token_with_ratelimit_configured_is_still_pass(tmp_path):
    cfg = {
        "gateway": {
            "bind": "0.0.0.0",
            "auth": {"token": _CFG_STRONG, "rateLimit": {"maxAttempts": 5}},
        }
    }
    ctx = collect(_home(tmp_path, cfg))
    assert check_gateway_rate_limit(ctx).status == PASS


def test_legacy_gateway_token_field_authenticates_b80_too(tmp_path):
    """The legacy `gateway.token` field (not `gateway.auth.token`) resolves the same
    way for B80 as it already does for B2."""
    cfg = {"gateway": {"bind": "0.0.0.0", "token": _CFG_STRONG}}
    ctx = collect(_home(tmp_path, cfg))
    assert check_gateway(ctx).status == WARN
    assert check_gateway_rate_limit(ctx).status == WARN


# ---------------------------------------------------------------------------
# Weak config token: mirrors the pre-existing weak-env leg exactly — B2 FAILs
# (guessable secret, a real exposure), B80 must not ALSO claim "authenticated but
# unthrottled" for it
# ---------------------------------------------------------------------------

def test_weak_config_token_does_not_trigger_the_ratelimit_assessment(tmp_path):
    cfg = {"gateway": {"bind": "0.0.0.0", "auth": {"token": _CFG_WEAK}}}
    ctx = collect(_home(tmp_path, cfg))
    assert check_gateway(ctx).status == FAIL
    b80 = check_gateway_rate_limit(ctx)
    assert b80.status == PASS
    assert "does not rely on a brute-forceable" in b80.detail


def test_config_token_at_the_boundary_for_b80(tmp_path):
    """23 chars does not authenticate, 24 does — the identical bar B2/B-312 uses."""
    below = check_gateway_rate_limit(
        collect(_home(tmp_path, {"gateway": {"bind": "0.0.0.0", "auth": {"token": "a" * 23}}}))
    )
    assert below.status == PASS

    at = check_gateway_rate_limit(
        collect(_home(tmp_path, {"gateway": {"bind": "0.0.0.0", "auth": {"token": "a" * 24}}}))
    )
    assert at.status == WARN


# ---------------------------------------------------------------------------
# Config-first precedence for B80 too: a weak config token is what OpenClaw actually
# authenticates with — a strong env credential is never reached, identical to B2/B-312
# ---------------------------------------------------------------------------

def test_config_token_precedence_over_env_credential_for_b80(tmp_path):
    """A WEAK config token must still leave B80 at PASS (not authenticated, for B80's
    purposes) even when a STRONG env credential is also present — config wins, so the
    env credential is never consulted, exactly mirroring B2/B-312's own precedence
    test."""
    cfg = {"gateway": {"bind": "0.0.0.0", "auth": {"token": _CFG_WEAK}}}
    home = _home(tmp_path, cfg, unit_lines=f"Environment={TOKEN_VAR}={_ENV_STRONG}\n")
    ctx = collect(home)
    assert check_gateway(ctx).status == FAIL
    b80 = check_gateway_rate_limit(ctx)
    assert b80.status == PASS
    assert "does not rely on a brute-forceable" in b80.detail


def test_strong_config_token_wins_over_env_credential_in_b80_evidence(tmp_path):
    """A strong config token authenticates on its own; the environment-supplied
    credential is never consulted, so it must not appear in B80's evidence label."""
    cfg = {"gateway": {"bind": "0.0.0.0", "auth": {"token": _CFG_STRONG}}}
    home = _home(tmp_path, cfg, unit_lines=f"Environment={TOKEN_VAR}={_ENV_STRONG}\n")
    ctx = collect(home)
    b80 = check_gateway_rate_limit(ctx)
    assert b80.status == WARN
    assert "config-supplied gateway.auth.token" in _blob(b80)
    assert "environment-supplied" not in _blob(b80)


# ---------------------------------------------------------------------------
# The full matrix — B2 and B80 must agree on every shape: either both treat the
# gateway as authenticated by a derived token (B2 WARN / B80 WARN, since none of these
# configure gateway.auth.rateLimit), or neither does (B2 FAIL / B80 PASS). "Both soften
# or neither."
# ---------------------------------------------------------------------------

_STRENGTHS = {
    "absent": None,
    "weak": "w" * 10,
    "strong": "z" * 30,
}


@pytest.mark.parametrize(
    "cfg_state,env_state", list(itertools.product(_STRENGTHS, _STRENGTHS))
)
def test_b2_b80_agree_on_every_config_env_combination(tmp_path, cfg_state, env_state):
    cfg_token = _STRENGTHS[cfg_state]
    env_token = _STRENGTHS[env_state]

    gw: dict = {"bind": "0.0.0.0"}
    if cfg_token is not None:
        gw["auth"] = {"token": cfg_token}
    cfg = {"gateway": gw}

    # Always ship a readable, benign systemd unit so an absent env credential is a
    # confirmed "nothing there" (PASS), never an unreadable-artifact UNKNOWN — the
    # axis under test is config/env *content*, not artifact readability.
    unit_lines = (
        f"Environment={TOKEN_VAR}={env_token}\n"
        if env_token is not None
        else "Environment=OPENCLAW_GATEWAY_PORT=8899\n"
    )
    ctx = collect(_home(tmp_path, cfg, unit_lines=unit_lines))

    b2 = check_gateway(ctx)
    b80 = check_gateway_rate_limit(ctx)

    # Config-first precedence (identical to B2/B-312): a config token, present at any
    # length, is what OpenClaw actually authenticates with — the environment is only
    # ever consulted when no config token exists at all.
    expected_authenticated = cfg_state == "strong" or (
        cfg_state == "absent" and env_state == "strong"
    )

    if expected_authenticated:
        assert b2.status == WARN, (cfg_state, env_state, b2.status, b2.detail)
        assert b80.status == WARN, (cfg_state, env_state, b80.status, b80.detail)
    else:
        assert b2.status == FAIL, (cfg_state, env_state, b2.status, b2.detail)
        assert b80.status == PASS, (cfg_state, env_state, b80.status, b80.detail)

    # The headline invariant this test exists to pin: B2 and B80 must never disagree
    # about whether a derived token authenticates this gateway.
    assert (b2.status == WARN) == (b80.status == WARN)

    for f in (b2, b80):
        if cfg_token:
            assert cfg_token not in _blob(f)
        if env_token:
            assert env_token not in _blob(f)


# ---------------------------------------------------------------------------
# The "explicit auth.mode set" arm of the same axis: mode is not derived at all here,
# so this is unaffected by B-310/B-312 — pinned as the complementary non-regression arm
# ---------------------------------------------------------------------------

def test_explicit_mode_token_no_ratelimit_is_unaffected(tmp_path):
    cfg = {"gateway": {"bind": "0.0.0.0", "auth": {"mode": "token", "token": _CFG_STRONG}}}
    ctx = collect(_home(tmp_path, cfg))
    assert check_gateway(ctx).status == PASS
    assert check_gateway_rate_limit(ctx).status == WARN


def test_explicit_mode_token_with_ratelimit_is_pass(tmp_path):
    cfg = {
        "gateway": {
            "bind": "0.0.0.0",
            "auth": {"mode": "token", "token": _CFG_STRONG, "rateLimit": {"maxAttempts": 5}},
        }
    }
    ctx = collect(_home(tmp_path, cfg))
    assert check_gateway(ctx).status == PASS
    assert check_gateway_rate_limit(ctx).status == PASS
