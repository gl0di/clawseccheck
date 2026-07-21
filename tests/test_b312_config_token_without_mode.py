"""B-312 — config-supplied `gateway.auth.token` with no explicit `auth.mode`.

THE RESIDUAL THIS CLOSES: `tests/test_b290_env_supplied_gateway_auth.py
::test_known_residual_config_token_without_mode_still_fails` pinned a known false-positive
FAIL — B-290 (ENV-4) deliberately left it out of scope because it is a config-only path with
no environment component. This closes it with its own C-135-reviewed triage.

GROUNDING: `resolveGatewayAuth` derives `mode="token"` from the credential itself when
`authConfig.mode` is falsy (auth-resolve-NyPBrh8F.js:34-42), and the credential is read
config-FIRST (:23-24) — i.e. a config token, when present, is what OpenClaw actually
authenticates the gateway with, ahead of any environment variable. So a config token with
no explicit `auth.mode` is the SAME shape B-290 fixed for the env-supplied case.

THE STRENGTH BAR CARRIES OVER (2a2f8af): `hasSharedSecret`
(server-runtime-config-r5ejxORO.js:66,78) is satisfied by ANY non-empty token, so the gateway
binds and listens one guess deep on a token as short as one character.
`assertGatewayAuthConfigured` (auth-B27MflKU.js:183-197) rejects only a MISSING credential;
no minimum length exists anywhere in the dist. OpenClaw's own audit fires
`gateway.token_too_short` (audit-UjVvFwCi.js:239) below 24 chars — the same bar this check
already applies to a config token elsewhere in `check_gateway`. So the softening here is
gated on `len(token) >= 24`, identically to the env leg.

Offline, read-only, stdlib only. Nothing is written outside tmp_path.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import FAIL, WARN
from clawseccheck.checks import check_gateway
from clawseccheck.collector import collect

EXPOSED_NO_AUTH_MODE = {"gateway": {"bind": "0.0.0.0"}}


def _home(root: Path, cfg: dict) -> Path:
    home = root / ".openclaw"
    home.mkdir(exist_ok=True)
    (home / "openclaw.json").write_text(json.dumps(cfg), encoding="utf-8")
    return home


def _blob(f) -> str:
    return " ".join([f.detail, f.fix, *f.evidence])


# ---------------------------------------------------------------------------
# The headline fix — clean fixture: strong config token, no auth.mode -> no longer FAILs
# ---------------------------------------------------------------------------

def test_strong_config_token_without_mode_no_longer_fails(tmp_path):
    """THE FIX. `gateway.auth.token` >=24 chars with no `auth.mode` set IS authenticated
    (OpenClaw derives mode="token" from it), so B2's FAIL was a false positive."""
    cfg = {"gateway": {"bind": "0.0.0.0", "auth": {"token": "a" * 40}}}
    f = check_gateway(collect(_home(tmp_path, cfg)))
    assert f.status != FAIL
    assert f.status == WARN
    assert "gateway.auth.token is set" in f.detail
    assert "the gateway is authenticated" in f.detail


def test_config_token_at_the_boundary(tmp_path):
    """23 chars fails, 24 passes — the identical bar the env leg uses."""
    below = check_gateway(
        collect(_home(tmp_path, {"gateway": {"bind": "0.0.0.0", "auth": {"token": "a" * 23}}}))
    )
    assert below.status == FAIL

    at = check_gateway(
        collect(_home(tmp_path, {"gateway": {"bind": "0.0.0.0", "auth": {"token": "a" * 24}}}))
    )
    assert at.status == WARN
    assert "the gateway is authenticated" in at.detail


# ---------------------------------------------------------------------------
# Bad fixture: sub-bar config token -> still FAILs (the strength bar)
# ---------------------------------------------------------------------------

def test_weak_config_token_without_mode_still_fails(tmp_path):
    """A one-guess-deep config secret is exposure, not authentication — mirrors the env
    leg's C-135 finding exactly."""
    for weak in ("a", "changeme", "password", "1234567890123456789012"):
        cfg = {"gateway": {"bind": "0.0.0.0", "auth": {"token": weak}}}
        f = check_gateway(collect(_home(tmp_path, cfg)))
        assert f.status == FAIL, f"{weak!r} ({len(weak)} chars) must not soften B2"
        assert "world-reachable behind a guessable secret" in f.detail

    # Leak probe: the credential value must never reach the report. Assembled from
    # fragments so no contiguous secret-shaped literal exists in the source (§2.3).
    marker = "Rk4" + "Tn8" + "Bx1"
    f = check_gateway(
        collect(_home(tmp_path, {"gateway": {"bind": "0.0.0.0", "auth": {"token": marker}}}))
    )
    assert f.status == FAIL
    assert marker not in f.detail
    assert marker not in " ".join(f.evidence or [])
    assert marker not in " ".join(f.fix or [])


def test_legacy_gateway_token_field_gets_the_same_treatment(tmp_path):
    """The legacy `gateway.token` field (not `gateway.auth.token`) resolves the same way."""
    strong = check_gateway(
        collect(_home(tmp_path, {"gateway": {"bind": "0.0.0.0", "token": "b" * 30}}))
    )
    assert strong.status == WARN

    weak = check_gateway(
        collect(_home(tmp_path, {"gateway": {"bind": "0.0.0.0", "token": "short"}}))
    )
    assert weak.status == FAIL


# ---------------------------------------------------------------------------
# Absence guard — the false-negative boundary that must NOT move
# ---------------------------------------------------------------------------

def test_absence_of_any_token_still_fails(tmp_path):
    """No config token, no env credential, nothing observable. Absence is not evidence
    of auth."""
    f = check_gateway(collect(_home(tmp_path, EXPOSED_NO_AUTH_MODE)))
    assert f.status == FAIL
    assert "exposed with auth.mode=None" in f.detail


def test_explicit_mode_none_is_never_softened_by_a_config_token(tmp_path):
    """`auth.mode="none"` is truthy in the dist, so resolveGatewayAuth keeps mode="none"
    regardless of any token also present in config. An explicit mode=none is a decision,
    not an omission — softening it would be a lying PASS on a genuinely broken posture."""
    cfg = {"gateway": {"bind": "0.0.0.0", "auth": {"mode": "none", "token": "a" * 40}}}
    f = check_gateway(collect(_home(tmp_path, cfg)))
    assert f.status == FAIL
    assert "auth.mode=none" in f.detail


# ---------------------------------------------------------------------------
# Config-first precedence: a config token takes priority over an env credential
# ---------------------------------------------------------------------------

def test_config_token_precedence_over_env_credential(tmp_path):
    """resolveGatewayAuth reads the credential config-FIRST (auth-resolve-NyPBrh8F.js:
    23-24). A WEAK config token must still FAIL even if a STRONG env credential is also
    present — the env variable is never reached because the config token wins."""
    home = tmp_path / ".openclaw"
    home.mkdir()
    cfg = {"gateway": {"bind": "0.0.0.0", "auth": {"token": "weak"}}}
    (home / "openclaw.json").write_text(json.dumps(cfg), encoding="utf-8")
    unit_dir = tmp_path / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True)
    (unit_dir / "openclaw-gateway.service").write_text(
        "[Unit]\nDescription=OpenClaw Gateway\n\n"
        "[Service]\nExecStart=/usr/bin/openclaw gateway run\n"
        f"Environment=OPENCLAW_GATEWAY_TOKEN={'a' * 40}\n"
        "\n[Install]\nWantedBy=default.target\n",
        encoding="utf-8",
    )
    f = check_gateway(collect(home))
    assert f.status == FAIL
    assert "config-supplied gateway.auth.token shorter than 24 chars" in f.detail


# ---------------------------------------------------------------------------
# Non-regression on the other B2 paths
# ---------------------------------------------------------------------------

def test_soft_clause_does_not_mask_a_real_fail_clause(tmp_path):
    """An unrelated FAIL-worthy condition must still FAIL even when the config-token
    clause was softened."""
    cfg = {
        "gateway": {"bind": "0.0.0.0", "auth": {"token": "a" * 40}},
        "channels": {"telegram": {"enabled": True, "dmPolicy": "open"}},
    }
    f = check_gateway(collect(_home(tmp_path, cfg)))
    assert f.status == FAIL
    assert "open dm/group policy" in f.detail
