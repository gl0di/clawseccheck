"""B-310 — B80 (gateway auth rate-limiting) silently skipped the rate-limit assessment
for an environment-authenticated gateway.

THE BEFORE-STATE THIS FIXES (measured on dev before the change, by calling the real check
function, not by reading it):

    cfg = {"gateway": {"bind": "0.0.0.0"}}          # no gateway.auth.mode at all
    check_gateway_rate_limit(ctx) -> PASS | "Gateway auth does not rely on a
        brute-forceable token/password secret (or is not configured)."

and that was byte-identical whether or not OPENCLAW_GATEWAY_TOKEN/_PASSWORD was supplied
persistently, because the check only ever read `gateway.auth.mode`. On a host whose
gateway token lives in its systemd unit, OpenClaw derives mode="token" from it
(auth-resolve-NyPBrh8F.js:34-42) and the gateway genuinely uses token auth — so a missing
gateway.auth.rateLimit on that host was never assessed at all. This is the same
config-only blindness B-290 (2a2f8af) fixed for B2.

THE STRENGTH BAR (mirrors B2/2a2f8af exactly): a credential must be >=24 chars to be
treated as authenticating at all — `hasSharedSecret` accepts any non-empty value, so a
weak env credential is B2's exposed/guessable-secret territory, not this check's
"authenticated but unthrottled" concern. A sub-bar credential is treated the same as no
credential.

THE UNKNOWN BOUNDARY: absence of a readable persistent artifact (no systemd unit, no
global dotenv) on a non-loopback bind with no explicit auth.mode must report UNKNOWN, not
a fabricated PASS — the check genuinely cannot tell whether the gateway is unauthenticated
or env-authenticated.

Secret-shaped values are assembled at runtime from fragments so no contiguous
secret-looking literal exists in the source (project rule §2.3).

Offline, read-only, stdlib only. Nothing is written outside tmp_path.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_gateway_rate_limit
from clawseccheck.collector import collect

TOKEN_VAR = "OPENCLAW_GATEWAY_" + "TOKEN"
PASSWORD_VAR = "OPENCLAW_GATEWAY_" + "PASSWORD"
_VALUE = "k" * 12 + "3" + "cr" + "3t" + "9" * 12  # 27 chars, >=24

EXPOSED_NO_MODE = {"gateway": {"bind": "0.0.0.0"}}


def _home(root: Path, cfg: dict, *, unit_lines: str = "", dotenv: str = "",
          units: bool = True) -> Path:
    home = root / ".openclaw"
    home.mkdir(exist_ok=True)
    (home / "openclaw.json").write_text(json.dumps(cfg), encoding="utf-8")
    if units:
        unit_dir = root / ".config" / "systemd" / "user"
        unit_dir.mkdir(parents=True, exist_ok=True)
        (unit_dir / "openclaw-gateway.service").write_text(
            "[Unit]\nDescription=OpenClaw Gateway\n\n"
            "[Service]\nExecStart=/usr/bin/openclaw gateway run\nRestart=always\n"
            + unit_lines
            + "\n[Install]\nWantedBy=default.target\n",
            encoding="utf-8",
        )
    if dotenv:
        (home / ".env").write_text(dotenv + "\n", encoding="utf-8")
    return home


def _blob(f) -> str:
    return " ".join([f.detail, f.fix, *(f.evidence or [])])


# ---------------------------------------------------------------------------
# The headline fix — bad fixture: env-authenticated, no rate limit -> no longer a
# silent PASS
# ---------------------------------------------------------------------------

def test_env_token_without_ratelimit_is_no_longer_a_silent_pass(tmp_path):
    f = check_gateway_rate_limit(
        collect(_home(tmp_path, EXPOSED_NO_MODE, unit_lines=f"Environment={TOKEN_VAR}={_VALUE}\n"))
    )
    assert f.status == WARN
    assert "brute-forced" in f.detail
    assert "environment-supplied" in _blob(f)
    assert _VALUE not in _blob(f)


def test_env_password_without_ratelimit_is_also_a_warn(tmp_path):
    f = check_gateway_rate_limit(
        collect(_home(tmp_path, EXPOSED_NO_MODE, unit_lines=f"Environment={PASSWORD_VAR}={_VALUE}\n"))
    )
    assert f.status == WARN
    assert _VALUE not in _blob(f)


def test_dotenv_supplied_token_without_ratelimit_is_a_warn(tmp_path):
    f = check_gateway_rate_limit(
        collect(_home(tmp_path, EXPOSED_NO_MODE, dotenv=f"{TOKEN_VAR}={_VALUE}"))
    )
    assert f.status == WARN
    assert _VALUE not in _blob(f)


# ---------------------------------------------------------------------------
# Clean fixture: env-authenticated WITH a rate limit configured -> unaffected PASS
# ---------------------------------------------------------------------------

def test_env_token_with_ratelimit_configured_is_pass(tmp_path):
    cfg = {"gateway": {"bind": "0.0.0.0", "auth": {"rateLimit": {"maxAttempts": 5}}}}
    f = check_gateway_rate_limit(
        collect(_home(tmp_path, cfg, unit_lines=f"Environment={TOKEN_VAR}={_VALUE}\n"))
    )
    assert f.status == PASS
    assert _VALUE not in _blob(f)


def test_config_token_mode_with_ratelimit_is_unchanged(tmp_path):
    """The real fleet's state: mode=token, rate limit configured in config alone."""
    cfg = {"gateway": {"bind": "0.0.0.0",
                       "auth": {"mode": "token", "token": "a" * 40,
                                "rateLimit": {"maxAttempts": 5}}}}
    f = check_gateway_rate_limit(collect(_home(tmp_path, cfg, units=False)))
    assert f.status == PASS


# ---------------------------------------------------------------------------
# Strength boundary: mirrors B2's 23/24-char bar exactly
# ---------------------------------------------------------------------------

def test_short_env_credential_does_not_trigger_the_ratelimit_assessment(tmp_path):
    """A sub-bar env credential is treated as though there is no credential at all —
    B2 already FAILs this as an exposed/guessable-secret gateway; B80 must not also
    claim it is 'authenticated but unthrottled'."""
    for weak in ("a", "changeme", "password", "1234567890123456789012"):
        f = check_gateway_rate_limit(
            collect(_home(tmp_path, EXPOSED_NO_MODE,
                          unit_lines=f"Environment={TOKEN_VAR}={weak}\n"))
        )
        assert f.status == PASS, f"{weak!r} ({len(weak)} chars) must not trigger a WARN"
        assert "does not rely on a brute-forceable" in f.detail


def test_env_credential_at_the_boundary(tmp_path):
    below = check_gateway_rate_limit(
        collect(_home(tmp_path, EXPOSED_NO_MODE,
                      unit_lines="Environment=" + TOKEN_VAR + "=" + "a" * 23 + "\n"))
    )
    assert below.status == PASS

    at = check_gateway_rate_limit(
        collect(_home(tmp_path, EXPOSED_NO_MODE,
                      unit_lines="Environment=" + TOKEN_VAR + "=" + "a" * 24 + "\n"))
    )
    assert at.status == WARN


# ---------------------------------------------------------------------------
# UNKNOWN path: env evidence unreadable -> UNKNOWN, never a fabricated PASS
# ---------------------------------------------------------------------------

def test_unreadable_env_evidence_on_exposed_bind_is_unknown(tmp_path):
    """No systemd unit, no dotenv — we genuinely cannot tell whether the gateway is
    unauthenticated or env-authenticated."""
    f = check_gateway_rate_limit(collect(_home(tmp_path, EXPOSED_NO_MODE, units=False)))
    assert f.status == UNKNOWN
    assert "cannot determine" in f.detail


def test_readable_but_empty_env_evidence_is_pass_not_unknown(tmp_path):
    """The unit was read; it just carries no gateway credential. That IS a confirmed
    'no token/password secret configured' — a real PASS, not an UNKNOWN."""
    f = check_gateway_rate_limit(
        collect(_home(tmp_path, EXPOSED_NO_MODE,
                      unit_lines="Environment=OPENCLAW_GATEWAY_PORT=8899\n"))
    )
    assert f.status == PASS
    assert "does not rely on a brute-forceable" in f.detail


def test_loopback_bind_is_pass_even_with_no_env_evidence_at_all(tmp_path):
    """Loopback short-circuits before any env-credential read is attempted — must not
    manufacture a spurious UNKNOWN on the common, already-safe case."""
    cfg = {"gateway": {"bind": "127.0.0.1:8080"}}
    f = check_gateway_rate_limit(collect(_home(tmp_path, cfg, units=False)))
    assert f.status == PASS


# ---------------------------------------------------------------------------
# Non-regression: an explicit non-token/password auth.mode never triggers env-reading
# ---------------------------------------------------------------------------

def test_explicit_non_token_mode_never_consults_the_environment(tmp_path):
    cfg = {"gateway": {"bind": "0.0.0.0", "auth": {"mode": "trusted-proxy"}}}
    f = check_gateway_rate_limit(
        collect(_home(tmp_path, cfg, unit_lines=f"Environment={TOKEN_VAR}={_VALUE}\n"))
    )
    assert f.status == PASS
    assert "does not rely on a brute-forceable" in f.detail
