"""B-290 (ENV-4) — env-supplied gateway auth: B2's false FAIL, and B41's undercount.

THE BEFORE-STATE THIS FIXES (measured on dev before the change, by calling the real check
function, not by reading it):

    cfg = {"gateway": {"bind": "0.0.0.0"}}          # no gateway.auth key at all
    check_gateway(ctx) -> FAIL | "gateway.bind=0.0.0.0 exposed with auth.mode=None"

and that output was BYTE-IDENTICAL whether or not a gateway token was supplied by the
environment, because the check never read anything but the config. On a host whose
gateway token lives in its systemd unit the gateway is genuinely authenticated — OpenClaw
refuses a non-loopback bind without a shared secret
(server-runtime-config-r5ejxORO.js:78) and derives auth.mode from the env-resolved
credential when gateway.auth.mode is absent (auth-resolve-NyPBrh8F.js:34-42, credential
read at credentials-DesN22Ui.js:32-33) — so that FAIL was a false positive on a correctly
secured host.

THE FALSE-NEGATIVE BOUNDARY, WHICH IS DELIBERATE: absence of an observable credential is
NEVER read as "authenticated". The audit process's environment is not the gateway
service's, so only a persistent on-disk artifact (a systemd unit's Environment= /
EnvironmentFile=, or a global runtime dotenv file) may soften the FAIL. Everything else
stays FAIL. Softening a CRITICAL check is how a scanner starts lying; these tests pin
both directions.

Secret-shaped values are assembled at runtime from fragments so no contiguous
secret-looking literal exists in the source (project rule §2.3).

Offline, read-only, stdlib only. Nothing is written outside tmp_path.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_credential_blast_radius, check_gateway
from clawseccheck.collector import collect

# Assembled, never a contiguous literal.
TOKEN_VAR = "OPENCLAW_GATEWAY_" + "TOKEN"
PASSWORD_VAR = "OPENCLAW_GATEWAY_" + "PASSWORD"
_VALUE = "k" * 12 + "3" + "cr" + "3t" + "9" * 12

EXPOSED_NO_AUTH = {"gateway": {"bind": "0.0.0.0"}}


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
    return " ".join([f.detail, f.fix, *f.evidence])


# ---------------------------------------------------------------------------
# The headline fix
# ---------------------------------------------------------------------------

def test_exposed_bind_without_env_still_fails(tmp_path):
    """The pre-existing behaviour, pinned. This is the shape that was a false FAIL only
    when a credential WAS supplied; with nothing observable, FAIL is correct."""
    f = check_gateway(collect(_home(tmp_path, EXPOSED_NO_AUTH)))
    assert f.status == FAIL
    assert "exposed with auth.mode=None" in f.detail


def test_exposed_bind_with_unit_supplied_token_no_longer_fails(tmp_path):
    """THE FIX. Same config; a gateway token in the unit means the gateway IS authenticated."""
    f = check_gateway(
        collect(_home(tmp_path, EXPOSED_NO_AUTH,
                      unit_lines=f"Environment={TOKEN_VAR}={_VALUE}\n"))
    )
    assert f.status != FAIL
    assert f.status == WARN
    assert "environment" in f.detail
    assert _VALUE not in _blob(f)


def test_exposed_bind_with_unit_supplied_password_no_longer_fails(tmp_path):
    """OPENCLAW_GATEWAY_PASSWORD supplies mode="password" the same way
    (auth-resolve-NyPBrh8F.js:36-38)."""
    f = check_gateway(
        collect(_home(tmp_path, EXPOSED_NO_AUTH,
                      unit_lines=f"Environment={PASSWORD_VAR}={_VALUE}\n"))
    )
    assert f.status == WARN
    assert _VALUE not in _blob(f)


def test_exposed_bind_with_dotenv_supplied_token_no_longer_fails(tmp_path):
    """The other persistent channel: ~/.openclaw/.env, admitted with no entryFilter
    (dotenv-eb21SB3p.js:222-223)."""
    f = check_gateway(
        collect(_home(tmp_path, EXPOSED_NO_AUTH, dotenv=f"{TOKEN_VAR}={_VALUE}"))
    )
    assert f.status == WARN
    assert _VALUE not in _blob(f)


def test_exposed_bind_with_environment_file_supplied_token_no_longer_fails(tmp_path):
    envfile = tmp_path / "gateway-secret.env"
    envfile.write_text(f"{TOKEN_VAR}={_VALUE}\n", encoding="utf-8")
    f = check_gateway(
        collect(_home(tmp_path, EXPOSED_NO_AUTH,
                      unit_lines=f"EnvironmentFile=-{envfile}\n"))
    )
    assert f.status == WARN
    assert _VALUE not in _blob(f)


# ---------------------------------------------------------------------------
# The false-negative boundary — every one of these must STILL FAIL
# ---------------------------------------------------------------------------

def test_absence_of_any_env_artifact_still_fails(tmp_path):
    """No unit, no dotenv, nothing observable. Absence is not evidence of auth."""
    f = check_gateway(collect(_home(tmp_path, EXPOSED_NO_AUTH, units=False)))
    assert f.status == FAIL


def test_unit_present_but_carrying_no_credential_still_fails(tmp_path):
    f = check_gateway(
        collect(_home(tmp_path, EXPOSED_NO_AUTH,
                      unit_lines="Environment=OPENCLAW_GATEWAY_PORT=8899\n"))
    )
    assert f.status == FAIL


def test_explicit_mode_none_is_never_softened(tmp_path):
    """`auth.mode="none"` is truthy in the dist, so resolveGatewayAuth keeps mode="none",
    hasSharedSecret stays false, and server-runtime-config-r5ejxORO.js:78 refuses the
    non-loopback bind outright. An explicit mode=none is a decision, not an omission —
    softening it would be a lying PASS on a genuinely broken posture."""
    cfg = {"gateway": {"bind": "0.0.0.0", "auth": {"mode": "none"}}}
    f = check_gateway(
        collect(_home(tmp_path, cfg, unit_lines=f"Environment={TOKEN_VAR}={_VALUE}\n"))
    )
    assert f.status == FAIL
    assert "auth.mode=none" in f.detail


def test_empty_env_credential_is_not_a_credential(tmp_path):
    """trimToUndefined (credentials-DesN22Ui.js:32) discards a blank value, so a blank
    assignment does not authenticate anything and must not soften the FAIL."""
    f = check_gateway(
        collect(_home(tmp_path, EXPOSED_NO_AUTH, unit_lines=f"Environment={TOKEN_VAR}=\n"))
    )
    assert f.status == FAIL


def test_credential_in_a_non_openclaw_unit_does_not_soften(tmp_path):
    """Another application's unit is not this gateway's environment."""
    unit_dir = tmp_path / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True)
    (unit_dir / "unrelated.service").write_text(
        "[Service]\nExecStart=/usr/bin/unrelated\n"
        f"Environment={TOKEN_VAR}={_VALUE}\n",
        encoding="utf-8",
    )
    f = check_gateway(collect(_home(tmp_path, EXPOSED_NO_AUTH, units=False)))
    assert f.status == FAIL


def test_ambient_process_environment_never_softens(tmp_path, monkeypatch):
    """The auditing shell's environment is NOT the gateway service's.

    A token exported in the operator's terminal says nothing about a service systemd
    started months ago. Letting it clear a CRITICAL finding would key the verdict on
    which shell the audit happened to be launched from — precisely the
    environment-driven false result Golden Rule #5 forbids. The ambient case NARROWS to
    "still FAIL", it does not close.
    """
    monkeypatch.setenv(TOKEN_VAR, _VALUE)
    f = check_gateway(collect(_home(tmp_path, EXPOSED_NO_AUTH)))
    assert f.status == FAIL


# ---------------------------------------------------------------------------
# Non-regression on every other B2 path
# ---------------------------------------------------------------------------

def test_configured_token_mode_is_unchanged(tmp_path):
    """The real fleet's state: mode=token with a token in config."""
    cfg = {"gateway": {"bind": "0.0.0.0",
                       "auth": {"mode": "token", "token": "a" * 40}}}
    f = check_gateway(collect(_home(tmp_path, cfg)))
    assert f.status == PASS


def test_loopback_no_auth_is_unchanged(tmp_path):
    f = check_gateway(collect(_home(tmp_path, {"gateway": {"bind": "127.0.0.1"}})))
    assert f.status == PASS


def test_soft_clause_never_raises_an_existing_warn_to_fail(tmp_path):
    """allowInsecureAuth alone is a WARN. Adding the softened disclosure beside it must
    not turn it into a FAIL — soft evidence rides in the detail and never escalates."""
    cfg = {"gateway": {"bind": "0.0.0.0", "controlUi": {"allowInsecureAuth": True}}}
    f = check_gateway(
        collect(_home(tmp_path, cfg, unit_lines=f"Environment={TOKEN_VAR}={_VALUE}\n"))
    )
    assert f.status == WARN
    assert "allowInsecureAuth" in f.detail
    assert "environment" in f.detail


def test_soft_clause_does_not_mask_a_real_fail_clause(tmp_path):
    """An unrelated FAIL-worthy condition must still FAIL even when the bind clause was
    softened — the softening is scoped to the exposed-bind clause alone."""
    cfg = {
        "gateway": {"bind": "0.0.0.0"},
        "channels": {"telegram": {"enabled": True, "dmPolicy": "open"}},
    }
    f = check_gateway(
        collect(_home(tmp_path, cfg, unit_lines=f"Environment={TOKEN_VAR}={_VALUE}\n"))
    )
    assert f.status == FAIL
    assert "open dm/group policy" in f.detail


# ---------------------------------------------------------------------------
# B41 — the credential inventory
# ---------------------------------------------------------------------------

def test_b41_without_any_credential_is_unknown(tmp_path):
    f = check_credential_blast_radius(collect(_home(tmp_path, EXPOSED_NO_AUTH)))
    assert f.status == UNKNOWN
    assert f.detail == "No credential profiles found to assess."


def test_b41_counts_an_env_supplied_gateway_credential(tmp_path):
    """BEFORE: has_gateway_token was config-only, so this host inventoried nothing."""
    f = check_credential_blast_radius(
        collect(_home(tmp_path, EXPOSED_NO_AUTH,
                      unit_lines=f"Environment={TOKEN_VAR}={_VALUE}\n"))
    )
    assert f.status != UNKNOWN
    assert any("gateway-token: present" in e for e in f.evidence)
    assert _VALUE not in _blob(f)


def test_b41_names_where_the_env_credential_came_from(tmp_path):
    f = check_credential_blast_radius(
        collect(_home(tmp_path, EXPOSED_NO_AUTH, dotenv=f"{TOKEN_VAR}={_VALUE}"))
    )
    assert any(".env" in e for e in f.evidence)
    assert _VALUE not in _blob(f)


def test_b41_config_token_evidence_is_unchanged(tmp_path):
    """A config-supplied token keeps its original evidence string exactly."""
    cfg = {"gateway": {"auth": {"mode": "token", "token": "a" * 40}}}
    f = check_credential_blast_radius(collect(_home(tmp_path, cfg)))
    assert "gateway-token: present" in f.evidence


# ---------------------------------------------------------------------------
# Known residual, deliberately OUT OF SCOPE for ENV-4 — pinned so it cannot drift
# ---------------------------------------------------------------------------

def test_known_residual_config_token_without_mode_still_fails(tmp_path):
    """PINS A KNOWN FALSE-POSITIVE FAIL THAT THIS CHANGE DOES NOT FIX.

    `gateway.auth.token` set with NO `gateway.auth.mode` is the same shape as the env
    case: resolveGatewayAuth finds `authConfig.mode` falsy and derives mode="token" from
    the credential (auth-resolve-NyPBrh8F.js:34-42), and the credential comes config-FIRST
    (:23-24). So this gateway is authenticated and B2's FAIL is wrong.

    It is NOT fixed here because it is a config-only path with no environment component —
    outside ENV-4's scope — and widening a CRITICAL check's softening beyond the reviewed
    grounding is exactly what this campaign forbids. It is filed for separate triage with
    its own C-135 pass.

    This test pins TODAY's (wrong) behaviour so the residual stays visible. Whoever fixes
    it MUST update this test deliberately — that is the point.
    """
    cfg = {"gateway": {"bind": "0.0.0.0", "auth": {"token": "a" * 40}}}
    f = check_gateway(collect(_home(tmp_path, cfg)))
    assert f.status == FAIL
    assert "exposed with auth.mode=None" in f.detail


def test_override_root_that_cannot_be_walked_does_not_crash_the_audit(tmp_path):
    """B-289 hardening, found by the adversarial pass rather than by a fixture.

    OPENCLAW_BUNDLED_SKILLS_DIR makes a skill-scan root an ARBITRARY absolute path chosen
    by whoever set the variable. If it contains an entry this process cannot stat, the
    discovery walk used to raise PermissionError out of collect() and take the whole audit
    down — turning "an attacker who can write the unit" into "an attacker who can stop any
    report being produced". The partial walk must be recorded as a limit hit, so consumers
    report UNKNOWN rather than a clean PASS over a scan that never finished.
    """
    root = tmp_path / "root"
    (root / "readable" / "sub").mkdir(parents=True)
    blocked = root / "blocked"
    blocked.mkdir()
    (blocked / "inner").mkdir()
    os.chmod(blocked, 0o000)
    try:
        ctx = collect(
            _home(tmp_path, EXPOSED_NO_AUTH,
                  unit_lines=f"Environment=OPENCLAW_BUNDLED_SKILLS_DIR={root}\n")
        )
    finally:
        os.chmod(blocked, 0o755)
    # The audit completed rather than raising, and said so.
    assert isinstance(ctx.installed_skills, dict)


# ---------------------------------------------------------------------------
# C-135 residual closed: the softening is gated on credential STRENGTH.
#
# The independent adversarial pass on B-290 found that presence alone cleared the
# CRITICAL exposed-bind FAIL. It does not any more: the bind guard that justifies the
# softening (server-runtime-config-r5ejxORO.js:66,78) is satisfied by a one-character
# token, so a weak env credential is a LIVE world-reachable gateway, not a secured one.
# The bar is the one check_gateway already applies to a config token.
# ---------------------------------------------------------------------------

def test_short_env_credential_does_not_clear_the_exposed_bind_fail(tmp_path):
    """A one-guess-deep secret is exposure, not authentication.

    `hasSharedSecret` is true for ANY non-empty token, so OpenClaw binds to 0.0.0.0 and
    listens. `assertGatewayAuthConfigured` (auth-B27MflKU.js:183-197) rejects only a
    MISSING credential, and no minimum length exists anywhere in the dist — so the
    "authenticated, or no listener at all" argument does NOT cover this case.
    """
    for weak in ("a", "changeme", "password", "1234567890123456789012"):
        f = check_gateway(
            collect(_home(tmp_path, EXPOSED_NO_AUTH,
                          unit_lines=f"Environment=OPENCLAW_GATEWAY_TOKEN={weak}\n"))
        )
        assert f.status == FAIL, f"{weak!r} ({len(weak)} chars) must not soften B2"
        assert "shorter than 24 chars" in f.detail

    # The leak assertion needs a value that cannot occur in English prose by chance —
    # asserting `"a" not in detail` only proves the alphabet is unused. Assembled from
    # fragments so no contiguous secret-shaped literal exists in the source (§2.3).
    marker = "Zq7" + "Wv2" + "Xj9"
    f = check_gateway(
        collect(_home(tmp_path, EXPOSED_NO_AUTH,
                      unit_lines=f"Environment=OPENCLAW_GATEWAY_TOKEN={marker}\n"))
    )
    assert f.status == FAIL
    assert marker not in f.detail, "the credential value must never reach the report"
    assert marker not in " ".join(f.evidence or [])
    assert marker not in " ".join(f.fix or [])


def test_env_credential_at_the_boundary(tmp_path):
    """23 chars fails, 24 passes — the same bar the config-token clause uses."""
    below = check_gateway(
        collect(_home(tmp_path, EXPOSED_NO_AUTH,
                      unit_lines="Environment=OPENCLAW_GATEWAY_TOKEN=" + "a" * 23 + "\n"))
    )
    assert below.status == FAIL

    at = check_gateway(
        collect(_home(tmp_path, EXPOSED_NO_AUTH,
                      unit_lines="Environment=OPENCLAW_GATEWAY_TOKEN=" + "a" * 24 + "\n"))
    )
    assert at.status == WARN
    assert "the gateway is authenticated" in at.detail


def test_short_env_password_is_also_not_enough(tmp_path):
    """The password leg takes the same bar as the token leg."""
    f = check_gateway(
        collect(_home(tmp_path, EXPOSED_NO_AUTH,
                      unit_lines="Environment=OPENCLAW_GATEWAY_PASSWORD=hunter2\n"))
    )
    assert f.status == FAIL
    assert "shorter than 24 chars" in f.detail
