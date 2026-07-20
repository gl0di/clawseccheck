"""B193 (B-290, ENV-4) — a gateway credential written inline into a systemd user unit.

Grounded in OpenClaw's OWN service audit: auditGatewayToken
(service-audit-bKq3tdW1.js:185-192) raises `gatewayTokenEmbedded` — "Gateway service
embeds OPENCLAW_GATEWAY_TOKEN and should be reinstalled." — and readEmbeddedGatewayToken
(:247) deliberately returns early when the value's source is EnvironmentFile-ONLY
(isEnvironmentFileOnlySource, systemd-B4Oq2owH.js:29-30). This check mirrors that
distinction exactly: it reads ctx.unit_env_inline, not ctx.unit_env_values.

Calibration: OpenClaw rates its own finding level "recommended", so a blanket FAIL would
be harsher than the vendor's audit. FAIL is reserved for the case where the privilege is
real and checkable — the unit file is readable by another local account.

No fixture carries a credential: the secret-shaped values here are assembled at runtime
from fragments so no contiguous secret-looking literal exists on disk (project rule §2.3).

Offline, read-only, stdlib only. Nothing is written outside tmp_path.
"""
from __future__ import annotations

import os
from pathlib import Path

from clawseccheck.catalog import BY_ID, FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_unit_embedded_gateway_secret
from clawseccheck.collector import collect

TOKEN_VAR = "OPENCLAW_GATEWAY_" + "TOKEN"
PASSWORD_VAR = "OPENCLAW_GATEWAY_" + "PASSWORD"
_VALUE = "q" * 12 + "3" + "cr" + "3t" + "7" * 12


def _home(root: Path, *, unit_lines: str = "", mode: int = 0o600,
          units: bool = True) -> Path:
    home = root / ".openclaw"
    home.mkdir(exist_ok=True)
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    if units:
        unit_dir = root / ".config" / "systemd" / "user"
        unit_dir.mkdir(parents=True, exist_ok=True)
        unit = unit_dir / "openclaw-gateway.service"
        unit.write_text(
            "[Unit]\nDescription=OpenClaw Gateway\n\n"
            "[Service]\nExecStart=/usr/bin/openclaw gateway run\n"
            + unit_lines
            + "\n[Install]\nWantedBy=default.target\n",
            encoding="utf-8",
        )
        os.chmod(unit, mode)
    return home


def _blob(f) -> str:
    return " ".join([f.detail, f.fix, *f.evidence])


def test_no_unit_is_unknown(tmp_path):
    f = check_unit_embedded_gateway_secret(collect(_home(tmp_path, units=False)))
    assert f.status == UNKNOWN


def test_unit_without_a_credential_passes(tmp_path):
    f = check_unit_embedded_gateway_secret(
        collect(_home(tmp_path, unit_lines="Environment=OPENCLAW_GATEWAY_PORT=8899\n"))
    )
    assert f.status == PASS


def test_owner_only_unit_with_an_inlined_token_warns(tmp_path):
    """Hygiene, not an active exposure: only this account can read the file today."""
    f = check_unit_embedded_gateway_secret(
        collect(_home(tmp_path, unit_lines=f"Environment={TOKEN_VAR}={_VALUE}\n",
                      mode=0o600))
    )
    assert f.status == WARN
    assert TOKEN_VAR in " ".join(f.evidence)
    assert _VALUE not in _blob(f)


def test_world_readable_unit_with_an_inlined_token_fails(tmp_path):
    """The escalation: every local account can read the gateway secret."""
    f = check_unit_embedded_gateway_secret(
        collect(_home(tmp_path, unit_lines=f"Environment={TOKEN_VAR}={_VALUE}\n",
                      mode=0o644))
    )
    assert f.status == FAIL
    assert "world-readable" in " ".join(f.evidence)
    assert _VALUE not in _blob(f)


def test_inlined_password_is_covered_too(tmp_path):
    f = check_unit_embedded_gateway_secret(
        collect(_home(tmp_path, unit_lines=f"Environment={PASSWORD_VAR}={_VALUE}\n",
                      mode=0o644))
    )
    assert f.status == FAIL
    assert PASSWORD_VAR in " ".join(f.evidence)


def test_environment_file_sourced_credential_does_not_fire(tmp_path):
    """The dist exempts an EnvironmentFile-only source (service-audit-bKq3tdW1.js:247).

    Moving the secret out of the unit and into a private env file is the RECOMMENDED
    remediation — flagging it would punish the fix.
    """
    envfile = tmp_path / "gateway-secret.env"
    envfile.write_text(f"{TOKEN_VAR}={_VALUE}\n", encoding="utf-8")
    os.chmod(envfile, 0o600)
    ctx = collect(_home(tmp_path, unit_lines=f"EnvironmentFile=-{envfile}\n", mode=0o644))
    # The value IS observed (B2/B41 need it) but is not attributed to an inline line.
    assert ctx.unit_env_values.get(TOKEN_VAR) == _VALUE
    assert TOKEN_VAR not in ctx.unit_env_inline
    assert check_unit_embedded_gateway_secret(ctx).status == PASS


def test_the_secret_value_never_appears_in_output(tmp_path):
    """§8: the value is read only so presence can be tested; it must never be emitted."""
    for mode in (0o600, 0o644):
        root = tmp_path / f"m{mode:o}"
        root.mkdir()
        f = check_unit_embedded_gateway_secret(
            collect(_home(root, unit_lines=f"Environment={TOKEN_VAR}={_VALUE}\n",
                          mode=mode))
        )
        assert _VALUE not in _blob(f)


def test_b193_is_catalogued_and_unscored():
    meta = BY_ID["B193"]
    assert meta.severity == "MEDIUM"
    # OpenClaw rates its own equivalent finding "recommended"; grading a host that merely
    # followed an older install path as a breach would overstate it.
    assert meta.scored is False
