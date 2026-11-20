"""B-1112 - a plaintext GitHub App private key in openclaw.json (OpenClaw 2026.11.5).

`tools.github.app.privateKey` (and the per-agent copy under `agents.entries.<id>.tools.github`)
is a SecretInput holding the PEM itself: github-tool-identity-*.mjs resolves it with
normalizeResolvedSecretInputString and signs the app JWT with the result. `privateKey` is not a
leaf name SECRET_KEY_RE knows, so before this change B1/C015 never saw it. Covered by a vendor
PATH rule, so an unrelated `privateKey` elsewhere does not start to flag.

Secret-shaped values are assembled at runtime from fragments.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.catalog import FAIL, PASS, WARN
from clawseccheck.checks import _secret_paths


def _pem() -> str:
    body = base64.b64encode(hashlib.sha256(b"b1112").digest() * 8).decode()
    return "-----BEGIN " + "RSA PRIVATE KEY-----\n" + body + "\n-----END " + "RSA PRIVATE KEY-----\n"


def _github(private_key) -> dict:
    # The real 11.5 shape of an app-installation identity.
    return {
        "kind": "app-installation",
        "app": {
            "appId": 123456,
            "installationId": 7654321,
            "accountId": 99,
            "privateKey": private_key,
            "repositories": [{"id": 1, "fullName": "octo/repo"}],
        },
    }


_REF = {"source": "env", "provider": "default", "id": "GITHUB_APP_KEY"}


def _cfg(scope: str, private_key) -> dict:
    if scope == "top":
        return {"tools": {"github": _github(private_key)}}
    if scope == "list":
        # The legacy roster: still collected by runtime-config-collectors-core-*.mjs and
        # migrated by Doctor, so a plaintext key there sits on disk too (C-135, 2026-11-20).
        return {"agents": {"list": [{"id": "main", "tools": {"github": _github(private_key)}}]}}
    return {"agents": {"entries": {"main": {"tools": {"github": _github(private_key)}}}}}


def _run(tmp_path: Path, cfg: dict, mode: int):
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    p = home / "openclaw.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")
    p.chmod(mode)
    _, findings, _ = audit(home)
    by = {f.id: f for f in findings}
    return by["B1"], by["C015"]


@pytest.mark.parametrize("scope", ["top", "agent", "list"])
def test_inline_pem_in_a_readable_config_fails_b1_and_warns_c015(tmp_path, scope):
    b1, c015 = _run(tmp_path, _cfg(scope, _pem()), 0o644)
    assert b1.status == FAIL, b1.detail
    assert c015.status == WARN
    blob = json.dumps([b1.detail, b1.evidence, b1.fix, c015.detail, c015.evidence])
    assert _pem().splitlines()[1][:20] not in blob  # the key material is never echoed


@pytest.mark.parametrize("scope", ["top", "agent", "list"])
def test_inline_pem_in_a_private_config_still_warns_c015(tmp_path, scope):
    b1, c015 = _run(tmp_path, _cfg(scope, _pem()), 0o600)
    assert b1.status == PASS and "file perms are tight" in b1.detail
    assert c015.status == WARN


@pytest.mark.parametrize("scope", ["top", "agent", "list"])
@pytest.mark.parametrize("ref", [_REF, "${GITHUB_APP_KEY}"], ids=["secretref", "template"])
def test_a_reference_is_clean(tmp_path, scope, ref):
    b1, c015 = _run(tmp_path, _cfg(scope, ref), 0o644)
    assert b1.status == PASS and c015.status == PASS


def test_no_github_identity_adds_nothing():
    assert _secret_paths({"tools": {"github": {"kind": "none"}}}) == []
    assert _secret_paths({"tools": {}}) == []


def test_paths_name_the_slot_not_the_value():
    paths = _secret_paths(_cfg("agent", _pem()))
    assert paths == ["agents.entries.main.tools.github.app.privateKey"]
    assert _secret_paths(_cfg("list", _pem())) == ["agents.list[0].tools.github.app.privateKey"]


def test_a_non_github_private_key_slot_is_not_widened():
    assert _secret_paths({"agents": {"defaults": {"tools": {"github": _github(_pem())}}}}) == []
    assert _secret_paths({"plugins": {"x": {"app": {"privateKey": _pem()}}}}) == []
