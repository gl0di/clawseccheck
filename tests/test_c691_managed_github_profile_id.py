"""C-691 (behaviour, part 1) - C015 read OpenClaw's managed GitHub profile id as a plaintext
token. The id is `ghp_` + 32 lowercase hex (`randomBytes(16)`, vendor
`github-identity-profile-id-*.mjs`: `/^ghp_[a-f0-9]{32}$/`), an opaque directory name stored at
`tools.github.profileId` (system scope) or `agents.entries.<id>.tools.github.profileId`.

It is recognised by PATH and SHAPE. A real classic token (`ghp_` + 36 base62) at that path, and
the id shape anywhere else, still WARN. Imports only names that exist on the unfixed tree, so
the "id at its path is clean" cases fail there for the stated reason (C015 WARN).

Direction: WARN -> PASS for the id at its vendor path only. Values are derived at runtime.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.catalog import PASS, WARN


def _hex32(seed: bytes = b"c691") -> str:
    return hashlib.sha256(seed).hexdigest()[:32]


def _profile_id(seed: bytes = b"c691") -> str:
    return "ghp" + "_" + _hex32(seed)


def _classic_token() -> str:
    raw = base64.b64encode(hashlib.sha256(b"c691-classic").digest()).decode()
    return "ghp" + "_" + "".join(c for c in raw if c.isalnum())[:36]


def _c015(tmp_path: Path, cfg: dict):
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    p = home / "openclaw.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")
    p.chmod(0o600)
    _, findings, _ = audit(home)
    return {f.id: f for f in findings}["C015"]


@pytest.mark.parametrize(
    "cfg",
    [
        {"tools": {"github": {"profileId": _profile_id(), "login": "octocat"}}},
        {"agents": {"entries": {"main": {"tools": {"github": {"profileId": _profile_id()}}}}}},
        {"tools": {"github": {"profileId": _profile_id()}},
         "agents": {"entries": {"a": {"tools": {"github": {"profileId": _profile_id(b"other")}}}}}},
    ],
    ids=["system-scope", "per-agent", "both-scopes"],
)
def test_the_managed_profile_id_at_its_path_is_not_a_secret(tmp_path, cfg):
    assert _c015(tmp_path, cfg).status == PASS


def test_the_control_without_the_block_is_also_clean(tmp_path):
    assert _c015(tmp_path, {"tools": {"profile": "coding"}}).status == PASS


@pytest.mark.parametrize(
    "label,cfg",
    [
        ("classic token at the profileId path", {"tools": {"github": {"profileId": _classic_token()}}}),
        ("id shape at the token key",
         {"tools": {"github": {"profileId": _profile_id(), "token": _profile_id(b"t")}}}),
        ("id shape in an unrelated key", {"notes": {"id": _profile_id()}}),
        ("profileId under a block that is not tools.github",
         {"integrations": {"github": {"profileId": _profile_id()}}}),
        ("the same id at its path and somewhere else",
         {"tools": {"github": {"profileId": _profile_id()}}, "notes": {"copy": _profile_id()}}),
        ("uppercase hex is not the vendor shape",
         {"tools": {"github": {"profileId": "ghp" + "_" + _hex32().upper()}}}),
        ("33 hex is not the vendor shape", {"tools": {"github": {"profileId": _profile_id() + "a"}}}),
        ("a token that merely starts with the id",
         {"tools": {"github": {"profileId": _profile_id(), "pat": _profile_id() + "Zq"}}}),
        ("profileId that is not a string", {"tools": {"github": {"profileId": [_profile_id()]}}}),
    ],
)
def test_a_real_token_or_the_id_shape_anywhere_else_still_warns(tmp_path, label, cfg):
    assert _c015(tmp_path, cfg).status == WARN, label
