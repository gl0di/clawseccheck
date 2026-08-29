"""B-666 — the "sensitive data" leg reads the credential store's CONTENT, not its name.

The defect, measured on a real fleet home on 2026-08-27: ``~/.openclaw/credentials/`` held
94 bytes in two files — a Telegram allow-list and an empty pairing-request list — and that
directory's mere EXISTENCE was the only thing holding up A1's CRITICAL 3/3 FAIL. Moving
those 94 bytes elsewhere flipped A1 to PASS and the grade from F/49 to C/79, while the bot
token, the provider profile and the gateway token all stayed exactly where they were.

Both directions are pinned here: a store holding no credential must not raise the leg, and
a credential ANYWHERE in the store must. No secret-shaped literal exists in this file —
every token is assembled at runtime from fragments (§2.3), the same rule tests/test_logsafe.py
follows.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from clawseccheck.checks import _credential_store_state, _trifecta_leg_sources
from clawseccheck.collector import Context

# Assembled at runtime so no contiguous secret-shaped string is ever stored in source.
_OAUTH_TOKEN = "ya29." + "A" * 40
_REFRESH = "1//0g" + "B" * 32


def _home(tmp_path: Path, files: dict) -> Path:
    home = tmp_path / "home"
    store = home / "credentials"
    store.mkdir(parents=True)
    for name, body in files.items():
        path = store / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
        os.chmod(path, 0o600)
    return home


def _sensitive(home: Path) -> list:
    ctx = Context(home=home)
    ctx.config = {}
    return _trifecta_leg_sources(ctx)["sensitive data"]


# ------------------------------------------------------------------ the reported case

def test_the_real_fleet_store_does_not_raise_the_leg(tmp_path):
    """The exact two files the real home held. Neither is a credential."""
    home = _home(tmp_path, {
        "telegram-default-allowFrom.json": json.dumps({"version": 1, "allowFrom": ["123456789"]}),
        "telegram-pairing.json": json.dumps({"version": 1, "requests": []}),
    })
    state = _credential_store_state(home)
    assert state["present"] is True
    assert state["secret_files"] == []
    assert state["incomplete"] is False
    assert _sensitive(home) == []


def test_an_empty_store_does_not_raise_the_leg(tmp_path):
    home = _home(tmp_path, {})
    assert _credential_store_state(home)["secret_files"] == []
    assert _sensitive(home) == []


def test_no_store_at_all_is_not_present(tmp_path):
    home = tmp_path / "bare"
    home.mkdir()
    state = _credential_store_state(home)
    # `digests` was added by B-677 so the MONITOR can see a credential REPLACED, which no
    # status-based check can — measured: with the sensitive-data leg already up, a second
    # credential file and a rotated token both produced zero alerts anywhere. Additive: no
    # existing key or value moved, and this exact-dict pin is what asked the question.
    assert state == {"present": False, "secret_files": [], "incomplete": False,
                     "reason": "", "digests": {}}
    assert _sensitive(home) == []


def test_a_missing_home_is_tolerated():
    """Some tests build Context via __new__ without a home; production always sets it."""
    assert _credential_store_state(None)["present"] is False


# ---------------------------------------------------------------- the other direction

def test_an_oauth_grant_in_the_store_raises_the_leg(tmp_path):
    """`credentials/oauth.json` is where `resolveOAuthDir` writes a real grant."""
    home = _home(tmp_path, {
        "oauth.json": json.dumps({"access_token": _OAUTH_TOKEN, "refresh_token": _REFRESH}),
        "telegram-pairing.json": json.dumps({"version": 1, "requests": []}),
    })
    state = _credential_store_state(home)
    assert state["secret_files"] == ["oauth.json"]
    sources = _sensitive(home)
    assert sources == ["credentials/oauth.json holds a plaintext credential"]


def test_a_credential_in_a_nested_file_is_found(tmp_path):
    home = _home(tmp_path, {"providers/openai.json": json.dumps({"apiKey": _OAUTH_TOKEN})})
    assert _credential_store_state(home)["secret_files"] == [os.path.join("providers", "openai.json")]


def test_no_secret_value_ever_reaches_a_source_string(tmp_path):
    """§8: evidence names files, never values."""
    home = _home(tmp_path, {"oauth.json": json.dumps({"access_token": _OAUTH_TOKEN})})
    blob = " ".join(_sensitive(home)) + json.dumps(_credential_store_state(home))
    assert _OAUTH_TOKEN not in blob
    assert "ya29" not in blob


def test_many_credential_files_disclose_the_overflow(tmp_path):
    """A truncated list that does not say it was truncated is the B-513 defect."""
    home = _home(tmp_path, {
        f"p{i}.json": json.dumps({"access_token": _OAUTH_TOKEN}) for i in range(6)
    })
    sources = _sensitive(home)
    assert len(sources) == 4
    assert sources[-1] == "(+3 more file(s) in credentials/ hold a plaintext credential)"


# --------------------------------------------------------------------- incompleteness

def test_an_unreadable_subdirectory_makes_the_answer_incomplete(tmp_path):
    """"No credential found" over a walk that could not finish is not "no credential"."""
    home = _home(tmp_path, {"nested/inner.json": json.dumps({"version": 1})})
    blocked = home / "credentials" / "nested"
    os.chmod(blocked, 0o000)
    try:
        state = _credential_store_state(home)
        assert state["incomplete"] is True
        assert state["reason"]
        assert state["secret_files"] == []
    finally:
        os.chmod(blocked, 0o700)


def test_an_oversized_file_makes_the_answer_incomplete(tmp_path):
    from clawseccheck.checks import _CRED_STORE_MAX_BYTES

    home = _home(tmp_path, {"huge.json": "x" * (_CRED_STORE_MAX_BYTES + 1)})
    state = _credential_store_state(home)
    assert state["incomplete"] is True
    assert "too large" in state["reason"]
