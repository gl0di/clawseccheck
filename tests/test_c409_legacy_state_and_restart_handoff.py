"""B356/B357 (CLAWSECCHECK-C-409) — re-scoped runtime-state hygiene checks.

Re-scoped by measurement against the installed dist (openclaw@2026.9.3) from this
task's original filing (2026-08-06, against 2026.7.1-2): the filed premise — a live
`credentials/<channel>-allowFrom.json` runtime allow-sender store, independent of
config — no longer holds. Both `credentials/<channel>-allowFrom.json` and
`identity/device-auth.json` are now legacy-only presence markers OpenClaw's own
`state-migrations.doctor`/`device-auth-store` modules check for, never live-authoritative
state; the modern allow-sender mechanism lives entirely in `openclaw.json`. Filename
presence only — content is never read.

`gateway-supervisor-restart-handoff.json` is unchanged from the filing, except that its
`expiresAt`/`createdAt` fields are epoch-millisecond integers, not ISO strings — measured
by hand-reading a real file on this machine, not assumed from the field name.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
import os

import pytest

from clawseccheck.catalog import BY_ID, LOW, PASS, UNKNOWN, WARN
from clawseccheck.checks import CHECKS, check_legacy_state_migration_pending, check_restart_handoff_stale
from clawseccheck.collector import Context


def _ctx(tmp_path):
    return Context(home=tmp_path)


# --------------------------------------------------------------------------- catalog

def test_b356_registered_in_catalog_and_checks():
    assert "B356" in BY_ID
    assert BY_ID["B356"].severity == LOW
    assert BY_ID["B356"].block == "advisory"
    assert check_legacy_state_migration_pending in CHECKS


def test_b357_registered_in_catalog_and_checks():
    assert "B357" in BY_ID
    assert BY_ID["B357"].severity == LOW
    assert BY_ID["B357"].block == "advisory"
    assert check_restart_handoff_stale in CHECKS


# --------------------------------------------------------------------------- B356: clean

def test_b356_clean_home_is_pass(tmp_path):
    f = check_legacy_state_migration_pending(_ctx(tmp_path))
    assert f.status == PASS
    assert "No legacy" in f.detail


def test_b356_empty_credentials_and_identity_dirs_is_pass(tmp_path):
    (tmp_path / "credentials").mkdir()
    (tmp_path / "identity").mkdir()
    f = check_legacy_state_migration_pending(_ctx(tmp_path))
    assert f.status == PASS


def test_b356_unrelated_file_in_credentials_is_not_matched(tmp_path):
    """The suffix filter must not over-match: a real secret/credential file in the same
    directory must never be read or named — only the exact legacy filename shape."""
    (tmp_path / "credentials").mkdir()
    (tmp_path / "credentials" / "some-other-secret.json").write_text("{}")
    f = check_legacy_state_migration_pending(_ctx(tmp_path))
    assert f.status == PASS


# --------------------------------------------------------------------------- B356: WARN

def test_b356_legacy_allowfrom_file_is_warn(tmp_path):
    (tmp_path / "credentials").mkdir()
    (tmp_path / "credentials" / "telegram-allowFrom.json").write_text("[]")
    f = check_legacy_state_migration_pending(_ctx(tmp_path))
    assert f.status == WARN
    assert any("telegram" in e and "allowFrom" in e for e in f.evidence)
    assert "openclaw doctor --fix" in f.fix


def test_b356_legacy_device_auth_file_is_warn(tmp_path):
    (tmp_path / "identity").mkdir()
    (tmp_path / "identity" / "device-auth.json").write_text("{}")
    f = check_legacy_state_migration_pending(_ctx(tmp_path))
    assert f.status == WARN
    assert any("device-auth" in e for e in f.evidence)


def test_b356_both_legacy_files_are_named_together(tmp_path):
    (tmp_path / "credentials").mkdir()
    (tmp_path / "credentials" / "discord-allowFrom.json").write_text("[]")
    (tmp_path / "identity").mkdir()
    (tmp_path / "identity" / "device-auth.json").write_text("{}")
    f = check_legacy_state_migration_pending(_ctx(tmp_path))
    assert f.status == WARN
    assert len(f.evidence) == 2


def test_b356_multiple_channel_allowfrom_files_are_all_named(tmp_path):
    (tmp_path / "credentials").mkdir()
    for channel in ("telegram", "discord", "whatsapp"):
        (tmp_path / "credentials" / f"{channel}-allowFrom.json").write_text("[]")
    f = check_legacy_state_migration_pending(_ctx(tmp_path))
    assert f.status == WARN
    assert len(f.evidence) == 3
    for channel in ("telegram", "discord", "whatsapp"):
        assert any(channel in e for e in f.evidence)


def test_b356_never_reads_legacy_file_content():
    """Filename presence only (§8) — a planted secret-shaped value in either legacy
    file's CONTENT must never reach the finding's detail/evidence/fix text."""
    import tempfile
    from pathlib import Path

    secret = "sk-ant-" + "a" * 20
    with tempfile.TemporaryDirectory() as d:
        home = Path(d)
        (home / "credentials").mkdir()
        (home / "credentials" / "telegram-allowFrom.json").write_text(
            json.dumps([secret]))
        (home / "identity").mkdir()
        (home / "identity" / "device-auth.json").write_text(
            json.dumps({"token": secret}))
        f = check_legacy_state_migration_pending(Context(home=home))
        blob = f.detail + f.fix + " ".join(f.evidence)
        assert secret not in blob


# --------------------------------------------------------------------------- B356: UNKNOWN

@pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0,
                    reason="permission bits are not meaningful as root or on Windows")
def test_b356_unlistable_credentials_dir_is_unknown(tmp_path):
    cred_dir = tmp_path / "credentials"
    cred_dir.mkdir()
    cred_dir.chmod(0o000)
    try:
        f = check_legacy_state_migration_pending(_ctx(tmp_path))
        assert f.status == UNKNOWN
        assert "could not be listed" in f.detail
    finally:
        cred_dir.chmod(0o700)


# --------------------------------------------------------------------------- B357: clean

def test_b357_no_handoff_file_is_pass(tmp_path):
    f = check_restart_handoff_stale(_ctx(tmp_path))
    assert f.status == PASS
    assert "No gateway-supervisor-restart-handoff.json" in f.detail


def test_b357_not_yet_expired_is_pass(tmp_path):
    (tmp_path / "gateway-supervisor-restart-handoff.json").write_text(
        json.dumps({"expiresAt": 99999999999999}))  # far future epoch-ms
    f = check_restart_handoff_stale(_ctx(tmp_path))
    assert f.status == PASS
    assert "in-progress restart handoff" in f.detail


# --------------------------------------------------------------------------- B357: WARN

def test_b357_expired_is_warn(tmp_path):
    (tmp_path / "gateway-supervisor-restart-handoff.json").write_text(
        json.dumps({"expiresAt": 1}))  # epoch-ms 1 -- long past
    f = check_restart_handoff_stale(_ctx(tmp_path))
    assert f.status == WARN
    assert "already passed" in f.detail
    assert "crashed supervisor" in f.detail


def test_b357_real_shape_from_a_real_install_is_warn(tmp_path):
    """The exact field set measured on a real box, minus token-shaped values —
    this is the shape hand-verified before trusting the dist's field-name-only
    citation of it."""
    (tmp_path / "gateway-supervisor-restart-handoff.json").write_text(json.dumps({
        "kind": "restart-handoff", "version": 1, "intentId": "abc123",
        "pid": 12345, "processInstanceId": "def456",
        "createdAt": 1782841196068, "expiresAt": 1782841256068,
        "reason": "config-reload", "source": "cli", "restartKind": "graceful",
        "supervisorMode": "managed",
    }))
    f = check_restart_handoff_stale(_ctx(tmp_path))
    assert f.status == WARN


# --------------------------------------------------------------------------- B357: UNKNOWN

def test_b357_malformed_json_is_unknown(tmp_path):
    (tmp_path / "gateway-supervisor-restart-handoff.json").write_text("not json{{{")
    f = check_restart_handoff_stale(_ctx(tmp_path))
    assert f.status == UNKNOWN
    assert "not valid JSON" in f.detail


def test_b357_not_a_dict_is_unknown(tmp_path):
    (tmp_path / "gateway-supervisor-restart-handoff.json").write_text("[1, 2, 3]")
    f = check_restart_handoff_stale(_ctx(tmp_path))
    assert f.status == UNKNOWN
    assert "not in the expected format" in f.detail


def test_b357_missing_expires_at_is_unknown(tmp_path):
    (tmp_path / "gateway-supervisor-restart-handoff.json").write_text(
        json.dumps({"kind": "restart-handoff"}))
    f = check_restart_handoff_stale(_ctx(tmp_path))
    assert f.status == UNKNOWN
    assert "no readable expiresAt" in f.detail


def test_b357_expires_at_wrong_type_is_unknown(tmp_path):
    """A caller mistake (or a future OpenClaw format change back to ISO strings) must
    degrade to UNKNOWN, never crash or silently misread the type."""
    (tmp_path / "gateway-supervisor-restart-handoff.json").write_text(
        json.dumps({"expiresAt": "2026-06-30T20:40:56"}))
    f = check_restart_handoff_stale(_ctx(tmp_path))
    assert f.status == UNKNOWN


def test_b357_expires_at_boolean_is_unknown(tmp_path):
    """bool is a subclass of int in Python -- must not silently pass isinstance(x, int)."""
    (tmp_path / "gateway-supervisor-restart-handoff.json").write_text(
        json.dumps({"expiresAt": True}))
    f = check_restart_handoff_stale(_ctx(tmp_path))
    assert f.status == UNKNOWN


@pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0,
                    reason="permission bits are not meaningful as root or on Windows")
def test_b357_unreadable_file_is_unknown(tmp_path):
    path = tmp_path / "gateway-supervisor-restart-handoff.json"
    path.write_text(json.dumps({"expiresAt": 1}))
    path.chmod(0o000)
    try:
        f = check_restart_handoff_stale(_ctx(tmp_path))
        assert f.status == UNKNOWN
        assert "unreadable" in f.detail
    finally:
        path.chmod(0o600)


# --------------------------------------------------------------------------- end to end

def test_b356_and_b357_reach_run_all(tmp_path):
    from clawseccheck.checks import run_all

    (tmp_path / "credentials").mkdir()
    (tmp_path / "credentials" / "telegram-allowFrom.json").write_text("[]")
    ctx = Context(home=tmp_path)
    findings = run_all(ctx)
    by_id = {f.id: f for f in findings}
    assert by_id["B356"].status == WARN
    assert by_id["B357"].status == PASS
