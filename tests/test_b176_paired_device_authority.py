"""B176 (B-243): standing operator authority in paired device store
(devices/paired.json).

`check_pending_device_pairing_scope` (B138) audits only the *pending* pairing
request store (devices/pending.json). Once a pairing is approved it moves to
devices/paired.json and carries a live standing operator token + granted scopes --
before this check, nothing read that store's scope/approvedScopes dimension.

Grounded: docs/research/openclaw-schema-recon.md §14.3 -- confirmed real keys
(live install) deviceId, publicKey, platform, clientId, clientMode, role, roles,
scopes, approvedScopes, tokens, createdAtMs, approvedAtMs, lastSeenAtMs,
lastSeenReason.

C-135: >=1 paired operator-scope device is the EXPECTED state for every normal
OpenClaw install (the user's own phone/laptop) -- so this is WARN/advisory
inventory, never FAIL, matching B138's precedent exactly. The check must never
read/echo the `tokens` field's value.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import BY_ID, FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_paired_device_operator_authority
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(home) -> Context:
    return Context(home=Path(home))


# ---------------------------------------------------------------------------
# Fixtures on disk
# ---------------------------------------------------------------------------

def test_bad_fixture_warns_on_high_scope_device():
    f = check_paired_device_operator_authority(
        _ctx(FIXTURES / "bad_b176_paired_operator_admin")
    )
    assert f.id == "B176"
    assert f.status == WARN
    assert any("webchat-a1b2c3d4" in e for e in f.evidence)
    assert any("operator.admin" in e for e in f.evidence)


def test_clean_fixture_passes_when_only_read_scope():
    f = check_paired_device_operator_authority(
        _ctx(FIXTURES / "clean_b176_paired_no_highscope")
    )
    assert f.id == "B176"
    assert f.status == PASS


# ---------------------------------------------------------------------------
# Never-echo-the-token contract
# ---------------------------------------------------------------------------

def test_token_value_never_echoed_in_evidence_or_detail():
    f = check_paired_device_operator_authority(
        _ctx(FIXTURES / "bad_b176_paired_operator_admin")
    )
    assert "REDACTED" not in f.detail
    assert not any("REDACTED" in e for e in f.evidence)
    assert not any("token" in e.lower() for e in f.evidence)


# ---------------------------------------------------------------------------
# UNKNOWN / absence / empty coverage (dynamic, tmp_path)
# ---------------------------------------------------------------------------

def test_pass_when_file_absent(tmp_path):
    """Absence of devices/paired.json is informative (nothing paired yet) -- PASS,
    not UNKNOWN, matching B138's precedent for its own absent-file case."""
    f = check_paired_device_operator_authority(_ctx(tmp_path))
    assert f.status == PASS


def test_pass_when_file_empty(tmp_path):
    d = tmp_path / "devices"
    d.mkdir()
    (d / "paired.json").write_text("{}", encoding="utf-8")
    f = check_paired_device_operator_authority(_ctx(tmp_path))
    assert f.status == PASS


def test_unknown_when_malformed_json(tmp_path):
    d = tmp_path / "devices"
    d.mkdir()
    (d / "paired.json").write_text("{not valid json", encoding="utf-8")
    f = check_paired_device_operator_authority(_ctx(tmp_path))
    assert f.status == UNKNOWN


def test_unknown_when_not_a_json_object(tmp_path):
    d = tmp_path / "devices"
    d.mkdir()
    (d / "paired.json").write_text('["not", "an", "object"]', encoding="utf-8")
    f = check_paired_device_operator_authority(_ctx(tmp_path))
    assert f.status == UNKNOWN


# ---------------------------------------------------------------------------
# Scope-field coverage: `scopes` alone (no approvedScopes) still triggers
# ---------------------------------------------------------------------------

def test_warn_operator_write_via_bare_scopes_field(tmp_path):
    d = tmp_path / "devices"
    d.mkdir()
    (d / "paired.json").write_text(
        '{"d1": {"deviceId": "cli-01", "platform": "linux", '
        '"scopes": ["operator.write"], "lastSeenAtMs": 1751000000000}}',
        encoding="utf-8",
    )
    f = check_paired_device_operator_authority(_ctx(tmp_path))
    assert f.status == WARN
    assert any("operator.write" in e for e in f.evidence)


def test_pass_when_only_low_scope_present(tmp_path):
    d = tmp_path / "devices"
    d.mkdir()
    (d / "paired.json").write_text(
        '{"d1": {"deviceId": "phone-01", "platform": "ios", '
        '"approvedScopes": ["operator.read", "operator.pairing"]}}',
        encoding="utf-8",
    )
    f = check_paired_device_operator_authority(_ctx(tmp_path))
    assert f.status == PASS


# ---------------------------------------------------------------------------
# B-243 FP fix: a device whose every token has been revoked holds no live
# authority, even though `scopes`/`approvedScopes` still list the historical
# grant (`openclaw devices revoke` deliberately leaves those fields alone --
# device-pairing-Dw7KWdQ7.js:783-812). Grounded: OpenClaw's own auth path
# treats a token with `revokedAtMs` set as dead (server-aux-handlers-
# BfM3vWwc.js:870).
# ---------------------------------------------------------------------------

def test_pass_when_only_token_is_revoked(tmp_path):
    """The FP this fix closes: scopes/approvedScopes still list operator.admin/
    operator.write (the historical baseline `openclaw devices revoke` leaves
    untouched), but the device's only token carries `revokedAtMs` -- OpenClaw's
    own auth returns null for it, so the device holds no live authority."""
    d = tmp_path / "devices"
    d.mkdir()
    (d / "paired.json").write_text(
        '{"hash-abc": {"deviceId": "old-laptop-0001", "platform": "linux", '
        '"role": "operator", "roles": ["operator"], '
        '"scopes": ["operator.admin", "operator.write"], '
        '"approvedScopes": ["operator.admin", "operator.write"], '
        '"tokens": {"operator": {"role": "operator", '
        '"scopes": ["operator.admin", "operator.write"], '
        '"createdAtMs": 1700000000000, "revokedAtMs": 1784000000000}}, '
        '"createdAtMs": 1700000000000, "lastSeenAtMs": 1700000002000}}',
        encoding="utf-8",
    )
    f = check_paired_device_operator_authority(_ctx(tmp_path))
    assert f.status == PASS


def test_warn_when_token_is_live_not_revoked(tmp_path):
    """Direction (b): an un-revoked (live) operator token must still WARN --
    the revoked-token skip must never swallow a genuine live grant."""
    d = tmp_path / "devices"
    d.mkdir()
    (d / "paired.json").write_text(
        '{"hash-xyz": {"deviceId": "unknown-android-1", "platform": "android", '
        '"approvedScopes": ["operator.admin"], '
        '"tokens": {"operator": {"role": "operator", '
        '"scopes": ["operator.admin"], "createdAtMs": 1784000000000}}, '
        '"lastSeenAtMs": 1784000002000}}',
        encoding="utf-8",
    )
    f = check_paired_device_operator_authority(_ctx(tmp_path))
    assert f.status == WARN
    assert any("unknown-android-1" in e for e in f.evidence)


def test_warn_when_only_some_tokens_revoked(tmp_path):
    """A device holding one revoked role token and one live role token must
    still WARN -- only an all-revoked `tokens` dict is treated as dead."""
    d = tmp_path / "devices"
    d.mkdir()
    (d / "paired.json").write_text(
        '{"hash-mix": {"deviceId": "mixed-device-1", "platform": "linux", '
        '"roles": ["operator", "viewer"], '
        '"approvedScopes": ["operator.admin", "operator.write"], '
        '"tokens": {'
        '"viewer": {"role": "viewer", "scopes": ["operator.read"], '
        '"createdAtMs": 1700000000000, "revokedAtMs": 1784000000000}, '
        '"operator": {"role": "operator", '
        '"scopes": ["operator.admin", "operator.write"], '
        '"createdAtMs": 1784000000000}}, '
        '"lastSeenAtMs": 1784000002000}}',
        encoding="utf-8",
    )
    f = check_paired_device_operator_authority(_ctx(tmp_path))
    assert f.status == WARN


def test_warn_when_tokens_field_absent():
    """No `tokens` field at all (as in the bad fixture) -- unchanged prior
    behavior: still WARN, since we have no revocation evidence either way."""
    f = check_paired_device_operator_authority(
        _ctx(FIXTURES / "bad_b176_paired_operator_admin")
    )
    assert f.status == WARN


def test_warn_when_tokens_dict_is_empty(tmp_path):
    """An empty `tokens` dict is not evidence of revocation -- `all()` over
    an empty iterable is vacuously True, so this pins that we guard against
    treating "no tokens recorded" as "all tokens revoked"."""
    d = tmp_path / "devices"
    d.mkdir()
    (d / "paired.json").write_text(
        '{"d1": {"deviceId": "device-1", "platform": "linux", '
        '"approvedScopes": ["operator.admin"], "tokens": {}, '
        '"lastSeenAtMs": 1784000002000}}',
        encoding="utf-8",
    )
    f = check_paired_device_operator_authority(_ctx(tmp_path))
    assert f.status == WARN


# ---------------------------------------------------------------------------
# C-135: never FAIL, whatever the shape
# ---------------------------------------------------------------------------

def test_never_fails_on_any_fixture():
    for name in ("bad_b176_paired_operator_admin", "clean_b176_paired_no_highscope"):
        f = check_paired_device_operator_authority(_ctx(FIXTURES / name))
        assert f.status != FAIL


def test_never_fails_on_many_high_scope_devices(tmp_path):
    """Multiple paired operator-scope devices (a legitimate household with several
    admin clients) must stay WARN, never escalate to FAIL."""
    d = tmp_path / "devices"
    d.mkdir()
    entries = {
        f"d{i}": {
            "deviceId": f"device-{i}",
            "platform": "linux",
            "approvedScopes": ["operator.admin"],
            "lastSeenAtMs": 1751000000000,
        }
        for i in range(10)
    }
    import json
    (d / "paired.json").write_text(json.dumps(entries), encoding="utf-8")
    f = check_paired_device_operator_authority(_ctx(tmp_path))
    assert f.status == WARN


# ---------------------------------------------------------------------------
# Check metadata
# ---------------------------------------------------------------------------

def test_check_meta_advisory_unscored_agents_surface():
    m = BY_ID["B176"]
    assert m.scored is False
    assert m.surface == "agents"
