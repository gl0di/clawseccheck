"""B384 (F-197): desktop.host.passwordFile's at-rest permissions.

Grounded against the installed OpenClaw dist: `desktop.host.passwordFile` is the sole
`-PasswordFile` TigerVNC's `-SecurityTypes VncAuth` uses (buildTigerVncArgv,
host-source-v64nW4u1.mjs). Same idiom as B182/B193: `_file_readable_by_others`
(checks/_shared.py) never counts a user-private group as an exposure (B-127); only
world-readable is exercised directly here, matching those checks' own test coverage of
the shared helper (re-tested there, not duplicated per-caller).

The password file's CONTENT is never read by the check or referenced in these tests.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import CATALOG, FAIL, PASS, UNKNOWN
from clawseccheck.checks import _config as _config_mod
from clawseccheck.checks import check_desktop_host_password_file
from clawseccheck.collector import Context


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def test_no_config_is_unknown():
    ctx = _ctx({})
    ctx.config = None
    assert check_desktop_host_password_file(ctx).status == UNKNOWN


def test_desktop_host_absent_is_pass():
    # A non-empty config with no `desktop` section -- `{}` alone is falsy and would hit
    # the distinct "no config loaded at all" UNKNOWN branch instead.
    r = check_desktop_host_password_file(_ctx({"gateway": {}}))
    assert r.status == PASS


def test_desktop_host_malformed_is_unknown():
    r = check_desktop_host_password_file(_ctx({"desktop": {"host": "nope"}}))
    assert r.status == UNKNOWN


def test_password_file_unset_is_pass():
    r = check_desktop_host_password_file(_ctx({"desktop": {"host": {"enabled": True}}}))
    assert r.status == PASS


def test_password_file_missing_is_unknown(tmp_path):
    missing = tmp_path / "nope.vncpw"
    cfg = {"desktop": {"host": {"enabled": True, "passwordFile": str(missing)}}}
    r = check_desktop_host_password_file(_ctx(cfg))
    assert r.status == UNKNOWN


def test_owner_only_password_file_is_pass(tmp_path):
    pw = tmp_path / "passwd"
    pw.write_bytes(b"\x00" * 8)  # inert placeholder, not a real VNC-obfuscated password
    pw.chmod(0o600)
    cfg = {"desktop": {"host": {"enabled": True, "passwordFile": str(pw)}}}
    r = check_desktop_host_password_file(_ctx(cfg))
    assert r.status == PASS
    assert "owner" in r.detail


def test_world_readable_password_file_is_fail(tmp_path):
    pw = tmp_path / "passwd"
    pw.write_bytes(b"\x00" * 8)
    pw.chmod(0o644)
    cfg = {"desktop": {"host": {"enabled": True, "passwordFile": str(pw)}}}
    r = check_desktop_host_password_file(_ctx(cfg))
    assert r.status == FAIL
    assert "world-readable" in r.detail
    assert any("world-readable" in e for e in r.evidence)
    # The (inert, placeholder) file content never appears in the finding (§8).
    assert "\\x00" not in r.detail and "\\x00" not in r.fix


def test_no_mode_based_finding_on_non_posix(tmp_path, monkeypatch):
    pw = tmp_path / "passwd"
    pw.write_bytes(b"\x00" * 8)
    pw.chmod(0o644)
    cfg = {"desktop": {"host": {"enabled": True, "passwordFile": str(pw)}}}
    monkeypatch.setattr(_config_mod, "_is_posix", lambda: False)
    r = check_desktop_host_password_file(_ctx(cfg))
    assert r.status == UNKNOWN
    assert "NTFS" in r.detail


def test_catalog_entry():
    m = next(c for c in CATALOG if c.id == "B384")
    assert m.surface == "secrets"
    assert m.scored is True
