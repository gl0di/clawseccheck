"""B321 (E-060 batch, 2026-07-25): browser.executablePath / profiles.*.{executablePath,
mcpCommand}.

Two sub-signals under one check ID:
  - executablePath (top-level and per-profile) is spawned with only an fs.existsSync()
    gate (chrome.executables-DP_XzlNl.js:626-640) -- a configured, EXISTING path that
    is writable by another local account is a FAIL (checks/_shared
    _dir_replaceable_by_others, on both the file itself and its parent directory).
  - profiles.<name>.mcpCommand (existing-session driver only) overrides the vendor
    default (npx -y chrome-devtools-mcp@latest) with zero OpenClaw-side validation --
    WARN-only, scored=False on that branch (B192/B324 precedent: a legitimate,
    plausibly-hardening customization, not to be punished with a FAIL).

Severity shape:
  - no browser config                                              -> UNKNOWN
  - browser configured, no executablePath and no mcpCommand         -> UNKNOWN
  - executablePath configured, ctx.include_host is False            -> UNKNOWN
  - executablePath configured + exists + writable by another acct   -> FAIL
  - existing-session mcpCommand != default "npx"                    -> WARN (scored=False)
  - executablePath configured + exists + tight, no mcpCommand       -> PASS
  - executablePath configured but does not exist on disk            -> contributes
    nothing (matches B186's own "configured-but-nonexistent = not a finding" precedent)

This module is offline, read-only, and writes nothing outside tmp_path.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_browser_executable_path
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _home(tmp_path: Path, config: dict | None = None) -> Path:
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    if config is not None:
        (home / "openclaw.json").write_text(json.dumps(config), encoding="utf-8")
    return home


# ---------------------------------------------------------------------------
# On-disk fixtures
# ---------------------------------------------------------------------------

def test_clean_fixture_passes_with_host_scan():
    """The clean fixture's executablePath is a guaranteed-nonexistent absolute path --
    with host scanning on, that contributes no evidence and no mcpCommand override is
    present, so the check reaches PASS."""
    ctx = collect(FIXTURES / "clean_b321_browser_executable_path")
    ctx.include_host = True
    r = check_browser_executable_path(ctx)
    assert r.status == PASS


def test_clean_fixture_without_host_scan_is_unknown():
    """The same fixture, without setting include_host, hits the --no-host gate: a
    configured executablePath cannot be assessed for writability without stat()-ing it."""
    r = check_browser_executable_path(collect(FIXTURES / "clean_b321_browser_executable_path"))
    assert r.status == UNKNOWN


def test_bad_fixture_warns_on_mcp_command_override():
    """The bad fixture has no executablePath at all -- only an existing-session
    mcpCommand override, which needs no host scan to evaluate."""
    r = check_browser_executable_path(collect(FIXTURES / "bad_b321_browser_executable_path"))
    assert r.status == WARN
    assert any("mcpCommand" in e for e in r.evidence)


# ---------------------------------------------------------------------------
# UNKNOWN baselines
# ---------------------------------------------------------------------------

def test_no_browser_config_is_unknown(tmp_path):
    r = check_browser_executable_path(collect(_home(tmp_path, config={"tools": {"profile": "minimal"}})))
    assert r.status == UNKNOWN


def test_no_config_found_is_unknown(tmp_path):
    r = check_browser_executable_path(collect(_home(tmp_path, config=None)))
    assert r.status == UNKNOWN


def test_browser_configured_with_nothing_to_assess_is_unknown(tmp_path):
    """browser present but neither executablePath nor an existing-session mcpCommand
    override is set anywhere -- nothing for this check to assess."""
    home = _home(tmp_path, config={"browser": {"noSandbox": False, "headless": True}})
    r = check_browser_executable_path(collect(home))
    assert r.status == UNKNOWN


def test_mcp_command_on_non_existing_session_driver_is_ignored(tmp_path):
    """mcpCommand only applies to the existing-session driver per the Zod schema and
    its consumption in normalizeChromeMcpOptions -- a profile using driver:"openclaw"
    setting mcpCommand is not a real signal and must not be flagged."""
    home = _home(tmp_path, config={"browser": {"profiles": {
        "main": {"driver": "openclaw", "mcpCommand": "/opt/not-actually-used", "color": "#FFFFFF"}
    }}})
    r = check_browser_executable_path(collect(home))
    assert r.status == UNKNOWN


def test_mcp_command_equal_to_vendor_default_is_not_flagged(tmp_path):
    """An explicit mcpCommand="npx" is textually identical to the vendor default
    (DEFAULT_CHROME_MCP_COMMAND) -- not a real override, must not WARN."""
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {"driver": "existing-session", "mcpCommand": "npx", "color": "#00AA00"}
    }}})
    r = check_browser_executable_path(collect(home))
    assert r.status == UNKNOWN


# ---------------------------------------------------------------------------
# executablePath configured but not currently present on disk
# ---------------------------------------------------------------------------

def test_nonexistent_executable_path_contributes_nothing(tmp_path):
    home = _home(tmp_path, config={"browser": {"executablePath": str(tmp_path / "does" / "not" / "exist")}})
    ctx = collect(home)
    ctx.include_host = True
    r = check_browser_executable_path(ctx)
    assert r.status == PASS


# ---------------------------------------------------------------------------
# --no-host gate
# ---------------------------------------------------------------------------

def test_executable_path_configured_without_host_scan_is_unknown(tmp_path):
    home = _home(tmp_path, config={"browser": {"executablePath": str(tmp_path / "chrome")}})
    r = check_browser_executable_path(collect(home))  # include_host defaults False
    assert r.status == UNKNOWN
    assert "no-host" in r.detail.lower() or "host" in r.detail.lower()


# ---------------------------------------------------------------------------
# FAIL: writable executablePath (top-level and per-profile)
# ---------------------------------------------------------------------------

def test_world_writable_executable_file_fails(tmp_path):
    exe_dir = tmp_path / "chromedir"
    exe_dir.mkdir()
    exe = exe_dir / "chrome"
    exe.write_text("#!/bin/sh\necho fake\n", encoding="utf-8")
    os.chmod(exe, 0o777)
    home = _home(tmp_path, config={"browser": {"executablePath": str(exe)}})
    ctx = collect(home)
    ctx.include_host = True
    r = check_browser_executable_path(ctx)
    assert r.status == FAIL
    assert any("world-writable" in e for e in r.evidence)
    assert any("browser.executablePath" in e for e in r.evidence)


def test_world_writable_parent_directory_fails(tmp_path):
    """Even a tight-mode binary is not tamper-proof if another account can replace the
    directory entry (rename/symlink) because the containing directory is writable."""
    exe_dir = tmp_path / "chromedir"
    exe_dir.mkdir()
    exe = exe_dir / "chrome"
    exe.write_text("#!/bin/sh\necho fake\n", encoding="utf-8")
    os.chmod(exe, 0o644)
    os.chmod(exe_dir, 0o777)
    home = _home(tmp_path, config={"browser": {"executablePath": str(exe)}})
    ctx = collect(home)
    ctx.include_host = True
    r = check_browser_executable_path(ctx)
    assert r.status == FAIL
    assert any("containing directory" in e for e in r.evidence)


def test_per_profile_executable_path_fails(tmp_path):
    exe_dir = tmp_path / "chromedir"
    exe_dir.mkdir()
    exe = exe_dir / "chrome"
    exe.write_text("x", encoding="utf-8")
    os.chmod(exe, 0o777)
    home = _home(tmp_path, config={"browser": {"profiles": {
        "custom": {"driver": "openclaw", "executablePath": str(exe), "color": "#123456"}
    }}})
    ctx = collect(home)
    ctx.include_host = True
    r = check_browser_executable_path(ctx)
    assert r.status == FAIL
    assert any("browser.profiles.custom.executablePath" in e for e in r.evidence)


def test_tight_executable_path_passes(tmp_path):
    exe_dir = tmp_path / "chromedir"
    exe_dir.mkdir(mode=0o755)
    exe = exe_dir / "chrome"
    exe.write_text("x", encoding="utf-8")
    os.chmod(exe, 0o755)
    home = _home(tmp_path, config={"browser": {"executablePath": str(exe)}})
    ctx = collect(home)
    ctx.include_host = True
    r = check_browser_executable_path(ctx)
    assert r.status == PASS


def test_sticky_world_writable_parent_is_not_flagged(tmp_path):
    """A sticky (mode 1777) world-writable directory is exempt -- the sticky bit blocks
    cross-owner rename/delete, so it is not a replace vector (mirrors C5/B186's own
    documented exemption)."""
    exe_dir = tmp_path / "sticky"
    exe_dir.mkdir()
    exe = exe_dir / "chrome"
    exe.write_text("x", encoding="utf-8")
    os.chmod(exe, 0o755)
    os.chmod(exe_dir, 0o1777)
    home = _home(tmp_path, config={"browser": {"executablePath": str(exe)}})
    ctx = collect(home)
    ctx.include_host = True
    r = check_browser_executable_path(ctx)
    assert r.status == PASS


# ---------------------------------------------------------------------------
# FAIL takes precedence over the mcpCommand WARN
# ---------------------------------------------------------------------------

def test_fail_takes_precedence_over_mcp_command_warn(tmp_path):
    exe_dir = tmp_path / "chromedir"
    exe_dir.mkdir()
    exe = exe_dir / "chrome"
    exe.write_text("x", encoding="utf-8")
    os.chmod(exe, 0o777)
    home = _home(tmp_path, config={"browser": {
        "executablePath": str(exe),
        "profiles": {"user": {"driver": "existing-session", "mcpCommand": "/opt/pinned-mcp", "color": "#00AA00"}},
    }})
    ctx = collect(home)
    ctx.include_host = True
    r = check_browser_executable_path(ctx)
    assert r.status == FAIL
    assert any("world-writable" in e for e in r.evidence)
    assert any("mcpCommand" in e for e in r.evidence)


# ---------------------------------------------------------------------------
# C-135 regression: symlinked executablePath whose TARGET's parent directory
# is writable, while the symlink's own location is tight.
# ---------------------------------------------------------------------------

def test_symlink_to_writable_directory_fails(tmp_path):
    """A configured executablePath that is a symlink hides the real writable
    directory from p.parent, which is purely syntactic and never follows the link.
    p.stat() (used by _dir_replaceable_by_others on the file itself, and by
    p.exists()) DOES follow the symlink, so the file-mode check alone cannot catch a
    tight-mode binary sitting inside a world-writable directory reached only through
    a symlink. Real-world shape: a distro/Nix/asdf-style symlink at a stable, tight
    path pointing into a shared or cache directory that is itself writable by
    another local account -- another account can replace the file the symlink
    resolves to without ever touching the symlink."""
    writable_dir = tmp_path / "shared_writable"
    writable_dir.mkdir()
    real_exe = writable_dir / "chrome-real"
    real_exe.write_text("x", encoding="utf-8")
    os.chmod(real_exe, 0o755)  # the file itself is tight...
    os.chmod(writable_dir, 0o777)  # ...but its real directory is not

    safe_dir = tmp_path / "opt_bin"
    safe_dir.mkdir(mode=0o755)
    symlink_path = safe_dir / "chrome"
    symlink_path.symlink_to(real_exe)

    home = _home(tmp_path, config={"browser": {"executablePath": str(symlink_path)}})
    ctx = collect(home)
    ctx.include_host = True
    r = check_browser_executable_path(ctx)
    assert r.status == FAIL
    assert any("symlink target" in e for e in r.evidence)
    assert any(str(writable_dir) in e for e in r.evidence)


def test_symlink_with_tight_target_directory_still_passes(tmp_path):
    """Sanity check for the fix above: a symlink whose target directory is ALSO
    tight must not be flagged -- the fix adds a check, it must not start flagging
    ordinary symlinked installs (e.g. /usr/bin/google-chrome -> /opt/google/chrome/
    google-chrome, both root-owned in the real world)."""
    real_dir = tmp_path / "opt_google_chrome"
    real_dir.mkdir(mode=0o755)
    real_exe = real_dir / "chrome-real"
    real_exe.write_text("x", encoding="utf-8")
    os.chmod(real_exe, 0o755)

    safe_dir = tmp_path / "usr_bin"
    safe_dir.mkdir(mode=0o755)
    symlink_path = safe_dir / "chrome"
    symlink_path.symlink_to(real_exe)

    home = _home(tmp_path, config={"browser": {"executablePath": str(symlink_path)}})
    ctx = collect(home)
    ctx.include_host = True
    r = check_browser_executable_path(ctx)
    assert r.status == PASS


# ---------------------------------------------------------------------------
# WARN branch is unscored (scored=False override)
# ---------------------------------------------------------------------------

def test_mcp_command_warn_is_unscored(tmp_path):
    home = _home(tmp_path, config={"browser": {"profiles": {
        "user": {"driver": "existing-session", "mcpCommand": "/opt/pinned-mcp", "color": "#00AA00"}
    }}})
    r = check_browser_executable_path(collect(home))
    assert r.status == WARN
    assert r.scored is False
