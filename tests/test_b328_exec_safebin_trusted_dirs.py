"""B328 (E-060): tools.exec.safeBinTrustedDirs writable-dir promotion.

See the comment block above check_exec_safe_bin_trusted_dirs in
clawseccheck/checks/_lifecycle.py for the full grounding and severity-model discussion.
Global-only scoping (mirrors B55/B43/B48's tools.elevated.allowFrom precedent) -- the
per-agent agents.list.<id>.tools.exec.safeBinTrustedDirs variant is a known, accepted,
inherited coverage gap, not exercised here.

Severity shape:
  - no openclaw.json at all                                        -> UNKNOWN
  - openclaw.json present but unparseable                          -> UNKNOWN
  - safeBinTrustedDirs absent/empty                                 -> PASS
  - configured, but host scanning disabled (--no-host)              -> UNKNOWN
  - configured, but non-POSIX platform                              -> UNKNOWN
  - configured, an entry is group/world-writable by another account -> FAIL
  - configured, an entry is the SAME filesystem object as one of the three
    well-known sticky world-writable system temp roots (/tmp, /var/tmp,
    /private/tmp) -- by any path spelling or symlink, not just the literal
    string -> FAIL
  - configured, entries verified and none writable                  -> PASS
  - a relative entry cannot be verified -> disclosed, never silently assumed safe
  - a would-be-FAIL directory, but the global tools.exec.safeBins is explicitly
    an empty list (the fast path is provably inert, modulo a per-agent
    override this check does not read)                              -> WARN

C-135 adversarial review (2026-07-25) found and fixed two real bugs in the
originally-landed check, both regression-tested below:
  - the bypass-root rule compared the configured path STRING against the three
    known root strings, which a symlink, '//tmp', or '/tmp/../tmp' all evaded
    while resolving to the exact same real /tmp (false negative);
  - a writable directory FAILed even when the global tools.exec.safeBins was
    explicitly emptied, which provably disables the fast path this directory
    would otherwise feed (false positive; now WARN instead of FAIL).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import _shared
from clawseccheck.checks._lifecycle import check_exec_safe_bin_trusted_dirs
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _home(tmp_path: Path, config: dict | None = None) -> Path:
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    if config is not None:
        (home / "openclaw.json").write_text(json.dumps(config), encoding="utf-8")
    return home


def _ctx(tmp_path: Path, config: dict | None, *, include_host: bool = True):
    ctx = collect(_home(tmp_path, config))
    ctx.include_host = include_host
    return ctx


# ---------------------------------------------------------------------------
# On-disk fixtures
# ---------------------------------------------------------------------------

def test_clean_fixture_passes():
    ctx = collect(FIXTURES / "clean_b328_exec_safebin_trusted_dirs")
    ctx.include_host = True
    r = check_exec_safe_bin_trusted_dirs(ctx)
    assert r.status == PASS


def test_bad_fixture_fails():
    """The checked-in bad fixture points safeBinTrustedDirs at the real /tmp -- always
    a sticky, world-writable directory on any POSIX dev/CI box, so this is
    deterministic without needing to chmod a git-checked-in directory."""
    ctx = collect(FIXTURES / "bad_b328_exec_safebin_trusted_dirs")
    ctx.include_host = True
    r = check_exec_safe_bin_trusted_dirs(ctx)
    assert r.status == FAIL
    assert any("/tmp" in e for e in r.evidence)


# ---------------------------------------------------------------------------
# UNKNOWN baselines
# ---------------------------------------------------------------------------

def test_no_config_file_is_unknown(tmp_path):
    r = check_exec_safe_bin_trusted_dirs(_ctx(tmp_path, None))
    assert r.status == UNKNOWN


def test_unparseable_config_is_unknown():
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.config_found = True
    c.config_parse_error = True
    c.include_host = True
    r = check_exec_safe_bin_trusted_dirs(c)
    assert r.status == UNKNOWN


# ---------------------------------------------------------------------------
# PASS: absent / empty (no host stat needed at all)
# ---------------------------------------------------------------------------

def test_safebin_trusted_dirs_absent_is_pass(tmp_path):
    r = check_exec_safe_bin_trusted_dirs(_ctx(tmp_path, {"tools": {"profile": "minimal"}}))
    assert r.status == PASS


def test_safebin_trusted_dirs_empty_list_is_pass(tmp_path):
    cfg = {"tools": {"exec": {"safeBinTrustedDirs": []}}}
    r = check_exec_safe_bin_trusted_dirs(_ctx(tmp_path, cfg))
    assert r.status == PASS


def test_absent_is_pass_even_with_no_host_scan(tmp_path):
    """The absent/empty PASS branch never touches the filesystem, so it must not be
    gated by include_host at all."""
    cfg = {"tools": {"profile": "minimal"}}
    r = check_exec_safe_bin_trusted_dirs(_ctx(tmp_path, cfg, include_host=False))
    assert r.status == PASS


# ---------------------------------------------------------------------------
# UNKNOWN: configured but cannot be verified
# ---------------------------------------------------------------------------

def test_configured_with_no_host_scan_is_unknown(tmp_path):
    target = tmp_path / "trusted-bin"
    target.mkdir()
    cfg = {"tools": {"exec": {"safeBinTrustedDirs": [str(target)]}}}
    r = check_exec_safe_bin_trusted_dirs(_ctx(tmp_path, cfg, include_host=False))
    assert r.status == UNKNOWN


def test_configured_on_non_posix_is_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr(_shared, "_is_posix", lambda: False)
    cfg = {"tools": {"exec": {"safeBinTrustedDirs": ["/opt/custom/bin"]}}}
    r = check_exec_safe_bin_trusted_dirs(_ctx(tmp_path, cfg, include_host=True))
    assert r.status == UNKNOWN


# ---------------------------------------------------------------------------
# PASS: verified, tight
# ---------------------------------------------------------------------------

def test_tight_directory_passes(tmp_path):
    target = tmp_path / "trusted-bin"
    target.mkdir()
    os.chmod(target, 0o755)
    cfg = {"tools": {"exec": {"safeBinTrustedDirs": [str(target)]}}}
    r = check_exec_safe_bin_trusted_dirs(_ctx(tmp_path, cfg, include_host=True))
    assert r.status == PASS


def test_nonexistent_directory_silently_passes(tmp_path):
    """Matches B186's own documented convention: a configured-but-nonexistent
    directory is not a finding."""
    missing = tmp_path / "does-not-exist"
    cfg = {"tools": {"exec": {"safeBinTrustedDirs": [str(missing)]}}}
    r = check_exec_safe_bin_trusted_dirs(_ctx(tmp_path, cfg, include_host=True))
    assert r.status == PASS


def test_private_group_writable_directory_is_not_flagged(tmp_path, monkeypatch):
    """Adversarial edge case: a user-private group (no other members) writable dir
    must not FAIL -- mirrors _dir_replaceable_by_others' own documented rule."""
    target = tmp_path / "trusted-bin"
    target.mkdir()
    os.chmod(target, 0o770)
    monkeypatch.setattr(_shared, "_group_has_other_members", lambda gid, uid: False)
    cfg = {"tools": {"exec": {"safeBinTrustedDirs": [str(target)]}}}
    r = check_exec_safe_bin_trusted_dirs(_ctx(tmp_path, cfg, include_host=True))
    assert r.status == PASS


def test_sticky_private_subdirectory_under_tmp_is_not_flagged(tmp_path):
    """Adversarial edge case, deliberately NOT escalated: an arbitrarily-deep,
    owner-only (0700) subdirectory under /tmp is as private as one under $HOME, and is
    NOT one of the three literal well-known roots -- must stay PASS (mirrors B186's own
    retracted "/tmp-rooted" heuristic discussion)."""
    import tempfile
    real_tmp = Path(tempfile.gettempdir())
    private = real_tmp / f"clawseccheck-b328-test-{os.getpid()}"
    private.mkdir(exist_ok=True)
    try:
        os.chmod(private, 0o700)
        cfg = {"tools": {"exec": {"safeBinTrustedDirs": [str(private)]}}}
        r = check_exec_safe_bin_trusted_dirs(_ctx(tmp_path, cfg, include_host=True))
        assert r.status == PASS
    finally:
        private.rmdir()


# ---------------------------------------------------------------------------
# FAIL: verified, writable
# ---------------------------------------------------------------------------

def test_world_writable_directory_fails(tmp_path):
    target = tmp_path / "writable-bin"
    target.mkdir()
    os.chmod(target, 0o777)
    cfg = {"tools": {"exec": {"safeBinTrustedDirs": [str(target)]}}}
    r = check_exec_safe_bin_trusted_dirs(_ctx(tmp_path, cfg, include_host=True))
    assert r.status == FAIL
    assert any("world-writable" in e for e in r.evidence)


def test_group_writable_with_other_members_fails(tmp_path, monkeypatch):
    target = tmp_path / "group-writable-bin"
    target.mkdir()
    os.chmod(target, 0o770)
    monkeypatch.setattr(_shared, "_group_has_other_members", lambda gid, uid: True)
    cfg = {"tools": {"exec": {"safeBinTrustedDirs": [str(target)]}}}
    r = check_exec_safe_bin_trusted_dirs(_ctx(tmp_path, cfg, include_host=True))
    assert r.status == FAIL


def test_var_tmp_root_fails(tmp_path):
    """The narrow creation-only-bypass rule also matches /var/tmp (the sticky bit
    exempts it from _dir_replaceable_by_others, but a fresh, unclaimed safeBins
    basename can still be planted there)."""
    if not Path("/var/tmp").is_dir():
        import pytest
        pytest.skip("/var/tmp not present on this host")
    cfg = {"tools": {"exec": {"safeBinTrustedDirs": ["/var/tmp"]}}}
    r = check_exec_safe_bin_trusted_dirs(_ctx(tmp_path, cfg, include_host=True))
    assert r.status == FAIL


def test_multiple_dirs_mixed_only_bad_reported(tmp_path):
    tight = tmp_path / "tight-bin"
    tight.mkdir()
    os.chmod(tight, 0o755)
    writable = tmp_path / "writable-bin"
    writable.mkdir()
    os.chmod(writable, 0o777)
    cfg = {"tools": {"exec": {"safeBinTrustedDirs": [str(tight), str(writable)]}}}
    r = check_exec_safe_bin_trusted_dirs(_ctx(tmp_path, cfg, include_host=True))
    assert r.status == FAIL
    assert any(str(writable) in e for e in r.evidence)
    assert not any(str(tight) in e for e in r.evidence)


# ---------------------------------------------------------------------------
# Relative-path handling: disclosed, never counted either way
# ---------------------------------------------------------------------------

def test_relative_path_is_not_verified_but_disclosed(tmp_path):
    cfg = {"tools": {"exec": {"safeBinTrustedDirs": ["relative/bin"]}}}
    r = check_exec_safe_bin_trusted_dirs(_ctx(tmp_path, cfg, include_host=True))
    assert r.status == PASS
    assert r.pass_confidence == "no_signal"
    assert any("relative/bin" in e for e in r.evidence)


def test_relative_path_alongside_confirmed_writable_dir_still_fails(tmp_path):
    """A relative entry must never mask a real FAIL from a sibling absolute entry."""
    writable = tmp_path / "writable-bin"
    writable.mkdir()
    os.chmod(writable, 0o777)
    cfg = {"tools": {"exec": {"safeBinTrustedDirs": ["relative/bin", str(writable)]}}}
    r = check_exec_safe_bin_trusted_dirs(_ctx(tmp_path, cfg, include_host=True))
    assert r.status == FAIL


# ---------------------------------------------------------------------------
# C-135 regression: _b328_creation_only_bypass_root must compare by filesystem
# IDENTITY, not by literal path string -- the first cut compared strings and was
# trivially evadable by any alias that resolves to the same real /tmp.
# ---------------------------------------------------------------------------

def test_double_slash_tmp_alias_fails(tmp_path):
    """'//tmp' is a distinct Python/pathlib string from '/tmp' (POSIX leaves exactly-
    two-leading-slashes implementation defined), but Linux/macOS both resolve it to the
    SAME real /tmp inode. A naive string-equality bypass-root check missed this and
    silently PASSED; found during C-135 adversarial review."""
    cfg = {"tools": {"exec": {"safeBinTrustedDirs": ["//tmp"]}}}
    r = check_exec_safe_bin_trusted_dirs(_ctx(tmp_path, cfg, include_host=True))
    assert r.status == FAIL
    assert any("//tmp" in e for e in r.evidence)


def test_dotdot_alias_tmp_fails(tmp_path):
    """'/tmp/../tmp' is a distinct, unnormalized string that stat()-resolves to the
    same real /tmp inode. Found during C-135 adversarial review alongside the
    double-slash case."""
    cfg = {"tools": {"exec": {"safeBinTrustedDirs": ["/tmp/../tmp"]}}}
    r = check_exec_safe_bin_trusted_dirs(_ctx(tmp_path, cfg, include_host=True))
    assert r.status == FAIL


def test_symlink_to_real_tmp_fails(tmp_path):
    """A symlink anywhere pointing AT the real /tmp reproduces the exact same
    plant-an-unclaimed-safeBin exploit as naming /tmp directly -- OpenClaw's own
    normalizeTrustedDir() resolves a configured entry with path.resolve() (lexical
    only, no symlink follow) and trusts binaries found under that literal directory
    string, so the operator-configured symlink path itself is what gets trusted.
    A naive string-equality bypass-root check missed this and silently PASSED;
    found during C-135 adversarial review."""
    link = tmp_path / "mytmp"
    os.symlink("/tmp", link)
    cfg = {"tools": {"exec": {"safeBinTrustedDirs": [str(link)]}}}
    r = check_exec_safe_bin_trusted_dirs(_ctx(tmp_path, cfg, include_host=True))
    assert r.status == FAIL
    assert any(str(link) in e for e in r.evidence)


# ---------------------------------------------------------------------------
# C-135 regression: explicitly-emptied global tools.exec.safeBins disables the
# ENTIRE safe-bin fast path (isSafeBinUsage short-circuits on safeBins.size===0
# before ever consulting trustedSafeBinDirs), so a writable directory is currently
# INERT -- a hard FAIL was a false positive on that config. Downgraded to WARN
# rather than silenced, because a per-agent safeBins override (not read by this
# check) can independently re-enable the fast path for that one agent.
# ---------------------------------------------------------------------------

def test_safebins_globally_emptied_downgrades_writable_dir_to_warn(tmp_path):
    target = tmp_path / "writable-bin"
    target.mkdir()
    os.chmod(target, 0o777)
    cfg = {"tools": {"exec": {"safeBins": [], "safeBinTrustedDirs": [str(target)]}}}
    r = check_exec_safe_bin_trusted_dirs(_ctx(tmp_path, cfg, include_host=True))
    assert r.status == WARN
    assert any(str(target) in e for e in r.evidence)


def test_safebins_globally_emptied_bypass_root_also_downgrades_to_warn(tmp_path):
    """The safeBins=[] mitigation must also apply to the bypass-root branch (a
    literal /tmp entry), not just the plain writable-directory branch."""
    cfg = {"tools": {"exec": {"safeBins": [], "safeBinTrustedDirs": ["/tmp"]}}}
    r = check_exec_safe_bin_trusted_dirs(_ctx(tmp_path, cfg, include_host=True))
    assert r.status == WARN


def test_safebins_non_empty_still_fails(tmp_path):
    """Adversarial edge case: safeBins configured but NON-empty must NOT trigger the
    mitigation -- only an explicitly empty list disables the fast path."""
    target = tmp_path / "writable-bin"
    target.mkdir()
    os.chmod(target, 0o777)
    cfg = {
        "tools": {
            "exec": {"safeBins": ["cat"], "safeBinTrustedDirs": [str(target)]}
        }
    }
    r = check_exec_safe_bin_trusted_dirs(_ctx(tmp_path, cfg, include_host=True))
    assert r.status == FAIL


def test_safebins_absent_still_fails(tmp_path):
    """Adversarial edge case: safeBins simply not configured (vendor default list
    applies, non-empty) must NOT trigger the mitigation -- only an explicit empty
    list does."""
    target = tmp_path / "writable-bin"
    target.mkdir()
    os.chmod(target, 0o777)
    cfg = {"tools": {"exec": {"safeBinTrustedDirs": [str(target)]}}}
    r = check_exec_safe_bin_trusted_dirs(_ctx(tmp_path, cfg, include_host=True))
    assert r.status == FAIL
