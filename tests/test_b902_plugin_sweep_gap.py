"""B-902 — `vet_plugin`'s tree sweep (checks/_mcp.py) shares B-899's unguarded
`Path.is_symlink()` crash.

`Path.is_symlink()` needs search (`x`) permission on the entry's PARENT to `lstat()` it.
A plugin subdirectory at mode 0644 (listable via `r`, not searchable) made every
`is_symlink()` call on its own contents raise `PermissionError` straight out of
`vet_plugin()` — uncaught at the `--vet-plugin` CLI entry point (cli.py). Mode 0000
(unlistable too) took a different, quieter path: `os.walk`'s default `onerror=None`
discarded the failure and the sweep silently skipped the whole subtree, so a native-
executable stowaway or embedded MCP spec placed there went unswept without a trace.

Both are now recorded as a gap via the shared B-899 helper (`checks/_shared.py`'s
`note_walk_gap`/`WALK_VANISHED_ERRNOS`) and folded into the same `coverage_gap_finding()`
vehicle `truncated`/`js_capped`/`budget_hit` already use — vet_plugin's existing
partial-scan contract, not a new one. See tests/test_b344_plugin_coverage_gaps.py for
that contract's own tests and tests/test_b87_symlink_escape.py for the sibling B87 guard
this shares its root cause and its shared helper with.

All offline; every fixture is fabricated inside pytest's tmp_path. Symlink/permission
semantics are POSIX-only, so the FS assertions are gated on os.name == "posix", and the
permission-shape tests are skipped under root (CAP_DAC_OVERRIDE bypasses the directory
search-permission check the guard depends on) — same gating as test_b87_symlink_escape.py.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import vet_plugin
from clawseccheck.cli import main

posix_only = pytest.mark.skipif(os.name != "posix", reason="permission bits are POSIX-only")
root_skip = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root bypasses directory search-permission checks",
)

_EMPTY_SCHEMA = {"type": "object", "additionalProperties": False}


def _mk_plugin(root: Path, pid: str = "demo") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "openclaw.plugin.json").write_text(
        json.dumps({"id": pid, "configSchema": _EMPTY_SCHEMA}), encoding="utf-8"
    )
    return root


def _coverage(f):
    return [r for r in f.ring_findings if r.id == "VET-COVERAGE"]


@pytest.fixture
def unlock():
    """Restore a chmod'd directory's mode even when an assertion fails, so a red test
    never leaves an unsearchable/unlistable directory behind for the next one."""
    locked: list = []
    yield locked.append
    for d in locked:
        try:
            d.chmod(0o755)
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# 1. Mode 0644 — listable, not searchable: used to raise PermissionError.      #
# --------------------------------------------------------------------------- #
@posix_only
@root_skip
def test_unsearchable_subdir_0644_does_not_crash(tmp_path, unlock):
    root = _mk_plugin(tmp_path / "plug")
    bad = root / "badsub"
    bad.mkdir()
    (bad / "note.txt").write_text("x", encoding="utf-8")
    bad.chmod(0o644)
    unlock(bad)

    f = vet_plugin(root)  # must not raise

    assert f.status == UNKNOWN
    cov = _coverage(f)
    assert len(cov) == 1, [r.detail for r in f.ring_findings]
    assert cov[0].status == UNKNOWN
    assert cov[0].engine_degraded is True
    assert "coverage is incomplete" in cov[0].detail


@posix_only
@root_skip
def test_unsearchable_subdir_0644_via_cli_renders_a_real_dossier(tmp_path, capsys):
    """cli.py's `--vet-plugin` calls `vet_plugin()` with no try/except at its own call
    site (the reachability the original bug report names) — `main()`'s own outermost
    `except Exception` already keeps a raw traceback off the user's screen, so `rc != 0`
    alone does not discriminate the fix (it fires either way). What only the fix
    produces is an actual risk dossier naming the coverage gap, rather than `main()`'s
    generic "unexpected internal error" crash banner with no dossier at all — the exact
    shape B-899's own tests measured for the sibling `--vet-skill` crash."""
    root = _mk_plugin(tmp_path / "plug")
    bad = root / "badsub"
    bad.mkdir()
    (bad / "note.txt").write_text("x", encoding="utf-8")
    bad.chmod(0o644)
    try:
        rc = main(["--vet-plugin", str(root)])  # must not raise
    finally:
        bad.chmod(0o755)
    out = capsys.readouterr()
    assert rc != 0
    assert "unexpected internal error" not in out.err
    assert "RISK DOSSIER" in out.out
    assert "coverage is incomplete" in out.out


# --------------------------------------------------------------------------- #
# 2. Mode 0000 — unlistable: used to be silently dropped (false-clean PASS).   #
# --------------------------------------------------------------------------- #
@posix_only
@root_skip
def test_unsearchable_subdir_0000_is_unknown_not_a_false_pass(tmp_path, unlock):
    root = _mk_plugin(tmp_path / "plug")
    bad = root / "badsub"
    bad.mkdir()
    (bad / "note.txt").write_text("x", encoding="utf-8")
    bad.chmod(0o000)
    unlock(bad)

    f = vet_plugin(root)

    assert f.status == UNKNOWN
    cov = _coverage(f)
    assert len(cov) == 1, [r.detail for r in f.ring_findings]
    assert cov[0].engine_degraded is True


# --------------------------------------------------------------------------- #
# 3. The gate path is disclosed in `fix`, never in `detail` (fingerprint       #
#    stability — baseline.fingerprint() hashes only `detail`).                #
# --------------------------------------------------------------------------- #
@posix_only
@root_skip
def test_gap_path_is_disclosed_in_fix_not_detail(tmp_path, unlock):
    root = _mk_plugin(tmp_path / "plug")
    bad = root / "badsub"
    bad.mkdir()
    (bad / "note.txt").write_text("x", encoding="utf-8")
    bad.chmod(0o644)
    unlock(bad)

    f = vet_plugin(root)
    cov = _coverage(f)
    assert len(cov) == 1
    assert "badsub" not in cov[0].detail, cov[0].detail
    assert "badsub" in cov[0].fix, cov[0].fix


# --------------------------------------------------------------------------- #
# 4. A vanished subdir mid-walk (ENOENT/ENOTDIR) is not a coverage gap.        #
# --------------------------------------------------------------------------- #
@posix_only
def test_vanished_subdir_during_walk_is_pass_not_a_gap(tmp_path, monkeypatch):
    """A subdirectory that disappears between os.walk listing its parent and descending
    into it (an npm/build temp dir cleaned mid-install, a concurrent re-install) must NOT
    count as a coverage gap: it existed when listed and is gone now, and a directory that
    no longer exists cannot hide a native-executable stowaway or embedded MCP spec.
    Mirrors test_b87_symlink_escape.py's identical control for the sibling B87 guard."""
    root = _mk_plugin(tmp_path / "plug")
    victim = root / "tmp_build"
    victim.mkdir()  # left empty: os.rmdir needs no scandir of its own
    real_scandir = os.scandir

    def flaky_scandir(path="."):
        if isinstance(path, (str, os.PathLike)) and os.fspath(path) == os.fspath(victim):
            os.rmdir(victim)  # gone by the time the walk looks
            raise FileNotFoundError(2, "No such file or directory", str(victim))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", flaky_scandir)

    f = vet_plugin(root)

    assert f.status == PASS, f.detail
    assert _coverage(f) == []


# --------------------------------------------------------------------------- #
# 5. A real WARN elsewhere in the same run still wins outright — one           #
#    unsearchable sibling never masks a confirmed finding.                    #
# --------------------------------------------------------------------------- #
@posix_only
@root_skip
def test_real_stowaway_warn_survives_beside_unsearchable_sibling(tmp_path, unlock):
    root = _mk_plugin(tmp_path / "plug")
    (root / "tool.bin").write_bytes(b"\x7fELF" + b"\x00" * 60)  # native-exe stowaway
    bad = root / "badsub"
    bad.mkdir()
    (bad / "note.txt").write_text("x", encoding="utf-8")
    bad.chmod(0o644)
    unlock(bad)

    f = vet_plugin(root)  # must not raise

    assert f.status == WARN, f.detail
    assert "stowaway" in f.detail
    # The gap is disclosed alongside it, not swallowed by the WARN outranking it.
    assert len(_coverage(f)) == 1


# --------------------------------------------------------------------------- #
# 6. Negative control — a clean, fully-searchable plugin tree is untouched.   #
# --------------------------------------------------------------------------- #
def test_clean_plugin_tree_is_unaffected(tmp_path):
    root = _mk_plugin(tmp_path / "plug")
    (root / "index.js").write_text("export const hello = () => 'hi';\n", encoding="utf-8")
    f = vet_plugin(root)
    assert f.status == PASS, f.detail
    assert _coverage(f) == []
