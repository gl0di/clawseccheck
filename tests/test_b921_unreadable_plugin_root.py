"""B-921 — `_locate_plugin_root`'s own root check crashes on an unreadable plugin root.

`checks/_vet.py`'s `_locate_plugin_root(p)` does `(p / _PLUGIN_MANIFEST).is_file()` to
look for the manifest INSIDE *p*. `Path.is_file()`/`is_dir()` only ignore
ENOENT/ENOTDIR/EBADF/ELOOP internally (see B-680's identical note on `Path.exists()` a
few lines up in the same module) — EACCES is not in that set. Resolving a child of *p*
needs search (`x`) permission on *p* itself, so a plugin ROOT at mode 0000 (or 0644 —
listable, not searchable) made every check inside `_locate_plugin_root` raise
`PermissionError` straight out of the function and both its reachable callers:

  * `checks/_mcp.py`'s `vet_plugin()` — uncaught at its own call site, surfacing to
    `--vet-plugin` users as `main()`'s generic "unexpected internal error" crash banner
    with no dossier at all (the exact shape B-899/B-902 closed for the tree-sweep case,
    one layer further down the same two checks).
  * `checks/_mcp.py`'s `_npm_projects_plugin_ids()` (the wrapper-dir sweep behind B152's
    `check_orphaned_plugin_caches` / `vet_mcp`'s wrapper-dir path) — uncaught inside a
    loop over every `npm/projects/<wrapper>` directory, so ONE unreadable wrapper dir
    aborted visibility into every other plugin cache in the same run.

Confirmed live against the two Python versions this repo's CI actually pins (3.9, 3.12)
before writing the fix: stat-ing *p* itself never raises (mode 0000 on *p* only blocks
searching INTO it — resolving *p* needs search permission on *p*'s PARENT, not on *p*),
but stat-ing a child of *p* does.

The fix guards every `is_file()`/`is_dir()` call inside `_locate_plugin_root` against
`OSError` and never lets it escape. Because `vet_plugin()`'s verdict is scored, it calls
the paired `_locate_plugin_root_or_reason()` instead of the plain wrapper so an
unreadable root — an engine-side "could not tell" — is NOT folded into the same
`engine_degraded=False` bucket as a genuinely-absent manifest (B-399): that would let an
attacker-controlled plugin root made deliberately unreadable score MORE leniently than
one the engine actually got to inspect, exactly the DEGRADED_CHECK_CAP worst-case
treatment this pairing exists to preserve.

All offline; every fixture is fabricated inside pytest's tmp_path. Permission semantics
are POSIX-only, so the FS assertions are gated on os.name == "posix", and the
permission-shape tests are skipped under root (CAP_DAC_OVERRIDE bypasses the directory
search-permission check the guard depends on) — same gating as
tests/test_b87_symlink_escape.py.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from clawseccheck.catalog import HIGH, PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    _locate_plugin_root,
    _locate_plugin_root_or_reason,
    check_orphaned_plugin_caches,
    vet_plugin,
)
from clawseccheck.cli import main
from clawseccheck.collector import Context

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


def _ctx(home: Path, cfg: dict | None = None) -> Context:
    c = Context(home=home)
    c.config = cfg or {}
    return c


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
# 1. `_locate_plugin_root` / `_locate_plugin_root_or_reason` — unit level.     #
# --------------------------------------------------------------------------- #


@posix_only
@root_skip
def test_locate_plugin_root_does_not_raise_on_0000_root(tmp_path, unlock):
    root = _mk_plugin(tmp_path / "plug")
    root.chmod(0o000)
    unlock(root)

    assert _locate_plugin_root(root) is None  # must not raise


@posix_only
@root_skip
def test_locate_plugin_root_or_reason_reports_why_on_0000_root(tmp_path, unlock):
    root = _mk_plugin(tmp_path / "plug")
    root.chmod(0o000)
    unlock(root)

    found, reason = _locate_plugin_root_or_reason(root)
    assert found is None
    assert reason is not None


@posix_only
@root_skip
def test_locate_plugin_root_or_reason_reports_why_on_0644_root(tmp_path, unlock):
    """0644 — listable via `r`, not searchable — is the other permission shape the
    report and its siblings (B-899/B-902) both cover; not just 0000."""
    root = _mk_plugin(tmp_path / "plug")
    root.chmod(0o644)
    unlock(root)

    found, reason = _locate_plugin_root_or_reason(root)
    assert found is None
    assert reason is not None


def test_locate_plugin_root_or_reason_no_reason_when_genuinely_absent(tmp_path):
    """Control: a readable, ordinary directory with no manifest resolves cleanly to
    (None, None) -- the reason must be None precisely when nothing prevented the look."""
    empty = tmp_path / "not-a-plugin"
    empty.mkdir()
    found, reason = _locate_plugin_root_or_reason(empty)
    assert found is None
    assert reason is None


# --------------------------------------------------------------------------- #
# 2. `vet_plugin()` on an unreadable root — must not crash, must be UNKNOWN,   #
#    and must be `engine_degraded` (not the weaker "genuinely absent" shape). #
# --------------------------------------------------------------------------- #


@posix_only
@root_skip
def test_unreadable_root_0000_does_not_crash_and_is_engine_degraded_unknown(tmp_path, unlock):
    root = _mk_plugin(tmp_path / "plug")
    root.chmod(0o000)
    unlock(root)

    f = vet_plugin(root)  # must not raise

    assert f.status == UNKNOWN
    assert f.severity == HIGH
    assert f.engine_degraded is True


@posix_only
@root_skip
def test_unreadable_root_0644_does_not_crash_and_is_engine_degraded_unknown(tmp_path, unlock):
    root = _mk_plugin(tmp_path / "plug")
    root.chmod(0o644)
    unlock(root)

    f = vet_plugin(root)  # must not raise

    assert f.status == UNKNOWN
    assert f.severity == HIGH
    assert f.engine_degraded is True


@posix_only
@root_skip
def test_unreadable_root_via_cli_renders_a_dossier_not_a_crash_banner(tmp_path, capsys):
    """cli.py's `--vet-plugin` calls `vet_plugin()` with no try/except at its own call
    site. Before the fix this reached `main()`'s outermost `except Exception`, which
    prints the generic "unexpected internal error ... open an issue" banner and leaves
    stdout empty -- no dossier, no JSON, nothing a downstream consumer (human or SARIF/
    JSON parser) can read at all.

    rc == 0 here, NOT != 0: `vet_plugin()`'s early-return UNKNOWNs (this one and its two
    pre-existing siblings, "no plugin found at {p}" / "not an OpenClaw plugin: no
    manifest found") carry no ring_findings/axis_reasons, so build_profile() drops the
    bare PLUGIN-VET container from every axis bucket (dossier.py's `_normalize_pool`
    docstring: "the container id itself maps to None and is dropped from axes") --
    `_danger_coverage_gap` never sees this finding's `engine_degraded` flag, so
    `overall_status` stays UNKNOWN rather than the WARN B-092 would floor a
    ring-findings-bearing engine-degraded UNKNOWN to (the B-902 tree-sweep shape).
    cli.py's own documented mapping then reads "UNKNOWN + target exists" as rc=0 --
    "valid target, inconclusive assessment". This is IDENTICAL to what the sibling
    "not an OpenClaw plugin" branch already returns for a readable-but-manifest-less
    directory (verified directly against `vet_plugin()` on this branch before writing
    this test) -- this fix does not introduce a new, more lenient rc for this shape; it
    replaces a crash (no output at all) with the SAME rc the nearest existing precedent
    already produces, plus an honest CAUTION dossier and a properly `engine_degraded`
    Finding (verified in the raw JSON: `--json` renders `"verdict": "CAUTION"`,
    `"engine_degraded": true`) where there used to be nothing. Whether early-return
    PLUGIN-VET containers SHOULD also feed the axis-bucket mechanism (so
    engine_degraded escalates rc for this whole family of early exits, not just the
    sub-finding-bearing ones) is a pre-existing question this fix does not attempt to
    resolve — see the task's final report for the flagged follow-up."""
    root = _mk_plugin(tmp_path / "plug")
    root.chmod(0o000)
    try:
        rc = main(["--vet-plugin", str(root)])  # must not raise
    finally:
        root.chmod(0o755)
    out = capsys.readouterr()
    assert rc == 0
    assert "unexpected internal error" not in out.err
    assert "RISK DOSSIER" in out.out
    assert "CAUTION" in out.out


@posix_only
@root_skip
def test_unreadable_root_via_cli_json_discloses_engine_degraded_and_reason(tmp_path, capsys):
    """The plain-text dossier's per-axis summary uses generic axis-template wording
    ("not measurable"), not the Finding's own `detail` -- the raw JSON output is where
    `engine_degraded` and the actual reason are actually asserted."""
    import json as _json

    root = _mk_plugin(tmp_path / "plug")
    root.chmod(0o000)
    try:
        rc = main(["--vet-plugin", str(root), "--json"])  # must not raise
    finally:
        root.chmod(0o755)

    out = capsys.readouterr()
    assert rc == 0
    payload = _json.loads(out.out)
    assert payload["verdict"] == "CAUTION"
    findings = payload["findings"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["id"] == "PLUGIN-VET"
    assert finding["status"] == "UNKNOWN"
    assert finding["engine_degraded"] is True
    assert "could not determine" in finding["detail"]
    assert str(root) not in finding["detail"]
    assert str(root) in finding["fix"]


@posix_only
@root_skip
def test_reason_disclosed_in_fix_not_detail(tmp_path, unlock):
    """`baseline.fingerprint()` hashes only `detail` -- a host-specific path folded
    into it would give every affected machine its own fingerprint and orphan any
    `.clawseccheckignore` entry already written against this UNKNOWN (B-899's identical
    rule). The plugin root path itself goes only in `fix`."""
    root = _mk_plugin(tmp_path / "plug")
    root.chmod(0o000)
    unlock(root)

    f = vet_plugin(root)
    assert str(root) not in f.detail, f.detail
    assert str(root) in f.fix, f.fix


# --------------------------------------------------------------------------- #
# 3. The C-135 question: an unreadable root must not score MORE leniently      #
#    than a genuinely-absent manifest -- engine_degraded distinguishes them.   #
# --------------------------------------------------------------------------- #


def test_genuinely_absent_manifest_is_not_engine_degraded(tmp_path):
    """Control for the adversarial question this bug's own note raises: a plain,
    fully-readable directory with no manifest at all is a confident "not a plugin" --
    engine_degraded stays False (B-399's weaker "nothing was ever there to examine"
    bucket), never True. Without this control, a fix that always sets
    engine_degraded=True on any None-root would pass every test above for the wrong
    reason and silently escalate every ordinary non-plugin target too."""
    not_a_plugin = tmp_path / "just-a-folder"
    not_a_plugin.mkdir()

    f = vet_plugin(not_a_plugin)

    assert f.status == UNKNOWN
    assert f.engine_degraded is False


@posix_only
@root_skip
def test_unreadable_root_is_engine_degraded_unlike_the_absent_control(tmp_path, unlock):
    """The two UNKNOWNs read identically at a glance ("not resolvable") but must not
    carry the same weight: an unreadable root is the worst-case "cannot rule out a
    CRITICAL" shape (DEGRADED_CHECK_CAP), a genuinely absent manifest is not."""
    root = _mk_plugin(tmp_path / "plug")
    root.chmod(0o000)
    unlock(root)

    f = vet_plugin(root)
    assert f.status == UNKNOWN
    assert f.engine_degraded is True


# --------------------------------------------------------------------------- #
# 4. Second reachable caller — the npm wrapper-dir sweep behind B152 / the     #
#    vet_mcp wrapper-dir path must not crash either.                          #
# --------------------------------------------------------------------------- #


@posix_only
@root_skip
def test_npm_wrapper_dir_unreadable_does_not_crash_orphaned_cache_check(tmp_path, unlock):
    home = tmp_path / ".openclaw"
    wrapper = home / "npm" / "projects" / "openclaw-demo-plugin-abc123"
    _mk_plugin(wrapper, pid="demo")
    wrapper.chmod(0o000)
    unlock(wrapper)

    f = check_orphaned_plugin_caches(_ctx(home, {"plugins": {"entries": {}}}))  # must not raise

    # Unresolvable id -> falls back to the wrapper dir's own name (already this call
    # site's established behavior for a genuinely-missing manifest, F-061 spirit: the
    # on-disk presence is still surfaced, never silently dropped by the crash it used
    # to be). Not declared -> WARN, same as any other orphaned cache.
    assert f.status == WARN
    assert any(wrapper.name in e for e in f.evidence)


# --------------------------------------------------------------------------- #
# 5. Negative control — a clean, fully-readable plugin root is unaffected.    #
# --------------------------------------------------------------------------- #


def test_normal_readable_plugin_root_still_resolves_and_scans(tmp_path):
    root = _mk_plugin(tmp_path / "plug")
    (root / "index.js").write_text("export const hello = () => 'hi';\n", encoding="utf-8")

    assert _locate_plugin_root(root) == root
    assert _locate_plugin_root_or_reason(root) == (root, None)

    f = vet_plugin(root)
    assert f.status == PASS, f.detail
