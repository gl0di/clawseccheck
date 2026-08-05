"""F-167 / B349: install-lifecycle hooks in the installed npm dependency tree.

Covers the `deptree` leaf (root discovery, bounded walk, hook-target resolution) and the
`check_dependency_tree_hooks` verdict it feeds. Offline, read-only, stdlib only.

The verdict model under test is deliberately three-way, and the UNKNOWN third is the part
worth guarding: a hook target we could not read is never a PASS. See the check's own
docstring for why FAIL is scoped to the already-validated detectors rather than a bespoke
"looks obfuscated" heuristic.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck import deptree
from clawseccheck.catalog import BY_ID, FAIL, PASS, UNKNOWN
from clawseccheck.checks import check_dependency_tree_hooks

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

CLEAN = FIXTURES / "deptree_clean_pkg"
BAD = FIXTURES / "deptree_bad_pkg"
UNREADABLE = FIXTURES / "deptree_unreadable_pkg"


class _Ctx:
    """Minimal stand-in. The check reads `ctx.dep_tree` and nothing else — the walk is
    audit()'s job, not the check's, so tests do the same one-line scan audit() does."""

    def __init__(self, root, *, scan=True):
        self.openclaw_pkg_root = Path(root) if root is not None else None
        if not scan or root is None:
            self.dep_tree = None
        else:
            self.dep_tree = deptree.scan_dep_tree(deptree.find_dep_tree(Path(root)))


def _pkg(root: Path, name: str, scripts=None, files=None) -> Path:
    d = root / "node_modules" / name
    d.mkdir(parents=True, exist_ok=True)
    manifest = {"name": name, "version": "1.0.0"}
    if scripts:
        manifest["scripts"] = scripts
    (d / "package.json").write_text(json.dumps(manifest) + "\n")
    for rel, body in (files or {}).items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return d


# ---------------------------------------------------------------------------
# catalog registration
# ---------------------------------------------------------------------------

def test_b349_is_catalogued_and_scored():
    meta = BY_ID["B349"]
    assert meta.severity == "CRITICAL"
    assert meta.scored is True
    assert meta.surface == "skills"


# ---------------------------------------------------------------------------
# find_package_root — the soundness gate is the name check
# ---------------------------------------------------------------------------

def test_find_package_root_accepts_a_package_that_names_itself(tmp_path):
    root = tmp_path / "lib" / "node_modules" / "openclaw"
    root.mkdir(parents=True)
    (root / "package.json").write_text(json.dumps({"name": "openclaw"}))
    (root / "openclaw.mjs").write_text("// entry\n")
    found = deptree.find_package_root("openclaw", which=lambda _n: str(root / "openclaw.mjs"))
    assert found == root


def test_find_package_root_walks_up_from_a_nested_bin(tmp_path):
    """The real clawhub layout resolves to `<root>/bin/clawdhub.js`, two levels down."""
    root = tmp_path / "clawhub"
    (root / "bin").mkdir(parents=True)
    (root / "package.json").write_text(json.dumps({"name": "clawhub"}))
    (root / "bin" / "clawdhub.js").write_text("// entry\n")
    found = deptree.find_package_root("clawhub", which=lambda _n: str(root / "bin" / "clawdhub.js"))
    assert found == root


def test_find_package_root_refuses_a_package_that_names_itself_differently(tmp_path):
    """A shadowed/renamed binary must never redirect the scan onto an unrelated tree —
    without this the check would report on some other package as though it were OpenClaw."""
    root = tmp_path / "not-openclaw"
    root.mkdir()
    (root / "package.json").write_text(json.dumps({"name": "something-else"}))
    (root / "entry.js").write_text("// entry\n")
    assert deptree.find_package_root("openclaw", which=lambda _n: str(root / "entry.js")) is None


def test_find_package_root_returns_none_when_nothing_is_on_path():
    assert deptree.find_package_root("openclaw", which=lambda _n: None) is None


# ---------------------------------------------------------------------------
# resolve_hook_targets — the false-positive-critical part
# ---------------------------------------------------------------------------

def test_resolve_hook_targets_resolves_an_explicit_node_invocation(tmp_path):
    pkg = _pkg(tmp_path, "p", files={"setup.mjs": "console.log(1)\n"})
    assert [p.name for p in deptree.resolve_hook_targets("node setup.mjs", pkg)] == ["setup.mjs"]


def test_resolve_hook_targets_appends_node_extensions(tmp_path):
    """`node scripts/postinstall` runs `scripts/postinstall.js` — the real protobufjs shape."""
    pkg = _pkg(tmp_path, "p", files={"scripts/postinstall.js": "console.log(1)\n"})
    got = deptree.resolve_hook_targets("node scripts/postinstall", pkg)
    assert [p.name for p in got] == ["postinstall.js"]


def test_resolve_hook_targets_ignores_a_bin_from_another_package(tmp_path):
    """`node-gyp-build` is a real, benign hook whose basename is not `node`. Measured on a
    live tree: this is the COMMON case, and it must yield no target rather than a guess."""
    pkg = _pkg(tmp_path, "p")
    assert deptree.resolve_hook_targets("node-gyp-build", pkg) == ()


def test_resolve_hook_targets_ignores_a_shell_builtin(tmp_path):
    pkg = _pkg(tmp_path, "p")
    assert deptree.resolve_hook_targets("echo 'preinstall: no-op'", pkg) == ()


def test_resolve_hook_targets_handles_a_chained_command(tmp_path):
    pkg = _pkg(tmp_path, "p", files={"b.js": "console.log(1)\n"})
    got = deptree.resolve_hook_targets("node missing.js && node b.js", pkg)
    assert [p.name for p in got] == ["b.js"]


def test_resolve_hook_targets_skips_node_flags(tmp_path):
    pkg = _pkg(tmp_path, "p", files={"s.js": "console.log(1)\n"})
    got = deptree.resolve_hook_targets("node --enable-source-maps s.js", pkg)
    assert [p.name for p in got] == ["s.js"]


def test_resolve_hook_targets_refuses_to_escape_the_package(tmp_path):
    """A `../..` target must never let a finding be attributed to the wrong package."""
    pkg = _pkg(tmp_path, "p")
    (tmp_path / "outside.js").write_text("console.log(1)\n")
    assert deptree.resolve_hook_targets("node ../../outside.js", pkg) == ()


def test_resolve_hook_targets_refuses_a_symlinked_target(tmp_path):
    pkg = _pkg(tmp_path, "p")
    real = tmp_path / "real.js"
    real.write_text("console.log(1)\n")
    try:
        (pkg / "link.js").symlink_to(real)
    except (OSError, NotImplementedError):  # pragma: no cover — platform without symlinks
        return
    assert deptree.resolve_hook_targets("node link.js", pkg) == ()


def test_resolve_hook_targets_survives_unbalanced_quotes(tmp_path):
    pkg = _pkg(tmp_path, "p")
    assert deptree.resolve_hook_targets("node 'unclosed", pkg) == ()


# ---------------------------------------------------------------------------
# scan_dep_tree
# ---------------------------------------------------------------------------

def test_scan_dep_tree_collects_every_install_phase(tmp_path):
    _pkg(tmp_path, "a", {"preinstall": "node x.js"}, {"x.js": "1\n"})
    _pkg(tmp_path, "b", {"install": "node y.js"}, {"y.js": "1\n"})
    _pkg(tmp_path, "c", {"postinstall": "node z.js"}, {"z.js": "1\n"})
    scan = deptree.scan_dep_tree(deptree.find_dep_tree(tmp_path))
    assert scan.packages == 3
    assert sorted(h.phase for h in scan.hooks) == ["install", "postinstall", "preinstall"]


def test_scan_dep_tree_ignores_non_install_phases(tmp_path):
    """`prepare`/`prepublish` run for a package being developed, not consumed."""
    _pkg(tmp_path, "a", {"prepare": "node x.js", "test": "node t.js"}, {"x.js": "1\n"})
    scan = deptree.scan_dep_tree(deptree.find_dep_tree(tmp_path))
    assert scan.hooks == ()


def test_scan_dep_tree_reports_truncation_when_the_budget_is_hit(tmp_path):
    for i in range(6):
        _pkg(tmp_path, f"p{i}")
    scan = deptree.scan_dep_tree(deptree.find_dep_tree(tmp_path), max_packages=3)
    assert scan.truncated is True


def test_scan_dep_tree_absent_tree_is_not_a_scanned_tree(tmp_path):
    scan = deptree.scan_dep_tree(deptree.find_dep_tree(tmp_path))
    assert scan.scanned is False and scan.packages == 0


def test_find_dep_tree_refuses_a_symlinked_node_modules(tmp_path):
    real = tmp_path / "elsewhere"
    real.mkdir()
    root = tmp_path / "pkg"
    root.mkdir()
    try:
        (root / "node_modules").symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):  # pragma: no cover
        return
    assert deptree.find_dep_tree(root) is None


def test_scan_dep_tree_counts_an_unparseable_manifest_without_crashing(tmp_path):
    d = tmp_path / "node_modules" / "broken"
    d.mkdir(parents=True)
    (d / "package.json").write_text("{not json")
    scan = deptree.scan_dep_tree(deptree.find_dep_tree(tmp_path))
    assert scan.unreadable == 1 and scan.packages == 0


# ---------------------------------------------------------------------------
# the check — all four verdict paths, driven through the real function
# ---------------------------------------------------------------------------

def test_clean_fixture_passes():
    f = check_dependency_tree_hooks(_Ctx(CLEAN))
    assert f.status == PASS
    assert f.id == "B349"


def test_clean_fixture_discloses_what_it_could_not_assess():
    """Two of the three clean hooks have no in-package target. A PASS that did not say so
    would be claiming coverage over hooks whose bytes were never read."""
    f = check_dependency_tree_hooks(_Ctx(CLEAN))
    joined = "\n".join(f.evidence or [])
    assert "coverage:" in joined
    # 2 = plain-hook-pkg's lifecycle target + native-addon-pkg's build-config target.
    # The other two hooks resolve to nothing, and so does the honest inline expansion.
    assert "targets read: 2" in joined


def test_bad_fixture_fails_and_names_the_package_and_rule():
    f = check_dependency_tree_hooks(_Ctx(BAD))
    assert f.status == FAIL
    joined = "\n".join(f.evidence or [])
    assert "compromised-pkg" in joined
    assert "JS_EVAL_DECODED" in joined


def test_unreadable_target_is_unknown_never_pass():
    """The load-bearing third verdict: a minified installer is not a clean one."""
    f = check_dependency_tree_hooks(_Ctx(UNREADABLE))
    assert f.status == UNKNOWN
    joined = "\n".join(f.evidence or [])
    assert "minified-installer-pkg" in joined


def test_missing_tree_is_unknown_not_pass(tmp_path):
    root = tmp_path / "openclaw"
    root.mkdir()
    (root / "package.json").write_text(json.dumps({"name": "openclaw"}))
    f = check_dependency_tree_hooks(_Ctx(root))
    assert f.status == UNKNOWN
    assert "no dependency" in f.detail or "no node_modules" in f.detail


def test_tree_not_walked_this_run_is_unknown():
    """No walk (audit ran without the dependency-tree pass) must degrade to UNKNOWN —
    a tree we never opened is not a clean one."""
    f = check_dependency_tree_hooks(_Ctx(None))
    assert f.status == UNKNOWN
    assert "not walked" in f.detail


def test_the_check_never_touches_the_filesystem_itself(monkeypatch):
    """Hermeticity regression: B349 walking on its own cost 2.4s per call — 102% of a whole
    audit — and reached the machine's real global npm install from any Context."""
    def _boom(*_a, **_k):  # pragma: no cover - must never be reached
        raise AssertionError("B349 must read ctx.dep_tree, never walk the filesystem")
    monkeypatch.setattr(deptree, "find_package_root", _boom)
    monkeypatch.setattr(deptree, "scan_dep_tree", _boom)
    assert check_dependency_tree_hooks(_Ctx(None)).status == UNKNOWN


def test_c135_esbuild_shaped_installer_does_not_fail(tmp_path):
    """C-135 blocker regression (2026-08-04).

    esbuild's official `postinstall` installer shells out with an interpolated version
    string. `analyze_javascript` grades that `JS_CHILD_PROCESS_DYNAMIC` / **warn** and
    documents it as "often legit"; the first cut of this check treated every rule as
    FAIL-eligible and so emitted a CRITICAL FAIL on it. An independent sweep over 124
    real dependency trees (25,834 packages) found 8 FAILs, all esbuild, all false —
    and OpenClaw pins `esbuild@0.28.1` in its own devDependencies, so a source install
    would have hit it. A warn-grade rule must be disclosed, never a verdict.
    """
    root = tmp_path / "openclaw"
    root.mkdir()
    (root / "package.json").write_text(json.dumps({"name": "openclaw"}))
    _pkg(root, "esbuild", {"postinstall": "node install.js"}, {"install.js": (
        "const child_process = require('child_process');\n"
        "function installUsingNPM(pkg, version, installDir) {\n"
        "  child_process.execSync(`npm install --loglevel=error ${pkg}@${version}`,\n"
        "    { cwd: installDir, stdio: 'pipe' });\n"
        "}\n"
        "module.exports = { installUsingNPM };\n"
    )})
    f = check_dependency_tree_hooks(_Ctx(root))
    assert f.status == PASS, f"warn-grade rule must not FAIL; got {f.status}: {f.evidence}"
    joined = "\n".join(f.evidence or [])
    assert "JS_CHILD_PROCESS_DYNAMIC" in joined, "the observation must still be disclosed"
    assert "not a verdict" in joined


def test_crit_grade_rule_still_fails_after_the_warn_split(tmp_path):
    """The other half of the C-135 fix: narrowing to crit must not silence a real signal."""
    root = tmp_path / "openclaw"
    root.mkdir()
    (root / "package.json").write_text(json.dumps({"name": "openclaw"}))
    _pkg(root, "bad", {"preinstall": "node s.js"}, {"s.js": (
        "const b = require('fs').readFileSync('p.b64', 'utf8');\n"
        "eval(Buffer.from(b, 'base64').toString('utf8'));\n"
    )})
    f = check_dependency_tree_hooks(_Ctx(root))
    assert f.status == FAIL
    assert "JS_EVAL_DECODED" in "\n".join(f.evidence or [])


def test_a_pass_never_carries_a_hit(monkeypatch):
    """Guards the bucket boundary: only the FAIL branch may name a package as a hit."""
    f = check_dependency_tree_hooks(_Ctx(CLEAN))
    assert f.status == PASS
    assert not any("JS_" in e for e in (f.evidence or []))
