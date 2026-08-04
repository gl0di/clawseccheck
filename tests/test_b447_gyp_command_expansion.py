"""B-447 / B349: GYP command-expansion — install-time execution with no lifecycle script.

B349 shipped enumerating `scripts.{preinstall,install,postinstall}` only. The node-gyp
supply-chain worm executes with **no lifecycle script at all**: its tarballs declare none,
and `<!(node index.js ...)` inside `binding.gyp` runs while node-gyp is merely CONFIGURING,
which npm invokes on its own because the file exists. A `scripts`-only check is exactly
the script-focused monitoring that shape was built to walk past.

The regression guard that matters is `test_a_package_with_no_scripts_key_still_yields_a_directive`:
the old code hit an early `continue` on the missing `scripts` key and never looked at
anything else in the package — so the verdict was a silent PASS.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck import deptree
from clawseccheck.catalog import FAIL, PASS, UNKNOWN
from clawseccheck.checks import check_dependency_tree_hooks

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

CLEAN = FIXTURES / "deptree_clean_pkg"
GYP_BAD = FIXTURES / "deptree_gyp_pkg"
GYP_UNREADABLE = FIXTURES / "deptree_gyp_unreadable_pkg"


class _Ctx:
    """Minimal stand-in — the check reads `ctx.dep_tree` and nothing else, so tests do the
    same one-line scan `audit()` does."""

    def __init__(self, root):
        self.openclaw_pkg_root = Path(root)
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


def _gyp_pkg(root: Path, name: str, gyp: str, files=None, scripts=None) -> Path:
    d = _pkg(root, name, scripts, files)
    (d / deptree.GYP_FILENAME).write_text(gyp)
    return d


# ---------------------------------------------------------------------------
# extract_gyp_commands — locating the syntax, deliberately not parsing GYP
# ---------------------------------------------------------------------------

def test_extracts_both_expansion_forms():
    """`<!(...)` runs a command; `<!@(...)` runs one and splits the output into a list.
    Both execute, so both are in scope."""
    text = '{"a": "<!(node one.js)", "b": "<!@(node two.js)"}'
    assert deptree.extract_gyp_commands(text) == ("node one.js", "node two.js")


def test_nested_parens_are_matched_by_depth_not_by_the_first_close():
    """The honest idiom nests parens. Stopping at the first `)` would hand the resolver a
    command nobody ever wrote."""
    text = '"include_dirs": ["<!(node -p \\"require(\'node-addon-api\').include\\")"]'
    assert deptree.extract_gyp_commands(text) == (
        'node -p \\"require(\'node-addon-api\').include\\"',
    )


def test_an_unbalanced_expansion_yields_nothing_but_does_not_stop_the_scan():
    """We cannot say where an unbalanced command ends, so we claim nothing about it —
    and a later, well-formed one must still be found (GR#4: no guessing, no silent stop)."""
    text = '"a": "<!(node broken.js", "b": "<!(node real.js)"'
    assert deptree.extract_gyp_commands(text) == ("node real.js",)


def test_a_bare_marker_without_a_paren_is_not_an_expansion():
    assert deptree.extract_gyp_commands('"note": "<!not an expansion"') == ()


def test_an_empty_expansion_body_is_dropped():
    assert deptree.extract_gyp_commands('"a": "<!()"') == ()


def test_the_per_file_expansion_cap_is_honoured():
    text = '"<!(node a.js)"' * 100
    assert len(deptree.extract_gyp_commands(text, max_expansions=5)) == 5


def test_a_hostile_config_of_unbalanced_markers_stays_bounded():
    """A `binding.gyp` is untrusted input from a package in the user's own tree. Without a
    bounded scan window every unbalanced `<!(` would run to EOF, which is quadratic — a
    denial of service on the audit rather than a finding. Wall-clock is the assertion
    because the defect is cost, not output."""
    import time

    hostile = "<!(" * (deptree.MAX_GYP_BYTES // 3)  # ~85k markers, not one of them closed
    t0 = time.monotonic()
    assert deptree.extract_gyp_commands(hostile) == ()
    assert time.monotonic() - t0 < 5.0, "the scan must be bounded, not quadratic"


def test_a_real_command_is_still_found_after_unbalanced_noise():
    """The bound must not cost recall on the shape that matters."""
    text = '"<!(node a.js' * 50 + '"<!(node real.js)"'
    assert "node real.js" in deptree.extract_gyp_commands(text)


def test_a_command_longer_than_the_window_is_not_reported_but_is_disclosed():
    """Past the window we never saw where the command ends, so we report nothing rather
    than a truncated command nobody wrote — and we SAY we fell short."""
    long_cmd = "node " + "x" * (deptree.MAX_GYP_COMMAND_BYTES + 10) + ".js"
    capped: list = []
    assert deptree.extract_gyp_commands(f'"<!({long_cmd})"', capped=capped) == ()
    assert capped, "a bound that is hit must be disclosed, not absorbed"


def test_decoy_markers_cannot_silently_evict_a_real_command():
    """EVASION GUARD. Every bound here is also a bypass if it fails quietly: the package
    author writes `binding.gyp`, so padding it with decoy `<!` markers ahead of the real
    expansion would push the real one out of the budget. The scanner is still allowed to
    stop — it is not allowed to stop without saying so."""
    text = "<!x" * (deptree.MAX_GYP_MARKERS + 10) + '"<!(node evil.js)"'
    capped: list = []
    out = deptree.extract_gyp_commands(text, capped=capped)
    assert "node evil.js" not in out, "sanity: the budget really is exhausted here"
    assert capped, "the exhausted budget must be reported so the verdict can degrade"


def test_an_unbalanced_expansion_is_not_reported_as_a_cap():
    """A config whose parens never balance is malformed for node-gyp too, so there is no
    command we missed — calling that a cap would degrade honest verdicts for nothing."""
    capped: list = []
    deptree.extract_gyp_commands('"<!(node broken.js', capped=capped)
    assert capped == []


def test_comments_and_single_quotes_do_not_defeat_extraction():
    """GYP is not JSON — it permits `#` comments, single quotes and trailing commas. This
    locates the expansion syntax rather than parsing, so none of that matters."""
    text = "# a comment\n{ 'sources': [ '<!(node gen.js)', ], }\n"
    assert deptree.extract_gyp_commands(text) == ("node gen.js",)


def test_a_commented_out_expansion_is_not_a_command():
    """C-135 defect (B-447). GYP takes `#` to end-of-line as a comment, and every real
    build config measured uses them. Lifting a commented-out expansion out as live meant
    reading and judging a file the installer would never run — reproduced end-to-end as a
    wrong UNKNOWN on an honest package."""
    text = "{'targets': [{\n  # 'include_dirs': ['<!(node ./scripts/includes.js)'],\n}]}"
    assert deptree.extract_gyp_commands(text) == ()


def test_a_hash_inside_a_string_is_not_a_comment():
    """The other direction: over-eager comment stripping would silently lose a real
    command, which is the one failure this must not have."""
    text = "{'sources': ['#tag', '<!(node gen.js)']}"
    assert deptree.extract_gyp_commands(text) == ("node gen.js",)


def test_a_comment_on_a_previous_line_does_not_hide_a_live_command():
    text = "# configure the addon\n{'sources': ['<!(node gen.js)']}"
    assert deptree.extract_gyp_commands(text) == ("node gen.js",)


def test_a_non_utf8_build_config_is_disclosed_not_silently_clean(tmp_path):
    """C-135 false negative (B-447). node-gyp reads a UTF-16 config fine; decoding it as
    UTF-8 turns every `<!(` into `<\\x00!\\x00(`, so expansions vanish and the package
    reads as clean. A silent PASS over bytes we could not read is what GR#4 forbids."""
    d = _pkg(tmp_path, "u16", None, {"index.js": "1\n"})
    (d / deptree.GYP_FILENAME).write_bytes(
        '{"sources": ["<!(node index.js)"]}'.encode("utf-16-le")
    )
    scan = deptree.scan_dep_tree(deptree.find_dep_tree(tmp_path))
    assert scan.build_directives == ()
    assert any("not UTF-8" in note for note in scan.gyp_capped)


# ---------------------------------------------------------------------------
# scan_dep_tree — the regression, and the boundaries around it
# ---------------------------------------------------------------------------

def test_a_package_with_no_scripts_key_still_yields_a_directive(tmp_path):
    """THE B-447 REGRESSION. A manifest with no `scripts` key hit an early `continue`, so
    nothing else in the package was ever looked at — which is precisely the manifest the
    worm ships. Before the fix this scan reported `hooks=0` and B349 passed silently."""
    _gyp_pkg(tmp_path, "worm", '{"sources": ["<!(node index.js)"]}', {"index.js": "1\n"})
    scan = deptree.scan_dep_tree(deptree.find_dep_tree(tmp_path))
    assert scan.hooks == (), "no lifecycle script exists — that is the whole point"
    assert len(scan.build_directives) == 1
    directive = scan.build_directives[0]
    assert directive.package == "worm"
    assert [t.name for t in directive.targets] == ["index.js"]


def test_the_shape_from_the_advisory_resolves(tmp_path):
    """`<!(node index.js > /dev/null 2>&1 && echo stub.c)` — redirections and a chained
    command must not stop the resolver reaching `index.js`."""
    _gyp_pkg(
        tmp_path, "worm",
        '{"sources": ["<!(node index.js > /dev/null 2>&1 && echo stub.c)"]}',
        {"index.js": "1\n"},
    )
    scan = deptree.scan_dep_tree(deptree.find_dep_tree(tmp_path))
    assert [t.name for t in scan.build_directives[0].targets] == ["index.js"]


def test_the_common_honest_idiom_resolves_to_no_target(tmp_path):
    """`node -e`/`node -p` run an inline expression, not a file. This is the overwhelming
    majority of real expansions, and it must leave nothing to assess."""
    _gyp_pkg(tmp_path, "addon", '{"include_dirs": ["<!(node -e \\"require(\'nan\')\\")"]}')
    scan = deptree.scan_dep_tree(deptree.find_dep_tree(tmp_path))
    assert len(scan.build_directives) == 1
    assert scan.build_directives[0].targets == ()


def test_a_non_node_expansion_resolves_to_no_target(tmp_path):
    """`pkg-config` is a real, measured idiom. We never read its bytes, so we say nothing."""
    _gyp_pkg(tmp_path, "addon", '{"libraries": ["<!@(pkg-config --libs sqlite3)"]}')
    assert deptree.scan_dep_tree(deptree.find_dep_tree(tmp_path)).build_directives[0].targets == ()


def test_a_target_outside_the_package_is_refused(tmp_path):
    """Confinement: a finding is attributed to a package, so its bytes must be that
    package's. Inherited from the hook resolver rather than re-implemented."""
    (tmp_path / "node_modules").mkdir(parents=True, exist_ok=True)
    (tmp_path / "node_modules" / "outside.js").write_text("1\n")
    _gyp_pkg(tmp_path, "addon", '{"sources": ["<!(node ../outside.js)"]}')
    assert deptree.scan_dep_tree(deptree.find_dep_tree(tmp_path)).build_directives[0].targets == ()


def test_a_nested_binding_gyp_is_not_read(tmp_path):
    """npm's automatic `node-gyp configure` looks at the package root. Reporting a nested
    one would manufacture a finding the installer never triggers."""
    d = _pkg(tmp_path, "addon", None, {"deep/index.js": "1\n"})
    (d / "deep" / deptree.GYP_FILENAME).write_text('{"sources": ["<!(node index.js)"]}')
    assert deptree.scan_dep_tree(deptree.find_dep_tree(tmp_path)).build_directives == ()


def test_a_symlinked_binding_gyp_is_refused_and_reported(tmp_path):
    """node-gyp reads THROUGH the symlink; we refuse to, because a link can point the walk
    outside the package we would attribute the finding to. That is a real blind spot, so
    it is named rather than passed over."""
    real = tmp_path / "elsewhere.gyp"
    real.write_text('{"sources": ["<!(node index.js)"]}')
    d = _pkg(tmp_path, "addon", None, {"index.js": "1\n"})
    try:
        (d / deptree.GYP_FILENAME).symlink_to(real)
    except (OSError, NotImplementedError):  # pragma: no cover
        return
    scan = deptree.scan_dep_tree(deptree.find_dep_tree(tmp_path))
    assert scan.build_directives == ()
    assert any("symlink" in note for note in scan.gyp_capped)


def test_an_oversized_binding_gyp_is_refused_and_reported(tmp_path):
    """Refusing it is right; refusing it silently would let a 257 KB build config buy a
    clean PASS. The consumer must be told, so the verdict can degrade to UNKNOWN."""
    _gyp_pkg(tmp_path, "addon", "#" * (deptree.MAX_GYP_BYTES + 1) + '\n"<!(node i.js)"',
             {"i.js": "1\n"})
    scan = deptree.scan_dep_tree(deptree.find_dep_tree(tmp_path))
    assert scan.build_directives == ()
    assert any("too large" in note for note in scan.gyp_capped)


def test_an_oversized_build_config_degrades_the_verdict_to_unknown(tmp_path):
    """End-to-end: the disclosure has to actually reach the verdict, or it is decoration."""
    root = tmp_path / "openclaw"
    root.mkdir()
    (root / "package.json").write_text(json.dumps({"name": "openclaw"}))
    _gyp_pkg(root, "addon", "#" * (deptree.MAX_GYP_BYTES + 1), {"i.js": "1\n"})
    f = check_dependency_tree_hooks(_Ctx(root))
    assert f.status == UNKNOWN
    assert "addon" in "\n".join(f.evidence or [])


def test_a_package_with_both_surfaces_yields_both(tmp_path):
    _gyp_pkg(tmp_path, "both", '{"sources": ["<!(node gen.js)"]}',
             {"gen.js": "1\n", "post.js": "1\n"}, scripts={"postinstall": "node post.js"})
    scan = deptree.scan_dep_tree(deptree.find_dep_tree(tmp_path))
    assert len(scan.hooks) == 1 and len(scan.build_directives) == 1


# ---------------------------------------------------------------------------
# the check — the verdict paths, driven through the real function
# ---------------------------------------------------------------------------

def test_bad_gyp_fixture_fails_with_no_lifecycle_hook_anywhere_in_the_tree():
    """The load-bearing assertion: the FAIL is reached on a tree that declares zero
    lifecycle scripts, so it cannot have come from the surface B349 already had."""
    ctx = _Ctx(GYP_BAD)
    assert ctx.dep_tree.hooks == ()
    f = check_dependency_tree_hooks(ctx)
    assert f.status == FAIL
    joined = "\n".join(f.evidence or [])
    assert "gyp-worm-pkg" in joined
    assert "JS_EVAL_DECODED" in joined
    assert deptree.GYP_FILENAME in joined, "the evidence must say WHERE to look"


def test_an_honest_addon_sharing_the_tree_is_not_named():
    """Selectivity, not just detection — the honest addon's inline expansion has no bytes
    to read, so naming it would be an accusation over something never examined."""
    f = check_dependency_tree_hooks(_Ctx(GYP_BAD))
    assert "honest-addon-pkg" not in "\n".join(f.evidence or [])


def test_clean_fixture_still_passes_with_a_resolvable_honest_gyp_target():
    """`native-addon-pkg` runs a REAL in-package file from its build config. Its bytes are
    read and found ordinary — which is the conjunction working, not the check being blind."""
    f = check_dependency_tree_hooks(_Ctx(CLEAN))
    assert f.status == PASS
    assert "native-addon-pkg" not in "\n".join(f.evidence or [])


def test_clean_fixture_discloses_the_expansion_count():
    joined = "\n".join(check_dependency_tree_hooks(_Ctx(CLEAN)).evidence or [])
    assert "build-config command expansions:" in joined
    assert "inline `node -e` expression" in joined, "coverage note must name what is skipped"


def test_unreadable_gyp_target_is_unknown_not_fail():
    """B97's precedent: we did not read it, so we claim nothing — and "I could not read
    this package's build script" is itself actionable."""
    f = check_dependency_tree_hooks(_Ctx(GYP_UNREADABLE))
    assert f.status == UNKNOWN
    joined = "\n".join(f.evidence or [])
    assert "minified-gyp-pkg" in joined
    assert "minified — unreadable" in joined


def test_a_warn_grade_gyp_target_does_not_fail(tmp_path):
    """The C-135 esbuild fix governs BOTH surfaces — the new one must not acquire a
    second, unreviewed threshold of its own."""
    root = tmp_path / "openclaw"
    root.mkdir()
    (root / "package.json").write_text(json.dumps({"name": "openclaw"}))
    _gyp_pkg(root, "addon", '{"sources": ["<!(node configure.js)"]}', {"configure.js": (
        "const child_process = require('child_process');\n"
        "const v = require('./package.json').version;\n"
        "child_process.execSync(`prebuild-install --tag v${v}`, { stdio: 'pipe' });\n"
    )})
    f = check_dependency_tree_hooks(_Ctx(root))
    assert f.status == PASS, f"warn-grade must not FAIL; got {f.status}: {f.evidence}"
    assert "not a verdict" in "\n".join(f.evidence or [])


def test_c135_a_non_english_comment_does_not_fail(tmp_path):
    """C-135 BLOCKER, reproduced end-to-end 2026-08-04 and fixed here.

    `textnorm.obfuscation_signals` reports "confusable characters folded to ASCII" for any
    Cyrillic or Greek text whatsoever, and `_b349_assess_target` fed that straight into the
    FAIL bucket — so an entirely honest build script whose only unusual property was a
    Russian comment earned a CRITICAL FAIL. That is a Golden-Rule-#5 false positive, and
    it was live on the lifecycle-hook surface too; B-447 only widened the exposed
    population. The discriminator is `confusable_in_ascii_context`, which `textnorm`
    already ships for exactly this and already keeps B58 off multilingual prose.
    """
    root = tmp_path / "openclaw"
    root.mkdir()
    (root / "package.json").write_text(json.dumps({"name": "openclaw"}))
    _gyp_pkg(root, "ru-addon", '{"sources": ["<!(node gen.js)"]}', {"gen.js": (
        "// Определяем платформу и печатаем имя исходника\n"
        "const os = require('os');\n"
        "console.log(os.arch() === 'arm64' ? 'src/arm64.cc' : 'src/generic.cc');\n"
    )})
    f = check_dependency_tree_hooks(_Ctx(root))
    assert f.status == PASS, f"an i18n comment must not FAIL; got {f.status}: {f.evidence}"
    joined = "\n".join(f.evidence or [])
    assert "reads as i18n" in joined, "the observation must still be disclosed, not dropped"


def test_a_homoglyph_swapped_into_a_latin_word_still_fails(tmp_path):
    """The other half: narrowing the confusable signal must not silence the real attack.
    A Cyrillic lookalike INSIDE an otherwise-Latin token is homoglyph substitution."""
    root = tmp_path / "openclaw"
    root.mkdir()
    (root / "package.json").write_text(json.dumps({"name": "openclaw"}))
    _gyp_pkg(root, "sneaky", '{"sources": ["<!(node gen.js)"]}', {"gen.js": (
        "const іgnore = requіre;\nconsole.log(1);\n"
    )})
    f = check_dependency_tree_hooks(_Ctx(root))
    assert f.status == FAIL, f"homoglyph substitution must still FAIL; got {f.evidence}"
    assert "confusable" in "\n".join(f.evidence or [])


def test_an_invisible_character_still_fails_regardless_of_script(tmp_path):
    """Zero-width, bidi and Tag-block characters have no legitimate use in a build script,
    so they were never gated — only the confusable class was."""
    root = tmp_path / "openclaw"
    root.mkdir()
    (root / "package.json").write_text(json.dumps({"name": "openclaw"}))
    _gyp_pkg(root, "zw", '{"sources": ["<!(node gen.js)"]}',
             {"gen.js": "const a​ = 1;\nconsole.log(a);\n"})
    assert check_dependency_tree_hooks(_Ctx(root)).status == FAIL


def test_no_count_reaches_the_detail(tmp_path):
    """B-385: `baseline.fingerprint()` hashes `detail` alone, and every number here is a
    property of the MACHINE's install, not the audited config. A count in `detail` would
    orphan a user's suppression the moment they `npm install` anything."""
    for f in (
        check_dependency_tree_hooks(_Ctx(CLEAN)),
        check_dependency_tree_hooks(_Ctx(GYP_BAD)),
        check_dependency_tree_hooks(_Ctx(GYP_UNREADABLE)),
    ):
        assert not any(ch.isdigit() for ch in f.detail), f.detail


def test_the_check_still_reads_only_ctx(monkeypatch):
    """Hermeticity (B-446): the check must never walk the filesystem itself. Extending it
    to a second surface is exactly when that could regress."""
    ctx = _Ctx(GYP_BAD)  # the walk is audit()'s job and happens BEFORE the check runs

    def _boom(*a, **kw):  # pragma: no cover — reaching this IS the failure
        raise AssertionError("the check walked the tree itself")

    monkeypatch.setattr(deptree, "scan_dep_tree", _boom)
    monkeypatch.setattr(deptree, "find_package_root", _boom)
    assert check_dependency_tree_hooks(ctx).status == FAIL
