"""C-637 - an importable file beside audit.py must not run silently inside the auditor.

`audit.py` runs with its own directory at the front of `sys.path` (Python puts it there for
a script, and the shim inserts it again), so a `json.py` / `re.py` / `sitecustomize.py` /
`*.so` dropped next to it is imported ahead of the standard library on every run.
`--verify-self` digests `clawseccheck/` only and the listed-file compare covers listed
files only, so neither notices an ADDED file.

The change under test:

* `audit.py` scans its own directory BEFORE any import and refuses (exit 2, nothing run)
  while an importable extra is there. It may use `os` and `sys` only: `from pathlib import
  Path` alone imports `re`, so a stray `re.py` would run on that very line.
* `clawseccheck.integrity.bundle_root_extras` applies the same rule for `--verify-self`,
  which only DISCLOSES (rc 0) and never touches `package_digest` / `combined`.
* the release workflow appends an "Expected top-level entries" line to SHA256SUMS.txt so
  an exhaustive directory compare is possible.

The rule is duplicated between audit.py and integrity.py on purpose (the shim cannot import
the package before its guard), so a differential test pins the two together.

Offline; every stray body writes a marker file under `tmp_path`, so "did it run" is
observed rather than inferred. ASCII only.
"""
from __future__ import annotations

import ast
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from clawseccheck import integrity
from clawseccheck.cli import main
from clawseccheck.integrity import (
    NOTE_BUNDLE_EXTRA,
    NOTE_UNREADABLE,
    bundle_root_extras,
    package_digest,
)

REPO = Path(__file__).resolve().parents[1]
AUDIT_PY = REPO / "audit.py"
WORKFLOW_PATH = REPO / ".github" / "workflows" / "clawhub-publish.yml"

_NEEDS_WORKFLOW = pytest.mark.skipif(
    not WORKFLOW_PATH.exists(),
    reason="CI workflow file not present (packaged skill ships without .github/)",
)
_NEEDS_REPLAY = (
    _NEEDS_WORKFLOW,
    pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available"),
    pytest.mark.skipif(shutil.which("git") is None, reason="git not available"),
)
_ROOT_SKIP = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores the read bit"
)


# ------------------------------------------------------------------------------ helpers

def _install(dest: Path) -> Path:
    """What a ClawHub install looks like on disk: the package plus the audit.py shim."""
    shutil.copytree(REPO / "clawseccheck", dest / "clawseccheck",
                    ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy2(AUDIT_PY, dest / "audit.py")
    return dest


def _run(install: Path, *args: str):
    return subprocess.run([sys.executable, "audit.py", *args], cwd=install,
                          capture_output=True, text=True, timeout=120)


def _pycaches(root: Path) -> list:
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("__pycache__"))


def _shim_rule():
    """`_bundle_extras` out of audit.py WITHOUT executing the shim.

    Not `runpy`: running audit.py in-process sets `sys.dont_write_bytecode = True` for the
    whole pytest run. The two constants and the function are lifted with `ast` instead.
    """
    tree = ast.parse(AUDIT_PY.read_text(encoding="utf-8"))
    keep = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id in ("_C637_ALLOWED", "_C637_SUFFIXES")
            for t in node.targets
        ):
            keep.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name == "_bundle_extras":
            keep.append(node)
    assert len(keep) == 3, "audit.py no longer carries the C-637 rule where this test looks"
    ns = {"os": os}
    exec(compile(ast.Module(body=keep, type_ignores=[]), "audit.py", "exec"), ns)
    return ns["_bundle_extras"]


def _marker_body(marker: Path) -> str:
    return "open(%r, 'w').write('ran')\n" % str(marker)


def _plant(install: Path, kind: str, name: str, marker: Path) -> None:
    """Create one stray entry named `name` (a trailing slash is a directory)."""
    target = install / name.rstrip("/")
    if kind == "py":
        target.write_text(_marker_body(marker), encoding="utf-8")
    elif kind == "bin":
        target.write_bytes(b"\x00\x01not python\n")
    elif kind == "pkg":
        target.mkdir()
        (target / "__init__.py").write_text(_marker_body(marker), encoding="utf-8")
    elif kind == "pkg-pyc":
        target.mkdir()
        (target / "__init__.pyc").write_bytes(b"\x00\x01")
    elif kind == "dangling":
        os.symlink(str(install / "does-not-exist-anywhere"), str(target))
    else:  # pragma: no cover - a typo in this table should fail loudly
        raise AssertionError(kind)


# ------------------------------------------------------------------ 1. the clean case

def test_clean_install_with_benign_extras_runs(tmp_path):
    """What a real install or dev root holds beside audit.py must not be refused."""
    install = _install(tmp_path / "install")
    (install / "_meta.json").write_text("{}", encoding="utf-8")
    (install / ".clawhub").mkdir()
    (install / ".clawhub" / "origin.json").write_text("{}", encoding="utf-8")
    (install / "skill-card.md").write_text("card\n", encoding="utf-8")
    (install / "docs").mkdir()
    (install / "docs" / "x.md").write_text("x\n", encoding="utf-8")
    (install / "references").mkdir()
    (install / "references" / "x.md").write_text("x\n", encoding="utf-8")
    (install / "__pycache__").mkdir()
    (install / "conftest.py").write_text("# dev checkout\n", encoding="utf-8")
    (install / "not_a_package").mkdir()
    (install / "not_a_package" / "data.txt").write_text("d\n", encoding="utf-8")
    (install / "foo.py~").write_text("editor backup\n", encoding="utf-8")
    (install / "foo.py.bak").write_text("backup\n", encoding="utf-8")

    result = _run(install, "--version")

    assert result.returncode == 0, result.stderr
    assert "refusing to run" not in result.stderr
    assert result.stdout.startswith("clawseccheck ")


def test_the_real_repo_root_is_clean_for_both_implementations():
    """Guards the dev-checkout allowlist: a new root-level .py would refuse every run."""
    assert _shim_rule()(str(REPO)) == []
    assert bundle_root_extras(REPO / "clawseccheck") == []


# --------------------------------------------------- 2. the bad case, run end to end

_BAD = [
    ("json.py", "py"),
    ("re.py", "py"),
    ("sitecustomize.py", "py"),
    ("usercustomize.py", "py"),
    ("foo.pyc", "bin"),
    ("y.pth", "bin"),
    ("x.cpython-312-x86_64-linux-gnu.so", "bin"),
    ("json/", "pkg"),
    ("pycpkg/", "pkg-pyc"),
    ("json.py", "dangling"),
    ("JSON.PY", "py"),
]


@pytest.mark.parametrize("flag", ["--version", "--verify-self"])
@pytest.mark.parametrize("name,kind", _BAD, ids=[f"{n}-{k}" for n, k in _BAD])
def test_a_stray_importable_entry_is_refused_and_never_runs(tmp_path, name, kind, flag):
    install = _install(tmp_path / "install")
    marker = tmp_path / "marker"
    _plant(install, kind, name, marker)

    result = _run(install, flag)

    assert result.returncode == 2, (result.returncode, result.stdout, result.stderr)
    assert "refusing to run" in result.stderr
    assert ascii(name) in result.stderr, result.stderr
    assert not marker.exists(), "the stray module was executed before the guard refused"
    assert result.stdout == "", "a refusal must print nothing on stdout"
    assert _pycaches(install) == [], "a refusal must not write bytecode into the install"


def test_the_refusal_renders_hostile_names_safely_and_states_its_cap(tmp_path):
    install = _install(tmp_path / "install")
    (install / "evil\x1b[31mred.py").write_text("x = 1\n", encoding="utf-8")
    for i in range(12):
        (install / f"extra{i:02d}.py").write_text("x = 1\n", encoding="utf-8")

    result = _run(install, "--version")

    assert result.returncode == 2
    assert "\x1b" not in result.stderr, "an attacker-chosen name reached the terminal raw"
    assert "\\x1b[31m" in result.stderr
    assert "(and 3 more)" in result.stderr, "the 10-name cap must be disclosed"


# ------------------------------------------------------------------ 3. the ordering

def test_only_os_and_sys_are_imported_before_the_guard():
    """`from pathlib import Path` imports `re`; anything else earlier defeats the guard."""
    tree = ast.parse(AUDIT_PY.read_text(encoding="utf-8"))
    guard_at = next(
        i for i, node in enumerate(tree.body)
        if isinstance(node, ast.If)
        and any(isinstance(n, ast.Name) and n.id == "_C637_EXTRAS" for n in ast.walk(node.test))
    )
    before = set()
    for node in tree.body[:guard_at]:
        if isinstance(node, ast.Import):
            before.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            before.add(node.module)
    assert before == {"os", "sys"}, before
    after = [n for n in tree.body[guard_at + 1:] if isinstance(n, ast.ImportFrom)]
    assert "pathlib" in {n.module for n in after}, "pathlib must come after the guard"


_STDLIB_STRAYS = ("re", "fnmatch", "ntpath", "functools")


def _stray_stdlib_modules(install: Path, tmp_path: Path) -> dict:
    markers = {}
    for mod in _STDLIB_STRAYS:
        markers[mod] = tmp_path / f"ran-{mod}"
        (install / f"{mod}.py").write_text(_marker_body(markers[mod]), encoding="utf-8")
    return markers


def test_a_stray_stdlib_module_is_refused_before_pathlib_can_import_it(tmp_path):
    """Fails if the guard is reverted or moved after `from pathlib import Path`."""
    install = _install(tmp_path / "install")
    markers = _stray_stdlib_modules(install, tmp_path)

    result = _run(install, "--version")

    assert result.returncode == 2, result.stderr
    ran = sorted(m for m, p in markers.items() if p.exists())
    assert ran == [], f"stray stdlib module(s) executed before the guard: {ran}"


def test_the_same_strays_do_run_when_the_guard_comes_after_pathlib(tmp_path):
    """Positive control for the test above: proves the strays are reachable at all.

    Builds a variant of audit.py with `from pathlib import Path` moved ahead of the guard
    and shows a planted stdlib module executes. Without this, "marker absent" could be
    true simply because nothing ever imports those names in this interpreter.
    """
    src = AUDIT_PY.read_text(encoding="utf-8")
    late = "from pathlib import Path  # noqa: E402\n"
    assert src.count(late) == 1 and src.count("import os\nimport sys\n") == 1
    variant = src.replace(late, "").replace(
        "import os\nimport sys\n", "from pathlib import Path\nimport os\nimport sys\n")
    install = _install(tmp_path / "install")
    (install / "audit.py").write_text(variant, encoding="utf-8")
    markers = _stray_stdlib_modules(install, tmp_path)

    _run(install, "--version")

    ran = sorted(m for m, p in markers.items() if p.exists())
    assert ran, "no stray stdlib module ran even with pathlib first: the control is vacuous"


# ------------------------------------------------------------------ 4. UNKNOWN

_DENY_LISTDIR = textwrap.dedent("""
    import os, runpy, sys
    def _deny(path="."):
        raise PermissionError(13, "Permission denied", str(path))
    if sys.argv[1] == "deny":
        os.listdir = _deny
    sys.argv = ["audit.py", "--version"]
    runpy.run_path(%r, run_name="__main__")
""")


def _run_with_listdir(install: Path, mode: str):
    code = _DENY_LISTDIR % str(install / "audit.py")
    return subprocess.run([sys.executable, "-c", code, mode], cwd=install,
                          capture_output=True, text=True, timeout=120)


def test_an_unlistable_root_is_refused_not_passed(tmp_path):
    install = _install(tmp_path / "install")

    control = _run_with_listdir(install, "allow")
    assert control.returncode == 0, control.stderr  # the wrapper itself works

    result = _run_with_listdir(install, "deny")
    assert result.returncode == 2, (result.stdout, result.stderr)
    assert "cannot be ruled out" in result.stderr
    assert "could not list" in result.stderr
    assert result.stdout == ""


@_ROOT_SKIP
def test_a_root_without_the_read_bit_is_refused_on_a_real_filesystem(tmp_path):
    install = _install(tmp_path / "install")
    script = install / "audit.py"
    install.chmod(0o311)  # x for traversal (the script is opened by path), no r to list
    try:
        result = subprocess.run([sys.executable, str(script), "--version"], cwd=tmp_path,
                                capture_output=True, text=True, timeout=120)
    finally:
        install.chmod(0o755)
    assert result.returncode == 2, (result.stdout, result.stderr)
    assert "cannot be ruled out" in result.stderr


def test_an_unlistable_subdirectory_is_skipped_not_a_crash(tmp_path, monkeypatch):
    root = tmp_path / "root"
    (root / "locked").mkdir(parents=True)
    (root / "other").mkdir()
    (root / "other" / "__init__.py").write_text("x = 1\n", encoding="utf-8")
    rule = _shim_rule()
    real = os.listdir

    def fake(path="."):
        if str(path) == str(root / "locked"):
            raise PermissionError(13, "Permission denied", str(path))
        return real(path)

    monkeypatch.setattr(os, "listdir", fake)

    assert rule(str(root)) == ["other/"]
    (root / "audit.py").write_text("", encoding="utf-8")
    (root / "clawseccheck").mkdir()
    assert [n for _k, n, _w in bundle_root_extras(root / "clawseccheck")] == ["other/"]


def test_integrity_reports_an_unlistable_root_as_one_unreadable_row(tmp_path, monkeypatch):
    pkg = tmp_path / "root" / "clawseccheck"
    pkg.mkdir(parents=True)
    (pkg.parent / "audit.py").write_text("", encoding="utf-8")
    real = os.listdir

    def fake(path="."):
        if str(path) == str(pkg.parent):
            raise PermissionError(13, "Permission denied", str(path))
        return real(path)

    monkeypatch.setattr(os, "listdir", fake)

    rows = bundle_root_extras(pkg)

    assert len(rows) == 1
    kind, name, why = rows[0]
    assert kind == NOTE_UNREADABLE and name == str(pkg.parent)
    assert "cannot be ruled out" in why


# ------------------------------------------------- 6. --verify-self discloses, rc 0

def _tree(tmp_path: Path, with_audit: bool = True) -> Path:
    root = tmp_path / "root"
    pkg = root / "clawseccheck"
    (pkg / "sub").mkdir(parents=True)
    (pkg / "a.py").write_text("# a\n", encoding="utf-8")
    (pkg / "sub" / "b.py").write_text("# b\n", encoding="utf-8")
    if with_audit:
        (root / "audit.py").write_text("# shim\n", encoding="utf-8")
    return pkg


def _verify_self(monkeypatch, capsys, pkg: Path):
    monkeypatch.setattr("clawseccheck.integrity._PKG_DIR", pkg)
    rc = main(["--verify-self"])
    return rc, capsys.readouterr().out


def _combined(out: str) -> str:
    return next(ln for ln in out.splitlines() if ln.startswith("combined :"))


def test_verify_self_discloses_a_stray_and_leaves_the_digest_and_rc_alone(
        tmp_path, monkeypatch, capsys):
    pkg = _tree(tmp_path)
    rc_clean, clean = _verify_self(monkeypatch, capsys, pkg)
    assert rc_clean == 0 and "Coverage note" not in clean

    (pkg.parent / "json.py").write_text("x = 1\n", encoding="utf-8")
    rc, out = _verify_self(monkeypatch, capsys, pkg)

    assert rc == 0, "a disclosed stray must not turn the digest run into a failure"
    assert "Coverage note" in out and "'json.py'" in out
    assert "OUTSIDE the digested package" in out
    assert _combined(out) == _combined(clean), "the digest must not see the parent dir"
    assert package_digest(pkg_dir=pkg)[0] in out


def test_verify_self_ignores_clutter_when_audit_py_is_not_beside_the_package(
        tmp_path, monkeypatch, capsys):
    """The site-packages shape: no audit.py, so the neighbours are not ours to judge."""
    pkg = _tree(tmp_path, with_audit=False)
    (pkg.parent / "json.py").write_text("x = 1\n", encoding="utf-8")
    (pkg.parent / "six.py").write_text("x = 1\n", encoding="utf-8")

    rc, out = _verify_self(monkeypatch, capsys, pkg)

    assert rc == 0 and "Coverage note" not in out
    assert bundle_root_extras(pkg) == []


def test_verify_self_names_an_unlistable_root_and_still_exits_zero(
        tmp_path, monkeypatch, capsys):
    pkg = _tree(tmp_path)
    real = os.listdir

    def fake(path="."):
        if str(path) == str(pkg.parent):
            raise PermissionError(13, "Permission denied", str(path))
        return real(path)

    monkeypatch.setattr(os, "listdir", fake)
    rc, out = _verify_self(monkeypatch, capsys, pkg)

    assert rc == 0
    assert "cannot be ruled out" in out


def test_verify_self_caps_and_escapes_the_names_it_prints(tmp_path, monkeypatch, capsys):
    pkg = _tree(tmp_path)
    (pkg.parent / "evil\x1b[31mred.py").write_text("x = 1\n", encoding="utf-8")
    for i in range(11):
        (pkg.parent / f"extra{i:02d}.py").write_text("x = 1\n", encoding="utf-8")

    rc, out = _verify_self(monkeypatch, capsys, pkg)

    assert rc == 0
    assert "\x1b" not in out
    assert "(and 2 more)" in out


# ---------------------------------------------- 7. the two implementations must agree

# `json.py` and `JSON.PY` are two entries only on a case-SENSITIVE file system. On a
# case-folding one (the macOS default, Windows) the second write lands on the first file, so
# the listing holds one name (`json.py`) and the pair cannot be built. The rule under test
# lower-cases names, so the pair is there to prove an upper-case SUFFIX is still caught;
# on a folding file system that is proved by an upper-case name with no lower-case twin.
_CASE_TWIN = "JSON.PY"
_CASE_TWIN_FOLDED = "Stray.PY"


def _fs_folds_case(directory: Path) -> bool:
    """True when `directory` is on a case-insensitive file system.

    Probed on the directory under test rather than guessed from `sys.platform`: APFS can be
    case-sensitive and a Linux directory can be casefold-mounted. The probe file is removed
    before returning so it never shows up in the listing under test.
    """
    probe = directory / "CaseProbe.tmp"
    probe.write_text("x\n", encoding="utf-8")
    try:
        return (directory / "caseprobe.tmp").exists()
    finally:
        probe.unlink()


def _matrix(root: Path, folds_case: bool = False) -> None:
    """One entry per shape the rule has to decide, flagged or not."""
    (root / "clawseccheck").mkdir()
    (root / "audit.py").write_text("# shim\n", encoding="utf-8")
    for name in ("json.py", _CASE_TWIN_FOLDED if folds_case else _CASE_TWIN, "re.pyc",
                 "y.pth", "z.pyd", "w.pyw", "a.so",
                 "x.cpython-312-x86_64-linux-gnu.so", "sitecustomize.py", "sitecustomize",
                 "UserCustomize.txt", "conftest.py", "foo.py~", "foo.py.bak", "_meta.json",
                 "skill-card.md", "README.md", "real.txt"):
        (root / name).write_text("x\n", encoding="utf-8")
    os.symlink(str(root / "nowhere"), str(root / "dangling.py"))
    os.symlink(str(root / "real.txt"), str(root / "link-to-text"))
    (root / "__pycache__").mkdir()
    (root / ".clawhub").mkdir()
    (root / ".clawhub" / "origin.json").write_text("{}", encoding="utf-8")
    (root / "docs").mkdir()
    (root / "docs" / "x.md").write_text("x\n", encoding="utf-8")
    (root / "empty").mkdir()
    (root / "namespace").mkdir()
    (root / "namespace" / "mod.py").write_text("x = 1\n", encoding="utf-8")
    (root / "nested").mkdir()
    (root / "nested" / "sub").mkdir()
    (root / "nested" / "sub" / "__init__.py").write_text("x = 1\n", encoding="utf-8")
    for d, init in (("pkg_py", "__init__.py"), ("pkg_pyc", "__init__.pyc"),
                    ("pkg_so", "__init__.cpython-312.so"), ("not_pkg_txt", "__init__.txt"),
                    ("not_pkg_bare", "__init__")):
        (root / d).mkdir()
        (root / d / init).write_text("x = 1\n", encoding="utf-8")
    (root / "pkg_target").mkdir()
    (root / "pkg_target" / "__init__.py").write_text("x = 1\n", encoding="utf-8")
    os.symlink(str(root / "pkg_target"), str(root / "linked_pkg"))


_EXPECTED_FLAGGED = sorted([
    "JSON.PY", "UserCustomize.txt", "a.so", "dangling.py", "json.py", "linked_pkg/",
    "pkg_pyc/", "pkg_py/", "pkg_so/", "pkg_target/", "re.pyc", "sitecustomize",
    "sitecustomize.py", "w.pyw", "x.cpython-312-x86_64-linux-gnu.so", "y.pth", "z.pyd",
])


def _expected_flagged(folds_case: bool) -> list:
    if not folds_case:
        return _EXPECTED_FLAGGED
    return sorted(_CASE_TWIN_FOLDED if n == _CASE_TWIN else n for n in _EXPECTED_FLAGGED)


def test_audit_shim_and_integrity_flag_exactly_the_same_names(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    folds_case = _fs_folds_case(root)
    _matrix(root, folds_case)

    shim = sorted(_shim_rule()(str(root)))
    lib_rows = bundle_root_extras(root / "clawseccheck")
    lib = sorted(name for _kind, name, _why in lib_rows)

    assert shim == _expected_flagged(folds_case), shim
    assert lib == shim, "audit.py and integrity.py have drifted apart"
    assert {kind for kind, _n, _w in lib_rows} == {NOTE_BUNDLE_EXTRA}


def test_the_rule_constants_match_between_the_two_files():
    tree = ast.parse(AUDIT_PY.read_text(encoding="utf-8"))
    consts = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in ("_C637_ALLOWED", "_C637_SUFFIXES"):
                consts[node.targets[0].id] = node.value
    allowed = ast.literal_eval(consts["_C637_ALLOWED"].args[0])
    suffixes = ast.literal_eval(consts["_C637_SUFFIXES"])
    assert set(allowed) == set(integrity._BUNDLE_ALLOWED)
    assert tuple(suffixes) == integrity._IMPORTABLE_SUFFIXES


# ------------------------------------- 8/9. the shipped bundle and SHA256SUMS.txt line

def _needs_replay(fn):
    for mark in _NEEDS_REPLAY:
        fn = mark(fn)
    return fn


def _replay(tmp_path: Path):
    inside = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], cwd=str(REPO),
                            capture_output=True, text=True)
    if inside.returncode != 0:
        pytest.skip("not a git checkout (source tarball): nothing to replay")
    from test_publish_workflow import _replay_staged_tree
    work, _total, _per_top = _replay_staged_tree(tmp_path)
    return work


def _run_generator(work: Path) -> str:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    block = text.split("python3 - <<'PYEOF'\n")[1].split("          PYEOF")[0]
    proc = subprocess.run([sys.executable, "-c", textwrap.dedent(block)], cwd=str(work),
                          capture_output=True, text=True)
    assert proc.returncode == 0, f"stdout: {proc.stdout!r}\nstderr: {proc.stderr!r}"
    return (work / "SHA256SUMS.txt").read_text(encoding="utf-8")


@_needs_replay
def test_the_staged_bundle_holds_no_importable_extra(tmp_path):
    work = _replay(tmp_path)
    staged = work / "dist" / "clawseccheck"

    assert _shim_rule()(str(staged)) == []
    assert bundle_root_extras(staged / "clawseccheck") == []

    # Teeth: the same scan over the same tree does flag a planted stray.
    (staged / "json.py").write_text("x = 1\n", encoding="utf-8")
    assert _shim_rule()(str(staged)) == ["json.py"]
    assert [n for _k, n, _w in bundle_root_extras(staged / "clawseccheck")] == ["json.py"]


@_needs_replay
def test_sha256sums_lists_the_expected_top_level_entries(tmp_path):
    work = _replay(tmp_path)
    staged = work / "dist" / "clawseccheck"
    heading = "Bundle files outside the engine package"
    prefix = "Expected top-level entries in the install directory (exhaustive, as staged): "

    published = _run_generator(work)

    lines = [ln for ln in published.splitlines() if ln.startswith("Expected top-level")]
    assert len(lines) == 1, lines
    assert lines[0].startswith(prefix)
    listed = lines[0][len(prefix):].split(" ")
    on_disk = sorted(os.listdir(staged))
    assert all(" " not in n for n in on_disk), "a staged name with a space breaks the format"
    assert listed == on_disk
    assert {"SKILL.md", "audit.py", "clawseccheck"} <= set(listed)
    assert published.index(heading) < published.index(lines[0])

    # `combined` is unchanged: still the digest of the checked-out package alone.
    combined, _ = package_digest(pkg_dir=work / "clawseccheck")
    assert f"combined : {combined}" in published

    # Teeth: a stray added to the staged tree shows up in the signed listing.
    (staged / "json.py").write_text("x = 1\n", encoding="utf-8")
    again = _run_generator(work)
    line = next(ln for ln in again.splitlines() if ln.startswith("Expected top-level"))
    assert "json.py" in line[len(prefix):].split(" ")
    assert f"combined : {combined}" in again
