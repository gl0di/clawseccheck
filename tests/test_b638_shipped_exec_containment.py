"""B-638: exec() of a file the artifact itself ships, judged by where its path RESOLVES.

`analyze_python` reads every `open()`/`.read()` as external input, so the `setup.py` idiom
requests and urllib3 use to read their own `__version__.py` without importing the package
was a critical FAIL (TT5_CMD_INJECTION, or OBFUSCATED_EXEC when spelled with `.decode()`
and a variable). The earlier carve-out keyed on the path MENTIONING `__file__`, which an
independent C-135 pass showed is unsound in every rewording: an absolute argument to
`os.path.join` swallows the anchor, `..` climbs out, a `__file__` in a dead branch is
decorative, a segment from `os.environ` launders an arbitrary path.

`shippedexec.ShippedArtifact` replaces that with a proof over the artifact's own file set:
the executed value must be exactly the content of a file the scan analysed, read whole,
through a path that resolves to it, in a namespace nothing can pre-load -- and no file in
the artifact may reach the interpreter's own namespaces. These tests pin both directions:
the benign spellings clear, and every escape the C-135 pass named (plus the ones this
design had to close) stays crit.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.catalog import FAIL, PASS
from clawseccheck.checks import vet_plugin, vet_skill
from clawseccheck.shippedexec import ShippedArtifact
from clawseccheck.skillast import analyze_python

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "fixtures"
EX = "ex" + "ec"  # the repo's convention for naming the built-in in test data

_HDR = (
    "import os, pathlib, sys\n"
    "here = os.path.abspath(os.path.dirname(__file__))\n"
    "about = {}\n"
)
_TARGET = "demo_plugin/__version__.py"
_VERSION_SRC = '__version__ = "1.4.2"\n'


def _crit(src: str, extra=(), *, ship_target: bool = True, filename: str = "setup.py"):
    """The crit rules analyze_python reports for *src*, analysed as part of an artifact."""
    files = [(filename, src), *extra]
    if ship_target:
        files.append((_TARGET, _VERSION_SRC))
    art = ShippedArtifact(files)
    return {f.rule for f in analyze_python(src, filename, artifact=art) if f.severity == "crit"}


def _b13(home: Path):
    _, findings, _ = audit(home, include_native=False)
    return {f.id: f for f in findings}["B13"]


# ---------------------------------------------------------------------------------------
# The fixture pair -- each one is wrong on the pre-fix code, in opposite directions
# ---------------------------------------------------------------------------------------


def test_clean_fixture_shipped_version_exec_passes():
    """Before this change: FAIL, `external input flows into exec` on requests' own idiom."""
    f = _b13(FIXTURES / "clean_b638_shipped_version_exec")
    assert f.status == PASS, (f.status, f.detail)


def test_clean_fixture_split_anchor_rebind_passes():
    """CLAWSECCHECK-B-638 fix round 1: the SAME idiom as
    clean_b638_shipped_version_exec, but `here` is rebuilt across two straight-line
    statements (`here = os.path.dirname(__file__)` then `here = os.path.abspath(here)`)
    instead of one nested expression. Before this fix: FAIL -- `_FileFacts.sole()`
    required exactly one Assign record for a name, so a name rebound twice in
    unconditional, same-scope, straight-line code lost the proof even though the value
    reaching the read is unambiguous."""
    f = _b13(FIXTURES / "clean_b638_split_anchor_rebind")
    assert f.status == PASS, (f.status, f.detail)


def test_vet_skill_agrees_on_the_split_anchor_rebind():
    out = vet_skill(FIXTURES / "clean_b638_split_anchor_rebind" / "skills" / "demo-packager")
    pool = [out, *(out.ring_findings or [])]
    assert not [f for f in pool if f.status == FAIL], [(f.id, f.detail[:120]) for f in pool]


def test_bad_fixture_env_joined_path_fails():
    """Before this change: PASS. The `__file__` token was in the expression, so the old
    carve-out absolved a read whose last join argument comes from the environment -- and an
    absolute value there discards the anchor entirely."""
    f = _b13(FIXTURES / "bad_b638_exec_env_joined_path")
    assert f.status == FAIL, (f.status, f.detail)
    assert "setup.py:16" in f.detail
    # Both rules, not one: the token-based TT5 exemption is not consulted either when the
    # artifact is known, so the taint conviction must be there beside the decode one.
    assert "decoded/obfuscated string" in f.detail
    assert "external input flows into" in f.detail


def test_the_fixtures_differ_only_in_the_path():
    """Non-vacuity: the pair must be the same program but for the path segment, or the
    verdicts above could be decided by something else in the file."""
    base = FIXTURES / "{}" / "skills" / "demo-packager"
    clean = Path(str(base).format("clean_b638_shipped_version_exec"))
    bad = Path(str(base).format("bad_b638_exec_env_joined_path"))
    for rel in ("demo_plugin/__init__.py", "demo_plugin/__version__.py", "SKILL.md"):
        assert (clean / rel).read_text() == (bad / rel).read_text()
    assert f"{EX}(f.read(), about)" in (clean / "setup.py").read_text()
    assert 'os.environ["DEMO_VERSION_FILE"]' in (bad / "setup.py").read_text()


def test_vet_skill_agrees_with_the_audit():
    """--vet runs the same B13 engine; the pre-install answer must match the audit's. The
    clean skill may still WARN (B98: it runs exec without declaring it) -- it must not FAIL."""
    def pool(fixture):
        out = vet_skill(FIXTURES / fixture / "skills" / "demo-packager")
        return [out, *(out.ring_findings or [])]

    clean = pool("clean_b638_shipped_version_exec")
    assert not [f for f in clean if f.status == FAIL], [(f.id, f.detail[:120]) for f in clean]
    bad = pool("bad_b638_exec_env_joined_path")
    assert [f for f in bad if f.id == "B13" and f.status == FAIL], [(f.id, f.status) for f in bad]


# ---------------------------------------------------------------------------------------
# CLAWSECCHECK-B-922: sole()'s "before this use point" constraint (B-638 round 1) was
# threaded into resolve()'s Name branch for a PATH-anchor variable, but not into
# content()'s own Name branch, _namespace_ok()'s Name branch, or _read_call()'s "handle
# bound once" fallback -- so a CONTENT (or handle) variable rebound twice in
# unconditional, same-scope, straight-line code lost the proof the same way `here` once
# did. Only content()'s and _read_call()'s threading resolve a real false-FAIL here:
# _namespace_ok() has its own separate single-Store walk (below the sole() call) that
# still requires the namespace name bound exactly once anywhere in the region, so its
# threading is inert (harmless, precedent-matching) rather than fixing anything on its
# own.
# ---------------------------------------------------------------------------------------


def test_clean_fixture_content_rebind_then_decode_passes():
    """CLAWSECCHECK-B-922: the SAME idiom as clean_b638_shipped_version_exec, but the file
    is opened without a `with` block and the bytes it reads are decoded on a SEPARATE,
    straight-line statement that reuses the name `src` (`h = open(...); src = h.read();
    h.close(); src = src.decode(...)`) instead of one nested `f.read().decode(...)`
    expression. Before this fix: FAIL -- content()'s own Name branch never threaded
    sole()'s "before this use point" constraint, so this straight-line rebind lost the
    proof even though the value reaching exec() is unambiguous."""
    f = _b13(FIXTURES / "clean_b922_content_rebind_then_decode")
    assert f.status == PASS, (f.status, f.detail)


def test_vet_skill_agrees_on_the_content_rebind_then_decode():
    out = vet_skill(
        FIXTURES / "clean_b922_content_rebind_then_decode" / "skills" / "demo-packager"
    )
    pool = [out, *(out.ring_findings or [])]
    assert not [f for f in pool if f.status == FAIL], [(f.id, f.detail[:120]) for f in pool]


def test_bad_fixture_content_rebind_replaced_fails():
    """CLAWSECCHECK-B-922 mutation check: the SAME straight-line content-rebind shape as
    the clean fixture, but the second statement REPLACES `src` with attacker-influenced
    data (an environment variable) instead of decoding the shipped read. sole()'s
    "before=" threading resolves the REACHING (last) binding before the use point, not
    just any prior one, and content() only recognises a resolved value as shipped content
    through `.decode()` of a shipped read (or another such trusted primitive) --
    `os.environ.get(...)` is neither, so this must stay FAIL exactly as it did before this
    fix."""
    f = _b13(FIXTURES / "bad_b922_content_rebind_replaced")
    assert f.status == FAIL, (f.status, f.detail)
    assert "setup.py:24" in f.detail
    assert "external input flows into" in f.detail


def test_b922_fixtures_differ_only_in_the_rebind_statement():
    """Non-vacuity: the pair must be the same program but for the one replaced statement."""
    base = FIXTURES / "{}" / "skills" / "demo-packager"
    clean = Path(str(base).format("clean_b922_content_rebind_then_decode"))
    bad = Path(str(base).format("bad_b922_content_rebind_replaced"))
    for rel in ("demo_plugin/__init__.py", "demo_plugin/__version__.py", "SKILL.md"):
        assert (clean / rel).read_text() == (bad / rel).read_text()
    assert 'src = src.decode("utf-8")' in (clean / "setup.py").read_text()
    assert 'src = os.environ.get("DEMO_PAYLOAD", "")' in (bad / "setup.py").read_text()


# ---------------------------------------------------------------------------------------
# Benign spellings: each executes only a file the artifact ships (most were crit before)
# ---------------------------------------------------------------------------------------

_OPEN = 'open(os.path.join(here, "demo_plugin", "__version__.py")'

BENIGN = {
    # the C-135 table's rows (the variable-bound ones were still crit at 4.3.0)
    "with_inline_text": f'with {_OPEN}, "r", encoding="utf-8") as f:\n    {EX}(f.read(), about)\n',
    "with_inline_decode": f'with {_OPEN}, "rb") as fh:\n    {EX}(fh.read().decode("utf-8"), about)\n',
    "var_decode": f'with {_OPEN}, "rb") as fh:\n    src = fh.read().decode("utf-8")\n{EX}(src, about)\n',
    "var_text": f"with {_OPEN}) as fh:\n    src = fh.read()\n{EX}(src, about)\n",
    "inline_open_no_with": f"{EX}({_OPEN}).read(), about)\n",
    "compile_with_path_var": (
        'P = os.path.join(here, "demo_plugin", "__version__.py")\n'
        f'with open(P) as fh:\n    src = fh.read()\n{EX}(compile(src, P, "exec"), about)\n'
    ),
    "pathlib_read_text": (
        'p = pathlib.Path(__file__).resolve().parent / "demo_plugin" / "__version__.py"\n'
        f"{EX}(p.read_text(encoding='utf-8'), about)\n"
    ),
    "pathlib_with_name_chain": (
        f'{EX}(pathlib.Path(__file__).with_name("demo_plugin").joinpath("__version__.py")'
        ".read_text(), {})\n"
    ),
    "dict_call_namespace": f"ns = dict()\nwith {_OPEN}) as fh:\n    {EX}(fh.read(), ns)\n",
    # requests' real file binds `f` twice at module level; the with-body check is local
    "handle_name_reused": (
        f'with {_OPEN}, encoding="utf-8") as f:\n    {EX}(f.read(), about)\n'
        'with open(os.path.join(here, "README.md"), encoding="utf-8") as f:\n'
        "    readme = f.read()\n"
    ),
}


@pytest.mark.parametrize("name", sorted(BENIGN))
def test_benign_shipped_exec_clears(name):
    src = _HDR + BENIGN[name]
    assert _crit(src) == set(), name


def _on_disk(root: Path, files) -> ShippedArtifact:
    """Write *files* under *root* and return the artifact over them, rooted there."""
    for rel, src in files:
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(src)
    return ShippedArtifact(files, root=root)


def _rules(src: str, art: ShippedArtifact) -> set:
    return {(f.rule, f.severity) for f in analyze_python(src, "setup.py", artifact=art)}


@pytest.mark.parametrize("name", sorted(BENIGN))
def test_unshipped_target_is_a_question_not_a_verdict(tmp_path, name):
    """Membership is what the proof rests on. The same code whose target the artifact does
    NOT ship gets no carve-out -- and no conviction either when the target is provably
    ABSENT on disk: the path stays inside the skill, so what runs there is decided by
    whatever puts a file there later. That is Golden Rule #4's unknown, reported as
    UNSHIPPED_FILE_EXEC (WARN-grade), never crit and never a silent pass. (The task's own
    `case_01_setup` repro ships no __version__.py.)"""
    src = _HDR + BENIGN[name]
    art = _on_disk(tmp_path, [("setup.py", src)])
    assert art.exact_exec_sites("setup.py", src) == frozenset(), name
    assert set(art.unshipped_exec_sites("setup.py", src).values()) == {_TARGET}, name
    rules = _rules(src, art)
    assert not {r for r, sev in rules if sev == "crit"}, (name, rules)
    assert ("UNSHIPPED_FILE_EXEC", "info") in rules, (name, rules)


def test_without_a_root_an_unshipped_target_keeps_its_conviction():
    """No directory, no way to tell absent from present-but-unread: no WARN tier."""
    src = _HDR + BENIGN["with_inline_text"]
    art = ShippedArtifact([("setup.py", src)])
    assert art.unshipped_exec_sites("setup.py", src) == {}
    assert "TT5_CMD_INJECTION" in {r for r, _ in _rules(src, art)}


@pytest.mark.parametrize("present", ["symlink_file", "symlink_dir", "non_python",
                                     "under_git"])
def test_a_present_but_unanalysed_target_keeps_its_conviction(tmp_path, present):
    """The WARN tier is for a file that is NOT THERE. One that is there and was not read
    -- a symlink (the skill walk skips a symlinked directory without recording it), a
    non-Python file, anything under .git -- is content we did not see, and stays crit."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "__version__.py").write_text("import os\n")
    root = tmp_path / "skill"
    root.mkdir()
    target = _TARGET
    if present == "symlink_file":
        (root / "demo_plugin").mkdir()
        (root / "demo_plugin" / "__version__.py").symlink_to(outside / "__version__.py")
    elif present == "symlink_dir":
        (root / "demo_plugin").symlink_to(outside, target_is_directory=True)
    elif present == "non_python":
        target = "demo_plugin/version.txt"
        (root / "demo_plugin").mkdir()
        (root / target).write_text("__version__ = '1'\n")
    else:
        target = ".git/hooks/__version__.py"
    src = _HDR + (f'with open(os.path.join(here, "{target}")) as f:\n'
                  f"    {EX}(f.read(), about)\n")
    art = _on_disk(root, [("setup.py", src)])
    assert art.unshipped_exec_sites("setup.py", src) == {}, present
    assert {r for r, sev in _rules(src, art) if sev == "crit"}, present


def test_a_root_that_is_not_the_artifact_gets_no_warn_tier(tmp_path):
    """A caller falling back to the wrong directory (a whole home, say) must not have
    every target there read as absent."""
    src = _HDR + BENIGN["with_inline_text"]
    art = ShippedArtifact([("setup.py", src)], root=tmp_path)  # setup.py is not in it
    assert art.unshipped_exec_sites("setup.py", src) == {}


@pytest.mark.parametrize("name", [
    "abs_swallow", "traversal_out", "env_segment_inline", "write_then_read",
    "transformed", "spoofed_namespace",
])
def test_an_escape_never_lands_in_the_unshipped_tier(tmp_path, name):
    """The WARN tier is only for a call that meets every condition but membership; a path
    that leaves the skill, a transformed value or a spoofable namespace stays crit."""
    src = _HDR + ESCAPES[name]
    art = _on_disk(tmp_path, [("setup.py", src)])
    assert art.unshipped_exec_sites("setup.py", src) == {}, name


def test_unshipped_exec_is_a_b13_warn(tmp_path):
    home = tmp_path / "home"
    skill = home / "skills" / "demo-packager"
    skill.mkdir(parents=True)
    (home / "openclaw.json").write_text(
        (FIXTURES / "clean_b638_shipped_version_exec" / "openclaw.json").read_text()
    )
    base = FIXTURES / "clean_b638_shipped_version_exec" / "skills" / "demo-packager"
    for rel in ("SKILL.md", "setup.py"):
        (skill / rel).write_text((base / rel).read_text())
    f = _b13(home)
    assert f.status == "WARN", (f.status, f.detail)
    assert "executes a file this scan never analysed" in f.detail
    assert _TARGET in f.detail
    assert f.sub_signals and all(s.lower() in f.detail.lower() for s in f.sub_signals)


def test_function_scope_idiom_clears_with_locals():
    src = (
        "import os\n\n"
        "def get_version():\n"
        "    here = os.path.dirname(__file__)\n"
        "    ns = {}\n"
        '    with open(os.path.join(here, "demo_plugin", "__version__.py")) as f:\n'
        "        code = f.read()\n"
        f"    {EX}(code, ns)\n"
        '    return ns["__version__"]\n'
    )
    assert _crit(src) == set()


def test_straight_line_anchor_rebind_clears():
    """CLAWSECCHECK-B-638 fix round 1: `here` rebuilt across two straight-line, module-
    scope statements -- `here = os.path.dirname(__file__)` then
    `here = os.path.abspath(here)` -- must resolve exactly like the one nested
    expression `here = os.path.abspath(os.path.dirname(__file__))`."""
    src = (
        "import os\n"
        "here = os.path.dirname(__file__)\n"
        "here = os.path.abspath(here)\n\n"
        "about = {}\n"
        f'with open(os.path.join(here, "demo_plugin", "__version__.py"), "r",'
        ' encoding="utf-8") as f:\n'
        f"    {EX}(f.read(), about)\n"
    )
    assert _crit(src) == set()


def test_two_hop_path_variable_rebind_clears():
    """The reviewer's second repro: the SAME straight-line rebind, but on the variable
    holding the full joined path rather than the directory anchor."""
    src = (
        "import os\n"
        "p = os.path.dirname(__file__)\n"
        'p = os.path.join(p, "demo_plugin", "__version__.py")\n\n'
        "about = {}\n"
        f'with open(p, "r", encoding="utf-8") as f:\n'
        f"    {EX}(f.read(), about)\n"
    )
    assert _crit(src) == set()


def test_straight_line_content_rebind_clears():
    """CLAWSECCHECK-B-922: `src` rebuilt across two straight-line, module-scope
    statements -- `src = h.read()` then `src = src.decode("utf-8")` -- reading via a
    plain open()/.close() (no `with`), must resolve exactly like the one nested
    expression `h.read().decode("utf-8")`."""
    src = (
        "import os\n"
        "here = os.path.abspath(os.path.dirname(__file__))\n"
        "about = {}\n"
        'h = open(os.path.join(here, "demo_plugin", "__version__.py"), "rb")\n'
        "src = h.read()\n"
        "h.close()\n"
        'src = src.decode("utf-8")\n'
        f"{EX}(src, about)\n"
    )
    assert _crit(src) == set()


def test_straight_line_handle_rebind_clears():
    """CLAWSECCHECK-B-922: the same threading applied to `_read_call`'s own "handle bound
    once" fallback -- the file HANDLE name (not the content) rebuilt across two
    straight-line statements before its single `.read()`."""
    src = (
        "import os\n"
        "here = os.path.abspath(os.path.dirname(__file__))\n"
        "about = {}\n"
        'h = open(os.path.join(here, "demo_plugin", "wrong.py"))\n'
        'h = open(os.path.join(here, "demo_plugin", "__version__.py"))\n'
        "src = h.read()\n"
        f"{EX}(src, about)\n"
    )
    assert _crit(src) == set()


def test_function_scope_does_not_trust_a_module_global():
    """A module global read by a function can be replaced from another file after import,
    so a function's path, handle and namespace must all be its own locals."""
    src = (
        "import os\n"
        "HERE = os.path.dirname(__file__)\n\n"
        "def get_version():\n"
        "    ns = {}\n"
        '    with open(os.path.join(HERE, "demo_plugin", "__version__.py")) as f:\n'
        f"        {EX}(f.read(), ns)\n"
    )
    assert _crit(src)


def test_script_in_a_subdirectory_climbs_its_own_directory():
    """`..` may pop a directory the scanned file really sits in (the walk proved it)."""
    src = (
        "import os\n"
        "here = os.path.dirname(__file__)\n"
        f'with open(os.path.join(here, "..", "demo_plugin", "__version__.py")) as f:\n'
        f"    {EX}(f.read(), {{}})\n"
    )
    assert _crit(src, filename="scripts/build.py") == set()


# ---------------------------------------------------------------------------------------
# Escapes: each stays crit (the C-135 families, then the ones this design had to close)
# ---------------------------------------------------------------------------------------

ESCAPES = {
    # C-135 families
    "abs_swallow": f'with open(os.path.join(here, "assets", "/tmp/.cache/stage2.py")) as f:\n    {EX}(f.read(), about)\n',
    "traversal_out": f'with open(os.path.join(here, "..", "..", "tmp", "stage2.py")) as f:\n    {EX}(f.read(), about)\n',
    "dead_branch_anchor": f'with open(here if False else "/tmp/x.py") as f:\n    {EX}(f.read(), about)\n',
    # CLAWSECCHECK-B-638 fix round 1: the straight-line rebind relaxation must stay a
    # categorical rejection the moment ANY of the name's bindings crosses a branch/loop
    # boundary -- paired controls for test_straight_line_anchor_rebind_clears.
    "branch_rebound_anchor": f'if sys.argv[1:]:\n    here = "/tmp/x"\nwith {_OPEN}) as f:\n    {EX}(f.read(), about)\n',
    "loop_rebound_anchor": f'for _ in range(1):\n    here = os.path.abspath(here)\nwith {_OPEN}) as f:\n    {EX}(f.read(), about)\n',
    # CLAWSECCHECK-B-922: the content-rebind relaxation (content()'s Name branch) must
    # stay a categorical rejection the moment the SECOND straight-line binding replaces
    # `src` with something that is not itself resolved shipped content, or crosses a
    # branch/loop boundary -- paired controls for test_straight_line_content_rebind_clears.
    "content_rebound_to_env": f'h = open(os.path.join(here, "demo_plugin", "__version__.py"), "rb")\nsrc = h.read()\nh.close()\nsrc = os.environ.get("X", "")\n{EX}(src, about)\n',
    "content_rebound_in_branch": f'h = open(os.path.join(here, "demo_plugin", "__version__.py"), "rb")\nsrc = h.read()\nh.close()\nif sys.argv[1:]:\n    src = input()\n{EX}(src, about)\n',
    "content_rebound_in_loop": f'h = open(os.path.join(here, "demo_plugin", "__version__.py"), "rb")\nsrc = h.read()\nh.close()\nfor _ in range(1):\n    src = "x"\n{EX}(src, about)\n',
    # CLAWSECCHECK-B-922: the SAME relaxation applied to _read_call's own "handle bound
    # once" fallback must stay a categorical rejection too -- paired controls for
    # test_straight_line_handle_rebind_clears.
    "handle_rebound_in_branch": f'h = open(os.path.join(here, "demo_plugin", "__version__.py"))\nif sys.argv[1:]:\n    h = open("/tmp/evil.py")\nsrc = h.read()\n{EX}(src, about)\n',
    "handle_rebound_in_loop": f'h = open(os.path.join(here, "demo_plugin", "__version__.py"))\nfor _ in range(1):\n    h = open("/tmp/evil.py")\nsrc = h.read()\n{EX}(src, about)\n',
    "env_segment_inline": f'with open(os.path.join(here, os.environ["P"]), "rb") as fh:\n    {EX}(fh.read().decode(), about)\n',
    "argv_segment": f"with open(os.path.join(here, sys.argv[1])) as f:\n    {EX}(f.read(), about)\n",
    "literal_tmp": f'with open("/tmp/stage2.py") as f:\n    {EX}(f.read(), about)\n',
    # the executed value must BE the content, not something derived from it
    "transformed": f'with {_OPEN}) as f:\n    src = f.read()\nsrc = src.replace("#", "")\n{EX}(src, about)\n',
    "rebound_in_branch": f'with {_OPEN}) as f:\n    src = f.read()\nif sys.argv[1:]:\n    src = input()\n{EX}(src, about)\n',
    "partial_read": f"with {_OPEN}) as f:\n    {EX}(f.read(64), about)\n",
    "suffix_read": f"with {_OPEN}) as f:\n    f.readline()\n    {EX}(f.read(), about)\n",
    "bytes_exec": f'with {_OPEN}, "rb") as f:\n    {EX}(f.read(), about)\n',
    "lossy_decode": f'with {_OPEN}, "rb") as f:\n    {EX}(f.read().decode("utf-8", "ignore"), about)\n',
    "foreign_codec": f'with {_OPEN}, encoding="utf-7") as f:\n    {EX}(f.read(), about)\n',
    "custom_opener": f"with {_OPEN}, opener=lambda p, fl: 0) as f:\n    {EX}(f.read(), about)\n",
    "real_decoder": f'with {_OPEN}, "rb") as f:\n    {EX}(__import__("base64").b64decode(f.read()), about)\n',
    # the namespace must not carry a spoofed name into the executed file
    "spoofed_namespace": f'with {_OPEN}) as f:\n    {EX}(f.read(), {{"open": print}})\n',
    "preloaded_namespace": f'about["open"] = print\nwith {_OPEN}) as f:\n    {EX}(f.read(), about)\n',
    "namespace_handed_out": f"print(about)\nwith {_OPEN}) as f:\n    {EX}(f.read(), about)\n",
    # nothing in the file may put different bytes at the path first
    "write_then_read": f'open(os.path.join(here, "demo_plugin", "__version__.py"), "w").write("x")\nwith {_OPEN}) as f:\n    {EX}(f.read(), about)\n',
    "subprocess_fetch": f'import subprocess\nsubprocess.run(["curl", "-o", "x", "u"])\nwith {_OPEN}) as f:\n    {EX}(f.read(), about)\n',
    "network_fetch": f'from urllib.request import urlopen\nurlopen("https://example.invalid/")\nwith {_OPEN}) as f:\n    {EX}(f.read(), about)\n',
    "imports_own_module": f"import demo_plugin\nwith {_OPEN}) as f:\n    {EX}(f.read(), about)\n",
    "chdir": f'os.chdir("/tmp")\nwith {_OPEN}) as f:\n    {EX}(f.read(), about)\n',
    "os_path_rebound": f"os.path.join = lambda *a: a[-1]\nwith {_OPEN}) as f:\n    {EX}(f.read(), about)\n",
    "open_shadowed": f"def open(*a, **k):\n    return None\nwith {_OPEN}) as f:\n    {EX}(f.read(), about)\n",
    "file_rebound": f'__file__ = "/tmp/x/setup.py"\nwith {_OPEN}) as f:\n    {EX}(f.read(), about)\n',
    "star_import": f"from helpers import *\nwith {_OPEN}) as f:\n    {EX}(f.read(), about)\n",
    # lexical vs physical path disagreement
    "literal_component_popped": f'with open(os.path.join(here, "lib", "..", "demo_plugin", "__version__.py")) as f:\n    {EX}(f.read(), about)\n',
    "dirname_of_trailing_slash": f'd = os.path.dirname(os.path.join(here, "demo_plugin/"))\nwith open(os.path.join(d, "demo_plugin", "__version__.py")) as f:\n    {EX}(f.read(), about)\n',
    # a stray dynamic call in the same file is code we cannot see into
    "stray_eval": f"x = {'ev' + 'al'}(input())\nwith {_OPEN}) as f:\n    {EX}(f.read(), about)\n",
    # CLAWSECCHECK-B-922 round 2: `sole()`'s "last same-scope binding before the use
    # point wins" resolution (content()'s Name branch, round 1) assumes direct-body
    # statements execute in SOURCE order. An independent C-135 review found that a
    # frame-jump/tracer technique breaks that assumption: install a trace/profile hook
    # that rewrites `frame.f_lineno` mid-run to SKIP the second, legitimate-looking
    # `src = raw.decode(...)` rebind sole() picks statically, so the value that actually
    # reaches exec() at runtime stays the FIRST, attacker-controlled `src = "MALICIOUS"`.
    # Each variant below is the SAME content-rebind shape as
    # test_straight_line_content_rebind_clears -- which must stay clear on its own, this
    # is the paired mutation control -- plus one frame-jump primitive; every one must
    # void the carve-out (stay crit) via `_tampers()` on its own.
    "frame_jump_f_lineno_direct_store": (
        f'h = open(os.path.join(here, "demo_plugin", "__version__.py"), "rb")\n'
        'raw = h.read()\n'
        'h.close()\n'
        'src = "MALICIOUS"\n'
        'def _skip(frame, event, arg):\n'
        '    if event == "line":\n'
        '        frame.f_lineno = frame.f_lineno + 1\n'
        '    return _skip\n'
        'sys.settrace(_skip)\n'
        'src = raw.decode("utf-8")\n'
        f'{EX}(src, about)\n'
    ),
    "frame_jump_type_dunder_set": (
        f'h = open(os.path.join(here, "demo_plugin", "__version__.py"), "rb")\n'
        'raw = h.read()\n'
        'h.close()\n'
        'src = "MALICIOUS"\n'
        'def _skip(frame, event, arg):\n'
        '    if event == "line":\n'
        '        type(frame).f_lineno.__set__(frame, frame.f_lineno + 1)\n'
        '    return _skip\n'
        'sys.settrace(_skip)\n'
        'src = raw.decode("utf-8")\n'
        f'{EX}(src, about)\n'
    ),
    "frame_jump_operator_attrgetter": (
        f'h = open(os.path.join(here, "demo_plugin", "__version__.py"), "rb")\n'
        'raw = h.read()\n'
        'h.close()\n'
        'src = "MALICIOUS"\n'
        'import _operator\n'
        '_get_lineno = _operator.attrgetter("f_lineno")\n'
        'def _skip(frame, event, arg):\n'
        '    if event == "line":\n'
        '        frame.f_lineno = _get_lineno(frame) + 1\n'
        '    return _skip\n'
        'sys.settrace(_skip)\n'
        'src = raw.decode("utf-8")\n'
        f'{EX}(src, about)\n'
    ),
    "frame_jump_settrace_entry": (
        f'h = open(os.path.join(here, "demo_plugin", "__version__.py"), "rb")\n'
        'raw = h.read()\n'
        'h.close()\n'
        'src = "MALICIOUS"\n'
        'sys.settrace(\n'
        '    lambda frame, event, arg: setattr(frame, "f_lineno", frame.f_lineno + 1)\n'
        ')\n'
        'src = raw.decode("utf-8")\n'
        f'{EX}(src, about)\n'
    ),
    "frame_jump_setprofile_entry": (
        f'h = open(os.path.join(here, "demo_plugin", "__version__.py"), "rb")\n'
        'raw = h.read()\n'
        'h.close()\n'
        'src = "MALICIOUS"\n'
        'def _skip(frame, event, arg):\n'
        '    if event == "line":\n'
        '        frame.f_lineno = frame.f_lineno + 1\n'
        '    return _skip\n'
        'sys.setprofile(_skip)\n'
        'src = raw.decode("utf-8")\n'
        f'{EX}(src, about)\n'
    ),
    # A distinct route from the `sys.settrace`/`setprofile` ATTRIBUTE access the entries
    # above trigger: `from threading import settrace` binds the bare NAME, so the call
    # site (`_threading_settrace(_skip)`) is a `Name`, never an `Attribute` -- only the
    # `_TAMPER_DOTTED_MODULES` entry on the import statement itself catches this one.
    "frame_jump_threading_settrace_import": (
        f'h = open(os.path.join(here, "demo_plugin", "__version__.py"), "rb")\n'
        'raw = h.read()\n'
        'h.close()\n'
        'src = "MALICIOUS"\n'
        'from threading import settrace as _threading_settrace\n'
        'def _skip(frame, event, arg):\n'
        '    if event == "line":\n'
        '        frame.f_lineno = frame.f_lineno + 1\n'
        '    return _skip\n'
        '_threading_settrace(_skip)\n'
        'src = raw.decode("utf-8")\n'
        f'{EX}(src, about)\n'
    ),
}


@pytest.mark.parametrize("name", sorted(ESCAPES))
def test_escape_stays_crit(name):
    src = _HDR + ESCAPES[name]
    assert _crit(src), name


@pytest.mark.skipif(
    not hasattr(__import__("sys"), "monitoring"),
    reason="sys.monitoring needs Python 3.12+",
)
def test_frame_jump_via_sys_monitoring_line_callback_stays_crit():
    """CLAWSECCHECK-B-922 round 2, 7th jump variant: a `sys.monitoring` LINE callback
    (Python 3.12+) receives `(code, line_number)`, not a frame -- so reaching
    `frame.f_lineno` from inside one still needs `sys._getframe()`, which was ALREADY a
    tamper attr before this round. Deliberately no `"monitoring"` token was added to any
    tamper list (too FP-prone: it would match unrelated attribute names) -- this test
    confirms detection holds anyway, through `_getframe` and the new `f_lineno` entry,
    not through naming `sys.monitoring` itself."""
    src = (
        f'h = open(os.path.join(here, "demo_plugin", "__version__.py"), "rb")\n'
        'raw = h.read()\n'
        'h.close()\n'
        'src = "MALICIOUS"\n'
        'def _skip(code, line_number):\n'
        '    frame = sys._getframe(1)\n'
        '    frame.f_lineno = frame.f_lineno + 1\n'
        'if hasattr(sys, "monitoring"):\n'
        '    _tool_id = sys.monitoring.PROFILER_ID\n'
        '    sys.monitoring.use_tool_id(_tool_id, "b922-poc")\n'
        '    sys.monitoring.register_callback(_tool_id, sys.monitoring.events.LINE, _skip)\n'
        '    sys.monitoring.set_events(_tool_id, sys.monitoring.events.LINE)\n'
        'src = raw.decode("utf-8")\n'
        f'{EX}(src, about)\n'
    )
    assert _crit(_HDR + src)


def test_shadowed_file_parameter_stays_crit():
    src = (
        "import os\n\n"
        "def load(__file__):\n"
        "    here = os.path.dirname(__file__)\n"
        '    with open(os.path.join(here, "demo_plugin", "__version__.py")) as f:\n'
        f"        {EX}(f.read(), {{}})\n"
    )
    assert _crit(src)


@pytest.mark.parametrize("target_src,cleared", [
    ('__version__ = "1.4.2"\n__title__ = "demo"\n', True),
    ('"""Version."""\nVERSION: str = "1.4.2"\nINFO = (1, 4, 2)\n', True),
    ("import os\nHERE = os.path.dirname(__file__)\n", False),  # runs code
    ('here = "/tmp/elsewhere"\n', False),                     # rebinds a name setup.py uses
    ('__name__ = "__main__"\n', False),                       # rebinds module magic
    ('open = "x"\n', False),                                  # rebinds a builtin it reads
])
def test_no_namespace_needs_a_constants_only_target(target_src, cleared):
    """Without a namespace the target runs in THIS file's globals: it can read names its
    standalone analysis never saw bound, and rebind names this file's later code resolves
    through. Only plain literal assignments to names this file does not use are the same
    as importing it."""
    src = _HDR + f"with {_OPEN}) as f:\n    {EX}(f.read())\n"
    art = ShippedArtifact([("setup.py", src), (_TARGET, target_src)])
    assert bool(art.exact_exec_sites("setup.py", src)) is cleared


def test_a_namespace_shared_by_two_calls_is_refused():
    """The first file executed could pre-load `open` or `__file__` into the dict the second
    one then resolves through."""
    src = _HDR + (f"with {_OPEN}) as f:\n    {EX}(f.read(), about)\n"
                  f"with {_OPEN}) as g:\n    {EX}(g.read(), about)\n")
    art = ShippedArtifact([("setup.py", src), (_TARGET, _VERSION_SRC)])
    assert art.exact_exec_sites("setup.py", src) == frozenset()


@pytest.mark.parametrize("spelling,cleared", [
    ('open(os.path.join(here, "demo_plugin", "__version__.py"))', False),
    ('open(os.path.join(here, "demo_plugin", "__version__.py"), encoding="utf-8")', True),
    ('open(os.path.join(here, "demo_plugin", "__version__.py"), "rb")', True),  # .decode()
])
def test_a_locale_decoded_read_needs_an_ascii_target(spelling, cleared):
    """No encoding means the process locale, which code can switch at run time to one
    where a byte pair swallows a backslash and moves a string boundary the scan saw.
    Only an all-ASCII target is immune; an explicit UTF-8 decode always is."""
    read = "f.read().decode()" if '"rb"' in spelling else "f.read()"
    src = _HDR + f"with {spelling} as f:\n    {EX}({read}, about)\n"
    target = '__version__ = "1.4.2"  # caf\u00e9\n'
    art = ShippedArtifact([("setup.py", src), (_TARGET, target)])
    assert bool(art.exact_exec_sites("setup.py", src)) is cleared


# ---------------------------------------------------------------------------------------
# A second file can swap the content under a read this file sees only from the inside
# ---------------------------------------------------------------------------------------

_SETUP = _HDR + BENIGN["with_inline_text"]

SECOND_FILE = {
    "builtins_import": "import builtins\nbuiltins.open = print\n",
    "dunder_builtins": "__builtins__.open = print\n",
    "module_attr_store": "import setup\nsetup.open = print\n",
    "setattr": "import io\nsetattr(io, 'x', 1)\n",
    "vars": "import io\nvars(io)\n",
    "frame_globals": "import sys\nsys._getframe(0)\n",
    "sys_modules": "import sys\nsys.modules.pop('pathlib', None)\n",
    "importlib": "import importlib\n",
    "runpy": "import runpy\n",
    "mock": "from unittest import mock\n",
    "dynamic_getattr": "import os\nname = 'x'\ngetattr(os, name)\n",
    "file_string": "NOTE = 'patched __file__ here'\n",
    "stray_exec_elsewhere": f"{EX}('x = 1')\n",
    "unparseable": "def broken(:\n",
}


@pytest.mark.parametrize("name", sorted(SECOND_FILE))
def test_second_file_tampering_voids_the_carve_out(name):
    assert _crit(_SETUP, [("helper.py", SECOND_FILE[name])]), name


def test_patching_a_path_method_voids_only_the_pathlib_spelling():
    """`.read_text()` is a Path METHOD: a second file storing to it -- here through a
    parameter, so no import names the target -- changes what the read returns. The builtin
    `open()` spelling does not go through Path methods, so it keeps its carve-out; that
    scoping is deliberate, because `self.parent = ...` is common and unrelated."""
    helper = [("helper.py", "def patch(c):\n    c.read_text = print\n")]
    pathlib_setup = _HDR + BENIGN["pathlib_read_text"]
    shipped = ShippedArtifact([("setup.py", pathlib_setup), (_TARGET, _VERSION_SRC), *helper])
    assert shipped.exact_exec_sites("setup.py", pathlib_setup) == frozenset()
    assert _crit(_SETUP, helper) == set()


def test_a_harmless_second_file_does_not():
    """Control for the table above: an ordinary sibling module costs nothing."""
    helper = "import json\n\ndef load(p):\n    with open(p) as f:\n        return json.load(f)\n"
    assert _crit(_SETUP, [("helper.py", helper)]) == set()


@pytest.mark.parametrize("shadow", ["pathlib.py", "vendor/os.py", "codecs/__init__.py"])
def test_a_module_shadowing_the_read_path_voids_the_carve_out(shadow):
    """`import pathlib` next to a shipped `pathlib.py` imports the artifact's copy."""
    assert _crit(_SETUP, [(shadow, "X = 1\n")])


def test_a_notebook_is_never_a_target(tmp_path):
    """The analysed source of a notebook is its extracted cells, not the bytes on disk, so
    executing the notebook file runs content this scan did not analyse -- and it is there."""
    src = _HDR + f'with open(os.path.join(here, "nb.ipynb")) as f:\n    {EX}(f.read(), about)\n'
    art = _on_disk(tmp_path, [("setup.py", src), ("nb.ipynb", "x = 1\n")])
    assert art.exact_exec_sites("setup.py", src) == frozenset()
    assert art.unshipped_exec_sites("setup.py", src) == {}
    assert {r for r, sev in _rules(src, art) if sev == "crit"}


# ---------------------------------------------------------------------------------------
# Contract
# ---------------------------------------------------------------------------------------


def test_artifact_must_hold_the_analysed_source():
    """A caller passing a different text for the same path gets no carve-out at all."""
    src = _HDR + BENIGN["with_inline_text"]
    art = ShippedArtifact([("setup.py", src + "\n# other\n"), (_TARGET, _VERSION_SRC)])
    assert art.exact_exec_sites("setup.py", src) == frozenset()
    crit = {f.rule for f in analyze_python(src, "setup.py", artifact=art) if f.severity == "crit"}
    assert crit


def test_without_an_artifact_behaviour_is_unchanged():
    """A caller that cannot say what the artifact holds keeps the pre-B-638 verdicts."""
    src = _HDR + BENIGN["with_inline_text"]
    assert "TT5_CMD_INJECTION" in {f.rule for f in analyze_python(src, "setup.py")}
    src = _HDR + BENIGN["with_inline_decode"]
    assert not {f.rule for f in analyze_python(src, "setup.py") if f.severity == "crit"}


def test_every_production_caller_passes_the_artifact():
    """The carve-out and the tighter rule both live behind `artifact=`; a call site that
    forgets it silently reverts to the token check this task replaced."""
    for rel in ("clawseccheck/checks/_vet.py", "clawseccheck/checks/_mcp.py",
                "clawseccheck/adjudication/_builder.py"):
        text = (REPO / rel).read_text()
        calls = re.findall(r"analyze_python\(([^()]*(?:\([^()]*\)[^()]*)*)\)", text)
        calls = [c for c in calls if c.strip() and "source: str" not in c]
        assert calls, rel
        assert all("artifact=" in c for c in calls), (rel, calls)


# ---------------------------------------------------------------------------------------
# --vet-plugin: loose plugin Python gets the same answer
# ---------------------------------------------------------------------------------------


def _plugin(root: Path, setup_src: str, *, ship_version: bool = True) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "openclaw.plugin.json").write_text(json.dumps({
        "id": "demo-plugin", "name": "demo-plugin", "version": "1.0.0",
        "description": "A demo plugin.", "skills": ["skills"],
        "configSchema": {"type": "object", "properties": {}},
    }))
    skill = root / "skills" / "demo"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: demo\ndescription: Formats text.\n---\n\nFormats text locally.\n"
    )
    (root / "setup.py").write_text(setup_src)
    if ship_version:
        (root / "demo_plugin").mkdir()
        (root / "demo_plugin" / "__init__.py").write_text('"""Demo."""\n')
        (root / "demo_plugin" / "__version__.py").write_text(_VERSION_SRC)
    return root


def test_plugin_root_setup_py_exec_of_shipped_version_is_not_a_fail(tmp_path):
    setup = (FIXTURES / "clean_b638_shipped_version_exec" / "skills" / "demo-packager"
             / "setup.py").read_text()
    out = vet_plugin(_plugin(tmp_path / "p", setup))
    assert out.status != FAIL, out.detail[:300]


def test_plugin_root_setup_py_exec_of_unshipped_path_warns(tmp_path):
    setup = (FIXTURES / "clean_b638_shipped_version_exec" / "skills" / "demo-packager"
             / "setup.py").read_text()
    out = vet_plugin(_plugin(tmp_path / "p", setup, ship_version=False))
    assert out.status == "WARN", out.detail[:300]
    assert "did not analyse as Python" in out.detail, out.detail[:300]


def test_plugin_env_joined_path_fails(tmp_path):
    setup = (FIXTURES / "bad_b638_exec_env_joined_path" / "skills" / "demo-packager"
             / "setup.py").read_text()
    out = vet_plugin(_plugin(tmp_path / "p", setup))
    assert out.status == FAIL, out.detail[:300]
