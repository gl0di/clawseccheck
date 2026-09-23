"""B-850 -- the artifact-containment ALLOWLIST recognizer that replaces B-752's
blocklist (`_path_expr_is_dunder_file_relative` and its supporting predicates) after
six C-135 rejections on task/b-850, each patch closing one bypass shape while another
stayed open or opened up. A blocklist asks "does a RECOGNIZED escape shape prove this
leaves the artifact?" and is permissive by default: an unrecognized shape gets the
exemption for free. This recognizer asks the opposite question -- "is this POSITIVELY
a construction from the `__file__` anchor that provably stays inside the artifact?" --
over a closed set of syntactic shapes; anything outside that set gets no exemption at
all (NOT_ANCHORED).

Four verdicts, worst-wins: BOUNDED (exempt, today's info-level DANGEROUS_SINK finding)
< UNPROVEN (anchored, a segment is runtime-computed -- WARN-only ARTIFACT_READ_UNPROVEN
/ B394, never FAIL) < ESCAPES (proven to leave the artifact, or a segment is a static
value hidden behind an unfoldable expression) / NOT_ANCHORED (not anchored on
`__file__` at all, or an unrecognized shape) -- the last two leave the pre-existing
OBFUSCATED_EXEC / TT5_CMD_INJECTION crit standing.

The corpus below is the architect's validated design corpus (F1-F6/G1-G11 are the six
named round-6 gaps plus further gaps found reading the code; B1-B20 are the benign
idioms the recognizer must never convict), reproduced here as the test's own source of
truth rather than imported from anywhere outside the repo. Two entries (B2, B20) are
corrected from the architect's full-mode expectation to strict mode's documented
behavior -- see `test_module_level_anchor_referenced_inside_a_function_is_unresolved_
in_strict_mode` for why, and the "B-850: artifact-containment ALLOWLIST recognizer"
module comment in skillast.py for the STRICT-vs-full-mode distinction (full mode is an
explicitly deferred follow-up, not implemented here).

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.checks import (
    PASS,
    WARN,
    check_artifact_read_unproven,
    check_installed_skills,
)
from clawseccheck.collector import collect
from clawseccheck.skillast import analyze_python

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

# Every case below wraps a path expression in the canonical decode-then-exec idiom:
# `with open(<path_expr>) as fh: exec(fh.read().decode("utf-8"), {})`. HDR imports
# everything a case might reference (os, sys, base64, Path, PurePath, dirname, join) --
# omitting one of these was two of the four known discrepancies the architect found in
# the pre-B-850 pinned tests (a missing PurePath import made a corpus case fail to
# resolve for a reason that had nothing to do with the recognizer under test).
HDR = (
    "import os\nimport sys\nimport base64\nfrom pathlib import Path, PurePath\n"
    "from os.path import dirname, join\n"
)
H = "here = os.path.dirname(__file__)\n"


def _rd(path_expr: str, prelude: str = "") -> str:
    return (
        HDR + prelude
        + f'with open({path_expr}, "rb") as fh:\n'
        f'    exec(fh.read().decode("utf-8"), {{}})\n'
    )


def _verdict(src: str, relpath: str) -> str:
    """'convict' (a crit finding), 'warn' (ARTIFACT_READ_UNPROVEN, no crit), or
    'clean' (neither) -- the three outcomes every case below is judged against."""
    findings = analyze_python(src, relpath)
    if any(f.severity == "crit" for f in findings):
        return "convict"
    if any(f.rule == "ARTIFACT_READ_UNPROVEN" for f in findings):
        return "warn"
    return "clean"


# ---------------------------------------------------------------------------------
# F1-F6: the six named round-6 gaps (each with lettered sub-variants) -- every one
# must convict (ESCAPES or NOT_ANCHORED: the pre-existing OBFUSCATED_EXEC crit stands).
# ---------------------------------------------------------------------------------
_F_CASES = [
    ("F1-index-trick", "mod.py", _rd("'/tmp/payload.py' + __file__[:0]")),
    ("F1b-index-trick-reversed", "mod.py", _rd("__file__[:0] + '/tmp/payload.py'")),
    ("F1c-tuple-index-pick", "pkg/mod.py", _rd("('/tmp/payload.py', __file__)[0]")),
    ("F2-pathlib-multi-arg-absolute-tail", "mod.py", _rd("Path(dirname(__file__), '/tmp/payload.py')")),
    ("F2b-purepath-absolute-tail", "pkg/mod.py", _rd("PurePath(here, 'data', '/tmp/payload.py')", H)),
    ("F3-parent-parent-sibling-dir", "mod.py", _rd("Path(__file__).parent.parent / 'victim' / 'secrets.py'")),
    ("F3b-nested-dirname-sibling-dir", "mod.py",
     _rd("os.path.join(os.path.dirname(os.path.dirname(__file__)), 'victim', 'secrets.py')")),
    ("F3c-parents-subscript-sibling-dir", "pkg/mod.py", _rd("Path(__file__).parents[2] / 'victim' / 'secrets.py'")),
    ("F4-absolute-then-relative-cancel", "mod.py", _rd("Path(here, 'a', 'b', 'c', '/tmp/x', '..', '..', 'p.py')", H)),
    ("F4b-fstring-absolute-then-relative", "mod.py", _rd("f\"{Path(here, 'a', 'b', '/tmp')}/../../p.py\"", H)),
    ("F4c-nested-path-then-join-relative", "mod.py", _rd("os.path.join(Path(here, 'a', '/tmp'), 'p.py')", H)),
    ("F5-rebind-to-traversal-literal", "pkg/mod.py",
     _rd("os.path.join(here, p)", H + "p = 'data.py'\np = '../../../tmp/x.py'\n")),
    ("F5b-rebind-anchor-itself", "pkg/mod.py", _rd("os.path.join(here, 'v.py')", H + "here = '/tmp'\n")),
    ("F5c-conditional-rebind-to-traversal", "pkg/mod.py",
     _rd("os.path.join(here, p)", H + "p = 'data.py'\nif os.environ.get('X'):\n    p = '../../../tmp/x.py'\n")),
    ("F6-nested-join-net-escape", "pkg/mod.py",
     _rd("os.path.join(os.path.join(os.path.dirname(__file__), '..', '..'), '..', 'tmp', 'x.py')")),
    ("F6b-starred-splice-escape", "pkg/mod.py",
     _rd("os.path.join(*[os.path.dirname(__file__), '..', '..', 'tmp', 'x.py'])")),
    ("F6c-starred-variable-splice-escape", "pkg/mod.py",
     _rd("os.path.join(here, *parts)", H + "parts = ['..', '..', 'tmp', 'x.py']\n")),
]

# ---------------------------------------------------------------------------------
# G1-G11: further gaps found reading the code (architect pass). G10 is the sole WARN
# (anchored, genuinely runtime-computed, no proof either way); every other one convicts.
# ---------------------------------------------------------------------------------
_G_CASES = [
    ("G1-folded-str-join-segment", "pkg/mod.py", "convict",
     _rd("os.path.join(here, seg)", H + "seg = '/'.join(['..', '..', '..', 'tmp', 'x.py'])\n")),
    ("G2-os-pardir-constant", "pkg/mod.py", "convict",
     _rd("os.path.join(here, os.pardir, os.pardir, 'tmp', 'x.py')", H)),
    ("G3-concat-no-separator-sibling-dir", "mod.py", "convict",
     _rd("os.path.dirname(__file__) + '_evil/x.py'")),
    ("G4-receiver-ifexp-either-branch-escapes", "pkg/mod.py", "convict",
     HDR + H + "flag = os.environ.get('F')\n"
     "exec((open(os.path.join(here, 'v.py'), 'rb') if flag else "
     "open('/tmp/x.py', 'rb')).read().decode(), {})\n"),
    ("G5-handle-boolop-either-branch-escapes", "pkg/mod.py", "convict",
     HDR + H + "flag = os.environ.get('F')\n"
     "with open(os.path.join(here, 'v.py'), 'rb') as a, open('/tmp/x.py', 'rb') as b:\n"
     "    exec((a if flag else b).read().decode(), {})\n"),
    ("G6-handle-name-rebound-to-escape", "pkg/mod.py", "convict",
     HDR + H + "fh = open(os.path.join(here, 'v.py'), 'rb')\n"
     "fh = open('/tmp/x.py', 'rb')\n"
     "exec(fh.read().decode(), {})\n"),
    ("G7-dunder-file-itself-rebound", "pkg/mod.py", "convict",
     _rd("os.path.join(os.path.dirname(__file__), 'v.py')", "__file__ = '/tmp/evil/x.py'\n")),
    ("G8-base64-hidden-static-segment", "pkg/mod.py", "convict",
     _rd("os.path.join(here, base64.b64decode('Li4vLi4vLi4vdG1wL3gucHk=').decode())", H)),
    ("G9-fake-dirname-receiver-not-os-path", "pkg/mod.py", "convict",
     _rd("os.path.join(E.dirname(__file__), 'v.py')",
         "class E:\n    @staticmethod\n    def dirname(p):\n        return '/tmp'\n")),
    ("G10-env-var-tail-segment", "pkg/mod.py", "warn",
     _rd("os.path.join(here, os.environ['P'])", H)),
    ("G11-param-tail-literal-callsite-escapes", "pkg/mod.py", "convict",
     HDR + H + "def load(n):\n"
     "    with open(os.path.join(here, n), 'rb') as fh:\n"
     "        exec(fh.read().decode(), {})\n"
     "load('../../../tmp/x.py')\n"),
]


@pytest.mark.parametrize("case_id,relpath,src", _F_CASES)
def test_f_case_convicts(case_id, relpath, src):
    assert _verdict(src, relpath) == "convict", case_id


@pytest.mark.parametrize("case_id,relpath,expect,src", _G_CASES)
def test_g_case(case_id, relpath, expect, src):
    assert _verdict(src, relpath) == expect, case_id


# ---------------------------------------------------------------------------------
# B1-B20: benign idioms the recognizer must never convict ("clean" = fully exempt;
# "nocrit" = clean OR warn is acceptable, never a crit; "same" = no __file__ involved
# at all, so B-850 cannot have changed the (already-convicting) baseline verdict).
# ---------------------------------------------------------------------------------
_BENIGN_CASES = [
    ("B1-plain-nested", "pkg/mod.py", "clean", _rd("os.path.join(os.path.dirname(__file__), 'data', 'v.py')")),
    ("B1-plain-root", "mod.py", "clean", _rd("os.path.join(os.path.dirname(__file__), 'data', 'v.py')")),
    ("B3-home-config-string", "mod.py", "same", _rd("os.path.expanduser('~/.config/myskill/settings.py')")),
    ("B3b-home-config-pathlib", "mod.py", "same", _rd("Path.home() / '.config' / 'myskill' / 'settings.py'")),
    ("B4-meipass-getattr-default", "mod.py", "clean",
     _rd("os.path.join(base, 'data', 'v.py')",
         "base = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))\n")),
    ("B4b-meipass-ifstmt-frozen-check", "mod.py", "clean",
     _rd("os.path.join(base, 'data', 'v.py')",
         "if getattr(sys, 'frozen', False):\n    base = sys._MEIPASS\n"
         "else:\n    base = os.path.dirname(os.path.abspath(__file__))\n")),
    ("B5-resource-dir-helper-file-param", "mod.py", "clean",
     _rd("os.path.join(resource_dir(__file__, 'data/tpl'), 'template.py')",
         "def resource_dir(anchor, rel):\n    return os.path.join(os.path.dirname(anchor), rel)\n")),
    ("B6-config-loader-single-hop", "mod.py", "clean",
     _rd("cfg_path", "cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config', 'settings.py')\n")),
    ("B8-setup-py-idiom", "setup.py", "clean",
     _rd("os.path.join(here, 'pkg', '__version__.py')", "here = os.path.abspath(os.path.dirname(__file__))\n")),
    ("B9-or-dot-truthiness-idiom", "mod.py", "clean",
     _rd("os.path.join(here, 'v.py')", "here = os.path.dirname(__file__) or '.'\n")),
    ("B10-location-idiom", "mod.py", "clean",
     _rd("os.path.join(__location__, 'v.py')",
         "__location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))\n")),
    ("B11-sanitiser-strips-slash", "mod.py", "nocrit",
     HDR + "def load(raw):\n    here = os.path.dirname(__file__)\n"
     "    with open(os.path.join(here, raw.replace('/', '_')), 'rb') as fh:\n"
     "        exec(fh.read().decode('utf-8'), {})\n"),
    ("B11b-sanitiser-strips-dotdot", "mod.py", "nocrit",
     HDR + H + "name = raw_name.replace('..', '_')\n"
     "with open(os.path.join(here, name), 'rb') as f:\n    exec(f.read().decode())\n"),
    ("B12-slash-join-literal-not-absolute", "pkg/mod.py", "clean",
     _rd("os.path.join(here, name)", H + "name = '/'.join(['data', 'v.py'])\n")),
    ("B13-with-name-swap", "mod.py", "clean", _rd("Path(__file__).with_name('impl.py')")),
    ("B14-resolve-parent-parent", "scripts/run.py", "clean",
     _rd("Path(__file__).resolve().parent.parent / 'lib' / 'v.py'")),
    ("B15-trailing-sep-concat", "mod.py", "clean",
     _rd("os.path.join(os.path.dirname(__file__), '') + 'v.py'")),
    ("B16-fstring-literal-tail", "pkg/mod.py", "clean", _rd("f'{here}/data/v.py'", H)),
    ("B17-one-up-nested-stays-inside", "pkg/mod.py", "clean", _rd("os.path.join(here, '..', 'shared', 'v.py')", H)),
    ("B18-traversal-cancels-itself", "mod.py", "clean",
     _rd("os.path.join(here, 'assets', '..', 'data', 'v.py')", H)),
    ("B19-anchor-and-read-same-function-scope", "plugin.py", "clean",
     HDR + "def helper():\n    here = os.path.dirname(__file__)\n"
     "    with open(os.path.join(here, 'data', 'v.py'), 'rb') as fh:\n"
     "        exec(fh.read().decode('utf-8'), {})\n"),
]


@pytest.mark.parametrize("case_id,relpath,expect,src", _BENIGN_CASES)
def test_benign_idiom(case_id, relpath, expect, src):
    got = _verdict(src, relpath)
    if expect == "clean":
        assert got == "clean", (case_id, got)
    elif expect == "nocrit":
        assert got in ("clean", "warn"), (case_id, got)
    elif expect == "same":
        # No __file__ anywhere in the expression: NOT_ANCHORED both before and after
        # B-850, so the decode signal stays armed and OBFUSCATED_EXEC still convicts.
        # This is not a B-850 claim -- it is a non-regression check on a case the
        # recognizer was never meant to touch.
        assert got == "convict", (case_id, got)


# ---------------------------------------------------------------------------------
# STRICT vs. full mode: a module-level anchor VALUE referenced from inside a function
# stays unresolved in strict mode (only module-level imports, module-level `def`s, and
# `__file__` itself resolve across that boundary) -- matching this project's pre-B-850
# production behavior for this exact shape (the old blocklist's `_scope_own_assigns`
# only ever looked at the enclosing function's OWN body, never the module's). The
# architect's corpus labels both of these "exempt"/"nocrit" against FULL mode (which
# also resolves module-level values inside functions); full mode is an explicitly
# deferred follow-up, not implemented here, so under STRICT mode both convict --
# correctly, per the module comment in skillast.py, and with no regression against
# today's shipped behavior.
# ---------------------------------------------------------------------------------


def test_module_level_anchor_referenced_inside_a_function_is_unresolved_in_strict_mode():
    src = (
        HDR
        + "HERE = os.path.dirname(os.path.abspath(__file__))\n"
        "def main():\n"
        "    with open(os.path.join(HERE, 'v.py'), 'rb') as fh:\n"
        "        exec(fh.read().decode('utf-8'), {})\n"
    )
    assert _verdict(src, "mod.py") == "convict"


def test_module_level_here_referenced_inside_a_different_function_is_unresolved():
    src = (
        HDR + H
        + "def load(name):\n"
        "    with open(os.path.join(here, 'plugins', f'{name}.py'), 'rb') as fh:\n"
        "        exec(fh.read().decode(), {})\n"
        "load('../../../tmp/x.py')\n"
    )
    assert _verdict(src, "mod.py") == "convict"


# ---------------------------------------------------------------------------------
# The `or`-with-a-relative-literal-first idiom actually reads a CWD-relative path, not
# an artifact-relative one -- it must NOT be exempt. (One of the four known pinned-test
# discrepancies the architect found: a prior draft of this exact case pinned a FALSE
# CLEAN. `"data/v.py"` is a non-empty literal, so `or` short-circuits to it -- the
# right-hand `here` never runs -- giving a CWD-relative root, not the __file__ anchor.)
# ---------------------------------------------------------------------------------


def test_or_expression_with_a_relative_literal_first_is_not_exempt():
    src = _rd('"data/v.py" or here', H)
    assert _verdict(src, "mod.py") == "convict"


# ---------------------------------------------------------------------------------
# Adversarial bypass shapes (a representative slice of the architect's 37-shape attack
# battery) -- none may ever come back "clean" (a FALSE CLEAN on a read that genuinely
# leaves the artifact).
# ---------------------------------------------------------------------------------
_ATTACK_CASES = [
    ("attack-loop-climb", "pkg/mod.py",
     _rd("p", H + "p = here\nfor _ in range(5):\n    p = os.path.dirname(p)\np = os.path.join(p, 'x.py')\n")),
    ("attack-while-climb", "pkg/mod.py",
     _rd("os.path.join(p, 'x.py')", H + "p = here\nwhile len(p) > 1:\n    p = os.path.join(p, '..')\n")),
    ("attack-global-rebind", "pkg/mod.py",
     HDR + "HERE = os.path.dirname(__file__)\n"
     "def evil():\n    global HERE\n    HERE = '/tmp'\nevil()\n"
     "with open(os.path.join(HERE, 'x.py'), 'rb') as fh:\n    exec(fh.read().decode(), {})\n"),
    ("attack-augassign-traversal", "pkg/mod.py",
     _rd("p", H + "p = here\np += '/../../../tmp/x.py'\n")),
    ("attack-percent-format-traversal", "pkg/mod.py",
     _rd("'%s/%s' % (here, '../../../tmp/x.py')", H)),
    ("attack-str-format-traversal", "pkg/mod.py",
     _rd("'{}/../../../tmp/x.py'.format(here)", H)),
    ("attack-sep-join-traversal", "pkg/mod.py",
     _rd("os.sep.join([here, '..', '..', '..', 'tmp', 'x.py'])", H)),
    ("attack-helper-returns-absolute", "pkg/mod.py",
     _rd("f(__file__)", "def f(a):\n    return '/tmp/x.py'\n")),
    ("attack-helper-param-swap", "pkg/mod.py",
     _rd("f(__file__, '/tmp/x.py')", "def f(a, b):\n    return b\n")),
    ("attack-lambda-helper", "pkg/mod.py",
     _rd("f(here)", H + "f = lambda a: '/tmp/x.py'\n")),
    ("attack-dict-lookup-traversal", "pkg/mod.py",
     _rd("os.path.join(here, d['k'])", H + "d = {'k': '../../../tmp/x.py'}\n")),
    ("attack-tuple-unpack-traversal", "pkg/mod.py",
     _rd("os.path.join(a, b)", H + "a, b = here, '../../../tmp/x.py'\n")),
    ("attack-del-then-rebind", "pkg/mod.py",
     _rd("os.path.join(here, 'x.py')", H + "del here\nhere = '/tmp'\n")),
    ("attack-decoy-dunder-file-param", "pkg/mod.py",
     HDR + "def f(__file__):\n"
     "    with open(os.path.join(os.path.dirname(__file__), 'v.py'), 'rb') as fh:\n"
     "        exec(fh.read().decode(), {})\nf('/tmp/x/y.py')\n"),
    ("attack-realpath-escape", "a/b/mod.py",
     _rd("os.path.realpath(os.path.join(here, '..', '..', '..', 'x.py'))", H)),
    ("attack-backslash-traversal", "pkg/mod.py",
     _rd("os.path.join(here, '..\\\\..\\\\..\\\\tmp\\\\x.py')", H)),
    ("attack-home-in-join", "pkg/mod.py",
     _rd("os.path.join(here, os.path.expanduser('~/x.py'))", H)),
    ("attack-chr-built-traversal", "pkg/mod.py",
     _rd("os.path.join(here, chr(46)*2 + '/' + chr(46)*2 + '/../tmp/x.py')", H)),
]


@pytest.mark.parametrize("case_id,relpath,src", _ATTACK_CASES)
def test_attack_shape_never_reads_clean(case_id, relpath, src):
    assert _verdict(src, relpath) != "clean", case_id


# ---------------------------------------------------------------------------------
# Wiring: the checks/_vet.py B394 bucket (WARN, never FAIL) and the standalone
# check_artifact_read_unproven (SKILL_CONTENT_RING member).
# ---------------------------------------------------------------------------------


def test_b13_bad_artifact_read_unproven_is_warn_not_fail():
    ctx = collect(FIXTURES / "bad_b394_artifact_read_unproven")
    f = check_installed_skills(ctx)
    assert f.status == WARN
    assert f.severity == "MEDIUM"


def test_b13_clean_bounded_plugin_read_stays_pass():
    ctx = collect(FIXTURES / "clean_b394_bounded_plugin_read")
    f = check_installed_skills(ctx)
    assert f.status == PASS


def test_standalone_check_bad_fixture_warns():
    ctx = collect(FIXTURES / "bad_b394_artifact_read_unproven")
    f = check_artifact_read_unproven(ctx)
    assert f.status == WARN
    assert f.id == "B394"


def test_standalone_check_clean_fixture_passes():
    ctx = collect(FIXTURES / "clean_b394_bounded_plugin_read")
    f = check_artifact_read_unproven(ctx)
    assert f.status == PASS
    assert f.id == "B394"
