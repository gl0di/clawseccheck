"""CLAWSECCHECK-B-914 — no `tempfile.mkdtemp` under `tests/` without a justifying comment.

B-914: 27 files under `tests/` called `tempfile.mkdtemp(...)` directly (39 call sites)
instead of using pytest's own `tmp_path`/`tmp_path_factory` fixtures, writing real
directories (each carrying an `openclaw.json`, sometimes more) into the SHARED SYSTEM
temp dir — and 25 of the 27 never cleaned up (no `rmtree`, no `TemporaryDirectory`
context manager), so they piled up unbounded on dev boxes and CI runners. A shared
system-temp root also risks races between parallel test runs, which pytest's own
per-test `tmp_path` tree does not.

All 27 were converted. Two shapes did the conversion:
  * a helper/test used ONCE (or a handful of times, threadable through each caller's own
    signature) -> `tmp_path` passed straight through, matching the pattern already used
    throughout this suite (e.g. tests/test_b017.py).
  * a plain, non-fixture HELPER FUNCTION called from many (10-30+) test bodies, where
    threading `tmp_path` through every call site would be pure churn -> a
    `@pytest.fixture(autouse=True, scope="module")` bridge that stashes the session-scoped
    `tmp_path_factory` into a module-level global the helper reads, so every throwaway
    home still lands inside pytest's own tmp tree without touching each caller. This
    mirrors an idiom already established in this suite: `_oracle_scratch` in
    tests/test_toolgrant_dist_grounding.py, and `_isolate_local_store` in conftest.py.

Two call sites remain, each with a same/adjacent-line justifying comment naming why
`tmp_path`/`tmp_path_factory` genuinely cannot substitute — the carve-out B-914 itself
allows ("except where a comment justifies it"):
  * tests/_harnessoracle.py — this module doubles as a standalone CLI
    (`python3.12 tests/_harnessoracle.py --write`), run OUTSIDE pytest to regenerate the
    pinned battery, so no tmp_path/tmp_path_factory fixture is ever available there.
    Self-cleans via a try/finally `shutil.rmtree`.
  * tests/test_vet_plan_advise.py — needs a path verifiably under
    `tempfile.gettempdir()` specifically (the real-quarantine-path advice branch), which
    pytest's `tmp_path` is not guaranteed to be on every platform. Cleaned up via
    `finally: real_tmp.rmdir()`.

This guard is mechanical, not semantic: it does not judge whether a NEW justification is
actually sound (that is a human/reviewer question) — it only enforces that one is written
down, in the same place the exception lives, so a bare re-introduction of the pre-B-914
pattern fails loudly instead of quietly regrowing the leak this task fixed. Same spirit as
tests/test_public_boundary.py's marker scan and tests/test_module_layout.py's placement
lint: AST-based (never a plain text grep, so a docstring/string-literal MENTION of
"tempfile.mkdtemp" is never mistaken for an actual call — see
test_a_docstring_mention_is_never_mistaken_for_a_call below), stdlib-only, offline,
deterministic, no fixtures, no subprocess.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.mechanical

REPO_ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = REPO_ROOT / "tests"

#: A justifying comment must contain this token, so an unrelated nearby comment (written
#: for a different statement entirely) can never accidentally satisfy the gate.
_JUSTIFICATION_TOKEN = "mkdtemp"

#: The exact, reviewed set of tests/ files allowed to carry a justified mkdtemp() call.
#: A new entry here means a NEW accepted residual and deserves the same review the two
#: originals got (see the module docstring) -- not a place to park an unreviewed one.
_ACCEPTED_RESIDUALS = frozenset({
    "tests/_harnessoracle.py",
    "tests/test_vet_plan_advise.py",
})


def _mkdtemp_call_lines(source: str) -> "list[int]":
    """1-based line numbers of every `<anything>.mkdtemp(...)` CALL in *source* -- an AST
    walk, not a text grep, so a docstring or string-literal MENTION of
    "tempfile.mkdtemp" (tests/_hermledger.py's own module docstring; a source string
    tests/test_monitor_detection_gate.py asserts appears in a DIFFERENT, out-of-scope
    file, scripts/monitor_detection_gate.py) is never mistaken for a real call site."""
    tree = ast.parse(source)
    lines = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "mkdtemp":
                lines.append(node.lineno)
    return lines


def _is_justified(source_lines: "list[str]", lineno: int) -> bool:
    """A call at 1-based *lineno* is justified when a `#` comment naming "mkdtemp" sits on
    that same line, one line below it, or anywhere in the CONTIGUOUS block of comment
    lines immediately above it -- "same or an adjacent line", B-914's own wording, read as
    a multi-line comment block counting as adjacent (the same rule
    tests/test_monitor_detection_gate.py's own "CONTIGUOUS comment block directly above"
    check uses). Stops at the first non-comment line walking upward, so a comment written
    for a DIFFERENT, earlier statement can never silently justify a new, unjustified call
    two statements later."""
    idx = lineno - 1
    if 0 <= idx < len(source_lines):
        line = source_lines[idx]
        hashpos = line.find("#")
        if hashpos != -1 and _JUSTIFICATION_TOKEN in line[hashpos:].lower():
            return True
    below = idx + 1
    if 0 <= below < len(source_lines):
        stripped = source_lines[below].strip()
        if stripped.startswith("#") and _JUSTIFICATION_TOKEN in stripped.lower():
            return True
    j = idx - 1
    while j >= 0 and source_lines[j].strip().startswith("#"):
        if _JUSTIFICATION_TOKEN in source_lines[j].lower():
            return True
        j -= 1
    return False


def _find_unjustified(path: Path) -> "list[int]":
    source = path.read_text(encoding="utf-8")
    source_lines = source.splitlines()
    return [
        lineno for lineno in _mkdtemp_call_lines(source)
        if not _is_justified(source_lines, lineno)
    ]


# --------------------------------------------------------------------------------------
# the gate

def test_no_unjustified_mkdtemp_under_tests():
    """A NEW `tempfile.mkdtemp(...)` call under `tests/` must either be replaced with
    `tmp_path`/`tmp_path_factory` (see the module docstring's two worked patterns) or
    carry a same/adjacent-line comment explaining why it genuinely cannot be."""
    violations = []
    for path in sorted(TESTS_DIR.glob("*.py")):
        for lineno in _find_unjustified(path):
            violations.append(f"{path.relative_to(REPO_ROOT)}:{lineno}")
    assert not violations, (
        "tempfile.mkdtemp() call(s) under tests/ with no justifying same/adjacent-line "
        "comment (CLAWSECCHECK-B-914 -- writes outside pytest's own tmp tree, into the "
        "shared system temp dir, usually never cleaned up):\n  " + "\n  ".join(violations) +
        "\n\nEither convert the call to tmp_path/tmp_path_factory (see conftest.py's "
        "_isolate_local_store or tests/test_toolgrant_dist_grounding.py's _oracle_scratch "
        "for the pattern to use when a plain helper is called from many test bodies), or "
        "add a comment on the same/adjacent line naming 'mkdtemp' and explaining why "
        "tmp_path genuinely cannot substitute here (see tests/_harnessoracle.py or "
        "tests/test_vet_plan_advise.py for worked examples)."
    )


def test_the_accepted_residuals_are_exactly_this_reviewed_set():
    """Names the surviving exceptions, so a THIRD one appearing here -- even with a
    comment attached -- gets noticed rather than silently piling up. Not a hard block on
    a new, sound exception ever existing, but a deliberate tripwire: extend
    _ACCEPTED_RESIDUALS only after giving the new comment's justification the same
    scrutiny the two originals got (module docstring)."""
    justified_files = set()
    for path in sorted(TESTS_DIR.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        source_lines = source.splitlines()
        calls = _mkdtemp_call_lines(source)
        if calls and all(_is_justified(source_lines, ln) for ln in calls):
            justified_files.add(str(path.relative_to(REPO_ROOT)))
    assert justified_files == set(_ACCEPTED_RESIDUALS), (
        f"the set of tests/ files carrying a justified tempfile.mkdtemp() call changed: "
        f"now {sorted(justified_files)}, expected {sorted(_ACCEPTED_RESIDUALS)} -- update "
        "_ACCEPTED_RESIDUALS only after reviewing the new/removed justification."
    )


# --------------------------------------------------------------------------------------
# unit-level controls on the checker itself -- a control that cannot fail controls
# nothing (same rule tests/test_hermeticity_gate.py's
# test_classify_recognizes_repo_tmp_and_interpreter_roots exists to satisfy).

def test_an_unjustified_call_is_detected():
    source = (
        "import tempfile\n"
        "def f():\n"
        "    d = tempfile.mkdtemp(prefix='x-')\n"
        "    return d\n"
    )
    lines = source.splitlines()
    calls = _mkdtemp_call_lines(source)
    assert calls == [3]
    assert not _is_justified(lines, 3)


def test_a_same_line_justification_is_accepted():
    source = (
        "import tempfile\n"
        "def f():\n"
        "    d = tempfile.mkdtemp(prefix='x-')  # mkdtemp: legitimate, see docstring\n"
        "    return d\n"
    )
    lines = source.splitlines()
    calls = _mkdtemp_call_lines(source)
    assert _is_justified(lines, calls[0])


def test_an_adjacent_line_justification_is_accepted():
    source = (
        "import tempfile\n"
        "def f():\n"
        "    # mkdtemp: legitimate, see docstring\n"
        "    d = tempfile.mkdtemp(prefix='x-')\n"
        "    return d\n"
    )
    lines = source.splitlines()
    calls = _mkdtemp_call_lines(source)
    assert _is_justified(lines, calls[0])


def test_a_multiline_comment_block_above_is_accepted_if_any_line_mentions_mkdtemp():
    """The real shape used in tests/_harnessoracle.py and tests/test_vet_plan_advise.py:
    a several-line explanation immediately above the call, only the first line of which
    names "mkdtemp" -- must still count as adjacent."""
    source = (
        "import tempfile\n"
        "def f():\n"
        "    # tempfile.mkdtemp, not tmp_path: this needs a real system temp dir path\n"
        "    # because some other reason spans a second explanatory line here too.\n"
        "    d = tempfile.mkdtemp(prefix='x-')\n"
        "    return d\n"
    )
    lines = source.splitlines()
    calls = _mkdtemp_call_lines(source)
    assert _is_justified(lines, calls[0])


def test_a_comment_block_for_an_earlier_unrelated_statement_does_not_justify():
    """The upward walk stops at the first non-comment line -- a comment block belonging
    to a PRIOR, unrelated statement must not leak forward onto a later, unjustified
    call two statements down."""
    source = (
        "import tempfile\n"
        "def f():\n"
        "    # mkdtemp: this explains the PREVIOUS line, not the one below\n"
        "    x = 1\n"
        "    d = tempfile.mkdtemp(prefix='x-')\n"
        "    return d\n"
    )
    lines = source.splitlines()
    calls = _mkdtemp_call_lines(source)
    assert not _is_justified(lines, calls[0])


def test_a_docstring_mention_is_never_mistaken_for_a_call():
    """tests/_hermledger.py's own shape: prose containing the literal text
    "tempfile.mkdtemp()" inside a triple-quoted string, not an actual call."""
    source = (
        '"""Uses ``tempfile.mkdtemp()`` internally, see elsewhere."""\n'
        "def f():\n"
        "    return 1\n"
    )
    assert _mkdtemp_call_lines(source) == []


def test_a_string_literal_mention_is_never_mistaken_for_a_call():
    """tests/test_monitor_detection_gate.py's own shape: a plain assertion that some
    OTHER file's SOURCE TEXT contains the string "tempfile.mkdtemp", not a call here."""
    source = (
        "def test_x():\n"
        "    src = 'whatever'\n"
        "    assert \"tempfile.mkdtemp\" in src\n"
    )
    assert _mkdtemp_call_lines(source) == []


def test_an_unrelated_nearby_comment_does_not_justify():
    """A `#` comment sits on the adjacent line but never mentions mkdtemp at all -- must
    not satisfy the gate. Without this, any comment anywhere near a NEW, unjustified call
    could accidentally silence this guard."""
    source = (
        "import tempfile\n"
        "def f():\n"
        "    # this line does something else entirely\n"
        "    d = tempfile.mkdtemp(prefix='x-')\n"
        "    return d\n"
    )
    lines = source.splitlines()
    calls = _mkdtemp_call_lines(source)
    assert not _is_justified(lines, calls[0])


def test_the_accepted_residual_files_actually_exist():
    """Guards the guard's own SCOPE: _ACCEPTED_RESIDUALS naming a file that no longer
    exists (renamed/removed) would silently stop covering anything real."""
    for rel in _ACCEPTED_RESIDUALS:
        assert (REPO_ROOT / rel).is_file(), f"{rel} is in _ACCEPTED_RESIDUALS but is gone"
