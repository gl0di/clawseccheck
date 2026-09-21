"""Staleness guard for tests/hermeticity_allowlist.txt (CLAWSECCHECK-hermeticity
follow-up, 2026-09-21).

Same idiom as tests/test_module_layout.py's ``test_exempt_entries_are_not_stale`` /
``test_exempt_line_claims_match_reality`` -- an exemption list rots into a rubber stamp
unless SOMETHING checks whether an entry is still earning its place. Before this module,
``tests/hermeticity_allowlist.txt`` had no such check at all: an entry could sit there
forever, its reason silently obsolete, with nothing red to say so. That is exactly the
failure mode the deptree entry's own original text invited (see the git history of that
entry's "CORRECTED, same day" paragraph) -- it named a fix branch and implied the entry
would become dead weight once that branch merged, when in fact a second, undiagnosed
cause kept the same pattern alive.

WHY NOT A LIVE, LEDGER-BASED CHECK.

The obvious "real" staleness check would run the tests each entry names under
``CSC_HERMETICITY_LEDGER`` and assert the entry's pattern actually appears in the
recorded ledger rows -- i.e. prove the entry is still exercised, not just plausible.
That is not practical as an always-on guard, for two independent reasons:

1. ``CSC_HERMETICITY_LEDGER`` is opt-in (conftest.py's ``pytest_configure`` returns
   immediately when the env var is unset), by explicit design, so this check would be a
   no-op on every ordinary ``pytest -q`` run -- the one place a staleness regression
   would actually need to be caught before it ships. Making the ledger non-opt-in would
   trade that for real cost on every run (a full subprocess-CLI sweep against this
   box's actual multi-GB npm-global install), which is the same tradeoff conftest.py
   already rejected once.
2. Even under the ledger, ``conftest.py``'s ``pytest_unconfigure`` deletes the ledger
   tmpdir (and the ``ledger.tsv`` inside it) as soon as the pytest PROCESS that
   collected it exits -- so a check would need to run the exercising tests and the
   comparison in the very same invocation (as ``test_hermeticity_gate.py`` itself does),
   AND select exactly the right subset of tests, in every run, or a clean entry would
   read as "not observed this run" and a genuinely dead one would read the same way as
   one that was simply not selected. A probe that wanted the raw ledger content for
   forensics after the fact had to write its own pytest plugin to copy it out before
   ``pytest_unconfigure`` ran -- confirming there is no ambient way to ask "was this
   entry exercised on this run" without deliberately constructing that exact invocation.

So: no live check here. The honest alternative is a purely static, always-on one that
cannot silently rot the way a bare exemption list does: every block must carry
machine-checkable EVIDENCE of when it was last confirmed and how -- a
``# Last confirmed exercised: YYYY-MM-DD via `<command>``` line (see the allowlist
file's own header) -- unless its pattern(s) are on THIS MODULE's own hardcoded
universal-pattern set (below). This guard fails when the evidence is missing,
malformed, or provably stale in the one way that IS mechanically checkable without
running anything: the command names a ``tests/test_*.py`` file that no longer exists in
this tree. That does not prove liveness (a passing check here is not "this pattern was
read today"); it proves the entry cannot have rotted in the specific, silent way this
project has already been bitten by (a named fix branch merging and a reader concluding,
correctly, that the fix branch's own effect is closed, but incorrectly, that the entry
itself is now dead). It is a floor, not a ceiling: passing this guard means the entry's
evidence has not silently rotted, never that the pattern was actually read today --
that stronger claim needs the live, opt-in ledger run explained above.

CLASSIFICATION MUST NOT DEPEND ON COMMENT ORDER OR SECTION POSITION.

The first cut of this guard classified a block as "needs a marker" by matching a
``# CLAWSECCHECK-hermeticity, YYYY-MM-DD.`` header against ONLY the block's first
comment line. That has exactly the shape this project has been bitten by elsewhere
this week (the subprocess-spawn guard missing a module global, the voice guard missing
an ungraded branch): "a shape I cannot classify is therefore safe." One prose line
ahead of the header hid the entire block -- including a dangling test reference inside
it -- from the guard, and nothing failed.

The fix inverts the default, per the stronger of the two options considered: a block is
exempt from carrying a marker ONLY when every pattern it contains is a member of
``_UNIVERSAL_PATTERNS`` below -- a small, hardcoded, literal set that requires editing
THIS MODULE's source (not the data file) to extend. Anything else -- any block this
guard cannot place on that literal list, regardless of what its comments say, what
header text appears where, or which section of the file it physically sits in --
defaults to "must carry a well-formed marker," and a block with neither a marker nor an
all-universal pattern set is reported as an UNCLASSIFIED BLOCK, not silently skipped.
This closes the same hole for the "genuinely universal" section too: a block cannot buy
its way out of the marker requirement by being commented to LOOK universal, or by being
positioned between the two section-header lines -- only by its pattern(s) literally
being on the hardcoded set does. See ``test_impersonating_the_universal_section_...``
and ``test_prose_prefixed_block_is_still_caught`` below for both probes that motivated
this.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST_PATH = Path(__file__).resolve().parent / "hermeticity_allowlist.txt"

# The ONLY way a block is exempt from carrying a confirmation marker: every pattern it
# contains is literally a member of this set. Deliberately a Python-source constant, not
# anything derived from the data file's comments or section headers -- extending it
# means touching this module (and its own review), not just editing a text file. Kept in
# sync BY EYE with tests/hermeticity_allowlist.txt's "genuinely universal" section;
# test_universal_patterns_constant_matches_the_allowlist_file below pins that sync so the
# two cannot silently drift apart.
_UNIVERSAL_PATTERNS = frozenset({
    "/proc",
    "/proc/**",
    "/proc/*/fd",
    "/proc/*/fd/**",
    "/dev/null",
    "/dev/urandom",
    "/dev/random",
})

_CONFIRMED_ATTEMPT_PREFIX = "# last confirmed exercised"
_CONFIRMED_RE = re.compile(
    r"^#\s*Last confirmed exercised:\s*(\d{4}-\d{2}-\d{2})\s+via\s+`(.+)`\s*$"
)
_TEST_FILE_TOKEN_RE = re.compile(r"tests/test_[A-Za-z0-9_]+\.py")


def _iter_blocks(text: str) -> list[tuple[list[str], list[str]]]:
    """Split the allowlist into (comment_lines, pattern_lines) blocks.

    Mirrors test_hermeticity_gate.py's own reading of the file (comment lines start
    with '#', pattern lines don't) but keeps the comment text instead of discarding it,
    since that text is exactly what this module inspects. A block ends at a blank line,
    or -- for a comment block that starts right after some patterns with no blank
    separator (this file has no such case today, but nothing should silently merge two
    unrelated entries together if one is ever added that way) -- when a new comment
    line follows pattern lines directly.
    """
    blocks: list[tuple[list[str], list[str]]] = []
    comment_lines: list[str] = []
    pattern_lines: list[str] = []

    def flush() -> None:
        if comment_lines or pattern_lines:
            blocks.append((list(comment_lines), list(pattern_lines)))

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            flush()
            comment_lines.clear()
            pattern_lines.clear()
            continue
        if line.startswith("#"):
            if pattern_lines:
                flush()
                comment_lines.clear()
                pattern_lines.clear()
            comment_lines.append(line)
        else:
            pattern_lines.append(line)
    flush()
    return blocks


def _is_universal_block(patterns: list[str]) -> bool:
    """True only when EVERY pattern in the block is literally on the hardcoded
    universal set -- never based on comment text or file position. A block mixing one
    universal pattern with one non-universal pattern is NOT universal: the non-universal
    pattern still needs its own justification, and bundling it next to a genuinely
    universal one must not launder it through this check."""
    return bool(patterns) and set(patterns) <= _UNIVERSAL_PATTERNS


def _confirmation_problems(text: str) -> list[str]:
    """Return one human-readable problem string per unclassified, malformed, or
    dangling block found in ``text``.

    A block is skipped only when it carries NO patterns at all (a bare comment, e.g. a
    section-header divider -- nothing there to ever need confirming) or when
    ``_is_universal_block`` says every one of its patterns is on the hardcoded literal
    set. Every other block -- regardless of what its comments say, what order they
    appear in, or which section of the file it sits in -- must carry exactly one
    well-formed ``# Last confirmed exercised: YYYY-MM-DD via `<command>``` line
    somewhere among its comments, naming a real ``tests/test_*.py`` file and mentioning
    ``CSC_HERMETICITY_LEDGER``, or it is reported as an unclassified block.

    Pure function of the text (no filesystem access beyond checking whether a NAMED
    test file exists), so it can be exercised directly against synthetic text -- see the
    regression tests below -- without touching the real allowlist file.
    """
    problems: list[str] = []
    for comments, patterns in _iter_blocks(text):
        if not patterns:
            continue
        if _is_universal_block(patterns):
            continue

        label = patterns[0]
        attempted = [
            c for c in comments if c.lower().startswith(_CONFIRMED_ATTEMPT_PREFIX)
        ]

        if not attempted:
            problems.append(
                f"{label!r}: UNCLASSIFIED BLOCK -- its pattern(s) are not on this "
                "guard's hardcoded universal list, and no "
                "'Last confirmed exercised: YYYY-MM-DD via `cmd`' marker was found "
                "anywhere in its comments (searched the whole block, not just the "
                "first line). A block this guard cannot place is treated as needing "
                "one, never as safe by default."
            )
            continue
        if len(attempted) > 1:
            problems.append(
                f"{label!r}: {len(attempted)} confirmation markers on one block, "
                "expected exactly 1"
            )
            continue

        m = _CONFIRMED_RE.match(attempted[0])
        if not m:
            problems.append(f"{label!r}: malformed confirmation marker: {attempted[0]!r}")
            continue

        _date, command = m.groups()
        if "CSC_HERMETICITY_LEDGER" not in command:
            problems.append(
                f"{label!r}: confirmation command does not mention "
                f"CSC_HERMETICITY_LEDGER, so running it would not actually exercise "
                f"the ledger: {command!r}"
            )

        test_tokens = _TEST_FILE_TOKEN_RE.findall(command)
        if not test_tokens:
            problems.append(
                f"{label!r}: confirmation command names no tests/test_*.py file, so "
                f"there is nothing to check it against: {command!r}"
            )
        for token in test_tokens:
            if not (REPO_ROOT / token).is_file():
                problems.append(
                    f"{label!r}: confirmation command names {token}, which no longer "
                    "exists in this tree -- the entry's evidence is dangling; "
                    "re-diagnose against a real reproducer or drop the entry"
                )
    return problems


# --------------------------------------------------------------------------------------
# The gated check against the REAL file. Always-on (no CSC_HERMETICITY_LEDGER needed to
# run it -- see the module docstring for why this is static, not ledger-based).

def test_every_non_universal_allowlist_block_has_a_wellformed_confirmation_marker() -> None:
    text = ALLOWLIST_PATH.read_text(encoding="utf-8")
    non_universal = [
        (comments, patterns)
        for comments, patterns in _iter_blocks(text)
        if patterns and not _is_universal_block(patterns)
    ]
    assert non_universal, (
        "no non-universal blocks found at all -- either every allowlist entry is now "
        "on the hardcoded universal list (update _UNIVERSAL_PATTERNS above to match) "
        "or this guard is silently checking nothing"
    )
    problems = _confirmation_problems(text)
    assert not problems, (
        "Stale, malformed, or unclassified hermeticity-allowlist block(s):\n"
        + "\n".join(f"  - {p}" for p in problems)
        + "\n\nEvery block in tests/hermeticity_allowlist.txt whose pattern(s) are not "
        "on this module's hardcoded _UNIVERSAL_PATTERNS set must carry a "
        "'# Last confirmed exercised: YYYY-MM-DD via `<command>`' line naming a real "
        "tests/test_*.py file and mentioning CSC_HERMETICITY_LEDGER -- see that file's "
        "header and this module's docstring for why."
    )


def test_universal_patterns_constant_matches_the_allowlist_file() -> None:
    """Keeps _UNIVERSAL_PATTERNS from silently drifting away from the file's own
    "genuinely universal" section -- not the classification mechanism itself (that is
    the point: this module never reads that section header at all), just a sync check
    so a change to one side is not forgotten on the other."""
    text = ALLOWLIST_PATH.read_text(encoding="utf-8")
    all_patterns = {p for _c, patterns in _iter_blocks(text) for p in patterns}
    missing_from_file = _UNIVERSAL_PATTERNS - all_patterns
    assert not missing_from_file, (
        f"_UNIVERSAL_PATTERNS names pattern(s) not present in the allowlist file at "
        f"all: {sorted(missing_from_file)} -- drop them from the hardcoded set"
    )


# --------------------------------------------------------------------------------------
# Regression tests for the checker itself -- prove it can fail, not only pass. Each
# builds a synthetic allowlist snippet in memory; none touches the real file.

def test_confirmation_checker_flags_a_missing_marker() -> None:
    text = (
        "# CLAWSECCHECK-hermeticity, 2026-09-21. Demo entry with no confirmation "
        "marker at all.\n"
        "$HOME/.csc-demo-dead/**\n"
    )
    problems = _confirmation_problems(text)
    assert problems, "expected the missing-marker case to be flagged"
    assert "$HOME/.csc-demo-dead/**" in problems[0]
    assert "UNCLASSIFIED BLOCK" in problems[0]


def test_confirmation_checker_flags_a_dangling_test_reference() -> None:
    """Coordinator probe 1: a correctly-shaped block (header first, marker second) with
    a dangling test reference. Must fail."""
    text = (
        "# CLAWSECCHECK-hermeticity, 2026-09-21. Demo entry.\n"
        "#\n"
        "# Last confirmed exercised: 2026-09-21 via `CSC_HERMETICITY_LEDGER=1 "
        "python3.12 -m pytest tests/test_this_file_does_not_exist_c598.py -q`\n"
        "$HOME/.csc-demo-dead/**\n"
    )
    problems = _confirmation_problems(text)
    assert problems, "expected the dangling-test-reference case to be flagged"
    assert any("no longer exists" in p for p in problems)


def test_prose_prefixed_block_with_dangling_reference_is_still_caught() -> None:
    """Coordinator probe 2: the SAME dangling entry as above, but with one prose line
    ahead of the header. Under the old first-line-only classification this made the
    whole block invisible to the guard (7 passed, silently exempt). Must ALSO fail,
    identically to probe 1 -- classification must not depend on comment order."""
    text = (
        "# A leading prose line that hides the block from the guard.\n"
        "# CLAWSECCHECK-hermeticity, 2026-09-21.\n"
        "# Last confirmed exercised: 2026-09-21 via `CSC_HERMETICITY_LEDGER=1 "
        "python3.12 -m pytest tests/test_also_does_not_exist.py`\n"
        "$HOME/.second-probe/**\n"
    )
    problems = _confirmation_problems(text)
    assert problems, (
        "expected the prose-prefixed dangling entry to be flagged exactly like the "
        "correctly-shaped one -- classification must not depend on which comment line "
        "the header happens to be"
    )
    assert any("no longer exists" in p for p in problems)
    assert any("$HOME/.second-probe/**" in p for p in problems)


def test_block_with_no_header_at_all_is_still_caught() -> None:
    """Stronger than the header-anywhere fix would need to pass: a block that never
    mentions the dated preamble at all -- just unrelated prose -- and a dangling
    reference. The old design would never have classified this as diagnosed regardless
    of ordering, since it never matches the header text anywhere. The new default
    (unclassified => must explain) catches it anyway."""
    text = (
        "# Nothing about this comment looks like the dated violation preamble.\n"
        "# It still needs to justify itself.\n"
        "$HOME/.csc-demo-headerless/**\n"
    )
    problems = _confirmation_problems(text)
    assert problems and "UNCLASSIFIED BLOCK" in problems[0]


def test_confirmation_checker_flags_a_command_that_never_touches_the_ledger() -> None:
    text = (
        "# CLAWSECCHECK-hermeticity, 2026-09-21. Demo entry.\n"
        "#\n"
        "# Last confirmed exercised: 2026-09-21 via `python3.12 -m pytest "
        "tests/test_watch.py -q`\n"
        "$HOME/.csc-demo-dead/**\n"
    )
    problems = _confirmation_problems(text)
    assert any("CSC_HERMETICITY_LEDGER" in p for p in problems)


def test_confirmation_checker_flags_a_malformed_date() -> None:
    text = (
        "# CLAWSECCHECK-hermeticity, 2026-09-21. Demo entry.\n"
        "#\n"
        "# Last confirmed exercised: not-a-date via `CSC_HERMETICITY_LEDGER=1 "
        "python3.12 -m pytest tests/test_watch.py -q`\n"
        "$HOME/.csc-demo-dead/**\n"
    )
    problems = _confirmation_problems(text)
    assert problems and "malformed confirmation marker" in problems[0]


def test_confirmation_checker_accepts_a_wellformed_entry() -> None:
    """The positive control: proves the checker does not simply always fail. Names a
    real file under the tests/test_*.py shape so the existence check has something true
    to pass against."""
    text = (
        "# CLAWSECCHECK-hermeticity, 2026-09-21. Demo entry.\n"
        "#\n"
        "# Last confirmed exercised: 2026-09-21 via `CSC_HERMETICITY_LEDGER=1 "
        "python3.12 -m pytest tests/test_watch.py -q`\n"
        "$HOME/.csc-demo-live/**\n"
    )
    assert _confirmation_problems(text) == []


def test_mixing_a_universal_pattern_with_a_non_universal_one_does_not_launder_it() -> None:
    """A block bundling one hardcoded-universal pattern with one that is NOT on that
    set is not universal -- the non-universal pattern must not ride through on its
    neighbor's exemption."""
    text = (
        "# CLAWSECCHECK-hermeticity, 2026-09-21. Demo entry mixing a real universal "
        "pattern with a smuggled one.\n"
        "$HOME/.csc-demo-smuggled/**\n"
        "/proc\n"
    )
    problems = _confirmation_problems(text)
    assert problems and "UNCLASSIFIED BLOCK" in problems[0]
    assert "$HOME/.csc-demo-smuggled/**" in problems[0]


def test_impersonating_the_universal_section_does_not_exempt_a_block() -> None:
    """Coordinator's second question: can a block be made to LOOK universal, or land
    inside that section's comment text, without its pattern actually being one? Builds
    a block whose comment text impersonates the real "genuinely universal" section
    header verbatim, wrapped around a pattern that is not on the hardcoded set. Must
    still be flagged -- universal-ness is per-literal-pattern, never per-comment-claim
    or per-position."""
    text = (
        "# ---- genuinely universal (observed on every real run, not machine-specific) "
        "--------\n"
        "# This pretends to belong to the universal section by quoting its header, but "
        "the pattern below is a specific machine path tied to one test, not a property "
        "of the OS.\n"
        "/etc/this-is-not-actually-universal\n"
    )
    problems = _confirmation_problems(text)
    assert problems and "UNCLASSIFIED BLOCK" in problems[0]
    assert "/etc/this-is-not-actually-universal" in problems[0]


def test_universal_block_needs_no_confirmation_marker() -> None:
    """The genuinely-universal entries (/proc, /dev/null, ...) are exempt because their
    patterns are literally on _UNIVERSAL_PATTERNS -- not because of any comment text --
    and carry no marker in the real file. Confirms the real file's own universal blocks
    pass with zero problems."""
    text = ALLOWLIST_PATH.read_text(encoding="utf-8")
    universal_only_blocks = [
        (comments, patterns)
        for comments, patterns in _iter_blocks(text)
        if patterns and _is_universal_block(patterns)
    ]
    assert universal_only_blocks, "expected at least one all-universal block in the real file"
    for comments, patterns in universal_only_blocks:
        assert not any(
            c.lower().startswith(_CONFIRMED_ATTEMPT_PREFIX) for c in comments
        ), f"{patterns}: a genuinely universal block should not need a marker at all"
