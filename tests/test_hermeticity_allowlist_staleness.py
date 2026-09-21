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
cannot silently rot the way a bare exemption list does: every "known, diagnosed
violation" entry must carry machine-checkable EVIDENCE of when it was last confirmed
and how -- a ``# Last confirmed exercised: YYYY-MM-DD via `<command>``` line (see the
allowlist file's own header) -- and this guard fails when that evidence is missing,
malformed, or provably stale in the one way that IS mechanically checkable without
running anything: the command names a ``tests/test_*.py`` file that no longer exists in
this tree. That does not prove liveness (a passing check here is not "this pattern was
read today"); it proves the entry cannot have rotted in the specific, silent way this
project has already been bitten by (a named fix branch merging and a reader concluding,
correctly, that the fix branch's own effect is closed, but incorrectly, that the entry
itself is now dead). It is a floor, not a ceiling: passing this guard means the entry's
evidence has not silently rotted, never that the pattern was actually read today --
that stronger claim needs the live, opt-in ledger run this module's docstring above
explains is not available to an always-on gate.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST_PATH = Path(__file__).resolve().parent / "hermeticity_allowlist.txt"

# The convention this file's own header documents: a diagnosed, dated violation opens
# with this exact preamble. The "genuinely universal" section (/proc, /dev/null, ...)
# does not use it -- those entries are a property of the OS, not of a reproducer that
# can go stale, so they carry no confirmation marker and this guard leaves them alone.
_DIAGNOSED_HEADER_RE = re.compile(r"^#\s*CLAWSECCHECK-hermeticity,\s*\d{4}-\d{2}-\d{2}\.")

_CONFIRMED_PREFIX = "# last confirmed exercised"
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


def _diagnosed_blocks(text: str) -> list[tuple[list[str], list[str]]]:
    return [
        (comments, patterns)
        for comments, patterns in _iter_blocks(text)
        if comments and _DIAGNOSED_HEADER_RE.match(comments[0])
    ]


def _confirmation_problems(text: str) -> list[str]:
    """Return one human-readable problem string per malformed/dangling/missing
    confirmation marker found among the diagnosed-violation blocks in ``text``.

    Pure function of the text (no filesystem access beyond checking whether a NAMED
    test file exists), so it can be exercised directly against synthetic text -- see
    the regression tests below -- without touching the real allowlist file.
    """
    problems: list[str] = []
    for comments, patterns in _diagnosed_blocks(text):
        label = patterns[0] if patterns else comments[0]
        markers = [c for c in comments if c.lower().startswith(_CONFIRMED_PREFIX)]

        if not markers:
            problems.append(
                f"{label!r}: no 'Last confirmed exercised: YYYY-MM-DD via `cmd`' "
                "marker on this diagnosed entry"
            )
            continue
        if len(markers) > 1:
            problems.append(
                f"{label!r}: {len(markers)} confirmation markers on one entry, "
                "expected exactly 1"
            )
            continue

        m = _CONFIRMED_RE.match(markers[0])
        if not m:
            problems.append(f"{label!r}: malformed confirmation marker: {markers[0]!r}")
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

def test_every_diagnosed_allowlist_entry_has_a_wellformed_confirmation_marker() -> None:
    text = ALLOWLIST_PATH.read_text(encoding="utf-8")
    diagnosed = _diagnosed_blocks(text)
    assert diagnosed, (
        "no 'CLAWSECCHECK-hermeticity, YYYY-MM-DD.' diagnosed entries found at all -- "
        "either the file's convention changed (update _DIAGNOSED_HEADER_RE above) or "
        "this guard is silently checking nothing"
    )
    problems = _confirmation_problems(text)
    assert not problems, (
        "Stale or malformed hermeticity-allowlist confirmation marker(s):\n"
        + "\n".join(f"  - {p}" for p in problems)
        + "\n\nEach 'known, diagnosed violation' entry in "
        "tests/hermeticity_allowlist.txt must carry a "
        "'# Last confirmed exercised: YYYY-MM-DD via `<command>`' line naming a real "
        "tests/test_*.py file and mentioning CSC_HERMETICITY_LEDGER -- see that file's "
        "header and this module's docstring for why."
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
    assert "no 'Last confirmed exercised" in problems[0]


def test_confirmation_checker_flags_a_dangling_test_reference() -> None:
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
    real file (this very module) under the tests/test_*.py shape so the existence
    check has something true to pass against."""
    text = (
        "# CLAWSECCHECK-hermeticity, 2026-09-21. Demo entry.\n"
        "#\n"
        "# Last confirmed exercised: 2026-09-21 via `CSC_HERMETICITY_LEDGER=1 "
        "python3.12 -m pytest tests/test_watch.py -q`\n"
        "$HOME/.csc-demo-live/**\n"
    )
    assert _confirmation_problems(text) == []


def test_universal_section_entries_need_no_confirmation_marker() -> None:
    """The genuinely-universal section (/proc, /dev/null, ...) is deliberately exempt
    -- it describes a property of the OS, not a reproducer tied to specific tests, so
    _diagnosed_blocks() must not pick it up even though it has no marker."""
    text = ALLOWLIST_PATH.read_text(encoding="utf-8")
    universal_patterns = {"/proc", "/proc/**", "/dev/null", "/dev/urandom", "/dev/random"}
    diagnosed_patterns = {
        p for _comments, patterns in _diagnosed_blocks(text) for p in patterns
    }
    assert not (universal_patterns & diagnosed_patterns), (
        "a universal entry was mis-classified as a diagnosed violation -- it would now "
        "require a confirmation marker it was never meant to carry"
    )
