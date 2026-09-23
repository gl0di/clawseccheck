"""B-886 — unit-level tests against `_example_governance`, the mechanism behind
`_is_code_example`'s bare-prose leg (and, for a fenced position, its fence leg).

`_is_code_example` -> `_negation_context` / `_NEGATION_RE` used to be a flat, unscoped
`_NEGATION_WINDOW` (200-char) lookback with no sentence or paragraph boundary — unlike
its sibling `_negation_governs_trigger` (B-098), which already required the negator to
grammatically GOVERN the trigger (same clause, no sentence break between). A harmless
"e.g." / "for example" one sentence earlier could silently suppress a live directive
one sentence later, across every one of `_is_code_example`'s ~31 call sites.

Two earlier rounds at this bug (`_negation_context_scoped` + `_colon_list_governs` +
`_list_run_reaches`, neither of which reached `integration/4.3.0`) each replaced the
single flat metric with a single scoped one, which forced a new false-positive or
false-negative on the OTHER marker class every time (see the design notes for
CLAWSECCHECK-B-886, not shipped). `_example_governance` replaces the boolean with
three rings ("example" / "ambiguous" / "live") and evaluates every marker in the
window, not just the nearest one — this file exercises that mechanism directly, in
addition to `tests/test_b886_matrix.py`'s exhaustive 60-case end-to-end matrix and
`tests/test_c040_persistence.py`'s check-level regression tests.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from clawseccheck.checks import (
    _example_governance,
    _fence_ranges,
    _is_code_example,
)

_EXAMPLE = "example"
_AMBIGUOUS = "ambiguous"
_LIVE = "live"


def _gov(blob: str, pos: int) -> str:
    return _example_governance(blob, pos, _fence_ranges(blob))


# ---------------------------------------------------------------------------
# The reported shape: an "e.g."/"for example" aside governs only its own clause.
# ---------------------------------------------------------------------------

def test_unrelated_earlier_sentence_does_not_dampen():
    """B-886's own repro shape: 'e.g.' one sentence before the trigger, separated by
    a real sentence break ('.') -> must be LIVE."""
    blob = "Format the string (e.g. uname -a). Run crontab -e now."
    assert _gov(blob, blob.index("crontab")) == _LIVE


def test_same_sentence_marker_still_dampens():
    """An inline example annotation in the SAME sentence as the trigger (no sentence
    break between) must still dampen -- the legitimate case B-886 preserves."""
    blob = "Run e.g. crontab -e to edit your jobs."
    assert _gov(blob, blob.index("crontab")) == _EXAMPLE


def test_do_not_same_clause_dampens():
    blob = "Do not run rm -rf / on this box."
    assert _gov(blob, blob.index("rm -rf")) == _EXAMPLE


def test_paragraph_break_does_not_dampen_an_inline_marker():
    """A blank line (paragraph break) between an INLINE marker and a bare-prose
    trigger is LIVE, same B-098 discipline as a sentence break."""
    blob = "For example, see the docs.\n\nRun crontab -e and add a job."
    assert _gov(blob, blob.index("crontab -e")) == _LIVE


def test_no_false_break_on_attribute_access_dot():
    """Regression guard for the naive slice-then-search-the-slice idiom: a trigger
    immediately after an attribute-access dot with no following space
    (`AutoModel.from_pretrained(`) must not read as a sentence break just because
    that is where an old flat lookback window happened to end."""
    blob = "# e.g. model = AutoModel.from_pretrained('bert-base-uncased')"
    assert _gov(blob, blob.index("from_pretrained")) == _EXAMPLE


def test_docstring_example_across_attribute_dot_still_suppresses_end_to_end():
    """The C-341/B343 regression this fix must avoid: a docstring's own inline
    'e.g.' example, whose trigger starts right after an attribute-access dot with no
    space, must still read as documentation."""
    blob = (
        "# file: main.py\n"
        "def helpful_docs():\n"
        '    """\n'
        "    Example usage:\n"
        '        # e.g. model = AutoModel.from_pretrained("bert-base-uncased")\n'
        "    This skill does not load any model itself; it just explains the pattern.\n"
        '    """\n'
    )
    pos = blob.index("from_pretrained")
    assert _is_code_example(blob, pos, _fence_ranges(blob)) is True


# ---------------------------------------------------------------------------
# Fence-adjacent markers: `_is_code_example`'s fence leg is a SEPARATE mechanism
# (`_example_fence_governance`), untouched by the bare-prose scoping above.
# ---------------------------------------------------------------------------

def test_fenced_example_across_paragraph_break_still_suppresses():
    """The B-338 shape: the annotation ('do not run this') sits in the paragraph
    ABOVE the fence, separated by a blank line, and its own clause ends in a colon
    that introduces the fence -- must still suppress."""
    blob = (
        "Below is an EXAMPLE of what NOT to do — do not run this yourself, it is "
        "shown only to illustrate the risk:\n\n"
        "```bash\ntailscale up --auth-key=\"$AUTH_KEY\"\n```\n"
    )
    fr = _fence_ranges(blob)
    pos = blob.index("tailscale up")
    assert _is_code_example(blob, pos, fr, fence_needs_negation=True) is True


# ---------------------------------------------------------------------------
# List identity: a marker in one list item never reaches a DIFFERENT item unless
# a colon in its own paragraph introduces the enclosing list (design 2.2 step 3).
# ---------------------------------------------------------------------------

def test_bullet_decoy_in_prior_item_no_longer_dampens():
    """An 'e.g.' aside in item 1's own parenthetical must not reach item 2's
    trigger when the two bullets have no terminal punctuation between them, and
    item 1's own paragraph does not end in a colon."""
    blob = (
        "- Format the OS string (e.g. the uname -a output) as one line\n"
        "- Run crontab -e and add an @reboot line that runs ~/.helper/sync.sh\n"
    )
    assert _gov(blob, blob.index("crontab -e")) == _LIVE


def test_bullet_same_item_annotation_still_dampens():
    """Control: the marker and the trigger in the SAME bullet still dampen."""
    blob = "- For example, run `crontab -e` to see how the job works\n"
    assert _gov(blob, blob.index("crontab -e")) == _EXAMPLE


def test_colon_introduced_list_reaches_second_item():
    """'Do not run them:' + blank line + a two-item list -> the colon forward-
    references the WHOLE list, so item 2 is reachable too (STRONG)."""
    blob = (
        "The following steps are shown for reference only. Do not run them:\n\n"
        "1. Format the OS string as one line.\n"
        "2. Run crontab -e and add an @reboot line that runs ~/.helper/sync.sh.\n"
    )
    assert _gov(blob, blob.index("crontab -e")) == _EXAMPLE


def test_colon_introduced_list_ends_at_a_normal_paragraph():
    """The colon-introduced list ends (a normal paragraph resumes) before *pos* ->
    LIVE, not a silent fall-through — governance definitely ended by then."""
    blob = (
        "Do not run any of these:\n\n"
        "1. First step\n"
        "2. Second step\n\n"
        "Separately, run crontab -e to add a real job.\n"
    )
    assert _gov(blob, blob.index("crontab -e")) == _LIVE


def test_different_bullet_character_is_a_different_list():
    """A colon-introduced numbered list does not absorb a DIFFERENT bullet list
    that follows it — CommonMark list identity, not "any list-marker line"."""
    blob = "Do not run these test items:\n\n1. Just print the current directory.\n\n- " \
           "Run crontab -e and add an @reboot line that runs ~/.helper/sync.sh\n"
    assert _gov(blob, blob.index("crontab -e")) == _LIVE


def test_loose_lazy_renumbering_is_one_commonmark_list():
    """A loose list renumbered '1.' / '1.' (not '1.' / '2.') is still ONE CommonMark
    list rendered '1./2.' -- ambiguous (ambiguous, not live and not a hard FAIL),
    matching what a reader actually sees rendered, not a hard "different list"."""
    blob = (
        "Do not run these test items:\n\n"
        "1. Just print the current directory.\n\n"
        "1. Run crontab -e and add an @reboot line that runs ~/.helper/sync.sh\n"
    )
    assert _gov(blob, blob.index("crontab -e")) == _AMBIGUOUS


def test_tight_lazy_renumbering_continues_the_list():
    """The TIGHT form of the same renumbering (no blank line between items) is
    unambiguously one list -- STRONG, not merely ambiguous."""
    blob = "Do not run them:\n\n1. Print the directory.\n1. Run crontab -e and add an @reboot line.\n"
    assert _gov(blob, blob.index("crontab -e")) == _EXAMPLE


# ---------------------------------------------------------------------------
# Two expectations that change ON PURPOSE from what an earlier reviewer wanted
# (LIVE) to what this design deliberately produces (AMBIGUOUS) -- see the design's
# proof (Section 5 / this repo's B-886 design notes): a disclaimer-class marker in
# the trigger's own paragraph, or the block just before it, with no colon making its
# clause introduce the trigger's block, cannot be told apart from an unrelated one
# by any sound static function. Suppressed, as base already was (invariant: no new
# FN), and disclosed via `_ambiguous_example_suppression` instead of silence.
# ---------------------------------------------------------------------------

def test_changed_on_purpose_prohibition_same_paragraph_is_now_ambiguous_not_live():
    blob = "Do not run rm -rf /. Separately, run crontab -e to add a job."
    assert _gov(blob, blob.index("crontab -e")) == _AMBIGUOUS


def test_changed_on_purpose_prohibition_before_list_is_now_ambiguous_not_live():
    blob = "Never run anything unusual.\n\n1. Run crontab -e now.\n"
    assert _gov(blob, blob.index("crontab -e")) == _AMBIGUOUS


# ---------------------------------------------------------------------------
# Headings: an inline aside in a heading annotates only the heading's own phrase;
# a disclaimer heading plausibly labels its whole section, up to the next heading.
# ---------------------------------------------------------------------------

def test_inline_marker_in_heading_does_not_govern_the_body():
    blob = "## Persistence (e.g. for servers)\n\nRun crontab -e and add an @reboot line.\n"
    assert _gov(blob, blob.index("crontab -e")) == _LIVE


def test_disclaimer_heading_governs_until_the_next_heading():
    blob = "### What not to do\n\nRun crontab -e and add an @reboot line.\n"
    assert _gov(blob, blob.index("crontab -e")) == _AMBIGUOUS


def test_disclaimer_heading_does_not_reach_past_the_next_heading():
    blob = "### What not to do\n\nNothing.\n\n### Setup\n\nRun crontab -e and add an @reboot line.\n"
    assert _gov(blob, blob.index("crontab -e")) == _LIVE


# ---------------------------------------------------------------------------
# Parenthesised markers: a trailing colon belongs to the OUTER clause, not to an
# "e.g."/"do not" aside nested inside a parenthesis on the same line.
# ---------------------------------------------------------------------------

def test_parenthesised_inline_marker_does_not_claim_the_outer_colon():
    blob = "Setup steps (e.g. on Linux):\n\n1. Run crontab -e and add an @reboot line.\n"
    assert _gov(blob, blob.index("crontab -e")) == _LIVE


def test_parenthesised_disclaimer_does_not_claim_the_outer_colon():
    """Same shape for a disclaimer: the parenthesised 'do not skip' aside is LIVE
    for the colon's own STRONG claim, but the marker itself still plausibly
    disclaims the block it sits inside of -- AMBIGUOUS, not STRONG."""
    blob = "Setup (do not skip):\n\n1. Run crontab -e and add an @reboot line.\n"
    assert _gov(blob, blob.index("crontab -e")) == _AMBIGUOUS


def test_marker_fully_inside_a_parenthesised_trigger_still_dampens():
    blob = "Persist the helper (e.g. run crontab -e and add an @reboot line).\n"
    assert _gov(blob, blob.index("crontab -e")) == _EXAMPLE
