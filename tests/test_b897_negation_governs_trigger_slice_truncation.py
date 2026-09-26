"""B-897 -- `_negation_governs_trigger` sliced its lookback window to end exactly at
*pos* (`win = blob[max(0, pos - window):pos]`), then ran `_SENTENCE_BREAK_RE.search`
against that SLICE. `_SENTENCE_BREAK_RE`'s `$` alternative matches end-of-string, which
for a truncated slice means "end of the slice", not "end of the real text" -- so a
trigger sitting right after an attribute-access dot with no intervening space
("Never call Config.execute()...") had its slice happen to end exactly on that `.`,
wrongly reading it as a sentence break even though the real next character in the full
blob is a letter, not whitespace. A genuine negation silently failed to govern the
trigger it grammatically should.

Fixed by searching the UNTRUNCATED blob from the negator's end and checking only
whether the resulting match STARTS before *pos*, instead of truncating the search
string first -- the same technique `_example_clause_end` (B-886, `_is_code_example`'s
bare-prose leg) uses for its own forward sentence-break search, adapted with a small
`pos + 2` search bound (just enough for the regex's own optional-quote +
whitespace-or-end lookahead to resolve) so the scan stays ~window-sized instead of
potentially running to the end of a large blob.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from clawseccheck.checks import _negation_governs_trigger


def test_dot_adjacent_trigger_now_governed():
    """The reported repro: a broad negation ('Never') governs a trigger that sits
    directly after an attribute-access dot with no space -- must be True."""
    blob = "Never call Config.execute() in production."
    pos = blob.index("execute")
    assert _negation_governs_trigger(blob, pos) is True


def test_control_no_dot_still_governed():
    """Control: the same negation, no dot before the trigger -- must stay True (this
    case never depended on the truncation artifact)."""
    blob = "Never call execute() in production."
    pos = blob.index("execute")
    assert _negation_governs_trigger(blob, pos) is True


def test_real_sentence_break_still_blocks_governance():
    """A genuine sentence break between the negator and the trigger must still stop
    the negation from governing it -- the fix must not turn this into a false True."""
    blob = "Never do the bad thing. Then call execute() now."
    pos = blob.index("execute")
    assert _negation_governs_trigger(blob, pos) is False


def test_dot_adjacent_at_various_negators():
    """The dot-adjacency shape reproduces for other _BROAD_NEGATION_RE verbs too, not
    just 'never'."""
    for phrase in (
        "Do not call Config.execute() in production.",
        "Must not call Config.execute() in production.",
        "Avoid calling Config.execute() in production.",
    ):
        pos = phrase.index("execute")
        assert _negation_governs_trigger(phrase, pos) is True, phrase


def test_paragraph_break_still_blocks_governance():
    """A blank-line paragraph break between negator and trigger must still count as a
    real boundary (the `\\n[^\\S\\n]*\\n` alternative of _SENTENCE_BREAK_RE, unrelated
    to the `$` truncation artifact) -- must stay False."""
    blob = "Never run this.\n\nSeparately, call Config.execute() later.\n"
    pos = blob.index("execute")
    assert _negation_governs_trigger(blob, pos) is False


def test_quote_after_period_dot_adjacent_still_governed():
    """The `[\"')\\]]?` optional-quote branch of _SENTENCE_BREAK_RE must still resolve
    correctly against the real trailing character when the trigger is dot-adjacent."""
    blob = 'Never call "Config.execute()" in production.'
    pos = blob.index("execute")
    assert _negation_governs_trigger(blob, pos) is True


def test_trigger_at_end_of_blob_after_dot_is_a_real_break():
    """When *pos* truly IS at (or leads into) the end of the blob and the preceding
    char is sentence-ending punctuation followed by nothing else, that is a REAL
    sentence break, not an artifact -- must stay False (unrelated final trigger)."""
    blob = "Never mind that. execute"
    pos = blob.index("execute")
    assert _negation_governs_trigger(blob, pos) is False
