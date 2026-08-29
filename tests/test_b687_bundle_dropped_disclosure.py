"""B-687: say when a bundle the caller sent was thrown away.

`read_judged_bundle_with_problem`'s docstring records the consequence for the sibling case
B-562 fixed: because `liveTest` feeds `scoring.compute`'s cap, **a lost bundle is a silently
HIGHER score**. B-597 put a disclosure at the end of `split_judged_bundle`; everything that
reaches it is reported. Four paths returned before it, each dropping a payload the caller
did send:

  * larger than MAX_BUNDLE_BYTES
  * not valid JSON at all — plain text, or a binary file read through errors="replace"
  * valid JSON whose top level is not an object
  * a recognised bucket key carrying the wrong type (the four isinstance gates had no else)

The last one is not hypothetical. B-597 exists because the tool's own error message taught a
host agent to move `verdicts` to the top level and drop `judged`; a mistyped `judged` is the
same class of mistake by the same kind of caller.

Half of this file holds the cases that must STAY silent. "Nothing was submitted" is a real
state — `adjudication._payload_carries_content` protects it deliberately — and it is also
what `read_judged_bundle_with_problem` produces for a path it could not open, which B-562
already reports with the path named. A fix that notes unconditionally turns one failure into
two lines and destroys the quiet case.
"""

import contextlib
import io
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clawseccheck.pipeline import MAX_BUNDLE_BYTES, split_judged_bundle  # noqa: E402


def _run(raw):
    """``(buckets, stderr)`` — the note channel is stderr, by adjudication._note's contract."""
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        out = split_judged_bundle(raw)
    return out, err.getvalue()


def _applied(out):
    return any(out[k] for k in ("attestation", "judged", "vetJudged", "liveTest"))


# ---------------------------------------------------------------------------
# Dropped, and now said so
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "label,raw,fragment",
    [
        ("plain text", "hello\n", "not valid JSON"),
        ("binary via errors=replace", "%PDF-1.4\n��\x00junk\n", "not valid JSON"),
        ("top level is an array", "[1, 2, 3]", "not a JSON object"),
    ],
)
def test_an_unusable_document_is_reported(label, raw, fragment):
    out, err = _run(raw)
    assert not _applied(out), label
    assert "--judged-bundle was read but nothing was applied" in err, label
    assert fragment in err, label
    assert "continues as if no bundle had been submitted" in err, label


def test_a_payload_over_the_cap_is_reported():
    out, err = _run(json.dumps({"judged": {"B13": {"v": "x" * MAX_BUNDLE_BYTES}}}))
    assert not _applied(out)
    assert f"larger than the {MAX_BUNDLE_BYTES}-byte cap" in err


def test_a_recognised_key_with_the_wrong_type_is_named():
    out, err = _run(json.dumps({"judged": [{"finding_id": "B13"}]}))
    assert not _applied(out)
    assert 'bucket "judged" carried the wrong type and was dropped' in err


def test_several_mistyped_buckets_agree_in_number():
    _, err = _run(json.dumps({"judged": "x", "vetJudged": {"a": 1}}))
    assert 'buckets "judged", "vetJudged" carried the wrong type and were dropped' in err


def test_a_mistyped_bucket_is_reported_even_when_a_sibling_survived():
    """A bucket thrown away is thrown away whether or not another one was applied.

    The check sits BEFORE the "any bucket present" early return for this reason; put it
    after and a partial loss goes silent, which is the shape of the bug being fixed.
    """
    out, err = _run(json.dumps({"judged": {"B13": {"verdict": "benign"}}, "liveTest": "x"}))
    assert _applied(out)
    assert out["judged"] == {"B13": {"verdict": "benign"}}
    assert 'bucket "liveTest" carried the wrong type' in err


# ---------------------------------------------------------------------------
# Must stay silent — the half that a careless fix breaks
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "label,raw",
    [
        ("empty payload — nothing submitted", ""),
        ("whitespace only", "   \n "),
        ("an explicitly empty document", "{}"),
        ("an explicitly empty bucket", '{"judged": {}}'),
    ],
)
def test_nothing_submitted_stays_quiet(label, raw):
    """`read_judged_bundle_with_problem` hands us "" for a path it could not OPEN, and
    B-562 already reports that case with the path named. A note here would double it."""
    _, err = _run(raw)
    assert err.strip() == "", label


def test_a_valid_bundle_is_applied_and_silent():
    """The control that matters most.

    Every other assertion in this file passes for a fix that notes unconditionally; this
    is the one that fails it. It is also the case my first measurement of this bug never
    made — I used a list for `judged`, which is itself one of the gaps, and concluded from
    three runs in the same blind spot that the whole channel was silent.
    """
    out, err = _run(json.dumps({"judged": {"B13": {"verdict": "benign"}}}))
    assert out["judged"] == {"B13": {"verdict": "benign"}}
    assert err.strip() == ""


# ---------------------------------------------------------------------------
# The existing disclosures must not move
# ---------------------------------------------------------------------------

def test_the_b597_rescue_and_its_note_are_unchanged():
    out, err = _run(json.dumps({"verdicts": [{"finding_id": "B13", "verdict": "ok"}]}))
    assert out["judged"] == {"verdicts": [{"finding_id": "B13", "verdict": "ok"}]}
    assert 'carried a top-level "verdicts" array' in err


def test_the_b597_unknown_keys_note_is_unchanged():
    _, err = _run(json.dumps({"unrelated": 1}))
    assert "none of its 1 top-level key(s) is a recognised bucket" in err


# ---------------------------------------------------------------------------
# §8: a note must never echo the payload
# ---------------------------------------------------------------------------

def test_no_note_echoes_anything_from_the_payload():
    """B-597's own rule: notes carry "only counts and this contract's own fixed key names
    — so an unrecognised key is counted, never echoed. A bundle key could otherwise carry
    a secret-shaped value straight into a diagnostic."

    The secret-shaped strings are assembled at runtime so no contiguous literal exists in
    this file (CLAUDE.md §2.3).
    """
    marker = "sk" + "-live-" + "AKIA" + "EXAMPLE" + "1234"
    payloads = [
        json.dumps({marker: 1}),
        json.dumps({"judged": marker}),
        json.dumps({"judged": [marker], "vetJudged": marker}),
        marker,
        "[" + json.dumps(marker) + "]",
    ]
    for raw in payloads:
        _, err = _run(raw)
        assert marker not in err, raw[:40]
