"""The shipped docs must not say a ``RESISTANT`` or an absent live-test bucket "changes
nothing".

That was true while the ``liveTest`` bucket (F-155) was cap-only. Once the five-layer
ledger landed, the bucket's presence and well-formedness (never its verdict) decides
whether the ``live_behaviour`` layer ran, and an incomplete ledger yields an ungraded
run. ``docs/USAGE.md`` and ``docs/OUTPUT_SCHEMA.md`` kept the pre-ledger sentence for a
long while because nothing pinned it: ``test_doc_facts.py`` only guards countable
claims.

This file therefore does three things, in this order:

1. derives the code fact the docs now assert (TRUTH tests) from the real ledger
   builder, so a future ledger change reddens the docs test instead of leaving prose to
   rot;
2. bans the old wording anywhere in the shipped text and requires the corrected wording
   in the two places that carried the false claim;
3. proves the ban can fail (guard-the-guard): the regexes are fed the exact old
   sentences and must match them.

Offline, deterministic, stdlib plus ``clawseccheck`` only.
"""
from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

from clawseccheck import cli
from clawseccheck import pipeline as pl
from clawseccheck.layers import (
    LAYER_LIVE_BEHAVIOUR,
    STATUS_NOT_SUBMITTED,
    STATUS_RAN,
)

REPO = Path(__file__).resolve().parents[1]
USAGE = REPO / "docs" / "USAGE.md"
OUTPUT_SCHEMA = REPO / "docs" / "OUTPUT_SCHEMA.md"

# Every shipped prose surface a reader can believe (same set as test_doc_facts'
# SHIPPED_TEXT, minus the SVG badges, which carry no such sentence). Rebuilt here on
# purpose: this file imports nothing from another test module.
SHIPPED_PROSE = (
    [REPO / "README.md", REPO / "SKILL.md"]
    + sorted((REPO / "docs").glob("*.md"))
    + [p for p in [REPO / "CONTRIBUTING.md"] if p.exists()]
)

_RESISTANT_ENTRY = {"tool": "multiturn", "id": "MT-01", "verdict": "RESISTANT"}

# The real incident shape: the bare tool name used as the id (dropped, F-193).
_FORGED_BUCKET = {
    "seed": "x",
    "verdicts": [{"id": "canary", "tool": "canary", "verdict": "RESISTANT"}],
}

# The old, false wording. Each pattern is anchored on the false claim itself, never on a
# bare "changes nothing" (SKILL.md and the vet SAFE notes use that phrase legitimately).
_OLD_CLAIMS = (
    re.compile(r"RESISTANT or nothing submitted changes nothing"),
    re.compile(
        r'RESISTANT" entry, an unrecognized tool/id/verdict, or an absent bucket '
        r"has ZERO effect, by construction"
    ),
    re.compile(r"can ever move anything"),
)


def _flat(path: Path) -> str:
    """The file as one whitespace-normalized string with backticks removed, so line
    wrapping and inline-code markup can neither hide nor fake a phrase."""
    return " ".join(path.read_text(encoding="utf-8").split()).replace("`", "")


def _ledger(bucket):
    args = SimpleNamespace(full=True, fast=False, multiturn=False, self_test=False)
    return cli._build_layer_ledger(
        args, [], live_test_bucket=bucket, commit_full_phases=False)


def _slice(text: str, start: str, end: str) -> str:
    """``text`` from ``start`` up to ``end`` (case-insensitive end anchor). A missing
    anchor fails loudly: a guard that finds nothing must not pass vacuously."""
    i = text.find(start)
    assert i != -1, f"anchor not found: {start!r}"
    m = re.compile(re.escape(end), re.IGNORECASE).search(text, i + len(start))
    assert m is not None, f"end anchor not found after {start!r}: {end!r}"
    return text[i:m.start()]


# --- 1. TRUTH: the code fact the docs assert ---------------------------------


class TestLedgerFactTheDocsAssert:
    def test_a_valid_resistant_entry_marks_live_behaviour_ran(self):
        ledger = _ledger({"verdicts": [dict(_RESISTANT_ENTRY)]})
        assert ledger.status(LAYER_LIVE_BEHAVIOUR) == STATUS_RAN
        assert LAYER_LIVE_BEHAVIOUR not in ledger.missing

    def test_nothing_submitted_leaves_it_not_submitted_and_the_run_incomplete(self):
        for bucket in (None, {}):
            ledger = _ledger(bucket)
            assert ledger.status(LAYER_LIVE_BEHAVIOUR) == STATUS_NOT_SUBMITTED, bucket
            assert LAYER_LIVE_BEHAVIOUR in ledger.missing
            assert ledger.complete is False

    def test_a_bucket_whose_every_entry_was_dropped_counts_as_nothing_submitted(self):
        ledger = _ledger(dict(_FORGED_BUCKET))
        assert ledger.status(LAYER_LIVE_BEHAVIOUR) == STATUS_NOT_SUBMITTED

    def test_the_cap_side_stays_cap_only(self):
        """RESISTANT never sets the cap, nothing submitted never sets it: the two
        facts ("does it move the score" and "does it complete the run") really are
        different, which is what the corrected sentences say."""
        assert pl.live_test_cap_signal({"verdicts": [dict(_RESISTANT_ENTRY)]}).hit is False
        assert pl.live_test_cap_signal(None).hit is False
        vulnerable = dict(_RESISTANT_ENTRY, verdict="VULNERABLE")
        assert pl.live_test_cap_signal({"verdicts": [vulnerable]}).hit is True


# --- 2. DOC-ABSENCE: the old claim is gone from every shipped text -----------


def test_shipped_prose_set_is_not_vacuous():
    assert USAGE in SHIPPED_PROSE and OUTPUT_SCHEMA in SHIPPED_PROSE
    assert all(p.exists() for p in SHIPPED_PROSE)


def test_no_shipped_text_says_resistant_or_nothing_changes_nothing():
    offenders = []
    for path in SHIPPED_PROSE:
        text = _flat(path)
        for pattern in _OLD_CLAIMS:
            for m in pattern.finditer(text):
                offenders.append(f"{path.relative_to(REPO)}@{m.start()}: {m.group(0)!r}")
    assert not offenders, (
        "a shipped doc still carries the pre-ledger claim that a RESISTANT or absent "
        "live-test bucket has no effect; scope it to the score cap:\n  "
        + "\n  ".join(offenders)
    )


# --- 3/4. DOC-PRESENCE: the corrected wording is there ------------------------


def test_usage_separates_the_cap_from_the_ledger():
    text = _flat(USAGE)
    claim = _slice(
        text,
        "carrying a --canary/--dryrun/--redteam/--multiturn verdict (F-155)",
        "only a run submitted with a seed",
    )
    # The doc's words are tied to the code's own vocabulary, not retyped literals.
    assert STATUS_NOT_SUBMITTED in claim
    assert "ungraded" in claim
    assert "live-behaviour layer" in claim
    assert "not the same as RESISTANT" in claim


def test_output_schema_scopes_zero_effect_to_the_cap_and_states_the_ledger_rule():
    text = _flat(OUTPUT_SCHEMA)
    claim = _slice(
        text,
        "FOURTH bucket, liveTest (F-155)",
        "trajectory (F-193, optional)",
    )
    assert LAYER_LIVE_BEHAVIOUR in claim
    assert STATUS_NOT_SUBMITTED in claim
    assert f"marks {LAYER_LIVE_BEHAVIOUR} as {STATUS_RAN}" in claim
    assert "graded: false" in claim
    assert "not the same as RESISTANT" in claim
    zero = [m.start() for m in re.finditer(r"ZERO effect", claim)]
    assert zero, "the score-cap sentence this test scopes is gone"
    for pos in zero:
        assert "on the score cap" in claim[pos:pos + len("ZERO effect") + 40], (
            f"an unscoped 'ZERO effect' at {pos}: {claim[pos:pos + 80]!r}"
        )


# --- 5. GUARD-THE-GUARD: the ban can actually fire ----------------------------

# The exact old sentences, assembled from fragments so the false claim is not one
# contiguous literal anywhere in the tree.
_OLD_USAGE = (
    "only VULNERABLE ever caps the grade - RESISTANT or nothing "
    + "submitted changes nothing - and only a run submitted with a seed"
)
_OLD_SCHEMA = (
    'only a "VULNERABLE" entry can ever move anyth' + "ing (live_injection_capped in "
    '§1) - a "RESISTANT" entry, an unrecognized tool/id/verdict, or an absent '
    "bucket has ZERO effect, by construction, not by convention"
)


def _matches_any_old_claim(text: str) -> bool:
    return any(p.search(text) for p in _OLD_CLAIMS)


def test_the_ban_matches_the_exact_old_sentences():
    assert _OLD_CLAIMS[0].search(_OLD_USAGE)
    assert _OLD_CLAIMS[1].search(_OLD_SCHEMA)
    assert _OLD_CLAIMS[2].search(_OLD_SCHEMA)


def test_the_ban_does_not_match_the_corrected_or_legitimate_wording():
    corrected_usage = (
        "only VULNERABLE ever caps the grade - a RESISTANT verdict never raises or lowers "
        "the score, and submitting nothing never caps it - but the cap is not the whole story"
    )
    corrected_schema = (
        'only a "VULNERABLE" entry can ever move the score - a "RESISTANT" entry, an '
        "unrecognized tool/id/verdict, or an absent bucket has ZERO effect on the score "
        "cap, by construction"
    )
    legitimate = "a probe that ran the analysis but never fired one changes nothing"
    for sentence in (corrected_usage, corrected_schema, legitimate):
        assert not _matches_any_old_claim(sentence), sentence
