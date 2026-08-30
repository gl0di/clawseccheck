"""Every cap signal the engine can set reaches the judge packet.

`run_state()`'s `capsFired` was built from an inline five-tuple while `scoring.compute`
sets **six** cap signals. The missing one was `cap_severity` -- an open CRITICAL or HIGH
finding, which is the most ordinary cap there is and the one every vulnerable config
produces. Measured before the fix:

    severity (open CRITICAL)   capsFired=[]
    config_blind               capsFired=[{'cap': 'config_blind_capped', ...}]

An empty list is not silence: `runState` says `stated: true` beside it, so the packet made
the positive claim that nothing capped the run, to a consumer with no way to check. That is
Golden Rule #4 reached through machine output rather than prose, and it lands on the judge
input rather than on a report a human can sanity-check.

Why the tests below are shaped the way they are: the defect was a **second ladder** kept in
step by hand, and the sibling defect in `report.py` (B-593/B-600) showed that a count pin is
what catches that class -- a new signal has to come to the census and say so. Wording is
deliberately NOT shared with `report._CAP_SIGNAL_TABLE`: that table phrases a cap for our
own report, these labels are read by a possibly third-party host agent. Two vocabularies,
one fact; the fact is what the census keeps aligned.

Offline, no CLI, stdlib only.
"""
from __future__ import annotations

import copy
import dataclasses
import itertools

import pytest

from clawseccheck.adjudication import _CAP_LADDER, run_state
from clawseccheck.catalog import Finding
from clawseccheck.pipeline import live_test_cap_signal
from clawseccheck.report import _CAP_SIGNAL_TABLE
from clawseccheck.scoring import ScoreResult, compute

# Each cap signal with the attributes `scoring.compute` would set for it.
_SIGNALS = (
    ("live", {"live_injection_capped": True, "live_injection_cap_reason": "canary:canary"}),
    ("config_blind", {"config_blind_capped": True, "config_blind_reason": "unreadable"}),
    ("degraded", {"degraded_capped": True, "degraded_count": 2}),
    ("severity", {"cap_severity": "CRITICAL"}),
    ("runtime", {"runtime_capped": True, "runtime_cap_reason": "skill_indicator"}),
    ("behavioral", {"behavioral_capped": True, "behavioral_cap_reason": "T1"}),
)
_NAMES = [name for name, _ in _SIGNALS]

_FINDINGS = [Finding(id="B2", title="ok", severity="LOW", status="PASS",
                     detail="d", fix="f", framework="x")]


def _score(active):
    score = copy.copy(compute(_FINDINGS))
    for name, fields in _SIGNALS:
        if name in active:
            for key, value in fields.items():
                object.__setattr__(score, key, value)
    return score


def _caps(active):
    return run_state(_score(active))["capsFired"]


# The ONE place the two vocabularies are related to each other. Kept in the test rather
# than in either module on purpose: neither side should have to know the other's words, and
# a seventh signal must land here as a missing key -- a decision someone makes -- instead of
# being absorbed silently.
_ENGINE_NAME_TO_FLAG = {
    "live": "live_injection_capped",
    "config_blind": "config_blind_capped",
    "degraded": "degraded_capped",
    "severity": "cap_severity",
    "runtime": "runtime_capped",
    "behavioral": "behavioral_capped",
}

# --------------------------------------------------------------- every signal, one by one

@pytest.mark.parametrize("name", _NAMES)
def test_each_cap_signal_alone_reaches_the_packet(name):
    """Per signal, not per fixture. `cap_severity` is the one that was missing, and no
    fixture-driven test would have found it: the packet is assembled from a ScoreResult,
    so the signals have to be driven directly to cover the ones a fixture never sets."""
    caps = _caps({name})
    assert len(caps) == 1, caps
    entry, = caps
    assert entry["what"].strip(), entry

    # Tie the entry to the ATTRIBUTES it claims to read. Without this, swapping two
    # entries' reason attributes is invisible: the wrong attribute is simply unset on a
    # one-signal score, so the key vanishes and every emptiness check still passes.
    flag = _ENGINE_NAME_TO_FLAG[name]
    assert entry["cap"] == flag, entry
    reason_attr, = [r for f, r, _ in _CAP_LADDER if f == flag]
    driven = dict(_SIGNALS)[name]
    if reason_attr is None:
        assert "reason" not in entry, entry
    else:
        assert entry["reason"] == driven[reason_attr], (entry, reason_attr)


def test_the_severity_cap_names_the_severity_that_capped():
    """The specific regression. `cap_severity` is the odd entry -- a string where the other
    five are booleans -- and that asymmetry is why it was skipped, so it gets its own
    assertion rather than riding the parametrised one."""
    entry, = _caps({"severity"})
    assert entry["cap"] == "cap_severity", entry
    assert entry["reason"] == "CRITICAL", entry


def test_nothing_capped_still_reports_an_empty_list():
    """The negative control. Without it, "always append something" passes everything
    above -- and an empty list here is a real answer, not a missing one."""
    assert _caps(set()) == []


# ------------------------------------------------------------------- combinations, as sets

def test_co_occurring_signals_are_all_listed():
    """`capsFired` is a list, so a partial answer looks exactly like a complete one to a
    consumer that only checks emptiness. Asserted as a SET."""
    caps = _caps({"severity", "runtime"})
    assert {c["cap"] for c in caps} == {"cap_severity", "runtime_capped"}, caps


@pytest.mark.parametrize("active", [frozenset(c) for c in itertools.combinations(_NAMES, 2)],
                         ids=lambda a: "+".join(sorted(a)))
def test_every_pair_lists_both(active):
    assert len({c["cap"] for c in _caps(active)}) == 2, _caps(active)


def test_all_six_at_once():
    assert len(_caps(set(_NAMES))) == len(_SIGNALS)


# ------------------------------------------------------------------------- the census

def test_the_ladder_covers_every_signal_the_engine_knows():
    """The guard that makes this durable rather than a one-off repair.

    Anchored on `dataclasses.fields(ScoreResult)` -- the PRODUCER -- not on
    `report._cap_signal_active`, which is a hand-written six-key literal with no
    introspection of scoring. The first version of this test compared lengths against that
    literal, and an independent review disproved the mechanism it claimed: a seventh signal
    added to scoring alone leaves both sides at six and the guard green. That is precisely
    the divergence B-689 WAS -- the ladder said five while scoring said six -- so anchoring
    on a peer would have been a guard against everything except the bug it was written for.

    A set, not a length: a ladder with the right count and one wrong flag passes a count.
    """
    signals = {f.name for f in dataclasses.fields(ScoreResult)
               if f.name.endswith("_capped")} | {"cap_severity"}
    assert {flag for flag, _, _ in _CAP_LADDER} == signals


def test_the_ladder_reads_attributes_that_actually_exist():
    """`ScoreResult` is not frozen, so `getattr(score, "behavioral_cappedd", False)` is a
    silent False, not an error: a typo emits nothing and raises nothing. Checked against
    the dataclass rather than against this file's own `_SIGNALS`, where a typo replicated
    into both literals stays green while production emits an empty list."""
    real = {f.name for f in dataclasses.fields(ScoreResult)}
    for flag, reason_attr, label in _CAP_LADDER:
        assert flag in real, flag
        if reason_attr is not None:
            assert reason_attr in real, (flag, reason_attr)
        assert label and label == label.strip(), (flag, label)


def test_no_two_entries_share_a_label():
    """A duplicated label misattributes one cap as another on third-party judge input --
    a fabricated fact, not a cosmetic slip."""
    labels = [label for _, _, label in _CAP_LADDER]
    assert len(set(labels)) == len(labels), labels




def test_the_ladder_is_in_the_engines_priority_order():
    """It used to be in a third arbitrary order -- neither the cascade's nor any other --
    which is the shape a hand-maintained copy drifts into.

    Anchored on `_CAP_SIGNAL_TABLE`, which is what `_cap_cascade` actually reads to pick the
    primary. An earlier version read `_cap_signal_active`'s dict-literal insertion order:
    the same six names today, but nothing makes them agree, so reordering the real authority
    left this green while the report and the packet named different leading caps.

    Two earlier versions of this test were also unfalsifiable -- one compared
    `dict(zip(a, b)).values()` against `b`, true by construction. Named here because that is
    the same can't-fail shape that let the sibling defect in report.py live for nine days.
    """
    priority = [name for name, _phrase in _CAP_SIGNAL_TABLE]
    assert set(priority) == set(_ENGINE_NAME_TO_FLAG), priority
    assert [flag for flag, _, _ in _CAP_LADDER] == [_ENGINE_NAME_TO_FLAG[n] for n in priority]


# ------------------------------------------------------------- Golden Rule #1 still holds

def test_the_live_reason_is_carried_through_verbatim():
    """The wiring `live_injection_cap_reason` got in this change, covered.

    Without this assertion, reverting that one word to `None` -- the pre-change state --
    leaves every other test in this file green, which an independent review demonstrated.
    """
    entry, = _caps({"live"})
    assert entry["reason"] == "canary:canary", entry


def test_the_widest_real_reason_stays_one_bounded_line():
    """`run_state` copies every reason VERBATIM -- `adjudication.py` contains no sanitiser,
    unlike `PipelineResult.to_json`, which routes the same class of payload through
    `report._sanitize_tree`. So the safety of this boundary rests entirely on the producers,
    and asserting it against this file's own 15-character fixtures would be asserting a
    property of the fixtures.

    The widest value any of the six can carry is the live one, so it is built HERE by the
    real producer at its own limit: six `multiturn:<32 chars>` labels plus the "(+N more)"
    suffix, which `pipeline.live_test_cap_signal` caps at 272 characters. That is what the
    320 bound below is measured against, rather than guessed -- an earlier version of this
    test pinned 120 and passed only because "canary:canary" is 13.
    """
    widest = live_test_cap_signal({"verdicts": [
        {"tool": "multiturn", "id": "i" * 32, "verdict": "VULNERABLE"} for _ in range(8)]})
    assert widest.hit and len(widest.reason) > 250, len(widest.reason)

    score = _score({"live"})
    object.__setattr__(score, "live_injection_cap_reason", widest.reason)
    entry, = run_state(score)["capsFired"]
    assert entry["reason"] == widest.reason
    assert "\n" not in entry["reason"] and "\r" not in entry["reason"]
    assert len(entry["reason"]) <= 320, len(entry["reason"])


def test_every_reason_is_a_bounded_single_line_label():
    """The shape every stable label must have. Deliberately weaker than the test above and
    kept for the other five: their producers are enumerations and regex-gated ids, so there
    is no wide case to build -- but a future entry wired to a free-text attribute would
    still have to pass this, and the one above says what the boundary does NOT enforce.
    """
    for entry in _caps(set(_NAMES)):
        reason = entry.get("reason")
        if reason is None:
            continue
        assert isinstance(reason, str) and reason.strip(), entry
        assert "\n" not in reason and "\r" not in reason, entry
        assert len(reason) <= 320, entry
