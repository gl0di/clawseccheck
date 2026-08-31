"""A capped run does not read as uncapped to a scanning consumer.

`sarif.py`'s completeness block published `configBlind` — one of the six signals that can
cap the score — and nothing else. So a run capped by an open CRITICAL, a fired behavioural
detector, a corroborated runtime indicator or a submitted VULNERABLE live-test verdict
emitted SARIF that said nothing about any of it, with `configBlind.capped: false` sitting
there looking like an answer.

That matters more here than in a report a human reads. SARIF goes to CI and code-scanning
consumers which act on it unaccompanied — nobody is reading the prose report beside it.

Same defect as B-689 (`capsFired: []` handed to the judge on a CRITICAL-capped run), split
off because `capsFired` was already a list there while `configBlind` is a named object for
one signal, and carrying six needed a decision about the public shape rather than a wider
literal.

The decisions this file pins:

* **One producer.** `adjudication.caps_fired` builds the list; `run_state` and this block
  both consume it. B-689, B-692, B-693 and B-694 were each one rule kept by hand in two
  places, and a fifth was not worth having.
* **Always present.** An empty list is a real answer — "nothing capped this run". The rule
  is the block's own, stated for `selfExcludedSkills` under B-560: an absent key would make
  that indistinguishable from "this producer is too old to say".
* **`configBlind` is unchanged.** It is documented and a consumer may already read it.
  Breaking it to tidy the duplication would trade a silence for a regression, so the two
  are pinned as unable to disagree instead.

Offline, stdlib only, writes nothing outside tmp_path.
"""
from __future__ import annotations

import copy
import dataclasses
import json

import pytest

from clawseccheck.adjudication import _CAP_LADDER, caps_fired
from clawseccheck.catalog import Finding
from clawseccheck.sarif import render_sarif
from clawseccheck.scoring import ScoreResult, compute

_FINDINGS = [Finding(id="B2", title="ok", severity="LOW", status="PASS",
                     detail="d", fix="f", framework="x")]

# Each signal with the attributes `scoring.compute` would set for it.
_SIGNALS = (
    ("live", {"live_injection_capped": True, "live_injection_cap_reason": "canary:canary"}),
    ("config_blind", {"config_blind_capped": True, "config_blind_reason": "unreadable"}),
    ("degraded", {"degraded_capped": True, "degraded_count": 2}),
    ("severity", {"cap_severity": "CRITICAL"}),
    ("runtime", {"runtime_capped": True, "runtime_cap_reason": "skill_indicator"}),
    ("behavioral", {"behavioral_capped": True, "behavioral_cap_reason": "T1"}),
)
_NAMES = [name for name, _ in _SIGNALS]
_FLAG_FOR = {
    "live": "live_injection_capped",
    "config_blind": "config_blind_capped",
    "degraded": "degraded_capped",
    "severity": "cap_severity",
    "runtime": "runtime_capped",
    "behavioral": "behavioral_capped",
}


def _score(active):
    score = copy.copy(compute(_FINDINGS))
    for name, fields in _SIGNALS:
        if name in active:
            for key, value in fields.items():
                object.__setattr__(score, key, value)
    return score


def _block(active):
    """The completeness block, out of the REAL renderer rather than a helper."""
    doc = json.loads(render_sarif(_FINDINGS, _score(active)))
    return doc["runs"][0]["properties"]["analysisCompleteness"]


# ------------------------------------------------------------------- every signal arrives

@pytest.mark.parametrize("name", _NAMES)
def test_each_cap_signal_alone_reaches_a_sarif_consumer(name):
    """Per signal, not per fixture: five of these were invisible, and no fixture-driven
    test would have found them because a fixture sets one signal at most."""
    block = _block({name})
    caps = block["capsFired"]
    assert [c["cap"] for c in caps] == [_FLAG_FOR[name]], caps
    assert caps[0]["what"].strip(), caps


def test_nothing_capped_emits_an_empty_list_not_a_missing_key():
    """B-560's rule for this block, applied to a second key. An absent key would make
    "nothing capped this run" and "this producer predates the field" identical."""
    block = _block(set())
    assert block["capsFired"] == []
    assert not any("capped" in line for line in block["limitations"]), block["limitations"]


def test_co_occurring_signals_are_all_listed_in_cascade_order():
    """A list makes a partial answer look exactly like a complete one to a consumer that
    only checks emptiness."""
    caps = [c["cap"] for c in _block({"severity", "config_blind"})["capsFired"]]
    assert caps == ["config_blind_capped", "cap_severity"], caps


def test_the_prose_limitation_names_the_caps_when_there_are_any():
    """A consumer keying on `limitations` alone — a common SARIF pattern — would otherwise
    still miss it. Structure is the requirement; this is the block's own convention."""
    lines = _block({"severity"})["limitations"]
    assert any("the score was capped" in line for line in lines), lines


# ------------------------------------------------------- what must NOT have changed

@pytest.mark.parametrize("name", _NAMES)
def test_config_blind_keeps_its_shape_and_cannot_disagree(name):
    """`configBlind` is documented and a consumer may already read it, so it is kept rather
    than folded in. The cost of keeping it is that one fact now appears twice — which is the
    failure this whole family is made of, so it is pinned rather than commented."""
    block = _block({name})
    assert set(block["configBlind"]) == {"capped", "reason"}, block["configBlind"]
    in_list = any(c["cap"] == "config_blind_capped" for c in block["capsFired"])
    assert block["configBlind"]["capped"] is in_list, block


def test_the_block_gained_exactly_one_key():
    """Additive by construction. A SARIF consumer reads by key, so an existing key changing
    meaning is the breakage that matters — this asserts none did."""
    block = _block(set())
    assert "capsFired" in block
    for key in ("configBlind", "graded", "layersTotal", "layersRan", "missingLayers",
                "notChecked", "limitations", "checksRun", "checksTotal"):
        assert key in block, key


# ------------------------------------------------------------------------- the census

def test_the_ladder_covers_every_signal_the_engine_can_set():
    """Anchored on `dataclasses.fields(ScoreResult)` — the PRODUCER — not on a peer.

    B-689's first version of this guard compared against `report._cap_signal_active`, which
    is a hand-written six-key literal with no introspection of scoring: it would have missed
    exactly the divergence it was written for. A set, not a length, because a ladder with the
    right count and one wrong flag passes a count.
    """
    signals = {f.name for f in dataclasses.fields(ScoreResult)
               if f.name.endswith("_capped")} | {"cap_severity"}
    assert {flag for flag, _, _ in _CAP_LADDER} == signals


def test_sarif_and_the_judge_packet_read_the_same_producer():
    """One list, two artifacts. If these ever diverge, a run is capped in one machine
    output and uncapped in the other — which is the shape of this bug and of B-689."""
    for name in _NAMES:
        score = _score({name})
        assert _block({name})["capsFired"] == caps_fired(score), name


def test_the_producer_is_not_reimplemented_in_sarif():
    """The structural half: `sarif.py` must not grow its own copy of the ladder. Measured
    before this change, it read `config_blind_capped` directly and knew none of the others.
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "clawseccheck" / "sarif.py").read_text(
        encoding="utf-8")
    for flag in ("live_injection_capped", "degraded_capped", "runtime_capped",
                 "behavioral_capped", "cap_severity"):
        assert flag not in src, flag
    assert "caps_fired" in src
