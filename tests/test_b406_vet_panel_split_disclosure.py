"""CLAWSECCHECK-B-406: same-input stability + split-panel disclosure on the
``--vet-judged`` escalation path.

Scope, decided against the ticket's own candidate directions: the judge is a
host agent outside this tool (stdlib-only, no network, no LLM), so ClawSecCheck
cannot make an external judge invocation itself deterministic across two wholly
separate calls -- nothing offline can compel that. What IS in this tool's own
control, and what these tests pin:

1. Same input -> same REQUEST: build_vet_judge_packet()/render_vet_judge_packet_json()
   are deterministic -- the packet handed to a judge for byte-identical findings is
   byte-identical every time, so any variance a pilot measures is not manufactured
   by clawseccheck's own packet construction.
2. An inconsistent RESPONSE is made detectable rather than silently authoritative:
   SKILL.md's documented 3-lens panel lets a host submit an optional ``votes``
   breakdown alongside its reduced ``verdict`` (the same field _annotate already
   used for the audit-path second opinion) -- escalate_vet_output previously parsed
   that breakdown and then discarded it, so a 2-1 split escalation and a 3-0
   unanimous one produced byte-identical `detail` text. This is now disclosed.

Explicitly NOT attempted here (see adjudication.py's B-406 docstring notes): a
persistent cross-invocation verdict cache. That is a real feature with its own
Golden-Rule-#2 design question, not a same-sitting patch, and would touch
history.py/monitor.py, which this task does not own.
"""
from __future__ import annotations

import json

from clawseccheck.adjudication import (
    _vet_run_fingerprint,
    build_vet_judge_packet,
    escalate_vet_output,
    render_vet_judge_packet_json,
)
from clawseccheck.catalog import FAIL, HIGH, WARN, Finding


def _primary():
    return Finding("B65", "t", HIGH, WARN, "primary detail", "fix it", "fw",
                    evidence=["skillx: matched pattern (skill.py:1)"])


# ---------------------------------------------------------------------------
# 1. Same input -> same request
# ---------------------------------------------------------------------------

def test_vet_judge_packet_is_deterministic_across_repeated_calls():
    """The REQUEST clawseccheck hands to a judge is stable: byte-identical
    findings must produce a byte-identical packet every time, regardless of
    how many times build_vet_judge_packet is called."""
    first = build_vet_judge_packet(_primary(), "skillx")
    second = build_vet_judge_packet(_primary(), "skillx")
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_render_vet_judge_packet_json_is_deterministic():
    a = render_vet_judge_packet_json(_primary(), target="skillx", version="9.9.9")
    b = render_vet_judge_packet_json(_primary(), target="skillx", version="9.9.9")
    assert a == b


# ---------------------------------------------------------------------------
# 2. Inconsistent response -> detectable, not silently authoritative
# ---------------------------------------------------------------------------

def test_split_panel_verdict_is_disclosed_in_escalated_detail():
    """A 2/3-DANGEROUS, 1-dissenting-SAFE panel still escalates (majority rules,
    per SKILL.md) but the disagreement must now be visible in the escalated
    finding's own `detail` -- not indistinguishable from a unanimous verdict."""
    fp = _vet_run_fingerprint("skillx")
    payload = json.dumps({
        "targetFingerprint": fp,
        "verdicts": [{
            "finding_id": "B65", "target": "skillx", "verdict": "DANGEROUS",
            "votes": {"SAFE": 1, "SUSPICIOUS": 0, "DANGEROUS": 2},
        }],
    })
    out = escalate_vet_output(_primary(), payload, target="skillx")
    assert out.status == FAIL
    assert "panel split" in out.detail
    assert "2/3 DANGEROUS" in out.detail


def test_unanimous_panel_verdict_is_not_flagged_as_split():
    """Negative control: a genuinely unanimous 3/3 panel must NOT be flagged as
    split -- the disclosure only fires on real disagreement."""
    fp = _vet_run_fingerprint("skillx")
    payload = json.dumps({
        "targetFingerprint": fp,
        "verdicts": [{
            "finding_id": "B65", "target": "skillx", "verdict": "DANGEROUS",
            "votes": {"SAFE": 0, "SUSPICIOUS": 0, "DANGEROUS": 3},
        }],
    })
    out = escalate_vet_output(_primary(), payload, target="skillx")
    assert out.status == FAIL
    assert "panel split" not in out.detail
    assert out.detail == "[escalated by host-agent judge: DANGEROUS] primary detail"


def test_no_votes_submitted_still_escalates_with_unchanged_detail():
    """Backward compatibility: a verdicts entry with no `votes` field at all
    (the pre-B-406 shape, and still schema-valid) must escalate exactly as
    before -- no split note, no crash."""
    fp = _vet_run_fingerprint("skillx")
    payload = json.dumps({
        "targetFingerprint": fp,
        "verdicts": [{"finding_id": "B65", "target": "skillx", "verdict": "DANGEROUS"}],
    })
    out = escalate_vet_output(_primary(), payload, target="skillx")
    assert out.status == FAIL
    assert "panel split" not in out.detail
    assert out.detail == "[escalated by host-agent judge: DANGEROUS] primary detail"


def test_split_disclosure_reaches_ring_findings_too():
    """The disclosure must apply everywhere _escalate_finding runs, not just the
    primary -- a ring_finding escalated by a split panel needs the same tell."""
    primary = _primary()
    primary.ring_findings = [
        Finding("B100", "t", HIGH, WARN, "ring detail", "fix it", "fw",
                evidence=["skillx: matched pattern (skill.py:2)"]),
    ]
    fp = _vet_run_fingerprint("skillx")
    payload = json.dumps({
        "targetFingerprint": fp,
        "verdicts": [{
            "finding_id": "B100", "target": "skillx", "verdict": "DANGEROUS",
            "votes": {"SAFE": 1, "SUSPICIOUS": 0, "DANGEROUS": 2},
        }],
    })
    out = escalate_vet_output(primary, payload, target="skillx")
    ring = next(f for f in out.ring_findings if f.id == "B100")
    assert ring.status == FAIL
    assert "panel split" in ring.detail
