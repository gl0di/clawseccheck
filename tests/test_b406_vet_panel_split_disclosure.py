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
    _VET_ATTEST_QUESTIONS,
    _vet_attest_new_findings,
    _vet_run_fingerprint,
    build_vet_judge_packet,
    escalate_vet_output,
    render_vet_judge_packet_json,
)
from clawseccheck.catalog import FAIL, HIGH, WARN, Finding
from clawseccheck.checks import vet_skill


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


def _primary_with_ring():
    primary = _primary()
    primary.ring_findings = [
        Finding("B100", "t", HIGH, WARN, "ring detail", "fix it", "fw",
                evidence=["skillx: matched pattern (skill.py:2)"]),
    ]
    return primary


# ---------------------------------------------------------------------------
# 3. Same parity gap, on the ATTEST-PROSE-* new-finding path
#    (_vet_attest_new_findings had its own copy of the same discard bug)
# ---------------------------------------------------------------------------

def test_attest_split_verdict_is_disclosed_in_new_finding_detail():
    """The vote-breakdown parity gap `_escalate_finding` closed above also
    existed, separately, on the ATTEST-PROSE-* new-finding path -- this
    function threw the same `votes` field away at its own call site."""
    verdicts_map = {
        ("ATTEST-PROSE-INJECTION", "quick-tool"): {
            "verdict": "DANGEROUS",
            "votes": {"SAFE": 1, "SUSPICIOUS": 0, "DANGEROUS": 2},
        },
    }
    findings = _vet_attest_new_findings("quick-tool", verdicts_map)
    assert len(findings) == 1
    f = findings[0]
    assert f.status == WARN
    assert "panel split" in f.detail
    assert "2/3 DANGEROUS" in f.detail


def test_attest_unanimous_verdict_is_not_flagged_as_split():
    """Negative control, mirroring the escalation-path test above: a genuinely
    unanimous panel must not be flagged, and `detail` must stay byte-identical
    to what this function produced before this change."""
    verdicts_map = {
        ("ATTEST-PROSE-INJECTION", "quick-tool"): {
            "verdict": "DANGEROUS",
            "votes": {"SAFE": 0, "SUSPICIOUS": 0, "DANGEROUS": 3},
        },
    }
    findings = _vet_attest_new_findings("quick-tool", verdicts_map)
    assert len(findings) == 1
    f = findings[0]
    assert "panel split" not in f.detail
    assert f.detail == (
        "[host-agent pre-install attestation, verdict DANGEROUS] "
        f"{_VET_ATTEST_QUESTIONS['ATTEST-PROSE-INJECTION']}"
    )


def test_attest_no_votes_submitted_still_unchanged_detail():
    """Backward compatibility: a verdicts entry with no `votes` field at all
    (the pre-B-406 shape, still schema-valid) must produce the same `detail`
    as before this change -- no split note, no crash."""
    verdicts_map = {("ATTEST-PROSE-INJECTION", "quick-tool"): {"verdict": "DANGEROUS"}}
    findings = _vet_attest_new_findings("quick-tool", verdicts_map)
    assert len(findings) == 1
    f = findings[0]
    assert "panel split" not in f.detail
    assert f.detail == (
        "[host-agent pre-install attestation, verdict DANGEROUS] "
        f"{_VET_ATTEST_QUESTIONS['ATTEST-PROSE-INJECTION']}"
    )


# ---------------------------------------------------------------------------
# 4. Cross-call idempotence -- the OWNED half of "same prose twice -> same
#    verdict": clawseccheck's own function, not the external judge, called
#    twice on byte-identical input.
# ---------------------------------------------------------------------------

def test_escalate_vet_output_is_idempotent_across_separate_calls():
    """ClawSecCheck cannot compel two wholly separate host-agent judge
    invocations to agree with each other -- that limit is the external
    judge's, disclosed in `fix`, not something this code can fix. What it
    CAN and must guarantee: two separate calls of ITS OWN
    `escalate_vet_output`, given byte-identical (engine_output, verdicts_raw,
    target), produce byte-identical output every time."""
    fp = _vet_run_fingerprint("skillx")
    payload = json.dumps({
        "targetFingerprint": fp,
        "verdicts": [
            {"finding_id": "B65", "target": "skillx", "verdict": "DANGEROUS",
             "votes": {"SAFE": 1, "SUSPICIOUS": 0, "DANGEROUS": 2}},
            {"finding_id": "ATTEST-PROSE-INJECTION", "target": "skillx", "verdict": "SUSPICIOUS",
             "votes": {"SAFE": 1, "SUSPICIOUS": 2, "DANGEROUS": 0}},
        ],
    })

    out_a = escalate_vet_output(_primary_with_ring(), payload, target="skillx")
    out_b = escalate_vet_output(_primary_with_ring(), payload, target="skillx")

    assert out_a.status == out_b.status == FAIL
    assert out_a.detail == out_b.detail
    ring_a = {f.id: (f.status, f.detail) for f in out_a.ring_findings}
    ring_b = {f.id: (f.status, f.detail) for f in out_b.ring_findings}
    assert ring_a == ring_b
    assert "ATTEST-PROSE-INJECTION" in ring_a
    assert "panel split" in ring_a["ATTEST-PROSE-INJECTION"][1]


# ---------------------------------------------------------------------------
# 5. Same skill content under two directory names -> same packet once the
#    name-derived field is normalised away
# ---------------------------------------------------------------------------

def test_same_skill_content_two_directory_names_normalises_to_the_same_packet(tmp_path):
    """The packet clawseccheck hands to a judge must be driven by the skill's
    CONTENT, not the incidental directory name it happens to be installed
    under -- the shape the pilot's "identical prose" premise actually needs.
    Same SKILL.md body, two different directory names -> packet items equal
    once the name-derived `target` field is stripped."""
    skill_md = (
        "---\nname: demo\ndescription: does a thing\n---\n"
        "# Demo\nJust reads a local file and prints it.\n"
    )
    dir_a = tmp_path / "alpha-skill"
    dir_b = tmp_path / "totally-different-name"
    for d in (dir_a, dir_b):
        d.mkdir(parents=True)
        (d / "SKILL.md").write_text(skill_md, encoding="utf-8")

    finding_a = vet_skill(dir_a)
    finding_b = vet_skill(dir_b)
    items_a = build_vet_judge_packet(finding_a, str(dir_a))
    items_b = build_vet_judge_packet(finding_b, str(dir_b))

    def _normalised(items):
        return [{k: v for k, v in item.items() if k != "target"} for item in items]

    assert len(items_a) == len(items_b) >= 1
    assert _normalised(items_a) == _normalised(items_b)
    assert {i["target"] for i in items_a} == {"alpha-skill"}
    assert {i["target"] for i in items_b} == {"totally-different-name"}
