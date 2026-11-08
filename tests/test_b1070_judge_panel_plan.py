"""B-1070: the ``--judge-packet`` envelope carries a ``panelPlan`` a chat panel can finish.

In chat a real home's packet was 123 items (121 UNKNOWN, ~109k chars, ~370 judge calls
under the 3-lens protocol); the agent scripted 109 identical SUSPICIOUS verdicts and
presented them as the panel. The plan separates the evidence-less items (answer ABSTAIN,
no fan-out), orders the rest, and bounds what a chat panel is asked to judge.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck import audit
from clawseccheck.adjudication import build_judge_packet
from clawseccheck.adjudication._builder import (
    PANEL_CHAT_BUDGET,
    build_panel_plan,
    render_judge_packet_json,
)
from clawseccheck.catalog import UNKNOWN, WARN

REPO = Path(__file__).resolve().parents[1]
VULN = REPO / "fixtures" / "home_vuln"


def _item(fid, target, disposition=UNKNOWN, abstain=False):
    schema = {"verdict": "SAFE | SUSPICIOUS | DANGEROUS"}
    if abstain:
        schema["abstain"] = "only when nothing in the packet lets you decide"
    return {"finding_id": fid, "target": target, "engine_disposition": disposition,
            "verdict_schema": schema}


def test_plan_counts_and_orders():
    items = [_item("B101", "B101", abstain=True), _item("B13", "skill-a"),
             _item("B65", "skill-b", disposition=WARN), _item("B17", "B17", abstain=True)]
    plan = build_panel_plan(items)
    assert (plan["items"], plan["evidenceLess"], plan["toJudge"]) == (4, 2, 2)
    assert plan["chatBudget"] == PANEL_CHAT_BUDGET
    # WARN first, and no evidence-less item is ever in the judge list.
    assert plan["judgeFirst"][0] == {"finding_id": "B65", "target": "skill-b"}
    assert {d["finding_id"] for d in plan["judgeFirst"]} == {"B13", "B65"}
    assert "Never generate verdicts by script" in plan["note"]
    assert "submit none for them" in plan["note"]


def test_the_envelope_carries_the_plan_and_it_matches_the_packet():
    ctx, findings, score = audit(VULN)
    doc = json.loads(render_judge_packet_json(ctx, findings, version="t", score=score))
    plan, packet = doc["panelPlan"], doc["judgePacket"]
    assert plan["items"] == len(packet)
    assert plan["evidenceLess"] + plan["toJudge"] == len(packet)
    keys = {(it["finding_id"], it["target"]) for it in packet}
    assert all((d["finding_id"], d["target"]) in keys for d in plan["judgeFirst"])


def test_an_evidence_less_item_asks_a_question_a_chat_judge_can_answer():
    ctx, findings, _score = audit(VULN)
    for it in build_judge_packet(ctx, findings):
        if "abstain" in it["verdict_schema"]:
            assert "full report" not in it["question"]
            assert "ABSTAIN" in it["question"]
