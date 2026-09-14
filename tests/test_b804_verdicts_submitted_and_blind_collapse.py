"""B-804: an empty judged.verdicts list must never read as "verdicts submitted", and a
config-blind run must not flood the judge packet with 150+ near-identical UNKNOWN items.

Two independent fixes, tested independently:

  1. pipeline.run_adjudication gates ``verdictsSubmitted`` on the PARSED verdict map
     (``adjudication._parse_verdicts``' own return value), not on the raw bundle shape.
  2. adjudication.build_judge_packet collapses UNKNOWNs whose *own* Finding.detail says
     the sole cause is a missing/unreadable openclaw.json into one disclosed run-level
     item, gated on the same structural config-blind signal scoring.py's own
     CONFIG_BLIND_CAP reads (``scoring._config_blind_signal``).

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck import pipeline as pl
from clawseccheck.adjudication import (
    _CONFIG_BLIND_COLLAPSE_MIN,
    build_judge_packet,
)
from clawseccheck.catalog import UNKNOWN
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


# ---------------------------------------------------------------------------
# Part 1 — verdictsSubmitted must track the PARSED map, not the raw bundle
# ---------------------------------------------------------------------------

def test_empty_verdicts_list_is_not_reported_as_submitted():
    """The exact repro shape: {"judged": {"verdicts": []}} over a config that would
    otherwise offer borderline items -- verdictsSubmitted must be False, and the
    rendered text must be the honest "awaiting adjudication" line, never "N of M
    judged"."""
    ctx = collect(FIXTURES / "home_vuln")
    from clawseccheck.checks import run_all
    findings = run_all(ctx)
    p = pl.run_adjudication(ctx, findings, bundle={"judged": {"verdicts": []}})
    assert p.data["verdictsSubmitted"] is False
    assert "secondOpinion" not in p.data
    assert "awaiting adjudication" in p.detail
    assert "judged" not in p.detail  # never the "N of M ... judged" wording
    joined = "\n".join(p.lines)
    assert "No verdicts submitted" in joined
    assert "borderline item(s) carry a submitted verdict" not in joined


def test_judged_bucket_with_no_verdicts_key_at_all_is_also_not_submitted():
    """A "judged" bucket present but carrying no "verdicts" array at all (e.g. {}) must
    resolve the same way as an explicit empty list -- both parse to zero usable
    entries, and _parse_verdicts' own contract treats them identically."""
    ctx = collect(FIXTURES / "home_vuln")
    from clawseccheck.checks import run_all
    findings = run_all(ctx)
    p = pl.run_adjudication(ctx, findings, bundle={"judged": {}})
    assert p.data["verdictsSubmitted"] is False
    assert "secondOpinion" not in p.data


def test_one_real_verdict_is_reported_as_submitted():
    """A genuinely non-empty, usable verdicts array must still take the old path:
    verdictsSubmitted True and the "1 of N ... judged" wording."""
    ctx = collect(FIXTURES / "home_vuln")
    from clawseccheck.checks import run_all
    findings = run_all(ctx)
    packet = build_judge_packet(ctx, findings)
    assert packet, "fixture must offer at least one borderline item for this test to mean anything"
    item = packet[0]
    bundle = {"judged": {"verdicts": [
        {"finding_id": item["finding_id"], "target": item["target"], "verdict": "SAFE"},
    ]}}
    p = pl.run_adjudication(ctx, findings, bundle=bundle)
    assert p.data["verdictsSubmitted"] is True
    assert isinstance(p.data["secondOpinion"], list)
    reviewed = sum(1 for row in p.data["secondOpinion"] if row.get("judge_verdict"))
    assert reviewed == 1
    assert f"1 of {len(p.data['secondOpinion'])} borderline item(s) judged" in p.quiet_line


def test_no_bundle_at_all_matches_empty_verdicts_exactly():
    """No bundle and an explicitly empty verdicts list must be indistinguishable to a
    consumer -- both are "nothing submitted"."""
    ctx = collect(FIXTURES / "home_vuln")
    from clawseccheck.checks import run_all
    findings = run_all(ctx)
    p_none = pl.run_adjudication(ctx, findings)
    p_empty = pl.run_adjudication(ctx, findings, bundle={"judged": {"verdicts": []}})
    assert p_none.data["verdictsSubmitted"] == p_empty.data["verdictsSubmitted"] is False
    assert p_none.detail == p_empty.detail
    assert p_none.quiet_line == p_empty.quiet_line


def test_wiring_the_fix_actually_gates_on_the_parsed_map(monkeypatch):
    """A monkeypatched _parse_verdicts returning {} for ANY input (simulating "nothing
    usable was submitted") must still leave verdictsSubmitted False even though the raw
    bundle carries a non-empty-looking "judged" dict -- proving the call site reads the
    PARSED result and not just bundle.get("judged") is not None."""
    ctx = collect(FIXTURES / "home_vuln")
    from clawseccheck.checks import run_all
    findings = run_all(ctx)
    # run_adjudication imports _parse_verdicts lazily FROM adjudication at call time
    # (see the module note on layering), so the patch target is the defining module.
    import clawseccheck.adjudication as adjudication_mod
    monkeypatch.setattr(adjudication_mod, "_parse_verdicts", lambda raw: {})
    p = pl.run_adjudication(
        ctx, findings,
        bundle={"judged": {"verdicts": [{"finding_id": "x", "target": "y", "verdict": "SAFE"}]}},
    )
    assert p.data["verdictsSubmitted"] is False


# ---------------------------------------------------------------------------
# Part 2 — config-blind collapse
# ---------------------------------------------------------------------------

def test_config_blind_run_collapses_the_shared_cause_into_one_item(tmp_path):
    """An entirely empty home (no openclaw.json at all) must not hand the judge one
    item per config-surface check restating the identical fact -- they collapse into
    one disclosed CONFIG_BLIND item naming every id it stands in for."""
    ctx = collect(tmp_path)
    assert ctx.config_found is False
    from clawseccheck.checks import run_all
    findings = run_all(ctx)
    packet = build_judge_packet(ctx, findings)

    collapsed = [i for i in packet if i["finding_id"] == "CONFIG_BLIND"]
    assert len(collapsed) == 1, "exactly one collapsed run-level item, not zero and not several"
    item = collapsed[0]

    ids = item["safe_facts"]["collapsed_finding_ids"]
    assert len(ids) >= _CONFIG_BLIND_COLLAPSE_MIN
    assert item["safe_facts"]["collapsed_count"] == len(ids)
    assert item["engine_disposition"] == UNKNOWN
    # nothing silently dropped: every named id must be ABSENT from the packet as its
    # own separate item (folded away, not duplicated)
    other_ids = {i["finding_id"] for i in packet if i["finding_id"] != "CONFIG_BLIND"}
    assert not (set(ids) & other_ids)
    # disclosed, not silent: the packet is smaller than the pre-collapse item count
    # would have been, and the reason is spelled out in plain text
    assert "openclaw.json" in item["redacted_evidence"]
    assert "openclaw.json" in item["question"]


def test_config_blind_collapse_has_uniform_packet_item_shape(tmp_path):
    """The synthetic item must carry exactly the same key set as every other packet
    item (tests/test_b571_packet_item_shape.py's own invariant) -- it goes through the
    identical post-processing pipeline, not a hand-rolled shortcut."""
    ctx = collect(tmp_path)
    from clawseccheck.checks import run_all
    findings = run_all(ctx)
    packet = build_judge_packet(ctx, findings)
    keysets = {tuple(sorted(i.keys())) for i in packet}
    assert len(keysets) == 1, f"packet items disagree on their key set: {keysets}"


def test_config_found_home_vuln_control_is_unaffected():
    """Control: a run where openclaw.json genuinely was read must never trigger the
    collapse -- proves the collapse is scoped to config-blind runs only, not a general
    "many UNKNOWNs" heuristic."""
    ctx = collect(FIXTURES / "home_vuln")
    assert ctx.config_found is True
    from clawseccheck.checks import run_all
    findings = run_all(ctx)
    packet = build_judge_packet(ctx, findings)
    assert not any(i["finding_id"] == "CONFIG_BLIND" for i in packet)


def test_full_pipeline_json_on_config_blind_home_does_not_flood(tmp_path):
    """End-to-end: --full --json on a config-blind home must not carry 150+
    near-identical borderline items in the top-level judgePacket."""
    from clawseccheck.cli import main
    import json
    import sys
    import io

    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        main(["--home", str(tmp_path), "--no-history", "--full", "--json"])
        out = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
    payload = json.loads(out)
    assert payload["verdictsSubmitted"] is False
    packet = payload["judgePacket"]
    collapsed = [i for i in packet if i["finding_id"] == "CONFIG_BLIND"]
    assert len(collapsed) == 1
    assert collapsed[0]["safe_facts"]["collapsed_count"] >= _CONFIG_BLIND_COLLAPSE_MIN


# ---------------------------------------------------------------------------
# Advisory-only invariant — the judge panel must never move the grade
# ---------------------------------------------------------------------------

def test_collapse_never_touches_findings_or_score(tmp_path):
    """Hard invariant (docs/OUTPUT_SCHEMA.md §13, restated by
    test_run_adjudication_own_config_safe_verdict_only_annotates elsewhere): assembling
    the judge packet -- collapsed or not -- must never alter a Finding's status,
    severity, or the findings list itself."""
    ctx = collect(tmp_path)
    from clawseccheck.checks import run_all
    findings_before = run_all(collect(tmp_path))
    build_judge_packet(ctx, findings_before)
    findings_after = run_all(collect(tmp_path))
    assert findings_before == findings_after
