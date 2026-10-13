"""C-712 item 4: a judge could only answer SAFE / SUSPICIOUS / DANGEROUS.

A live OpenClaw agent was handed a packet of 25 UNKNOWN-status items, every one of which
carried the boilerplate "no evidence entries" line, and had no honest answer: any categorical
verdict would have measured the missing information, not the suspicion. It submitted an empty
list. The protocol now accepts a fourth verdict, ``ABSTAIN`` (exact string), meaning "I could
not decide from the packet".

ABSTAIN is treated exactly like "no verdict submitted for this item". It never lowers or
raises a finding, never counts as reviewed, and is counted and disclosed wherever unreviewed
items are. The load-bearing property, attacked below from every side: ABSTAIN must never be
able to HIDE a real verdict for the same item, and an all-ABSTAIN bundle must leave the run in
the state an empty verdict list leaves it in.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
VULN = str(REPO_ROOT / "fixtures" / "home_vuln")


def _run(tmp_path: Path, *args: str):
    fake_home = tmp_path / "home"
    fake_home.mkdir(exist_ok=True)
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", VULN, "--no-history",
         "--no-deptree", "--no-host", "--data-dir", str(tmp_path / "state"), *args],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=400,
        env={**os.environ, "HOME": str(fake_home)})


def _packet(tmp_path: Path) -> list:
    return json.loads(_run(tmp_path, "--judge-packet").stdout)["judgePacket"]


def _entry(item, verdict, **extra):
    return {"finding_id": item["finding_id"], "target": item["target"],
            "verdict": verdict, "reason": "r", **extra}


def _judged(tmp_path, name, entries):
    """``--judged`` run: the standalone JSON with its ``secondOpinion`` panel."""
    f = tmp_path / f"{name}.json"
    f.write_text(json.dumps({"verdicts": entries}), encoding="utf-8")
    proc = _run(tmp_path, "--json", "--judged", str(f))
    assert proc.returncode in (0, 1), proc.stderr[:400]
    return json.loads(proc.stdout), proc.stderr


def _bundle(tmp_path, name, entries):
    """``--full --judged-bundle`` run: the whole-audit JSON."""
    f = tmp_path / f"{name}.json"
    f.write_text(json.dumps({"judged": {"verdicts": entries}}), encoding="utf-8")
    proc = _run(tmp_path, "--full", "--json", "--judged-bundle", str(f))
    assert proc.returncode in (0, 1), proc.stderr[:400]
    return json.loads(proc.stdout), proc.stderr


def _without(d, *keys):
    return {k: v for k, v in d.items() if k not in keys}


def _rows(payload):
    return {(r["finding_id"], r["target"]): r for r in payload["secondOpinion"]}


# ------------------------------------------------------------------ the parser (unit)

def test_abstain_is_a_recognised_verdict_that_stores_nothing(capsys):
    """ABSTAIN alone must not read as 'every submitted entry was unusable' (B-330's loud
    complaint), and must not enter the map the consumers read."""
    from clawseccheck.adjudication import _parse_verdicts

    raw = json.dumps({"verdicts": [
        {"finding_id": "B100", "target": "B100", "verdict": "ABSTAIN"}]})
    assert _parse_verdicts(raw) == {}
    err = capsys.readouterr().err
    assert "usable" not in err, err
    assert "1 ABSTAIN answer(s) submitted" in err, err


def test_abstain_with_a_real_verdict_for_the_same_item_never_hides_it(capsys):
    """Both orders. The non-abstain verdict wins exactly as it would have alone, and the
    item is not reported as abstained (it has a verdict)."""
    from clawseccheck.adjudication import _parse_verdicts

    def entry(v):
        return {"finding_id": "B100", "target": "B100", "verdict": v,
                "votes": {v: 2, "ABSTAIN": 1}}

    for real in ("SAFE", "SUSPICIOUS", "DANGEROUS"):
        alone = _parse_verdicts(json.dumps({"verdicts": [entry(real)]}))
        for order in ([entry("ABSTAIN"), entry(real)], [entry(real), entry("ABSTAIN")]):
            got = _parse_verdicts(json.dumps({"verdicts": order}))
            assert got == alone, (real, order)
            assert got[("B100", "B100")]["verdict"] == real
    assert "abstained" not in capsys.readouterr().err


def test_abstain_between_two_real_verdicts_does_not_disturb_severity_resolution():
    from clawseccheck.adjudication import _parse_verdicts

    def entry(v):
        return {"finding_id": "B100", "target": "B100", "verdict": v}

    raw = json.dumps({"verdicts": [entry("DANGEROUS"), entry("ABSTAIN"), entry("SAFE")]})
    assert _parse_verdicts(raw)[("B100", "B100")]["verdict"] == "DANGEROUS"


def test_abstentions_are_reported_to_the_caller_and_exclude_judged_items():
    from clawseccheck.adjudication import _parse_verdicts_with_abstentions

    def entry(i, v):
        return {"finding_id": f"B{i}", "target": f"B{i}", "verdict": v}

    raw = json.dumps({"verdicts": [
        entry(1, "ABSTAIN"), entry(2, "DANGEROUS"), entry(2, "ABSTAIN"),
        entry(3, "ABSTAIN"), entry(3, "ABSTAIN"), entry(4, "SAFE")]})
    verdicts, abstained = _parse_verdicts_with_abstentions(raw)
    assert set(verdicts) == {("B2", "B2"), ("B4", "B4")}
    assert abstained == {("B1", "B1"), ("B3", "B3")}


def test_a_lower_case_abstain_is_an_unknown_verdict_like_any_other(capsys):
    """Unknown verdict strings keep today's behaviour: the entry is dropped, and when that
    leaves nothing usable the B-330 note says so. ABSTAIN is the exact string."""
    from clawseccheck.adjudication import _parse_verdicts, _parse_verdicts_with_abstentions

    raw = json.dumps({"verdicts": [
        {"finding_id": "B100", "target": "B100", "verdict": "abstain"}]})
    assert _parse_verdicts(raw) == {}
    err = capsys.readouterr().err
    assert "0 of 1 submitted entries were usable" in err, err
    assert _parse_verdicts_with_abstentions(raw)[1] == frozenset()


def test_abstain_value_shapes_that_are_not_the_string_stay_unusable():
    from clawseccheck.adjudication import _parse_verdicts_with_abstentions

    for bad in (["ABSTAIN"], {"ABSTAIN": 1}, None, 3, " ABSTAIN", "ABSTAIN "):
        raw = json.dumps({"verdicts": [
            {"finding_id": "B100", "target": "B100", "verdict": bad}]})
        assert _parse_verdicts_with_abstentions(raw) == ({}, frozenset()), bad


# ----------------------------------------------------- the packet advertises the option

def _finding(status, evidence=None, fid="C99"):
    from clawseccheck.catalog import MEDIUM, Finding

    f = Finding(fid, "t", MEDIUM, status, "detail", "fix", "fw")
    if evidence is not None:
        f.evidence = evidence
    return f


def test_only_a_structurally_empty_own_audit_unknown_is_told_it_may_abstain(tmp_path):
    """An invitation not to answer is a way to steer a judge off a finding, so the offer
    is keyed on what the item IS, never on its disposition word: an audit finding the
    engine left UNKNOWN, with no evidence, no named subject and no destination host. The
    audit packet also carries real signals about installed third-party code labelled
    UNKNOWN on purpose, and those must be judged."""
    from clawseccheck.adjudication import (
        _VERDICT_SCHEMA, _VERDICT_SCHEMA_EMPTY_UNKNOWN, _abstain_offered,
        _item_from_finding, _vet_attest_packet_items, build_vet_judge_packet,
    )
    from clawseccheck.catalog import UNKNOWN, WARN
    from clawseccheck.checks import vet_skill

    assert "abstain" not in _VERDICT_SCHEMA
    assert "ABSTAIN" in _VERDICT_SCHEMA_EMPTY_UNKNOWN["abstain"]
    # The three severity values keep their severity-ascending order and stay the only
    # members of the list the structural tests derive the parser vocabulary from.
    assert _VERDICT_SCHEMA["verdict"] == ["SAFE", "SUSPICIOUS", "DANGEROUS"]
    assert _VERDICT_SCHEMA_EMPTY_UNKNOWN["verdict"] == _VERDICT_SCHEMA["verdict"]

    def offered(f):
        return _abstain_offered(_item_from_finding(f), f)

    assert offered(_finding(UNKNOWN)) is True                       # the one admitted shape
    assert offered(_finding(WARN)) is False                         # the engine saw a signal
    # An UNKNOWN that names a subject is about third-party content: never offered.
    assert offered(_finding(UNKNOWN, ["evil-skill: reads a file then posts it (a.py:8)"])) is False
    # An UNKNOWN with any evidence at all, subject or not, is not empty.
    assert offered(_finding(UNKNOWN, ["gateway.bind: value could not be resolved"])) is False

    # The real audit packet. Both sides of the split must be populated, or it is vacuous.
    packet = _packet(tmp_path)
    with_hint = [i for i in packet if "abstain" in i["verdict_schema"]]
    plain = [i for i in packet if "abstain" not in i["verdict_schema"]]
    assert with_hint and plain, (len(with_hint), len(plain))
    for item in with_hint:
        assert item["engine_disposition"] == "UNKNOWN"
        assert item["target"] == item["finding_id"], item["finding_id"]
        assert "destination_host" not in item["safe_facts"]
        assert item["redacted_evidence"].startswith("no evidence entries"), item["finding_id"]
    for item in plain:
        assert (item["engine_disposition"] != "UNKNOWN" or item["target"] != item["finding_id"]
                or not item["redacted_evidence"].startswith("no evidence entries")), item

    # No --vet item is ever told it may abstain: the fixed prose-attestation questions and
    # a real vet target's own borderline items alike.
    for item in _vet_attest_packet_items("skillx"):
        assert "abstain" not in item["verdict_schema"]
    skill = tmp_path / "skillx"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: skillx\ndescription: notes helper\n---\nKeeps notes.\n", encoding="utf-8")
    vet_items = build_vet_judge_packet(vet_skill(skill), str(skill))
    assert vet_items
    for item in vet_items:
        assert "abstain" not in json.dumps(item["verdict_schema"]).lower(), item["finding_id"]


def test_the_recovered_signals_about_installed_code_are_never_offered_abstain():
    """The synthetic sources (recovered taint, B62, env-auth kwarg, keyword trigger) are
    real signals the packet labels UNKNOWN. Read from the source: each of them, and the
    config-blind roll-up, is built with the plain schema, and the abstain schema is
    assigned at exactly one place, behind `_abstain_offered`."""
    import inspect

    from clawseccheck.adjudication import _builder

    src = inspect.getsource(_builder)
    assert src.count("_VERDICT_SCHEMA_EMPTY_UNKNOWN") == 2, "one definition, one assignment"
    assign = src.index('item["verdict_schema"] = _VERDICT_SCHEMA_EMPTY_UNKNOWN')
    assert "if _abstain_offered(item, f):" in src[assign - 120:assign]
    for fn in (_builder._b62_items, _builder._recover_dropped_taint,
               _builder._env_auth_kwarg_items, _builder._keyword_gated_trigger_items,
               _builder._config_blind_collapsed_item):
        body = inspect.getsource(fn)
        assert "_VERDICT_SCHEMA_EMPTY_UNKNOWN" not in body, fn.__name__
        assert '"verdict_schema": _VERDICT_SCHEMA' in body, fn.__name__


def test_the_bundle_template_names_abstain_beside_the_other_verdicts():
    from clawseccheck.adjudication import build_bundle_template

    verdict_hint = build_bundle_template()["entryExample"]["judged"]["verdict"]
    for value in ("SAFE", "SUSPICIOUS", "DANGEROUS", "ABSTAIN"):
        assert value in verdict_hint


# ------------------------------------------------------- through the real CLI: --judged

def test_cli_judged_abstain_alone_changes_nothing_but_the_annotation(tmp_path):
    packet = _packet(tmp_path)
    base, _ = _judged(tmp_path, "empty", [])
    got, err = _judged(tmp_path, "abs", [_entry(packet[0], "ABSTAIN")])

    assert _without(got, "secondOpinion") == _without(base, "secondOpinion")
    row = _rows(got)[(packet[0]["finding_id"], packet[0]["target"])]
    assert row["judge_verdict"] is None
    assert "abstain" in row["annotation"].lower()
    assert "not yet reviewed" not in row["annotation"]
    assert [r["judge_verdict"] for r in got["secondOpinion"]] == [None] * len(packet)
    # Every OTHER row is byte-identical to the no-verdict run.
    other = {k: v for k, v in _rows(got).items()
             if k != (packet[0]["finding_id"], packet[0]["target"])}
    assert other == {k: v for k, v in _rows(base).items() if k in other}
    assert "1 ABSTAIN answer(s) submitted" in err


def test_cli_judged_abstain_mixed_with_every_real_verdict(tmp_path):
    packet = _packet(tmp_path)
    want = ["SAFE", "SUSPICIOUS", "DANGEROUS", "ABSTAIN"]
    entries = [_entry(packet[i], v) for i, v in enumerate(want)]
    got, err = _judged(tmp_path, "mixed", entries)
    rows = _rows(got)
    for item, v in zip(packet, want):
        row = rows[(item["finding_id"], item["target"])]
        assert row["judge_verdict"] == (None if v == "ABSTAIN" else v)
    assert "1 ABSTAIN answer(s) submitted" in err
    assert "usable" not in err


def test_cli_judged_duplicates_with_abstain_equal_the_real_verdict_alone(tmp_path):
    packet = _packet(tmp_path)
    item = packet[0]
    for real in ("SAFE", "SUSPICIOUS", "DANGEROUS"):
        alone, _ = _judged(tmp_path, "alone", [_entry(item, real)])
        for tag, entries in (
            ("ab-first", [_entry(item, "ABSTAIN"), _entry(item, real)]),
            ("ab-last", [_entry(item, real), _entry(item, "ABSTAIN")]),
        ):
            got, err = _judged(tmp_path, tag, entries)
            assert got == alone, (real, tag)
            assert "abstained" not in err


def test_cli_judged_without_any_abstain_is_unchanged_in_shape(tmp_path):
    """No ABSTAIN anywhere: the artifact has no abstention wording at all."""
    packet = _packet(tmp_path)
    got, err = _judged(tmp_path, "plain", [_entry(packet[0], "DANGEROUS")])
    assert "abstain" not in json.dumps(got["secondOpinion"]).lower()
    assert "abstain" not in err.lower()


# ------------------------------------------------ through the real CLI: --judged-bundle

def _state(payload):
    """Everything about the run that is not the verdict-layer prose."""
    phases = [{k: v for k, v in p.items() if k not in ("detail", "elapsed_s")}
              for p in payload["phases"]]
    return {**_without(payload, "phases", "judgePacket", "runState", "secondOpinion"),
            "phases": phases}


def test_bundle_all_abstain_leaves_the_state_an_empty_verdict_list_leaves(tmp_path):
    packet = _packet(tmp_path)
    empty, _ = _bundle(tmp_path, "empty", [])
    allabs, err = _bundle(tmp_path, "allabs", [_entry(i, "ABSTAIN") for i in packet])

    assert allabs["verdictsSubmitted"] is False
    assert "secondOpinion" not in allabs
    assert _state(allabs) == _state(empty)
    assert "usable" not in err, err
    # ... and the abstentions are still disclosed, in the adjudication phase's own text.
    detail = next(p["detail"] for p in allabs["phases"] if p["name"] == "adjudication")
    assert f"{len(packet)} item(s) abstained" in detail, detail
    empty_detail = next(p["detail"] for p in empty["phases"] if p["name"] == "adjudication")
    assert "abstain" not in empty_detail


def test_bundle_mixed_abstain_never_counts_as_reviewed(tmp_path):
    packet = _packet(tmp_path)
    entries = [_entry(packet[0], "DANGEROUS"), _entry(packet[1], "ABSTAIN"),
               _entry(packet[2], "ABSTAIN"), _entry(packet[2], "SAFE"),
               _entry(packet[3], "ABSTAIN")]
    got, _ = _bundle(tmp_path, "mixed", entries)
    base, _ = _bundle(tmp_path, "base", [])

    assert got["verdictsSubmitted"] is True
    rows = _rows(got)
    verdict_of = {k: r["judge_verdict"] for k, r in rows.items() if r["judge_verdict"]}
    assert verdict_of == {
        (packet[0]["finding_id"], packet[0]["target"]): "DANGEROUS",
        (packet[2]["finding_id"], packet[2]["target"]): "SAFE",
    }
    detail = next(p["detail"] for p in got["phases"] if p["name"] == "adjudication")
    assert f"2 of {len(packet)} borderline item(s) judged" in detail, detail
    assert "2 item(s) abstained" in detail, detail
    # Advisory only: score, grade, caps and findings are those of the no-verdict run.
    for key in ("score", "grade", "capped", "findings", "missing_layers"):
        assert got[key] == base[key], key


def test_bundle_duplicate_abstain_and_danger_equal_danger_alone(tmp_path):
    packet = _packet(tmp_path)
    item = packet[0]
    alone, _ = _bundle(tmp_path, "alone", [_entry(item, "DANGEROUS")])
    for tag, entries in (
        ("first", [_entry(item, "ABSTAIN"), _entry(item, "DANGEROUS")]),
        ("last", [_entry(item, "DANGEROUS"), _entry(item, "ABSTAIN")]),
    ):
        got, err = _bundle(tmp_path, tag, entries)
        assert got["secondOpinion"] == alone["secondOpinion"], tag
        assert _state(got) == _state(alone), tag
        details = [p["detail"] for p in got["phases"]]
        assert details == [p["detail"] for p in alone["phases"]], tag
        # (the tmp path embedded in a --full payload spells this test's own name)
        assert "abstain" not in json.dumps(got["secondOpinion"]).lower()
        assert "abstain" not in err.lower()


# ------------------------------------------------------------------ review round 2

_MISCASED = ("dangerous", "DANGEROUS ", "Dangerous")


def _miscased_entries():
    return [{"finding_id": f"B{100 + i}", "target": f"t{i}", "verdict": v}
            for i, v in enumerate(_MISCASED)]


def test_an_abstain_does_not_silence_the_nothing_usable_warning(capsys):
    """An ABSTAIN is 'no entry': a file whose OTHER verdicts are all unusable must still be
    told so, with the count of those other entries. Before this, one ABSTAIN swallowed the
    warning and a judge whose DANGEROUS answers were mis-cased lost them all unannounced."""
    from clawseccheck.adjudication import _parse_verdicts

    bad = _miscased_entries()
    assert _parse_verdicts(json.dumps({"verdicts": bad})) == {}
    control = capsys.readouterr().err
    assert "0 of 3 submitted entries were usable" in control, control  # the control fires

    abstain = {"finding_id": "B1", "target": "t", "verdict": "ABSTAIN"}
    for entries in ([abstain] + bad, bad + [abstain], [abstain, abstain] + bad):
        assert _parse_verdicts(json.dumps({"verdicts": entries})) == {}
        err = capsys.readouterr().err
        assert "0 of 3 submitted entries were usable" in err, err
        assert "1 ABSTAIN answer(s) submitted" in err, err


def test_an_abstain_beside_a_usable_verdict_raises_no_warning(capsys):
    from clawseccheck.adjudication import _parse_verdicts

    entries = [{"finding_id": "B1", "target": "t", "verdict": "ABSTAIN"},
               {"finding_id": "B2", "target": "t", "verdict": "DANGEROUS"}]
    assert set(_parse_verdicts(json.dumps({"verdicts": entries}))) == {("B2", "t")}
    err = capsys.readouterr().err
    assert "usable" not in err, err


def test_an_abstain_inside_votes_still_counts_toward_the_total():
    """One DANGEROUS and two ABSTAIN is disclosed as 1/3: the split line exists to show how
    few lenses stood behind a verdict, and leaving the abstentions out would make it read
    as unanimous."""
    from clawseccheck.adjudication import _annotate, _vote_tally

    assert _vote_tally("DANGEROUS", {"DANGEROUS": 1, "ABSTAIN": 2}) == (1, 3)
    assert _vote_tally("DANGEROUS", {"DANGEROUS": 1}) == (1, 1)
    assert _vote_tally("DANGEROUS", {"DANGEROUS": 1, "SAFE": 2}) == (1, 3)
    with_abstain = _annotate("WARN", {"verdict": "DANGEROUS",
                                      "votes": {"DANGEROUS": 1, "ABSTAIN": 2}})
    assert "1/3 DANGEROUS" in with_abstain, with_abstain


def test_an_item_that_also_drew_an_unusable_answer_is_not_shown_as_abstained():
    """ABSTAIN plus a mis-cased DANGEROUS for the SAME item: something else was said about
    it and lost, so the item reads as not reviewed rather than as a deliberate abstention."""
    from clawseccheck.adjudication import _parse_verdicts_with_abstentions

    entries = [{"finding_id": "B1", "target": "t", "verdict": "ABSTAIN"},
               {"finding_id": "B1", "target": "t", "verdict": "dangerous"},
               {"finding_id": "B2", "target": "t", "verdict": "ABSTAIN"}]
    out, abstained = _parse_verdicts_with_abstentions(json.dumps({"verdicts": entries}))
    assert out == {}
    assert abstained == frozenset({("B2", "t")})


def test_the_abstain_note_speaks_about_its_own_item_only(capsys):
    """One ABSTAIN beside an applied DANGEROUS: the note must not read as 'nothing was
    raised' for the whole file."""
    from clawseccheck.adjudication import _parse_verdicts

    entries = [{"finding_id": "B1", "target": "t", "verdict": "ABSTAIN"},
               {"finding_id": "B2", "target": "t", "verdict": "DANGEROUS"}]
    assert set(_parse_verdicts(json.dumps({"verdicts": entries}))) == {("B2", "t")}
    err = capsys.readouterr().err
    assert "1 ABSTAIN answer(s) submitted" in err, err
    assert "nothing was reviewed" not in err
    assert "every other entry in the file is read as usual" in err
