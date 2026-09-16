"""B-760 part 2: a plugin's own PLUGIN-VET WARN never reached the judge packet.

`vet_plugin`'s primary Finding carries id "PLUGIN-VET" -- the container/aggregate
verdict for the whole plugin. `_is_borderline` only ever admitted UNKNOWN or a WARN
whose id is in `_FN_PRONE_WARN_IDS`, and "PLUGIN-VET" was never in that set -- so for
a plugin whose ONLY signal rides on the primary alone (no `.ring_findings` entry,
exactly the shape `_vet_pool`'s own docstring warns about), `build_vet_judge_packet`
carried none of the plugin's real findings, only the three always-offered generic
attestation questions, and a verdict submitted back for it via `--vet-judged` was
silently dropped with no disclosure.

Reproduced here with the task's own repro shape: a plugin whose only content is an
`eval(atob(...))` JS signal (`tests/test_vet_plugin.py::test_plugin_with_eval_of_
decoded_js_warns` is the identical fixture) -- WARN, empty ring_findings, entirely
on the primary. `vet_skill`'s equivalent primary Finding already used id "B13",
already in `_FN_PRONE_WARN_IDS`, which is why skills never had this gap.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.adjudication import (
    _FN_PRONE_WARN_IDS,
    _ID_QUESTIONS,
    _is_borderline,
    _vet_run_fingerprint,
    build_vet_judge_packet,
    escalate_vet_output,
)
from clawseccheck.catalog import FAIL, PASS, WARN
from clawseccheck.checks import vet_plugin

_EMPTY_SCHEMA = {"type": "object", "additionalProperties": False}


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _eval_atob_plugin(tmp_path: Path) -> Path:
    """The task's own repro shape: a plugin whose only signal is an obfuscated
    `eval(atob(...))` JS payload -- identical fixture to
    tests/test_vet_plugin.py::test_plugin_with_eval_of_decoded_js_warns."""
    root = tmp_path / "plug"
    root.mkdir(parents=True, exist_ok=True)
    _write(root / "openclaw.plugin.json",
           json.dumps({"id": "demo", "configSchema": _EMPTY_SCHEMA}))
    _write(root / "index.js", "eval(atob(BLOB));\n")
    return root


# ------------------------------------------------------------------ the fixture
def test_the_repro_fixture_rides_on_the_primary_alone(tmp_path):
    """Grounds the scenario before asserting anything about routing: WARN,
    id PLUGIN-VET, no ring_findings -- the exact shape `_vet_pool`'s docstring
    says a ring_findings-only packet would miss."""
    f = vet_plugin(_eval_atob_plugin(tmp_path))
    assert f.id == "PLUGIN-VET"
    assert f.status == WARN, f.detail
    assert not f.ring_findings


# ------------------------------------------------------------------ the routing
def test_plugin_vet_is_in_fn_prone_warn_ids():
    assert "PLUGIN-VET" in _FN_PRONE_WARN_IDS


def test_a_warn_plugin_vet_is_borderline():
    f = type("F", (), {"id": "PLUGIN-VET", "status": WARN, "suppressed": False,
                        "not_applicable": False})()
    assert _is_borderline(f)


def test_plugin_vet_has_a_curated_question():
    q = _ID_QUESTIONS.get("PLUGIN-VET")
    assert q, "PLUGIN-VET routed to the judge with no question of its own"
    assert q.rstrip().endswith("[SAFE / SUSPICIOUS / DANGEROUS + reason]")


def test_routing_cannot_admit_a_fail_or_a_pass():
    """Bounded by construction, same as B63's own precedent (test_c378): adding an
    id to _FN_PRONE_WARN_IDS can only ever add a QUESTION -- `_is_borderline` still
    reaches UNKNOWN/WARN only, so this can never pull a FAIL or PASS into the packet
    or bypass Golden Rule #5."""
    fail = type("F", (), {"id": "PLUGIN-VET", "status": FAIL, "suppressed": False,
                           "not_applicable": False})()
    passed = type("F", (), {"id": "PLUGIN-VET", "status": PASS, "suppressed": False,
                             "not_applicable": False})()
    assert not _is_borderline(fail)
    assert not _is_borderline(passed)


# ------------------------------------------------------------------ end to end
def test_plugin_vet_reaches_the_rendered_packet(tmp_path):
    """Through the real packet builder on the real fixture, not the predicate alone
    -- a gate with no caller can pass its own unit tests and still not fire (B-570)."""
    root = _eval_atob_plugin(tmp_path)
    f = vet_plugin(root)
    packet = build_vet_judge_packet(f, str(root))
    items = [i for i in packet if i["finding_id"] == "PLUGIN-VET"]
    assert items, (
        "PLUGIN-VET absent from the judge packet -- the plugin's real finding never "
        "reached the judge, only the three always-offered generic attestation "
        "questions did"
    )
    assert items[0]["question"] == _ID_QUESTIONS["PLUGIN-VET"]
    assert items[0]["engine_disposition"] == WARN


def test_a_dangerous_verdict_for_plugin_vet_now_escalates_to_fail(tmp_path):
    """The other half of the round trip: a verdict submitted back for the item the
    packet now carries must actually apply, not be silently dropped the way it was
    before this fix (escalate_vet_output shares `_is_borderline` with the packet
    builder, so the same omission blocked both directions identically)."""
    root = _eval_atob_plugin(tmp_path)
    f = vet_plugin(root)
    packet = build_vet_judge_packet(f, str(root))
    item = next(i for i in packet if i["finding_id"] == "PLUGIN-VET")

    verdicts = json.dumps({
        "targetFingerprint": _vet_run_fingerprint(str(root)),
        "verdicts": [{"finding_id": "PLUGIN-VET", "target": item["target"],
                     "verdict": "DANGEROUS"}],
    })
    escalated = escalate_vet_output(f, verdicts, target=str(root))
    assert escalated.status == FAIL
    assert "escalated by host-agent judge" in escalated.detail


def test_a_safe_verdict_for_plugin_vet_does_not_move_the_status(tmp_path):
    """The escalate-only invariant (C-254) applies to PLUGIN-VET exactly as it does
    to every other borderline id -- a judge reviewing untrusted plugin content may
    never LOWER a verdict, only raise one."""
    root = _eval_atob_plugin(tmp_path)
    f = vet_plugin(root)
    packet = build_vet_judge_packet(f, str(root))
    item = next(i for i in packet if i["finding_id"] == "PLUGIN-VET")

    verdicts = json.dumps({
        "targetFingerprint": _vet_run_fingerprint(str(root)),
        "verdicts": [{"finding_id": "PLUGIN-VET", "target": item["target"],
                     "verdict": "SAFE"}],
    })
    escalated = escalate_vet_output(f, verdicts, target=str(root))
    assert escalated.status == WARN


def test_every_fn_prone_id_still_has_a_question():
    """The omission class this task is an instance of (same invariant
    tests/test_c378_b63_routed_to_judge.py already pins for B63) -- re-asserted here
    so a future id added without a question fails at the point of addition."""
    missing = sorted(i for i in _FN_PRONE_WARN_IDS if not _ID_QUESTIONS.get(i))
    assert not missing, f"in _FN_PRONE_WARN_IDS but with no _ID_QUESTIONS entry: {missing}"
