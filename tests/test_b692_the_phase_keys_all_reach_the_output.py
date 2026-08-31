"""Nothing the adjudication phase produces is dropped on the way out by omission.

`run_adjudication` builds seven keys. `PipelineResult.to_json` copied five, and the two it
left behind were the two nothing else reads back:

- **`runState`** — the run-level frame B-623 added *precisely* so a `--full` adjudication
  does not hand a judge a band of UNKNOWNs with no way to see the run itself was blind,
  capped or ungraded. The phase's own comment says so in as many words; the emitter then
  discarded it. The standalone `--judge-packet` carried it, and the composed route — the
  one `run_adjudication`'s operator text tells you to use — did not. That asymmetry is how
  B-689's `capsFired` ENTRY for `live_injection_cap_reason` came to be correct and to reach
  nobody: the flag is structurally always False on the standalone path, and the composed
  path that resolves it threw the whole frame away. The entry, precisely — the underlying
  value was never hidden. `render_json` has always published `live_injection_cap_reason` as
  a top-level key of this same payload, next to `graded`, `cap_severity`, `not_checked`,
  `missing_layers` and `degraded_count`. What `runState` adds is a self-contained frame in
  the shape §12 defines, for a consumer that lifts `judgePacket` out and hands it on.
- **`verdictsSubmitted`** — set on every run and read by nobody, because it never left.

An allowlist is a legitimate decision about a public shape. The guard here does not
second-guess it; it makes leaving a key out a *decision* rather than an oversight, by
deriving what the phase can produce from the phase's own source. Same shape as B-689's
`_CAP_LADDER` census and B-693's emitter census, for the same reason: a hand-kept list
beside a hand-kept producer is where these keep diverging.

Offline, stdlib only, writes nothing outside tmp_path.
"""
from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

from clawseccheck.pipeline import (
    _ADJUDICATION_JSON_KEYS,
    PHASE_ADJUDICATION,
    PhaseResult,
    PipelineResult,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SAFE = str(REPO_ROOT / "fixtures" / "home_safe")
_PIPELINE_SRC = (REPO_ROOT / "clawseccheck" / "pipeline.py").read_text(encoding="utf-8")

_LIVE_BUNDLE = ('{"liveTest": {"seed": "s", "verdicts": '
                '[{"tool": "redteam", "id": "PI-01", "verdict": "VULNERABLE"}]}}')
_JUDGED_BUNDLE = ('{"judged": {"verdicts": [{"finding_id": "B13", "target": "B13",'
                  ' "verdict": "SAFE", "reason": "why"}]}}')
# `judged` is an OBJECT and `vetJudged` an ARRAY — `_BUCKET_TYPES` drops the wrong type with
# a stderr note, so a test that mixed them up would measure a dropped bucket, not a branch.
_VET_BUNDLE = '{"vetJudged": [{"targetFingerprint": "deadbeef", "verdicts": []}]}'


# ------------------------------------------------------------------------- the census

def _keys_the_phase_can_produce() -> set[str]:
    """Every key `run_adjudication` can put on its phase data, read off its own source.

    Static rather than behavioural on purpose: the keys live on three different branches
    (`judged`, `vetJudged`, and the unconditional literal), so exercising the function
    would only cover the branches the test remembered to drive — which is the same
    "asserted what I happened to set up" failure this file exists to prevent.
    """
    fn, = [n for n in ast.parse(_PIPELINE_SRC).body
           if isinstance(n, ast.FunctionDef) and n.name == "run_adjudication"]
    keys: set[str] = set()
    for node in ast.walk(fn):
        # `data: dict = {...}` — the unconditional keys
        if (isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
                and node.target.id == "data" and isinstance(node.value, ast.Dict)):
            keys |= {k.value for k in node.value.keys
                     if isinstance(k, ast.Constant) and isinstance(k.value, str)}
        # `data["X"] = ...` — the branch-conditional ones
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if (isinstance(tgt, ast.Subscript) and isinstance(tgt.value, ast.Name)
                        and tgt.value.id == "data" and isinstance(tgt.slice, ast.Constant)
                        and isinstance(tgt.slice.value, str)):
                    keys.add(tgt.slice.value)
    return keys


def test_the_derivation_found_something_to_check():
    """A guard whose input is empty passes everything. `run_adjudication` sets seven keys
    across three branches; if this drops below that, the AST shapes moved and the census
    below is measuring nothing."""
    produced = _keys_the_phase_can_produce()
    assert len(produced) >= 7, sorted(produced)
    assert "runState" in produced and "verdictsSubmitted" in produced, sorted(produced)


def test_the_emitter_carries_every_key_the_phase_produces():
    """The census. A new key on the phase reddens this until someone decides — in the
    allowlist — whether it belongs in the public shape.

    Complete only because `test_the_phase_uses_no_key_shape_the_census_cannot_see` below
    forbids the idioms this derivation does not model. Alone it sees `data["X"] = …` and the
    opening literal and nothing else: measured, `data.update({...})`, `data.setdefault(...)`
    and `data = {**data, ...}` each add a key it fails to report, and the `>= 7` floor above
    only fires on REMOVAL — so an added-and-missed key stays green. The pair is the guard;
    either half alone is not.
    """
    missing = _keys_the_phase_can_produce() - set(_ADJUDICATION_JSON_KEYS)
    assert not missing, sorted(missing)


def test_the_phase_uses_no_key_shape_the_census_cannot_see():
    """What makes the census above complete, rather than merely usually right.

    `_keys_the_phase_can_produce` models two idioms. Three others would add a key it never
    reports — measured on mutated copies of this source, each invisible: `data.update({...})`,
    `data.setdefault(...)`, and rebinding `data = {**data, ...}`. Rather than chase every way
    Python can grow a dict, forbid the ones the derivation does not model, so "the two shapes
    are exhaustive" is enforced instead of assumed. Same move as B-693's `json.dumps` lock.

    The AnnAssign that OPENS `data` is the one legitimate binding and is skipped.
    """
    fn, = [n for n in ast.parse(_PIPELINE_SRC).body
           if isinstance(n, ast.FunctionDef) and n.name == "run_adjudication"]
    banned_methods = {"update", "setdefault", "pop", "popitem", "clear", "__setitem__"}
    offenders = []
    for node in ast.walk(fn):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "data"
                and node.func.attr in banned_methods):
            offenders.append(("data.%s()" % node.func.attr, node.lineno))
        if isinstance(node, (ast.Assign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for tgt in targets:
                if isinstance(tgt, ast.Name) and tgt.id == "data":
                    offenders.append(("rebinds `data`", node.lineno))
    assert not offenders, offenders


def test_the_allowlist_names_nothing_the_phase_cannot_produce():
    """The other direction: a key kept in the allowlist after its producer went away is a
    promise the output silently stops keeping."""
    stale = set(_ADJUDICATION_JSON_KEYS) - _keys_the_phase_can_produce()
    assert not stale, sorted(stale)


# -------------------------------------------------------------- the emitter, directly

def _to_json(data: dict) -> dict:
    result = PipelineResult()
    result.add(PhaseResult(name=PHASE_ADJUDICATION, status="ok"))
    result.phases[-1].data = data
    return result.to_json()


def test_every_allowlisted_key_survives_the_emitter():
    payload = _to_json({k: {"probe": k} for k in _ADJUDICATION_JSON_KEYS})
    for key in _ADJUDICATION_JSON_KEYS:
        assert payload.get(key) == {"probe": key}, key


def test_a_key_the_phase_never_set_is_not_invented():
    """Absence must stay absence: the emitter copies what is there, it does not default."""
    payload = _to_json({"judgePacket": []})
    assert "runState" not in payload and "verdictsSubmitted" not in payload


# ------------------------------------------------------------------- and end to end

def _full_json(tmp_path: Path, *extra: str) -> dict:
    proc = subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", SAFE, "--full", "--fast",
         "--json", "--data-dir", str(tmp_path / "state"), "--no-history", *extra],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=600)
    assert proc.returncode in (0, 1), proc.stderr[-2000:]
    return json.loads(proc.stdout)


def _bundle(tmp_path: Path, name: str, body: str) -> str:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return str(p)


def test_a_submitted_live_verdict_reaches_the_judge_through_run_state(tmp_path):
    """The headline, and the loop B-689 could not close from its own side: the live cap is
    resolvable only on `--full`, and `--full` was the route that dropped the frame."""
    payload = _full_json(tmp_path, "--judged-bundle",
                         _bundle(tmp_path, "live.json", _LIVE_BUNDLE))
    caps = payload["runState"]["capsFired"]
    entry, = [c for c in caps if c["cap"] == "live_injection_capped"]
    assert entry["reason"] == "redteam:PI-01", entry


def test_an_unsubmitted_run_still_carries_the_frame_and_says_nothing_capped(tmp_path):
    """The negative control. Without it, "always attach runState" would pass the test above
    while `capsFired` said whatever it liked."""
    payload = _full_json(tmp_path)
    assert payload["runState"]["capsFired"] == [], payload["runState"]
    assert payload["runState"]["stated"] is True


# `runState.<camelCase>` and the top-level snake_case key that carries the same fact. The
# frame is a deliberate restatement — its point is that it travels self-contained when a
# consumer lifts `judgePacket` out — and the cost of a restatement is that it can drift.
_SAME_FACT_TWICE = {
    "graded": "graded",
    "missingLayers": "missing_layers",
    "notChecked": "not_checked",
    "degradedChecks": "degraded_count",
}


@pytest.mark.parametrize("nested,top", sorted(_SAME_FACT_TWICE.items()))
def test_the_frame_never_contradicts_the_payload_it_rides_in(tmp_path, nested, top):
    """One question, one answer.

    Four facts now appear twice in a `--full --json` document. Nothing forces them to agree:
    `runState` is built by `run_adjudication` from the score, the top-level keys by
    `report.render_json` from the same score, and either could start reading something else.
    Two answers to one question is the failure mode this whole family of bugs is made of, so
    the duplication gets a guard rather than a comment.

    Found by a real failure rather than foreseen: adding `runState` broke
    `test_f155_live_injection_cap.py::test_resistant_verdict_scores_the_same_but_ledger_shows_it_ran`,
    which excluded `missing_layers` from a comparison and did not know the same fact had
    grown a second home.
    """
    payload = _full_json(tmp_path)
    assert payload["runState"][nested] == payload[top], (nested, top)


@pytest.mark.parametrize("name,body,expected", [
    ("none", None, False),
    ("live.json", _LIVE_BUNDLE, False),
    ("judged.json", _JUDGED_BUNDLE, True),
    ("vet.json", _VET_BUNDLE, True),
    ("empty-vet.json", '{"vetJudged": []}', False),
    ("empty-judged.json", '{"judged": {}}', True),
], ids=["no-bundle", "live-only", "judged", "vetJudged", "empty-vetJudged", "empty-judged"])
def test_verdicts_submitted_tracks_verdict_buckets_not_live_tests(tmp_path, name, body,
                                                                  expected):
    """Measured semantics, not assumed. `verdictsSubmitted` is raised by the `judged` branch
    and by the `vetJudged` branch, and NOT by a `liveTest`-only bundle -- so it is a
    different question from `"secondOpinion" in payload`, which is why carrying it is worth
    a key rather than being derivable by the consumer."""
    extra = () if body is None else ("--judged-bundle", _bundle(tmp_path, name, body))
    payload = _full_json(tmp_path, *extra)
    assert payload["verdictsSubmitted"] is expected, payload.get("secondOpinion")


def test_both_envelopes_describe_the_run_the_same_way(tmp_path):
    """`runState` now rides two artifacts. They must not drift into two shapes -- which is
    exactly what the cap ladders did across four surfaces (B-689/B-690)."""
    composed = _full_json(tmp_path)["runState"]
    proc = subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", SAFE, "--judge-packet",
         "--data-dir", str(tmp_path / "s2"), "--no-history"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=600)
    standalone = json.loads(proc.stdout)["runState"]
    assert set(composed) == set(standalone), (sorted(composed), sorted(standalone))
    assert composed["stated"] is standalone["stated"] is True
