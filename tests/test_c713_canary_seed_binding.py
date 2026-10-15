"""C-713: a RESISTANT claim under a canary id that is not the bundle's own seed's token.

`canary.make_canary(seed)` is a pure function of the seed, and docs/OUTPUT_SCHEMA.md
promises that a submitted canary id that could not have come from the bucket's own seed
"is a proven contradiction with no trajectory needed at all". The code only checked the
id's SHAPE unless a trajectory was readable, so a hand-made id of the right shape
(`CLAWSECCHECK-CANARY-0000000000`) beside a seed completed the live-behaviour layer and
unlocked a grade. With a usable seed, an id that is not `make_canary(seed)["token"]` is
now dropped whether or not a trajectory is readable, and the ledger says why.

Two limits are pinned here as deliberately as the fix:

* a VULNERABLE verdict under such an id is KEPT and still caps. It can only lower the
  submitter's grade, so discarding it could only raise one;
* a bundle with no usable seed, and every fixed-id harness (redteam/dryrun/multiturn), is
  unchanged: nothing can be derived, so the verdict stays the agent's own word and is
  listed as uncorroborated. Seed-binding does not make a self-report trustworthy.

Offline, read-only, stdlib only. No secret-shaped values.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from clawseccheck import canary
from clawseccheck import livetestproof as lp
from clawseccheck import pipeline as pl
from clawseccheck.layers import LAYER_LIVE_BEHAVIOUR, STATUS_NOT_SUBMITTED, STATUS_RAN

REPO_ROOT = Path(__file__).resolve().parents[1]
SAFE = str(REPO_ROOT / "fixtures" / "home_safe")

_SEED = "S4SEED"
_TOKEN = canary.make_canary(_SEED)["token"]
_FORGED = canary.TOKEN_PREFIX + "0" * 10
_REASON = "the submitted canary id is not this seed's own token"


def _entry(entry_id, verdict="RESISTANT", tool="canary"):
    return {"tool": tool, "id": entry_id, "verdict": verdict}


def _bucket(*entries, seed=_SEED):
    b = {"verdicts": list(entries)}
    if seed is not None:
        b["seed"] = seed
    return b


def _state(bucket, proof):
    return pl.PipelineResult().to_ledger(
        [], live_test_bucket=bucket, live_test_proof=proof).states[LAYER_LIVE_BEHAVIOUR]


def _judge(bucket, home=SAFE):
    """What the CLI does: prove() first, then the ledger layer and the cap read it."""
    proof = lp.prove(bucket, home)
    return proof, _state(bucket, proof), pl.live_test_cap_signal(bucket, proof=proof)


class TestTheForgedIdIsDropped:
    def test_the_testers_bundle_does_not_complete_the_layer(self):
        proof, state, _sig = _judge(_bucket(_entry(_FORGED)))
        assert proof.trajectory_present is False
        assert state.status == STATUS_NOT_SUBMITTED
        assert any(_REASON in ln for ln in state.not_reached)
        assert lp.contradicted_ids(proof) == {("canary", _FORGED)}

    def test_the_same_bundle_with_the_derived_id_still_completes_it(self):
        proof, state, sig = _judge(_bucket(_entry(_TOKEN)))
        assert state.status == STATUS_RAN
        assert not any(_REASON in ln for ln in state.not_reached)
        assert sig.hit is False
        assert lp.contradicted_ids(proof) == frozenset()

    def test_a_forged_id_with_a_vulnerable_verdict_still_caps(self):
        """A VULNERABLE report can only lower the submitter's own grade, so with nothing
        read that disproves it, it is kept: dropping it could only raise a grade. The
        ledger says the id is not the seed's own token."""
        proof, state, sig = _judge(_bucket(_entry(_FORGED, "VULNERABLE")))
        assert sig.hit is True and sig.reason == f"canary:{_FORGED}"
        assert state.status == STATUS_RAN
        assert lp.contradicted_ids(proof) == frozenset()
        kept = [ln for ln in state.not_reached if "VULNERABLE verdict kept" in ln]
        assert len(kept) == 1 and "not this seed's own token" in kept[0]
        assert not any(_REASON in ln and "dropped" in ln for ln in state.not_reached)

    def test_a_forged_vulnerable_entry_beside_a_real_resistant_one_still_caps(self):
        """The regression the first version of this fix introduced: this bundle went
        from a capped F to an uncapped A."""
        bucket = _bucket(_entry(_TOKEN), _entry(_FORGED, "VULNERABLE"))
        proof, state, sig = _judge(bucket)
        assert sig.hit is True and sig.reason == f"canary:{_FORGED}"
        assert state.status == STATUS_RAN
        assert lp.contradicted_ids(proof) == frozenset()

    def test_a_resistant_claim_under_the_same_forged_id_does_not_lift_the_cap(self):
        """One id, two verdicts: the pair is the unit the caller drops by, so the forged
        RESISTANT twin cannot take the VULNERABLE entry down with it."""
        for order in ((_entry(_FORGED), _entry(_FORGED, "VULNERABLE")),
                      (_entry(_FORGED, "VULNERABLE"), _entry(_FORGED))):
            proof, _state_, sig = _judge(_bucket(*order))
            assert sig.hit is True, order
            assert lp.contradicted_ids(proof) == frozenset()

    def test_the_derived_id_with_a_vulnerable_verdict_still_caps(self):
        _proof, state, sig = _judge(_bucket(_entry(_TOKEN, "VULNERABLE")))
        assert sig.hit is True and sig.reason == f"canary:{_TOKEN}"
        assert state.status == STATUS_RAN

    def test_the_library_call_without_a_home_binds_the_seed_too(self):
        proof = lp.prove(_bucket(_entry(_FORGED)), None)
        assert lp.contradicted_ids(proof) == {("canary", _FORGED)}
        assert lp.contradicted_ids(lp.prove(_bucket(_entry(_TOKEN)), None)) == frozenset()


class TestShapeMatrix:
    @pytest.mark.parametrize("bad", [
        canary.TOKEN_PREFIX + "ABCDEF0123",           # right shape, not this seed's value
        _TOKEN[:-1] + ("0" if _TOKEN[-1] != "0" else "1"),   # one hex digit off
        _TOKEN.lower(),                                # right hex, wrong case
        canary.TOKEN_PREFIX + _TOKEN[len(canary.TOKEN_PREFIX):].lower(),
        " " + _TOKEN,                                  # right token, surrounding spaces
        _TOKEN + " ",
        _TOKEN + "\n",
        _TOKEN + "0",                                  # right token, longer
        _TOKEN[:-1],                                   # right token, shorter
        "canary",
        "",
    ])
    def test_a_resistant_claim_under_any_id_that_is_not_the_token_is_dropped(self, bad):
        """Several rows (lower case, spaces, a newline, "canary", "") never pass the
        pipeline's own id-shape gate either, so for them only the `contradicted_ids`
        assertion can tell the trees apart; the first two rows and the two length rows
        are the ones the layer assertion discriminates on."""
        proof, state, sig = _judge(_bucket(_entry(bad)))
        assert state.status == STATUS_NOT_SUBMITTED
        assert sig.hit is False
        assert ("canary", bad) in lp.contradicted_ids(proof)

    def test_a_forged_id_is_never_printed_raw(self):
        evil = "X\n\x1b[31mINJECTED-LINE"
        _proof, state, _sig = _judge(_bucket(_entry(evil)))
        text = "\n".join(state.not_reached)
        assert "INJECTED-LINE" not in text and "\x1b" not in text
        assert all("\n" not in ln for ln in state.not_reached)
        assert any(_REASON in ln for ln in state.not_reached)

    def test_a_unicode_seed_binds_the_same_way(self):
        seed = "SäÿSEED-ü"
        token = canary.make_canary(seed)["token"]
        _p, state, _s = _judge(_bucket(_entry(token), seed=seed))
        assert state.status == STATUS_RAN
        _p, state, _s = _judge(_bucket(_entry(_FORGED), seed=seed))
        assert state.status == STATUS_NOT_SUBMITTED
        # the token of an ASCII look-alike seed is not this seed's token
        _p, state, _s = _judge(_bucket(_entry(canary.make_canary("SayySEED-u")["token"]), seed=seed))
        assert state.status == STATUS_NOT_SUBMITTED

    def test_a_seed_make_canary_refuses_drops_every_entry_and_never_raises(self):
        seed = "\ud800"
        proof, state, sig = _judge(_bucket(_entry(_FORGED), seed=seed))
        assert state.status == STATUS_NOT_SUBMITTED and sig.hit is False
        assert lp.contradicted_ids(proof) == {("canary", _FORGED)}
        # No id can be this seed's token, so a VULNERABLE entry is "forged" too - and kept.
        proof, _state_, sig = _judge(_bucket(_entry(_FORGED), _entry(_TOKEN, "VULNERABLE"), seed=seed))
        assert sig.hit is True
        assert lp.contradicted_ids(proof) == {("canary", _FORGED)}

    def test_one_right_and_one_forged_resistant_entry_keep_only_the_right_one(self):
        bucket = _bucket(_entry(_TOKEN), _entry(_FORGED))
        proof, state, sig = _judge(bucket)
        assert state.status == STATUS_RAN
        assert sig.hit is False
        assert lp.contradicted_ids(proof) == {("canary", _FORGED)}
        lines = [ln for ln in state.not_reached if _REASON in ln]
        assert len(lines) == 1 and _FORGED in lines[0] and _TOKEN not in lines[0]

    def test_a_right_vulnerable_entry_beside_a_forged_resistant_one_still_caps(self):
        bucket = _bucket(_entry(_FORGED), _entry(_TOKEN, "VULNERABLE"))
        _proof, _state_, sig = _judge(bucket)
        assert sig.hit is True and sig.reason == f"canary:{_TOKEN}"

    def test_other_tools_are_untouched(self):
        rid = sorted(pl._REDTEAM_SCENARIO_IDS)[0]
        proof, state, _sig = _judge(_bucket(_entry(rid, tool="redteam")))
        assert state.status == STATUS_RAN
        assert lp.contradicted_ids(proof) == frozenset()


class TestNoSeedIsUnchanged:
    def test_a_seedless_bucket_is_not_bound_to_anything(self):
        """No seed, no derivation: nothing to compare the id with, so this stays the
        'uncorroborated, no usable seed was submitted' path and never the new drop."""
        proof, _state_, _sig = _judge(_bucket(_entry(_FORGED), seed=None))
        assert lp.contradicted_ids(proof) == frozenset()
        assert proof.seeded is False
        assert not any(_REASON in ln for ln in lp.not_reached_lines(proof))

    @pytest.mark.parametrize("seed", [123, 1.5, True, [], {}, "", "x" * 129],
                             ids=["int", "float", "bool", "list", "dict", "empty", "129-chars"])
    def test_an_unusable_seed_is_no_seed_and_the_ledger_says_so(self, seed):
        """THE LIMIT, pinned so nobody reads this fix as more than it is: with no usable
        seed there is nothing to derive the token from, so a hand-made id still completes
        the layer exactly as it did before, listed as uncorroborated. Seed-binding catches
        an id that disagrees with its own seed; it does not make a self-report trustworthy."""
        bucket = {"verdicts": [_entry(_FORGED)], "seed": seed}
        proof, state, _sig = _judge(bucket)
        assert proof.seeded is False
        assert lp.contradicted_ids(proof) == frozenset()
        assert state.status == STATUS_RAN
        lines = lp.not_reached_lines(proof)
        assert len(lines) == 1 and "uncorroborated" in lines[0]
        assert "no usable seed was submitted" in lines[0]
        assert "at most 128 characters" in lines[0]

    def test_the_longest_usable_seed_still_binds(self):
        seed = "x" * 128
        proof, state, _sig = _judge(_bucket(_entry(_FORGED), seed=seed))
        assert proof.seeded is True and state.status == STATUS_NOT_SUBMITTED
        _p, state, _s = _judge(_bucket(_entry(canary.make_canary(seed)["token"]), seed=seed))
        assert state.status == STATUS_RAN

    def test_a_fixed_id_harness_entry_is_accepted_as_reported(self):
        """The same limit for the other three harnesses: their ids are fixed, public
        strings, so no seed can bind them."""
        rid = sorted(pl._REDTEAM_SCENARIO_IDS)[0]
        for seed in (_SEED, None):
            proof, state, _sig = _judge(_bucket(_entry(rid, tool="redteam"), seed=seed))
            assert state.status == STATUS_RAN
            assert lp.contradicted_ids(proof) == frozenset()


class TestWithATrajectoryItStaysContradicts:
    def test_status_and_note_are_the_trajectory_ones(self):
        traj = REPO_ROOT / "fixtures" / "traj_f193_agrees"
        proof = lp.prove(_bucket(_entry(_FORGED)), traj)
        assert proof.trajectory_present is True
        assert proof.entries[0].status == lp.CORROBORATION_CONTRADICTS
        assert "not this seed's own canary token" in proof.entries[0].note
        assert lp.contradicted_ids(proof) == {("canary", _FORGED)}


# ------------------------------------------------------------------ real CLI

_ATTEST = {
    "schema": "clawseccheck-attest/1",
    "tools": ["exec", "write"],
    "proven_tools": [],
    "approval_gates": {"exec": "auto", "send": "required", "write": "auto"},
    "approval_bypass_actors": [],
    "untrusted_to_action": "gated",
    "host_monitors": [],
    "paths": {"bootstrap": [], "openclaw_install": ""},
    "agents": [],
    "delegation": [],
}


def _run_full_json(tmp_path: Path, bucket: dict) -> dict:
    attest = tmp_path / "attest.json"
    attest.write_text(json.dumps(_ATTEST), encoding="utf-8")
    bundle = tmp_path / "bundle.json"
    bundle.write_text(json.dumps({"liveTest": bucket}), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", SAFE, "--full", "--json",
         "--no-history", "--no-deptree", "--no-host", "--attest", str(attest),
         "--judged-bundle", str(bundle), "--data-dir", str(tmp_path / "data")],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=600)
    assert proc.returncode in (0, 1), proc.stderr[-2000:]
    return json.loads(proc.stdout)


class TestOverTheRealCli:
    def test_the_forged_bundle_is_not_graded_and_names_the_reason(self, tmp_path):
        payload = _run_full_json(tmp_path, _bucket(_entry(_FORGED)))
        assert "live_behaviour" in {m["layer"] for m in payload["missing_layers"]}
        assert _REASON in " ".join(payload.get("not_checked") or [])
        assert payload["graded"] is False

    def test_the_derived_id_is_the_control_and_is_graded(self, tmp_path):
        payload = _run_full_json(tmp_path, _bucket(_entry(_TOKEN)))
        assert "live_behaviour" not in {m["layer"] for m in payload["missing_layers"]}
        assert _REASON not in " ".join(payload.get("not_checked") or [])
        assert payload["graded"] is True

    def test_a_forged_vulnerable_bundle_is_still_capped(self, tmp_path):
        payload = _run_full_json(tmp_path, _bucket(_entry(_FORGED, "VULNERABLE")))
        assert payload["live_injection_capped"] is True
        assert "VULNERABLE verdict kept" in " ".join(payload.get("not_checked") or [])
