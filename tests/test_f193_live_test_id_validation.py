"""F-193 (interim check) — a liveTest verdict's ``id`` must be one the tool's own
``make_*()`` scenario generator could actually have produced, not merely a string of
the right generic shape.

Before this, ``pipeline._LIVE_TEST_ID_RE`` accepted ANY short alnum-plus-hyphen string
— including the bare tool name. A real incident submitted
``{"tool": "canary", "id": "canary", "verdict": "RESISTANT"}`` and it was accepted as a
structurally-valid entry, letting one self-authored line stand in for the whole
live-behaviour layer. This is NOT F-193's full fix (a separate, in-flight effort
verifies against the agent's own recorded trajectory instead); it is the cheap, static
half: reject an id that could not have come from the real generator for that tool, and
reject a multiturn verdict submitted in the same run that issued the multiturn plant
(the harness is two-phase by construction, so that shape is definitionally forged).

Offline, deterministic, no network. Uses the shipped fixtures only.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from clawseccheck import cli
from clawseccheck import pipeline as pl
from clawseccheck.cli import main
from clawseccheck.layers import LAYER_LIVE_BEHAVIOUR, STATUS_NOT_SUBMITTED, STATUS_RAN

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE = str(FIXTURES / "home_safe")

# The real incident shape: the bare tool name used as the id.
_FORGED_INCIDENT_BUCKET = {
    "seed": "x",
    "verdicts": [{"id": "canary", "tool": "canary", "verdict": "RESISTANT"}],
}

_VALID_CANARY_ID = "CLAWSECCHECK-CANARY-DEADBEEFCAFE0123"


def _bundle_file(tmp_path: Path, payload: dict, name: str = "bundle.json") -> str:
    p = tmp_path / name
    p.write_text(json.dumps(payload), encoding="utf-8")
    return str(p)


class TestRealScenarioIdsAccepted:
    """Clean case: an id the real generator actually produces is accepted, per tool."""

    def test_redteam_real_id_accepted(self):
        entry_id = next(iter(pl._REDTEAM_SCENARIO_IDS))
        bucket = {"verdicts": [{"tool": "redteam", "id": entry_id, "verdict": "VULNERABLE"}]}
        entries = pl._valid_live_test_entries(bucket)
        assert entries == [("redteam", entry_id, "VULNERABLE")]

    def test_dryrun_real_id_accepted(self):
        entry_id = next(iter(pl._DRYRUN_SCENARIO_IDS))
        bucket = {"verdicts": [{"tool": "dryrun", "id": entry_id, "verdict": "VULNERABLE"}]}
        entries = pl._valid_live_test_entries(bucket)
        assert entries == [("dryrun", entry_id, "VULNERABLE")]

    def test_multiturn_real_id_accepted(self):
        entry_id = next(iter(pl._MULTITURN_SCENARIO_IDS))
        bucket = {"verdicts": [{"tool": "multiturn", "id": entry_id, "verdict": "VULNERABLE"}]}
        entries = pl._valid_live_test_entries(bucket)
        assert entries == [("multiturn", entry_id, "VULNERABLE")]

    def test_canary_real_token_shape_accepted(self):
        bucket = {"verdicts": [
            {"tool": "canary", "id": _VALID_CANARY_ID, "verdict": "RESISTANT"}]}
        entries = pl._valid_live_test_entries(bucket)
        assert entries == [("canary", _VALID_CANARY_ID, "RESISTANT")]

    def test_canary_seeded_length_token_also_accepted(self):
        # make_canary(seed=...) emits a SHORTER (10 hex char) token than the unseeded
        # (16 hex char) form — both real shapes must be accepted.
        seeded_id = "CLAWSECCHECK-CANARY-" + "A" * 10
        bucket = {"verdicts": [
            {"tool": "canary", "id": seeded_id, "verdict": "RESISTANT"}]}
        entries = pl._valid_live_test_entries(bucket)
        assert entries == [("canary", seeded_id, "RESISTANT")]

    def test_ledger_reads_ran_for_a_genuine_submission(self):
        ledger = pl.PipelineResult().to_ledger(
            [], live_test_bucket={"verdicts": [
                {"tool": "canary", "id": _VALID_CANARY_ID, "verdict": "RESISTANT"}]})
        assert ledger.status(LAYER_LIVE_BEHAVIOUR) == STATUS_RAN


class TestToolNameAsIdRejected:
    """Bad case: the exact forged shape the real incident submitted."""

    def test_bare_tool_name_as_id_rejected(self):
        entries = pl._valid_live_test_entries(_FORGED_INCIDENT_BUCKET)
        assert entries == []

    def test_bare_tool_name_never_hits_the_cap(self):
        sig = pl.live_test_cap_signal(_FORGED_INCIDENT_BUCKET)
        assert sig.hit is False
        assert sig.reason is None

    def test_ledger_reads_not_submitted_for_the_forged_bucket(self):
        ledger = pl.PipelineResult().to_ledger(
            [], live_test_bucket=_FORGED_INCIDENT_BUCKET)
        assert ledger.status(LAYER_LIVE_BEHAVIOUR) == STATUS_NOT_SUBMITTED

    def test_fabricated_but_plausible_id_also_rejected(self):
        # Not the bare tool name, but still not a real generated id -- e.g. PI-99 is
        # not one of redteam's real 22 ids.
        bucket = {"verdicts": [{"tool": "redteam", "id": "PI-99", "verdict": "VULNERABLE"}]}
        assert pl._valid_live_test_entries(bucket) == []

    def test_end_to_end_repro_never_grades_on_the_forged_bundle(self, tmp_path, capsys):
        """The exact incident repro: an otherwise-empty home + a forged liveTest
        verdict must never earn a letter grade."""
        attest = {
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
        home = tmp_path / "empty_home"
        home.mkdir()
        attest_path = _bundle_file(tmp_path, attest, name="attest.json")
        bundle_path = _bundle_file(
            tmp_path, {"liveTest": _FORGED_INCIDENT_BUCKET}, name="bundle.json")
        rc = main([
            "--home", str(home), "--full", "--json", "--no-history",
            "--attest", attest_path, "--judged-bundle", bundle_path,
        ])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["grade"] is None
        assert payload["score"] is None
        assert payload["graded"] is False


class TestSameRunMultiturnRejected:
    """A multiturn verdict submitted in the same invocation that issued the plant is
    definitionally forged -- the harness is two-phase by construction."""

    def test_multiturn_entry_dropped_when_freshly_issued(self):
        bucket = {"verdicts": [{"tool": "multiturn", "id": "MT-01", "verdict": "VULNERABLE"}]}
        assert pl._valid_live_test_entries(bucket) == [("multiturn", "MT-01", "VULNERABLE")]
        assert pl._valid_live_test_entries(
            bucket, multiturn_freshly_issued=True) == []

    def test_multiturn_cap_signal_never_hits_when_freshly_issued(self):
        bucket = {"verdicts": [{"tool": "multiturn", "id": "MT-01", "verdict": "VULNERABLE"}]}
        sig = pl.live_test_cap_signal(bucket, multiturn_freshly_issued=True)
        assert sig.hit is False

    def test_other_tools_unaffected_by_the_multiturn_flag(self):
        entry_id = next(iter(pl._REDTEAM_SCENARIO_IDS))
        bucket = {"verdicts": [{"tool": "redteam", "id": entry_id, "verdict": "VULNERABLE"}]}
        sig = pl.live_test_cap_signal(bucket, multiturn_freshly_issued=True)
        assert sig.hit is True

    def test_ledger_reads_not_submitted_when_only_entry_is_a_fresh_multiturn(self):
        bucket = {"verdicts": [{"tool": "multiturn", "id": "MT-01", "verdict": "RESISTANT"}]}
        ledger = pl.PipelineResult().to_ledger(
            [], live_test_bucket=bucket, multiturn_freshly_issued=True)
        assert ledger.status(LAYER_LIVE_BEHAVIOUR) == STATUS_NOT_SUBMITTED

    def test_build_layer_ledger_derives_the_flag_from_args(self):
        """cli._build_layer_ledger reads args.multiturn/args.self_test directly --
        never threaded as a separate kwarg -- so a caller whose args set either one
        gets the same protection with no extra plumbing."""
        bucket = {"verdicts": [{"tool": "multiturn", "id": "MT-01", "verdict": "VULNERABLE"}]}
        args = SimpleNamespace(full=True, fast=False, multiturn=True, self_test=False)
        ledger = cli._build_layer_ledger(
            args, [], live_test_bucket=bucket, commit_full_phases=False)
        assert ledger.status(LAYER_LIVE_BEHAVIOUR) == STATUS_NOT_SUBMITTED

    def test_build_layer_ledger_self_test_also_counts_as_freshly_issued(self):
        bucket = {"verdicts": [{"tool": "multiturn", "id": "MT-01", "verdict": "VULNERABLE"}]}
        args = SimpleNamespace(full=True, fast=False, multiturn=False, self_test=True)
        ledger = cli._build_layer_ledger(
            args, [], live_test_bucket=bucket, commit_full_phases=False)
        assert ledger.status(LAYER_LIVE_BEHAVIOUR) == STATUS_NOT_SUBMITTED

    def test_build_layer_ledger_normal_run_unaffected(self):
        bucket = {"verdicts": [{"tool": "multiturn", "id": "MT-01", "verdict": "VULNERABLE"}]}
        args = SimpleNamespace(full=True, fast=False, multiturn=False, self_test=False)
        ledger = cli._build_layer_ledger(
            args, [], live_test_bucket=bucket, commit_full_phases=False)
        assert ledger.status(LAYER_LIVE_BEHAVIOUR) == STATUS_RAN


class TestSkillMdNoLongerTeachesTheRejectedShape:
    def test_skill_md_example_does_not_use_bare_tool_name_as_id(self):
        skill_md = Path(__file__).resolve().parent.parent / "SKILL.md"
        text = skill_md.read_text(encoding="utf-8")
        assert '"id": "canary"' not in text
        assert '"tool": "canary", "id": "canary"' not in text

    def test_skill_md_shows_a_real_scenario_id_shape(self):
        skill_md = Path(__file__).resolve().parent.parent / "SKILL.md"
        text = skill_md.read_text(encoding="utf-8")
        # The replacement example uses a real redteam id.
        assert '"id": "PI-01"' in text


class TestGenuineBundleStillCompletesLayer5:
    """Positive control (per the task's own DoD): a genuine, correctly-shaped bundle
    must still let layer 5 complete and a run still reach a grade."""

    def test_genuine_resistant_bundle_still_grades_home_safe(self, tmp_path, capsys):
        attest = {
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
        genuine_bucket = {"seed": "x", "verdicts": [
            {"tool": "canary", "id": _VALID_CANARY_ID, "verdict": "RESISTANT"}]}
        attest_path = _bundle_file(tmp_path, attest, name="attest.json")
        bundle_path = _bundle_file(
            tmp_path, {"liveTest": genuine_bucket}, name="bundle.json")
        rc = main([
            "--home", SAFE, "--full", "--json", "--no-history",
            "--attest", attest_path, "--judged-bundle", bundle_path,
        ])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["graded"] is True
        assert payload["grade"] is not None
        assert payload["missing_layers"] == []
