"""C-724 items 4, 5 and 6: small truths in the second-opinion path.

4. A well-formed verdict entry that matches no judge-packet item is counted in one stderr
   `note:` (a number, never the entry's text) on --judged, --judged-bundle and --vet-judged.
5. --seed rejects an empty, blank or over-long value at the command line (exit 2).
6. A verdict whose own `votes` do not include it is not shown as a 0/N tally.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from clawseccheck.canary import make_canary
from clawseccheck.catalog import FAIL, HIGH, WARN, Finding

REPO_ROOT = Path(__file__).resolve().parent.parent
_MARK = "matched no item in the judge packet"


def _entry(fid: str, target: str, verdict: str = "SAFE", **extra) -> dict:
    return {"finding_id": fid, "target": target, "verdict": verdict, **extra}


# ------------------------------------------------------------------------ item 4: --judged

@pytest.fixture
def one_item_packet(monkeypatch):
    from clawseccheck.adjudication import _verdicts

    monkeypatch.setattr(_verdicts, "build_judge_packet", lambda ctx, findings: [
        {"finding_id": "B65", "target": "skillx", "engine_disposition": "WARN"}])


class TestUnmatchedEntriesAreCounted:
    def test_a_judged_run_counts_entries_that_match_no_packet_item(self, one_item_packet, capsys):
        from clawseccheck.adjudication import _parse_verdicts_with_abstentions, _second_opinion

        raw = json.dumps({"verdicts": [
            _entry("B65", "skillx", "DANGEROUS"),         # matches: applied
            _entry("B65", "someone-else", "SAFE"),        # real id, wrong target
            _entry("NOT-A-CHECK", "skillx", "SUSPICIOUS"),  # unknown id
            _entry("B1", "skillx", "ABSTAIN"),            # an ABSTAIN for a non-packet item
        ]})
        vmap, abstained = _parse_verdicts_with_abstentions(raw)
        capsys.readouterr()
        rows = _second_opinion(None, [], vmap, abstained)
        err = capsys.readouterr().err
        assert "note: 3 submitted (finding_id, target) pairs " + _MARK in err
        assert rows[0]["judge_verdict"] == "DANGEROUS"
        # A count only: nothing the submitter wrote comes back.
        for text in ("someone-else", "NOT-A-CHECK"):
            assert text not in err

    def test_one_is_singular(self, one_item_packet, capsys):
        from clawseccheck.adjudication import _second_opinion

        _second_opinion(None, [], {("B65", "skillx"): {"verdict": "SAFE", "votes": None},
                                   ("X", "y"): {"verdict": "SAFE", "votes": None}}, frozenset())
        assert "note: 1 submitted (finding_id, target) pair " + _MARK in capsys.readouterr().err

    def test_nothing_unmatched_is_silent(self, one_item_packet, capsys):
        from clawseccheck.adjudication import _second_opinion

        _second_opinion(None, [], {("B65", "skillx"): {"verdict": "SAFE", "votes": None}},
                        frozenset())
        _second_opinion(None, [], {}, frozenset())
        assert _MARK not in capsys.readouterr().err

    def test_the_applied_output_is_unchanged_by_the_note(self, one_item_packet, capsys):
        from clawseccheck.adjudication import _second_opinion

        matched = {("B65", "skillx"): {"verdict": "SUSPICIOUS", "votes": None}}
        before = _second_opinion(None, [], matched, frozenset())
        noisy = dict(matched)
        noisy[("junk", "skillx")] = {"verdict": "DANGEROUS", "votes": None}
        assert _second_opinion(None, [], noisy, frozenset()) == before

    def test_over_the_judged_flag(self, tmp_path, capsys):
        from clawseccheck.cli import main

        (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
        verdicts = tmp_path / "verdicts.json"
        verdicts.write_text(json.dumps({"verdicts": [_entry("B1", "nowhere", "SAFE")]}),
                            encoding="utf-8")
        rc = main(["--home", str(tmp_path), "--judged", str(verdicts), "--no-native",
                   "--no-host"])
        captured = capsys.readouterr()
        assert rc == 0
        assert captured.err.count(_MARK) == 1 and "note: 1 submitted (finding_id, target) pair " in captured.err
        # Nothing matched, so no packet row carries a verdict.
        rows = json.loads(captured.out)["secondOpinion"]
        assert rows and all(r["judge_verdict"] is None for r in rows)
        assert "nowhere" not in captured.err

    def test_over_the_judged_bundle_flag(self, tmp_path):
        (tmp_path / "home").mkdir()
        (tmp_path / "home" / "openclaw.json").write_text("{}", encoding="utf-8")
        bundle = tmp_path / "bundle.json"
        bundle.write_text(json.dumps({"judged": {"verdicts": [
            _entry("B1", "nowhere", "SAFE"), _entry("B2", "nowhere", "DANGEROUS")]}}),
            encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, "-m", "clawseccheck", "--home", str(tmp_path / "home"), "--full",
             "--json", "--no-history", "--no-deptree", "--no-host", "--no-update-notice",
             "--judged-bundle", str(bundle), "--data-dir", str(tmp_path / "data")],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=600)
        assert proc.returncode in (0, 1), proc.stderr[-1500:]
        assert "note: 2 submitted (finding_id, target) pairs " + _MARK in proc.stderr
        assert _MARK not in proc.stdout


def _vet_inputs():
    from clawseccheck.adjudication import render_vet_judge_packet_json

    primary = Finding("B65", "t", HIGH, WARN, "primary detail", "fix it", "fw",
                      evidence=["skillx: matched pattern (skill.py:1)"])
    primary.ring_findings = []
    rendered = json.loads(render_vet_judge_packet_json(primary, target="skillx", version="9.9.9"))
    return primary, rendered["targetFingerprint"]


class TestVetJudged:
    def test_unmatched_entries_are_counted_and_the_matching_one_still_applies(self, capsys):
        from clawseccheck.adjudication import escalate_vet_output

        primary, fp = _vet_inputs()
        raw = json.dumps({"targetFingerprint": fp, "verdicts": [
            _entry("B65", "skillx", "DANGEROUS"),
            _entry("B65", "zz-wrong-target", "DANGEROUS"),
            _entry("ZZ-ID-999", "skillx", "SAFE"),
            _entry("ZZ-ID-998", "skillx", "ABSTAIN")]})
        out = escalate_vet_output(primary, raw, target="skillx")
        err = capsys.readouterr().err
        assert out.status == FAIL
        assert "note: 3 submitted (finding_id, target) pairs " + _MARK in err
        assert "ZZ-ID-99" not in err and "zz-wrong-target" not in err

    def test_all_entries_matching_is_silent(self, capsys):
        from clawseccheck.adjudication import escalate_vet_output

        primary, fp = _vet_inputs()
        raw = json.dumps({"targetFingerprint": fp, "verdicts": [
            _entry("B65", "skillx", "DANGEROUS"),
            _entry("ATTEST-PROSE-MISMATCH", "skillx", "ABSTAIN")]})
        escalate_vet_output(primary, raw, target="skillx")
        assert _MARK not in capsys.readouterr().err

    def test_a_fingerprint_mismatch_keeps_its_own_note_only(self, capsys):
        from clawseccheck.adjudication import escalate_vet_output

        primary, _ = _vet_inputs()
        raw = json.dumps({"targetFingerprint": "0" * 16,
                          "verdicts": [_entry("B999", "skillx", "SAFE")]})
        escalate_vet_output(primary, raw, target="skillx")
        err = capsys.readouterr().err
        assert "targetFingerprint" in err and _MARK not in err


# ---------------------------------------------------------------------------- item 5: --seed

_HARNESS_FLAGS = ("--canary", "--redteam", "--dryrun", "--multiturn", "--self-test")


def _cli(*argv: str):
    return subprocess.run([sys.executable, "-m", "clawseccheck", *argv], cwd=REPO_ROOT,
                          capture_output=True, text=True, timeout=300)


class TestSeedArgument:
    @pytest.mark.parametrize("flag", _HARNESS_FLAGS)
    @pytest.mark.parametrize("seed", ["", "   ", "\t\n"])
    def test_an_empty_or_blank_seed_is_refused(self, flag, seed):
        proc = _cli(flag, "--seed", seed)
        assert proc.returncode == 2
        assert proc.stdout == ""
        assert "--seed: must not be empty or blank" in proc.stderr

    def test_an_over_long_seed_is_refused(self):
        proc = _cli("--canary", "--seed", "a" * 129)
        assert proc.returncode == 2
        assert "--seed: must be at most 128 characters" in proc.stderr

    def test_every_seed_of_1_to_128_characters_keeps_working_unchanged(self):
        for seed in ("x", " x ", "a" * 128, "é"):
            proc = _cli("--canary", "--seed", seed)
            assert proc.returncode == 0, (seed, proc.stderr[-300:])
            assert make_canary(seed)["token"] in proc.stdout
            assert _cli("--canary", "--seed", seed).stdout == proc.stdout


# ------------------------------------------------------------------- item 6: votes that omit it

class TestVotesThatDoNotContainTheVerdict:
    def test_the_annotation_does_not_read_as_a_zero_tally(self):
        from clawseccheck.adjudication import _annotate

        line = _annotate("WARN", {"verdict": "DANGEROUS", "votes": {"SAFE": 3}})
        assert "0/3" not in line
        assert "judge: DANGEROUS (the submitted votes do not include it: 3 under other labels)" in line
        # the verdict and its priority are kept
        assert line == _annotate("WARN", {"verdict": "DANGEROUS", "votes": None}).replace(
            "judge: DANGEROUS", "judge: DANGEROUS (the submitted votes do not include it: 3 under other labels)")

    def test_the_other_shapes_read_exactly_as_before(self):
        from clawseccheck.adjudication import _annotate

        assert "judges: 3/3 DANGEROUS" in _annotate(
            "WARN", {"verdict": "DANGEROUS", "votes": {"DANGEROUS": 3}})
        assert "judges: 2/3 DANGEROUS" in _annotate(
            "WARN", {"verdict": "DANGEROUS", "votes": {"DANGEROUS": 2, "SAFE": 1}})
        assert "judge: DANGEROUS →" in _annotate(
            "WARN", {"verdict": "DANGEROUS", "votes": None})

    def test_vet_judged_does_not_report_a_split_for_it(self):
        from clawseccheck.adjudication import _escalate_finding

        f = Finding("B65", "t", HIGH, WARN, "d", "fix", "fw",
                    evidence=["skillx: matched pattern (skill.py:1)"])
        out = _escalate_finding(f, {("B65", "skillx"): {"verdict": "DANGEROUS",
                                                        "votes": {"SAFE": 3}}})
        assert out.status == FAIL
        assert out.detail.startswith(
            "[escalated by host-agent judge: DANGEROUS (the submitted votes do not include "
            "it: 3 under other labels)] ")
        assert "panel split" not in out.detail and "0/3" not in out.detail

    def test_a_real_split_still_reads_as_a_split(self):
        from clawseccheck.adjudication import _escalate_finding

        f = Finding("B65", "t", HIGH, WARN, "d", "fix", "fw",
                    evidence=["skillx: matched pattern (skill.py:1)"])
        out = _escalate_finding(f, {("B65", "skillx"): {
            "verdict": "DANGEROUS", "votes": {"DANGEROUS": 2, "SAFE": 1}}})
        assert "(panel split: 2/3 DANGEROUS)" in out.detail

    def test_the_prose_attestation_finding_says_the_same(self):
        from clawseccheck.adjudication import _vet_attest_new_findings

        found = _vet_attest_new_findings("skillx", {
            ("ATTEST-PROSE-MISMATCH", "skillx"): {"verdict": "DANGEROUS",
                                                  "votes": {"SAFE": 3}}})
        assert len(found) == 1
        assert "(the submitted votes do not include it: 3 under other labels)" in found[0].detail
        assert "panel split" not in found[0].detail
