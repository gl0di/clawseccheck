"""F-153: --fast and --judged-bundle are --full modifiers, on the same terms --quiet
already is (C-128/B-066 lineage) — used without --full, or shadowed by a winning
primary mode, they have no effect and must say so on stderr rather than being
silently dropped.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.cli import main

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
VULN = str(FIXTURES / "home_vuln")
BASE = ["--no-native", "--no-history"]


# ---------------------------------------------------------------------------
# --fast has no effect without --full
# ---------------------------------------------------------------------------

def test_fast_without_full_notes_no_effect(capsys):
    rc = main(["--home", VULN] + BASE + ["--fast"])
    err = capsys.readouterr().err
    assert rc == 0
    assert "--fast has no effect without --full" in err


def test_fast_shadowed_by_a_winning_primary_mode_notes_no_effect(capsys):
    rc = main(["--home", VULN] + BASE + ["--fast", "--json"])
    err = capsys.readouterr().err
    assert rc == 0
    assert "--fast" in err


def test_fast_with_full_emits_no_note(capsys):
    rc = main(["--home", VULN] + BASE + ["--full", "--fast"])
    err = capsys.readouterr().err
    assert rc in (0, 1)
    assert "--fast" not in err


# ---------------------------------------------------------------------------
# --judged-bundle has no effect without --full
# ---------------------------------------------------------------------------

def test_judged_bundle_without_full_notes_no_effect(tmp_path, capsys):
    bundle = tmp_path / "b.json"
    bundle.write_text(json.dumps({"judged": {}}), encoding="utf-8")
    rc = main(["--home", VULN] + BASE + ["--judged-bundle", str(bundle)])
    err = capsys.readouterr().err
    assert rc == 0
    assert "--judged-bundle has no effect without --full" in err


def test_judged_bundle_shadowed_by_a_winning_primary_mode_notes_no_effect(tmp_path, capsys):
    bundle = tmp_path / "b.json"
    bundle.write_text(json.dumps({"judged": {}}), encoding="utf-8")
    rc = main(["--home", VULN] + BASE + ["--judged-bundle", str(bundle), "--json"])
    err = capsys.readouterr().err
    assert rc == 0
    assert "--judged-bundle" in err


def test_judged_bundle_with_full_emits_no_note_and_is_consumed(tmp_path, capsys):
    """B-804: an EMPTY judged bucket ({"judged": {}}) no longer produces a
    `secondOpinion` -- that is now "nothing submitted", not "consumed". Prove
    consumption with a real, usable verdict instead, exactly as a host agent's
    round trip would supply one."""
    from clawseccheck.adjudication import build_judge_packet
    from clawseccheck.checks import run_all
    from clawseccheck.collector import collect
    ctx = collect(VULN)
    packet = build_judge_packet(ctx, run_all(ctx))
    assert packet, "fixture must offer at least one borderline item for this test to mean anything"
    item = packet[0]
    bundle = tmp_path / "b.json"
    bundle.write_text(json.dumps({"judged": {"verdicts": [
        {"finding_id": item["finding_id"], "target": item["target"], "verdict": "SAFE"},
    ]}}), encoding="utf-8")
    rc = main(["--home", VULN] + BASE + ["--full", "--json",
                                         "--judged-bundle", str(bundle)])
    err = capsys.readouterr()
    assert rc in (0, 1)
    assert "--judged-bundle" not in err.err
    payload = json.loads(err.out)
    assert "secondOpinion" in payload
    assert payload["verdictsSubmitted"] is True


def test_full_fast_and_judged_bundle_together_emit_no_spurious_note(tmp_path, capsys):
    bundle = tmp_path / "b.json"
    bundle.write_text(json.dumps({"judged": {}}), encoding="utf-8")
    rc = main(["--home", VULN] + BASE + ["--full", "--fast",
                                         "--judged-bundle", str(bundle)])
    err = capsys.readouterr().err
    assert rc in (0, 1)
    assert "--fast" not in err
    assert "--judged-bundle" not in err


# ---------------------------------------------------------------------------
# Exit-code parity between --quiet and verbose --full (C5) — the pipeline's
# has_fail must not diverge between the two render branches.
# ---------------------------------------------------------------------------

def test_full_exit_code_matches_between_quiet_and_verbose():
    rc_verbose = main(["--home", VULN] + BASE + ["--full", "--exit-code"])
    rc_quiet = main(["--home", VULN] + BASE + ["--full", "--quiet", "--exit-code"])
    assert rc_verbose == rc_quiet
