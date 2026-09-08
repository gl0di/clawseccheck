"""B-536 — the SKILL SWEEP header pointed at a score and a grade that were not there.

`--full`'s CLAWSECCHECK SKILL SWEEP section opens with a "visibility only" sentence:
the per-skill verdicts below it never move the audit's own number. That fact is true on
every run shape. The sentence asserted it by POINTING --

    Not folded into the score or grade above

-- and on a `graded=False` run there is no score and no grade above it to point at.
C-423 removed both from every renderer, so the reader was sent hunting up the page for
a figure the run had deliberately refused to print; the only "score" on the way up is
the tamper posture, which carries its own "not this run's verdict" disclaimer.

Same family as C-423 / C-426 / C-428 / B-532: output whose prose presupposes a run
shape it did not check for. The fix moves ONLY the noun (`cli._sweep_not_folded_clause`)
-- the fact survives in both directions, because "a sweep verdict never moves the
audit's number" is exactly as true when there is no number.

Asserted through the real entry point (`cli.main`) on a rendered `--full` run, in BOTH
directions on purpose: a fix that simply deleted the pointer everywhere would pass a
one-sided test while making the graded report vaguer -- trading a false claim on one run
shape for a weaker one on the other. The graded case therefore pins that the original
wording is still printed.

Offline; writes only under pytest's tmp_path (`--home` and `--data-dir` are both
redirected, so nothing touches a real ~/.clawseccheck or ~/.openclaw).
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.cli import _sweep_not_folded_clause, main

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE = str(FIXTURES / "home_safe")

#: The deixis this task removes from ungraded runs, verbatim as it is rendered.
POINTER = "score or grade above"

#: The sentence's stable prefix — present on every `--full` run, both shapes.
SWEEP_HEADER = "Per-skill verdict for every installed skill."


def _full_run(capsys, tmp_path, *extra):
    """A rendered `--full` run, with every writable location under tmp_path."""
    code = main([
        "--home", SAFE,
        "--data-dir", str(tmp_path / "data"),
        "--full", "--no-history", "--no-color", "--ascii",
        *extra,
    ])
    return code, capsys.readouterr().out


def _graded_inputs(tmp_path):
    """The two files that carry a `--full` run to all five layers.

    `self_report` is `ran` iff a schema-valid attestation reached `audit()`, and
    `live_behaviour` iff `--judged-bundle`'s `liveTest` bucket holds at least one
    structurally-valid entry -- REGARDLESS of its verdict (`pipeline.to_ledger`).
    RESISTANT is used deliberately: it completes the layer without tripping
    `scoring.LIVE_INJECTION_CAP`, so this run is graded rather than merely capped.
    """
    attest_path = tmp_path / "attest.json"
    attest_path.write_text(json.dumps({
        "schema": "clawseccheck-attest/1",
        "tools": [],
        "approval_gates": {"exec": "unknown", "send": "unknown", "write": "unknown"},
        "untrusted_to_action": "unknown",
    }))
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps({"liveTest": {
        "seed": "b536b536b536b536",
        "verdicts": [{"tool": "canary", "id": "canary", "verdict": "RESISTANT"}],
    }}))
    return str(attest_path), str(bundle_path)


def _sweep_line(out: str) -> str:
    for line in out.splitlines():
        if line.startswith(SWEEP_HEADER):
            return line
    raise AssertionError(
        "the SKILL SWEEP header line was not rendered at all — this test can no "
        "longer see the string it exists to pin:\n" + out[-1500:])


# ---- the defect ----

def test_ungraded_full_does_not_point_at_a_score_or_grade(capsys, tmp_path):
    _, out = _full_run(capsys, tmp_path)
    # Guard the premise: this run really is ungraded. Without it, a future change that
    # made a bare --full graded would leave this test passing while asserting nothing.
    assert "No grade yet" in out, "premise broken: this --full run was graded"
    assert POINTER not in out, (
        "an ungraded --full run still points at a score or grade above it:\n"
        + _sweep_line(out))


def test_ungraded_full_still_states_the_fact(capsys, tmp_path):
    """The pointer goes; the thing it was there to say does not."""
    _, out = _full_run(capsys, tmp_path)
    line = _sweep_line(out)
    assert "Not folded into" in line, line
    assert "score or grade" in line, line
    assert "--vet <path>" in line, line


# ---- the opposite direction ----

def test_graded_full_still_points_at_the_score_and_grade_it_prints(capsys, tmp_path):
    attest_path, bundle_path = _graded_inputs(tmp_path)
    _, out = _full_run(capsys, tmp_path,
                       "--attest", attest_path, "--judged-bundle", bundle_path)
    assert "No grade yet" not in out, "premise broken: this --full run was ungraded"
    assert "Grade:" in out, "premise broken: no grade was printed above the sweep"
    assert POINTER in _sweep_line(out), (
        "a graded --full run lost the pointer to the score and grade it does print:\n"
        + _sweep_line(out))


# ---- the clause itself ----

def test_clause_moves_only_the_noun():
    class _Score:
        def __init__(self, graded):
            self.graded = graded

    assert _sweep_not_folded_clause(_Score(True)) == "the score or grade above"
    assert POINTER not in _sweep_not_folded_clause(_Score(False))


def test_clause_defaults_to_graded_for_a_stand_in_without_the_attribute():
    """`scoring.compute`'s `ledger=None` contract: no ledger means graded."""
    assert _sweep_not_folded_clause(object()) == "the score or grade above"
