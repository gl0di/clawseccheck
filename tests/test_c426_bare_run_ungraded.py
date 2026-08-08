"""C-426 (I5) — a bare run carries no grade, and no command republishes one.

I4 made a `--full` run ungraded when its five-layer check was incomplete. A BARE run
-- no flags at all, the way almost every user invokes the tool -- kept printing
`Score: 97/100  Grade: A` off a check that reached only three of the five layers.

This closes that, and the closing is wider than the default report: every mode below
takes its `score` from the SAME `audit()` call, so the ledger is built once, early,
by the one shared producer (`cli._build_layer_ledger`) and inherited everywhere.

The four modes that needed their own attention are `--trend`, `--monitor`,
`--percentile` and `--next`: they never reach `_resolve_runtime_caps` (they take
`_apply_live_test_cap`, and `--trend` returns before that call site is reached), so
before this increment they published a letter and a percentile rank for a run the
report refused to grade.

Two properties are asserted in the opposite direction on purpose, because "ungraded"
must not quietly become "unconditional":

* a `--full` run whose five layers ALL ran still gets its letter;
* a direct `scoring.compute(findings, ctx)` library call is still graded -- that is
  C-422's `ledger=None` default, and every existing caller depends on it.

Offline; writes only under pytest's tmp_path.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from clawseccheck import audit
from clawseccheck.cli import _build_layer_ledger, _percentile_line, main
from clawseccheck.layers import (
    LAYER_ORDER,
    STATUS_RAN,
    LayerLedger,
    LayerState,
)
from clawseccheck.scoring import compute

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE = str(FIXTURES / "home_safe")

# A letter grade as the report actually prints it, e.g. "Grade: A" / "Grade A".
_GRADE_RE = re.compile(r"\bGrade:?\s+[A-F]\b")
_SCORE_RE = re.compile(r"\b\d{1,3}\s*/\s*100\b")


def _run(capsys, *argv):
    code = main(list(argv))
    cap = capsys.readouterr()
    return code, cap.out, cap.err


def _verdict_text(text: str) -> str:
    """Everything except the tamper-posture line, which is NOT this run's verdict.

    `Tamper posture: 31/100` is a sub-score of one specific defence and prints its own
    disclaimer saying so. C-423 deliberately kept the measurement and dropped only its
    letter, precisely so a reader does not take it for the verdict -- see
    `feedback_never_suppress_a_finding_for_presentation`: withholding a real
    measurement to satisfy a presentation rule is the wrong trade.

    So it is exempt from the no-number rule -- but the exemption is only sound while
    the disclaimer is there, which `test_tamper_posture_is_labelled_as_not_the_verdict`
    asserts separately. Do not widen this to drop any other line.
    """
    return "\n".join(ln for ln in text.splitlines()
                     if not ln.lstrip().startswith("Tamper posture:"))


def _assert_publishes_no_grade(text: str, where: str) -> None:
    body = _verdict_text(text)
    assert not _GRADE_RE.search(body), f"{where} still prints a letter grade:\n{body[:600]}"
    assert not _SCORE_RE.search(body), f"{where} still prints an NN/100 score:\n{body[:600]}"


# ---- the default report ----

def test_bare_run_prints_no_letter_and_no_score(capsys):
    _, out, _ = _run(capsys, "--home", SAFE, "--no-history", "--no-color")
    _assert_publishes_no_grade(out, "the bare run")


def test_bare_run_says_which_layers_did_not_run(capsys):
    _, out, _ = _run(capsys, "--home", SAFE, "--no-history", "--no-color")
    assert "No grade yet" in out
    # The three a bare run genuinely cannot reach. Wording comes from
    # layers.describe_layer -- this asserts the layers are NAMED, not the phrasing.
    assert "installed skills and plugins" in out
    assert "agent self-report" in out
    assert "live behaviour test" in out


def test_tamper_posture_is_labelled_as_not_the_verdict(capsys):
    """This is what makes `_verdict_text`'s exemption sound rather than a hole.

    The tamper posture keeps its number on an ungraded run -- it is a real
    measurement of a real defence and suppressing it would be the wrong trade -- so
    it MUST keep saying it is not the verdict. Printing a bare `31/100` directly under
    "No grade yet" would give the reader a second letter-and-number scale in exactly
    the position they take for the answer.
    """
    _, out, _ = _run(capsys, "--home", SAFE, "--no-history", "--no-color")
    line = next(ln for ln in out.splitlines() if ln.lstrip().startswith("Tamper posture:"))
    assert "not this run's verdict" in line
    assert not _GRADE_RE.search(line), "the tamper posture must not carry a letter either"


def test_bare_run_still_leads_with_the_most_urgent_finding(capsys):
    """Withholding the grade must not leave the reader with nothing at the top.

    Three headline shapes are legal, and the third exists because of this increment:
    a FAIL leads with `Most urgent:`; a clean run says nothing urgent was found; and a
    run with open WARNs but no FAIL says `Nothing failed outright — most serious open
    item: …`. That third one was added when the grade stopped occupying this slot and
    the flat all-clear started printing directly above a listed CRITICAL WARN.
    """
    _, out, _ = _run(capsys, "--home", SAFE, "--no-history", "--no-color")
    head = "\n".join(out.splitlines()[:5])
    assert ("Most urgent" in head
            or "Nothing urgent found" in head
            or "Nothing failed outright" in head)


def test_the_all_clear_headline_never_outruns_the_evidence(capsys):
    """A flat "nothing urgent" must not print above a listed CRITICAL.

    On a config-blind run the card lists WARN findings by severity in its own "Most
    urgent" section, so the two lines contradicted each other. FAIL-only stays the bar
    for the word "urgent" -- the fix is to stop claiming more than "no FAIL" while
    something is still open, not to widen the bar.
    """
    _, out, _ = _run(capsys, "--home", SAFE, "--no-history", "--no-color")
    if "Nothing urgent found" in out:
        assert "WARN" not in out and "⚠️" not in out, (
            "the flat all-clear printed on a run that still has open findings")


def test_bare_run_exit_code_is_unchanged(capsys):
    """A CI script that only checks exit status must keep working."""
    code, _, _ = _run(capsys, "--home", SAFE, "--no-history", "--no-color")
    assert code == 0


def test_fast_needs_no_special_case(capsys):
    """--fast is documented as 'only with --full'; bare + --fast is still a bare run."""
    _, out, err = _run(capsys, "--home", SAFE, "--fast", "--no-history", "--no-color")
    assert "--fast" in err                       # the no-effect note still fires
    _assert_publishes_no_grade(out, "a bare --fast run")
    assert "No grade yet" in out


# ---- JSON agrees with the text ----

def test_bare_json_withholds_the_numbers_but_keeps_the_keys(capsys):
    _, out, _ = _run(capsys, "--home", SAFE, "--no-history", "--json")
    p = json.loads(out)
    assert p["graded"] is False
    for key in ("score", "grade", "raw_score"):
        assert key in p, f"{key} must stay present, as null -- not disappear"
        assert p[key] is None
    assert p["missing_layers"], "an ungraded run must say WHICH layers did not run"


def test_bare_json_projection_does_not_republish_the_withheld_score(capsys):
    """C-423 closed this leak for --full; the bare path must not reopen it.

    `render_json`'s projection block runs its own compute() calls. Without the ledger
    threaded through, `projection.current.score` published the very number the
    top-level `score` key was withholding -- one key apart in the same document.
    """
    _, out, _ = _run(capsys, "--home", SAFE, "--no-history", "--json")
    p = json.loads(out)
    projection = p.get("projection") or {}
    current = projection.get("current") or {}
    assert current.get("score") is None
    assert current.get("grade") is None


# ---- the four modes that bypass _resolve_runtime_caps ----

def test_percentile_refuses_to_rank_an_ungraded_run(capsys):
    _, out, _ = _run(capsys, "--percentile", "--home", SAFE, "--no-color")
    _assert_publishes_no_grade(out, "--percentile")
    assert "No rank yet" in out
    assert "%" not in out, "a percentile rank was published for a run with no score"


def test_trend_publishes_no_letter_and_records_no_grade(tmp_path, capsys):
    hist = tmp_path / "h.jsonl"
    _, out, _ = _run(capsys, "--trend", "--home", SAFE, "--history", str(hist), "--no-color")
    _assert_publishes_no_grade(out, "--trend")
    assert "no grade" in out
    row = json.loads(hist.read_text(encoding="utf-8").splitlines()[-1])
    assert "score" not in row and "grade" not in row
    assert row["graded"] is False


def test_next_actions_publish_no_letter(capsys):
    _, out, _ = _run(capsys, "--next", "--home", SAFE, "--no-color")
    _assert_publishes_no_grade(out, "--next")


def test_monitor_publishes_no_letter(tmp_path, capsys):
    _, out, _ = _run(capsys, "--monitor", "--home", SAFE, "--no-color",
                     "--state", str(tmp_path / "state.json"),
                     "--events", str(tmp_path / "events.jsonl"),
                     "--history", str(tmp_path / "h.jsonl"))
    _assert_publishes_no_grade(out, "--monitor")


def test_percentile_line_is_the_single_decision_point():
    """Both call sites route through one helper so they cannot drift apart."""
    ctx, findings, graded = audit(SAFE)
    assert graded.graded is True
    assert "No rank yet" not in _percentile_line(graded, True)

    ungraded = compute(findings, ctx, ledger=_bare_ledger(findings))
    assert ungraded.graded is False
    assert "No rank yet" in _percentile_line(ungraded, True)


# ---- the opposite direction: 'ungraded' must not become unconditional ----

def _bare_ledger(findings):
    class _Args:
        fast = False
    return _build_layer_ledger(_Args(), findings)


def _complete_ledger():
    return LayerLedger(states={layer: LayerState(status=STATUS_RAN) for layer in LAYER_ORDER})


def test_a_complete_five_layer_ledger_still_grades():
    ctx, findings, _ = audit(SAFE)
    result = compute(findings, ctx, ledger=_complete_ledger())
    assert result.graded is True
    assert result.grade is not None
    assert result.score is not None
    assert result.missing_layers == ()


def test_a_direct_library_call_with_no_ledger_is_still_graded():
    """C-422's `ledger=None means graded` default -- every existing caller relies on it."""
    ctx, findings, from_audit = audit(SAFE)
    assert from_audit.graded is True
    assert compute(findings, ctx).graded is True


def test_the_bare_ledger_is_built_by_the_one_shared_producer():
    """A second, hand-rolled builder anywhere is what this helper exists to prevent."""
    _, findings, _ = audit(SAFE)
    ledger = _bare_ledger(findings)
    assert ledger.complete is False
    statuses = {layer: ledger.status(layer) for layer in LAYER_ORDER}
    assert statuses["static"] == STATUS_RAN
    assert statuses["logs_trajectories"] == STATUS_RAN
    # Never optimistically "ran": no phase was committed by a bare invocation.
    assert statuses["installed_sweep"] != STATUS_RAN


def test_a_bare_call_never_claims_the_sweep_ran_even_under_full():
    """`--full --badge` and friends never run the sweep -- `--full` is a no-op there.

    So the shared producer keys the optimistic 'sweep ran' marking on the CALLER
    having committed to running those phases, not on `args.full` being set. Reading
    the flag inside the helper would fabricate a completed sweep for every mode that
    ignores `--full`.
    """
    _, findings, _ = audit(SAFE)

    class _Args:
        fast = False
        full = True

    assert _build_layer_ledger(_Args(), findings).status("installed_sweep") != STATUS_RAN
    committed = _build_layer_ledger(_Args(), findings, commit_full_phases=True,
                                    behavioral_ran=True)
    assert committed.status("installed_sweep") == STATUS_RAN
