"""CLAWSECCHECK-B-715 — the log/trajectory scope-note clause must say plainly that
there was nothing to scan when B164 found no log/transcript sink at all, instead of the
generic "ran, coverage not accounted for" wording — which reads as a caveat about
something left unaccounted for, when the truth is simpler and more actionable: turn
logging on.

This is a WORDING fix only. The layer's `ran` status is correct and untouched (B164
always runs in the base audit) — an earlier attempt demoted the layer instead, flipped
636 of 670 fixture homes, broke 12 tests, and was reverted. `layers.py` and
`pipeline.py` are out of scope here; see `clawseccheck/report.py`'s `_SCOPE_CLAUSES`
comment block and `_log_hunt_found_no_sink` for the reasoning this file pins.

B164 (`checks/_egress.py::check_log_threat_hunt`) has TWO distinct UNKNOWN branches:

  * `if not sinks:`      -> "No agent log/transcript sinks found ... nothing to
                             content-scan."   -- THERE WAS NOTHING TO SCAN (this file's
                             subject).
  * `if not any_scanned:` -> "N sink(s) found but none were readable/non-empty ...
                              nothing to content-scan." -- sinks exist, we could not
                              read them. NOT this file's subject: telling the operator
                              "nothing to scan" here would be false and would hide the
                              more actionable defect (fix the permissions).

Both share the substring "nothing to content-scan" in B164's OWN detail, which is
exactly why the renderer's discriminator (`_log_hunt_found_no_sink`) matches the
no-sinks branch's specific PREFIX and not on UNKNOWN alone.

Offline, read-only, stdlib only. Nothing written outside pytest's own machinery; the
real `~/.openclaw` is never read (`fixtures/home_safe` only).
"""
from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

from clawseccheck import pipeline as pl
from clawseccheck import report
from clawseccheck import scoring
from clawseccheck.catalog import HIGH, PASS, UNKNOWN, Finding
from clawseccheck.checks import run_all
from clawseccheck.checks._egress import check_log_threat_hunt
from clawseccheck.collector import collect
from clawseccheck.layers import (
    LAYER_LOGS_TRAJECTORIES,
    LAYER_ORDER,
    STATUS_RAN,
    LayerLedger,
    LayerState,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
HOME_SAFE = FIXTURES / "home_safe"

NOTHING_TO_SCAN = "ran, nothing to scan"
COVERAGE_NOT_ACCOUNTED = "ran, coverage not accounted for"
SUBJECT = "already logged"  # substring of the logs/trajectories subject phrase


def _run_full(home: Path):
    """The real call chain a `--full` report goes through: collect -> run_all ->
    run_pipeline -> to_ledger -> scoring.compute -> render_report — mirrors
    tests/test_b558_ledger_coverage_single_producer.py's own pattern, not the static
    `_SCOPE_CLAUSES` table read directly."""
    ctx = collect(home)
    findings = run_all(ctx)
    result = pl.run_pipeline(ctx, findings, home_dir=ctx.home, ascii_only=True)
    ledger = result.to_ledger(findings)
    score = scoring.compute(findings, ctx, ledger=ledger)
    text = report.render_report(findings, score, ascii_only=True, ctx=ctx)
    return findings, score, text


def _logs_clause(text: str) -> str:
    """Isolate the single scope-note line for the logs/trajectories subject, the same
    way test_b520_scope_note_ledger.py isolates its clauses — by subject phrase — so an
    assertion cannot be satisfied by some unrelated line in a thousand-line report."""
    for line in text.splitlines():
        if SUBJECT in line:
            return line
    raise AssertionError(f"no logs/trajectories scope clause found:\n{text}")


def _seeded_finding(status: str, detail: str) -> Finding:
    return Finding("B164", "seeded", HIGH, status, detail, "fix", "framework")


def _ran_ledger() -> LayerLedger:
    """Every layer `ran` — the shape `pipeline.to_ledger` produces on a complete run,
    same helper shape as test_b520_scope_note_ledger.py's `_ledger()`."""
    states = {layer: LayerState(status=STATUS_RAN) for layer in LAYER_ORDER}
    return LayerLedger(states=MappingProxyType(states))


# ------------------------------------------------- the coupling pin (do this first)


def test_the_renderer_s_no_sink_prefix_is_still_what_b164_emits():
    """`report._log_hunt_found_no_sink` matches
    `detail.startswith("No agent log/transcript sinks found")` — a literal string
    coupled to B164's own prose, not to any shared constant. If B164's detail is ever
    reworded, that match silently stops firing: no exception, no red test at the
    coupling site itself — just the misleading "ran, coverage not accounted for" line
    quietly coming back with nothing catching it. This test runs the REAL check
    function (not a hand-built Finding) over `fixtures/home_safe` (measured: no log or
    transcript sink present) and pins that its detail still starts with the exact
    prefix the renderer keys on. A reword must break HERE, at the source, not degrade
    the report silently."""
    ctx = collect(HOME_SAFE)
    finding = check_log_threat_hunt(ctx)
    assert finding.id == "B164"
    assert finding.status == UNKNOWN, finding.detail
    assert finding.detail.startswith("No agent log/transcript sinks found"), finding.detail


# --------------------------------------------------------------- tests 1 + 2: home_safe


def test_home_safe_logs_clause_says_nothing_to_scan_not_unaccounted_coverage():
    findings, _score, text = _run_full(HOME_SAFE)
    b164 = next((f for f in findings if f.id == "B164"), None)
    assert b164 is not None and b164.status == UNKNOWN, "fixture assumption changed"
    clause = _logs_clause(text)
    assert NOTHING_TO_SCAN in clause, clause
    assert COVERAGE_NOT_ACCOUNTED not in clause, clause


def test_home_safe_logs_clause_still_carries_the_advice():
    _findings, _score, text = _run_full(HOME_SAFE)
    clause = _logs_clause(text)
    assert "--behavioral" in clause, clause
    assert "--analyze-trajectory" in clause, clause


# ------------------------------------------------------------ test 3: the discriminator


def test_unreadable_sinks_are_not_told_nothing_to_scan():
    """B164's OTHER UNKNOWN branch (`if not any_scanned:`) — sinks exist, none were
    readable/non-empty. Must NOT read "nothing to scan": that would be false and would
    hide the more actionable fact (fix the permissions). Without this test the fix is
    satisfiable by matching UNKNOWN alone, which would mislabel this case too."""
    findings = [_seeded_finding(
        UNKNOWN,
        "3 log/transcript sink(s) found but none were readable/non-empty "
        "— nothing to content-scan.",
    )]
    score = scoring.compute(findings, ledger=_ran_ledger())
    lines, _live_tested = report._scope_note_lines(score, findings)
    clause = next(ln for ln in lines if SUBJECT in ln)
    assert NOTHING_TO_SCAN not in clause, clause
    assert COVERAGE_NOT_ACCOUNTED in clause, clause


# ------------------------------------------------------------------------ test 4: PASS


def test_scanned_sink_keeps_the_original_wording():
    findings = [_seeded_finding(
        PASS, "1 log/transcript sink(s) scanned; nothing suspicious found.",
    )]
    score = scoring.compute(findings, ledger=_ran_ledger())
    lines, _live_tested = report._scope_note_lines(score, findings)
    clause = next(ln for ln in lines if SUBJECT in ln)
    assert COVERAGE_NOT_ACCOUNTED in clause, clause
    assert NOTHING_TO_SCAN not in clause, clause


# -------------------------------------------------------------------- test 5: the layer


def test_home_safe_logs_trajectories_layer_is_not_demoted():
    """This change touches only the SENTENCE, never the ledger. `logs_trajectories`
    stays absent from `missing_layers` on home_safe, exactly as before B-715: the layer
    still `ran` (B164 always runs in the base audit) — only the wording of the clause
    describing that changed."""
    _findings, score, _text = _run_full(HOME_SAFE)
    missing = dict(getattr(score, "missing_layers", ()) or ())
    assert LAYER_LOGS_TRAJECTORIES not in missing, missing
