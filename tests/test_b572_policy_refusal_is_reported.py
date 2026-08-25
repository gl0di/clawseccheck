"""B-572 — --propose-ignore must say when it refuses a verdict on policy.

The parse-level diagnostic already exists: a malformed payload gets a detailed
"produced no usable entries" note. A perfectly well-formed SAFE verdict that
build_ignore_proposals declines by its own rules was dropped in silence, so a
partially-refused submission looked exactly like a judge that reviewed fewer items.

The refusal is correct and is the safety property working. These tests pin that it is
SAID, not that it stops — and that saying it costs nothing: stdout, the proposals array
and the note-free case all stay as they were.
"""
import json

import pytest

from clawseccheck.adjudication import (
    _is_borderline,
    _target_from_evidence,
    render_ignore_proposals_json,
)
from clawseccheck.catalog import Finding


def _f(fid, status, evidence=None, **kw):
    # Positional order matches tests/test_adjudication.py: id, title, severity, status,
    # detail, fix, framework.
    return Finding(
        fid, "t", "MEDIUM", status, f"{fid} detail", "fix it", "fw",
        evidence=evidence if evidence is not None else [f"{fid}-target"],
        **kw,
    )


def _payload(pairs):
    return json.dumps({"verdicts": [
        {"finding_id": fid, "target": tgt, "verdict": v} for fid, tgt, v in pairs
    ]})


def _render(findings, pairs):
    return render_ignore_proposals_json(
        findings, verdicts_raw=_payload(pairs), version="test")


# --------------------------------------------------------------- the defect
def test_policy_refused_safe_verdict_is_reported(capsys):
    """A SAFE verdict on a FAIL-status finding is never a candidate — say so."""
    borderline = _f("B100", "UNKNOWN")
    fail = _f("B1", "FAIL")
    out = _render([borderline, fail], [
        ("B100", _target_from_evidence(borderline), "SAFE"),
        ("B1", _target_from_evidence(fail), "SAFE"),
    ])
    err = capsys.readouterr().err
    assert "1 of 2 submitted SAFE verdicts were not proposed" in err
    assert "not suppression candidates" in err
    # the accepted one is still proposed — reporting must not change the outcome
    assert len(json.loads(out)["proposedIgnoreEntries"]) == 1


def test_the_refused_finding_id_is_not_named(capsys):
    """Counts and reason classes only.

    Naming the refused id would read as advice on how to make a finding suppressible,
    and _note's contract is fixed text plus integers so nothing needs redacting.
    """
    fail = _f("B1", "FAIL")
    _render([fail], [("B1", _target_from_evidence(fail), "SAFE")])
    err = capsys.readouterr().err
    assert "not suppression candidates" in err
    assert "B1" not in err


def test_a_verdict_matching_no_finding_is_its_own_class(capsys):
    _render([_f("B100", "UNKNOWN")], [("B999", "ghost", "SAFE")])
    err = capsys.readouterr().err
    assert "did not match any finding in this run" in err


def test_an_aggregate_finding_refusal_names_the_scoping_reason(capsys):
    """A multi-evidence finding cannot be scoped to the one target reviewed."""
    aggr = _f("B100", "UNKNOWN", evidence=["skill-a", "skill-b", "skill-c"])
    _render([aggr], [("B100", _target_from_evidence(aggr), "SAFE")])
    err = capsys.readouterr().err
    assert "aggregates more than one target" in err


# --------------------------------------------------------------- no false chatter
def test_a_fully_eligible_submission_stays_silent(capsys):
    """Every submitted verdict accepted -> nothing to report.

    Without this the fix would trade one silence for constant noise, and a note that
    fires every run stops being read.
    """
    a, b = _f("B100", "UNKNOWN"), _f("B101", "UNKNOWN")
    out = _render([a, b], [
        ("B100", _target_from_evidence(a), "SAFE"),
        ("B101", _target_from_evidence(b), "SAFE"),
    ])
    assert capsys.readouterr().err == ""
    assert len(json.loads(out)["proposedIgnoreEntries"]) == 2


def test_no_verdicts_at_all_stays_silent(capsys):
    render_ignore_proposals_json([_f("B100", "UNKNOWN")], verdicts_raw="", version="t")
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("verdict", ["SUSPICIOUS", "DANGEROUS"])
def test_a_non_safe_verdict_is_not_a_refusal(capsys, verdict):
    """The judge declining to call something safe is not a request we refused.

    Counting it would report a refusal to a caller that never asked for suppression.
    """
    f = _f("B100", "UNKNOWN")
    _render([f], [("B100", _target_from_evidence(f), verdict)])
    assert capsys.readouterr().err == ""


# --------------------------------------------------------------- channel contract
def test_the_note_never_reaches_stdout(capsys):
    """Every consumer of this module renders JSON to stdout; a diagnostic there
    would corrupt the artifact."""
    fail = _f("B1", "FAIL")
    out = _render([fail], [("B1", _target_from_evidence(fail), "SAFE")])
    captured = capsys.readouterr()
    assert "not proposed" in captured.err
    assert "not proposed" not in captured.out
    assert json.loads(out)["proposedIgnoreEntries"] == []


def test_borderline_population_is_unchanged_by_the_diagnostic():
    """Pins that reporting did not quietly widen or narrow what gets proposed."""
    a = _f("B100", "UNKNOWN")
    assert _is_borderline(a)
    out = _render([a], [("B100", _target_from_evidence(a), "SAFE")])
    assert [p["finding_id"] for p in json.loads(out)["proposedIgnoreEntries"]] == ["B100"]
