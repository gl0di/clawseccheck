"""B-518 — the header tally counted a different set than the report it heads.

Measured on a real bare run (`python3 -m clawseccheck --no-history`), line 8 of the
report disagreed with the list printed underneath it:

    header   (2 FAIL, 21 WARN - incl. 2 CRITICAL, 7 HIGH, 7 MEDIUM, 7 LOW)
    body     38 issue(s), grouped by subject
    --json   38 FAIL/WARN findings, 38 unique check ids

FAIL, CRITICAL and HIGH agreed; MEDIUM was short by 9 and LOW by 6 — exactly the 15
advisory (`scored=False`) WARNs the run emitted. Not a dedup artifact: severity counted
over unique ids is identical to severity counted over findings.

Every one of those 15 is a finding the reader can see in the body — C015 (secrets at
rest), B14 (egress surface), B164 (threats surfaced in agent logs), B68 (filesystem
confinement). `scored=False` means "does not move the score", never "is not an issue".

## Why it only became wrong now

`report.py`'s tally is old (2026-06-20). On a **graded** run it sits directly under the
score explanation, which names its own narrower denominator — "over N scored checks …
UNKNOWN/advisory checks are excluded". That sentence is C-423-gated on `graded`, so on an
ungraded run it is not emitted at all and the tally is left with no qualifier anywhere
near it: the nearest occurrence of "scored" was 369 lines below.

So the counting did not change; the context that made it honest disappeared. That makes
this the same family as B-506 — a summary contradicting the body of its own report.

## The fix, and what it must not disturb

The tally now counts `issues`, the exact list the body renders (FAIL/WARN, unsuppressed).
The "Why N/100" line keeps the *scored* counts, because its arithmetic has to reconcile
with `raw_score` — and it already discloses that narrower denominator in its own text.
Both numbers are now labeled by what they head; neither is a silent subset of the other.

Stdlib-only, offline, writes nothing.
"""
from __future__ import annotations

import re

from clawseccheck.catalog import CRITICAL, FAIL, LOW, MEDIUM, PASS, WARN, Finding
from clawseccheck.layers import (
    LAYER_LIVE_BEHAVIOUR,
    LAYER_ORDER,
    LAYER_SELF_REPORT,
    STATUS_RAN,
    STATUS_UNAVAILABLE,
    LayerLedger,
    LayerState,
)
from clawseccheck.report import render_report
from clawseccheck.scoring import compute


def _f(fid: str, severity: str, status: str, *, scored: bool = True) -> Finding:
    return Finding(fid, f"check {fid}", severity, status, "detail", "fix", "framework",
                   scored=scored)


# One scored FAIL, one scored WARN, and two ADVISORY WARNs. The advisory pair is the
# whole point: they are displayed as issues but excluded from the score, which is the
# exact shape that made the real run's header 15 short.
FINDINGS = [
    _f("B1", CRITICAL, FAIL),
    _f("B2", MEDIUM, WARN),
    _f("B3", MEDIUM, WARN, scored=False),
    _f("B4", LOW, WARN, scored=False),
    _f("B5", LOW, PASS),
]

# What the body must report, derived from the data rather than restated as a literal so
# the two can never drift apart in this file.
_EXPECTED_ISSUES = sum(1 for f in FINDINGS if f.status in (FAIL, WARN))


def _graded():
    return compute(FINDINGS,
                   ledger=LayerLedger(states={ln: LayerState(status=STATUS_RAN)
                                              for ln in LAYER_ORDER}))


def _ungraded():
    states = {ln: LayerState(status=STATUS_RAN) for ln in LAYER_ORDER}
    states[LAYER_SELF_REPORT] = LayerState(status=STATUS_UNAVAILABLE)
    states[LAYER_LIVE_BEHAVIOUR] = LayerState(status=STATUS_UNAVAILABLE)
    return compute(FINDINGS, ledger=LayerLedger(states=states))


# Tolerant of how the dash renders under --ascii and of the severity list contents.
_TALLY_RE = re.compile(r"^\((\d+) FAIL, (\d+) WARN\D+incl\.\s*(.+)\)$", re.M)
_BODY_RE = re.compile(r"^(\d+) issue\(s\), grouped by subject", re.M)


def _tally(out: str) -> tuple[int, int, dict]:
    m = _TALLY_RE.search(out)
    assert m, f"the header tally line disappeared from the report:\n{out[:600]}"
    sev = {}
    for part in m.group(3).split(","):
        n, name = part.strip().split(" ", 1)
        sev[name.strip()] = int(n)
    return int(m.group(1)), int(m.group(2)), sev


def _body_count(out: str) -> int:
    m = _BODY_RE.search(out)
    assert m, f"the body issue count disappeared from the report:\n{out[:600]}"
    return int(m.group(1))


# ── the contract, on both grade states ───────────────────────────────────────

def test_ungraded_header_tally_equals_the_body_it_heads():
    """The run that exposed this: no score explanation, so no qualifier anywhere near."""
    out = render_report(FINDINGS, _ungraded(), ascii_only=True, color=False)
    n_fail, n_warn, _ = _tally(out)
    assert _body_count(out) == _EXPECTED_ISSUES
    assert n_fail + n_warn == _EXPECTED_ISSUES, (
        f"header says {n_fail} FAIL + {n_warn} WARN = {n_fail + n_warn}, body says "
        f"{_body_count(out)} issue(s) — a summary must not contradict its own list")


def test_graded_header_tally_equals_the_body_it_heads():
    """Same contract on the graded path — the fix must not hold only where it was found."""
    out = render_report(FINDINGS, _graded(), ascii_only=True, color=False)
    n_fail, n_warn, _ = _tally(out)
    assert n_fail + n_warn == _EXPECTED_ISSUES == _body_count(out)


def test_advisory_warnings_are_counted_as_issues():
    """`scored=False` means "does not move the score", not "is not an issue".

    Stated separately from the totals above because this is the actual defect: on the
    real config the dropped set was C015, B14, B164, B68 and eleven more — all of them
    printed in the body, none of them in the header count.
    """
    out = render_report(FINDINGS, _ungraded(), ascii_only=True, color=False)
    _, n_warn, _ = _tally(out)
    advisory = sum(1 for f in FINDINGS if f.status == WARN and not f.scored)
    assert advisory == 2, "fixture drifted; this test would no longer prove anything"
    assert n_warn == 3, (
        f"header counted {n_warn} WARN; 2 of the 3 are advisory and were the ones lost")


def test_severity_breakdown_sums_to_the_headline_total():
    """The "incl. …" clause must decompose the number in front of it, not a subset."""
    for score in (_ungraded(), _graded()):
        out = render_report(FINDINGS, score, ascii_only=True, color=False)
        n_fail, n_warn, sev = _tally(out)
        assert sum(sev.values()) == n_fail + n_warn, (
            f"severity parts {sev} do not add up to {n_fail + n_warn}")
        assert sev.get(MEDIUM) == 2, f"MEDIUM undercounted: {sev}"
        assert sev.get(LOW) == 1, f"LOW undercounted: {sev}"


# ── what the fix must not disturb ────────────────────────────────────────────

def test_the_why_line_keeps_the_scored_denominator():
    """The score explanation must stay reconcilable with `raw_score`.

    Widening the tally must not widen this: its counts feed an arithmetic the reader is
    invited to redo, and advisory findings carry no weight in it. It states its own
    narrower denominator, which is why the two numbers can legitimately differ.
    """
    out = render_report(FINDINGS, _graded(), ascii_only=True, color=False)
    m = re.search(r"from (\d+) pass, (\d+) warn, (\d+) fail", out)
    assert m, "the 'Why N/100' breakdown disappeared"
    n_pass, n_warn, n_fail = (int(g) for g in m.groups())
    scored = [f for f in FINDINGS if f.scored]
    assert n_pass == sum(1 for f in scored if f.status == PASS)
    assert n_warn == sum(1 for f in scored if f.status == WARN) == 1
    assert n_fail == sum(1 for f in scored if f.status == FAIL)
    assert "advisory checks are excluded" in out, (
        "the sentence that licenses the narrower denominator is what keeps the two "
        "different numbers honest; it must survive")


def test_suppressed_findings_stay_out_of_both_counts():
    """The body excludes suppressed findings; the header must exclude exactly the same."""
    findings = list(FINDINGS) + [
        Finding("B9", "check B9", CRITICAL, WARN, "d", "f", "fw", suppressed=True)]
    out = render_report(findings, _ungraded(), ascii_only=True, color=False)
    n_fail, n_warn, sev = _tally(out)
    assert n_fail + n_warn == _EXPECTED_ISSUES == _body_count(out), (
        "a suppressed finding leaked into the header tally")
    assert sev.get(CRITICAL) == 1, f"suppressed CRITICAL leaked into the breakdown: {sev}"
