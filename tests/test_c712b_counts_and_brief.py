"""C-712 items 1 and 8: the dashboard card reconciles its own issue count, and `--brief`
says whose monitor has not run.

Item 1. The header said "38 issues" while the subject blocks listed 28, with nothing
saying where the other 10 were. The 10 are the lower-confidence (MEDIUM / ATTESTED)
FAIL/WARN findings: `render_dashboard_findings` leaves them out of the subject blocks by
design, `--full` shows them under "Worth a glance" (6 under --compact, which a budget cut
usually removes), and the default card names only the top few. Nothing was wrong with
the number - it counts every non-suppressed FAIL/WARN - but a reader could not tell. These
tests pin the arithmetic: the header count is exactly the sum of the parts the card names,
and each part is read back from what the renderer printed or from the same filter lists
the renderer uses, never from a second tally.

Item 8. "Monitoring is effectively not running" read as a statement about the machine. The
evidence is ClawSecCheck's own monitor journal; a run with --no-history, or another tool,
leaves no trace there. Only the sentence changes: the ladder, the alert and the exit code
do not.

Offline and deterministic: fixtures only, no network.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.catalog import CRITICAL, FAIL, HIGH, LOW, MEDIUM, WARN, Finding
from clawseccheck.dedup import deduplicate_findings
from clawseccheck.report import (
    _glance_qualifying_findings,
    render_brief,
    render_dashboard,
)
from clawseccheck.scoring import compute

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
_BUDGET = 4096

_HEADER_RE = re.compile(r"(\d+) issues?(?: \((\d+) high-confidence, (\d+) lower-confidence[^)]*\))?")
_FAMILY_RE = re.compile(r"^│ .+ — (\d+) issue\(s\)$", re.M)
_POINTER_RE = re.compile(
    r"\(\+(\d+) more findings? not named above — (?:(\d+) high-confidence)?"
    r"(?:, )?(?:(\d+) lower-confidence)?;")


def _f(id_, status, severity=HIGH, **kw):
    return Finding(id=id_, title=f"title {id_}", severity=severity, status=status,
                   detail=f"detail {id_}", fix=f"fix {id_}", framework="Test", **kw)


def _mixed(n_high: int, n_low: int) -> list:
    """n_high high-confidence and n_low lower-confidence FAIL/WARN findings."""
    out = [_f(f"H{i}", FAIL if i % 2 else WARN, CRITICAL if i % 3 == 0 else HIGH)
           for i in range(n_high)]
    out += [_f(f"L{i}", WARN, MEDIUM, confidence=MEDIUM) for i in range(n_low)]
    return out


def _header_line(out: str) -> str:
    # The issue count sits on the line that carries "issue" before the first section frame.
    for ln in out.splitlines():
        if _HEADER_RE.search(ln):
            return ln
    raise AssertionError("no header line with an issue count:\n" + out[:600])


def _header_counts(out: str):
    m = _HEADER_RE.search(_header_line(out))
    n = int(m.group(1))
    h = int(m.group(2)) if m.group(2) is not None else None
    low = int(m.group(3)) if m.group(3) is not None else None
    return n, h, low


# --------------------------------------------------------------------------- item 1

@pytest.mark.parametrize("compact", [False, True])
@pytest.mark.parametrize("ascii_only", [False, True])
def test_full_card_header_reconciles_with_the_subject_blocks(compact, ascii_only):
    findings = _mixed(9, 5)
    out = render_dashboard(findings, compute(findings), full=True, compact=compact,
                           ascii_only=ascii_only)
    n, h, low = _header_counts(out)
    assert n == 14
    assert (h, low) == (9, 5)
    assert n == h + low
    if not ascii_only:
        # What the card actually printed: the family headers add up to the high-confidence part.
        assert sum(int(x) for x in _FAMILY_RE.findall(out)) == h
    # The lower-confidence part is the renderer's own filter list, not a second tally.
    assert low == len(_glance_qualifying_findings(deduplicate_findings(findings)))


def test_full_card_clause_says_where_the_rest_is():
    findings = _mixed(4, 3)
    plain = render_dashboard(findings, compute(findings), full=True)
    assert "listed further down" in _header_line(plain)
    compact = render_dashboard(findings, compute(findings), full=True, compact=True)
    assert "full report" in _header_line(compact)


def test_full_card_clause_does_not_overclaim_past_the_glance_limit():
    findings = _mixed(3, 15)
    out = render_dashboard(findings, compute(findings), full=True)
    line = _header_line(out)
    n, h, low = _header_counts(out)
    assert (n, h, low) == (18, 3, 15)
    assert "12 listed further down, the rest in the full report" in line, line
    assert "(+3 more)" in out  # the glance section's own overflow marker agrees


def test_no_lower_confidence_means_no_clause_and_an_unchanged_header():
    findings = _mixed(6, 0)
    for compact in (False, True):
        out = render_dashboard(findings, compute(findings), full=True, compact=compact)
        line = _header_line(out)
        assert "6 issues" in line
        assert "high-confidence" not in line and "lower-confidence" not in line
    plain = render_dashboard(findings, compute(findings))
    assert "high-confidence" not in plain and "lower-confidence" not in plain


def test_ungraded_header_gets_the_same_clause():
    findings = _mixed(2, 2)
    score = compute(findings)
    score.graded = False
    out = render_dashboard(findings, score, full=True)
    n, h, low = _header_counts(out)
    assert (n, h, low) == (4, 2, 2)


def test_default_card_pointer_names_each_remainder():
    # 8 high-confidence findings, the card names at most 5; 4 lower-confidence never appear.
    findings = _mixed(8, 4)
    out = render_dashboard(findings, compute(findings))
    n, h, low = _header_counts(out)
    assert n == 12 and h is None, "the default card keeps its plain header"
    m = _POINTER_RE.search(out)
    assert m, out
    more, high_more, lower = int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0)
    named = out.split("· Most urgent ·")[1].split("\n\n")[0].strip().splitlines()
    assert n == len(named) + high_more + lower
    assert more == high_more + lower
    assert lower == 4


def test_default_card_pointer_is_unchanged_without_lower_confidence():
    findings = _mixed(8, 0)
    out = render_dashboard(findings, compute(findings))
    assert "(+3 more findings not named above — the full list is in the report.)" in out


def test_pdf_card_does_not_claim_blocks_it_does_not_print():
    # --full with a PDF renders the overview card, not the subject blocks: the header must not
    # promise "high-confidence" blocks below, the pointer carries the reconciliation instead.
    findings = _mixed(7, 3)
    out = render_dashboard(findings, compute(findings), full=True, pdf_path="/x/report.pdf")
    assert _header_counts(out)[1] is None
    assert _POINTER_RE.search(out)


@pytest.mark.parametrize("home", ["home_safe", "home_vuln"])
def test_fixture_cards_reconcile_in_every_shape(home):
    ctx, findings, score = audit(home=FIXTURES / home)
    deduped = deduplicate_findings(findings)
    low_n = len(_glance_qualifying_findings(deduped))

    # default card: header == named + each remainder
    plain = render_dashboard(findings, score, ctx=ctx)
    n, _h, _l = _header_counts(plain)
    named_block = plain.split("· Most urgent ·")
    named = len(named_block[1].split("\n\n")[0].strip().splitlines()) if len(named_block) > 1 else 0
    m = _POINTER_RE.search(plain)
    rest = int(m.group(1)) if m else 0
    assert n == named + rest
    if m and low_n:
        assert int(m.group(3) or 0) == low_n

    for compact in (False, True):
        full = render_dashboard(findings, score, ctx=ctx, full=True, compact=compact)
        n, h, low = _header_counts(full)
        if low_n:
            assert (h, low) == (n - low_n, low_n), full[:500]
        else:
            assert h is None
        if not compact and h is not None:
            assert sum(int(x) for x in _FAMILY_RE.findall(full)) == h
        if compact:
            assert len(full) <= _BUDGET, len(full)


def test_compact_clause_is_dropped_rather_than_cost_the_card_a_line():
    # Sweep the card size across the budget edge: the split is substituted into the header
    # only while the whole card still fits, so the length never exceeds the budget, the
    # count is always the plain one when the clause is absent, and both outcomes occur.
    seen_with, seen_without = False, False
    for n_high in range(20, 90):
        findings = _mixed(n_high, 3)
        out = render_dashboard(findings, compute(findings), full=True, compact=True)
        assert len(out) <= _BUDGET, (n_high, len(out))
        n, h, low = _header_counts(out)
        assert n == n_high + 3
        if h is None:
            seen_without = True
            assert "high-confidence, " not in _header_line(out)
        else:
            seen_with = True
            assert (h, low) == (n_high, 3)
    assert seen_with and seen_without


def test_compact_clause_only_replaces_the_header_phrase():
    findings = _mixed(5, 3)
    out = render_dashboard(findings, compute(findings), full=True, compact=True)
    n, h, low = _header_counts(out)
    assert (n, h, low) == (8, 5, 3)
    assert len(out) <= _BUDGET
    # Everything but the header phrase is what the plain card prints.
    plain = out.replace(" (5 high-confidence, 3 lower-confidence: see the full report)", "", 1)
    assert "high-confidence" not in plain and plain.count("8 issues") == 1


# --------------------------------------------------------------------------- item 8

_NOW = datetime(2026, 8, 11, 12, 0, 0)


def _iso(days_ago: float) -> str:
    return (_NOW - timedelta(days=days_ago)).isoformat()


def test_brief_names_clawseccheck_own_monitor_not_monitoring_in_general():
    out = render_brief({"ts": _iso(29)}, [], [], now=_NOW)
    assert "ClawSecCheck's own monitor" in out
    assert "29 days" in out
    assert "--no-history" in out
    assert "another tool" in out
    assert "effectively not running" not in out
    assert "nothing has checked this setup" not in out
    assert "Monitoring is" not in out
    # The advice that survived: stopping the schedule is the cheap way to silence a monitor.
    assert "cheapest way to silence a monitor" in out


def test_brief_ladder_and_silence_are_unchanged():
    # Same boundaries, same silence for a fresh check, same stale-but-not-dead sentence.
    assert render_brief({"ts": _iso(0.02)}, [], [], now=_NOW) == ""
    stale = render_brief({"ts": _iso(5)}, [], [], now=_NOW)
    assert "longer than" in stale and "ClawSecCheck's own monitor" not in stale
    assert "ClawSecCheck's own monitor" in render_brief({"ts": _iso(14.5)}, [], [], now=_NOW)
    assert "ClawSecCheck's own monitor" not in render_brief({"ts": _iso(13.5)}, [], [], now=_NOW)


def test_brief_dead_tier_still_counts_as_a_finding_for_the_exit_code():
    # `--brief --exit-code` keys on the rendered text being non-empty; the sentence moved,
    # the tier did not.
    assert render_brief({"ts": _iso(20)}, [], [], now=_NOW) != ""


def test_low_severity_noise_is_not_counted_as_lower_confidence():
    # LOW severity with HIGH confidence belongs to the subject blocks, not the remainder.
    findings = [_f("L1", WARN, LOW), _f("M1", WARN, MEDIUM, confidence=MEDIUM)]
    out = render_dashboard(findings, compute(findings), full=True)
    assert _header_counts(out)[:3] == (2, 1, 1)
