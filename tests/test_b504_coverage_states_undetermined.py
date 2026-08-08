"""B-504 — the coverage block must count checks, not only surfaces.

`— Coverage of OpenClaw surfaces —` counts SURFACES, and a surface counts as
"checked" the moment one of its checks returns any verdict. On the maintainer's own
config that printed:

    ✅ checked 14 · ◑ partial/unknown 0  (of 14 config surfaces)

while 25 of 100 scored checks — 18 of them HIGH — had reached no verdict at all.

The gap is not cosmetic. `scoring.compute` drops UNKNOWN from the denominator, so
an undetermined HIGH check is indistinguishable from a PASS in the final number:
18 checks that could not look cost the grade nothing. Two earlier audits named this
class and it kept shipping, because nothing in an ordinary run's output made it
visible — the pre-existing loud caution only fires below 35% assessable, and this
run sat at 75%.

What this module does NOT do, deliberately: it does not assert any cap or grade
change. Capping on unknown density moves grades on real configs and needs its own
adversarial review and false-positive gate. This is disclosure only, which cannot
create a false FAIL.

Stdlib-only, offline, writes nothing.
"""
from __future__ import annotations

import re

from clawseccheck.catalog import CATALOG, FAIL, HIGH, LOW, MEDIUM, PASS, UNKNOWN, Finding
from clawseccheck.report import _coverage_lines

_IDS = [m.id for m in CATALOG][:40]


def _f(fid: str, severity: str, status: str, *, scored: bool = True) -> Finding:
    return Finding(fid, f"seeded {fid}", severity, status,
                   "detail", "fix", "framework", scored=scored)


def _line(lines, needle: str):
    return next((ln for ln in lines if needle in ln), None)


def test_undetermined_scored_checks_are_stated_on_every_run():
    """The headline defect: a quarter of the catalog undetermined, and silent."""
    findings = ([_f(_IDS[i], LOW, PASS) for i in range(10)]
                + [_f(_IDS[10 + i], HIGH, UNKNOWN) for i in range(5)])
    lines = _coverage_lines(findings, ascii_only=True, color=False)
    stated = _line(lines, "scored checks reached a verdict")
    assert stated is not None, (
        "no checks-level coverage line — the block states only surfaces, which is "
        f"exactly the defect: {lines!r}")
    assert "10 of 15" in stated, stated
    assert "5 did not" in stated, stated
    assert "5 HIGH or worse" in stated, stated


def test_the_severity_of_what_was_missed_is_named():
    """18 undetermined HIGH checks is a different fact from 18 undetermined LOWs."""
    findings = ([_f(_IDS[i], LOW, PASS) for i in range(3)]
                + [_f(_IDS[3], HIGH, UNKNOWN), _f(_IDS[4], LOW, UNKNOWN)])
    stated = _line(_coverage_lines(findings, ascii_only=True, color=False),
                   "scored checks reached a verdict")
    assert "2 did not (1 HIGH or worse)" in stated, stated


def test_no_severe_misses_omits_the_severity_tail():
    findings = [_f(_IDS[0], LOW, PASS), _f(_IDS[1], LOW, UNKNOWN)]
    stated = _line(_coverage_lines(findings, ascii_only=True, color=False),
                   "scored checks reached a verdict")
    assert "1 did not;" in stated, stated
    assert "HIGH or worse" not in stated, stated


def test_a_fully_determined_run_says_so_positively():
    """Disclosure must not become a permanent scare line."""
    findings = [_f(_IDS[i], MEDIUM, PASS if i % 2 else FAIL) for i in range(6)]
    stated = _line(_coverage_lines(findings, ascii_only=True, color=False),
                   "reached a verdict")
    assert stated is not None and "all 6 scored checks" in stated, stated
    assert "did not" not in stated, stated


def test_advisory_findings_are_excluded_from_the_denominator():
    """`scored=False` findings never reach the grade, so counting them would state a
    coverage figure that has nothing to do with the number it explains."""
    findings = ([_f(_IDS[0], LOW, PASS)]
                + [_f(_IDS[1 + i], HIGH, UNKNOWN, scored=False) for i in range(9)])
    stated = _line(_coverage_lines(findings, ascii_only=True, color=False),
                   "reached a verdict")
    assert "all 1 scored checks" in stated, stated


def test_the_surfaces_line_is_still_there():
    """The new line supplements the surface view; it does not replace it."""
    findings = [_f(_IDS[0], LOW, PASS), _f(_IDS[1], HIGH, UNKNOWN)]
    lines = _coverage_lines(findings, ascii_only=True, color=False)
    assert _line(lines, "config surfaces") is not None, lines


def test_the_two_lines_can_disagree_and_that_is_the_point():
    """A surface reports "checked" on one verdict while its other checks are blind.

    This is the exact shape that made "partial/unknown 0" true and useless: it is
    not a bug in the surface line, which is why the fix adds a second count rather
    than changing the first.
    """
    findings = [_f(_IDS[0], LOW, PASS)] + [_f(_IDS[1 + i], HIGH, UNKNOWN) for i in range(4)]
    lines = _coverage_lines(findings, ascii_only=True, color=False)
    surfaces = _line(lines, "config surfaces")
    checks = _line(lines, "scored checks reached a verdict")
    assert surfaces and checks
    # The surface line's own "partial" figure counts surfaces with NO verdict at all;
    # the checks line counts undetermined checks. Different numbers, both honest.
    m = re.search(r"partial/unknown (\d+)", surfaces)
    assert m, surfaces
    assert "4 did not" in checks, checks
