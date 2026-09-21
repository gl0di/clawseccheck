"""C-571 — a run-level banner when the installed OpenClaw is newer than any check in this
build was actually grounded against.

B363's B-833 fix (checks/_shared.py::_cross_context_default) proved the hazard: the
`tools.message.crossContext.allowAcrossProviders` config PATH and its declared schema
default/enum never moved between OpenClaw 2026.9.4 and 2026.9.5 — only the vendor's
RESOLVER LINE did (`=== true` -> `!== false`) — so nothing short of executing the vendor
caught it, and B363 silently PASSed the newly-dangerous default until that fix landed.
That fix covers the one flip that WAS found, entirely inside one check. There was no
audit-level signal that the report as a whole was produced by a build grounded against an
older OpenClaw than the one actually installed — which is the general case of the same
hazard, for the next flip, in some check with no version-aware branch at all.

`openclawdist.grounding_gap` / `GROUNDED_MAX_VERSION` supply that signal; `render_report`
surfaces it as a disclosure line, ahead of everything else, that never touches score/grade.

Offline, read-only, stdlib only — no dist is read; the installed build is injected
through `Context.installed_dist_version`, exactly as test_b502_version_rollback.py and
test_b833_cross_context_default_flip.py already do.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import CRITICAL, PASS, Finding
from clawseccheck.collector import Context
from clawseccheck.openclawdist import GROUNDED_MAX_VERSION, grounding_gap
from clawseccheck.report import render_report
from clawseccheck.scoring import compute

_GROUNDED_STR = ".".join(str(p) for p in GROUNDED_MAX_VERSION)


# ── the pure function ─────────────────────────────────────────────────────────────────

class TestGroundingGap:
    @pytest.mark.parametrize("installed", [
        None,
        "",
        "2026.9.5",     # exactly the grounded ceiling -> no gap
        "2026.9.4",     # older -> no gap
        "2026.7.1-2",   # much older -> no gap
        "2026.9.5-1",   # a correction release of the grounded build -> still no gap
        "2026.9",       # too short to be a calendar release -> unknown, not a gap
        "0.0.0",        # not a calendar release either
        "2026.9.6-rc1", # pre-release token -> unorderable, never a fabricated gap
        123,            # not even a string
    ])
    def test_no_gap_reported(self, installed):
        assert grounding_gap(installed) is None

    @pytest.mark.parametrize("installed, expected", [
        ("2026.9.6", (2026, 9, 6)),
        ("2026.10.1", (2026, 10, 1)),
        ("2027.1.1", (2027, 1, 1)),
        ("2026.9.6-1", (2026, 9, 6)),   # a correction release of a NEWER build still gaps
    ])
    def test_gap_reported_when_strictly_newer(self, installed, expected):
        assert grounding_gap(installed) == expected


# ── the report banner ────────────────────────────────────────────────────────────────

_FINDINGS = [Finding("B1", "Lethal trifecta reachable", CRITICAL, PASS,
                      "detail", "fix", "framework")]


def _ctx(installed_dist_version=None):
    return Context(home=Path("/nonexistent"), installed_dist_version=installed_dist_version)


def _report(installed_dist_version):
    ctx = _ctx(installed_dist_version)
    score = compute(_FINDINGS, ctx=ctx)
    return render_report(_FINDINGS, score, ascii_only=True, color=False, ctx=ctx)


class TestGroundingBanner:
    def test_fires_when_installed_is_newer_than_grounded(self):
        text = _report("2026.9.6")
        assert f"grounded against OpenClaw up to {_GROUNDED_STR}" in text
        assert "you are running 2026.9.6" in text
        assert "may be mis-grounded" in text

    def test_silent_when_installed_equals_the_grounded_ceiling(self):
        text = _report(_GROUNDED_STR)
        assert "grounded against OpenClaw up to" not in text

    def test_silent_when_installed_is_older(self):
        text = _report("2026.7.1-2")
        assert "grounded against OpenClaw up to" not in text

    def test_silent_when_installed_is_unknown(self):
        text = _report(None)
        assert "grounded against OpenClaw up to" not in text

    def test_never_touches_score_or_grade(self):
        stale = _ctx("2026.9.6")
        current = _ctx("2026.9.5")
        score_stale = compute(_FINDINGS, ctx=stale)
        score_current = compute(_FINDINGS, ctx=current)
        assert score_stale.score == score_current.score
        assert score_stale.grade == score_current.grade
        assert score_stale.capped == score_current.capped

    def test_does_not_claim_to_name_affected_checks(self):
        """The banner must not invent a specific check list/count — B363's own fix shows
        the affected set is not soundly enumerable (no schema-path diff catches the
        hazard, only executing the vendor does)."""
        text = _report("2026.9.6")
        line = next(ln for ln in text.splitlines() if "grounded against OpenClaw" in ln)
        assert "checks may be mis-grounded" not in line  # no fabricated "N checks"
