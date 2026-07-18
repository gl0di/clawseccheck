"""Brand consistency across the 8 terminal/chat header renderers.

report.py used to hand-roll its mascot/separator per function, so the same brand
drifted three ways within one file (a literal ``" - "``, ``"—"`` and ``" · "`` all
appeared as "the" separator, `render_monitor` never got the mascot at all, and
`render_card`'s seal used a stray 🔍 instead of the 🦞 mascot). This file pins that
every header-producing spot in report.py / menu.py / palette.py / history.py now
single-sources through :mod:`clawseccheck.brand` instead of a hand-rolled literal,
for both the non-ASCII and ``--ascii`` path.

These are TIER 1 surfaces (see brand.py's module docstring): plain text that reaches
every channel a skill's output is relayed over (terminal, web ControlUI, chat), so a
byte-exact match against :func:`brand.header` is the right bar — not a loose
substring check.

Offline, deterministic, stdlib only — no I/O, no network.
"""
from __future__ import annotations

import ast as _ast
from pathlib import Path as _Path

from clawseccheck import brand
from clawseccheck.catalog import CRITICAL, FAIL, Finding
from clawseccheck.history import render_trend
from clawseccheck.menu import render_menu, render_onboarding
from clawseccheck.palette import render_palette
from clawseccheck.report import render_card, render_dashboard, render_monitor, render_report
from clawseccheck.scoring import ScoreResult, compute


def _findings():
    return [Finding(id="B2", title="t", severity=CRITICAL, status=FAIL,
                     detail="d", fix="f", framework="Test")]


def _score() -> ScoreResult:
    return compute(_findings())


# ── render_report ─────────────────────────────────────────────────────────────

class TestRenderReportHeader:
    def test_header_matches_brand_header(self):
        out = render_report(_findings(), _score())
        assert out.splitlines()[0] == brand.header(subtitle="OpenClaw Security Audit")

    def test_ascii_header_matches_brand_header(self):
        out = render_report(_findings(), _score(), ascii_only=True)
        assert out.splitlines()[0] == brand.header(subtitle="OpenClaw Security Audit",
                                                     ascii_only=True)

    def test_ascii_never_carries_the_mascot(self):
        out = render_report(_findings(), _score(), ascii_only=True)
        assert brand.MASCOT not in out


# ── render_dashboard ──────────────────────────────────────────────────────────

class TestRenderDashboardHeader:
    def test_header_starts_with_the_brand_mascot_and_a_single_separator(self):
        # render_dashboard doesn't route the whole line through brand.header() — it
        # has its own noun ("OpenClaw Security Audit", not "ClawSecCheck") — but the
        # mascot and every separator inside the line must still be brand-sourced.
        out = render_dashboard(_findings(), _score())
        first = out.splitlines()[0]
        assert first.startswith(f"{brand.MASCOT} OpenClaw Security Audit")
        # Every separator inside the line is the ONE brand separator — never a
        # stray em-dash mixed in alongside the middle-dot.
        assert "—" not in first
        assert first.count(brand.SEPARATOR.strip()) >= 2

    def test_findings_rule_uses_the_brand_separator(self):
        out = render_dashboard(_findings(), _score())
        sep = brand.SEPARATOR.strip()
        assert f"{sep} Findings {sep}" in out
        assert "— Findings —" not in out

    def test_ascii_never_carries_the_mascot_or_unicode_separator(self):
        out = render_dashboard(_findings(), _score(), ascii_only=True)
        assert brand.MASCOT not in out
        assert brand.SEPARATOR.strip() not in out
        assert "—" not in out


# ── render_card ───────────────────────────────────────────────────────────────

class TestRenderCardHeader:
    def test_header_line_matches_brand_header(self):
        out = render_card(_score(), _findings())
        assert out.splitlines()[0] == brand.header()

    def test_seal_uses_the_brand_mascot_not_a_magnifier(self):
        out = render_card(_score(), _findings())
        assert brand.MASCOT in out.splitlines()[-2]  # the "audited by ClawSecCheck" line
        assert "🔍" not in out

    def test_ascii_never_carries_the_mascot(self):
        out = render_card(_score(), _findings(), ascii_only=True)
        assert brand.MASCOT not in out
        assert "🔍" not in out

    def test_box_stays_the_pinned_width_after_the_seal_swap(self):
        # The mascot swap (🔍 -> brand.MASCOT) must not shift the box's right edge.
        # By design the seal line (l3) is padded ONE character narrower than the
        # other two content lines, because the mascot/magnifier is double-width in
        # many terminals — that was true before this migration (see the inline
        # comment) and stays true after it; only the *character* changed.
        out = render_card(_score(), _findings())
        _header, top, l1, l2, l3, bot = out.splitlines()
        assert len(top) == len(bot) == len(l1) == len(l2)
        assert len(l3) == len(l1) - 1


# ── render_monitor ────────────────────────────────────────────────────────────

class TestRenderMonitorHeader:
    def test_header_matches_brand_header(self):
        out = render_monitor([], _score(), baseline=True)
        assert out.splitlines()[0] == brand.header(subtitle="Threat Monitor")

    def test_ascii_header_matches_brand_header(self):
        out = render_monitor([], _score(), ascii_only=True, baseline=True)
        assert out.splitlines()[0] == brand.header(subtitle="Threat Monitor", ascii_only=True)

    def test_now_carries_the_mascot_settled_design(self):
        # Settled design: render_monitor previously never showed the mascot at
        # all, even non-ASCII. It gains one now, like every other header-bearing
        # renderer.
        out = render_monitor([], _score(), baseline=True)
        assert out.startswith(brand.MASCOT)

    def test_ascii_never_carries_the_mascot(self):
        out = render_monitor([], _score(), ascii_only=True, baseline=True)
        assert brand.MASCOT not in out

    def test_rule_spans_the_mascot_header(self):
        # A hardcoded "=" * 30 rule under-ran the header once it grew the mascot
        # (display width 32, since MASCOT renders double-width): the "="-rule
        # stopped 2 columns short of the title on the line above it. The rule
        # must be at least as wide as the header's *display* width, not just its
        # Python character count.
        out = render_monitor([], _score(), baseline=True)
        header, rule = out.splitlines()[:2]
        display_width = len(header) + 1  # +1 for the double-width mascot column
        assert len(rule) >= display_width

    def test_ascii_rule_width_unchanged(self):
        # The --ascii rule width must stay exactly what it was before this fix
        # (no mascot => no under-run => no reason for the rule to move).
        out = render_monitor([], _score(), ascii_only=True, baseline=True)
        assert out.splitlines()[1] == "=" * 30


# ── menu: render_onboarding / render_menu ─────────────────────────────────────

class TestMenuHeaders:
    def test_onboarding_header_matches_brand_header(self):
        out = render_onboarding(reason="missing", home="~/.openclaw")
        assert out.splitlines()[0] == brand.header(subtitle="welcome")

    def test_onboarding_ascii_header_matches_brand_header(self):
        out = render_onboarding(reason="missing", home="~/.openclaw", ascii_only=True)
        assert out.splitlines()[0] == brand.header(subtitle="welcome", ascii_only=True)

    def test_menu_header_matches_brand_header(self):
        out = render_menu(version="9.9.9")
        assert out.splitlines()[0] == brand.header(subtitle="v9.9.9")

    def test_menu_ascii_header_matches_brand_header(self):
        out = render_menu(version="9.9.9", ascii_only=True)
        assert out.splitlines()[0] == brand.header(subtitle="v9.9.9", ascii_only=True)


# ── render_palette ────────────────────────────────────────────────────────────

class TestPaletteHeader:
    def test_header_matches_brand_header(self):
        out = render_palette()
        assert out.splitlines()[0] == brand.header(subtitle="everything it can do")

    def test_ascii_header_matches_brand_header(self):
        out = render_palette(ascii_only=True)
        assert out.splitlines()[0] == brand.header(subtitle="everything it can do",
                                                     ascii_only=True)


# ── render_trend ──────────────────────────────────────────────────────────────

class TestTrendHeader:
    def test_header_matches_brand_header(self):
        rows = [{"date": "2026-06-15", "score": 72, "grade": "C"}]
        out = render_trend(rows)
        assert out.splitlines()[0] == brand.header(subtitle="Score Trend")

    def test_ascii_header_matches_brand_header(self):
        rows = [{"date": "2026-06-15", "score": 72, "grade": "C"}]
        out = render_trend(rows, ascii_only=True)
        assert out.splitlines()[0] == brand.header(subtitle="Score Trend", ascii_only=True)

    def test_wordmark_no_longer_repeats(self):
        # The bug this fixes: two separate header lines both carrying "ClawSecCheck"
        # ("🦞 ClawSecCheck" then "ClawSecCheck - Score Trend") collapsed to one.
        rows = [{"date": "2026-06-15", "score": 72, "grade": "C"}]
        out = render_trend(rows)
        assert out.count(brand.WORDMARK) == 1


# ── --ascii never renders the mascot, across all 8 ────────────────────────────

def test_ascii_drops_the_mascot_everywhere():
    """Regression guard: --ascii must never leak brand.MASCOT, for any of the 8
    renderers this task touches."""
    score = _score()
    findings = _findings()
    outputs = [
        render_report(findings, score, ascii_only=True),
        render_dashboard(findings, score, ascii_only=True),
        render_card(score, findings, ascii_only=True),
        render_monitor([], score, ascii_only=True, baseline=True),
        render_onboarding(reason="missing", home="~/.openclaw", ascii_only=True),
        render_menu(version="9.9.9", ascii_only=True),
        render_palette(ascii_only=True),
        render_trend([{"date": "2026-06-15", "score": 72, "grade": "C"}], ascii_only=True),
    ]
    for out in outputs:
        assert brand.MASCOT not in out


# ─────────────────────────────────────────────────────────────────────────────
# Source-level brand lock.
#
# The per-renderer tests above check RENDERED OUTPUT, so they only cover the
# renderers that existed when they were written — a new renderer added tomorrow
# with a hardcoded mascot would pass every one of them. These assert the
# invariant at the source level instead: brand values live in brand.py and
# nowhere else.
#
# Prose is exempt on purpose. Comments and docstrings legitimately discuss the
# mascot (several explain the very bug this epic fixed), so the lock inspects
# real string VALUES via ast rather than grepping lines — a grep cannot tell a
# literal apart from a sentence about it.
# ─────────────────────────────────────────────────────────────────────────────

_PKG = _Path(__file__).resolve().parents[1] / "clawseccheck"

# menu.py's magnifier is a FUNCTIONAL action icon for the "Check everything" menu
# entry (the magnifier means "inspect"), not a brand mark. It is the one allowed
# use; anywhere else a magnifier is the old brand drift returning.
_MAGNIFIER_ALLOWED = {"menu.py"}


def _value_strings(path):
    """Every string literal that is a real value — docstrings excluded."""
    tree = _ast.parse(path.read_text(encoding="utf-8"))
    docstrings = set()
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.Module, _ast.ClassDef, _ast.FunctionDef, _ast.AsyncFunctionDef)):
            body = getattr(node, "body", None)
            if body and isinstance(body[0], _ast.Expr) and isinstance(body[0].value, _ast.Constant) \
                    and isinstance(body[0].value.value, str):
                docstrings.add(id(body[0].value))
    return [
        n.value for n in _ast.walk(tree)
        if isinstance(n, _ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings
    ]


def _package_modules():
    return sorted(p for p in _PKG.rglob("*.py") if "__pycache__" not in p.parts)


def test_the_mascot_has_exactly_one_home():
    offenders = []
    for path in _package_modules():
        if path.name == "brand.py":
            continue
        if any(brand.MASCOT in s for s in _value_strings(path)):
            offenders.append(str(path.relative_to(_PKG)))
    assert not offenders, (
        "the mascot is hardcoded outside brand.py — import brand.MASCOT (or "
        f"brand.header()) instead: {offenders}"
    )


def test_the_wordmark_has_exactly_one_home():
    offenders = []
    for path in _package_modules():
        if path.name == "brand.py":
            continue
        for s in _value_strings(path):
            # A bare wordmark literal is drift. Longer sentences that merely contain
            # the product name (report prose, remediation text) are not what this guards.
            if s.strip() == brand.WORDMARK:
                offenders.append(f"{path.relative_to(_PKG)}: {s!r}")
    assert not offenders, (
        "the wordmark is hardcoded outside brand.py — import brand.WORDMARK: " + str(offenders)
    )


def test_the_magnifier_never_returns_as_a_brand_mark():
    offenders = []
    for path in _package_modules():
        if path.name in _MAGNIFIER_ALLOWED:
            continue
        if any("\U0001F50D" in s for s in _value_strings(path)):
            offenders.append(str(path.relative_to(_PKG)))
    assert not offenders, (
        "a magnifier glyph is back in a shipped string — the brand mark is the mascot; "
        f"only {sorted(_MAGNIFIER_ALLOWED)} may use it, as a functional action icon: {offenders}"
    )


def test_no_module_keeps_its_own_grade_colour_ramp():
    """The B-234 shadow bug in one assertion.

    report.py once defined `_GRADE_COLOR` twice — ANSI names, then hex — so the
    second silently shadowed the first and the terminal grade lost its colour.
    Any module-level dict mapping grade letters to colours, outside brand.py, is
    that bug waiting to happen again.
    """
    grades = {"A", "B", "C", "D", "F"}
    offenders = []
    for path in _package_modules():
        if path.name == "brand.py":
            continue
        tree = _ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:  # module level only
            if not isinstance(node, (_ast.Assign, _ast.AnnAssign)):
                continue
            value = node.value
            if not isinstance(value, _ast.Dict):
                continue
            keys = {k.value for k in value.keys
                    if isinstance(k, _ast.Constant) and isinstance(k.value, str)}
            if keys and keys <= grades and len(keys) >= 3:
                targets = node.targets if isinstance(node, _ast.Assign) else [node.target]
                names = [t.id for t in targets if isinstance(t, _ast.Name)]
                offenders.append(f"{path.relative_to(_PKG)}: {names or '<dict>'}")
    assert not offenders, (
        "a grade->colour ramp is defined outside brand.py — use brand.grade_ansi() "
        f"or brand.grade_hex(): {offenders}"
    )
