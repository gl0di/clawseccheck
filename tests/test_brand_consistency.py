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

Beyond the per-renderer header checks, this file carries three more locks:

* **the manifest icon** — SKILL.md's ``metadata.openclaw.emoji`` is the very first
  brand surface a user sees (ClawHub, the OpenClaw skill list) and nothing else in
  the suite pinned it, so reverting it to a magnifier used to pass every test;
* **the hand-rolled-header lock** — a source-level guard that sees a header built
  by hand instead of through :func:`brand.header`, which the earlier
  ``s.strip() == brand.WORDMARK`` guard sailed straight past. It reads each
  string-producing *expression*, not just plain literals, so a header ASSEMBLED by
  interpolation or concatenation (``f"{brand.WORDMARK} - New Screen"``) is caught
  too — that shape is the likeliest drift now that every header-rendering module
  imports ``brand``, and a literal-only scan is structurally blind to it;
* **the voice invariants** — design-system.md Layer 0 ("plain language always —
  never internal codes; calm, not alarmist; local · read-only · nothing leaves
  your machine") asserted over RENDERED output from a real audit, not over a grep
  of the sources.

Offline, deterministic, stdlib only — no I/O beyond reading the repo's own files
and the checked-in fixtures, no network.
"""
from __future__ import annotations

import ast as _ast
import json as _json
import re as _re
from pathlib import Path as _Path

from clawseccheck import audit, brand
from clawseccheck.catalog import BY_ID, CRITICAL, FAIL, Finding
from clawseccheck.dedup import deduplicate_findings
from clawseccheck.guide import render_next_actions, suggest_actions
from clawseccheck.history import render_trend
from clawseccheck.menu import render_menu, render_onboarding
from clawseccheck.palette import render_palette
from clawseccheck.report import (
    render_card,
    render_dashboard,
    render_html,
    render_monitor,
    render_report,
    render_subject_inventory,
)
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


# ─────────────────────────────────────────────────────────────────────────────
# The hand-rolled-header lock.
#
# `test_the_wordmark_has_exactly_one_home` above only catches a literal that IS
# exactly the wordmark, so any LONGER hand-rolled header sailed past it — which
# is precisely how three live CLI surfaces (--canary / --redteam / --dryrun) kept
# shipping "ClawSecCheck - <subtitle>", with the ASCII hyphen this campaign
# unified away and no mascot, long after every other renderer had migrated.
#
# The shape that matters is "wordmark, then a separator, then a subtitle": that is
# a header, and a header must come from brand.header(). A literal that merely
# STARTS with the product name and continues in prose is not
# ("ClawSecCheck audits an OpenClaw setup...", argparse's "ClawSecCheck OpenClaw
# security self-audit (read-only).", the HTML title "ClawSecCheck Security Audit
# Report"), so requiring the separator is what keeps this guard off real prose.
# ─────────────────────────────────────────────────────────────────────────────

# The separators a header line can plausibly use: both brand ones, plus the
# em/en-dash, colon and pipe that hand-rolled headers have drifted to before.
_HEADER_SEPARATORS = "".join(sorted({
    brand.SEPARATOR.strip(), brand.ASCII_SEPARATOR.strip(), "—", "–", ":", "|",
}))

# The separator must carry whitespace on at least one side. brand.header() always
# emits one (" · " / " - "), and so did every hand-rolled header this task
# migrated, so requiring it costs no detection — while a wordmark welded straight
# onto its next character is a slug, not a header ("ClawSecCheck-report.html",
# "ClawSecCheck-v3.53.0"), and those used to trip this guard spuriously.
#
# Known residual: a colon-prefixed sentence ("ClawSecCheck: nothing to do.") still
# matches, because a space after the colon is exactly what a colon header has too.
# Separating them needs a capitalisation/word-count heuristic, which would be a
# fragile condition guarding a string that does not exist in the package today —
# left alone deliberately rather than traded for a real blind spot.
_HAND_ROLLED_HEADER_RE = _re.compile(
    r"^\s*(?:{mascot}\s*)?{wordmark}(?:\s+[{seps}]|[{seps}]\s)".format(
        mascot=_re.escape(brand.MASCOT),
        wordmark=_re.escape(brand.WORDMARK),
        seps=_re.escape(_HEADER_SEPARATORS),
    )
)

# ── Seeing a header that is ASSEMBLED rather than written out ────────────────
#
# Matching the regex against plain `ast.Constant` literals only would lock the
# single least likely shape. Every module that renders a header now imports
# `brand`, so `brand.WORDMARK` is in scope exactly where a header gets written —
# which makes `f"{brand.WORDMARK} - New Screen"` the MOST ergonomic way to drift,
# and a literal-only scan is structurally blind to it. Verified before this was
# added: of the five natural drift shapes, only the plain literal was caught.
#
# So each string-producing expression is rebuilt from its parts, with `brand.X`
# references resolved to their real values, and the regex runs over THAT.

# What an expression splices in that cannot be known at parse time (a variable, a
# call, a number). NUL is deliberate: no wordmark, mascot or separator pattern can
# match it, so an unresolvable piece can never manufacture a hit.
_UNRESOLVED = "\x00"

# A `str.format()` replacement field. Only used to fill a template in argument
# order — enough to see `"{} - New Screen".format(brand.WORDMARK)`.
_FORMAT_FIELD_RE = _re.compile(r"\{[^{}]*\}")


def _brand_reference(node):
    """The value behind `brand.WORDMARK` / a bare `WORDMARK` import, else None."""
    if isinstance(node, _ast.Attribute) and isinstance(node.value, _ast.Name) \
            and node.value.id == "brand":
        name = node.attr
    elif isinstance(node, _ast.Name):
        name = node.id
    else:
        return None
    if not name.isupper():
        return None
    value = getattr(brand, name, None)
    return value if isinstance(value, str) else None


def _render_expression(node) -> str:
    """The string an expression evaluates to, as far as source alone can tell."""
    resolved = _brand_reference(node)
    if resolved is not None:
        return resolved
    if isinstance(node, _ast.Constant):
        return node.value if isinstance(node.value, str) else _UNRESOLVED
    if isinstance(node, _ast.JoinedStr):  # an f-string
        return "".join(_render_expression(v) for v in node.values)
    if isinstance(node, _ast.FormattedValue):  # one {...} inside an f-string
        return _render_expression(node.value)
    if isinstance(node, _ast.BinOp) and isinstance(node.op, _ast.Add):  # "a" + b
        return _render_expression(node.left) + _render_expression(node.right)
    if isinstance(node, _ast.Call) and isinstance(node.func, _ast.Attribute) \
            and node.func.attr == "format":
        filler = iter([_render_expression(a) for a in node.args])
        return _FORMAT_FIELD_RE.sub(
            lambda _m: next(filler, _UNRESOLVED), _render_expression(node.func.value)
        )
    return _UNRESOLVED


def _assembled_strings_from_source(src: str) -> list:
    """Every string an expression in *src* can produce — docstrings excluded.

    Composite nodes are rendered whole AND their parts are rendered on their own
    (an `ast.walk` sees both), which is harmless: a fragment can only match if it
    already carries the wordmark and a separator, in which case it is drift too.
    """
    tree = _ast.parse(src)
    docstrings = set()
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.Module, _ast.ClassDef, _ast.FunctionDef, _ast.AsyncFunctionDef)):
            body = getattr(node, "body", None)
            if body and isinstance(body[0], _ast.Expr) and isinstance(body[0].value, _ast.Constant) \
                    and isinstance(body[0].value.value, str):
                docstrings.add(id(body[0].value))
    return [
        _render_expression(n) for n in _ast.walk(tree)
        if isinstance(n, (_ast.Constant, _ast.JoinedStr, _ast.BinOp, _ast.Call))
        and id(n) not in docstrings
    ]


def _hand_rolled_headers_in_source(src: str) -> list:
    """The hand-rolled brand headers *src* contains, deduplicated and ordered."""
    seen = []
    for s in _assembled_strings_from_source(src):
        if _HAND_ROLLED_HEADER_RE.match(s) and s not in seen:
            seen.append(s)
    return seen


def test_no_module_hand_rolls_a_brand_header():
    offenders = []
    for path in _package_modules():
        if path.name == "brand.py":
            continue
        for s in _hand_rolled_headers_in_source(path.read_text(encoding="utf-8")):
            offenders.append(f"{path.relative_to(_PKG)}: {s!r}")
    assert not offenders, (
        "a brand header is built by hand instead of through brand.header() — that is how "
        "the separator/mascot drifts back in one renderer at a time: " + str(offenders)
    )


def test_the_header_lock_recognizes_the_shape_it_replaced():
    """The guard above is only worth having if it still matches the real drift.

    Pinned through the SAME extractor the guard uses, over synthetic module
    SOURCE — not against runtime strings. An f-string written in a test is already
    an ordinary string by the time it is compared, so matching one would certify
    the regex against a shape the source scan can never encounter, and read as
    coverage of the interpolated case while providing none. Every case below is
    real Python text, parsed exactly as a shipped module is.
    """
    drifted = [
        '_t = "ClawSecCheck - active canary self-test"',   # was canary.render_canary
        '_t = "ClawSecCheck - Live Red-Team Suite v1"',    # was redteam.render_suite
        '_t = "ClawSecCheck - Runtime Dry-Run Harness"',   # was dryrun.render_dryrun
        '_t = f"{brand.MASCOT} {brand.WORDMARK} · Some New Screen"',
        '_t = f"{brand.WORDMARK} — Some New Screen"',
        '_t = f"{brand.WORDMARK}: Some New Screen"',
        '_t = brand.WORDMARK + " - Some New Screen"',
        '_t = brand.WORDMARK + brand.SEPARATOR + "Some New Screen"',
        '_t = "{} - Some New Screen".format(brand.WORDMARK)',
        '_t = f"{MASCOT} {WORDMARK} | Some New Screen"',   # `from .brand import ...` style
    ]
    for src in drifted:
        assert _hand_rolled_headers_in_source(src), f"the lock no longer sees drift: {src!r}"

    prose = [
        '_t = "ClawSecCheck OpenClaw security self-audit (read-only)."',
        '_t = "ClawSecCheck Security Audit Report"',
        '_t = "ClawSecCheck audits an OpenClaw setup for security holes'
        ' — I just need to find yours:"',
        '_t = "Generated locally by ClawSecCheck · read-only'
        ' · this report never leaves your machine"',
        '_t = f"A newer {brand.WORDMARK} is available: v{latest}"',
        '_t = "Nothing to purge — no ClawSecCheck local store files found."',
        # The migrated shape itself must stay invisible, or the guard would flag
        # the very call it exists to push authors towards.
        '_t = brand.header("Some New Screen", ascii_only=ascii_only)',
        '_t = brand.header("Some New Screen") + (" 🧪" if not ascii_only else "")',
        # A wordmark welded onto the next character is a slug, not a header.
        '_t = "ClawSecCheck-report.html"',
        '_t = "ClawSecCheck-v3.53.0"',
        '_t = f"{brand.WORDMARK}-{version}.html"',
    ]
    for src in prose:
        assert not _hand_rolled_headers_in_source(src), f"the lock fires on real prose: {src!r}"


# ─────────────────────────────────────────────────────────────────────────────
# SKILL.md manifest parity.
#
# metadata.openclaw.emoji is the FIRST brand surface a user meets — ClawHub's
# listing and the OpenClaw skill picker read it, and no renderer is involved. It
# was the one brand value nothing in the suite pinned, so reverting it to the old
# magnifier passed the whole suite silently.
# ─────────────────────────────────────────────────────────────────────────────

_SKILL_MD = _Path(__file__).resolve().parents[1] / "SKILL.md"


def _skill_frontmatter_metadata() -> dict:
    """Return SKILL.md's frontmatter ``metadata:`` value, parsed as JSON.

    Every failure mode reports what is actually wrong with the manifest instead of
    surfacing as a bare KeyError/JSONDecodeError traceback — a broken manifest is
    a shipping problem, and the test output should say so in one line.
    """
    lines = _SKILL_MD.read_text(encoding="utf-8").splitlines()
    assert lines and lines[0].strip() == "---", (
        f"{_SKILL_MD.name} does not open with a YAML frontmatter fence ('---'); "
        "ClawHub reads the skill's name/version/metadata from it"
    )
    try:
        end = lines.index("---", 1)
    except ValueError:
        raise AssertionError(
            f"{_SKILL_MD.name} frontmatter is never closed by a '---' line"
        ) from None

    raw = None
    for line in lines[1:end]:
        if line.startswith("metadata:"):
            raw = line[len("metadata:"):].strip()
            break
    assert raw, (
        f"{_SKILL_MD.name} frontmatter has no single-line 'metadata:' key holding a JSON "
        "object — that is where the skill's icon, display name and tags live"
    )

    try:
        meta = _json.loads(raw)
    except ValueError as exc:
        raise AssertionError(
            f"{_SKILL_MD.name} 'metadata:' is not parsable JSON ({exc}); it starts {raw[:60]!r}"
        ) from None
    assert isinstance(meta, dict), (
        f"{_SKILL_MD.name} 'metadata:' parsed as {type(meta).__name__}, not a JSON object"
    )
    return meta


def test_skill_manifest_metadata_is_parsable():
    assert _skill_frontmatter_metadata()  # the readable-failure path, exercised


def test_skill_manifest_icon_is_the_brand_mascot():
    meta = _skill_frontmatter_metadata()
    openclaw = meta.get("openclaw")
    assert isinstance(openclaw, dict), (
        f"{_SKILL_MD.name} metadata has no 'openclaw' object (got {openclaw!r}) — the "
        "skill's icon is read from metadata.openclaw.emoji"
    )
    assert "emoji" in openclaw, (
        f"{_SKILL_MD.name} metadata.openclaw has no 'emoji' key — the skill would list "
        "with no brand icon at all"
    )
    assert openclaw["emoji"] == brand.MASCOT, (
        f"{_SKILL_MD.name} metadata.openclaw.emoji is {openclaw['emoji']!r}, not the brand "
        f"mascot {brand.MASCOT!r} — this is the first brand surface a user sees"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Voice invariants, over RENDERED output.
#
# design-system.md Layer 0 states the voice contract: "plain language always —
# never internal codes (`B2 FAIL`); describe the real risk in one sentence. Calm,
# not alarmist. Lead with the law: local · read-only · nothing leaves your
# machine." A grep of the sources cannot check any of that — the strings are
# assembled at render time — so these run the REAL renderers over a REAL audit of
# the deliberately-vulnerable fixture home and assert over what comes out.
# ─────────────────────────────────────────────────────────────────────────────

_FIXTURES = _Path(__file__).resolve().parents[1] / "fixtures"

# Hype templates. Deliberately multi-word: the bare words "urgent" and
# "compromised" are CALM, correct security vocabulary and appear in shipped
# doctrine text (attest.py, catalog.py, risk.py, guide.py, report.py). Banning
# them would fail the build on perfectly good prose. What the doctrine forbids is
# the marketing-alarm register, which is what these phrasings are.
BANNED_PHRASES = (
    "act now",
    "act immediately",
    "immediate action required",
    "urgent action required",
    "do not ignore",
    "critical alert",
)

# Shouting = a RUN of consecutive all-caps words, not a single one: FAIL / WARN /
# CRITICAL / MCP / TLS are legitimate labels and acronyms. Four is the threshold
# because three has a real, benign occurrence — report.py's "== INVENTORY BY
# SUBJECT" section rule — and a guard that fires on a settled section label is a
# false positive, not a lock. Letters only (no digits/underscores) so an env-var
# roster like "AWS_SECRET_ACCESS_KEY OPENAI_API_KEY GITHUB_TOKEN" can never trip it.
_SHOUTED_RUN_RE = _re.compile(r"\b[A-Z]{2,}(?:[ ,]+[A-Z]{2,}){3,}\b")

# Stacked exclamation marks. A SINGLE "!" is not banned: render_monitor's ASCII
# severity mark is literally "[!]", and a remediation snippet may legitimately
# contain one (`[ ! -f x ]`, `!=`). Two in a row is unambiguously shouting.
_MULTI_BANG_RE = _re.compile(r"!{2,}")

# Built from the catalog, never hardcoded: the real prefixes are A/B/C/T (A1, B15,
# C032, T1), so a hardcoded "[A-B]\d+" would miss C032 and T1 outright and would
# not grow when a new prefix is introduced.
_CHECK_ID_RE = _re.compile(
    r"\b(" + "|".join(_re.escape(i) for i in sorted(BY_ID, key=len, reverse=True)) + r")\b"
)

_HTML_DROP_RE = _re.compile(r"<(script|style)\b.*?</\1>", _re.S | _re.I)
_HTML_TAG_RE = _re.compile(r"<[^>]+>")


def _visible_text(html: str) -> str:
    """The prose a reader actually sees — markup, CSS and scripts removed.

    Without this the HTML export trips every guard on its own plumbing:
    ``<!doctype html>`` alone would read as an exclamation mark.
    """
    return _HTML_TAG_RE.sub(" ", _HTML_DROP_RE.sub(" ", html))


def _audit_fixture():
    """A real audit of the vulnerable fixture home — read-only, offline, no network.

    Real findings matter here: the voice invariants must hold over the prose the
    checks themselves emit (detail/fix text), not over strings a test invented.
    """
    return audit(home=str(_FIXTURES / "home_vuln"))


def _owner_facing_surfaces(ctx, findings, score) -> dict:
    return {
        "render_report": render_report(findings, score, ctx=ctx),
        "render_report --ascii": render_report(findings, score, ascii_only=True, ctx=ctx),
        "render_dashboard": render_dashboard(findings, score),
        "render_card": render_card(score, findings),
        "render_monitor": render_monitor([("HIGH", "a check changed")], score),
        "render_html": _visible_text(render_html(findings, score)),
        # A standalone CLI surface in its own right (`--next`, and appended to the
        # default run), so the voice contract has to hold over it too.
        "render_next_actions": render_next_actions(suggest_actions(findings, score)),
    }


class TestVoiceNeverLeaksInternalCodes:
    """"never internal codes (`B2 FAIL`)" — design-system.md Layer 0."""

    def test_check_ids_never_leak_outside_the_subject_inventory_index(self):
        ctx, findings, score = _audit_fixture()
        # The ONE deliberate exception: the by-subject inventory index (v3.52.0)
        # is a compact roster whose whole job is to name each check, so its lines
        # are allowed to carry the id. Allowing exactly those LINES — recomputed
        # from the same renderer — keeps the exception from spreading anywhere else.
        deduped = deduplicate_findings(findings)
        allowed = {
            line
            for mode in (False, True)
            for line in render_subject_inventory(deduped, ctx, ascii_only=mode).splitlines()
            if _CHECK_ID_RE.search(line)
        }
        offenders = []
        for name, text in _owner_facing_surfaces(ctx, findings, score).items():
            for line in text.splitlines():
                if _CHECK_ID_RE.search(line) and line not in allowed:
                    offenders.append(f"{name}: {line.strip()!r}")
        assert not offenders, (
            "an internal check id reached owner-facing output — say what the risk is, not "
            f"which check number found it: {offenders[:8]}"
        )

    def test_the_inventory_exception_is_real_and_narrow(self):
        """Keeps the allowance above honest in both directions.

        If the inventory ever stopped emitting ids the allowance would be vacuous
        and nobody would notice; if the rest of the report started emitting them,
        dropping ctx would no longer produce id-free output.
        """
        ctx, findings, score = _audit_fixture()
        assert _CHECK_ID_RE.search(render_report(findings, score, ctx=ctx)), \
            "the subject-inventory index no longer carries check ids — the allowance is vacuous"
        assert not _CHECK_ID_RE.search(render_report(findings, score)), \
            "the report body (no inventory index) leaks check ids into owner-facing prose"


class TestVoiceIsCalmNotAlarmist:
    """"Calm, not alarmist" — design-system.md Layer 0."""

    def test_no_surface_shouts_in_all_caps(self):
        ctx, findings, score = _audit_fixture()
        offenders = [
            f"{name}: {run!r}"
            for name, text in _owner_facing_surfaces(ctx, findings, score).items()
            for run in _SHOUTED_RUN_RE.findall(text)
        ]
        assert not offenders, (
            "owner-facing output shouts in all caps — the voice is calm; state the risk in "
            f"sentence case: {offenders[:8]}"
        )

    def test_no_surface_stacks_exclamation_marks(self):
        ctx, findings, score = _audit_fixture()
        offenders = [
            name
            for name, text in _owner_facing_surfaces(ctx, findings, score).items()
            if _MULTI_BANG_RE.search(text)
        ]
        assert not offenders, (
            f"owner-facing output stacks exclamation marks — that is alarm, not information: "
            f"{offenders}"
        )

    def test_no_surface_uses_a_hype_template(self):
        ctx, findings, score = _audit_fixture()
        offenders = [
            f"{name}: {phrase!r}"
            for name, text in _owner_facing_surfaces(ctx, findings, score).items()
            for phrase in BANNED_PHRASES
            if phrase in text.lower()
        ]
        assert not offenders, (
            "owner-facing output uses a marketing-alarm phrasing — describe the real risk in "
            f"one sentence instead: {offenders}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# The local-only disclaimer, verbatim.
#
# "Lead with the law: local · read-only · nothing leaves your machine" is the
# single most load-bearing sentence the tool says about itself — an HTML report a
# user forwards is exactly where that promise has to travel with it. Pinned as a
# literal, on purpose: this is a regression lock on the exact words, so rewording
# is a deliberate act rather than an accident.
# ─────────────────────────────────────────────────────────────────────────────

HTML_FOOTER_DISCLAIMER = (
    "Generated locally by ClawSecCheck · read-only · this report never leaves your machine"
)


def test_html_report_carries_the_verbatim_local_only_disclaimer():
    ctx, findings, score = _audit_fixture()
    html = render_html(findings, score)
    assert HTML_FOOTER_DISCLAIMER in html, (
        "the --html export lost (or reworded) its local-only footer; that promise is the "
        f"first thing the report has to say about itself: expected {HTML_FOOTER_DISCLAIMER!r}"
    )
