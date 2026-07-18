"""Terminal Dashboard render (C-102): score-bar, coverage map, opt-in ANSI colour.

All tests are offline, deterministic and write nothing outside pytest's tmp — the
renderers are pure string builders over in-memory findings.
"""
from __future__ import annotations

from clawseccheck.ansi import _CODES, paint, should_color, strip_ansi
from clawseccheck.catalog import BY_ID, FAIL, HIGH, LOW, MEDIUM, PASS, UNKNOWN, WARN, Finding
from clawseccheck.report import _coverage_lines, _grade_color, _score_bar, render_report
from clawseccheck.scoring import ScoreResult

_ESC = "\x1b["


# ── Helpers ───────────────────────────────────────────────────────────────────

class _FakeStream:
    def __init__(self, tty: bool):
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def _score(**kw) -> ScoreResult:
    defaults = dict(score=49, grade="F", capped=False, raw_score=49,
                    failed_critical=0, failed_high=0)
    defaults.update(kw)
    return ScoreResult(**defaults)


def _finding(id_: str, status: str, severity: str = HIGH) -> Finding:
    return Finding(id=id_, title=f"Check {id_}", severity=severity, status=status,
                   detail=f"detail {id_}", fix=f"fix {id_}", framework="Test")


def _findings() -> list[Finding]:
    real_id = next(iter(BY_ID))  # a real catalog id → at least one 'checked' surface
    return [
        _finding(real_id, PASS, LOW),
        _finding("T2", FAIL, HIGH),
        _finding("T3", WARN, MEDIUM),
        _finding("T4", UNKNOWN, LOW),
    ]


# ── ansi.should_color ─────────────────────────────────────────────────────────

class TestShouldColor:
    def test_no_color_flag_wins(self):
        assert should_color(no_color_flag=True, stream=_FakeStream(True), env={}) is False

    def test_no_color_env_disables_even_when_empty(self):
        # no-color.org: presence disables regardless of value.
        assert should_color(stream=_FakeStream(True), env={"NO_COLOR": ""}) is False

    def test_no_color_env_beats_force_color(self):
        assert should_color(stream=_FakeStream(True),
                            env={"NO_COLOR": "1", "FORCE_COLOR": "1"}) is False

    def test_force_color_enables_without_tty(self):
        assert should_color(stream=_FakeStream(False), env={"FORCE_COLOR": "1"}) is True

    def test_tty_enables(self):
        assert should_color(stream=_FakeStream(True), env={}) is True

    def test_non_tty_disables(self):
        assert should_color(stream=_FakeStream(False), env={}) is False


# ── ansi.paint / strip_ansi ─────────────────────────────────────────────────

class TestPaint:
    def test_paint_wraps_and_resets(self):
        assert paint("x", "red") == f"{_ESC}31mx{_ESC}0m"

    def test_disabled_is_noop(self):
        assert paint("x", "red", enabled=False) == "x"

    def test_empty_text_is_noop(self):
        assert paint("", "red") == ""

    def test_no_style_is_noop(self):
        assert paint("x") == "x"

    def test_unknown_style_dropped(self):
        assert paint("x", "bogus") == "x"

    def test_strip_ansi_roundtrip(self):
        colored = paint("hello", "green", "bold")
        assert _ESC in colored
        assert strip_ansi(colored) == "hello"


# ── grade colour (C-241: single-sourced from brand.GRADE_ANSI) ────────────────

class TestGradeColor:
    def test_returns_a_known_ansi_style_name_not_a_hex_string(self):
        # Regression for the report.py `_GRADE_COLOR` shadow bug (see brand.py's
        # module docstring): the ansi-name dict must win, never the hex dict a
        # second definition used to silently replace it with.
        for grade in ("A", "B", "C", "D", "F"):
            color = _grade_color(grade)
            assert color in _CODES, f"_grade_color({grade!r}) = {color!r} is not a known ansi.py style"
            assert not color.startswith("#"), f"_grade_color({grade!r}) leaked a hex colour: {color!r}"

    def test_matches_brand_grade_ansi(self):
        from clawseccheck import brand
        for grade in ("A", "B", "C", "D", "F"):
            assert _grade_color(grade) == brand.grade_ansi(grade)


# ── score bar ─────────────────────────────────────────────────────────────────

class TestScoreBar:
    def test_unicode_proportion(self):
        # 50/100 of 16 cells = 8 filled, 8 empty.
        bar = _score_bar(50, "C")
        assert bar.count("█") == 8
        assert bar.count("░") == 8

    def test_ascii_form_and_clamp(self):
        assert _score_bar(100, "A", ascii_only=True) == "[" + "#" * 16 + "]"
        assert _score_bar(0, "F", ascii_only=True) == "[" + "-" * 16 + "]"

    def test_ascii_has_no_unicode(self):
        assert _score_bar(49, "F", ascii_only=True).isascii()

    def test_color_wraps_fill(self):
        plain = _score_bar(49, "F")
        colored = _score_bar(49, "F", color=True)
        assert _ESC in colored
        assert strip_ansi(colored) == plain  # colour is purely additive

    def test_fill_run_itself_is_coloured_not_just_the_empty_run(self):
        # C-241 regression: report.py used to define `_GRADE_COLOR` twice under the
        # same name — ANSI colour names, then (later in the file) hex codes for the
        # HTML/SVG badge — so the second definition silently shadowed the first and
        # `_grade_color()` always returned a hex string like "#e05d44". paint() drops
        # any style name it doesn't recognise (ansi._CODES has no hex keys), so the
        # FILL run rendered with no colour at all. The prior `test_color_wraps_fill`
        # above didn't catch this: `empty_s` is separately painted "grey" (always a
        # valid ansi.py name), so `_ESC in colored` was already true from the *empty*
        # run alone. This test isolates the fill run specifically.
        colored = _score_bar(49, "F", color=True)
        fill_run = colored.split("\x1b[90m", 1)[0]  # everything before the grey empty run
        assert _ESC in fill_run, f"the filled portion of the score bar carries no colour: {colored!r}"


# ── coverage map ──────────────────────────────────────────────────────────────

class TestCoverageLines:
    def test_header_and_counts_present(self):
        lines = _coverage_lines(_findings())
        text = "\n".join(lines)
        assert "Coverage of OpenClaw surfaces" in text
        assert "checked" in text and "partial" in text
        assert "of 13 config surfaces" in text

    def test_not_checkable_names_listed(self):
        text = "\n".join(_coverage_lines(_findings()))
        # grounded, static names from coverage._NOT_CHECKABLE
        assert "egress" in text
        assert "not-checkable" in text

    def test_ascii_is_pure_ascii(self):
        text = "\n".join(_coverage_lines(_findings(), ascii_only=True))
        assert text.isascii()

    def test_color_is_strippable_to_plain(self):
        plain = "\n".join(_coverage_lines(_findings()))
        colored = "\n".join(_coverage_lines(_findings(), color=True))
        assert _ESC in colored
        assert strip_ansi(colored) == plain


# ── render_report integration ────────────────────────────────────────────────

class TestRenderReportColor:
    def test_score_bar_and_coverage_appear(self):
        out = render_report(_findings(), _score())
        assert "Coverage of OpenClaw surfaces" in out
        assert "█" in out or "░" in out  # score bar rendered

    def test_color_off_has_no_escape_codes(self):
        out = render_report(_findings(), _score(), color=False)
        assert _ESC not in out

    def test_color_on_emits_escape_codes(self):
        out = render_report(_findings(), _score(), color=True)
        assert _ESC in out

    def test_color_is_additive_only(self):
        # Stripping colour from the coloured render must equal the plain render.
        plain = render_report(_findings(), _score(), color=False)
        colored = render_report(_findings(), _score(), color=True)
        assert strip_ansi(colored) == plain

    def test_ascii_no_color_is_pure_ascii(self):
        out = render_report(_findings(), _score(), ascii_only=True, color=False)
        assert out.isascii()

    def test_no_color_default(self):
        # The default (no color kwarg) must never colourise — protects piped output.
        assert _ESC not in render_report(_findings(), _score())
