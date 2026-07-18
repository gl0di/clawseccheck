"""Tests for clawseccheck.brand — the single source of brand truth (F-129).

This module is the FOUNDATION six sibling brand-unification tasks build on, so the
load-bearing job of this test file is pinning the exact public API surface (names,
shapes, values) those siblings will import — not exercising every renderer that will
eventually consume it (report.py/menu.py/palette.py/history.py migrations are
separate, later changes).

Offline, stdlib only, read-only — no writes anywhere, nothing outside tmp_path.
"""
from __future__ import annotations

import re
# stdlib xml.etree is used to parse ONLY clawseccheck.brand.LOGO_SVG, a small
# hardcoded string constant this repo authors and ships — never external/attacker-
# controlled input, so the usual XXE / billion-laughs stdlib-parser risk does not
# apply here. `defusedxml` is a third-party dependency and CLAUDE.md §1 forbids
# adding one (stdlib only, even for dev/test code beyond pytest/ruff).
import xml.etree.ElementTree as ET

import clawseccheck.brand as brand


# ── Tier 1: seen everywhere (text) ───────────────────────────────────────────

class TestMascotAndWordmark:
    def test_mascot_is_the_claw_emoji(self):
        assert brand.MASCOT == "🦞"

    def test_wordmark_is_exact(self):
        assert brand.WORDMARK == "ClawSecCheck"

    def test_separators(self):
        assert brand.SEPARATOR == " · "
        assert brand.ASCII_SEPARATOR == " - "


class TestHeader:
    def test_bare_header_no_subtitle(self):
        assert brand.header() == f"{brand.MASCOT} {brand.WORDMARK}"

    def test_header_with_subtitle_uses_the_brand_separator(self):
        out = brand.header("v9.9.9")
        assert out == f"{brand.MASCOT} {brand.WORDMARK}{brand.SEPARATOR}v9.9.9"
        assert out == "🦞 ClawSecCheck · v9.9.9"

    def test_ascii_header_drops_mascot_and_folds_separator(self):
        out = brand.header("v9.9.9", ascii_only=True)
        assert out == f"{brand.WORDMARK}{brand.ASCII_SEPARATOR}v9.9.9"
        assert brand.MASCOT not in out
        out.encode("ascii")  # must round-trip as pure ASCII

    def test_ascii_bare_header_is_just_the_wordmark(self):
        assert brand.header(ascii_only=True) == brand.WORDMARK

    def test_header_is_single_sourced_from_the_constants(self):
        # A future edit that hardcodes a literal instead of the constants breaks
        # this the moment MASCOT/WORDMARK/SEPARATOR change — that's the point.
        saved_mascot, saved_wordmark, saved_sep = brand.MASCOT, brand.WORDMARK, brand.SEPARATOR
        try:
            brand.MASCOT, brand.WORDMARK, brand.SEPARATOR = "X", "Y", "|"
            assert brand.header("z") == "X Y|z"
        finally:
            brand.MASCOT, brand.WORDMARK, brand.SEPARATOR = saved_mascot, saved_wordmark, saved_sep


class TestFrame:
    def test_returns_three_lines(self):
        lines = brand.frame("label")
        assert len(lines) == 3

    def test_open_on_the_right_no_closing_border(self):
        top, mid, bot = brand.frame("🌐 Exposure & Network — 1 issue(s)")
        assert top.startswith("┌") and not top.endswith("┐")
        assert bot.startswith("└") and not bot.endswith("┘")
        assert mid.startswith("│ 🌐 Exposure & Network — 1 issue(s)")
        assert not mid.rstrip().endswith("│", 1)  # no right-hand pipe either

    def test_default_width_matches_existing_renderers(self):
        top, _mid, bot = brand.frame("x")
        assert top == "┌" + "─" * brand.FRAME_WIDTH
        assert bot == "└" + "─" * brand.FRAME_WIDTH

    def test_width_is_overridable(self):
        top, _mid, bot = brand.frame("x", width=10)
        assert top == "┌" + "─" * 10
        assert bot == "└" + "─" * 10


# ── Tier 2 / 3: colour palette ────────────────────────────────────────────────

_HEX_RE = re.compile(r"^#[0-9a-fA-F]{3}$|^#[0-9a-fA-F]{6}$")
_GRADES = ("A", "B", "C", "D", "F")


class TestGradeColour:
    def test_grade_hex_covers_every_grade(self):
        assert set(brand.GRADE_HEX) == set(_GRADES)
        for grade, value in brand.GRADE_HEX.items():
            assert _HEX_RE.match(value), f"{grade} -> {value!r} is not a valid hex colour"

    def test_grade_ansi_covers_every_grade(self):
        assert set(brand.GRADE_ANSI) == set(_GRADES)
        # Every ANSI name must be one ansi.py's palette actually knows (paint()
        # silently drops unknown style names, so a typo here would be silent).
        from clawseccheck.ansi import _CODES
        for grade, name in brand.GRADE_ANSI.items():
            assert name in _CODES, f"{grade} -> {name!r} is not a known ansi.py style"

    def test_grade_hex_and_grade_ansi_are_never_the_same_dict(self):
        # The original report.py bug: two colour maps sharing one name, so the
        # second (hex) silently shadowed the first (ansi names). Pin them apart.
        assert brand.GRADE_HEX is not brand.GRADE_ANSI
        assert brand.GRADE_HEX != brand.GRADE_ANSI

    def test_grade_hex_accessor_normalizes_and_falls_back(self):
        assert brand.grade_hex("A") == brand.GRADE_HEX["A"]
        assert brand.grade_hex("A+") == brand.GRADE_HEX["A"]
        assert brand.grade_hex("b-") == brand.GRADE_HEX["B"]
        assert brand.grade_hex("nonsense") == brand._DEFAULT_HEX
        assert brand.grade_hex("") == brand._DEFAULT_HEX
        assert brand.grade_hex(None) == brand._DEFAULT_HEX

    def test_grade_ansi_accessor_normalizes_and_falls_back(self):
        assert brand.grade_ansi("F") == brand.GRADE_ANSI["F"]
        assert brand.grade_ansi("f") == brand.GRADE_ANSI["F"]
        assert brand.grade_ansi("D-") == brand.GRADE_ANSI["D"]
        assert brand.grade_ansi("?") == brand._DEFAULT_ANSI
        assert brand.grade_ansi(None) == brand._DEFAULT_ANSI


class TestBrandRed:
    def test_is_a_valid_hex_colour(self):
        assert brand.BRAND_RED == "#e34234"
        assert _HEX_RE.match(brand.BRAND_RED)


class TestSeverity:
    def test_severity_style_is_a_frozen_dataclass(self):
        style = brand.SeverityStyle(glyph="x", ansi="red", hex="#000")
        assert style.glyph == "x" and style.ansi == "red" and style.hex == "#000"
        try:
            style.glyph = "y"
        except Exception:
            pass
        else:
            raise AssertionError("SeverityStyle must be frozen (immutable)")

    def test_severity_covers_the_four_levels(self):
        assert set(brand.SEVERITY) == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    def test_severity_glyphs_match_the_design_system_legend(self):
        assert brand.SEVERITY["CRITICAL"].glyph == "🔴"
        assert brand.SEVERITY["HIGH"].glyph == "🟠"
        assert brand.SEVERITY["MEDIUM"].glyph == "🟡"
        assert brand.SEVERITY["LOW"].glyph == "⚪"

    def test_severity_colours_are_derived_from_the_grade_ramp_not_hand_duplicated(self):
        # Each severity rides one grade band: CRITICAL=F, HIGH=D, MEDIUM=C, LOW=B.
        # These are the values report.py rendered before the brand migration, so the
        # single-sourcing must not silently recolour anyone's existing report.
        # by equality to the SAME source dicts so the two can't silently drift.
        assert brand.SEVERITY["CRITICAL"].ansi == brand.GRADE_ANSI["F"]
        assert brand.SEVERITY["CRITICAL"].hex == brand.GRADE_HEX["F"]
        assert brand.SEVERITY["HIGH"].ansi == brand.GRADE_ANSI["D"]
        assert brand.SEVERITY["HIGH"].hex == brand.GRADE_HEX["D"]
        assert brand.SEVERITY["MEDIUM"].ansi == brand.GRADE_ANSI["C"]
        assert brand.SEVERITY["MEDIUM"].hex == brand.GRADE_HEX["C"]

    def test_every_severity_style_field_is_the_right_type(self):
        for name, style in brand.SEVERITY.items():
            assert isinstance(style, brand.SeverityStyle), name
            assert isinstance(style.glyph, str) and style.glyph
            assert isinstance(style.ansi, str) and style.ansi
            assert _HEX_RE.match(style.hex), f"{name}.hex = {style.hex!r}"


# ── Tier 3: the graphical mark ────────────────────────────────────────────────

class TestLogoSvg:
    def test_is_a_non_empty_string(self):
        assert isinstance(brand.LOGO_SVG, str)
        assert brand.LOGO_SVG.strip()

    def test_is_well_formed_xml(self):
        root = ET.fromstring(brand.LOGO_SVG)
        assert root.tag.endswith("svg")

    def test_has_a_viewbox_and_no_hardcoded_huge_size(self):
        root = ET.fromstring(brand.LOGO_SVG)
        assert root.get("viewBox")

    def test_carries_no_external_references(self):
        # Self-contained, matching the --html export's "no external assets" rule
        # (docs/design-system.md Component 11): no href/src/xlink:href anywhere,
        # and the only "http" text allowed is the required SVG XML namespace URI.
        assert "xlink:href" not in brand.LOGO_SVG
        assert " href=" not in brand.LOGO_SVG
        assert " src=" not in brand.LOGO_SVG
        occurrences = [m.start() for m in re.finditer("http", brand.LOGO_SVG)]
        for pos in occurrences:
            assert brand.LOGO_SVG[pos:pos + len("http://www.w3.org")] == "http://www.w3.org", (
                "unexpected network-shaped reference in LOGO_SVG"
            )

    def test_uses_the_brand_red_accent(self):
        assert brand.BRAND_RED in brand.LOGO_SVG

    def test_has_an_accessible_label(self):
        root = ET.fromstring(brand.LOGO_SVG)
        assert root.get("role") == "img"
        assert root.get("aria-label")


# ── Module shape (Layer 1 leaf: no cycles, stdlib only) ──────────────────────

class TestLeafContract:
    def test_brand_imports_nothing_from_clawseccheck(self):
        import ast
        from pathlib import Path

        src = Path(brand.__file__).read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert node.module is None or "clawseccheck" not in (node.module or ""), (
                    f"brand.py must not import from clawseccheck (found: {node.module})"
                )
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert "clawseccheck" not in alias.name, (
                        f"brand.py must not import clawseccheck (found: {alias.name})"
                    )

    def test_exported_from_the_package_root(self):
        import clawseccheck

        assert "brand" in clawseccheck.__all__
        assert clawseccheck.brand is brand


# ── Full API surface pin (what the six dependent tasks import) ───────────────

_EXPECTED_PUBLIC_NAMES = {
    "MASCOT", "WORDMARK", "SEPARATOR", "ASCII_SEPARATOR", "FRAME_WIDTH",
    "header", "frame",
    "GRADE_HEX", "GRADE_ANSI", "grade_hex", "grade_ansi",
    "BRAND_RED", "SeverityStyle", "SEVERITY",
    "LOGO_SVG",
}


def test_expected_public_names_all_exist():
    missing = [n for n in _EXPECTED_PUBLIC_NAMES if not hasattr(brand, n)]
    assert not missing, f"brand.py is missing expected public name(s): {missing}"


def test_no_undocumented_shrink_of_the_public_surface():
    # One-directional like tests/checks_public_api.txt's guard: this only fails if
    # a name the pinned set expects disappears, never when a new one is added.
    live_public = {n for n in dir(brand) if not n.startswith("_")}
    missing = _EXPECTED_PUBLIC_NAMES - live_public
    assert not missing, f"public API shrank, missing: {missing}"
