"""Guard tests for the SVG badge's mascot mark and the README banner's brand
grounding (CLAWSECCHECK-C-242 / epic E-048).

Two separate surfaces, one rule for both: colour and mascot must be traceable back
to clawseccheck.brand — never a second, independently hand-kept literal that could
silently drift from it.

Offline, stdlib only, read-only — no writes outside tmp_path.
"""
from __future__ import annotations

# stdlib xml.etree parses only render_svg()'s own output below — a string this repo
# generates internally from trusted ScoreResult/Finding objects, never
# attacker-controlled input, so the usual XXE / billion-laughs stdlib-parser risk
# does not apply (same reasoning as tests/test_brand.py's LOGO_SVG parsing).
# `defusedxml` is a third-party dependency; CLAUDE.md §1 forbids adding one.
import xml.etree.ElementTree as ET
from pathlib import Path

import clawseccheck.brand as brand
from clawseccheck import audit, render_svg
from clawseccheck.scoring import ScoreResult
from scripts.gen_banner import build_banner_html

REPO = Path(__file__).resolve().parents[1]
BANNER_PATH = REPO / "docs" / "assets" / "src" / "banner.html"
FIXTURES = REPO / "fixtures"


def _score(score: int = 80, grade: str = "B") -> ScoreResult:
    return ScoreResult(score=score, grade=grade, capped=False, raw_score=score,
                        failed_critical=0, failed_high=0)


# ── render_svg: the badge carries a mark sourced from brand.LOGO_SVG ─────────

class TestBadgeMascotMark:
    def test_badge_carries_a_mark_derived_from_logo_svg(self):
        """The badge embeds the same paths brand.LOGO_SVG defines — not a second,
        independently hand-drawn icon that could drift from it."""
        _, findings, score = audit(FIXTURES / "home_safe")
        svg = render_svg(score, findings)
        assert '<circle cx="32" cy="32" r="30" fill="#e34234"/>' in svg
        assert '<circle cx="32" cy="32" r="5" fill="#fff"/>' in svg
        assert brand.BRAND_RED in svg

    def test_badge_stays_ascii_safe_and_never_embeds_the_mascot_glyph(self):
        """A shields.io-style badge must round-trip as pure ASCII. The mascot glyph
        itself (MASCOT, an emoji) is deliberately NOT used in the badge — an emoji
        would break that ASCII guarantee — see the comment above render_svg. This
        pins the design choice, not just the accident of today's output."""
        _, findings, score = audit(FIXTURES / "home_safe")
        svg = render_svg(score, findings)
        svg.encode("ascii")
        assert brand.MASCOT not in svg

    def test_badge_still_reports_grade_and_score_only(self):
        """Adding the mark must not change what the badge discloses — grade, score,
        and (when applicable) the suppression-count marker only."""
        _, findings, score = audit(FIXTURES / "home_safe")
        svg = render_svg(score, findings)
        assert "OpenClaw Security" in svg
        assert score.grade in svg
        assert str(score.score) in svg

    def test_badge_is_well_formed_across_every_grade(self):
        """Every grade letter must still produce a parseable, ASCII-safe SVG with
        the icon nested inside — never overlapping/negative geometry."""
        for grade in ("A", "B", "C", "D", "F"):
            svg = render_svg(_score(score=50, grade=grade), [])
            svg.encode("ascii")
            root = ET.fromstring(svg)
            assert root.tag.endswith("svg")
            ns = "{http://www.w3.org/2000/svg}"
            nested = root.findall(ns + "svg")
            assert len(nested) == 1, "expected exactly one nested icon <svg>"
            icon_x = float(nested[0].get("x"))
            icon_w = float(nested[0].get("width"))
            assert icon_x >= 0
            assert icon_x + icon_w < float(root.get("width"))


# ── docs/assets/src/banner.html: colour + mascot sourced from brand.py ───────

class TestBannerGroundedInBrand:
    def test_banner_uses_the_brand_red_accent_not_a_bare_literal_only(self):
        text = BANNER_PATH.read_text(encoding="utf-8")
        assert brand.BRAND_RED in text

    def test_banner_uses_the_brand_mascot(self):
        text = BANNER_PATH.read_text(encoding="utf-8")
        assert brand.MASCOT in text

    def test_banner_is_byte_identical_to_the_generator_output(self):
        """The load-bearing guard: banner.html is not just *consistent with*
        brand.py by coincidence, it IS scripts/gen_banner.py's output. Any manual
        edit that drifts from brand.py (or from the generator's template) fails
        here, whether or not it happens to still contain the right substrings."""
        assert BANNER_PATH.read_text(encoding="utf-8") == build_banner_html()

    def test_guard_actually_fires_on_a_corrupted_copy(self):
        """Prove the two guards above are not vacuously green: a banner.html that
        hardcodes a different accent colour must make both checks fail."""
        text = BANNER_PATH.read_text(encoding="utf-8")
        corrupted = text.replace(brand.BRAND_RED, "#00ff00")
        assert brand.BRAND_RED not in corrupted
        assert corrupted != build_banner_html()


class TestGenBannerIsDeterministic:
    def test_pure_function_is_idempotent(self):
        assert build_banner_html() == build_banner_html()

    def test_running_the_generator_twice_does_not_change_the_file(self, tmp_path):
        """A real (but sandboxed, tmp_path-only) run of the generator: write twice,
        confirm the second run is a no-op. Never touches the real repo file."""
        out = tmp_path / "banner.html"
        first = build_banner_html()
        out.write_text(first, encoding="utf-8")
        second = build_banner_html()
        out.write_text(second, encoding="utf-8")
        assert first == second
        assert out.read_text(encoding="utf-8") == first

    def test_generated_html_has_no_leftover_template_placeholders(self):
        body = build_banner_html()
        assert "{rgb}" not in body and "{red}" not in body and "{mascot}" not in body
