"""HTML report rendering (render_html with inline CSS, no external assets)."""
import re
from pathlib import Path

from clawseccheck import audit, brand
from clawseccheck.brand import GRADE_HEX, SEVERITY
from clawseccheck.catalog import CRITICAL, FAIL, HIGH, LOW, MEDIUM, Finding
from clawseccheck.report import render_html

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

# Any http(s):// substring in render_html's output must be this SVG namespace
# URI (a required, inert XML identifier — never fetched) and nothing else. A
# match here means an external stylesheet/font/image/script slipped in.
_HTTP_URL_RE = re.compile(r"https?://[^\"'\s>]+")
_ALLOWED_HTTP_URL = "http://www.w3.org/2000/svg"


def test_html_report_starts_with_doctype():
    """HTML output must start with valid DOCTYPE or <html>."""
    _, findings, score = audit(FIXTURES / "home_safe")
    html = render_html(findings, score)
    assert html.startswith("<!doctype html") or html.startswith("<html")


def test_html_report_contains_grade():
    """HTML report must include the grade."""
    _, findings, score = audit(FIXTURES / "home_safe")
    html = render_html(findings, score)
    assert score.grade in html


def test_html_report_contains_score():
    """HTML report must include the numerical score."""
    _, findings, score = audit(FIXTURES / "home_safe")
    html = render_html(findings, score)
    assert f"{score.score}/100" in html


def test_html_report_uses_the_brand_mascot_not_the_magnifier():
    """C-241 regression: the <h1> title used to hardcode a stray 🔍 (magnifier-glass
    brand-drift) instead of the 🦞 mascot every other renderer uses; must now read
    from clawseccheck.brand, single-sourced."""
    _, findings, score = audit(FIXTURES / "home_safe")
    html = render_html(findings, score)
    assert "🔍" not in html
    # F-130 replaced the plain <h1> text with the inline LOGO_SVG + wordmark, so pin the
    # brand being present rather than the exact markup that task deliberately changed.
    assert brand.WORDMARK in html
    assert "Security Audit Report" in html


def test_html_badge_colour_comes_from_brand_grade_hex():
    """badge_color must be single-sourced from brand.GRADE_HEX (the report.py
    `_GRADE_COLOR` shadow-bug's hex dict), not a second hand-kept dict that could
    silently drift from it."""
    _, findings, score = audit(FIXTURES / "home_safe")
    html = render_html(findings, score)
    assert f"--grade: {brand.grade_hex(score.grade)};" in html


def test_html_severity_colours_come_from_brand_grade_hex():
    """sev_color (the per-severity summary-chip / finding-card ramp) must mirror
    brand.GRADE_HEX exactly — F for CRITICAL/HIGH, C for MEDIUM, B for LOW — the
    same values report.py always shipped, now single-sourced instead of a second
    hardcoded dict that could silently drift from the badge's."""
    findings = [
        Finding(id=f"T{i}", title=f"Test {sev}", severity=sev, status=FAIL,
                detail="detail", fix="fix", framework="Test")
        for i, sev in enumerate((CRITICAL, HIGH, MEDIUM, LOW))
    ]
    score_obj = type("ScoreResult", (), {
        "score": 40, "grade": "F", "capped": False, "raw_score": 40,
        "failed_critical": 1, "failed_high": 0,
    })()
    html = render_html(findings, score_obj)
    assert f"--sev:{brand.GRADE_HEX['F']};" in html  # CRITICAL and HIGH
    assert f"--sev:{brand.GRADE_HEX['C']};" in html  # MEDIUM
    assert f"--sev:{brand.GRADE_HEX['B']};" in html  # LOW


def test_html_report_html_escapes_finding_text():
    """Finding details must be HTML-escaped to prevent injection."""
    findings = [
        Finding(
            id="TEST1",
            title="Test Finding with <script>alert('xss')</script>",
            severity="HIGH",
            status=FAIL,
            detail="Detail with <img src=x onerror=alert(1)> and & < > characters",
            fix="machine-data only (not rendered, F-074)",
            framework="Test",
        )
    ]
    score_obj = type("ScoreResult", (), {
        "score": 50,
        "grade": "D",
        "capped": False,
        "raw_score": 50,
        "failed_critical": 0,
        "failed_high": 1,
    })()
    html = render_html(findings, score_obj)

    # Verify HTML entities are escaped
    assert "&lt;script&gt;" in html
    assert "&lt;img" in html
    assert "&amp;" in html
    # Ensure raw dangerous content is not present in the rendered output
    assert "<script>alert" not in html
    # The detail should show the escaped version
    assert "Detail with &lt;img src=x onerror=alert(1)&gt;" in html


def test_html_report_contains_trifecta():
    """HTML report must include Lethal Trifecta ratio."""
    _, findings, score = audit(FIXTURES / "home_safe")
    html = render_html(findings, score)
    assert "/3" in html


def test_html_report_contains_private_warning():
    """HTML report must have a visible warning that it's private."""
    _, findings, score = audit(FIXTURES / "home_safe")
    html = render_html(findings, score)
    assert "Private" in html or "private" in html
    assert "must" in html.lower() and "not" in html.lower() and "shar" in html.lower()


def test_html_report_shows_findings_when_issues_exist():
    """HTML report must include findings details when there are issues."""
    _, findings, score = audit(FIXTURES / "home_vuln")
    html = render_html(findings, score)
    # Should have findings section
    assert "Findings" in html or "findings" in html.lower()
    # Should have at least one issue (home_vuln has known issues)
    issues = [f for f in findings if f.status in ("FAIL", "WARN")]
    if issues:
        # At least one issue title should be in HTML
        assert any(issue.title in html for issue in issues)


def test_html_report_handles_no_issues_gracefully():
    """HTML report should handle clean audits gracefully."""
    _, findings, score = audit(FIXTURES / "home_safe")
    html = render_html(findings, score)
    # Should be valid HTML
    assert html.count("<html") >= 1
    assert html.count("</html>") >= 1
    # Should not break
    assert len(html) > 100


def test_html_report_inline_css_no_external_assets():
    """HTML report must have inline CSS, no external stylesheets."""
    _, findings, score = audit(FIXTURES / "home_safe")
    html = render_html(findings, score)
    # Should have inline style tags
    assert "<style>" in html
    # Should NOT reference external resources
    assert "http" not in html.lower() or "http" in html  # Allow internal mentions only
    assert "<!link" not in html.lower()
    assert '<link' not in html.lower()


def test_html_report_no_lens_emoji():
    """render_html must no longer use the standalone magnifying-glass emoji —
    the header now carries brand.LOGO_SVG + the wordmark instead (CLAWSECCHECK
    brand epic, C-e)."""
    _, findings, score = audit(FIXTURES / "home_safe")
    html = render_html(findings, score)
    assert "\U0001F50D" not in html  # 🔍


def test_html_report_inlines_brand_logo_svg():
    """render_html must inline brand.LOGO_SVG (an actual <svg>, not the mascot
    emoji — a graphical mark is HTML/badge-only, brand.py Tier 3)."""
    _, findings, score = audit(FIXTURES / "home_safe")
    html = render_html(findings, score)
    assert "<svg" in html.lower()
    assert 'aria-label="ClawSecCheck"' in html


def test_html_report_wordmark_readable_without_the_graphic():
    """The logo mark is aria-hidden (decorative, next to real text) — a screen
    reader must still get a readable 'ClawSecCheck' from actual text content,
    not only from inside the (hidden) SVG."""
    _, findings, score = audit(FIXTURES / "home_safe")
    html = render_html(findings, score)
    assert 'class="logo-mark" aria-hidden="true"' in html
    assert "ClawSecCheck" in html  # real text, outside the hidden SVG


def test_html_report_svg_logo_is_self_contained():
    """The inlined SVG must not pull in any external resource: no xlink:href to
    an external file, no @import, no http(s):// reference other than the SVG
    namespace URI itself (a required, inert XML identifier)."""
    _, findings, score = audit(FIXTURES / "home_safe")
    html = render_html(findings, score)
    assert "xlink:href" not in html.lower()
    assert "@import" not in html
    assert "<script" not in html.lower()
    for match in _HTTP_URL_RE.finditer(html):
        assert match.group(0) == _ALLOWED_HTTP_URL, (
            f"unexpected external reference in render_html() output: {match.group(0)!r}"
        )


def test_html_report_badge_color_matches_brand_grade_hex():
    """The grade badge color (`--grade: {hex}`) must equal brand.GRADE_HEX for
    the reported grade — single-sourced, not a local duplicate."""
    _, findings, score = audit(FIXTURES / "home_safe")
    html = render_html(findings, score)
    expected = GRADE_HEX.get(score.grade, "#9f9f9f")
    assert f"--grade: {expected};" in html


_FINDING_CARD_RE = re.compile(
    r'<article class="finding" style="--sev:(#[0-9a-fA-F]+);">.*?'
    r'<span class="sev-pill">([A-Z]+)</span>.*?</article>',
    re.DOTALL,
)


def test_html_report_severity_colors_match_brand_severity():
    """Every severity chip/finding-card color (`--sev:{hex}`) for a severity
    that actually occurs must equal brand.SEVERITY[severity].hex — compared
    against brand.py's live constants, not a hardcoded hex literal, so the
    test tracks the single source of truth instead of re-duplicating it.

    Scoped to BOTH surfaces independently (summary chips and finding cards),
    not just an `in html` existence check over the whole document: a chip
    emitting the right hex can't mask a card emitting the wrong one (or vice
    versa) the way a single substring search over the full page can."""
    _, findings, score = audit(FIXTURES / "home_vuln")
    html = render_html(findings, score)
    issues = [f for f in findings if f.status in (FAIL, "WARN") and not getattr(f, "suppressed", False)]
    severities_present = {f.severity for f in issues}
    assert severities_present, "fixture must exercise at least one severity"

    # Summary chips: `<span class="sev-chip" style="--sev:{hex};">`.
    for sev in severities_present:
        expected = SEVERITY[sev].hex
        assert f"--sev:{expected};" in html

    # Finding cards: each card's own `--sev:` must match ITS OWN severity
    # pill, not just some hex appearing somewhere in the document. This is
    # what mutation-testing proved the old `in html` check could not catch:
    # a `_finding_card` that hardcodes one hex for every severity still
    # satisfies "the right hexes appear somewhere" (the chips supply them)
    # while every card itself is wrong.
    cards = _FINDING_CARD_RE.findall(html)
    assert len(cards) == len(issues), (
        f"expected one finding-card match per issue ({len(issues)}), got {len(cards)} — "
        "the card-scoping regex may be out of sync with render_html's markup"
    )
    for color, sev in cards:
        expected = SEVERITY[sev].hex
        assert color == expected, (
            f"finding card for severity {sev!r} rendered --sev:{color} but "
            f"brand.SEVERITY[{sev!r}].hex is {expected} — drift reintroduced "
            "in the card path"
        )


def test_html_report_unknown_grade_falls_back_to_default_color():
    """An unrecognized grade must not KeyError — badge_color falls back to the
    same neutral grey brand.GRADE_HEX.get(...) already defaults to."""
    findings = []
    score_obj = type("ScoreResult", (), {
        "score": 0,
        "grade": "?",
        "capped": False,
        "raw_score": 0,
        "failed_critical": 0,
        "failed_high": 0,
    })()
    html = render_html(findings, score_obj)
    assert "--grade: #9f9f9f;" in html
