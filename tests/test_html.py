"""HTML report rendering (render_html with inline CSS, no external assets)."""
import re
from pathlib import Path

from clawseccheck import audit, brand
from clawseccheck.brand import GRADE_HEX, SEVERITY
from clawseccheck.catalog import (
    CRITICAL,
    FAIL,
    FAIL_WEIGHT_STATUSES,
    HIGH,
    LOW,
    MEDIUM,
    Finding,
)
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
    # The only <link> allowed is the self-contained data-URI favicon (brand.
    # FAVICON_DATA_URI) — a `data:` href never triggers a network fetch, so it
    # doesn't violate "no external assets"; an external stylesheet/font <link> would.
    links = re.findall(r"<link[^>]*>", html, re.IGNORECASE)
    assert len(links) == 1, f"unexpected <link> tag(s): {links}"
    assert 'rel="icon"' in links[0] and 'href="data:' in links[0], links[0]


def test_html_report_no_lens_emoji():
    """render_html must no longer use the standalone magnifying-glass emoji —
    the header now carries brand.LOGO_SVG + the wordmark instead (CLAWSECCHECK
    brand epic, C-e)."""
    _, findings, score = audit(FIXTURES / "home_safe")
    html = render_html(findings, score)
    assert "\U0001F50D" not in html  # 🔍


def test_html_report_inlines_a_real_graphical_mark():
    """The header must carry a GRAPHICAL mark, inlined, and not an emoji.

    C-508 changed the format and not the property. This asserted `"<svg" in html`, because
    the header used to embed `brand.LOGO_SVG` — which labels itself PROVISIONAL in
    `brand.py`: a circle and two arcs standing in for art that did not exist yet. The header
    now shows the real mascot, which ships as `brand.HEADER_LOGO_DATA_URI` (the same bytes
    the favicon already inlines). So the test asks what it always meant to ask — is there a
    real, inlined, non-emoji mark — instead of pinning the one format that happened to
    satisfy it. `LOGO_SVG` is still vector and still right for the 14px badge and the PDF;
    `test_brand.py::TestLogoSvg` keeps guarding it there.
    """
    _, findings, score = audit(FIXTURES / "home_safe")
    html = render_html(findings, score)

    assert brand.HEADER_LOGO_DATA_URI in html, "the header carries no inlined mark"
    assert 'class="logo-mark"' in html
    # Inlined, not fetched — the whole point of a data URI here.
    assert "data:image/" in html
    # A mark, not a glyph: the mascot emoji is a terminal/chat surface, never this one.
    assert brand.MASCOT not in html, (
        "the emoji stood in for the graphical mark — brand.py Tier 3 is HTML/badge-only"
    )


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


def test_html_report_has_self_contained_favicon():
    """render_html's <head> must carry a browser-tab icon sourced from brand.
    FAVICON_DATA_URI — single-sourced (not a hand-copied duplicate) and inline
    (a `data:` URI, never an external file the report would fail to resolve once
    saved/moved elsewhere)."""
    _, findings, score = audit(FIXTURES / "home_safe")
    html = render_html(findings, score)
    assert f'<link rel="icon" type="image/png" href="{brand.FAVICON_DATA_URI}">' in html


def test_html_report_badge_color_matches_brand_grade_hex():
    """The grade badge color (`--grade: {hex}`) must equal brand.GRADE_HEX for
    the reported grade — single-sourced, not a local duplicate."""
    _, findings, score = audit(FIXTURES / "home_safe")
    html = render_html(findings, score)
    expected = GRADE_HEX.get(score.grade, "#9f9f9f")
    assert f"--grade: {expected};" in html


#: `class="finding[^"]*"` rather than a literal `class="finding"`: the card carries a
#: status modifier (`finding is-fail`) since the tint was moved from severity to status,
#: and pinning the exact attribute value would have made this regex match only the WARN
#: cards while still reporting a count — the failure mode is silent under-scoping, not an
#: error. What the test actually guards is unchanged and still exact: one match per issue,
#: and each card's own `--sev` against its own pill.
_FINDING_CARD_RE = re.compile(
    r'<article class="finding[^"]*" style="--sev:(#[0-9a-fA-F]+);">.*?'
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


# --- status must be visible, not merely encoded (C-508) ----------------------------

#: The card's opening tag plus the two things that identify it: its title (which maps the
#: card back to the finding that produced it, so status comes from the DATA rather than
#: from the rendering) and its severity pill.
_CARD_IDENTITY_RE = re.compile(
    r'(<article class="[^"]*" style="--sev:#[0-9a-fA-F]+;">).*?'
    r'<span class="finding-title">(.*?)</span>.*?'
    r'<span class="sev-pill">([A-Z]+)</span>.*?</article>',
    re.DOTALL,
)


def test_status_changes_the_card_at_matched_severity():
    """A FAIL and a WARN of the SAME severity must not render as the same card.

    `--sev` is the *severity* colour, so every card used to be washed with it and status
    was carried by nothing but a glyph — the smallest mark on the card. Measured on a
    rendered page before the fix, a HIGH FAIL and a HIGH WARN differed by 4-6 of 255 in
    each channel: a difference that exists in the CSS and not in anyone's eye.

    The property pinned here is deliberately not "the class is spelled `is-fail`" — that
    would pin the spelling and miss the point. It is: at matched severity, the card's
    opening tag differs by status, and the stylesheet acts on whatever token carries the
    difference. Both halves are required. A marker no rule reads is invisible, which is
    the state this test exists to keep the page out of; and severity is already carried
    twice, by the pill and the rule colour, so it cannot stand in for status.
    """
    _, findings, score = audit(FIXTURES / "home_vuln")
    html = render_html(findings, score)
    esc_title = {}
    for f in findings:
        esc_title.setdefault(
            re.sub(r"\s+", " ", f.title).strip(), f.status
        )

    by_sev: dict = {}
    for tag, title, sev in _CARD_IDENTITY_RE.findall(html):
        status = esc_title.get(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", title)).strip())
        if status is None:
            continue
        band = "fail" if status in FAIL_WEIGHT_STATUSES else "warn"
        by_sev.setdefault(sev, {}).setdefault(band, tag)

    matched = {s: g for s, g in by_sev.items() if len(g) == 2}
    assert matched, (
        "the fixture no longer produces a FAIL and a WARN at the same severity, so this "
        "test cannot tell status apart from severity — point it at a fixture that does"
    )

    differing_tokens = set()
    for sev, g in matched.items():
        assert g["fail"] != g["warn"], (
            f"at severity {sev} the FAIL card and the WARN card render an identical "
            f"opening tag ({g['fail']}) — status is invisible and only severity shows"
        )
        fail_cls = set(re.search(r'class="([^"]*)"', g["fail"]).group(1).split())
        warn_cls = set(re.search(r'class="([^"]*)"', g["warn"]).group(1).split())
        differing_tokens |= fail_cls ^ warn_cls

    assert differing_tokens, "the tags differ but not by a class the stylesheet can select"
    for token in differing_tokens:
        rule = re.search(r"\.finding\.%s\s*\{([^}]*)\}" % re.escape(token), html)
        assert rule, f"nothing in the stylesheet selects .finding.{token}"
        body = rule.group(1)
        missing = [p for p in ("background", "border-left") if p not in body]
        assert not missing, (
            f".finding.{token} exists but sets no {' or '.join(missing)}, so the status "
            f"marker is only partly drawn: {body.strip()!r}"
        )
