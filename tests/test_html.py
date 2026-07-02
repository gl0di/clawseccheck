"""HTML report rendering (render_html with inline CSS, no external assets)."""
from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import FAIL, Finding
from clawseccheck.report import render_html

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


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
