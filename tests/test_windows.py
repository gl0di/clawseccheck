"""Windows / portability behaviour: no false POSIX-perm findings, ASCII output."""
from pathlib import Path

from clawseccheck import audit, render_card, render_json, render_report

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _by_id(findings):
    return {f.id: f for f in findings}


def test_posix_perm_checks_are_skipped_on_windows(monkeypatch, tmp_path):
    # NTFS uses ACLs, not POSIX mode bits — we must not raise a false
    # "world-readable" finding on Windows even if st_mode looks loose.
    from clawseccheck import checks
    # simulate Windows without touching the global os.name (which pathlib reads)
    monkeypatch.setattr(checks._shared, "_is_posix", lambda: False)

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(
        '{"channels":{"telegram":{"accounts":{"main":'
        '{"botToken":"1234567890abcdef1234567890"}}}}}'
    )
    cfg.chmod(0o644)  # "loose" on POSIX, but we are pretending to be Windows
    f = _by_id(audit(tmp_path)[1])
    assert f["B1"].status == "PASS"
    assert f["B11"].status == "PASS"


def test_ascii_rendering_is_pure_ascii():
    _, findings, score = audit(FIXTURES / "home_vuln")
    report = render_report(findings, score, ascii_only=True)
    card = render_card(score, findings, ascii_only=True)
    # must be encodable by a legacy Windows console (cp1252/ascii) without error
    report.encode("ascii")
    card.encode("ascii")
    render_json(findings, score).encode("ascii")
    assert "[CRITICAL]" in report  # ascii severity token for an issue line is present
    assert "ClawSecCheck" in card


def test_unicode_rendering_still_default():
    _, findings, score = audit(FIXTURES / "home_safe")
    # default (non-ascii) output uses the real unicode glyph language: the 🦞 header
    # mascot plus a severity dot on issue lines (home_safe carries WARNs).
    out = render_report(findings, score, ascii_only=False)
    assert "🦞" in out
    assert "🟠" in out or "🟡" in out
