"""The PDF report's identity and its vertical arithmetic.

Three defects shipped together in one artifact, and none of them was a logic error — each
was a drawing decision nothing checked:

1. The header mark was a hand-redrawn copy of ``brand.LOGO_SVG``, which ``brand.py`` labels
   PROVISIONAL. Once the HTML report started showing the real mascot, the two artifacts of
   a single run showed two different logos.

2. ``flow.y`` in this renderer is a text BASELINE, not a box edge, so a drop measured from
   a filled band has to clear the next line's ascender before any gap is visible at all.
   The section header dropped 8pt, which is almost exactly the ascender of the 11pt finding
   title beneath it: measured on a real report, the band's bottom edge sat **0.08pt** above
   the glyph tops. The heading and the first finding touched, in every section, on every
   page, and every test stayed green because nothing looked at geometry.

3. The block's accent bar takes its colour from SEVERITY, so a HIGH FAIL and a HIGH WARN
   were the same block with a different first word.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import base64
import re

from _pdftext import content_streams

from clawseccheck.brand import FAVICON_DATA_URI
from clawseccheck.catalog import CRITICAL, FAIL, HIGH, MEDIUM, Finding
from clawseccheck.pdf import _CONTENT_W, _png_rgba, render_pdf
from clawseccheck.scoring import compute

#: Helvetica's ascender, in ems. Used to turn a baseline into the top of the glyphs above
#: it — the conversion whose absence is defect 2 above. Slightly generous on purpose: a
#: guard that under-estimates the ascender would not have caught the shipped collision.
_ASCENT = 0.72

#: `_draw_section_header`'s band: a filled rect of the full content width, 19pt tall.
_BAND = re.compile(
    rb"([\d.]+) ([\d.]+) ([\d.]+) rg\n([\d.]+) ([-\d.]+) ([\d.]+) 19\.00 re f")
#: One text-drawing op, with the font size and baseline it draws at.
_TEXT = re.compile(
    rb"BT /F[12] ([\d.]+) Tf [\d.]+ [\d.]+ [\d.]+ rg 1 0 0 1 [-\d.]+ ([-\d.]+) Tm")


def _finding(fid: str, status: str, severity: str, title: str) -> Finding:
    return Finding(
        id=fid, title=title, severity=severity, status=status,
        detail="Why this matters, at enough length to wrap onto a second line so the "
               "block has a real height to draw a panel behind.",
        fix="Do the thing.", framework="Test", scored=True, evidence=[],
    )


def _render(findings: list[Finding]) -> bytes:
    return render_pdf(findings, compute(findings))


# --- 1. the mark is the real one -------------------------------------------------


def test_the_pdf_embeds_the_same_mark_the_html_and_the_favicon_use():
    """Not "an image is present" — the exact samples of `brand.FAVICON_DATA_URI`.

    Anchored on the single source of truth rather than on a byte count or a hash literal,
    so replacing the mascot updates every surface at once and this test follows it. The
    alpha channel is asserted separately: without an /SMask the mark arrives in an opaque
    rectangle, which is a different defect that an RGB-only check would not see.
    """
    w, h, rgb, alpha = _png_rgba(base64.b64decode(FAVICON_DATA_URI.split(",", 1)[1]))
    pdf = _render([_finding("B1", FAIL, CRITICAL, "Secrets in plaintext config")])
    streams = content_streams(pdf)
    assert rgb in streams, (
        f"the {w}x{h} brand mark's RGB samples are not in the PDF — the header is drawing "
        "something other than brand.FAVICON_DATA_URI (the provisional vector, most likely)")
    assert alpha in streams, (
        "the mark's alpha channel is not embedded, so it has no /SMask and will render as "
        "an opaque box over the header band")
    assert b"/SMask" in pdf and b"/XObject" in pdf, (
        "the image is embedded but not declared: without /XObject in the page's /Resources "
        "the `Do` operator draws nothing at all")


# --- 2. a filled band never touches the text under it ----------------------------


def test_no_section_band_collides_with_the_line_beneath_it():
    """Every section band must clear the ascender of the first line under it.

    The shipped gap was 0.08pt. This asserts a real one, over every band on every page, so
    the arithmetic cannot silently regress for one caller — `_draw_section_header` is used
    by the subject headings and by every `--full` pipeline block, whose following text is
    set at different sizes.
    """
    findings = [
        _finding("B1", FAIL, CRITICAL, "Secrets in plaintext config"),
        _finding("B2", FAIL, HIGH, "Gateway exposure and channel authentication"),
        _finding("B8", "WARN", HIGH, "Human approval on destructive actions"),
        _finding("B12", "WARN", MEDIUM, "Local-first and model hygiene"),
    ]
    bands_checked = 0
    for stream in content_streams(_render(findings)):
        for band in _BAND.finditer(stream):
            width, band_bottom = float(band.group(6)), float(band.group(5))
            if abs(width - _CONTENT_W) > 1.0:
                continue                       # a chip or a swatch, not a section band
            # The FIRST text after the band is the band's OWN label, drawn inside it —
            # taking that one measures the heading against its own box and reports a
            # nonsense overlap. The line this guard is about is the first one whose
            # baseline sits below the band, which is exactly how it is identified here.
            below = [(float(m.group(1)), float(m.group(2)))
                     for m in _TEXT.finditer(stream, band.end())
                     if float(m.group(2)) < band_bottom]
            if not below:
                continue                       # band at the very end of a page
            size, baseline = below[0]
            gap = band_bottom - (baseline + _ASCENT * size)
            bands_checked += 1
            assert gap >= 4.0, (
                f"a section band's bottom edge is {gap:.2f}pt from the glyph tops of the "
                f"{size:g}pt line under it — `flow.y` is a BASELINE, so the drop after the "
                "band must clear the ascender before any gap begins")
    assert bands_checked, "no section band was found — the regex is out of step with pdf.py"


# --- 3. status is drawn, not only written ----------------------------------------

#: `_finding_block`'s tint panel: a filled rect of the content width plus its 12pt bleed.
#: Captures the panel's bottom edge and height, so the guard can ask about geometry and
#: not only about how many were drawn.
_PANEL = re.compile(
    rb"[\d.]+ [\d.]+ [\d.]+ rg\n[-\d.]+ ([-\d.]+) %.2f ([\d.]+) re f" % (_CONTENT_W + 12.0))


def _panel_boxes(findings: list[Finding]) -> "list[list[tuple[float, float]]]":
    """Per page, each tint panel as ``(bottom, top)``."""
    return [[(float(m.group(1)), float(m.group(1)) + float(m.group(2)))
             for m in _PANEL.finditer(stream)]
            for stream in content_streams(_render(findings))]


def _panels(findings: list[Finding]) -> int:
    return sum(len(page) for page in _panel_boxes(findings))


def test_a_failure_draws_a_panel_and_a_warning_does_not():
    """Status has to be DRAWN, not only written in the title.

    An earlier version of this guard rendered the same finding twice, once as FAIL and once
    as WARN, and asserted the graphics differed. It passed with the distinction deleted:
    status also drives the SCORE, and the score bar and grade badge are graphics, so the two
    documents differed for a reason that had nothing to do with the finding block. Counting
    the panels directly is what the claim actually is.
    """
    high_fail = _finding("B55", FAIL, HIGH, "Filesystem-write tool exposure")
    high_warn = _finding("B8", "WARN", HIGH, "Human approval on destructive actions")
    assert _panels([high_fail, high_warn]) == 1, (
        "a FAIL and a WARN of the same severity draw the same block — the accent bar takes "
        "its colour from SEVERITY, so with no panel the only thing separating them is the "
        "word in the title")
    assert _panels([high_warn]) == 0, "a warning must sit on the plain page"
    assert _panels([high_fail, _finding("B1", FAIL, CRITICAL, "Secrets in config")]) == 2


def test_neighbouring_panels_do_not_run_together():
    """Counting panels is not enough: the first version of this tint was tall enough to
    overlap its neighbour, so four consecutive failures drew four panels that rendered as
    one undivided smear and read as a single finding. The panel's top padding has to stay
    under the inter-finding spacing, which is what this measures."""
    findings = [_finding(f"B{i}", FAIL, HIGH, f"Failure number {i}") for i in range(1, 5)]
    for page in _panel_boxes(findings):
        boxes = sorted(page)
        for (lo_b, lo_t), (hi_b, hi_t) in zip(boxes, boxes[1:]):
            assert hi_b >= lo_t, (
                f"two failure panels overlap by {lo_t - hi_b:.2f}pt "
                f"({lo_b:.1f}-{lo_t:.1f} and {hi_b:.1f}-{hi_t:.1f}) — a run of failures "
                "renders as one band instead of several findings")


def test_the_control_holds_two_identical_runs_render_identically():
    """Without this, a guard comparing renders would also pass on a non-deterministic
    writer, which would make it evidence of nothing."""
    one = _render([_finding("B55", FAIL, HIGH, "Filesystem-write tool exposure")])
    two = _render([_finding("B55", FAIL, HIGH, "Filesystem-write tool exposure")])
    assert one == two, "render_pdf is documented as deterministic byte-for-byte"
