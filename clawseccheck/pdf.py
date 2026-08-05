"""Minimal, dependency-free PDF 1.4 writer, plus the audit report laid out on top of it.

Why this exists: a filesystem path is worthless to a user reading their agent's report
from a phone (e.g. over Telegram) — a mobile chat client does not render an HTML
attachment inline, but a PDF opens in the client's own viewer. `render_html` (report.py)
stays the rich desktop/archival format; `render_pdf` is the deliverable-into-chat one,
built off the same complete finding set.

Design constraints, all deliberate:

- **stdlib-only** (Golden Rule #1) — `zlib` for the content-stream compression, nothing
  else. No PDF library, no font-embedding library.
- **Base-14 fonts only** (`/Helvetica`, `/Helvetica-Bold`) — no font file is embedded, so
  every glyph drawn must be one the PDF spec guarantees every viewer already has. That
  means **ASCII-only text**: no emoji, no Unicode box-drawing, no accented Latin-1
  characters. Anything else is replaced with ``?`` by `_ascii_safe` — a crash is never an
  acceptable outcome for content that can come from a hostile skill's title/detail
  strings. Output has been English-only since v2.0.0 (CLAUDE.md §9), so this loses
  nothing the tool was already promising to render faithfully.
- **Classic (non-cross-reference-stream) PDF 1.4 layout** — header, N indirect objects
  each with a byte offset, a plain xref table, and a trailer. This is the simplest
  correctly-readable PDF shape and what every extraction tool (`pdftotext`, `pdfinfo`)
  expects from a "PDF 1.4" file.
- **No active content** — no `/JavaScript`, no `/AcroForm`, no embedded files. We ship a
  security tool; the report artifact itself must not be one more thing to audit.
- **Lossless pagination** — every line of every finding is drawn somewhere; a block that
  does not fit the remaining space on a page is continued on the next one rather than
  dropped (see `_PageFlow.line`). This is the direct fix for the B-444 failure class
  (a renderer silently truncating the finding list).

Usage::

    from clawseccheck.pdf import render_pdf
    pdf_bytes = render_pdf(findings, score)
    from .safeio import secure_write_bytes
    secure_write_bytes(Path("report.pdf"), pdf_bytes)
"""
from __future__ import annotations

import zlib

from .brand import BRAND_RED, GRADE_HEX, SEVERITY, WORDMARK, grade_hex
from .catalog import CRITICAL, FAIL, HIGH, LOW, MEDIUM, PASS, UNKNOWN, WARN, Finding
from .report import (
    _behavioral_block_lines, _cap_also_clause, _cap_cascade, _cap_primary_reason_text,
    _coverage_lines, _group_issues_by_subject, _mcp_inventory_lines,
    _plugins_inventory_lines, _risk_chain_lines, _sanitize, _second_opinion_item_lines,
    _second_opinion_lines,
    _SEV_ORDER, _skills_inventory_lines, _subject_summary_rows, _trifecta_ratio,
    _worth_a_glance_lines, build_inventory,
)
from .scoring import ScoreResult
from .textnorm import asciify

# ---------------------------------------------------------------------------
# Standard Adobe Core-14 Helvetica AFM glyph widths, per 1000 text-space units,
# ASCII printable range 0x20-0x7E. This is font metrics data — identical across every
# PDF-generating tool that ships base-14 support (reportlab, fpdf2, pdfminer,
# Ghostscript's own Helvetica.afm) — not proprietary content; it is what makes
# word-wrapping against an unembedded font possible at all.
# ---------------------------------------------------------------------------
_HELVETICA_WIDTHS: dict[int, int] = {
    0x20: 278, 0x21: 278, 0x22: 355, 0x23: 556, 0x24: 556, 0x25: 889, 0x26: 667,
    0x27: 191, 0x28: 333, 0x29: 333, 0x2A: 389, 0x2B: 584, 0x2C: 278, 0x2D: 333,
    0x2E: 278, 0x2F: 278,
    0x30: 556, 0x31: 556, 0x32: 556, 0x33: 556, 0x34: 556, 0x35: 556, 0x36: 556,
    0x37: 556, 0x38: 556, 0x39: 556,
    0x3A: 278, 0x3B: 278, 0x3C: 584, 0x3D: 584, 0x3E: 584, 0x3F: 556, 0x40: 1015,
    0x41: 667, 0x42: 667, 0x43: 722, 0x44: 722, 0x45: 667, 0x46: 611, 0x47: 778,
    0x48: 722, 0x49: 278, 0x4A: 500, 0x4B: 667, 0x4C: 556, 0x4D: 833, 0x4E: 722,
    0x4F: 778, 0x50: 667, 0x51: 778, 0x52: 722, 0x53: 667, 0x54: 611, 0x55: 722,
    0x56: 667, 0x57: 944, 0x58: 667, 0x59: 667, 0x5A: 611,
    0x5B: 278, 0x5C: 278, 0x5D: 278, 0x5E: 469, 0x5F: 556, 0x60: 333,
    0x61: 556, 0x62: 556, 0x63: 500, 0x64: 556, 0x65: 556, 0x66: 278, 0x67: 556,
    0x68: 556, 0x69: 222, 0x6A: 222, 0x6B: 500, 0x6C: 222, 0x6D: 833, 0x6E: 556,
    0x6F: 556, 0x70: 556, 0x71: 556, 0x72: 333, 0x73: 500, 0x74: 278, 0x75: 556,
    0x76: 500, 0x77: 722, 0x78: 500, 0x79: 500, 0x7A: 500,
    0x7B: 334, 0x7C: 260, 0x7D: 334, 0x7E: 584,
}
_DEFAULT_GLYPH_WIDTH = 556  # falls back for anything outside the table (shouldn't happen
# post `_ascii_safe`, since every byte 0x20-0x7E is covered above and control/DEL bytes
# are never drawn as visible glyphs)
# Helvetica-Bold runs ~5-8% wider per glyph than regular; rather than a second full
# table, wrap-width math for bold text applies this safety factor so a bold line's
# measured width is never an UNDER-estimate (which is what would cause visual overflow —
# an over-estimate just wraps one word earlier than strictly necessary, which is safe).
_BOLD_WIDTH_FACTOR = 1.08

_PAGE_W, _PAGE_H = 612.0, 792.0  # US Letter, points
_MARGIN = 50.0
_CONTENT_W = _PAGE_W - 2 * _MARGIN
_FOOTER_H = 30.0
_TOP_Y = _PAGE_H - _MARGIN
_BOTTOM_Y = _MARGIN + _FOOTER_H


def _ascii_safe(s: str) -> str:
    """Encode *s* for the base-14 content stream. Never raises — common typographic Unicode
    (arrows, dashes, curly quotes, middot, multiply sign) is first folded to an ASCII
    equivalent; anything still outside printable ASCII then becomes ``?``.

    B-484: this used to carry its OWN third fold table, a strict subset of
    `textnorm.ASCII_MAP` except for U+2212 MINUS SIGN (now in the shared table). Folding
    through the one table means a dash renders identically in the PDF and in the terminal
    report it mirrors."""
    return asciify(s or "")


def _pdf_literal(s: str) -> str:
    """Escape a string for a PDF ``(...)`` literal (backslash and parens only — the
    input is already ASCII-safe, so no other byte needs escaping)."""
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _hex_to_rgb01(hexcolor: str) -> tuple[float, float, float]:
    h = (hexcolor or "#999999").lstrip("#")
    if len(h) != 6:
        h = "999999"
    return (int(h[0:2], 16) / 255.0, int(h[2:4], 16) / 255.0, int(h[4:6], 16) / 255.0)


def _text_width(s: str, size: float, bold: bool = False) -> float:
    w = sum(_HELVETICA_WIDTHS.get(ord(c), _DEFAULT_GLYPH_WIDTH) for c in s) * size / 1000.0
    return w * _BOLD_WIDTH_FACTOR if bold else w


def _wrap_text(text: str, size: float, max_width: float, bold: bool = False) -> list[str]:
    """Greedy word-wrap against the Helvetica width table. A single token wider than
    `max_width` on its own (a long path/URL in finding evidence) is hard-split by
    character rather than left to overflow the page — this only ever affects layout,
    never drops content."""
    words = text.split()
    if not words:
        return []
    lines: list[str] = []
    cur = ""
    for w in words:
        candidate = w if not cur else f"{cur} {w}"
        if _text_width(candidate, size, bold) <= max_width or not cur:
            if _text_width(w, size, bold) > max_width:
                if cur:
                    lines.append(cur)
                chunk = ""
                for ch in w:
                    if chunk and _text_width(chunk + ch, size, bold) > max_width:
                        lines.append(chunk)
                        chunk = ch
                    else:
                        chunk += ch
                cur = chunk
            else:
                cur = candidate
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines


# ---------------------------------------------------------------------------
# Low-level PDF object writer — classic (non-xref-stream) PDF 1.4.
# ---------------------------------------------------------------------------
class _PdfDoc:
    def __init__(self) -> None:
        self._bodies: dict[int, bytes] = {}
        self._next = 1
        # Filled in by the caller once known (Pages needs a number reserved before its
        # Kids exist; Root/Info need their objects created before render() can trail them).
        self.pages_parent: int | None = None
        self.root: int | None = None
        self.info: int | None = None

    def reserve(self) -> int:
        n = self._next
        self._next += 1
        return n

    def set_object(self, num: int, body: bytes) -> None:
        self._bodies[num] = body

    def add_object(self, body: bytes) -> int:
        n = self.reserve()
        self.set_object(n, body)
        return n

    def render(self) -> bytes:
        """Serialize header + every object (in ascending object-number order, so the
        result is deterministic byte-for-byte given the same inputs) + xref + trailer."""
        if any(n not in self._bodies for n in range(1, self._next)):
            raise RuntimeError("pdf.py: a reserved object number was never filled in")
        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")  # binary-marker comment, PDF convention
        offsets: dict[int, int] = {}
        for n in range(1, self._next):
            offsets[n] = len(out)
            out += f"{n} 0 obj\n".encode("ascii")
            out += self._bodies[n]
            out += b"\nendobj\n"
        xref_offset = len(out)
        count = self._next
        out += f"xref\n0 {count}\n".encode("ascii")
        out += b"0000000000 65535 f \n"
        for n in range(1, count):
            out += f"{offsets[n]:010d} 00000 n \n".encode("ascii")
        if self.root is None or self.info is None:
            raise RuntimeError("pdf.py: render() called before root/info were set")
        out += (
            f"trailer\n<< /Size {count} /Root {self.root} 0 R /Info {self.info} 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF"
        ).encode("ascii")
        return bytes(out)


def _stream_content_object(doc: _PdfDoc, raw: bytes) -> int:
    """Add a page /Contents stream object, zlib-compressed (FlateDecode)."""
    compressed = zlib.compress(raw, 9)
    header = f"<< /Length {len(compressed)} /Filter /FlateDecode >>\nstream\n".encode("ascii")
    return doc.add_object(header + compressed + b"\nendstream")


# ---------------------------------------------------------------------------
# Page-flow layout — accumulates content-stream ops for the current page, starting a
# fresh page whenever the next line would run past the footer.
# ---------------------------------------------------------------------------
class _PageFlow:
    def __init__(self, doc: _PdfDoc, font_helv: int, font_bold: int) -> None:
        self._doc = doc
        self._font_helv = font_helv
        self._font_bold = font_bold
        self._page_ops: list[str] = []
        self.pages: list[int] = []  # finished Page object numbers, in order
        self.y = _TOP_Y
        self.page_epoch = 0  # bumped on every new page — lets a caller detect a block
        # (e.g. one finding) that straddled a page break, where a start-y captured on the
        # old page and an end-y read on the new page would otherwise combine into a
        # meaningless rect height (two different pages' coordinate spaces).
        self._new_page()

    def _new_page(self) -> None:
        if self._page_ops:
            self._finish_page()
        self.y = _TOP_Y
        self._page_ops = []
        self.page_epoch += 1

    def _finish_page(self) -> None:
        page_no = len(self.pages) + 1
        footer = (
            f"BT /F1 8 Tf 0.45 0.45 0.45 rg 1 0 0 1 {_MARGIN:.2f} {(_MARGIN - 15):.2f} Tm "
            f"(ClawSecCheck - read-only, generated locally, never leaves your machine) Tj ET\n"
            f"BT /F1 8 Tf 0.45 0.45 0.45 rg 1 0 0 1 {(_PAGE_W - _MARGIN - 40):.2f} "
            f"{(_MARGIN - 15):.2f} Tm (Page {page_no}) Tj ET\n"
        )
        raw = ("0 0 0 rg\n" + "\n".join(self._page_ops) + "\n" + footer).encode("ascii")
        content_num = _stream_content_object(self._doc, raw)
        page_num = self._doc.add_object(
            (
                f"<< /Type /Page /Parent {self._doc.pages_parent} 0 R "
                f"/Resources << /Font << /F1 {self._font_helv} 0 R /F2 {self._font_bold} 0 R >> >> "
                f"/MediaBox [0 0 {_PAGE_W:g} {_PAGE_H:g}] /Contents {content_num} 0 R >>"
            ).encode("ascii")
        )
        self.pages.append(page_num)

    def finish(self) -> None:
        self._finish_page()

    def ensure_space(self, height: float) -> None:
        if self.y - height < _BOTTOM_Y:
            self._new_page()

    def rect(self, x: float, y: float, w: float, h: float, hexcolor: str) -> None:
        r, g, b = _hex_to_rgb01(hexcolor)
        self._page_ops.append(f"{r:.3f} {g:.3f} {b:.3f} rg\n{x:.2f} {y:.2f} {w:.2f} {h:.2f} re f")

    def line(self, text: str, *, size: float = 10, bold: bool = False,
              color: str | None = None, indent: float = 0.0, gap_before: float = 0.0,
              gap_after: float = 2.0) -> None:
        """Draw one already-wrapped line, breaking to a new page first if it does not fit.

        This is the single place text ever reaches the content stream, so every caller
        (title, detail, labels, family headers) funnels through the same
        sanitize -> ascii-safe -> pdf-literal-escape pipeline — nothing skips it."""
        line_h = size * 1.35
        self.ensure_space(gap_before + line_h)
        self.y -= gap_before
        safe = _pdf_literal(_ascii_safe(_sanitize(text)))
        r, g, b = _hex_to_rgb01(color) if color else (0.0, 0.0, 0.0)
        font = "/F2" if bold else "/F1"
        self._page_ops.append(
            f"BT {font} {size:g} Tf {r:.3f} {g:.3f} {b:.3f} rg "
            f"1 0 0 1 {(_MARGIN + indent):.2f} {self.y:.2f} Tm ({safe}) Tj ET"
        )
        self.y -= line_h + gap_after

    def wrapped(self, text: str, *, size: float = 10, bold: bool = False,
                color: str | None = None, indent: float = 0.0) -> None:
        max_w = _CONTENT_W - indent
        for wline in _wrap_text(_ascii_safe(_sanitize(text)), size, max_w, bold):
            self.line(wline, size=size, bold=bold, color=color, indent=indent, gap_after=1.0)

    def spacer(self, h: float) -> None:
        self.ensure_space(h)
        self.y -= h

    def raw(self, op: str) -> None:
        """Append a raw content-stream fragment (path/graphics ops) to the current page.
        Used for the header band + logo mark — absolute vector drawing rather than the
        line-flow text every other method funnels through. The caller owns the graphics
        state it sets (colours/line-width); `_logo_ops` wraps its own ops in q/Q so
        nothing leaks into the text that follows."""
        self._page_ops.append(op)

    def text_abs(self, x: float, y: float, text: str, size: float, *,
                 bold: bool = False, rgb: tuple = (0.0, 0.0, 0.0)) -> None:
        """Draw one line of text at an ABSOLUTE (x, y) baseline — no wrapping, no y-advance,
        no page break. For the header/badge/summary-table cells, whose layout is positioned
        by hand near the top of page 1; callers pass short fixed-width label text that fits.
        Same sanitize -> ascii-safe -> pdf-literal pipeline as `line`."""
        safe = _pdf_literal(_ascii_safe(_sanitize(text)))
        r, g, b = rgb
        font = "/F2" if bold else "/F1"
        self._page_ops.append(
            f"BT {font} {size:g} Tf {r:.3f} {g:.3f} {b:.3f} rg "
            f"1 0 0 1 {x:.2f} {y:.2f} Tm ({safe}) Tj ET")


# ---------------------------------------------------------------------------
# Vector drawing — the brand mark as native PDF path ops, plus the branded header,
# severity chips and per-subject summary table. base-14 forbids embedding a font, but
# PDF draws vector paths itself, so the logo is the SAME geometry as brand.LOGO_SVG,
# rendered crisp at any size (no raster, no external asset — Golden Rule #1).
# ---------------------------------------------------------------------------
_KAPPA = 0.5522847498  # cubic-bezier control-point factor for a quarter-circle arc

# status -> swatch colour for the subject-summary table (grade ramp; UNKNOWN neutral grey)
_STATUS_HEX = {FAIL: GRADE_HEX["F"], WARN: GRADE_HEX["C"], PASS: GRADE_HEX["B"], UNKNOWN: "#9f9f9f"}


def _circle_path(cx: float, cy: float, r: float) -> str:
    """Four cubic-bezier arcs approximating a full circle (PDF has no arc primitive).
    Path-construction ops only (no paint op) — the caller appends ``S`` (stroke) or
    ``f`` (fill)."""
    k = _KAPPA * r
    return (f"{cx + r:.2f} {cy:.2f} m "
            f"{cx + r:.2f} {cy + k:.2f} {cx + k:.2f} {cy + r:.2f} {cx:.2f} {cy + r:.2f} c "
            f"{cx - k:.2f} {cy + r:.2f} {cx - r:.2f} {cy + k:.2f} {cx - r:.2f} {cy:.2f} c "
            f"{cx - r:.2f} {cy - k:.2f} {cx - k:.2f} {cy - r:.2f} {cx:.2f} {cy - r:.2f} c "
            f"{cx + k:.2f} {cy - r:.2f} {cx + r:.2f} {cy - k:.2f} {cx + r:.2f} {cy:.2f} c")


def _quad_to_cubic_path(p0, ctrl, p1) -> str:
    """One quadratic Bezier (LOGO_SVG's ``Q`` claw arcs) exactly converted to the cubic
    ``c`` PDF operator: cp1 = p0 + 2/3(ctrl-p0), cp2 = p1 + 2/3(ctrl-p1). Returns
    ``m ... c`` (no paint op)."""
    x0, y0 = p0
    cx, cy = ctrl
    x1, y1 = p1
    c1x, c1y = x0 + 2.0 / 3.0 * (cx - x0), y0 + 2.0 / 3.0 * (cy - y0)
    c2x, c2y = x1 + 2.0 / 3.0 * (cx - x1), y1 + 2.0 / 3.0 * (cy - y1)
    return (f"{x0:.2f} {y0:.2f} m "
            f"{c1x:.2f} {c1y:.2f} {c2x:.2f} {c2y:.2f} {x1:.2f} {y1:.2f} c")


def _logo_ops(x0: float, y0: float, size: float, rgb=(1.0, 1.0, 1.0)) -> str:
    """`brand.LOGO_SVG` rendered as native PDF path ops, in *rgb*, inside a *size*-point
    box whose bottom-left is (x0, y0): a ring, two claw arcs and a centre dot — the same
    geometry as the SVG, drawn white for the BRAND_RED header band. SVG is y-down, PDF is
    y-up, so every point is flipped through (64 - sy). Wrapped in q/Q so its colour and
    line-width never leak into later content."""
    s = size / 64.0

    def _p(sx, sy):
        return (x0 + sx * s, y0 + (64.0 - sy) * s)

    r, g, b = rgb
    out = [f"q {r:.3f} {g:.3f} {b:.3f} RG {r:.3f} {g:.3f} {b:.3f} rg 1 J 1 j"]
    out.append(f"{2.6 * s:.2f} w " + _circle_path(*_p(32, 32), 29.0 * s) + " S")
    out.append(f"{4.0 * s:.2f} w " + _quad_to_cubic_path(_p(20, 24), _p(13, 32), _p(20, 40)) + " S")
    out.append(_quad_to_cubic_path(_p(44, 24), _p(51, 32), _p(44, 40)) + " S")
    out.append(_circle_path(*_p(32, 32), 5.0 * s) + " f")
    out.append("Q")
    return "\n".join(out)


def _draw_header(flow: "_PageFlow", version: str) -> None:
    """The BRAND_RED header band (page 1): full-bleed rectangle + white logo mark +
    wordmark + subtitle + version. Sets `flow.y` to just below the band so the body
    starts under it. No date is stamped — render_pdf output is deterministic byte-for-byte
    per its docstring, and a clock read would break that."""
    band_h = 74.0
    flow.rect(0.0, _PAGE_H - band_h, _PAGE_W, band_h, BRAND_RED)
    logo_sz = 36.0
    flow.raw(_logo_ops(_MARGIN, _PAGE_H - band_h / 2.0 - logo_sz / 2.0, logo_sz, (1.0, 1.0, 1.0)))
    tx = _MARGIN + logo_sz + 14.0
    flow.text_abs(tx, _PAGE_H - 34.0, WORDMARK, 19, bold=True, rgb=(1.0, 1.0, 1.0))
    flow.text_abs(tx, _PAGE_H - 50.0, "Security Audit Report", 10.5, rgb=(1.0, 0.86, 0.83))
    right = f"v{version}"
    flow.text_abs(_PAGE_W - _MARGIN - _text_width(right, 9.5), _PAGE_H - 34.0, right,
                  9.5, rgb=(1.0, 0.86, 0.83))
    flow.y = _PAGE_H - band_h - 20.0


def _draw_chips(flow: "_PageFlow", sev_counts: dict) -> None:
    """A row of filled severity chips (CRITICAL/HIGH/MEDIUM/LOW n) in the SEVERITY ramp,
    white text — only the severities that actually occur."""
    active = [(sev, n) for sev, n in sev_counts.items() if n]
    if not active:
        return
    flow.ensure_space(22.0)
    y = flow.y
    x = _MARGIN
    for sev, n in active:
        text = f"{sev} {n}"
        w = _text_width(text, 9, bold=True) + 14.0
        style = SEVERITY.get(sev)
        flow.rect(x, y - 15.0, w, 15.0, style.hex if style else "#999999")
        flow.text_abs(x + 7.0, y - 11.0, text, 9, bold=True, rgb=(1.0, 1.0, 1.0))
        x += w + 6.0
    flow.y = y - 15.0 - 8.0


def _draw_subject_summary(flow: "_PageFlow", rows) -> None:
    """The "Inventory by subject" table: one row per subject — status swatch, label, and a
    right-aligned "count · STATUS". Rows come from report._subject_summary_rows (derived
    from build_inventory, so this cannot disagree with the JSON inventory)."""
    for label, status, count in rows:
        flow.ensure_space(16.0)
        y = flow.y
        flow.rect(_MARGIN, y - 10.0, 7.0, 7.0, _STATUS_HEX.get(status, "#9f9f9f"))
        flow.text_abs(_MARGIN + 13.0, y - 9.0, label, 10)
        right = f"{count}    {status}"
        flow.text_abs(_PAGE_W - _MARGIN - _text_width(right, 9), y - 9.0, right,
                      9, rgb=(0.42, 0.42, 0.42))
        flow.y = y - 16.0
        flow.rect(_MARGIN, flow.y + 4.0, _CONTENT_W, 0.4, "#e2e2e2")


def _draw_section_header(flow: "_PageFlow", text: str) -> None:
    """A section header bar: light fill with a BRAND_RED left accent."""
    flow.ensure_space(26.0)
    flow.spacer(4.0)
    y = flow.y
    flow.rect(_MARGIN, y - 17.0, _CONTENT_W, 19.0, "#f4efe9")
    flow.rect(_MARGIN, y - 17.0, 3.0, 19.0, BRAND_RED)
    flow.text_abs(_MARGIN + 11.0, y - 13.0, text, 12, bold=True, rgb=(0.16, 0.16, 0.16))
    flow.y = y - 17.0 - 8.0


def _draw_subject_header(flow: "_PageFlow", label: str, n: int) -> None:
    """A per-subject findings section header."""
    _draw_section_header(flow, f"{label} - {n} issue(s)")


def _pipeline_block(flow: "_PageFlow", title: str, lines) -> None:
    """Render one `--full` pipeline block (Skills / Plugins / MCP / RISK chains /
    Behavioural / Second opinion / Coverage / Worth a glance) into the PDF.

    *lines* comes from report.py's OWN line renderer for that block, called with
    ``ascii_only=True`` — so the PDF and the chat card are one system rather than two
    formatters that can drift, and every glyph is already base-14-safe ([X]/[!]/[OK]/[?]
    instead of the unicode markers, which would each become '?'). Leading indentation is
    preserved as a left inset so nested roster/reason lines still read as nested; the text
    itself word-wraps rather than overflowing (nothing is ever dropped)."""
    if not lines:
        return
    # One renderer (_coverage_lines) already opens with its own text rule
    # ("-- Coverage of OpenClaw surfaces --") because the terminal report splices it in
    # unlabelled. Drop that line rather than drawing the title twice — matched by content,
    # not by position, so a change to its decoration cannot silently reintroduce the dupe.
    lines = list(lines)
    if lines and lines[0].strip(" -=").casefold() == title.casefold():
        lines = lines[1:]
    _draw_section_header(flow, title)
    for raw in lines:
        text = raw.rstrip()
        if not text.strip():
            flow.spacer(4.0)
            continue
        indent = (len(text) - len(text.lstrip(" "))) * 3.0
        flow.wrapped(text.lstrip(" "), size=9, color="#333333", indent=min(indent, 60.0))
    flow.spacer(6.0)


def _finding_block(flow: _PageFlow, f: Finding) -> None:
    sev_style = SEVERITY.get(f.severity)
    sev_hex = sev_style.hex if sev_style else "#999999"
    status_word = "FAIL" if f.status == FAIL else "WARN"
    # Keep a finding's title (and the start of its detail) from being orphaned alone at
    # the very bottom of a page — everything past that still breaks losslessly line by
    # line via `_PageFlow.line`'s own `ensure_space`.
    flow.ensure_space(3 * 12 * 1.35)
    bar_y_top = flow.y
    start_epoch = flow.page_epoch
    flow.line(f"[{status_word}] {f.id}: {_sanitize(f.title)}", size=11, bold=True, gap_after=1.0)
    flow.line(f"Severity: {f.severity}", size=9, color=sev_hex, gap_after=2.0)
    if f.detail:
        flow.wrapped(f"Why: {_sanitize(f.detail)}", size=9.5, color="#444444", indent=8.0)
    # A block that straddled a page break has `bar_y_top` and the current `flow.y` in two
    # different pages' coordinate spaces — combining them into one rect height would be
    # meaningless (and the rect would land on the wrong page entirely). Skip the purely
    # decorative accent bar in that case rather than draw a broken one; the finding's
    # text content itself is never affected either way (see `_PageFlow.line`'s own
    # per-line `ensure_space`, which is what actually guarantees nothing is lost).
    if flow.page_epoch == start_epoch:
        flow.rect(_MARGIN - 8, flow.y, 2.2, bar_y_top - flow.y, sev_hex)
    flow.spacer(6.0)


def render_pdf(findings: list[Finding], score: ScoreResult, native=None,
               *, ctx=None, plugin_sweep=None, risk=None, behavioral=None,
               adjudication=None) -> bytes:
    """Render the complete audit (all FAIL/WARN findings, grouped BY SUBJECT the same way
    `render_html` groups them, under a branded header band + a per-subject summary table)
    as a paginated, base-14-only PDF. Returns bytes — this
    renderer has no text form, unlike every other `render_*` in the package.

    Byte-level guarantees a caller can rely on (pinned by `tests/test_pdf.py`): starts
    ``%PDF-``, ends ``%%EOF``, every xref offset resolves to the object it claims, the
    object count matches the trailer ``/Size``, and no ``/JavaScript``/``/AcroForm``/
    embedded-file entry is ever emitted.
    """
    doc = _PdfDoc()
    pages_num = doc.reserve()
    doc.pages_parent = pages_num
    font_helv = doc.add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    font_bold = doc.add_object(
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"
    )

    flow = _PageFlow(doc, font_helv, font_bold)

    issues = [f for f in findings if f.status in (FAIL, WARN) and not getattr(f, "suppressed", False)]
    issues.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.status != FAIL))

    # Lazy import: __version__ is assigned in __init__.py AFTER `from .pdf import
    # render_pdf` runs, so a module-level import here would be a circular-import
    # ImportError at package-init time (same reasoning as report.py's lazy imports).
    from . import __version__ as _pkg_version  # noqa: PLC0415

    # ── Branded header band (page 1) + grade badge ───────────────────────────────
    _draw_header(flow, _pkg_version)
    grade_color = grade_hex(score.grade)
    badge_top = flow.y
    badge_s = 54.0
    flow.rect(_MARGIN, badge_top - badge_s, badge_s, badge_s, grade_color)
    # Centre the grade LETTER inside the badge — the old layout drew it a size above the
    # box (baseline maths put a white glyph on the white page: invisible). Cap height is
    # ~0.70 of the point size for Helvetica, so this centres it vertically in the square.
    g_size = 30.0
    g_w = _text_width(score.grade, g_size, bold=True)
    flow.text_abs(_MARGIN + (badge_s - g_w) / 2.0, badge_top - badge_s + (badge_s - g_size * 0.70) / 2.0,
                  score.grade, g_size, bold=True, rgb=(1.0, 1.0, 1.0))
    tx = _MARGIN + badge_s + 16.0
    flow.text_abs(tx, badge_top - 15.0, f"Security score {score.score}/100", 13, bold=True)
    bar_y = badge_top - 27.0
    flow.rect(tx, bar_y - 7.0, 210.0, 7.0, "#e6e6e6")
    pct = max(0, min(100, int(score.score)))
    if pct:
        flow.rect(tx, bar_y - 7.0, 210.0 * pct / 100.0, 7.0, grade_color)
    flow.text_abs(tx, badge_top - 46.0, f"Lethal Trifecta {_trifecta_ratio(findings)}",
                  9.5, rgb=(0.40, 0.40, 0.40))
    flow.y = badge_top - badge_s - 12.0

    degraded_n = getattr(score, "degraded_count", 0)
    if degraded_n:
        plural = "check" if degraded_n == 1 else "checks"
        flow.wrapped(
            f"Incomplete: {degraded_n} {plural} could not reach a reliable verdict this run "
            "(crashed, timed out, or hit unreadable/corrupted input) - this grade is incomplete.",
            size=9.5, color="#b94a48",
        )
    primary, extras = _cap_cascade(score)
    if primary is not None:
        reason = _cap_primary_reason_text(primary, score)
        also = _cap_also_clause(extras)
        flow.wrapped(f"Capped from {score.raw_score} ({reason}{also})", size=9.5, color="#b94a48")

    # ── Severity chips ───────────────────────────────────────────────────────────
    flow.spacer(6.0)
    sev_counts = {sev: sum(1 for f in issues if f.severity == sev) for sev in (CRITICAL, HIGH, MEDIUM, LOW)}
    _draw_chips(flow, sev_counts)

    # ── Inventory by subject (summary table) ─────────────────────────────────────
    summary_rows = _subject_summary_rows(findings, ctx, plugin_sweep=plugin_sweep)
    if summary_rows:
        flow.spacer(8.0)
        flow.line("Inventory by subject", size=12.5, bold=True, gap_after=6.0)
        _draw_subject_summary(flow, summary_rows)

    # ── Findings, grouped by subject ─────────────────────────────────────────────
    flow.spacer(10.0)
    if not issues:
        flow.line(
            "No known attack pattern matched across the audited surfaces. Keep it that way.",
            size=11, bold=True, color="#1a7f37",
        )
    else:
        for _subj_key, subj_label, subj_issues in _group_issues_by_subject(issues):
            _draw_subject_header(flow, subj_label, len(subj_issues))
            for f in subj_issues:
                _finding_block(flow, f)

    # ── The --full pipeline (C-374) ──────────────────────────────────────────────
    # Same fixed order `render_dashboard(full=True)` uses, rendered from the SAME line
    # renderers, so the PDF can carry everything the combined chat card carries — which
    # is what lets that card collapse to an overview + this attachment instead of pasting
    # 11.5 KB into a chat message. Every block is caller-supplied: a run that skipped a
    # phase (a plain audit, --fast, or the phase's own budget) passes None and only that
    # block is omitted. Nothing here re-scans or re-judges anything.
    inv = build_inventory(findings, ctx, plugin_sweep=plugin_sweep) if ctx is not None else None
    if inv is not None and inv["skills"]:
        _pipeline_block(flow, "Skills", _skills_inventory_lines(inv, ctx, ascii_only=True))
    _pipeline_block(flow, "Plugins", _plugins_inventory_lines(plugin_sweep, ascii_only=True))
    if inv is not None and inv["mcp"]:
        _pipeline_block(flow, "MCP servers", _mcp_inventory_lines(inv, ascii_only=True))
    _pipeline_block(flow, "RISK chains", _risk_chain_lines(risk or [], ascii_only=True))
    # Behavioural / Second opinion are shown whenever the phase RAN, even to report
    # "nothing fired" (Golden Rule #4) — their own renderers already encode that.
    _pipeline_block(flow, "Behavioural", _behavioral_block_lines(behavioral, ascii_only=True))
    _pipeline_block(flow, "Second opinion (advisory)",
                    _second_opinion_lines(adjudication, ascii_only=True)
                    # B-470: the attachment has the room the chat card does not, so the
                    # judge panel's per-item verdicts land here instead of being computed
                    # and discarded behind a bare count.
                    + _second_opinion_item_lines(adjudication))
    _pipeline_block(flow, "Coverage of OpenClaw surfaces",
                    _coverage_lines(findings, ascii_only=True))
    _pipeline_block(flow, "Worth a glance", _worth_a_glance_lines(findings, ascii_only=True))

    flow.finish()

    pages_body = f"<< /Type /Pages /Kids [{' '.join(f'{n} 0 R' for n in flow.pages)}] /Count {len(flow.pages)} >>"
    doc.set_object(pages_num, pages_body.encode("ascii"))
    catalog_num = doc.add_object(f"<< /Type /Catalog /Pages {pages_num} 0 R >>".encode("ascii"))
    info_num = doc.add_object(
        f"<< /Producer ({_pdf_literal(_ascii_safe('ClawSecCheck v' + _pkg_version))}) "
        f"/Title (ClawSecCheck Security Audit Report) >>".encode("ascii")
    )
    doc.root = catalog_num
    doc.info = info_num
    return doc.render()
