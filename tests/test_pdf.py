"""Tests for clawseccheck.pdf.render_pdf (CLAWSECCHECK-F-162).

Byte-level structural checks don't depend on any external tool. The `pdftotext`/
`pdfinfo` round-trip checks are dev-box convenience (skip when poppler-utils is
absent, e.g. a minimal CI image) — same `shutil.which(...)` skip idiom already used
by tests/test_publish_workflow.py for `bash`.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import zlib
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.catalog import CRITICAL, FAIL, HIGH, PASS, UNKNOWN, WARN, Finding
from clawseccheck.pdf import render_pdf
from clawseccheck.safeio import secure_write_bytes
from clawseccheck.scoring import compute

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_HAS_PDFTOTEXT = shutil.which("pdftotext") is not None
_HAS_PDFINFO = shutil.which("pdfinfo") is not None


def _finding(id_: str, status: str, severity: str = HIGH,
             detail: str = "detail text", title: str | None = None) -> Finding:
    return Finding(
        id=id_,
        title=title or f"Title for {id_}",
        severity=severity,
        status=status,
        detail=detail,
        fix="fix text",
        framework="Test",
        scored=True,
        evidence=[],
    )


def _content_text(data: bytes) -> str:
    """All page content streams, decompressed and concatenated — lets a test assert on
    what was actually DRAWN without needing poppler installed. Note PDF string literals
    escape parens, so `(advisory)` appears as `\\(advisory\\)`."""
    out = ""
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", data, re.S):
        try:
            out += zlib.decompress(m.group(1)).decode("latin-1", "replace")
        except zlib.error:
            continue
    return out


def _pdftotext(data: bytes) -> str:
    return subprocess.run(
        ["pdftotext", "-", "-"], input=data, capture_output=True, check=True,
    ).stdout.decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# Byte-level structure (no external tool needed)
# ---------------------------------------------------------------------------

def test_starts_pdf_header_ends_eof():
    findings = [_finding("B1", FAIL)]
    data = render_pdf(findings, compute(findings))
    assert data.startswith(b"%PDF-1.4")
    assert data.rstrip(b"\n").endswith(b"%%EOF")


def test_xref_offsets_resolve_and_object_count_matches_trailer_size():
    findings = [_finding(f"B{i}", FAIL if i % 2 else WARN) for i in range(1, 6)]
    data = render_pdf(findings, compute(findings))

    m = re.search(rb"startxref\n(\d+)\n%%EOF", data)
    assert m, "no startxref/%%EOF trailer found"
    xref_offset = int(m.group(1))

    header = re.match(rb"xref\n0 (\d+)\n", data[xref_offset:])
    assert header, "xref table header not found at the claimed offset"
    count = int(header.group(1))

    trailer_m = re.search(rb"/Size (\d+) /Root (\d+) 0 R /Info (\d+) 0 R", data)
    assert trailer_m, "trailer /Size /Root /Info not found"
    assert int(trailer_m.group(1)) == count, "trailer /Size must equal the xref object count"

    entries_start = xref_offset + len(header.group(0))
    for n in range(1, count):  # object 0 is the always-free head entry, skip it
        entry = data[entries_start + n * 20: entries_start + (n + 1) * 20]
        offset_str = entry[:10]
        assert offset_str.isdigit(), f"xref entry {n} is not a 10-digit offset: {entry!r}"
        obj_offset = int(offset_str)
        assert data[obj_offset:obj_offset + len(f"{n} 0 obj")] == f"{n} 0 obj".encode("ascii"), (
            f"xref entry {n} points to offset {obj_offset}, which is not the start of object {n}"
        )
    # Root and Info themselves must be valid object numbers within range.
    root_num, info_num = int(trailer_m.group(2)), int(trailer_m.group(3))
    assert 1 <= root_num < count
    assert 1 <= info_num < count


def test_no_javascript_no_forms_no_embedded_files_in_raw_bytes():
    """Tool-independent guarantee: we ship a security tool, so the artifact itself
    must never carry active content, regardless of whether pdfinfo is installed."""
    findings = [_finding("B1", FAIL)]
    data = render_pdf(findings, compute(findings))
    for marker in (b"/JavaScript", b"/JS ", b"/AcroForm", b"/EmbeddedFile", b"/Launch"):
        assert marker not in data


def test_render_pdf_is_pure_and_deterministic(tmp_path):
    """render_pdf must not touch the filesystem and must be a pure function of its
    inputs (same findings/score in -> byte-identical PDF out) — anything else would
    make the byte-level tests above flaky and would mean the "offline, read-only"
    contract every other renderer honours doesn't hold here."""
    before = sorted(tmp_path.iterdir())
    findings = [_finding("B1", FAIL), _finding("B2", WARN)]
    score = compute(findings)
    a = render_pdf(findings, score)
    b = render_pdf(findings, score)
    assert a == b
    assert sorted(tmp_path.iterdir()) == before


def test_empty_findings_renders_all_clear_and_is_still_valid():
    findings = [_finding("B1", PASS), _finding("B2", UNKNOWN)]
    data = render_pdf(findings, compute(findings))
    assert data.startswith(b"%PDF-1.4")
    assert data.rstrip(b"\n").endswith(b"%%EOF")
    if _HAS_PDFTOTEXT:
        assert "No known attack pattern" in _pdftotext(data)


def test_suppressed_findings_are_excluded():
    f = _finding("B1", FAIL)
    f.suppressed = True
    data = render_pdf([f], compute([f]))
    if _HAS_PDFTOTEXT:
        assert "B1" not in _pdftotext(data)


# ---------------------------------------------------------------------------
# pdftotext / pdfinfo round-trip (dev-box convenience)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _HAS_PDFTOTEXT, reason="pdftotext not available")
def test_pdftotext_contains_every_fail_warn_finding_id():
    findings = [_finding(f"B{i}", FAIL if i % 3 == 0 else WARN) for i in range(1, 12)]
    findings.append(_finding("PASS1", PASS))  # must NOT appear
    data = render_pdf(findings, compute(findings))
    text = _pdftotext(data)
    for f in findings:
        if f.status in (FAIL, WARN):
            assert f.id in text, f"finding id {f.id} missing from extracted PDF text"
    assert "PASS1" not in text


def test_single_finding_straddling_a_page_break_draws_no_broken_bar():
    """A finding whose OWN detail is long enough to span multiple pages used to leave
    the severity-color accent bar's start-y captured on one page and its end-y read on
    another — two different pages' coordinate spaces combined into one rect, which
    landed a meaningless-height rectangle on the wrong page. The bar is now skipped for
    a block that straddles a page break rather than drawn broken. The finding's severity
    accent bar is uniquely 2.2pt wide (see _finding_block); every OTHER rect the report
    draws (header band, grade badge, score bar, severity chips, the subject summary
    swatches/separators, the subject-section header accent) has a different width, so its
    absence is a precise signal the straddled bar was skipped, not drawn broken."""
    long_detail = "word " * 3000  # forces this single finding across several pages
    f = _finding("B1", FAIL, detail=long_detail)
    data = render_pdf([f], compute([f]))

    content_streams = [
        zlib.decompress(m.group(1))
        for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", data, re.S)
    ]
    # Filter to actual page content streams (they contain "BT" text ops); font/other
    # dict-only objects never match `stream` at all, so this is already page content.
    page_streams = [s for s in content_streams if b"BT" in s]
    assert len(page_streams) >= 2, "test setup: this detail must actually force >1 page"
    rect_lines = [line for s in page_streams for line in s.decode("ascii").splitlines()
                  if line.strip().endswith("re f")]
    # A rect op is "x y w h re f"; the finding accent bar is the only one 2.2pt wide.
    accent_bars = [line for line in rect_lines if line.split()[2] == "2.20"]
    assert not accent_bars, f"straddled finding must not draw its accent bar, got: {accent_bars}"


@pytest.mark.skipif(not _HAS_PDFTOTEXT, reason="pdftotext not available")
def test_multipage_no_finding_lost_across_page_break():
    # Long, varied detail text per finding forces several page breaks well before
    # 80 findings would fit on a single US-Letter page at 9.5-11pt line heights.
    findings = [
        _finding(
            f"B{i:03d}", FAIL if i % 2 == 0 else WARN,
            detail=("This is a deliberately long finding detail string, repeated "
                     f"padding text to force page breaks for finding number {i}. ") * 4,
        )
        for i in range(1, 81)
    ]
    data = render_pdf(findings, compute(findings))
    text = _pdftotext(data)
    missing = [f.id for f in findings if f.id not in text]
    assert not missing, f"{len(missing)} finding(s) lost across a page break: {missing[:10]}"

    if _HAS_PDFINFO:
        info = subprocess.run(["pdfinfo", "-"], input=data, capture_output=True, check=True).stdout
        pages_line = next(line for line in info.decode().splitlines() if line.startswith("Pages:"))
        assert int(pages_line.split(":")[1].strip()) >= 2


@pytest.mark.skipif(not _HAS_PDFINFO, reason="pdfinfo not available")
def test_pdfinfo_reports_clean_single_page_doc():
    findings = [_finding("B1", FAIL)]
    data = render_pdf(findings, compute(findings))
    info = subprocess.run(["pdfinfo", "-"], input=data, capture_output=True, check=True).stdout.decode()
    assert "JavaScript:      no" in info
    assert "Form:            none" in info
    assert "PDF version:     1.4" in info


# ---------------------------------------------------------------------------
# Hostile / non-ASCII input never crashes the writer
# ---------------------------------------------------------------------------

def test_non_ascii_detail_never_crashes_and_is_transliterated():
    hostile = "→ café \U0001F600 ​‮ evil"  # arrow, accent, emoji, ZW/RTL override
    f = _finding("B1", FAIL, detail=hostile, title="Title → with unicode")
    data = render_pdf([f], compute([f]))  # must not raise
    assert data.startswith(b"%PDF-1.4")
    assert data.rstrip(b"\n").endswith(b"%%EOF")
    # every byte fed to a content stream is plain ASCII — the raw UTF-8 encoding of the
    # accented word must never appear anywhere in the file (compressed streams make a
    # substring search of the *decompressed* text meaningless, so this checks the
    # stronger, tool-independent property instead: the offending bytes were never
    # written in the first place).
    assert "café".encode("utf-8") not in data
    if _HAS_PDFTOTEXT:
        text = _pdftotext(data)
        assert "B1" in text  # the finding itself must still be present, just ascii'd
        assert "evil" in text


def test_long_unbroken_token_is_hard_split_not_dropped():
    long_token = "x" * 500  # e.g. a very long path/URL with no spaces to wrap on
    f = _finding("B1", WARN, detail=f"see {long_token} for details")
    data = render_pdf([f], compute([f]))
    assert data.startswith(b"%PDF-1.4")
    if _HAS_PDFTOTEXT:
        text = _pdftotext(data)
        assert "x" * 20 in text.replace("\n", "")  # substantial chunks of the token survive


# ---------------------------------------------------------------------------
# Real fixture, integration-level (mirrors the real-world B-444 truncation class)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _HAS_PDFTOTEXT, reason="pdftotext not available")
def test_real_fixture_home_vuln_carries_every_fail_warn_id():
    ctx, findings, score = audit(FIXTURES / "home_vuln")
    issues = [f for f in findings if f.status in (FAIL, WARN) and not getattr(f, "suppressed", False)]
    assert issues, "fixture must actually produce FAIL/WARN findings for this test to mean anything"
    data = render_pdf(findings, score)
    text = _pdftotext(data)
    missing = [f.id for f in issues if f.id not in text]
    assert not missing, f"real-fixture finding(s) missing from the PDF: {missing}"


def test_writes_via_secure_write_bytes(tmp_path):
    findings = [_finding("B1", FAIL)]
    data = render_pdf(findings, compute(findings))
    dest = tmp_path / "report.pdf"
    secure_write_bytes(dest, data)
    assert dest.read_bytes() == data
    assert oct(dest.stat().st_mode)[-3:] == "600"


# ── C-374: the PDF carries the whole --full pipeline ────────────────────────────────
#
# This is what lets `--dashboard --full --pdf` collapse its 11.5 KB chat card into an
# overview plus this attachment. If a block lived only in the card, collapsing would
# silently drop analysis the run actually performed.

# Card section label -> the PDF's title for the same block. Wording differs in two spots
# (the card says "MCP"/"RISK Chains", the PDF spells them out), so the mapping is
# declared rather than string-matched — and declaring it is the point: a NEW block added
# to the dashboard has no entry here and trips the drift guard below.
_CARD_TO_PDF_BLOCK = {
    "Skills": "Skills",
    "Plugins": "Plugins",
    "MCP": "MCP servers",
    "RISK Chains": "RISK chains",
    "Behavioural": "Behavioural",
    "Second opinion (advisory)": "Second opinion (advisory)",
    "Worth a glance": "Worth a glance",
}
# Card-only sections: the chat card's own furniture, never PDF pipeline blocks.
_CARD_ONLY_SECTIONS = {"Findings", "Inventory by subject", "Most urgent"}


def _dashboard_section_labels() -> set:
    """Section labels render_dashboard draws, read out of its source."""
    src = (Path(__file__).resolve().parent.parent / "clawseccheck" / "report.py").read_text()
    found = set()
    for m in re.finditer(r'f"\{sep\} (?:\{glance_marker\})?([^{]*?) \{sep\}"', src):
        found.add(m.group(1).strip())
    return found


def _pdf_block_titles() -> set:
    src = (Path(__file__).resolve().parent.parent / "clawseccheck" / "pdf.py").read_text()
    return set(re.findall(r'_pipeline_block\(\s*flow,\s*"([^"]+)"', src))


def test_every_dashboard_block_has_a_pdf_counterpart():
    """Drift guard: a block added to the combined card must also reach the PDF, or the
    card can no longer be collapsed behind the attachment without losing it."""
    card = _dashboard_section_labels() - _CARD_ONLY_SECTIONS
    unmapped = sorted(card - set(_CARD_TO_PDF_BLOCK))
    assert not unmapped, (
        f"dashboard block(s) with no declared PDF counterpart: {unmapped} — render them "
        "in pdf.py's --full pipeline section and add them to _CARD_TO_PDF_BLOCK")
    pdf_titles = _pdf_block_titles()
    missing = sorted(t for t in _CARD_TO_PDF_BLOCK.values() if t not in pdf_titles)
    assert not missing, f"declared PDF block(s) not actually rendered by pdf.py: {missing}"


def test_full_pipeline_blocks_are_drawn_into_the_pdf():
    """End-to-end: with phase results supplied, every pipeline block's title is really
    drawn in the PDF content stream (not merely wired up in source)."""
    class _Phase:
        def __init__(self, detail):
            self.ran, self.detail, self.lines = True, detail, [detail]

    class _RiskPath:
        id, severity = "RISK-01", CRITICAL
        title, why = "chain title", "chain why"
        chain = ["untrusted input", "exec"]

    findings = [_finding("B1", FAIL), _finding("B2", WARN)]
    data = render_pdf(
        findings, compute(findings),
        risk=[_RiskPath()],
        behavioral=_Phase("nothing fired"),
        adjudication=_Phase("nothing in the borderline band"),
    )
    text = _content_text(data)
    for title in ("RISK chains", "Behavioural", "Second opinion", "Coverage of OpenClaw surfaces"):
        assert title in text, f"{title!r} missing from the PDF"
    # Parens are escaped in a PDF literal — assert on the escaped form, not the raw one.
    assert r"Second opinion \(advisory\)" in text


def test_coverage_block_header_is_not_drawn_twice():
    """_coverage_lines carries its own text rule; the PDF must not print the title twice."""
    findings = [_finding("B1", FAIL)]
    text = _content_text(render_pdf(findings, compute(findings)))
    assert text.count("Coverage of OpenClaw surfaces") == 1
