"""B-588: a severity tally has to say what it counts.

The PDF's and the HTML's page-one blocks rendered the severity half alone::

    CRITICAL 2
    HIGH 8
    MEDIUM 16
    LOW 13

while the text report, on the same run, said::

    (3 FAIL, 36 WARN — incl. 2 CRITICAL, 8 HIGH, 16 MEDIUM, 13 LOW)

So a reader of the *attachable* deliverable — the copy that travels furthest from whoever
ran it, and whose first page is the part that gets read — takes `CRITICAL 2` for two
critical FAILURES. That run's `--json` split was `fail_counts_by_severity = {"critical":
1, "high": 2}`: one of the two CRITICALs was a WARN, and six of the eight HIGHs were.

Fixed at the producer (`report.issue_population_line`), consumed by all three surfaces, so
the wording cannot drift apart again. The chips are unchanged — a severity ramp over
FAIL+WARN is the right population to show; only the label was missing.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import re
import subprocess
import sys
import zlib
from pathlib import Path

from clawseccheck.catalog import CRITICAL, FAIL, HIGH, LOW, PASS, WARN, Finding
from clawseccheck.report import issue_population_line, render_html
from clawseccheck.scoring import compute

REPO_ROOT = Path(__file__).resolve().parents[1]
VULN = str(REPO_ROOT / "fixtures" / "home_vuln")


def _f(fid: str, status: str, severity: str) -> Finding:
    return Finding(id=fid, title=fid, severity=severity, status=status,
                   detail="d", fix="f", framework="x")


def _run(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", VULN,
         "--data-dir", str(tmp_path / "state"), "--no-history", *args],
        cwd=REPO_ROOT, capture_output=True, text=True)


def _pdf_text(path: Path) -> list[str]:
    raw = path.read_bytes()
    out: list[str] = []
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", raw, re.S):
        data = m.group(1)
        try:
            data = zlib.decompress(data)
        except Exception:
            pass
        for tj in re.finditer(rb"\((?:\\.|[^\\()])*\)\s*Tj", data):
            parts = re.findall(rb"\((?:\\.|[^\\()])*\)", tj.group(0))
            out.append(b"".join(p[1:-1] for p in parts).decode("latin-1"))
    return out


# ------------------------------------------------------------------ the producer

def test_the_line_names_both_halves():
    """The whole defect in one assertion: the severity numbers are meaningless without
    the FAIL/WARN split in front of them."""
    # 1 FAIL + 2 WARN, and the CRITICAL row is itself mixed — the exact shape a bare
    # `CRITICAL 2` misreads.
    issues = [_f("A1", FAIL, CRITICAL), _f("B9", WARN, CRITICAL), _f("B3", WARN, HIGH)]
    assert issue_population_line(issues) == "1 FAIL, 2 WARN — incl. 2 CRITICAL, 1 HIGH"


def test_a_critical_warn_is_counted_not_hidden():
    """C-135: the tempting wrong fix is to make the chips count FAILs only, which would
    make the label true and the numbers wrong. A CRITICAL WARN is exactly the finding
    page one most needs to carry."""
    line = issue_population_line([_f("B9", WARN, CRITICAL)])
    assert line == "0 FAIL, 1 WARN — incl. 1 CRITICAL"


def test_severities_that_do_not_occur_are_omitted():
    assert issue_population_line([_f("B9", FAIL, LOW)]) == "1 FAIL, 0 WARN — incl. 1 LOW"


def test_nothing_to_describe_renders_nothing():
    assert issue_population_line([]) == ""
    assert issue_population_line([_f("B2", PASS, HIGH)]) == ""


def test_the_order_is_worst_first():
    issues = [_f("a", WARN, LOW), _f("b", WARN, CRITICAL), _f("c", WARN, HIGH)]
    assert issue_population_line(issues).endswith("1 CRITICAL, 1 HIGH, 1 LOW")


# ------------------------------------------------------------- the three surfaces

def test_the_pdf_page_one_states_the_population(tmp_path):
    """The deliverable the defect was really about."""
    dest = tmp_path / "r.pdf"
    _run(tmp_path, "--pdf", str(dest))
    lines = _pdf_text(dest)
    assert any(ln.startswith("CRITICAL ") for ln in lines), "the chips must remain"
    # The em dash folds to "-" here: pdf.py ships base-14 fonts only (see textnorm.asciify).
    assert any(re.match(r"\d+ FAIL, \d+ WARN - incl\. ", ln) for ln in lines), lines[:14]


def test_the_html_states_the_population(tmp_path):
    dest = tmp_path / "r.html"
    _run(tmp_path, "--html", str(dest))
    html = dest.read_text(encoding="utf-8")
    assert re.search(r'summary-population">\d+ FAIL, \d+ WARN — incl\. ', html)


def test_all_three_surfaces_report_the_same_numbers(tmp_path):
    """A per-surface fix is how they drift; the guarantee is that they agree."""
    pdf, html = tmp_path / "a.pdf", tmp_path / "a.html"
    text = _run(tmp_path, "--save", str(tmp_path / "a.txt")).stdout
    _run(tmp_path, "--pdf", str(pdf))
    _run(tmp_path, "--html", str(html))

    pat = r"(\d+) FAIL, (\d+) WARN [—-] incl\. ([^)\n<]+)"
    from_text = re.search(pat, text)
    from_pdf = next((re.match(pat, ln) for ln in _pdf_text(pdf) if re.match(pat, ln)), None)
    from_html = re.search(pat, html.read_text(encoding="utf-8"))
    assert from_text and from_pdf and from_html
    assert from_text.group(1, 2) == from_pdf.group(1, 2) == from_html.group(1, 2)
    assert from_text.group(3).strip() == from_pdf.group(3).strip()


def test_the_html_omits_the_caption_when_there_is_nothing_to_count():
    """No issues means no chips and no orphan label — never an empty div with a stray
    "0 FAIL, 0 WARN"."""
    html = render_html([], compute([]))
    assert 'summary-population">' not in html


def test_the_text_report_line_is_byte_identical(tmp_path):
    """The wording moved into a shared producer; the surface that already had it right
    must not have changed by a character."""
    text = _run(tmp_path, "--save", str(tmp_path / "b.txt")).stdout
    assert re.search(r"^\(\d+ FAIL, \d+ WARN — incl\. .+\)$", text, re.M)


def test_the_pdf_stays_deterministic(tmp_path):
    """pdf.py embeds no timestamp, which is what lets a CI diff the artifact. A caption
    built from a re-derived tally could have broken that quietly."""
    one, two = tmp_path / "1.pdf", tmp_path / "2.pdf"
    _run(tmp_path, "--pdf", str(one))
    _run(tmp_path, "--pdf", str(two))
    assert one.read_bytes() == two.read_bytes()


def test_the_fixture_really_is_a_mixed_population(tmp_path):
    """Guards the premise, not just the rendering: if `fixtures/home_vuln` ever became
    all-FAIL at every severity, these tests would still pass while demonstrating nothing.
    Today its HIGH row is 4 FAIL + 4 WARN — the exact shape a bare `HIGH 8` misreads."""
    import json
    payload = json.loads(_run(tmp_path, "--json").stdout)
    issues = [f for f in payload["findings"]
              if f["status"] in ("FAIL", "WARN") and not f.get("suppressed")]
    highs = [f for f in issues if f["severity"] == HIGH]
    assert any(f["status"] == FAIL for f in highs)
    assert any(f["status"] == WARN for f in highs), "premise gone: no mixed severity row"
    assert payload["fail_counts_by_severity"]["high"] < len(highs)
