"""B-1068: an HTML report written by the ``--dashboard --full`` run must carry the same
pipeline blocks the PDF of that run carries - above all "Second opinion (advisory)".

Before: ``render_html`` had no risk/behavioral/adjudication parameter at all, and the
dashboard wrote its ``--html`` side output BEFORE the adjudication phase ran, so an HTML
and a PDF built from one judged bundle disagreed: the PDF listed the panel's verdicts, the
HTML had no second-opinion block (and no RISK chains / Behavioural / Worth a glance).
"""
from __future__ import annotations

import json
import re
import zlib
from pathlib import Path

from clawseccheck.cli import main
from clawseccheck.report import render_html

REPO = Path(__file__).resolve().parents[1]
VULN = REPO / "fixtures" / "home_vuln"
OPT_OUT = ["--no-native", "--no-host", "--no-sockets", "--no-deptree", "--no-dist",
           "--no-history"]


def _pdf_text(path: Path) -> str:
    raw = path.read_bytes()
    out = []
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", raw, re.S):
        body = m.group(1)
        try:
            body = zlib.decompress(body)
        except zlib.error:
            pass
        out.extend(x.decode("latin-1") for x in re.findall(rb"\((.*?)\)\s*Tj", body))
    return " ".join(out)


def test_html_and_pdf_from_one_judged_run_carry_the_same_pipeline_blocks(tmp_path, capsys):
    bundle = tmp_path / "bundle.json"
    bundle.write_text(json.dumps({"judged": {"verdicts": []}}), encoding="utf-8")
    html_out, pdf_out = tmp_path / "r.html", tmp_path / "r.pdf"
    rc = main(["--home", str(VULN), "--dashboard", "--full", "--judged-bundle", str(bundle),
               "--html", str(html_out), "--pdf", str(pdf_out),
               "--data-dir", str(tmp_path / "store"), *OPT_OUT])
    capsys.readouterr()
    assert rc in (0, 1, 2)
    html = html_out.read_text(encoding="utf-8")
    pdf = _pdf_text(pdf_out)
    for title in ("Second opinion (advisory)", "RISK chains", "Behavioural",
                  "Worth a glance"):
        if title in pdf:
            assert title in html, f"{title!r} is in the PDF but not in the HTML"
    assert "Second opinion (advisory)" in html


def test_a_plain_html_page_is_unchanged_without_pipeline_phases():
    from clawseccheck import audit
    ctx, findings, score = audit(VULN)
    page = render_html(findings, score, ctx=ctx)
    assert 'class="pipeline"' not in page
