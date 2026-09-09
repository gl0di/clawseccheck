"""B-767: a check that crashed or timed out this run must be disclosed by EVERY
renderer -- text, json, sarif, html, pdf, card -- not just some of them.

Measured before this fix: render_report (text), render_html and pdf.render_pdf all
shared one disclosure ("N checks could not reach a reliable verdict this run..."),
render_json carried it structurally (`degraded_count` + per-finding
`engine_degraded`), but SARIF's `analysisCompleteness` block counted an
engine-degraded finding as an indistinguishable ordinary UNKNOWN, and
render_dashboard (the ONE artifact SKILL.md tells the agent to paste into chat)
never mentioned a degraded check at all. Both gaps are closed alongside this test.

Offline, read-only; nothing is written outside pytest's tmp_path / in-memory bytes.
"""
from __future__ import annotations

import json
from pathlib import Path

from _pdftext import content_text

import clawseccheck.checks as checks
from clawseccheck.collector import collect
from clawseccheck.pdf import render_pdf
from clawseccheck.report import render_dashboard, render_html, render_json, render_report
from clawseccheck.sarif import render_sarif
from clawseccheck.scoring import compute

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_DISCLOSURE = "could not reach a reliable verdict"


def _boom(ctx):
    raise RuntimeError("engineered crash for the B-767 cross-renderer guard")


def test_all_six_renderers_disclose_an_engine_degraded_check(monkeypatch):
    monkeypatch.setattr(checks, "CHECKS", list(checks.CHECKS) + [_boom])

    # home_vuln (not home_safe): a real CRITICAL FAIL (A1) already caps the score at
    # FAIL_CAPS[CRITICAL] == 49 == DEGRADED_CHECK_CAP, so the crash's OWN cap never
    # additionally lowers the score -- `degraded_capped` stays False even though
    # `degraded_count` is nonzero. That is deliberate, not incidental: render_report's
    # own disclosure is written to fire "regardless of whether DEGRADED_CHECK_CAP ended
    # up strictly binding" (its own comment), specifically so a worse cap can never mask
    # a degraded check. A home_safe-only version of this guard cannot tell that
    # unconditional design from a renderer that only mentions the crash when it happens
    # to be picked as the cap-cascade's PRIMARY reason -- measured directly: with
    # home_safe, DEGRADED_CHECK_CAP alone WAS primary, so removing the dedicated card
    # disclosure line still passed (the pre-existing conditional cap-cascade text
    # happened to say "could not reach a reliable verdict" too, by coincidence).
    ctx = collect(FIXTURES / "home_vuln")
    findings = checks.run_all(ctx)
    score = compute(findings)

    # Sanity: the engineered crash actually produced what the rest of this test
    # exercises, and the scenario is the harder one described above, not the one
    # where any renderer's disclosure would pass by coincidence.
    degraded_ids = [f.id for f in findings if getattr(f, "engine_degraded", False)]
    assert degraded_ids, "the engineered crash must produce an engine_degraded finding"
    assert getattr(score, "degraded_count", 0) >= 1
    assert getattr(score, "cap_severity", None) == "CRITICAL", (
        "fixture must carry a real CRITICAL FAIL for the scenario below to hold"
    )
    assert getattr(score, "degraded_capped", None) is False, (
        "the crash must NOT be the binding cap -- otherwise this guard cannot tell a "
        "renderer's real unconditional disclosure from an incidental one"
    )

    # --- text ---------------------------------------------------------------
    text = render_report(findings, score, ctx=ctx)
    assert _DISCLOSURE in text, "text report dropped the degraded-check disclosure"

    # --- json -----------------------------------------------------------------
    payload = json.loads(render_json(findings, score, ctx=ctx))
    assert payload.get("degraded_count", 0) >= 1
    assert any(f.get("engine_degraded") for f in payload["findings"]), (
        "no finding in --json carries engine_degraded: true"
    )

    # --- sarif ------------------------------------------------------------
    sarif_doc = json.loads(render_sarif(findings, score, ctx=ctx))
    ac = sarif_doc["runs"][0]["properties"]["analysisCompleteness"]
    assert ac["engineDegradedCount"] >= 1, "SARIF analysisCompleteness never counted the crash"
    assert any("crashed or timed out" in line for line in ac["limitations"])

    # --- html ---------------------------------------------------------------
    html = render_html(findings, score, ctx=ctx)
    assert _DISCLOSURE in html, "HTML report dropped the degraded-check disclosure"

    # --- pdf ------------------------------------------------------------------
    pdf_bytes = render_pdf(findings, score, ctx=ctx)
    pdf_text = content_text(pdf_bytes)
    assert _DISCLOSURE in pdf_text, "PDF report dropped the degraded-check disclosure"

    # --- card (chat dashboard) -- the gap this task actually closes --------
    card = render_dashboard(findings, score, ctx=ctx)
    assert _DISCLOSURE in card, (
        "the chat card -- the one artifact SKILL.md tells the agent to paste -- "
        "never disclosed the degraded check"
    )
