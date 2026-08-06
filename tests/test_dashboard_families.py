"""render_report grouping (F-044 + C-372): findings grouped by Inventory SUBJECT
(OpenClaw core / Host / Agents / Skills / MCP / Channels / Logs) instead of a flat
severity list, and the Lethal Trifecta (A1) folded into its subject (Agents, via the
"trifecta" surface) instead of a standalone headline. C-372 promoted the report/HTML/PDF
detail view from the 7-family taxonomy to the 8-subject one; the summary already led with
"Inventory by subject" (F-131).

All tests are offline and deterministic — no network calls, no file writes.
"""
from __future__ import annotations

from clawseccheck.catalog import CRITICAL, HIGH, FAIL, MEDIUM, PASS, UNKNOWN, WARN, Finding
from clawseccheck.report import render_report
from clawseccheck.scoring import compute


def _f(id_, status, severity=HIGH, **kw):
    return Finding(id=id_, title=f"title {id_}", severity=severity, status=status,
                   detail=f"detail {id_}", fix=f"fix {id_}", framework="Test", **kw)


def test_no_standalone_trifecta_headline():
    """The old '⛔ Lethal Trifecta: 3/3' headline chip must be gone."""
    a1 = _f("A1", FAIL, CRITICAL, evidence=["untrusted input", "sensitive data", "outbound actions"])
    out = render_report([a1], compute([a1]))
    assert "Lethal Trifecta: 3/3" not in out


def test_trifecta_finding_lands_under_agents():
    a1 = _f("A1", FAIL, CRITICAL, evidence=["untrusted input", "sensitive data", "outbound actions"])
    out = render_report([a1], compute([a1]))
    assert "│ Agents" in out
    idx_subject = out.index("│ Agents")
    # rindex: the FIX FIRST block (B-077) also names the top finding near the top of
    # the report — the grouped listing is the LAST occurrence of the title.
    idx_finding = out.rindex("title A1")
    assert idx_finding > idx_subject


def test_findings_grouped_by_real_catalog_subject():
    """A1 (trifecta surface) groups under Agents; B2 (gateway surface) under OpenClaw core."""
    a1 = _f("A1", FAIL, CRITICAL, evidence=["untrusted input", "sensitive data", "outbound actions"])
    b2 = _f("B2", FAIL, CRITICAL)
    out = render_report([a1, b2], compute([a1, b2]))
    openclaw_idx = out.index("│ OpenClaw core")
    agents_idx = out.index("│ Agents")
    # rindex: FIX FIRST (B-077) may repeat the top finding's title before the
    # grouped listing — position checks target the LAST (grouped) occurrence.
    a1_title_idx = out.rindex("title A1")
    b2_title_idx = out.rindex("title B2")
    # OpenClaw core renders before Agents (fixed SUBJECT_ORDER)
    assert openclaw_idx < agents_idx
    # each finding sits inside its own subject's section, not the other's
    assert openclaw_idx < b2_title_idx < agents_idx
    assert agents_idx < a1_title_idx


def test_unknown_findings_tallied_not_enumerated():
    """A pile of UNKNOWN findings collapses to one count line, not N separate titles."""
    # Synthetic ids outside CATALOG all fall into the same "Other" bucket, so the
    # tally is deterministic regardless of how real check ids are spread across families.
    unknowns = [_f(f"X{i}", UNKNOWN, MEDIUM) for i in range(10)]
    out = render_report(unknowns, compute(unknowns))
    assert "10 not assessed" in out
    # none of the individual UNKNOWN titles should be spelled out
    for f in unknowns:
        assert f"title {f.id}" not in out


def test_pass_findings_shown_compact_no_why_fix():
    p = _f("B3", PASS, HIGH)
    out = render_report([p], compute([p]))
    assert "title B3" in out
    assert "why: detail B3" not in out
    assert "fix: fix B3" not in out


def test_fail_warn_findings_keep_why_but_no_fix():
    w = _f("B4", WARN, HIGH)
    out = render_report([w], compute([w]))
    assert "title B4" in out
    assert "why: detail B4" in out
    assert "fix:" not in out  # reports-only (F-074)


def test_all_suppressed_still_shows_clean_message():
    supp = _f("B1", FAIL, CRITICAL, suppressed=True)
    out = render_report([supp], compute([supp]))
    assert "No known attack pattern matched. Keep it that way." in out
    assert "[Secrets & Data]" not in out


def test_unrecognized_id_falls_back_to_other_bucket_not_dropped():
    """A finding whose id isn't in CATALOG (e.g. a native-audit passthrough) must still render."""
    f = _f("NATIVE-1", FAIL, HIGH)
    out = render_report([f], compute([f]))
    assert "title NATIVE-1" in out


def test_subject_header_says_clear_when_nothing_to_fix_in_that_subject():
    p = _f("B3", PASS, HIGH)  # B3 -> tools -> OpenClaw core
    out = render_report([p], compute([p]))
    assert "│ OpenClaw core — clear" in out


def test_ascii_only_keeps_bracket_format():
    """ascii_only=True must produce the legacy [Subject] - … bracket format, not the framed one."""
    b2 = _f("B2", FAIL, CRITICAL)  # gateway -> OpenClaw core
    p = _f("C5", PASS, HIGH)       # host -> Host machine
    out = render_report([b2, p], compute([b2, p]), ascii_only=True)
    assert "[OpenClaw core]" in out
    assert "[Host machine] - clear" in out
    # framed chars must not appear in ascii output
    assert "┌" not in out
    assert "│ OpenClaw core" not in out
    assert "└" not in out
