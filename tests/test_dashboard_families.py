"""Dashboard family grouping (F-044): findings grouped by OpenClaw surface family
instead of a flat severity list, and the Lethal Trifecta (A1) folded into
Privilege & Execution instead of a standalone headline.

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


def test_trifecta_finding_lands_under_privilege_and_execution():
    a1 = _f("A1", FAIL, CRITICAL, evidence=["untrusted input", "sensitive data", "outbound actions"])
    out = render_report([a1], compute([a1]))
    assert "│ Privilege & Execution" in out
    idx_family = out.index("│ Privilege & Execution")
    # rindex: the FIX FIRST block (B-077) also names the top finding near the top of
    # the report — the grouped listing is the LAST occurrence of the title.
    idx_finding = out.rindex("title A1")
    assert idx_finding > idx_family


def test_findings_grouped_by_real_catalog_family():
    """B1 (secrets surface) groups under Secrets & Data; B2 (gateway) under Exposure & Network."""
    b1 = _f("B1", FAIL, CRITICAL)
    b2 = _f("B2", FAIL, CRITICAL)
    out = render_report([b1, b2], compute([b1, b2]))
    exposure_idx = out.index("│ Exposure & Network")
    secrets_idx = out.index("│ Secrets & Data")
    # rindex: FIX FIRST (B-077) may repeat the top finding's title before the
    # grouped listing — position checks target the LAST (grouped) occurrence.
    b1_title_idx = out.rindex("title B1")
    b2_title_idx = out.rindex("title B2")
    # Exposure & Network renders before Secrets & Data (fixed FAMILY_ORDER)
    assert exposure_idx < secrets_idx
    # each finding sits inside its own family's section, not the other's
    assert exposure_idx < b2_title_idx < secrets_idx
    assert secrets_idx < b1_title_idx


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


def test_fail_warn_findings_keep_full_detail():
    w = _f("B4", WARN, HIGH)
    out = render_report([w], compute([w]))
    assert "title B4" in out
    assert "why: detail B4" in out
    assert "fix: fix B4" in out


def test_all_suppressed_still_shows_clean_message():
    supp = _f("B1", FAIL, CRITICAL, suppressed=True)
    out = render_report([supp], compute([supp]))
    assert "No issues found by ClawSecCheck. Keep it that way." in out
    assert "[Secrets & Data]" not in out


def test_unrecognized_id_falls_back_to_other_bucket_not_dropped():
    """A finding whose id isn't in CATALOG (e.g. a native-audit passthrough) must still render."""
    f = _f("NATIVE-1", FAIL, HIGH)
    out = render_report([f], compute([f]))
    assert "title NATIVE-1" in out


def test_family_header_says_clear_when_nothing_to_fix_in_that_family():
    p = _f("B3", PASS, HIGH)
    out = render_report([p], compute([p]))
    assert "│ Privilege & Execution — clear" in out


def test_ascii_only_keeps_bracket_format():
    """ascii_only=True must produce the legacy [Family] - … bracket format, not the framed one."""
    p = _f("B3", PASS, HIGH)
    b2 = _f("B2", FAIL, CRITICAL)
    out = render_report([p, b2], compute([p, b2]), ascii_only=True)
    assert "[Exposure & Network]" in out
    assert "[Privilege & Execution] - clear" in out
    # framed chars must not appear in ascii output
    assert "┌" not in out
    assert "│ Exposure" not in out
    assert "└" not in out
