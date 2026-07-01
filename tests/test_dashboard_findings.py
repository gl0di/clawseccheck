"""Unit tests for render_dashboard_findings (Section 3 dashboard block).

All tests are offline and deterministic — no network calls, no file writes.
"""
from __future__ import annotations

from clawseccheck.catalog import (
    ATTESTED, CRITICAL, FAIL, HIGH, MEDIUM, PASS, UNKNOWN, Finding,
)
from clawseccheck.report import render_dashboard_findings


def _f(id_: str, status: str, severity: str = HIGH, **kw) -> Finding:
    """Build a minimal Finding for testing."""
    return Finding(
        id=id_,
        title=f"title {id_}",
        severity=severity,
        status=status,
        detail=f"detail {id_}",
        fix=f"fix {id_}",
        framework="Test",
        **kw,
    )


# ─── 1. Open 3-sided frame ──────────────────────────────────────────────────

def test_emits_open_three_sided_frame():
    """Exposure FAIL: frame has ┌, │ label, └ — but NO closed right border."""
    f = _f("B2", FAIL, CRITICAL)   # B2 -> gateway -> exposure
    out = render_dashboard_findings([f])

    assert "┌" in out
    assert "│ Exposure & Network — 1 to fix" in out
    assert "└" in out

    # The open 3-sided box must NOT close the right side
    assert "to fix │" not in out
    assert "to fix|" not in out


# ─── 2. Only FAIL and WARN pass through ────────────────────────────────────

def test_only_fail_and_warn():
    """PASS and UNKNOWN titles must be absent; FAIL title+detail+fix must be present."""
    pass_f   = _f("B3",   PASS,    HIGH)
    unknown_f = _f("B4",  UNKNOWN, HIGH)
    fail_f   = _f("B2",   FAIL,    CRITICAL)

    out = render_dashboard_findings([pass_f, unknown_f, fail_f])

    # PASS/UNKNOWN must not appear
    assert "title B3" not in out
    assert "title B4" not in out
    assert "not assessed" not in out

    # FAIL must appear with full detail
    assert "title B2" in out
    assert "why: detail B2" in out
    assert "fix: fix B2" in out


# ─── 3. MEDIUM and ATTESTED confidence excluded ────────────────────────────

def test_medium_and_attested_excluded():
    """MEDIUM/ATTESTED-confidence FAILs are excluded; HIGH-confidence FAIL is present."""
    med_fail     = _f("B2",   FAIL, CRITICAL, confidence=MEDIUM)
    attested_fail = _f("B3",  FAIL, HIGH,     confidence=ATTESTED)
    high_fail    = _f("B15",  FAIL, HIGH,     confidence="HIGH")  # mcp -> supply_chain

    out = render_dashboard_findings([med_fail, attested_fail, high_fail])

    # MEDIUM and ATTESTED titles must be absent
    assert "title B2" not in out
    assert "title B3" not in out

    # HIGH-confidence FAIL must appear
    assert "title B15" in out


# ─── 4. Empty families are omitted ─────────────────────────────────────────

def test_empty_families_omitted():
    """When findings land only in Exposure, other family headers must not appear."""
    f = _f("B2", FAIL, CRITICAL)   # exposure only

    out = render_dashboard_findings([f])

    assert "Privilege & Execution" not in out
    assert "Supply Chain" not in out
    assert "— clear" not in out


# ─── 5. A1 lands under Privilege & Execution ───────────────────────────────

def test_a1_lands_under_privilege():
    """A1 (Lethal Trifecta) routes to Privilege & Execution, not a standalone headline."""
    a1 = _f("A1", FAIL, CRITICAL,
             evidence=["untrusted input", "sensitive data", "outbound actions"])

    out = render_dashboard_findings([a1])

    assert "│ Privilege & Execution" in out
    priv_idx = out.index("│ Privilege & Execution")
    title_idx = out.index("title A1")
    assert title_idx > priv_idx


# ─── 6. Suppressed findings excluded ───────────────────────────────────────

def test_suppressed_excluded():
    """A suppressed FAIL must be absent; if it's the only finding the OK message appears."""
    supp = _f("B2", FAIL, CRITICAL, suppressed=True)

    out = render_dashboard_findings([supp])

    assert "title B2" not in out
    assert "No high-confidence issues to fix." in out


# ─── 7. Severity order within a family ─────────────────────────────────────

def test_severity_order_within_family():
    """CRITICAL must appear before HIGH within the same family."""
    # B2 and B11 both map to gateway -> exposure
    high_f     = _f("B11",  FAIL, HIGH)
    critical_f = _f("B2",   FAIL, CRITICAL)

    out = render_dashboard_findings([high_f, critical_f])

    crit_idx = out.index("title B2")
    high_idx = out.index("title B11")
    assert crit_idx < high_idx


# ─── 8. ascii_only uses bracket format ────────────────────────────────────

def test_ascii_only_uses_brackets():
    """ascii_only=True: [Exposure & Network] bracket, no box chars, no unicode icons."""
    f = _f("B2", FAIL, CRITICAL)

    out = render_dashboard_findings([f], ascii_only=True)

    assert "[Exposure & Network]" in out

    # Box-drawing and unicode icons must be absent
    assert "┌" not in out
    assert "│ Exposure" not in out
    assert "└" not in out
    assert "⛔" not in out


# ─── 9. No qualifying findings → clean message ─────────────────────────────

def test_no_qualifying_findings_message():
    """Only PASS/UNKNOWN → 'No high-confidence issues to fix.' with no frame chars."""
    p = _f("B3", PASS,    HIGH)
    u = _f("B4", UNKNOWN, HIGH)

    out = render_dashboard_findings([p, u])

    assert "No high-confidence issues to fix." in out
    assert "┌" not in out
    assert "└" not in out
    assert "│" not in out
