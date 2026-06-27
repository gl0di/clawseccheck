"""Tests for clawseccheck.dedup — two-pass confidence-based finding dedup."""
from __future__ import annotations

from types import SimpleNamespace


from clawseccheck.catalog import Finding, FAIL, WARN, PASS, UNKNOWN, HIGH, CRITICAL
from clawseccheck.dedup import deduplicate_findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(id_="B1", title="Test", severity=HIGH, status=FAIL,
             detail="some detail", fix="fix it", framework="F",
             confidence="HIGH", **kwargs) -> Finding:
    """Construct a minimal Finding for test use."""
    return Finding(
        id=id_, title=title, severity=severity, status=status,
        detail=detail, fix=fix, framework=framework,
        confidence=confidence, **kwargs
    )


def _ns(**kwargs):
    """Duck-type Finding with arbitrary extra fields (e.g. path, matched_text)."""
    defaults = dict(
        id="B1", title="T", severity=HIGH, status=FAIL,
        detail="detail", fix="fix", framework="F",
        confidence="HIGH", scored=True, evidence=[],
        suppressed=False, pass_confidence=None,
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# test_empty_list
# ---------------------------------------------------------------------------

def test_empty_list():
    assert deduplicate_findings([]) == []


# ---------------------------------------------------------------------------
# test_distinct_findings_preserved
# ---------------------------------------------------------------------------

def test_distinct_findings_preserved():
    f1 = _finding(id_="B1", detail="alpha detail")
    f2 = _finding(id_="B2", detail="beta detail")
    f3 = _finding(id_="B3", detail="gamma detail")
    result = deduplicate_findings([f1, f2, f3])
    assert len(result) == 3
    ids = {f.id for f in result}
    assert ids == {"B1", "B2", "B3"}


# ---------------------------------------------------------------------------
# test_pass1_same_file_dedup
# ---------------------------------------------------------------------------

def test_pass1_same_file_dedup_keeps_higher_confidence():
    """Two findings: same check id, same path, same detail → keep higher confidence."""
    low_conf = _ns(id="B5", detail="shared detail", confidence="MEDIUM", title="Low")
    high_conf = _ns(id="B5", detail="shared detail", confidence="HIGH", title="High")

    result = deduplicate_findings([low_conf, high_conf])
    assert len(result) == 1
    assert result[0].confidence == "HIGH"


def test_pass1_same_file_dedup_first_wins_when_equal_confidence():
    """When confidences are equal the first (incumbent) is kept."""
    f1 = _ns(id="B5", detail="shared detail", confidence="HIGH", title="First")
    f2 = _ns(id="B5", detail="shared detail", confidence="HIGH", title="Second")

    result = deduplicate_findings([f1, f2])
    assert len(result) == 1
    assert result[0].title == "First"


def test_pass1_different_detail_not_deduped():
    """Same check id but different detail text → both preserved."""
    f1 = _finding(id_="B5", detail="detail A")
    f2 = _finding(id_="B5", detail="detail B")
    result = deduplicate_findings([f1, f2])
    assert len(result) == 2


# ---------------------------------------------------------------------------
# test_pass2_cross_file_dedup
# ---------------------------------------------------------------------------

def test_pass2_cross_file_dedup_keeps_higher_confidence():
    """Two findings: same check id + detail, DIFFERENT path → cross-file dedup
    keeps the one with higher confidence."""
    low_conf = _ns(id="B7", path="/etc/a.json", detail="shared snippet",
                   confidence="MEDIUM", title="Low")
    high_conf = _ns(id="B7", path="/etc/b.json", detail="shared snippet",
                    confidence="HIGH", title="High")

    result = deduplicate_findings([low_conf, high_conf])
    assert len(result) == 1
    assert result[0].confidence == "HIGH"


def test_pass2_cross_file_different_check_ids_not_deduped():
    """Different check ids with same detail → NOT cross-file deduped."""
    f1 = _ns(id="B7", path="/a.json", detail="same text", confidence="HIGH")
    f2 = _ns(id="B8", path="/b.json", detail="same text", confidence="HIGH")
    result = deduplicate_findings([f1, f2])
    assert len(result) == 2


# ---------------------------------------------------------------------------
# test_no_matched_text_skips_pass2
# ---------------------------------------------------------------------------

def test_no_matched_text_skips_pass2():
    """Findings with empty detail are NOT cross-file deduped even with same check id."""
    f1 = _ns(id="B9", path="/a.json", detail="", confidence="MEDIUM")
    f2 = _ns(id="B9", path="/b.json", detail="", confidence="HIGH")
    # Both survive because there is no content fingerprint to match on.
    result = deduplicate_findings([f1, f2])
    assert len(result) == 2


def test_no_matched_text_finding_class_different_ids_preserved():
    """Plain Findings with different check ids and empty detail are both kept
    (no content fingerprint, different check ids → not merged by either pass)."""
    f1 = _finding(id_="B9", detail="")
    f2 = _finding(id_="B10", detail="")
    result = deduplicate_findings([f1, f2])
    assert len(result) == 2


# ---------------------------------------------------------------------------
# test_sort_order
# ---------------------------------------------------------------------------

def test_sort_order_fail_warn_pass():
    """Output is sorted FAIL → WARN → PASS regardless of input order."""
    p = _finding(id_="B1", status=PASS, detail="pass detail")
    w = _finding(id_="B2", status=WARN, detail="warn detail")
    f = _finding(id_="B3", status=FAIL, detail="fail detail")

    result = deduplicate_findings([p, w, f])
    statuses = [r.status for r in result]
    assert statuses == [FAIL, WARN, PASS]


def test_sort_order_unknown_last():
    """UNKNOWN findings sort after PASS."""
    u = _finding(id_="B4", status=UNKNOWN, detail="unknown detail")
    p = _finding(id_="B1", status=PASS, detail="pass detail")
    f = _finding(id_="B3", status=FAIL, detail="fail detail")

    result = deduplicate_findings([u, p, f])
    assert result[0].status == FAIL
    assert result[-1].status == UNKNOWN


def test_sort_order_severity_within_fail():
    """Within FAIL, CRITICAL sorts before HIGH."""
    high_fail = _finding(id_="B1", severity=HIGH, status=FAIL, detail="high fail")
    crit_fail = _finding(id_="B2", severity=CRITICAL, status=FAIL, detail="crit fail")

    result = deduplicate_findings([high_fail, crit_fail])
    assert result[0].severity == CRITICAL
    assert result[1].severity == HIGH
