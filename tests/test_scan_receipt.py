"""Tests for compute_scan_receipt (scan receipt / Merkle-root hash over findings)."""
import dataclasses
import hashlib


from clawseccheck.catalog import Finding
from clawseccheck.report import _SCAN_RECEIPT_FIELDS, compute_scan_receipt


def _make_finding(
    id: str = "B1",
    title: str = "Test finding",
    severity: str = "HIGH",
    status: str = "FAIL",
    detail: str = "something bad happened",
    fix: str = "fix it now",
    framework: str = "test",
) -> Finding:
    return Finding(
        id=id,
        title=title,
        severity=severity,
        status=status,
        detail=detail,
        fix=fix,
        framework=framework,
    )


def test_compute_deterministic():
    """Same findings in different order produce the same receipt."""
    f1 = _make_finding(id="B1", detail="issue one", severity="HIGH")
    f2 = _make_finding(id="B2", detail="issue two", severity="CRITICAL")
    assert compute_scan_receipt([f1, f2]) == compute_scan_receipt([f2, f1])


def test_empty_findings():
    """Empty list returns sha256 of empty bytes as a hex string."""
    expected = hashlib.sha256(b"").hexdigest()
    assert compute_scan_receipt([]) == expected


def test_different_findings_different_receipt():
    """Findings that differ in detail or severity produce a different receipt."""
    f1 = _make_finding(id="B1", detail="issue alpha", severity="HIGH")
    f2 = _make_finding(id="B1", detail="issue beta", severity="CRITICAL")
    assert compute_scan_receipt([f1]) != compute_scan_receipt([f2])


def test_never_raises():
    """compute_scan_receipt(None) and compute_scan_receipt([]) must not raise."""
    result_none = compute_scan_receipt(None)
    result_empty = compute_scan_receipt([])
    assert isinstance(result_none, str)
    assert isinstance(result_empty, str)


def test_hex_format():
    """Receipt returned for a non-empty list is a 64-char lowercase hex string."""
    f = _make_finding()
    result = compute_scan_receipt([f])
    assert len(result) == 64
    assert all(c in "0123456789abcdef" for c in result)


# ---------------------------------------------------------------------------
# B-756: every field the digest claims to cover actually exists on Finding, and
# actually moves the receipt. The pre-fix version read check_id/rule_id/verdict/path/
# file/line — none of which Finding ever had — through a `getattr(..., default)` that
# silently hid the miss, so the receipt only ever moved on `detail` (and `severity`,
# via the `verdict` fallback): flipping every finding's status to PASS, or renaming
# every check id, left it byte-identical. Every test below is one that regime would
# have failed.
# ---------------------------------------------------------------------------

def test_scan_receipt_fields_all_exist_on_finding():
    """The digest must never again claim to cover a field Finding doesn't have — a
    `getattr` default is exactly what hid that the first time (B-756)."""
    real_fields = {f.name for f in dataclasses.fields(Finding)}
    missing = [name for name in _SCAN_RECEIPT_FIELDS if name not in real_fields]
    assert not missing, f"_SCAN_RECEIPT_FIELDS names field(s) Finding does not have: {missing}"


def test_scan_receipt_field_set_is_pinned():
    """Pin the exact key set so a silent rename cannot empty the digest's coverage
    again without this test going red."""
    assert set(_SCAN_RECEIPT_FIELDS) == {"id", "status", "severity", "title", "fix", "detail"}


def test_flipping_every_status_to_pass_moves_the_receipt():
    """The headline B-756 measurement: a report where every check failed and one
    where every check passed must NOT produce the same receipt."""
    findings = [_make_finding(id=f"B{i}", status="FAIL") for i in range(5)]
    passed = [dataclasses.replace(f, status="PASS") for f in findings]
    assert compute_scan_receipt(findings) != compute_scan_receipt(passed)


def test_renaming_every_check_id_moves_the_receipt():
    findings = [_make_finding(id=f"B{i}") for i in range(5)]
    renamed = [dataclasses.replace(f, id=f"X{f.id}") for f in findings]
    assert compute_scan_receipt(findings) != compute_scan_receipt(renamed)


def test_changing_every_title_moves_the_receipt():
    findings = [_make_finding(id=f"B{i}", title=f"title {i}") for i in range(5)]
    retitled = [dataclasses.replace(f, title=f"renamed {f.title}") for f in findings]
    assert compute_scan_receipt(findings) != compute_scan_receipt(retitled)


def test_changing_every_fix_text_moves_the_receipt():
    findings = [_make_finding(id=f"B{i}", fix=f"fix {i}") for i in range(5)]
    refixed = [dataclasses.replace(f, fix=f"do this instead: {f.fix}") for f in findings]
    assert compute_scan_receipt(findings) != compute_scan_receipt(refixed)


def test_status_pass_vs_fail_single_finding():
    """Narrower single-finding form of the headline measurement, isolating status
    alone with every other field held constant."""
    f_fail = _make_finding(id="B1", status="FAIL")
    f_pass = dataclasses.replace(f_fail, status="PASS")
    assert compute_scan_receipt([f_fail]) != compute_scan_receipt([f_pass])
