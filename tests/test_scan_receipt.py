"""Tests for compute_scan_receipt (scan receipt / Merkle-root hash over findings)."""
import hashlib


from clawseccheck.catalog import Finding
from clawseccheck.report import compute_scan_receipt


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
