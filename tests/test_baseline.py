"""Baseline suppression via .clawseccheckignore."""
from clawseccheck import audit
from clawseccheck.baseline import apply, fingerprint, load_ignore
from clawseccheck.catalog import CRITICAL, FAIL, HIGH, PASS, WARN, Finding
from clawseccheck.report import render_json, render_report
from clawseccheck.scoring import compute


def _f(cid, severity, status, detail="d"):
    return Finding(cid, "t", severity, status, detail, "fix", "fw")


def test_fingerprint_stable_and_detail_sensitive():
    assert fingerprint(_f("B14", WARN, WARN, "same")) == fingerprint(_f("B14", WARN, WARN, "same"))
    assert fingerprint(_f("B14", WARN, WARN, "a")) != fingerprint(_f("B14", WARN, WARN, "b"))
    assert fingerprint(_f("B14", WARN, WARN)).startswith("B14:")


def test_load_ignore_parsing(tmp_path):
    (tmp_path / ".clawseccheckignore").write_text("# comment\n\nB14\nB2:ab12cd34\n  B7  \n")
    assert load_ignore(tmp_path) == {"B14", "B2:ab12cd34", "B7"}
    assert load_ignore(tmp_path / "nope") == set()


def test_apply_by_id_and_by_fingerprint():
    a, b = _f("B14", "MEDIUM", WARN), _f("B2", CRITICAL, FAIL, "x")
    apply([a, b], {"B14"})
    assert a.suppressed and not b.suppressed
    c = _f("B9", "MEDIUM", WARN, "y")
    apply([c], {fingerprint(c)})
    assert c.suppressed


def test_suppressed_critical_does_not_cap_score():
    keep = _f("B3", HIGH, PASS)
    supp = _f("B2", CRITICAL, FAIL, "x")
    supp.suppressed = True
    r = compute([keep, supp])
    assert r.score == 100 and r.capped is False




def test_suppressed_flag_in_json_output():
    supp = _f("B2", CRITICAL, FAIL, "gateway exposed")
    supp.suppressed = True
    out = render_json([supp], compute([supp]))
    assert '"suppressed": true' in out

def test_suppressed_excluded_from_report():
    supp = _f("B2", CRITICAL, FAIL, "x")
    supp.suppressed = True
    out = render_report([supp], compute([supp]))
    assert "No issues found" in out
    assert "1 finding(s) suppressed via .clawseccheckignore" in out


def test_audit_applies_clawseccheckignore(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}")
    _, findings, _ = audit(tmp_path)
    target = next(f for f in findings if f.status == WARN)
    (tmp_path / ".clawseccheckignore").write_text(target.id + "\n")
    _, findings2, _ = audit(tmp_path)
    assert next(f for f in findings2 if f.id == target.id).suppressed


# ---- governance warning: suppressing a CRITICAL finding ----

def test_suppressed_critical_severity_emits_governance_warning():
    """render_report warns when a CRITICAL-severity finding is suppressed."""
    supp = _f("B2", CRITICAL, FAIL, "gateway exposed")
    supp.suppressed = True
    out = render_report([supp], compute([supp]))
    assert "WARNING: a CRITICAL finding (B2) is suppressed" in out


def test_suppressed_critical_check_id_emits_governance_warning():
    """render_report warns when a sensitive check id (B1/B2/B13/B20) is suppressed,
    even when its severity is not CRITICAL (message now states the real severity)."""
    # B20 is MEDIUM severity but is a sensitive check id
    supp = _f("B20", "MEDIUM", WARN, "bootstrap world-writable")
    supp.suppressed = True
    out = render_report([supp], compute([supp]))
    assert "WARNING: a MEDIUM finding (B20) is suppressed" in out


def test_suppressed_high_severity_fail_emits_governance_warning():
    """Regression (H3): a suppressed HIGH FAIL caps the score at 79, so hiding it inflates
    the grade — it must still be surfaced, not silently dropped."""
    supp = _f("B22", HIGH, FAIL, "self-modification path")
    supp.suppressed = True
    out = render_report([supp], compute([supp]))
    assert "WARNING: a HIGH finding (B22) is suppressed" in out


def test_suppressed_non_critical_does_not_emit_governance_warning():
    """render_report must NOT warn when a non-critical finding is suppressed."""
    supp = _f("B14", "MEDIUM", WARN, "egress surface")
    supp.suppressed = True
    out = render_report([supp], compute([supp]))
    assert "WARNING: a CRITICAL finding" not in out


def test_suppressed_critical_warns_once_per_finding():
    """One warning line per suppressed critical finding, not duplicated."""
    s1 = _f("B1", CRITICAL, FAIL, "secret in config")
    s1.suppressed = True
    s2 = _f("B2", CRITICAL, FAIL, "gateway exposed")
    s2.suppressed = True
    out = render_report([s1, s2], compute([s1, s2]))
    assert out.count("WARNING: a CRITICAL finding (B1)") == 1
    assert out.count("WARNING: a CRITICAL finding (B2)") == 1
