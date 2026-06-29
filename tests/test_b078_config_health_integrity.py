from pathlib import Path
from clawseccheck.catalog import CATALOG, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_config_health_integrity
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(home):
    return Context(home=Path(home))


def test_b78_unknown_when_file_absent():
    f = check_config_health_integrity(_ctx("/nonexistent"))
    assert f.id == "B78" and f.status == UNKNOWN


def test_b78_pass_clean():
    f = check_config_health_integrity(_ctx(FIXTURES / "clean_b78_health"))
    assert f.status == PASS


def test_b78_warn_suspicious_signature():
    f = check_config_health_integrity(_ctx(FIXTURES / "bad_b78_health"))
    assert f.status == WARN
    assert f.evidence
    assert not any("sig-deadbeef" in e or "/home/" in e for e in f.evidence)


def test_b78_meta_high_advisory():
    m = next(c for c in CATALOG if c.id == "B78")
    assert m.scored is False
    assert m.severity == "HIGH"
    assert m.surface == "monitoring"
