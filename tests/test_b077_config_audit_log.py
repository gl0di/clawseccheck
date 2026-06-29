from pathlib import Path
from clawseccheck.catalog import CATALOG, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_config_audit_log
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(home):
    return Context(home=Path(home))


def test_b77_unknown_when_log_absent():
    f = check_config_audit_log(_ctx("/nonexistent"))
    assert f.id == "B77" and f.status == UNKNOWN


def test_b77_pass_clean():
    f = check_config_audit_log(_ctx(FIXTURES / "clean_b77_audit"))
    assert f.status == PASS


def test_b77_warn_suspicious_entry():
    f = check_config_audit_log(_ctx(FIXTURES / "bad_b77_suspicious"))
    assert f.status == WARN
    assert any("suspicious" in e for e in f.evidence)


def test_b77_warn_unexpected_writer():
    f = check_config_audit_log(_ctx(FIXTURES / "bad_b77_writer"))
    assert f.status == WARN
    assert any("unexpected process" in e for e in f.evidence)
    assert not any("/tmp/" in e for e in f.evidence)


def test_b77_meta_advisory_medium():
    m = next(c for c in CATALOG if c.id == "B77")
    assert m.scored is False
    assert m.severity == "MEDIUM"
    assert m.confidence == "MEDIUM"
    assert m.surface == "monitoring"
