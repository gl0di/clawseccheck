from pathlib import Path
from clawseccheck.catalog import CATALOG, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_session_approval_policy
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(home):
    return Context(home=Path(home))


def test_b79_unknown_when_no_sessions():
    f = check_session_approval_policy(_ctx("/nonexistent"))
    assert f.id == "B79" and f.status == UNKNOWN


def test_b79_pass_mixed_policy():
    f = check_session_approval_policy(_ctx(FIXTURES / "clean_b79_sessions"))
    assert f.status == PASS


def test_b79_warn_all_never():
    f = check_session_approval_policy(_ctx(FIXTURES / "bad_b79_sessions"))
    assert f.status == WARN
    assert any("approval_policy=never" in e for e in f.evidence)
    assert any("turns sampled" in e for e in f.evidence)


def test_b79_meta_advisory_tools():
    m = next(c for c in CATALOG if c.id == "B79")
    assert m.scored is False
    assert m.severity == "MEDIUM"
    assert m.surface == "tools"
