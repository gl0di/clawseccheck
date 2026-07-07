"""B135 — accepted-despite-failed-verification skill install (.clawhub/lock.json)."""
from pathlib import Path

from clawseccheck.catalog import CATALOG, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_clawhub_lock_verification
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(home):
    return Context(home=Path(home))


def test_warn_rejected_skill_installed_anyway():
    f = check_clawhub_lock_verification(_ctx(FIXTURES / "bad_b135_clawhub_lock_reject"))
    assert f.id == "B135"
    assert f.status == WARN
    assert any("sketchy-skill" in e for e in f.evidence)
    assert any("card.missing" in e for e in f.evidence)


def test_pass_verified_skill():
    f = check_clawhub_lock_verification(_ctx(FIXTURES / "clean_b135_clawhub_lock_pass"))
    assert f.id == "B135"
    assert f.status == PASS


def test_pass_unsigned_alone_does_not_warn_when_decision_is_pass():
    """Regression guard: a live fleet install showed signature.status="unsigned" and
    suspicious staticScan/skillSpector sub-signals while decision="pass" (the registry's
    own aggregate judgment, e.g. a disclosed security tool tripping its own detection
    regexes). Flagging on "unsigned" alone would reproduce that false positive — the
    trigger must stay verification.ok/decision, never signature/sub-signals alone."""
    f = check_clawhub_lock_verification(_ctx(FIXTURES / "clean_b135_clawhub_lock_pass"))
    assert f.status == PASS


def test_pass_when_no_lock_file(tmp_path):
    f = check_clawhub_lock_verification(_ctx(tmp_path))
    assert f.status == PASS


def test_pass_when_skills_dict_empty(tmp_path):
    d = tmp_path / "workspace" / ".clawhub"
    d.mkdir(parents=True)
    (d / "lock.json").write_text('{"version": 1, "skills": {}}', encoding="utf-8")
    f = check_clawhub_lock_verification(_ctx(tmp_path))
    assert f.status == PASS


def test_unknown_when_malformed_json(tmp_path):
    d = tmp_path / "workspace" / ".clawhub"
    d.mkdir(parents=True)
    (d / "lock.json").write_text("{not valid json", encoding="utf-8")
    f = check_clawhub_lock_verification(_ctx(tmp_path))
    assert f.status == UNKNOWN


def test_unknown_when_not_a_dict(tmp_path):
    d = tmp_path / "workspace" / ".clawhub"
    d.mkdir(parents=True)
    (d / "lock.json").write_text("[1, 2, 3]", encoding="utf-8")
    f = check_clawhub_lock_verification(_ctx(tmp_path))
    assert f.status == UNKNOWN


def test_warn_detected_under_workspace_home_variant(tmp_path):
    """.clawhub/lock.json can live under any of the WORKSPACE_DIRS names, not just
    "workspace" — must not hardcode a single shape (Golden Rule #6)."""
    d = tmp_path / "workspace-home" / ".clawhub"
    d.mkdir(parents=True)
    (d / "lock.json").write_text(
        '{"version": 1, "skills": {"rogue": {"version": "1.0.0", '
        '"verification": {"ok": false, "decision": "fail", "reasons": ["signature.invalid"]}}}}',
        encoding="utf-8",
    )
    f = check_clawhub_lock_verification(_ctx(tmp_path))
    assert f.status == WARN
    assert any("rogue" in e for e in f.evidence)


def test_pass_ok_missing_and_decision_missing_does_not_warn(tmp_path):
    """A verification block lacking both ok/decision keys is not itself evidence of
    rejection — must not assume failure from absence."""
    d = tmp_path / "workspace" / ".clawhub"
    d.mkdir(parents=True)
    (d / "lock.json").write_text(
        '{"version": 1, "skills": {"s": {"version": "1.0.0", "verification": {"schema": "x"}}}}',
        encoding="utf-8",
    )
    f = check_clawhub_lock_verification(_ctx(tmp_path))
    assert f.status == PASS


def test_meta_advisory_skills():
    m = next(c for c in CATALOG if c.id == "B135")
    assert m.scored is False
    assert m.surface == "skills"
