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


# ---------------------------------------------------------------------------
# B-258: "the registry rejected this" vs "the registry has not answered yet"
#
# B135 used to WARN on ok=False/decision="fail" without inspecting WHY. One real
# reason is that ClawHub's security audit simply had not finished — an unfinished
# audit is not a security verdict, and reporting it as a rejection is untrue. The
# split below is fail-closed: only the reason codes actually observed on a real
# lock file count as inconclusive, so a genuine rejection can never be silenced.
# ---------------------------------------------------------------------------


def _pending_lock(tmp_path, reasons, security):
    """Write a lock whose single skill failed verification with *reasons*/*security*."""
    import json

    d = tmp_path / "workspace" / ".clawhub"
    d.mkdir(parents=True)
    entry = {
        "version": "1.0.0",
        "verification": {
            "schema": "clawhub.skill.verify.v1",
            "ok": False,
            "decision": "fail",
            "reasons": reasons,
        },
    }
    if security is not None:
        entry["verification"]["security"] = security
    (d / "lock.json").write_text(
        json.dumps({"version": 1, "skills": {"s": entry}}), encoding="utf-8"
    )
    return _ctx(tmp_path)


def test_unknown_when_security_audit_is_still_pending():
    """The real shape observed on a live lock: reasons ["card.missing",
    "security.status_not_clean", "security.pending"] with security.status "pending",
    passed false and every verdict field null. The registry had not answered yet; it
    cleared on its own once the audit completed."""
    f = check_clawhub_lock_verification(
        _ctx(FIXTURES / "clean_b135_clawhub_lock_pending")
    )
    assert f.id == "B135"
    assert f.status == UNKNOWN
    assert any("audit-still-running" in e for e in f.evidence)
    assert "not a registry verdict" in f.detail or "inconclusive" in f.detail


def test_unknown_when_only_reason_is_a_missing_skill_card(tmp_path):
    """card.missing is a listing-completeness gate (the skill-card.md document is not
    published), never a security verdict."""
    f = check_clawhub_lock_verification(
        _pending_lock(tmp_path, ["card.missing"], {"status": "clean", "passed": True})
    )
    assert f.status == UNKNOWN


def test_warn_survives_a_real_verdict_alongside_pending_reasons(tmp_path):
    """GR#5 the other way: one inconclusive reason must not launder a real one."""
    f = check_clawhub_lock_verification(
        _pending_lock(
            tmp_path,
            ["security.pending", "signature.invalid"],
            {"status": "pending", "passed": False},
        )
    )
    assert f.status == WARN
    assert any("signature.invalid" in e for e in f.evidence)


def test_warn_on_an_unrecognised_reason_code(tmp_path):
    """The reason codes are server-generated and NOT enumerable client-side — the CLI
    schema types them as a bare `reasons: "string[]"`. So anything not explicitly
    classified as inconclusive keeps the WARN; a future not-yet-answered code costs a
    stale WARN, never a silenced rejection."""
    f = check_clawhub_lock_verification(
        _pending_lock(tmp_path, ["some.future.code"], {"status": "pending"})
    )
    assert f.status == WARN


def test_warn_when_status_not_clean_is_a_real_verdict(tmp_path):
    """security.status_not_clean is derived from security.status. It only restates the
    pending fact while that status IS pending; with a non-pending status it is a verdict."""
    f = check_clawhub_lock_verification(
        _pending_lock(
            tmp_path,
            ["security.status_not_clean"],
            {"status": "suspicious", "passed": False, "rawStatus": "suspicious"},
        )
    )
    assert f.status == WARN


def test_warn_when_rejection_records_no_reason_at_all(tmp_path):
    """A rejection with an empty reasons list must not be downgraded on missing data."""
    for reasons in ([], None):
        f = check_clawhub_lock_verification(
            _pending_lock(tmp_path / str(reasons), reasons, {"status": "pending"})
        )
        assert f.status == WARN, reasons


def test_warn_when_a_reason_is_not_a_string(tmp_path):
    """Malformed reasons must fail closed, not parse into an inconclusive verdict."""
    f = check_clawhub_lock_verification(
        _pending_lock(tmp_path, ["card.missing", 42], {"status": "pending"})
    )
    assert f.status == WARN


def test_a_real_rejection_outranks_a_pending_one(tmp_path):
    """With both kinds present the WARN must win — the report may not lead with UNKNOWN
    while a genuinely rejected skill sits installed."""
    import json

    d = tmp_path / "workspace" / ".clawhub"
    d.mkdir(parents=True)
    (d / "lock.json").write_text(
        json.dumps(
            {
                "version": 1,
                "skills": {
                    "waiting": {
                        "version": "1.0.0",
                        "verification": {
                            "ok": False,
                            "decision": "fail",
                            "reasons": ["security.pending"],
                            "security": {"status": "pending"},
                        },
                    },
                    "rejected": {
                        "version": "2.0.0",
                        "verification": {
                            "ok": False,
                            "decision": "fail",
                            "reasons": ["signature.invalid"],
                        },
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    f = check_clawhub_lock_verification(_ctx(tmp_path))
    assert f.status == WARN
    assert any("rejected" in e for e in f.evidence)
    assert not any("waiting" in e for e in f.evidence)
