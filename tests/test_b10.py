"""B10 — audit-log observability (check_audit_log).

B-514 rewrote this module. It used to open with "OpenClaw exposes no config field to
toggle audit logging; audit is a CLI command only" and pinned an invariant that B10 can
NEVER return PASS. Both came from the check's own source comment, which came from the
internal schema recon — and all three were wrong. The installed schema has:

    const OpenClawSchema = object({ ...
        audit: object({ enabled: boolean().optional() }).strict().optional(),
        logging: object({ ...

so `audit.enabled` is a real, top-level field. B10 had been declining to read it and
telling the user "OpenClaw exposes no audit-log config field".

Two details worth keeping in mind while reading the cases below:

* The field is a KILL SWITCH, not a preference. `types.base-DD09OBJd.d.ts:252` documents
  it as "Record metadata-only audit events (agent runs and tool actions) ... Default:
  true. Disabling stops new writes; existing records stay readable until they expire."
  So `false` silently ends the agent-activity ledger.
* ABSENT is that documented default, i.e. the safe state. Warning on it would be a false
  positive on every stock config. Note the default is documented in the `.d.ts`, NOT in
  the zod schema — a first pass at this fix grounded on zod alone and wrongly reported
  the default as unreadable. Grounding a claim means checking every authority the dist
  offers, not the first one that answers.
* `logging.audit` really is a phantom. Only the top-level `audit.*` sibling is real, and
  the old note is kept in-source for exactly that half.

Verdicts:
  WARN    : audit.enabled is false (explicitly off), or logging.redactSensitive == "off"
  PASS    : audit.enabled is true, or absent (documented default, reduced confidence)
  UNKNOWN : audit.enabled present but not a boolean
  (never FAIL)
"""
from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_audit_log
from clawseccheck.collector import Context


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


# ---- the defect itself: the field is real and must be read ----

def test_b10_never_claims_the_audit_field_does_not_exist():
    """The exact sentence B-514 was filed for, on every branch."""
    for cfg in ({}, {"audit": {}}, {"audit": {"enabled": True}}, {"audit": {"enabled": False}},
                {"logging": {"redactSensitive": "off"}}):
        detail = check_audit_log(_ctx(cfg)).detail.lower()
        assert "exposes no audit-log config field" not in detail, cfg
        assert "no config toggle" not in detail, cfg


def test_b10_audit_enabled_true_passes():
    f = check_audit_log(_ctx({"audit": {"enabled": True}}))
    assert f.status == PASS
    assert "audit.enabled" in f.detail


def test_b10_pass_does_not_claim_the_log_actually_exists():
    """A config toggle is not evidence a trail is written, retained or reachable —
    the same distinction every other config-only PASS in this project has to make."""
    f = check_audit_log(_ctx({"audit": {"enabled": True}}))
    assert "config" in f.detail.lower()
    assert "not observable from config" in f.detail.lower()


def test_b10_audit_enabled_false_warns():
    f = check_audit_log(_ctx({"audit": {"enabled": False}}))
    assert f.status == WARN
    assert "false" in f.detail.lower()


def test_b10_explicit_off_outranks_the_redaction_arm_and_keeps_both_facts():
    """Both are true at once; the finding must not drop one to report the other."""
    f = check_audit_log(_ctx({
        "audit": {"enabled": False},
        "logging": {"redactSensitive": "off"},
    }))
    assert f.status == WARN
    assert "audit.enabled is false" in f.detail
    assert "redactsensitive" in f.detail.lower()


# ---- WARN: redaction explicitly disabled (pre-existing behaviour) ----

def test_b10_redact_off_warns():
    f = check_audit_log(_ctx({"logging": {"redactSensitive": "off"}}))
    assert f.status == WARN


def test_b10_redact_off_detail_mentions_redact():
    f = check_audit_log(_ctx({"logging": {"redactSensitive": "off"}}))
    assert "redact" in f.detail.lower() or "off" in f.detail.lower()


# ---- PASS: absent means the documented default, which is on ----

def test_b10_empty_config_passes_on_the_documented_default():
    f = check_audit_log(_ctx({}))
    assert f.status == PASS
    assert f.pass_confidence == "no_signal"
    assert "default is true" in f.detail


def test_b10_absent_is_never_reported_as_off():
    """The GR#5 trap this branch exists to avoid: a stock config has no audit key at
    all, so warning on absence would fire on essentially every real user."""
    detail = check_audit_log(_ctx({})).detail.lower()
    assert "is false" not in detail
    assert "switched off" not in detail


def test_b10_audit_object_present_but_empty_is_the_same_as_absent():
    assert check_audit_log(_ctx({"audit": {}})).status == PASS


def test_b10_explicit_true_outranks_the_inherited_default():
    """Both PASS, but only one of them is the operator's own statement."""
    explicit = check_audit_log(_ctx({"audit": {"enabled": True}}))
    inherited = check_audit_log(_ctx({}))
    assert explicit.status == inherited.status == PASS
    assert explicit.pass_confidence != "no_signal"
    assert inherited.pass_confidence == "no_signal"


# ---- UNKNOWN: present, but not a boolean ----

def test_b10_non_boolean_audit_enabled_is_unknown():
    """Zod would reject these; treating a truthy string as "on" would invent a verdict."""
    for value in ("true", "yes", 1, 0, []):
        assert check_audit_log(_ctx({"audit": {"enabled": value}})).status == UNKNOWN, value


def test_b10_json_null_reads_as_unset_not_as_a_bad_value():
    """A JSON null is indistinguishable from an absent key and means the same thing."""
    assert check_audit_log(_ctx({"audit": {"enabled": None}})).status == PASS


# ---- the redaction arm is unchanged ----

def test_b10_redact_tools_does_not_block_the_audit_verdict():
    assert check_audit_log(_ctx({"logging": {"redactSensitive": "tools"}})).status == PASS


def test_b10_logging_absent_passes():
    assert check_audit_log(_ctx({"gateway": {"port": 19001}})).status == PASS


def test_b10_logging_empty_dict_passes():
    assert check_audit_log(_ctx({"logging": {}})).status == PASS


def test_b10_unexpected_redact_value_does_not_warn():
    assert check_audit_log(_ctx({"logging": {"redactSensitive": "all"}})).status == PASS


# ---- never FAIL ----

def test_b10_never_fails():
    """B10 has no FAIL branch: an audit toggle being off is a visibility gap, not a
    reachable compromise. (The old form of this test also forbade PASS — that was the
    B-514 defect written down as an invariant.)"""
    for cfg in (
        {},
        {"audit": {"enabled": True}},
        {"audit": {"enabled": False}},
        {"audit": {"enabled": False}, "logging": {"redactSensitive": "off"}},
        {"logging": {"redactSensitive": "off"}},
        {"logging": {"redactSensitive": "tools"}},
        {"logging": {"redactSensitive": "all"}},
        {"logging": {}},
        {"gateway": {"port": 19001}},
    ):
        assert check_audit_log(_ctx(cfg)).status != FAIL, cfg


# ---- UNKNOWN: the config itself could not be read ----

def test_b10_unparseable_config_is_unknown_not_the_default_pass():
    """B-524: absent-because-default and absent-because-unparsed are different answers.

    When the collector positively finds openclaw.json and positively fails to parse it,
    ``ctx.config`` falls back to ``{}`` — so ``audit.enabled`` reads as absent for a
    reason that has nothing to do with what the operator configured. Answering with the
    documented default there tells the user "nothing here turns it off" about a file
    nothing ever read. GR#4: report UNKNOWN, not a PASS the check never earned.
    """
    c = _ctx({})
    c.config_found = True
    c.config_parse_error = True

    f = check_audit_log(c)

    assert f.status == UNKNOWN
    assert f.engine_degraded is True, (
        "must ride the canonical engine-degraded signal so DEGRADED_CHECK_CAP applies"
    )


def test_b10_the_parse_flag_alone_separates_unknown_from_the_default_pass():
    """The discriminator has to be the parse flag, not the emptiness of the dict.

    Both calls below see exactly the same ``{}``. If this check keyed on "config is
    empty" instead, it would return UNKNOWN on every non-OpenClaw machine — the mirror
    false-negative of the bug being fixed, and the one ``_surface_absent`` documents at
    length. Same input, two verdicts, one flag apart.
    """
    absent = _ctx({})
    unreadable = _ctx({})
    unreadable.config_found = True
    unreadable.config_parse_error = True

    assert check_audit_log(absent).status == PASS
    assert check_audit_log(unreadable).status == UNKNOWN


def test_b10_unparseable_config_never_claims_nothing_turned_it_off(tmp_path):
    """End to end through the real audit(), on the shape that produced the defect.

    The sentence is the finding: on a truncated config the old branch asserted "Nothing
    here turns it off" about a file the auditor could not read.
    """
    import os

    import clawseccheck

    (tmp_path / "openclaw.json").write_text('{"mcp": {"servers": ')  # truncated JSON
    os.chmod(tmp_path / "openclaw.json", 0o600)

    ctx, findings, _ = clawseccheck.audit(tmp_path)

    assert ctx.config_parse_error is True
    b10 = next(f for f in findings if f.id == "B10")
    assert b10.status == UNKNOWN, f"got {b10.status} — {b10.detail}"
    assert "nothing here turns it off" not in b10.detail.lower()
    assert "default is true" not in b10.detail


# ---- end to end through the real audit, on real fixture homes ----

def test_b10_fixture_homes_reach_the_new_verdicts():
    """Not a trace: the fixtures go through audit() the way a user's config does.

    B-514's whole failure mode was a check that never read a field, so the branch that
    matters is the one where the field IS present on disk.
    """
    import clawseccheck

    fixtures = Path(__file__).resolve().parent.parent / "fixtures"
    for name, expected in (("clean_b10_audit_enabled", PASS),
                           ("bad_b10_audit_disabled", WARN)):
        home = fixtures / name / "openclaw_home"
        _, findings, _ = clawseccheck.audit(str(home))
        b10 = next(f for f in findings if f.id == "B10")
        assert b10.status == expected, f"{name}: got {b10.status} — {b10.detail}"
        assert "audit.enabled" in b10.detail, name
