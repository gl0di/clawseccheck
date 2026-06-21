"""Attestation layer (v0.26.0) — agent self-report enriches the static audit.

B43 classifies the agent's REAL held verbs by blast radius; B44 cross-checks the
self-report against the static tool allow-list. Both read ctx.attestation and carry
ATTESTED confidence. With no attestation they return UNKNOWN, so the default audit
and its score are unchanged (regression guard below). Offline, deterministic.
"""
from __future__ import annotations

import json

from clawseccheck import attest, audit
from clawseccheck.catalog import ATTESTED, FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    check_attestation_mismatch,
    check_capability_blast_radius,
)
from clawseccheck.collector import Context


def _ctx(config=None, attestation=None):
    return Context(home=None, config=config or {}, attestation=attestation or {})


# --------------------------------------------------------------- classify_verb
def test_classify_mailbox_config_is_highest():
    for v in ("create_filter", "auto_forward", "add_delegate", "set_signature",
              "vacation_responder", "create_rule"):
        assert attest.classify_verb(v) == "MAILBOX_CONFIG", v


def test_classify_destructive():
    for v in ("delete_forever", "empty_trash", "purge_messages", "hard_delete"):
        assert attest.classify_verb(v) == "DESTRUCTIVE", v


def test_classify_egress():
    for v in ("send_email", "forward", "reply", "slack_send_message", "upload_file"):
        assert attest.classify_verb(v) == "EGRESS", v


def test_classify_reversible():
    for v in ("search_threads", "get_thread", "create_draft", "label_message",
              "list_labels", "archive_thread"):
        assert attest.classify_verb(v) == "REVERSIBLE", v


def test_classify_unknown():
    assert attest.classify_verb("frobnicate_quux") == "UNKNOWN"


def test_auto_forward_beats_plain_egress():
    # 'auto_forward' must classify as MAILBOX_CONFIG, not EGRESS — order matters.
    assert attest.classify_verb("auto_forward") == "MAILBOX_CONFIG"
    assert attest.classify_verb("forward") == "EGRESS"


# --------------------------------------------------------------- load / template
def test_load_missing_file_returns_empty(tmp_path):
    assert attest.load_attestation(tmp_path / "nope.json") == {}


def test_load_bad_json_returns_empty(tmp_path):
    p = tmp_path / "a.json"
    p.write_text("{not valid", encoding="utf-8")
    assert attest.load_attestation(p) == {}


def test_load_non_object_returns_empty(tmp_path):
    p = tmp_path / "a.json"
    p.write_text("[1, 2, 3]", encoding="utf-8")
    assert attest.load_attestation(p) == {}


def test_load_wrong_schema_returns_empty(tmp_path):
    p = tmp_path / "a.json"
    p.write_text(json.dumps({"schema": "something-else/9", "tools": ["x"]}), encoding="utf-8")
    assert attest.load_attestation(p) == {}


def test_load_valid_roundtrip(tmp_path):
    p = tmp_path / "a.json"
    payload = {"schema": attest.SCHEMA_ID, "tools": ["search", "send_email"]}
    p.write_text(json.dumps(payload), encoding="utf-8")
    assert attest.load_attestation(p)["tools"] == ["search", "send_email"]


def test_parse_attestation_from_dict():
    d = {"schema": attest.SCHEMA_ID, "tools": ["x"]}
    assert attest.parse_attestation(d) == d


def test_parse_attestation_from_json_string():
    s = json.dumps({"schema": attest.SCHEMA_ID, "tools": ["search"]})
    assert attest.parse_attestation(s)["tools"] == ["search"]


def test_parse_attestation_bad_json_string():
    assert attest.parse_attestation("{not json") == {}


def test_parse_attestation_non_object():
    assert attest.parse_attestation("[1,2]") == {}
    assert attest.parse_attestation(42) == {}


def test_parse_attestation_wrong_schema():
    assert attest.parse_attestation({"schema": "other/2", "tools": ["x"]}) == {}


def test_parse_attestation_no_schema_ok():
    # schema is optional; absence is allowed
    assert attest.parse_attestation({"tools": ["search"]})["tools"] == ["search"]


def test_template_is_valid_and_complete():
    t = attest.template()
    assert t["schema"] == attest.SCHEMA_ID
    for key in ("tools", "approval_gates", "untrusted_to_action", "host_monitors"):
        assert key in t
    # round-trips through json (it's what --ask emits)
    assert json.loads(json.dumps(t))["schema"] == attest.SCHEMA_ID


def test_is_ungated():
    assert attest.is_ungated({"untrusted_to_action": "ungated"}) is True
    assert attest.is_ungated({"approval_gates": {"send": "auto"}}) is True
    assert attest.is_ungated({"untrusted_to_action": "gated"}) is False
    assert attest.is_ungated({"approval_gates": {"send": "required"}}) is False
    assert attest.is_ungated({}) is False


# --------------------------------------------------------------- B43 verdicts
def test_b43_unknown_without_attestation():
    f = check_capability_blast_radius(_ctx())
    assert f.status == UNKNOWN
    assert f.confidence == ATTESTED


def test_b43_pass_reversible_only():
    att = {"tools": ["search_threads", "get_thread", "create_draft", "label_message"]}
    f = check_capability_blast_radius(_ctx(attestation=att))
    assert f.status == PASS


def test_b43_warn_high_blast_but_gated():
    att = {"tools": ["search", "send_email"],
           "untrusted_to_action": "gated",
           "approval_gates": {"send": "required"}}
    f = check_capability_blast_radius(_ctx(attestation=att))
    assert f.status == WARN
    assert any("EGRESS" in e for e in f.evidence)


def test_b43_fail_high_blast_and_ungated():
    att = {"tools": ["search", "send_email", "create_filter"],
           "untrusted_to_action": "ungated"}
    f = check_capability_blast_radius(_ctx(attestation=att))
    assert f.status == FAIL
    assert any("MAILBOX_CONFIG" in e for e in f.evidence)


def test_b43_fail_when_a_gate_is_auto():
    att = {"tools": ["delete_forever"], "approval_gates": {"write": "auto"}}
    f = check_capability_blast_radius(_ctx(attestation=att))
    assert f.status == FAIL


# --------------------------------------------------------------- B44 verdicts
def test_b44_unknown_without_attestation():
    f = check_attestation_mismatch(_ctx(config={"tools": {"allow": ["send_email"]}}))
    assert f.status == UNKNOWN


def test_b44_unknown_without_allowlist():
    att = {"tools": ["search"]}
    f = check_attestation_mismatch(_ctx(config={}, attestation=att))
    assert f.status == UNKNOWN


def test_b44_warn_undisclosed_high_blast():
    # config grants a forwarding verb the agent omitted from its self-report
    cfg = {"tools": {"allow": ["search_threads", "create_filter"]}}
    att = {"tools": ["search_threads"]}
    f = check_attestation_mismatch(_ctx(config=cfg, attestation=att))
    assert f.status == WARN
    assert any("create_filter" in e for e in f.evidence)


def test_b44_pass_all_acknowledged():
    cfg = {"tools": {"allow": ["search_threads", "send_email"]}}
    att = {"tools": ["search_threads", "send_email", "get_thread"]}
    f = check_attestation_mismatch(_ctx(config=cfg, attestation=att))
    assert f.status == PASS


def test_b44_reversible_grants_never_flagged():
    # only reversible verbs in the allow-list -> nothing to disclose -> PASS
    cfg = {"tools": {"allow": ["search_threads", "label_message"]}}
    att = {"tools": ["search_threads"]}
    f = check_attestation_mismatch(_ctx(config=cfg, attestation=att))
    assert f.status == PASS


# --------------------------------------------------------------- regression guard
def test_no_attestation_keeps_score_unchanged(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    _, f_plain, s_plain = audit(tmp_path)
    _, f_att, s_att = audit(tmp_path, attestation={"tools": ["search"]})
    # B43/B44 are scored=False, so neither the score nor grade move
    assert s_plain.score == s_att.score
    assert s_plain.grade == s_att.grade
    # both new checks present; UNKNOWN without attestation
    plain = {f.id: f.status for f in f_plain}
    assert plain["B43"] == UNKNOWN and plain["B44"] == UNKNOWN


def test_audit_threads_attestation_through(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    _, findings, _ = audit(tmp_path, attestation={
        "tools": ["search_threads", "create_draft"]})
    b43 = next(f for f in findings if f.id == "B43")
    assert b43.status == PASS
