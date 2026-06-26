"""Attestation layer (v0.26.0) — agent self-report enriches the static audit.

B43 classifies the agent's REAL held verbs by blast radius; B44 cross-checks the
self-report against the static tool allow-list. Both read ctx.attestation and carry
ATTESTED confidence. With no attestation they return UNKNOWN, so the default audit
and its score are unchanged (regression guard below). Offline, deterministic.
"""
from __future__ import annotations

import json

from clawseccheck import attest, audit
from clawseccheck.catalog import ATTESTED, FAIL, HIGH, PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    _host_finding,
    check_attestation_mismatch,
    check_capability_blast_radius,
)
from clawseccheck.collector import Context


def _ctx(config=None, attestation=None, host=None):
    c = Context(home=None, config=config or {}, attestation=attestation or {})
    c.host = host
    return c


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


def test_classify_exec_is_high_blast():
    # Field finding (v0.30): arbitrary exec is the broadest blast radius and was UNKNOWN.
    for v in ("Bash", "bash", "shell", "run_shell_command", "exec", "subprocess_run",
              "powershell", "run_command", "code_interpreter", "terminal"):
        assert attest.classify_verb(v) == "EXEC", v
    assert "EXEC" in attest.HIGH_BLAST_CLASSES


def test_exec_hints_do_not_false_positive_on_benign_reads():
    # The omitted bare 'system'/'eval'/'spawn' would have caught these — they must NOT.
    for v in ("get_system_info", "system_status", "evaluate_expression",
              "evaluate_model", "spawn_subagent", "list_events"):
        assert attest.classify_verb(v) != "EXEC", v


def test_b43_flags_a_lone_exec_tool():
    # Regression for the field gap: an agent holding only Bash must NOT be PASS.
    warn = check_capability_blast_radius(_ctx(attestation={"tools": ["Bash"]}))
    assert warn.status == WARN and any("EXEC" in e for e in warn.evidence)
    fail = check_capability_blast_radius(_ctx(attestation={
        "tools": ["Bash"], "untrusted_to_action": "ungated"}))
    assert fail.status == FAIL


def test_b43_real_session_toolset_warns():
    # The exact toolset from the field report — Bash makes it high-blast.
    toolset = ["Agent", "AskUserQuestion", "Bash", "Edit", "Read", "ScheduleWakeup",
               "SendUserFile", "Skill", "ToolSearch", "Workflow", "Write"]
    f = check_capability_blast_radius(_ctx(attestation={"tools": toolset}))
    assert f.status == WARN
    assert any("EXEC" in e for e in f.evidence)


def test_classify_reversible():
    for v in ("search_threads", "get_thread", "create_draft", "label_message",
              "list_labels", "archive_thread"):
        assert attest.classify_verb(v) == "REVERSIBLE", v


def test_classify_unknown():
    assert attest.classify_verb("frobnicate_quux") == "UNKNOWN"


# --------------------------------------------------------------- verb normalization
def test_normalize_strips_mcp_namespace():
    assert attest.normalize_verb("mcp__claude_ai_Slack__slack_send_message") == "slack_send_message"
    assert attest.normalize_verb("gmail.send") == "send"
    assert attest.normalize_verb("create_draft") == "create_draft"


def test_provider_name_does_not_pollute_classification():
    # 'SendGrid' contains 'send' but the verb is a reversible list — must NOT be EGRESS.
    assert attest.classify_verb("mcp__SendGrid__list_templates") == "REVERSIBLE"


def test_trailing_separator_does_not_hide_verb():
    # Regression: a trailing separator must not strip the verb to '' and hide it.
    assert attest.normalize_verb("forward__") == "forward"
    assert attest.classify_verb("forward__") == "EGRESS"
    assert attest.classify_verb("delete_forever__") == "DESTRUCTIVE"
    assert attest.classify_verb("send.") == "EGRESS"


def test_normalize_never_raises_on_separator_only():
    for s in ("", "__", ".", "...", "   "):
        assert isinstance(attest.normalize_verb(s), str)


def test_namespaced_real_verbs_classify_on_the_verb():
    assert attest.classify_verb("mcp__claude_ai_Slack__slack_send_message") == "EGRESS"
    assert attest.classify_verb("mcp__claude_ai_Gmail__create_draft") == "REVERSIBLE"
    assert attest.classify_verb(
        "mcp__claude_ai_Zapier__facebook_pages_create_page_post") == "EGRESS"


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
    for key in ("tools", "approval_gates", "untrusted_to_action", "approval_bypass_actors", "host_monitors"):
        assert key in t
    # round-trips through json (it's what --ask emits)
    assert json.loads(json.dumps(t))["schema"] == attest.SCHEMA_ID


def test_is_ungated():
    assert attest.is_ungated({"untrusted_to_action": "ungated"}) is True
    assert attest.is_ungated({"untrusted_to_action": " Ungated "}) is True
    assert attest.is_ungated({"untrusted_to_action": "gated"}) is False
    assert attest.is_ungated({"approval_gates": {"send": "auto"}}) is False
    assert attest.is_ungated({}) is False


def test_approval_gates_auto():
    assert attest.approval_gates_auto({"approval_gates": {"write": "auto", "send": "required", "exec": "AUTO"}}) == ["exec", "write"]
    assert attest.approval_gates_auto({"approval_gates": {"send": "required", "write": "unknown"}}) == []
    assert attest.approval_gates_auto({"approval_gates": {"send": "Auto "}}) == ["send"]
    assert attest.approval_gates_auto({"approval_gates": []}) == []


def test_approval_bypass_actors():
    att = {"approval_bypass_actors": ["Cron", "unknown", "heartbeat", "sleeper", "CRON"]}
    assert attest.approval_bypass_actors(att) == ["cron", "heartbeat", "sleeper"]

    legacy = {"bypass_actors": "heartbeat, scheduled, cron"}
    assert set(attest.approval_bypass_actors(legacy)) == {"heartbeat", "scheduled", "cron"}



# --------------------------------------------------------------- B43 verdicts
def test_b43_unknown_when_no_readable_verbs():
    # Regression: a list with no string entries must be UNKNOWN, not a false PASS.
    for junk in ([1, 2, 3], [{"k": "v"}], [["nested"]]):
        f = check_capability_blast_radius(_ctx(attestation={"tools": junk}))
        assert f.status == UNKNOWN, junk


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


def test_b43_warn_when_a_gate_is_auto_without_bypass_signal():
    att = {"tools": ["delete_forever"], "approval_gates": {"write": "auto"}}
    f = check_capability_blast_radius(_ctx(attestation=att))
    assert f.status == WARN


def test_b43_fail_when_a_gate_is_auto_with_runtime_sleeper_bypass():
    att = {
        "tools": ["delete_forever"],
        "approval_gates": {"write": "auto"},
        "approval_bypass_actors": ["sleeper"],
    }
    f = check_capability_blast_radius(_ctx(attestation=att))
    assert f.status == FAIL
    assert any("approval bypass actor(s):" in e for e in f.evidence)


def test_b43_warn_when_a_gate_is_auto_with_unknown_bypass_actor():
    att = {
        "tools": ["delete_forever"],
        "approval_gates": {"write": "auto"},
        "approval_bypass_actors": ["unknown"]
    }
    f = check_capability_blast_radius(_ctx(attestation=att))
    assert f.status == WARN
    assert not any("approval bypass actor(s):" in e for e in f.evidence)


def test_b43_fail_when_a_gate_is_auto_with_cron_or_heartbeat_bypass():
    att = {"tools": ["delete_forever"], "approval_gates": {"write": "auto"}}
    f = check_capability_blast_radius(_ctx(config={"cron": "daily"}, attestation=att))
    assert f.status == FAIL
    assert any("approval bypass actor(s):" in e for e in f.evidence)


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


def test_b44_namespace_mismatch_is_not_flagged():
    # config lists the MCP-namespaced grant; agent reports the bare verb — same thing,
    # so normalization must prevent a false "undisclosed".
    cfg = {"tools": {"allow": ["mcp__claude_ai_Gmail__send_email"]}}
    att = {"tools": ["send_email"]}
    f = check_attestation_mismatch(_ctx(config=cfg, attestation=att))
    assert f.status == PASS


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


def test_b44_evidence_names_verbs_in_json(tmp_path):
    # Field finding (v0.31): the flagged verbs must reach the user, not just be computed.
    from clawseccheck.report import render_json
    (tmp_path / "openclaw.json").write_text(
        json.dumps({"tools": {"allow": ["search_threads", "gmail_send", "create_filter"]}}),
        encoding="utf-8")
    _, findings, score = audit(tmp_path, attestation={"tools": ["search_threads"]})
    data = json.loads(render_json(findings, score))
    b44 = next(f for f in data["findings"] if f["id"] == "B44")
    assert b44["status"] == "WARN"
    joined = " ".join(b44["evidence"])
    assert "create_filter" in joined and "gmail_send" in joined


def test_b44_evidence_in_text_report(tmp_path):
    from clawseccheck.report import render_report
    (tmp_path / "openclaw.json").write_text(
        json.dumps({"tools": {"allow": ["gmail_send"]}}), encoding="utf-8")
    _, findings, score = audit(tmp_path, attestation={"tools": ["search_threads"]})
    out = render_report(findings, score)
    assert "gmail_send" in out


def test_audit_threads_attestation_through(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    _, findings, _ = audit(tmp_path, attestation={
        "tools": ["search_threads", "create_draft"]})
    b43 = next(f for f in findings if f.id == "B43")
    assert b43.status == PASS


# --------------------------------------------------------------- real MCP toolsets
# Taxonomy hardened against actual toolset shapes so it survives real use (1.0 trigger).
GMAIL_REVERSIBLE = [
    "search_threads", "get_thread", "create_draft", "list_drafts", "list_labels",
    "create_label", "update_label", "delete_label", "label_message", "label_thread",
    "unlabel_message", "unlabel_thread",
]


def test_real_gmail_toolset_is_pass():
    # The session's Gmail toolset holds NO send/forward — only draft/label/search.
    f = check_capability_blast_radius(_ctx(attestation={"tools": GMAIL_REVERSIBLE}))
    assert f.status == PASS


def test_real_gmail_verbs_never_high_blast():
    for v in GMAIL_REVERSIBLE:
        assert attest.classify_verb(v) not in attest.HIGH_BLAST_CLASSES, v


def test_slack_send_and_schedule_are_egress():
    assert attest.classify_verb("slack_send_message") == "EGRESS"
    assert attest.classify_verb("slack_schedule_message") == "EGRESS"


def test_facebook_page_publish_is_egress():
    for v in ("facebook_pages_create_page_post", "facebook_pages_create_page_photo",
              "facebook_pages_create_page_video", "facebook_messenger_send_message_from_page"):
        assert attest.classify_verb(v) == "EGRESS", v


def test_calendar_mutations_are_not_high_blast():
    # create/update/respond on a calendar are reversible-ish — must not false-FAIL.
    for v in ("create_event", "update_event", "respond_to_event", "get_event", "list_events"):
        assert attest.classify_verb(v) not in attest.HIGH_BLAST_CLASSES, v


# --------------------------------------------------------------- host-monitor attestation
def test_host_attestation_upgrades_unscanned_to_pass():
    # No host scan run (host=None), but the agent attests an EDR -> B53 PASS, ATTESTED.
    ctx = _ctx(attestation={"host_monitors": ["CrowdStrike Falcon EDR"]})
    f = _host_finding("B53", "edr_av", ctx)
    assert f.status == PASS
    assert f.confidence == ATTESTED
    assert any("CrowdStrike" in e for e in f.evidence)


def test_host_attestation_keyword_must_match_class():
    # An EDR attestation does NOT satisfy the network-IDS class.
    ctx = _ctx(attestation={"host_monitors": ["CrowdStrike Falcon EDR"]})
    f = _host_finding("B50", "network_ids", ctx)
    assert f.status == UNKNOWN  # unscanned + no matching attestation


def test_host_attestation_suricata_matches_network_ids():
    ctx = _ctx(attestation={"host_monitors": ["Suricata on the gateway"]})
    f = _host_finding("B50", "network_ids", ctx)
    assert f.status == PASS and f.confidence == ATTESTED


def test_static_present_wins_over_attestation():
    # A real detection (HIGH) is never relabelled to ATTESTED by a self-report.
    host = {"supported": True, "classes": {
        "network_ids": {"status": "present", "found": ["suricata"], "active": True}}}
    ctx = _ctx(attestation={"host_monitors": ["Suricata"]}, host=host)
    f = _host_finding("B50", "network_ids", ctx)
    assert f.status == PASS and f.confidence == HIGH
