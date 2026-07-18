"""B173 (B-237) — security.audit.suppressions self-blinds OpenClaw's native audit.

Grounded against the real openclaw schema: zod-schema-O9ml_nmo.js SecuritySchema —
security.audit.suppressions is an array of {checkId (required), titleIncludes?,
detailIncludes?, reason?}. See docs/research/openclaw-schema-recon.md §19 for the full
grounding pass (workspace root, not shipped with this repo).

Absent/empty -> PASS (nothing suppressed, zero false positives on a stock config). A
non-empty list is disclosure-only by default (WARN) -- a suppression is how an operator
knowingly accepts a specific, reviewed native finding, not itself a vulnerability. FAIL
only when a suppressed checkId is one this project has grounded as UNCONDITIONALLY
"critical" in the native audit source (audit-UjVvFwCi.js).
"""
from pathlib import Path

from clawseccheck.checks import check_audit_suppressions
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(config):
    c = Context(home=Path("/nonexistent"))
    c.config = config
    return c


# ---- real fixture dirs (collect() end-to-end, not a bare dict) ----

def test_b173_clean_fixture_passes():
    r = check_audit_suppressions(collect(FIXTURES / "clean_b173_no_suppressions"))
    assert r.status == "PASS"


def test_b173_bad_fixture_critical_suppression_fails():
    r = check_audit_suppressions(collect(FIXTURES / "bad_b173_critical_suppression"))
    assert r.status == "FAIL"
    assert any("gateway.bind_no_auth" in e for e in r.evidence)


def test_b173_bad_fixture_low_severity_suppression_warns():
    r = check_audit_suppressions(collect(FIXTURES / "bad_b173_low_severity_suppression"))
    assert r.status == "WARN"
    assert any("logging.redact_off" in e for e in r.evidence)


def test_b173_bad_fixture_trusted_proxy_notice_suppression_warns_not_fails():
    # B-237: suppressing gateway.trusted_proxy_auth is a knowingly-accepted disclosure of a
    # native notice that fires unconditionally whenever trusted-proxy auth is enabled at all
    # (audit-UjVvFwCi.js:245-254) -- its remediation is a verification checklist, not a config
    # change a correctly-hardened operator (e.g. behind Pomerium/Caddy/nginx SSO) can act on.
    # Escalating this to FAIL was a confirmed false positive; must stay WARN-only.
    r = check_audit_suppressions(
        collect(FIXTURES / "bad_b173_trusted_proxy_notice_suppression")
    )
    assert r.status == "WARN"
    assert any("gateway.trusted_proxy_auth" in e for e in r.evidence)


# ---- clean / absent configuration -> PASS (zero false positives) ----

def test_b173_empty_config_passes():
    r = check_audit_suppressions(_ctx({}))
    assert r.id == "B173"
    assert r.status == "PASS"
    assert r.scored is True


def test_b173_security_key_absent_passes():
    assert check_audit_suppressions(_ctx({"gateway": {"port": 19001}})).status == "PASS"


def test_b173_audit_present_no_suppressions_key_passes():
    cfg = {"security": {"audit": {}}}
    assert check_audit_suppressions(_ctx(cfg)).status == "PASS"


def test_b173_empty_suppressions_list_passes():
    cfg = {"security": {"audit": {"suppressions": []}}}
    assert check_audit_suppressions(_ctx(cfg)).status == "PASS"


def test_b173_non_list_suppressions_value_passes():
    # defensive: a malformed non-array value must not crash or false-FAIL
    cfg = {"security": {"audit": {"suppressions": "oops"}}}
    r = check_audit_suppressions(_ctx(cfg))
    assert r.status == "PASS"


# ---- non-empty suppressions of a non-critical checkId -> WARN (disclosure only) ----

def test_b173_low_severity_suppression_warns_not_fails():
    cfg = {"security": {"audit": {"suppressions": [
        {"checkId": "gateway.trusted_proxy_no_allowlist"},
    ]}}}
    r = check_audit_suppressions(_ctx(cfg))
    assert r.status == "WARN"
    assert r.id == "B173"
    assert any("gateway.trusted_proxy_no_allowlist" in e for e in r.evidence)


def test_b173_info_severity_suppression_warns():
    # the synthetic disclosure finding itself (severity: "info") is a legitimate,
    # low-stakes thing to suppress -- still just a WARN-level disclosure here.
    cfg = {"security": {"audit": {"suppressions": [
        {"checkId": "gateway.tailscale_serve"},
    ]}}}
    assert check_audit_suppressions(_ctx(cfg)).status == "WARN"


def test_b173_suppression_evidence_names_index_and_checkid():
    cfg = {"security": {"audit": {"suppressions": [
        {"checkId": "logging.redact_off"},
    ]}}}
    r = check_audit_suppressions(_ctx(cfg))
    assert any("suppressions[0]" in e and "logging.redact_off" in e for e in r.evidence)


def test_b173_reason_presence_disclosed_but_text_not_echoed():
    # Assembled at runtime so no secret-shaped literal sits in source (project doctrine).
    frag_a, frag_b = "tok_", "AbCdEf123456"
    secretish_reason = f"accepted risk, ref {frag_a}{frag_b}"
    cfg = {"security": {"audit": {"suppressions": [
        {"checkId": "gateway.trusted_proxy_no_allowlist", "reason": secretish_reason},
    ]}}}
    r = check_audit_suppressions(_ctx(cfg))
    assert r.status == "WARN"
    joined = " ".join(r.evidence)
    assert "reason given" in joined
    assert secretish_reason not in joined
    assert frag_a + frag_b not in joined


def test_b173_multiple_low_severity_entries_all_disclosed():
    cfg = {"security": {"audit": {"suppressions": [
        {"checkId": "logging.redact_off"},
        {"checkId": "gateway.token_too_short"},
    ]}}}
    r = check_audit_suppressions(_ctx(cfg))
    assert r.status == "WARN"
    assert len(r.evidence) == 2


# ---- suppression of a grounded unconditional-critical native checkId -> FAIL ----

def test_b173_gateway_bind_no_auth_suppression_fails():
    cfg = {"security": {"audit": {"suppressions": [
        {"checkId": "gateway.bind_no_auth"},
    ]}}}
    r = check_audit_suppressions(_ctx(cfg))
    assert r.status == "FAIL"
    assert r.severity == "CRITICAL"
    assert any("gateway.bind_no_auth" in e for e in r.evidence)


def test_b173_fs_config_perms_writable_suppression_fails():
    cfg = {"security": {"audit": {"suppressions": [
        {"checkId": "fs.config.perms_writable", "reason": "known"},
    ]}}}
    assert check_audit_suppressions(_ctx(cfg)).status == "FAIL"


def test_b173_trusted_proxy_no_proxies_suppression_still_fails():
    # Real defect (empty trustedProxies -> "All requests will be rejected") -- must keep
    # escalating even though the sibling gateway.trusted_proxy_auth notice does not (B-237).
    cfg = {"security": {"audit": {"suppressions": [
        {"checkId": "gateway.trusted_proxy_no_proxies"},
    ]}}}
    assert check_audit_suppressions(_ctx(cfg)).status == "FAIL"


def test_b173_trusted_proxy_no_user_header_suppression_still_fails():
    cfg = {"security": {"audit": {"suppressions": [
        {"checkId": "gateway.trusted_proxy_no_user_header"},
    ]}}}
    assert check_audit_suppressions(_ctx(cfg)).status == "FAIL"


def test_b173_trusted_proxy_auth_suppression_warns_not_fails():
    # B-237 confirmed false positive: gateway.trusted_proxy_auth is literally
    # severity:"critical" in the native source, but it fires unconditionally whenever
    # gateway.auth.mode === "trusted-proxy" is set at all (a verification notice, not a
    # defect with actionable remediation) -- see the in-source comment above
    # _NATIVE_UNCONDITIONAL_CRITICAL_CHECK_IDS. A reviewed suppression of it must stay
    # WARN-only, never escalate.
    cfg = {"security": {"audit": {"suppressions": [
        {"checkId": "gateway.trusted_proxy_auth", "reason": "reviewed, proxy handles SSO"},
    ]}}}
    r = check_audit_suppressions(_ctx(cfg))
    assert r.status == "WARN"
    assert any("gateway.trusted_proxy_auth" in e for e in r.evidence)


def test_b173_elevated_allowfrom_wildcard_templated_checkid_fails():
    # tools.elevated.allowFrom.<provider>.wildcard -- provider varies, suffix/severity don't.
    cfg = {"security": {"audit": {"suppressions": [
        {"checkId": "tools.elevated.allowFrom.telegram.wildcard"},
    ]}}}
    r = check_audit_suppressions(_ctx(cfg))
    assert r.status == "FAIL"


def test_b173_elevated_allowfrom_large_templated_checkid_warns_not_fails():
    # the sibling ".large" templated checkId is a conditional/lesser finding -- WARN only.
    cfg = {"security": {"audit": {"suppressions": [
        {"checkId": "tools.elevated.allowFrom.discord.large"},
    ]}}}
    assert check_audit_suppressions(_ctx(cfg)).status == "WARN"


def test_b173_conditional_severity_checkid_stays_warn():
    # gateway.control_ui.allowed_origins_wildcard is `exposed ? "critical" : "warn"` in the
    # native source -- clawseccheck cannot re-derive that statically, so it must NOT
    # escalate to FAIL on a guess (C-135 / Golden Rule #5).
    cfg = {"security": {"audit": {"suppressions": [
        {"checkId": "gateway.control_ui.allowed_origins_wildcard"},
    ]}}}
    assert check_audit_suppressions(_ctx(cfg)).status == "WARN"


def test_b173_mixed_entries_any_critical_hit_escalates_to_fail():
    cfg = {"security": {"audit": {"suppressions": [
        {"checkId": "logging.redact_off"},
        {"checkId": "gateway.loopback_no_auth"},
    ]}}}
    r = check_audit_suppressions(_ctx(cfg))
    assert r.status == "FAIL"
    joined = " ".join(r.evidence)
    assert "logging.redact_off" in joined and "gateway.loopback_no_auth" in joined


# ---- malformed entries: never crash, never a guess FAIL ----

def test_b173_entry_missing_checkid_ignored():
    cfg = {"security": {"audit": {"suppressions": [
        {"reason": "oops no checkId"},
    ]}}}
    r = check_audit_suppressions(_ctx(cfg))
    assert r.status == "WARN"


def test_b173_non_dict_entries_ignored_without_crash():
    cfg = {"security": {"audit": {"suppressions": ["not-a-dict", 42, None]}}}
    r = check_audit_suppressions(_ctx(cfg))
    assert r.status == "WARN"


def test_b173_blank_checkid_string_ignored():
    cfg = {"security": {"audit": {"suppressions": [{"checkId": "   "}]}}}
    r = check_audit_suppressions(_ctx(cfg))
    assert r.status == "WARN"


# ---- UNKNOWN path: unreadable/unparseable config, never a fake PASS/FAIL (Golden Rule #4) ----

def test_b173_unreadable_config_returns_unknown():
    c = _ctx({"security": {"audit": {"suppressions": [{"checkId": "gateway.bind_no_auth"}]}}})
    c.config_parse_error = True
    r = check_audit_suppressions(c)
    assert r.status == "UNKNOWN"
    assert r.id == "B173"


def test_b173_never_unknown_when_config_is_readable():
    for cfg in (
        {},
        {"security": {"audit": {"suppressions": []}}},
        {"security": {"audit": {"suppressions": [{"checkId": "logging.redact_off"}]}}},
        {"security": {"audit": {"suppressions": [{"checkId": "gateway.bind_no_auth"}]}}},
    ):
        assert check_audit_suppressions(_ctx(cfg)).status != "UNKNOWN"
