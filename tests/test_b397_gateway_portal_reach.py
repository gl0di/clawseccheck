"""B397 — agent-opened Gateway portals (gateway.portals, the `portal` tool) are gated
only by a per-portal bearer token in the URL, never by gateway.auth, trusted-proxy
identity or any access layer in front of the Gateway.

See clawseccheck/checks/_config.py::check_gateway_portal_reach's own docstring for the
full grounding trail (openclaw@2026.9.6). This test module pins the design's verdict
matrix: three transports (ingress / Tailscale Serve / direct), a loopback-direct PASS
decided before any tool-policy read, an operator-only PASS when no agent scope holds
the `portal` tool, and a WARN only when a not-fully-sandboxed agent scope is granted the
tool while the transport is reachable off-host or unresolved. Never FAIL (advisory,
unscored).
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import (
    BY_ID,
    FAIL_WEIGHT_STATUSES,
    MEDIUM,
    PASS,
    UNKNOWN,
    WARN,
    ast_for,
    owasp_for,
)
from clawseccheck.checks import (
    CHECKS,
    CHECKS_BY_ID,
    _b397_direct_reach,
    _b397_ingress_domain_ok,
    _portal_model_version,
    check_gateway_portal_reach,
)
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_BASE_GATEWAY = {
    "mode": "local",
    "port": 18789,
    "bind": "loopback",
    "auth": {"mode": "token", "token": "a-very-long-token-of-32-characters"},
    "tailscale": {"mode": "off"},
}


def _cfg(gateway_overrides=None, **top):
    gateway = dict(_BASE_GATEWAY)
    if gateway_overrides:
        gateway.update(gateway_overrides)
    cfg = {
        "meta": {"lastTouchedVersion": "2026.9.6"},
        "gateway": gateway,
        "models": {"main": {"provider": "ollama/llama3"}},
    }
    cfg.update(top)
    return cfg


def _ctx(cfg, tmp_path, **kwargs):
    return Context(home=tmp_path, config=cfg, config_found=True, **kwargs)


def _run(cfg, tmp_path, **kwargs):
    return check_gateway_portal_reach(_ctx(cfg, tmp_path, **kwargs))


def _f(name: str):
    return check_gateway_portal_reach(collect(FIXTURES / name))


# ------------------------------------------------------------------ fixture-level

def test_clean_loopback_fixture_passes():
    f = _f("clean_b397_portals_loopback")
    assert f.status == PASS, f.detail
    assert "loopback" in f.detail


def test_clean_ingress_no_agent_portal_fixture_passes_operator_only():
    f = _f("clean_b397_ingress_no_agent_portal")
    assert f.status == PASS, f.detail
    assert "operator" in f.detail


def test_bad_ingress_agent_portal_fixture_warns():
    f = _f("bad_b397_ingress_agent_portal")
    assert f.status == WARN, f.detail
    assert "gateway.portals.ingress" in f.detail


def test_bad_direct_lan_agent_portal_fixture_warns():
    f = _f("bad_b397_direct_lan_agent_portal")
    assert f.status == WARN, f.detail
    assert "transport=direct" in f.evidence


def test_unknown_ingress_unknown_field_fixture_is_unknown():
    f = _f("unknown_b397_ingress_unknown_field")
    assert f.status == UNKNOWN, f.detail
    assert "'bindHost'" in f.detail


# ------------------------------------------------------------------ never-fails + catalog

_SYNTHETIC_CONFIGS = [
    _cfg(),  # loopback, no tools at all
    _cfg({"bind": "lan"}, **{"tools": {"profile": "coding"}}),
    _cfg(
        {"portals": {"ingress": {"domain": "portals.example.com", "port": 18790}}},
        **{"tools": {"profile": "coding"}},
    ),
    _cfg({"tailscale": {"mode": "funnel"}}, **{"tools": {"profile": "coding"}}),
    {"gateway": []},
    {"gateway": {"portals": None}},
    {},
]


def test_never_fails_on_fixtures_and_synthetic_configs(tmp_path):
    for name in (
        "clean_b397_portals_loopback",
        "clean_b397_ingress_no_agent_portal",
        "bad_b397_ingress_agent_portal",
        "bad_b397_direct_lan_agent_portal",
        "unknown_b397_ingress_unknown_field",
    ):
        assert _f(name).status not in FAIL_WEIGHT_STATUSES, name
    for cfg in _SYNTHETIC_CONFIGS:
        assert _run(cfg, tmp_path).status not in FAIL_WEIGHT_STATUSES, cfg


def test_catalog_meta_is_unscored_advisory():
    meta = BY_ID["B397"]
    assert meta.scored is False
    assert meta.block == "advisory"
    assert meta.severity == MEDIUM
    assert meta.surface == "gateway"


def test_registered_in_checks_by_id_and_checks_list():
    assert "B397" in CHECKS_BY_ID
    assert check_gateway_portal_reach in CHECKS


def test_owasp_and_ast_mappings():
    assert owasp_for("B397") == ("LLM06",)
    assert ast_for("B397") == ("AST06",)


def test_no_status_is_in_fail_weight_statuses_for_this_check(tmp_path):
    seen = {_run(cfg, tmp_path).status for cfg in _SYNTHETIC_CONFIGS}
    assert not seen & FAIL_WEIGHT_STATUSES


def test_no_config_is_unknown(tmp_path):
    f = check_gateway_portal_reach(collect(tmp_path))
    assert f.status == UNKNOWN
    assert "No config was read" in f.detail


def test_unparseable_config_is_unknown_engine_degraded(tmp_path):
    (tmp_path / "openclaw.json").write_text("{not json", encoding="utf-8")
    ctx = collect(tmp_path)
    f = check_gateway_portal_reach(ctx)
    assert f.status == UNKNOWN
    assert f.engine_degraded is True


# ------------------------------------------------------------------ transport: ingress

def test_ingress_wins_over_tailscale_serve(tmp_path):
    cfg = _cfg(
        {
            "tailscale": {"mode": "serve"},
            "portals": {"ingress": {"domain": "portals.example.com", "port": 18790}},
        },
        tools={"profile": "coding"},
    )
    f = _run(cfg, tmp_path)
    assert f.status == WARN
    assert "transport=ingress" in f.evidence


def test_ingress_wins_over_lan_bind(tmp_path):
    cfg = _cfg(
        {"bind": "lan", "portals": {"ingress": {"domain": "portals.example.com", "port": 18790}}},
        tools={"profile": "coding"},
    )
    f = _run(cfg, tmp_path)
    assert f.status == WARN
    assert "transport=ingress" in f.evidence
    assert not any("gateway.bind" in e for e in f.evidence)


def test_ingress_with_tailscale_mode_on_is_still_ingress_warn(tmp_path):
    cfg = _cfg(
        {
            "tailscale": {"mode": "on"},
            "portals": {"ingress": {"domain": "portals.example.com", "port": 18790}},
        },
        tools={"profile": "coding"},
    )
    f = _run(cfg, tmp_path)
    assert f.status == WARN
    assert "transport=ingress" in f.evidence


# ------------------------------------------------------------------ transport: tailscale

def test_tailscale_serve_warns(tmp_path):
    cfg = _cfg({"tailscale": {"mode": "serve"}}, tools={"profile": "coding"})
    f = _run(cfg, tmp_path)
    assert f.status == WARN
    assert "Tailscale Serve" in f.detail
    assert "tailnet" in f.detail


def test_tailscale_funnel_warns_and_pins_serve_only(tmp_path):
    cfg = _cfg({"tailscale": {"mode": "funnel"}}, tools={"profile": "coding"})
    f = _run(cfg, tmp_path)
    assert f.status == WARN
    assert "never Funnel" in f.detail


# ------------------------------------------------------------------ transport: direct

def test_direct_lan_warns(tmp_path):
    cfg = _cfg({"bind": "lan"}, tools={"profile": "coding"})
    assert _run(cfg, tmp_path).status == WARN


def test_direct_tailnet_warns(tmp_path):
    cfg = _cfg({"bind": "tailnet"}, tools={"profile": "coding"})
    assert _run(cfg, tmp_path).status == WARN


def test_direct_host_port_form_warns(tmp_path):
    cfg = _cfg({"bind": "0.0.0.0:8080"}, tools={"profile": "coding"})
    assert _run(cfg, tmp_path).status == WARN


def test_direct_custom_remote_host_warns(tmp_path):
    cfg = _cfg(
        {"bind": "custom", "customBindHost": "192.168.1.10"}, tools={"profile": "coding"}
    )
    assert _run(cfg, tmp_path).status == WARN


def test_direct_custom_loopback_host_passes(tmp_path):
    cfg = _cfg({"bind": "custom", "customBindHost": "127.0.0.1"}, tools={"profile": "coding"})
    f = _run(cfg, tmp_path)
    assert f.status == PASS
    assert "loopback" in f.detail


def test_direct_loopback_host_port_form_passes(tmp_path):
    cfg = _cfg({"bind": "127.0.0.1:18789"}, tools={"profile": "coding"})
    f = _run(cfg, tmp_path)
    assert f.status == PASS


def test_direct_bind_absent_passes_and_says_not_set(tmp_path):
    gateway = dict(_BASE_GATEWAY)
    del gateway["bind"]
    cfg = {
        "meta": {"lastTouchedVersion": "2026.9.6"},
        "gateway": gateway,
        "tools": {"profile": "coding"},
        "models": {"main": {"provider": "ollama/llama3"}},
    }
    f = _run(cfg, tmp_path)
    assert f.status == PASS
    assert "not set" in f.detail


def test_gateway_block_absent_passes(tmp_path):
    cfg = {
        "meta": {"lastTouchedVersion": "2026.9.6"},
        "tools": {"profile": "coding"},
        "models": {"main": {"provider": "ollama/llama3"}},
    }
    f = _run(cfg, tmp_path)
    assert f.status == PASS


def test_direct_tls_enabled_evidence_says_https(tmp_path):
    cfg = _cfg({"bind": "lan", "tls": {"enabled": True}}, tools={"profile": "coding"})
    f = _run(cfg, tmp_path)
    assert f.status == WARN
    assert any("HTTPS" in e for e in f.evidence)


def test_direct_tls_disabled_evidence_says_plain_http(tmp_path):
    cfg = _cfg({"bind": "lan"}, tools={"profile": "coding"})
    f = _run(cfg, tmp_path)
    assert f.status == WARN
    assert any("plain HTTP" in e for e in f.evidence)


# ------------------------------------------------------------------ unresolved bind

def test_bind_auto_with_agent_grant_is_unknown(tmp_path):
    cfg = _cfg({"bind": "auto"}, tools={"profile": "coding"})
    f = _run(cfg, tmp_path)
    assert f.status == UNKNOWN
    assert "gateway.bind" in f.detail


def test_bind_auto_with_no_grant_passes_operator_only(tmp_path):
    cfg = _cfg({"bind": "auto"}, tools={"profile": "minimal"})
    f = _run(cfg, tmp_path)
    assert f.status == PASS
    assert "operator" in f.detail


def test_bind_custom_without_customBindHost_and_grant_is_unknown(tmp_path):
    cfg = _cfg({"bind": "custom"}, tools={"profile": "coding"})
    f = _run(cfg, tmp_path)
    assert f.status == UNKNOWN


def test_bind_int_with_grant_is_unknown(tmp_path):
    cfg = _cfg({"bind": 8080}, tools={"profile": "coding"})
    f = _run(cfg, tmp_path)
    assert f.status == UNKNOWN


# ------------------------------------------------------------------ tool gating

def test_ingress_with_minimal_profile_passes(tmp_path):
    cfg = _cfg(
        {"portals": {"ingress": {"domain": "portals.example.com", "port": 18790}}},
        tools={"profile": "minimal"},
    )
    assert _run(cfg, tmp_path).status == PASS


def test_ingress_with_messaging_profile_passes(tmp_path):
    cfg = _cfg(
        {"portals": {"ingress": {"domain": "portals.example.com", "port": 18790}}},
        tools={"profile": "messaging"},
    )
    assert _run(cfg, tmp_path).status == PASS


def test_ingress_with_portal_denied_passes(tmp_path):
    cfg = _cfg(
        {"portals": {"ingress": {"domain": "portals.example.com", "port": 18790}}},
        tools={"profile": "coding", "deny": ["portal"]},
    )
    assert _run(cfg, tmp_path).status == PASS


def test_ingress_with_group_ui_denied_passes(tmp_path):
    cfg = _cfg(
        {"portals": {"ingress": {"domain": "portals.example.com", "port": 18790}}},
        tools={"profile": "coding", "deny": ["group:ui"]},
    )
    assert _run(cfg, tmp_path).status == PASS


def test_sandbox_all_no_roster_passes(tmp_path):
    cfg = _cfg({"bind": "lan"}, tools={"profile": "coding"},
               agents={"defaults": {"sandbox": {"mode": "all"}}})
    assert _run(cfg, tmp_path).status == PASS


def test_sandbox_non_main_no_roster_warns(tmp_path):
    cfg = _cfg({"bind": "lan"}, tools={"profile": "coding"},
               agents={"defaults": {"sandbox": {"mode": "non-main"}}})
    assert _run(cfg, tmp_path).status == WARN


def test_roster_one_sandboxed_one_not_names_only_the_unsandboxed(tmp_path):
    cfg = _cfg(
        {"bind": "lan"},
        tools={"profile": "coding"},
        agents={
            "entries": {
                "safe": {"sandbox": {"mode": "all"}},
                "risky": {},
            }
        },
    )
    f = _run(cfg, tmp_path)
    assert f.status == WARN
    assert any("risky" in e for e in f.evidence)
    assert not any("safe" in e for e in f.evidence)


def test_roster_all_deny_portal_global_unset_passes(tmp_path):
    cfg = _cfg(
        {"bind": "lan"},
        agents={
            "entries": {
                "a": {"tools": {"profile": "coding", "deny": ["portal"]}},
                "b": {"tools": {"profile": "coding", "deny": ["portal"]}},
            }
        },
    )
    f = _run(cfg, tmp_path)
    assert f.status == PASS


def test_global_byprovider_opaque_all_rows_is_unknown(tmp_path):
    cfg = _cfg(
        {"portals": {"ingress": {"domain": "portals.example.com", "port": 18790}}},
        tools={"profile": "coding", "byProvider": {"anthropic": {"allow": ["portal"]}}},
    )
    f = _run(cfg, tmp_path)
    assert f.status == UNKNOWN


def test_one_opaque_one_granted_warns_with_possible_language(tmp_path):
    cfg = _cfg(
        {"portals": {"ingress": {"domain": "portals.example.com", "port": 18790}}},
        tools={"profile": "coding"},
        agents={
            "entries": {
                "opaque": {"tools": {"byProvider": {"anthropic": {"allow": ["portal"]}}}},
                "plain": {},
            }
        },
    )
    f = _run(cfg, tmp_path)
    assert f.status == WARN
    assert any("may open portals" in e for e in f.evidence)


def test_malformed_tools_block_is_unknown_with_ingress(tmp_path):
    cfg = _cfg(
        {"portals": {"ingress": {"domain": "portals.example.com", "port": 18790}}},
        tools={"allow": "portal"},
    )
    f = _run(cfg, tmp_path)
    assert f.status == UNKNOWN


def test_malformed_tools_block_with_loopback_still_passes_reach_first(tmp_path):
    cfg = _cfg(tools={"allow": "portal"})
    f = _run(cfg, tmp_path)
    assert f.status == PASS


# ------------------------------------------------------------------ shape UNKNOWNs

def test_gateway_not_a_dict_is_unknown(tmp_path):
    f = _run({"gateway": []}, tmp_path)
    assert f.status == UNKNOWN


def test_portals_null_is_unknown(tmp_path):
    cfg = _cfg({"portals": None})
    assert _run(cfg, tmp_path).status == UNKNOWN


def test_portals_string_is_unknown(tmp_path):
    cfg = _cfg({"portals": "x"})
    assert _run(cfg, tmp_path).status == UNKNOWN


def test_portals_unrecognised_key_is_unknown(tmp_path):
    cfg = _cfg({"portals": {"foo": 1}})
    f = _run(cfg, tmp_path)
    assert f.status == UNKNOWN
    assert "'foo'" in f.detail


def test_portals_empty_object_passes(tmp_path):
    cfg = _cfg({"portals": {}})
    assert _run(cfg, tmp_path).status == PASS


def test_ingress_null_is_unknown(tmp_path):
    cfg = _cfg({"portals": {"ingress": None}})
    assert _run(cfg, tmp_path).status == UNKNOWN


def test_ingress_without_port_is_unknown(tmp_path):
    cfg = _cfg({"portals": {"ingress": {"domain": "portals.example.com"}}})
    f = _run(cfg, tmp_path)
    assert f.status == UNKNOWN
    assert "port" in f.detail


def test_ingress_port_shapes_are_unknown(tmp_path):
    for bad_port in ("18790", True, 0, 70000):
        cfg = _cfg({"portals": {"ingress": {"domain": "portals.example.com", "port": bad_port}}})
        f = _run(cfg, tmp_path)
        assert f.status == UNKNOWN, bad_port


def test_ingress_domain_shapes_are_unknown(tmp_path):
    bad_domains = [
        "",
        5,
        {"source": "env", "provider": "default", "id": "X"},
        "localhost",
        "10.0.0.1",
        "bad_label.example.com",
        "${PORTAL_DOMAIN}",
    ]
    for bad_domain in bad_domains:
        cfg = _cfg({"portals": {"ingress": {"domain": bad_domain, "port": 18790}}})
        f = _run(cfg, tmp_path)
        assert f.status == UNKNOWN, bad_domain


def test_ingress_port_equals_default_gateway_port_when_gateway_port_absent(tmp_path):
    gateway = dict(_BASE_GATEWAY)
    del gateway["port"]
    gateway["portals"] = {"ingress": {"domain": "portals.example.com", "port": 18789}}
    cfg = {"meta": {"lastTouchedVersion": "2026.9.6"}, "gateway": gateway,
           "models": {"main": {"provider": "ollama/llama3"}}}
    f = _run(cfg, tmp_path)
    assert f.status == UNKNOWN
    assert "18789" in f.detail


def test_ingress_port_equals_explicit_gateway_port(tmp_path):
    cfg = _cfg(
        {"port": 19000, "portals": {"ingress": {"domain": "portals.example.com", "port": 19000}}}
    )
    f = _run(cfg, tmp_path)
    assert f.status == UNKNOWN


def test_ingress_port_differs_from_gateway_port_is_allowed(tmp_path):
    cfg = _cfg(
        {"port": 19000, "portals": {"ingress": {"domain": "portals.example.com", "port": 18789}}},
        tools={"profile": "coding"},
    )
    f = _run(cfg, tmp_path)
    assert f.status == WARN


def test_tailscale_malformed_is_unknown(tmp_path):
    cfg = _cfg({"tailscale": "on"})
    f = _run(cfg, tmp_path)
    assert f.status == UNKNOWN


def test_tailscale_mode_unrecognised_is_unknown(tmp_path):
    cfg = _cfg({"tailscale": {"mode": "on"}})
    f = _run(cfg, tmp_path)
    assert f.status == UNKNOWN


def test_ingress_ignores_bad_tailscale_mode(tmp_path):
    cfg = _cfg(
        {
            "tailscale": {"mode": "on"},
            "portals": {"ingress": {"domain": "portals.example.com", "port": 18790}},
        },
        tools={"profile": "coding"},
    )
    f = _run(cfg, tmp_path)
    assert f.status == WARN
    assert "transport=ingress" in f.evidence


# ------------------------------------------------------------------ version

def test_installed_dist_predates_9_6_with_ingress_is_unknown(tmp_path):
    cfg = _cfg({"portals": {"ingress": {"domain": "portals.example.com", "port": 18790}}})
    f = _run(cfg, tmp_path, installed_dist_version="2026.9.5")
    assert f.status == UNKNOWN
    assert "predates" in f.detail


def test_installed_dist_predates_9_6_direct_lan_is_unknown(tmp_path):
    cfg = _cfg({"bind": "lan"})
    f = _run(cfg, tmp_path, installed_dist_version="2026.9.5")
    assert f.status == UNKNOWN


def test_installed_dist_at_9_6_warns_without_qualifier(tmp_path):
    cfg = _cfg({"bind": "lan"}, tools={"profile": "coding"})
    f = _run(cfg, tmp_path, installed_dist_version="2026.9.6")
    assert f.status == WARN
    assert "2026.9.6" not in f.fix


def test_none_installed_with_stamp_9_6_evaluated_no_qualifier(tmp_path):
    cfg = _cfg({"bind": "lan"}, tools={"profile": "coding"})
    f = _run(cfg, tmp_path)
    assert f.status == WARN
    assert "2026.9.6" not in f.fix


def test_none_installed_with_no_stamp_evaluated_with_qualifier(tmp_path):
    cfg = {
        "gateway": dict(_BASE_GATEWAY, bind="lan"),
        "tools": {"profile": "coding"},
        "models": {"main": {"provider": "ollama/llama3"}},
    }
    f = _run(cfg, tmp_path)
    assert f.status == WARN
    assert "2026.9.6" in f.fix


def test_none_installed_with_stale_stamp_is_not_treated_as_grounded(tmp_path):
    cfg = {
        "meta": {"lastTouchedVersion": "2026.9.5"},
        "gateway": dict(_BASE_GATEWAY, bind="lan"),
        "tools": {"profile": "coding"},
        "models": {"main": {"provider": "ollama/llama3"}},
    }
    f = _run(cfg, tmp_path)
    # A stamp below the grounded threshold is "unknown", not "predates" -- still
    # evaluated with the fix qualifier, never a silent PASS/false confidence.
    assert f.status == WARN
    assert "2026.9.6" in f.fix


def test_prerelease_installed_version_falls_through_to_stamp(tmp_path):
    cfg = _cfg({"bind": "lan"}, tools={"profile": "coding"})
    f = _run(cfg, tmp_path, installed_dist_version="2026.9.6-beta.1")
    assert f.status == WARN
    assert "2026.9.6" not in f.fix  # stamp (2026.9.6) grounds it


def test_future_installed_version_is_grounded(tmp_path):
    cfg = _cfg({"bind": "lan"}, tools={"profile": "coding"})
    f = _run(cfg, tmp_path, installed_dist_version="2026.10.1")
    assert f.status == WARN
    assert "2026.9.6" not in f.fix


def test_installed_0_0_0_is_unknown_generation_but_evaluated(tmp_path):
    cfg = _cfg({"bind": "lan"}, tools={"profile": "coding"})
    f = _run(cfg, tmp_path, installed_dist_version="0.0.0")
    assert f.status == WARN
    assert "2026.9.6" in f.fix


def test_portal_model_version_direct_answers(tmp_path):
    ctx_grounded = _ctx(_cfg(), tmp_path, installed_dist_version="2026.9.6")
    ctx_predates = _ctx(_cfg(), tmp_path, installed_dist_version="2026.7.1-2")
    ctx_unknown = _ctx({}, tmp_path, installed_dist_version="0.0.0")
    assert _portal_model_version(ctx_grounded) == "grounded"
    assert _portal_model_version(ctx_predates) == "predates"
    assert _portal_model_version(ctx_unknown) == "unknown"


# ------------------------------------------------------------------ hygiene

def test_detail_is_byte_identical_regardless_of_installed_version(tmp_path):
    cfg = _cfg({"bind": "lan"}, tools={"profile": "coding"})
    f_with = _run(cfg, tmp_path, installed_dist_version="2026.9.6")
    f_without = _run(cfg, tmp_path)
    assert f_with.detail == f_without.detail


def test_secret_shaped_key_name_is_redacted():
    fragments = ("sk-ant-", "api03-", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    secret_shaped = "".join(fragments)
    from clawseccheck.logsafe import redact

    assert secret_shaped not in redact(repr(secret_shaped))


def test_secret_shaped_key_via_unknown_field_path_is_redacted(tmp_path):
    fragments = ("sk-ant-", "api03-", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    secret_shaped_key = "".join(fragments)
    cfg = _cfg({"portals": {"ingress": {"domain": "portals.example.com", "port": 18790,
                                          secret_shaped_key: 1}}})
    f = _run(cfg, tmp_path)
    assert f.status == UNKNOWN
    assert secret_shaped_key not in f.detail
    assert secret_shaped_key not in "".join(f.evidence)
    assert secret_shaped_key not in f.fix


def test_pass_detail_has_no_warn_consequence_language(tmp_path):
    cfg = _cfg(tools={"profile": "coding"})
    f = _run(cfg, tmp_path)
    assert f.status == PASS
    assert "allowing" not in f.detail


def test_warn_details_contain_allowing(tmp_path):
    for cfg in (
        _cfg({"bind": "lan"}, tools={"profile": "coding"}),
        _cfg({"tailscale": {"mode": "serve"}}, tools={"profile": "coding"}),
        _cfg({"portals": {"ingress": {"domain": "portals.example.com", "port": 18790}}},
             tools={"profile": "coding"}),
    ):
        f = _run(cfg, tmp_path)
        assert f.status == WARN
        assert "allowing" in f.detail


# ------------------------------------------------------------------ helpers, unit-tested directly

def test_b397_ingress_domain_ok_accepts_a_plain_wildcard_domain():
    assert _b397_ingress_domain_ok("portals.example.com") is True


def test_b397_ingress_domain_ok_rejects_ip_literal():
    assert _b397_ingress_domain_ok("10.0.0.1") is False


def test_b397_ingress_domain_ok_rejects_underscore_label():
    assert _b397_ingress_domain_ok("bad_label.example.com") is False


def test_b397_ingress_domain_ok_rejects_no_dot():
    assert _b397_ingress_domain_ok("localhost") is False


def test_b397_ingress_domain_ok_rejects_too_long():
    assert _b397_ingress_domain_ok("a" * 250 + ".com") is False


def test_b397_direct_reach_loopback_absent_bind():
    assert _b397_direct_reach({}) == ("local", "loopback (gateway.bind is not set)")


def test_b397_direct_reach_lan_is_remote():
    reach, label = _b397_direct_reach({"gateway": {"bind": "lan"}})
    assert reach == "remote"
    assert label == "gateway.bind=lan"


def test_b397_direct_reach_auto_is_unresolved():
    reach, _label = _b397_direct_reach({"gateway": {"bind": "auto"}})
    assert reach == "unresolved"


def test_b397_direct_reach_custom_loopback_is_local():
    reach, label = _b397_direct_reach(
        {"gateway": {"bind": "custom", "customBindHost": "127.0.0.1"}}
    )
    assert reach == "local"
    assert "127.0.0.1" in label


def test_b397_direct_reach_custom_without_host_is_unresolved():
    reach, _label = _b397_direct_reach({"gateway": {"bind": "custom"}})
    assert reach == "unresolved"


def test_b397_direct_reach_non_string_bind_is_unresolved():
    reach, label = _b397_direct_reach({"gateway": {"bind": 8080}})
    assert reach == "unresolved"
    assert "not a string" in label
