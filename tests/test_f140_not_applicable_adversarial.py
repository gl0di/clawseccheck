"""F-140 adversarial matrix — "try to make it lie". For every migrated check, every
config shape in which its surface REALLY EXISTS must fail to reach the migrated
``not servers``-style branch, so ``not_applicable`` can never be True.

This is the C-135-shaped half of the migration: the degradation matrix
(``tests/test_f140_not_applicable_degrades.py``) proves the flag drops when the READ was
incomplete; this file proves it never fires when the SURFACE was present. A false
``not_applicable=True`` is the exact lying-PASS shape the field was introduced to
prevent -- it tells the owner "this doesn't apply to you" about a surface they actually
have, and (via ``adjudication._is_borderline``) drops the finding out of the judge
packet and the ignore proposals at the same time.

Each check is exercised through EVERY discovery shape its own helper understands, not
just the modern one -- a legacy shape that the helper reads but this test forgets is
precisely how a "no X configured" branch starts firing on a host that has X.

Offline, read-only.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import UNKNOWN
from clawseccheck.checks import (
    _shared,
    check_control_plane_mutation,
    check_multiagent_exposure,
    check_outbound_proxy,
    check_path_safety,
    check_plugin_app_server_command,
    check_plugin_permission_mode,
    check_secrets_provider_exec,
    check_sender_identity,
    check_session_visibility,
    check_subagents,
)
from clawseccheck.collector import Context


def _ctx(cfg: dict) -> Context:
    """A COMPLETE config read -- so if the flag still comes back True, it is the
    surface-detection logic that is wrong, not the completeness predicate."""
    c = Context(home=Path("/nonexistent"), config_found=True, config_parse_error=False)
    c.config = cfg
    return c


_SUBAGENT_SPEC = {"delegationMode": "auto"}

# ---------------------------------------------------------------------------
# B46 / B18 -- _has_subagents() reads four shapes (agents.subagents,
# agents.defaults.subagents, a multi-entry agents.list, and the PER-ENTRY
# agents.list[i].subagents added in B-296 round 2).
# ---------------------------------------------------------------------------
_SUBAGENT_FORMS = {
    "agents.subagents": {"agents": {"subagents": _SUBAGENT_SPEC}},
    "agents.defaults.subagents": {"agents": {"defaults": {"subagents": _SUBAGENT_SPEC}}},
    "agents.list_multi_entry": {"agents": {"list": [{"id": "a"}, {"id": "b"}]}},
    "agents.list_entry_subagents": {
        "agents": {"list": [{"id": "a", "subagents": _SUBAGENT_SPEC}]}
    },
}


@pytest.mark.parametrize("form", sorted(_SUBAGENT_FORMS))
def test_b46_delegation_present_in_every_form_stays_applicable(form):
    f = check_multiagent_exposure(_ctx(_SUBAGENT_FORMS[form]))
    assert f.status != UNKNOWN, f"form={form}: B46 wrongly saw no multi-agent topology"
    assert f.not_applicable is False, form


@pytest.mark.parametrize("form", sorted(_SUBAGENT_FORMS))
def test_b18_delegation_present_in_every_form_stays_applicable(form):
    """NB: B18 may legitimately still return UNKNOWN here -- its SECOND UNKNOWN branch
    ("subagents configured but no elevated/exec tools detected") is deliberately NOT
    migrated. That is the point: the status may be UNKNOWN, but the flag must be False,
    because the delegation surface demonstrably exists."""
    f = check_subagents(_ctx(_SUBAGENT_FORMS[form]))
    assert f.not_applicable is False, form


def test_b18_second_unknown_branch_is_never_not_applicable():
    """The un-migrated low-risk branch, reached explicitly: delegation IS configured,
    there simply are no elevated/exec tools to inherit."""
    f = check_subagents(_ctx({"agents": {"subagents": _SUBAGENT_SPEC}}))
    assert f.status == UNKNOWN
    assert f.not_applicable is False
    assert "no elevated/exec tools" in f.detail


# ---------------------------------------------------------------------------
# B30 -- channels.<provider>, with the B-041 enabled:false carve-out.
# ---------------------------------------------------------------------------

def test_b30_live_channel_stays_applicable():
    f = check_sender_identity(_ctx({"channels": {"telegram": {"token": "x"}}}))
    assert f.status != UNKNOWN
    assert f.not_applicable is False


def test_b30_channel_without_explicit_enabled_is_live():
    """``enabled`` absent means live (the filter is ``is not False``), so a config that
    merely omits the key must not be read as "no channels"."""
    f = check_sender_identity(_ctx({"channels": {"slack": {}}}))
    assert f.not_applicable is False


def test_b30_all_channels_disabled_is_not_applicable():
    """Pinned judgement call: a channel with ``enabled: false`` matches no sender, so its
    identity flags are not a live bypass (B-041 already routes this to UNKNOWN rather
    than risking a §5 hard-FAIL false positive). With the config read completely, that
    is genuine surface absence, not an unassessed risk."""
    f = check_sender_identity(_ctx({"channels": {"telegram": {"enabled": False}}}))
    assert f.status == UNKNOWN
    assert f.not_applicable is True


# ---------------------------------------------------------------------------
# B39 -- EITHER `session` OR `tools.sessions` is enough of a surface.
# ---------------------------------------------------------------------------
_SESSION_FORMS = {
    "session_only": {"session": {"dmScope": "per-peer"}},
    "tools.sessions_only": {"tools": {"sessions": {"visibility": "self"}}},
    "both": {"session": {"dmScope": "per-peer"}, "tools": {"sessions": {"visibility": "self"}}},
}


@pytest.mark.parametrize("form", sorted(_SESSION_FORMS))
def test_b39_session_surface_present_stays_applicable(form):
    f = check_session_visibility(_ctx(_SESSION_FORMS[form]))
    assert f.status != UNKNOWN, f"form={form}: B39 wrongly saw no session config"
    assert f.not_applicable is False, form


# ---------------------------------------------------------------------------
# B32 -- any `gateway` dict is a surface, including an empty one.
# ---------------------------------------------------------------------------

def test_b32_gateway_present_stays_applicable():
    f = check_control_plane_mutation(_ctx({"gateway": {"bind": "127.0.0.1"}}))
    assert f.status != UNKNOWN
    assert f.not_applicable is False


def test_b32_empty_gateway_dict_is_still_a_surface():
    """``gateway: {}`` is a declared gateway with defaults -- the check's own guard is
    ``isinstance(gw, dict)``, not truthiness, and this pins that it stays that way."""
    f = check_control_plane_mutation(_ctx({"gateway": {}}))
    assert f.status != UNKNOWN
    assert f.not_applicable is False


# ---------------------------------------------------------------------------
# B57 / B167 -- _plugins() reads BOTH plugins.entries.<name> and the legacy bare
# plugins map.
# ---------------------------------------------------------------------------
_PLUGIN_FORMS = {
    "plugins.entries": {"plugins": {"entries": {"codex": {}}}},
    "legacy_bare_plugins_map": {"plugins": {"codex": {}}},
}


@pytest.mark.parametrize("form", sorted(_PLUGIN_FORMS))
def test_b57_plugin_present_in_every_form_stays_applicable(form):
    f = check_plugin_permission_mode(_ctx(_PLUGIN_FORMS[form]))
    assert f.status != UNKNOWN, f"form={form}: B57 wrongly saw no installed plugin"
    assert f.not_applicable is False, form


@pytest.mark.parametrize("form", sorted(_PLUGIN_FORMS))
def test_b167_plugin_present_in_every_form_stays_applicable(form):
    f = check_plugin_app_server_command(_ctx(_PLUGIN_FORMS[form]))
    assert f.status != UNKNOWN, f"form={form}: B167 wrongly saw no installed plugin"
    assert f.not_applicable is False, form


def test_b167_plugin_without_appserver_command_passes_not_not_applicable():
    """The most tempting mis-migration: plugins exist but none sets appServer.command.
    That is a real assessment of a real surface (PASS), never surface absence."""
    f = check_plugin_app_server_command(_ctx({"plugins": {"entries": {"codex": {}}}}))
    assert f.status != UNKNOWN
    assert f.not_applicable is False


# ---------------------------------------------------------------------------
# B194 -- two migrated sites, and the exec-provider shape that must clear both.
# ---------------------------------------------------------------------------

def test_b194_site1_no_providers_block_is_not_applicable():
    f = check_secrets_provider_exec(_ctx({}))
    assert f.status == UNKNOWN
    assert f.not_applicable is True
    assert "No secrets.providers configured" in f.detail


def test_b194_site2_providers_without_command_exec_is_not_applicable():
    """Providers exist, but none is the command-based source:"exec" shape -- the schema's
    source:"exec" + pluginIntegration variant has no ``command`` field and so carries
    none of the writable-path/symlink escape surface this check models."""
    ctx = _ctx({"secrets": {"providers": {"vault": {"source": "env"}}}})
    f = check_secrets_provider_exec(ctx)
    assert f.status == UNKNOWN
    assert f.not_applicable is True
    assert "none use a command-based" in f.detail


def test_b194_pluginintegration_exec_without_command_is_not_applicable():
    """The precise shape the site-2 narrowing exists for."""
    ctx = _ctx({
        "secrets": {
            "providers": {"p": {"source": "exec", "pluginIntegration": {"plugin": "x"}}}
        }
    })
    f = check_secrets_provider_exec(ctx)
    assert f.status == UNKNOWN
    assert f.not_applicable is True


def test_b194_command_exec_provider_stays_applicable():
    ctx = _ctx({"secrets": {"providers": {"p": {"source": "exec", "command": "/bin/true"}}}})
    f = check_secrets_provider_exec(ctx)
    assert f.status != UNKNOWN, "B194 wrongly saw no command-based exec provider"
    assert f.not_applicable is False


# ---------------------------------------------------------------------------
# B155 -- the proxy surface exists in three independent shapes, and each one alone must
# keep the check applicable. Missing any of them is how a "no proxy configured" branch
# starts firing on a host that has one.
# ---------------------------------------------------------------------------
_PROXY_FORMS = {
    "proxy.proxyUrl": {"proxy": {"proxyUrl": "https://proxy.internal:8080"}},
    "proxy.enabled": {"proxy": {"enabled": True}},
    "provider_request_proxy_tls": {
        "models": {
            "providers": {
                "openai": {"request": {"proxy": {"tls": {"insecureSkipVerify": True}}}}
            }
        }
    },
    "provider_request_tls": {
        "models": {"providers": {"openai": {"request": {"tls": {"insecureSkipVerify": True}}}}}
    },
    "provider_allow_private_network": {
        "models": {"providers": {"openai": {"request": {"allowPrivateNetwork": True}}}}
    },
    "web_fetch_trusted_env_proxy": {
        "tools": {"web": {"fetch": {"useTrustedEnvProxy": True}}}
    },
}


@pytest.mark.parametrize("form", sorted(_PROXY_FORMS))
def test_b155_proxy_surface_present_in_every_form_stays_applicable(form):
    f = check_outbound_proxy(_ctx(_PROXY_FORMS[form]))
    assert f.status != UNKNOWN, f"form={form}: B155 wrongly saw no outbound-proxy surface"
    assert f.not_applicable is False, form


def test_b155_credential_in_proxy_url_still_fails():
    """The FAIL path is untouched by the migration -- pinned here because B155 is the one
    F-140 site whose non-UNKNOWN branches include a hard FAIL."""
    from clawseccheck.catalog import FAIL
    f = check_outbound_proxy(_ctx({"proxy": {"proxyUrl": "http://user:pw@proxy.internal:8080"}}))
    assert f.status == FAIL
    assert f.not_applicable is False


def test_b155_genuinely_absent_proxy_is_not_applicable():
    f = check_outbound_proxy(_ctx({}))
    assert f.status == UNKNOWN
    assert f.not_applicable is True


# --- C-135 regression: surface presence must be evaluated DIRECTLY, never inferred
# from "the signal scan found nothing". A configured-and-CLEAN per-provider proxy
# produces no FAIL/WARN, and before this fix it fell through to the "no outbound proxy
# configured" UNKNOWN and was reported not-applicable -- telling the owner the check did
# not apply to them about a proxy they had actually configured. ---

def test_b155_clean_provider_proxy_is_pass_not_not_applicable():
    """The exact reported repro. schema-grounded per-provider explicit proxy, clean."""
    from clawseccheck.catalog import PASS
    f = check_outbound_proxy(_ctx({
        "models": {
            "providers": {
                "openai": {
                    "request": {
                        "proxy": {"mode": "explicit-proxy", "url": "https://clean.example.com"}
                    }
                }
            }
        }
    }))
    assert f.status == PASS, (
        "a configured, clean per-provider proxy is a REAL surface assessed clean -- "
        "not an absent one"
    )
    assert f.not_applicable is False


def test_b155_clean_provider_request_tls_is_pass_not_not_applicable():
    """Same hole, second shape: request.tls declared and clean."""
    from clawseccheck.catalog import PASS
    f = check_outbound_proxy(_ctx({
        "models": {"providers": {"openai": {"request": {"tls": {"insecureSkipVerify": False}}}}}
    }))
    assert f.status == PASS
    assert f.not_applicable is False


def test_b155_provider_only_pass_does_not_claim_a_managed_proxy():
    """The provider-only PASS carries its own wording: this host has NO top-level
    proxy.* block, so reusing the managed-proxy sentence would be a different false
    statement."""
    f = check_outbound_proxy(_ctx({
        "models": {"providers": {"openai": {"request": {"proxy": {"url": "https://ok.example"}}}}}
    }))
    assert "Per-provider outbound transport is configured" in f.detail
    assert "Managed outbound proxy is configured" not in f.detail


def test_b155_proxy_enabled_false_stays_not_applicable():
    """Pinned so the fix above does not over-widen. ``enabled`` is a hard gate in the
    dist (``enabled !== true``), so a disabled proxy with no URL carries none of the
    exposures this check models -- genuine surface absence, same reasoning as B30's
    all-disabled channels."""
    f = check_outbound_proxy(_ctx({"proxy": {"enabled": False}}))
    assert f.status == UNKNOWN
    assert f.not_applicable is True


@pytest.mark.parametrize("cfg", [
    {"models": {"providers": {"o": {"request": {"allowPrivateNetwork": False}}}}},
    {"tools": {"web": {"fetch": {"useTrustedEnvProxy": False}}}},
], ids=["allowPrivateNetwork_false", "useTrustedEnvProxy_false"])
def test_b155_request_level_false_booleans_are_not_a_surface(cfg):
    """The other half of "do not over-widen": these two are only signals when TRUE (and
    then they already WARN). An explicit ``false`` is the default posture, so treating it
    as a declared proxy would assert a surface nobody configured -- the mirror-image
    error of the bug this section fixes."""
    f = check_outbound_proxy(_ctx(cfg))
    assert f.status == UNKNOWN
    assert f.not_applicable is True


# --- C-135 round 2: a dict is not automatically a transport. A STUB proxy/TLS object
# (empty, or carrying only unrecognized keys) is a THIRD state, distinct from both
# neighbours it sits between:
#
#   surface absent   -> UNKNOWN, not_applicable=True   (nothing declared at all)
#   surface STUB     -> UNKNOWN, not_applicable=False  (declared, but unassessable)
#   surface present  -> PASS/WARN/FAIL                 (declared and parsed)
#
# Promoting a stub to PASS would claim we assessed something we never parsed -- a false
# PASS on a HIGH scored check. Marking it not_applicable would claim absence when we
# demonstrably read a proxy key. Only a plain UNKNOWN is honest (Golden Rule #4). ---

def _provider_request(req: dict) -> dict:
    return {"models": {"providers": {"openai": {"request": req}}}}


@pytest.mark.parametrize("req", [
    {"proxy": {}},
    {"proxy": {"foo": "bar"}},
    {"proxy": {"url": "   "}},
    {"proxy": {"tls": {}}},
    {"tls": {}},
    {"tls": {"zzz": 1}},
], ids=[
    "empty_proxy", "garbage_proxy_keys", "blank_proxy_url",
    "proxy_with_empty_nested_tls", "empty_tls", "garbage_tls_keys",
])
def test_b155_stub_transport_object_is_plain_unknown(req):
    """Neither PASS (nothing was assessed) nor not_applicable (a proxy key WAS read)."""
    f = check_outbound_proxy(_ctx(_provider_request(req)))
    assert f.status == UNKNOWN, "a stub transport object must not be promoted to PASS"
    assert f.not_applicable is False, (
        "a stub transport object must not claim surface ABSENCE -- the config declares a "
        "proxy/tls key we simply could not parse"
    )


@pytest.mark.parametrize("req", [
    {"proxy": {"mode": "explicit-proxy", "url": "https://clean.example.com"}},
    {"proxy": {"mode": "explicit-proxy"}},
    {"proxy": {"url": "https://clean.example.com"}},
    {"proxy": {"tls": {"insecureSkipVerify": False}}},
    {"tls": {"insecureSkipVerify": False}},
], ids=["mode_and_url", "mode_only", "url_only", "nested_tls_declared", "tls_declared"])
def test_b155_substantive_transport_object_is_pass(req):
    """The control side: each of these declares a real, parseable setting, so the stub
    guard above must not swallow them back into UNKNOWN."""
    from clawseccheck.catalog import PASS
    f = check_outbound_proxy(_ctx(_provider_request(req)))
    assert f.status == PASS
    assert f.not_applicable is False


def test_b155_stub_alongside_a_real_transport_is_still_pass():
    """One provider's stub must not veto another provider's genuinely-configured, clean
    transport -- real surface exists and was assessed."""
    from clawseccheck.catalog import PASS
    f = check_outbound_proxy(_ctx({"models": {"providers": {
        "a": {"request": {"proxy": {}}},
        "b": {"request": {"proxy": {"url": "https://ok.example"}}},
    }}}))
    assert f.status == PASS
    assert f.not_applicable is False


# --- C-135 round 3: the substantive-TLS field set must be the COMPLETE schema field
# list, not just the one field B155 judges. Recognizing only `insecureSkipVerify` sent a
# real custom-CA / SNI-override config into the stub bucket and reported "no outbound
# proxy configured" -- fail-safe (never a false PASS) but a false negative on a declared
# transport. Field set grounded on ConfiguredProviderRequestTlsSchema. ---

def test_b155_tls_custom_ca_and_sni_without_insecure_skip_verify_is_pass():
    """The exact repro: a real TLS pin that never mentions insecureSkipVerify."""
    from clawseccheck.catalog import PASS
    f = check_outbound_proxy(_ctx(_provider_request(
        {"tls": {"serverName": "api.example.com", "ca": "-----BEGIN CERTIFICATE-----"}}
    )))
    assert f.status == PASS, (
        "a declared custom-CA/SNI TLS config is a real, assessable transport -- not a stub"
    )
    assert f.not_applicable is False


@pytest.mark.parametrize("field", ["ca", "cert", "key", "passphrase", "serverName"])
def test_b155_each_schema_tls_string_field_alone_is_substantive(field):
    """Every non-judged field of the schema object, one at a time -- so a future edit
    that drops one from the recognized set fails here by name."""
    from clawseccheck.catalog import PASS
    f = check_outbound_proxy(_ctx(_provider_request({"tls": {field: "value"}})))
    assert f.status == PASS, f"request.tls.{field} alone should count as declared TLS"
    assert f.not_applicable is False


def test_b155_schema_tls_field_inside_nested_proxy_tls_is_substantive():
    from clawseccheck.catalog import PASS
    f = check_outbound_proxy(_ctx(_provider_request(
        {"proxy": {"tls": {"serverName": "api.example.com"}}}
    )))
    assert f.status == PASS
    assert f.not_applicable is False


@pytest.mark.parametrize("tls", [
    {"serverName": "   "},
    {"ca": 123},
    {"cert": None},
], ids=["blank_string", "non_string_ca", "null_cert"])
def test_b155_malformed_schema_tls_values_remain_stubs(tls):
    """Widening the field set must not weaken the value test: a recognized key holding a
    blank or wrong-typed value still declares nothing assessable."""
    f = check_outbound_proxy(_ctx(_provider_request({"tls": tls})))
    assert f.status == UNKNOWN
    assert f.not_applicable is False


def test_b155_tls_passphrase_value_is_never_echoed():
    """§8: the secret-shaped field is tested for DECLARATION only. Its value must not
    reach detail or evidence."""
    marker = "".join(["pass", "phrase", "-value-", "marker"])
    f = check_outbound_proxy(_ctx(_provider_request(
        {"tls": {"passphrase": marker, "serverName": "api.example.com"}}
    )))
    assert marker not in f.detail
    assert not any(marker in e for e in f.evidence)


def test_b155_stub_does_not_suppress_a_real_signal():
    """A stub on one provider must not mask a genuine WARN on another."""
    from clawseccheck.catalog import WARN
    f = check_outbound_proxy(_ctx({"models": {"providers": {
        "a": {"request": {"proxy": {}}},
        "b": {"request": {"tls": {"insecureSkipVerify": True}}},
    }}}))
    assert f.status == WARN
    assert f.not_applicable is False


def test_b155_detail_text_is_unchanged_by_the_migration():
    """The advisory nudge still reads exactly as before -- the flag rides the same branch
    and does not silence it (and baseline.fingerprint() hashes this string)."""
    f = check_outbound_proxy(_ctx({}))
    assert f.detail.startswith("No outbound proxy configured")
    assert "informational, not required" in f.detail


# ---------------------------------------------------------------------------
# C5 -- the three-way discrimination. Exactly ONE of its UNKNOWN branches is
# not-applicable; the other two are unassessed risk and must keep the ordinary posture.
# ---------------------------------------------------------------------------

def _host_ctx(include_host: bool) -> Context:
    c = Context(home=Path("/nonexistent"), config_found=True, config_parse_error=False)
    c.include_host = include_host
    return c


def test_c5_non_posix_is_not_applicable(monkeypatch):
    """The POSIX mode bits C5 models do not exist on a non-POSIX platform -- no amount
    of extra evidence could make the check apply."""
    monkeypatch.setattr(_shared, "_is_posix", lambda: False)
    f = check_path_safety(_host_ctx(True))
    assert f.status == UNKNOWN
    assert f.not_applicable is True


def test_c5_no_host_scanning_is_not_not_applicable():
    """``--no-host``: the surface almost certainly exists; the operator told us not to
    look. That is a coverage gap the user can close by re-running, so it must stay an
    ordinary UNKNOWN."""
    f = check_path_safety(_host_ctx(False))
    assert f.status == UNKNOWN
    assert f.not_applicable is False


def test_c5_openclaw_not_discoverable_is_not_not_applicable(monkeypatch):
    """Discovery failure is not absence: the install tree may exist somewhere this run
    could not find, which is why the fix text invites ``--attest``."""
    monkeypatch.setattr(_shared, "_is_posix", lambda: True)
    monkeypatch.setattr("clawseccheck.checks._capability.shutil.which", lambda _n: None)
    f = check_path_safety(_host_ctx(True))
    assert f.status == UNKNOWN
    assert f.not_applicable is False


# ---------------------------------------------------------------------------
# The hard rule, pinned once for the whole migration: not-applicable never degrades
# into PASS anywhere. report.py's _worst_of_statuses rolls a chain up from plain status
# STRINGS, so it cannot see the flag -- which is exactly why it is safe, and exactly why
# a future "treat not_applicable as all-clear" optimisation must break this test first.
# ---------------------------------------------------------------------------

def test_not_applicable_finding_never_rolls_up_as_pass():
    from clawseccheck.catalog import PASS
    from clawseccheck.report import _worst_of_statuses, _worst_status

    ctx = Context(home=Path("/nonexistent"), config_found=True, config_parse_error=False)
    na = check_control_plane_mutation(ctx)
    assert na.not_applicable is True, "precondition: need a real not_applicable finding"

    assert _worst_of_statuses([na.status]) == UNKNOWN
    assert _worst_of_statuses([na.status, PASS]) == UNKNOWN
    assert _worst_status([na]) == UNKNOWN, (
        "a not_applicable finding must still roll up as UNKNOWN, never PASS -- "
        "'doesn't apply' is not 'all clear'"
    )
