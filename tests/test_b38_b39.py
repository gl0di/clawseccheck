"""B38 (Browser Control / Cookie & SSRF Exposure) and
B39 (Session Visibility / Cross-user Transcript Leak) tests.

Conservative philosophy: FAIL only on positive evidence; UNKNOWN when the config
cannot tell us; PASS when browser/session is configured but no dangerous flags are set.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_browser_ssrf, check_session_visibility
from clawseccheck.collector import Context


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


# ============================================================
# B38 — Browser Control / Cookie & SSRF Exposure
# ============================================================

# --- UNKNOWN when no browser config ---

def test_b38_no_browser_config_unknown():
    assert check_browser_ssrf(_ctx({})).status == UNKNOWN


def test_b38_browser_not_dict_unknown():
    assert check_browser_ssrf(_ctx({"browser": True})).status == UNKNOWN


# --- FAIL: dangerouslyAllowPrivateNetwork == true ---

def test_b38_private_network_allowed_fails():
    cfg = {"browser": {
        "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": True},
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == FAIL
    assert "dangerouslyAllowPrivateNetwork" in f.detail
    assert len(f.evidence) >= 1


def test_b38_private_network_evidence_contains_metadata_ip():
    cfg = {"browser": {
        "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": True},
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == FAIL
    assert "169.254.169.254" in " ".join(f.evidence)


def test_b38_private_network_false_does_not_fail():
    cfg = {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": ["example.com"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == PASS


# --- FAIL: legacy allowPrivateNetwork alias == true (C-135, 2026-09-16) ---
# resolveBrowserSsrFPolicy (installed 2026.9.4 dist, config-Dc3xLSSD.mjs:117-130) ORs
# this flat legacy key into dangerouslyAllowPrivateNetwork before the browser ever
# uses the policy; OpenClaw's own doctor migration confirms the same key by name.
# A raw config setting ONLY this key was previously invisible to B38.

def test_b38_legacy_allow_private_network_alone_fails():
    cfg = {"browser": {
        "ssrfPolicy": {"allowPrivateNetwork": True},
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == FAIL
    assert "allowPrivateNetwork" in f.detail
    assert len(f.evidence) >= 1


def test_b38_legacy_allow_private_network_overrides_dangerously_false():
    # OpenClaw ORs the two keys -- dangerouslyAllowPrivateNetwork=false does not
    # neutralize a legacy allowPrivateNetwork=true sibling.
    cfg = {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "allowPrivateNetwork": True,
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == FAIL


def test_b38_legacy_allow_private_network_false_does_not_fail():
    cfg = {"browser": {
        "ssrfPolicy": {
            "allowPrivateNetwork": False,
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": ["example.com"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == PASS


def test_b38_legacy_allow_private_network_truthy_nonbool_string_does_not_fail():
    # Same coercion-proof gate as dangerouslyAllowPrivateNetwork -- `is True`, not truthy.
    cfg = {"browser": {
        "ssrfPolicy": {
            "allowPrivateNetwork": "true",
            "hostnameAllowlist": ["example.com"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status != FAIL, f.detail


def test_b38_legacy_allow_private_network_fix_mentions_both_keys():
    cfg = {"browser": {
        "ssrfPolicy": {"allowPrivateNetwork": True},
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == FAIL
    assert "allowPrivateNetwork" in f.fix
    assert "doctor --fix" in f.fix


# --- B-853: blockedHostnames lever is gated on the actual private-network trigger,
# never unconditional, and its wording must not claim it "blocks" the addresses --
# it matches by hostname/IP text only (resolveHostnamePolicyChecks, installed 2026.9.5
# dist ssrf-B1sxrDMt.mjs:189), and shouldSkipPrivateNetworkChecks (same file, 114-115)
# skips the resolved-IP check entirely while the flag is on -- an attacker-chosen
# hostname that RESOLVES to one of the listed addresses is not caught by it. C-135
# (B-722) already found the unconditional-mention defect once; this pins all three
# branches so it cannot regress silently.

def test_b38_blockedhostnames_advice_present_when_flag_on():
    cfg = {"browser": {
        "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": True},
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == FAIL
    assert "blockedHostnames" in f.fix


def test_b38_blockedhostnames_advice_present_for_legacy_alias_alone():
    cfg = {"browser": {
        "ssrfPolicy": {"allowPrivateNetwork": True},
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == FAIL
    assert "blockedHostnames" in f.fix


def test_b38_blockedhostnames_advice_absent_on_nosandbox_only():
    # Neither private-network flag is set -- B38 FAILs on noSandbox alone, and the
    # blockedHostnames lever (which only makes sense when the flag is on) must not
    # appear as noise pointed at a flag this config never enabled.
    cfg = {"browser": {"noSandbox": True}}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == FAIL
    assert "blockedHostnames" not in f.fix


def test_b38_blockedhostnames_advice_qualifies_name_only_not_resolved_ip():
    # The wording must disclose the name-only-match gap, not just tell the operator to
    # add the key -- an attacker-chosen hostname that resolves to a listed IP is not
    # caught by blockedHostnames while the private-network flag stays on.
    cfg = {"browser": {
        "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": True},
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == FAIL
    assert "resolves to" in f.fix
    assert "NOT caught" in f.fix or "not caught" in f.fix.lower()
    # Must not overclaim it blocks the addresses themselves (rather than the literal
    # names/IPs an attacker would have to type verbatim).
    assert "still blocks them" not in f.fix


# --- Grounded non-applicability: nested network.* shape is channel-scoped, not browser
# (isPrivateNetworkOptInEnabled, ssrf-policy-CFLWuj1r.mjs, reads it for CHANNEL config;
# browser.ssrfPolicy's own canonical schema, SsrFPolicyConfigSchema, has no `network`
# member and resolveBrowserSsrFPolicy never reads cfg?.ssrfPolicy?.network). Pins that
# B38 does not treat this shape as a bypass -- guards against a future regression that
# adds it back without re-grounding.

def test_b38_nested_network_shape_is_not_read():
    cfg = {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "network": {"dangerouslyAllowPrivateNetwork": True, "allowPrivateNetwork": True},
            "hostnameAllowlist": ["example.com"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == PASS, f.detail


def test_b38_private_network_truthy_nonbool_string_does_not_fail():
    # CLAWSECCHECK-C-135-B722-followup: the installed 2026.9.4 dist types this field as
    # a plain boolean() (no coercion) inside a strictObject, and the runtime's own bypass
    # gate (isPrivateNetworkAllowedByPolicy, src/infra/net/ssrf.ts) is `=== true` --
    # a truthy non-bool value never actually enables private-network access, so `is True`
    # (not a truthy check) is the correct gate here. Pins the behavior risk.py's
    # _browser_ssrf() was found to diverge from (a truthy bool() read there).
    cfg = {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": "true",
            "hostnameAllowlist": ["example.com"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status != FAIL, f.detail


# --- FAIL: noSandbox == true ---

def test_b38_no_sandbox_fails():
    cfg = {"browser": {"noSandbox": True}}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == FAIL
    assert "noSandbox" in f.detail
    assert len(f.evidence) >= 1


def test_b38_no_sandbox_false_does_not_fail():
    cfg = {"browser": {
        "noSandbox": False,
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": ["example.com"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == PASS


# --- FAIL when both dangerous flags are set ---

def test_b38_both_dangerous_flags_fails():
    cfg = {"browser": {
        "noSandbox": True,
        "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": True},
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == FAIL
    assert len(f.evidence) == 2


# --- WARN: browser configured with no hostnameAllowlist ---

def test_b38_no_allowlist_warns():
    cfg = {"browser": {
        "headless": True,
        "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": False},
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == WARN
    assert "hostnameAllowlist" in f.detail


def test_b38_empty_allowlist_warns():
    cfg = {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": [],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == WARN


def test_b38_no_ssrf_policy_at_all_warns():
    cfg = {"browser": {"headless": True}}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == WARN


# --- PASS: sandboxed, private network blocked, allowlist present ---

def test_b38_fully_hardened_passes():
    cfg = {"browser": {
        "headless": True,
        "noSandbox": False,
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": ["example.com", "api.myservice.io"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == PASS


def test_b38_allowlist_present_no_sandbox_key_passes():
    # noSandbox absent (defaults to sandboxed) — should PASS
    cfg = {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": ["trusted.example.com"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == PASS


# --- QUALITY: wildcard / user-content hosts downgrade PASS to WARN ---

def test_b38_wildcard_allowlist_entry_warns_not_pass():
    cfg = {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": ["*.example.com"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == WARN
    assert "*.example.com" in " ".join(f.evidence)


def test_b38_bare_wildcard_allowlist_entry_warns():
    cfg = {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": ["*"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == WARN


def test_b38_known_user_content_host_warns_not_pass():
    cfg = {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": ["pastebin.com"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == WARN
    assert "pastebin.com" in " ".join(f.evidence)


def test_b38_user_content_host_subdomain_warns():
    cfg = {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": ["raw.githubusercontent.com"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == WARN


def test_b38_clean_tight_allowlist_still_passes():
    # No false positives: a clean, specific allowlist with no wildcards/user-content
    # hosts must still PASS.
    cfg = {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": ["example.com", "api.myservice.io"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == PASS


# --- C-342: AI-vendor user-content hosts (ESET H1 2026 "AI-fix") ---

def test_b38_ai_vendor_user_content_host_warns():
    cfg = {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": ["claude.ai"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == WARN
    assert "claude.ai" in " ".join(f.evidence)


def test_b38_ai_vendor_api_host_stays_clean():
    # A skill calling the provider's actual API host must NOT be caught by the
    # claude.ai/chatgpt.com additions — api.anthropic.com is a different host
    # entirely, not a subdomain of claude.ai.
    cfg = {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": ["api.anthropic.com"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == PASS


def test_b38_ai_vendor_docs_host_stays_clean():
    # Vendor documentation domains are not user-content hosts either.
    cfg = {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": ["docs.anthropic.com"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == PASS


# --- F-158: URL-rewriting image/CDN proxies (TA488/OWAReaper, CVE-2026-42897) ---

def test_b38_weserv_proxy_host_warns():
    cfg = {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": ["images.weserv.nl"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == WARN
    assert "images.weserv.nl" in " ".join(f.evidence)


def test_b38_wsrv_proxy_host_warns():
    cfg = {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": ["wsrv.nl"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == WARN


def test_b38_photon_proxy_host_warns():
    # i3.wp.com is the exact host OWAReaper relayed exfil traffic through.
    cfg = {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": ["i3.wp.com"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == WARN
    assert "i3.wp.com" in " ".join(f.evidence)


def test_b38_slack_imgs_proxy_host_warns():
    cfg = {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": ["slack-imgs.com"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == WARN


def test_b38_wordpress_blog_host_stays_clean():
    # Deliberately did NOT add the bare "wp.com" / "wordpress.com" platform domains —
    # only the specific i0-i3.wp.com Photon CDN hosts. An ordinary WordPress.com blog
    # subdomain must not be caught by suffix matching.
    cfg = {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": ["myblog.wordpress.com"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == PASS


def test_b38_bare_wp_com_stays_clean():
    # "wp.com" itself (no i0-i3 prefix) is not a valid Photon proxy host form.
    cfg = {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": ["wp.com"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == PASS


# --- Evidence populated on FAIL ---

def test_b38_fail_evidence_populated():
    cfg = {"browser": {"noSandbox": True}}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == FAIL
    assert f.evidence


# ============================================================
# B39 — Session Visibility / Cross-user Transcript Leak
# ============================================================

# --- UNKNOWN when no session config ---

def test_b39_no_session_config_unknown():
    assert check_session_visibility(_ctx({})).status == UNKNOWN


# B-796: a config that WAS found (non-empty, just unrelated to sessions) now correctly
# WARNs rather than UNKNOWN -- OpenClaw defaults tools.sessions.visibility to "all"
# when the key is absent, so "this config never mentions sessions" is the single most
# exposed state B39 can observe, not a neutral one. Only a config that was never found
# at all stays UNKNOWN (test_b39_no_session_config_unknown, above, via config_found).
def test_b39_config_present_without_session_keys_warns_on_visibility_default():
    f = check_session_visibility(_ctx({"gateway": {}}))
    assert f.status == WARN
    assert "defaults this to" in f.detail


# --- FAIL: dmScope == "main" with non-owner channels ---

def test_b39_main_scope_with_allowlist_channel_fails():
    cfg = {
        "session": {"dmScope": "main"},
        "channels": {"telegram": {"dmPolicy": "allowlist", "groupPolicy": "allowlist"}},
    }
    f = check_session_visibility(_ctx(cfg))
    assert f.status == FAIL
    assert "dmScope" in f.detail
    assert len(f.evidence) >= 1


def test_b39_main_scope_with_open_channel_fails():
    cfg = {
        "session": {"dmScope": "main"},
        "channels": {"discord": {"dmPolicy": "open"}},
    }
    f = check_session_visibility(_ctx(cfg))
    assert f.status == FAIL
    assert "main" in f.detail


def test_b39_main_scope_no_channels_does_not_fail():
    # "main" with no channels that allow non-owners -> no cross-user contamination
    cfg = {"session": {"dmScope": "main"}}
    f = check_session_visibility(_ctx(cfg))
    # Should NOT be FAIL (no non-owner channels)
    assert f.status != FAIL


# --- B-058 regression: account-nested + paired ingress (was a false PASS) ---
# check_session_visibility previously read only top-level dmPolicy/groupPolicy, so a DM
# allowlist nested under channels.<p>.accounts.<id> slipped through as PASS on a real
# cross-user-leak config. It now routes through _external_input_channels (accounts-aware,
# open/allowlist/paired), so neither the account nesting nor the paired policy can hide.
def test_b39_main_scope_account_nested_allowlist_fails():
    cfg = {
        "session": {"dmScope": "main"},
        "channels": {"telegram": {"accounts": {"main": {"dmPolicy": "allowlist"}}}},
    }
    f = check_session_visibility(_ctx(cfg))
    assert f.status == FAIL, f.detail
    assert f.evidence


def test_b39_main_scope_account_nested_paired_fails():
    cfg = {
        "session": {"dmScope": "main"},
        "channels": {"telegram": {"accounts": {"m": {"dmPolicy": "pairing"}}}},
    }
    assert check_session_visibility(_ctx(cfg)).status == FAIL


def test_b39_main_scope_paired_channel_fails():
    # paired = external (non-owner) ingress, now counted alongside open/allowlist
    cfg = {"session": {"dmScope": "main"}, "channels": {"tg": {"dmPolicy": "pairing"}}}
    assert check_session_visibility(_ctx(cfg)).status == FAIL


# clean control: an owner-only channel is NOT external ingress -> no cross-user risk.
# tools.sessions.visibility is set explicitly to "self" here so this test isolates the
# dmScope+channel dimension from the (correctly, separately-WARNing since B-796)
# visibility-default dimension.
def test_b39_main_scope_owner_only_channel_passes():
    cfg = {
        "session": {"dmScope": "main"},
        "channels": {"tg": {"dmPolicy": "owner"}},
        "tools": {"sessions": {"visibility": "self"}},
    }
    assert check_session_visibility(_ctx(cfg)).status == PASS


# --- FAIL takes priority over WARN ---

def test_b39_fail_takes_priority_over_warn():
    cfg = {
        "session": {"dmScope": "main"},
        "channels": {"telegram": {"dmPolicy": "allowlist"}},
        "tools": {"sessions": {"visibility": "all"}},
    }
    f = check_session_visibility(_ctx(cfg))
    assert f.status == FAIL


# --- WARN: tools.sessions.visibility in ("agent", "all") ---

def test_b39_visibility_agent_warns():
    cfg = {"tools": {"sessions": {"visibility": "agent"}}}
    f = check_session_visibility(_ctx(cfg))
    assert f.status == WARN
    assert "visibility" in f.detail
    assert len(f.evidence) >= 1


def test_b39_visibility_all_warns():
    cfg = {"tools": {"sessions": {"visibility": "all"}}}
    f = check_session_visibility(_ctx(cfg))
    assert f.status == WARN
    assert "all" in f.detail


def test_b39_visibility_self_does_not_warn():
    cfg = {"tools": {"sessions": {"visibility": "self"}}}
    f = check_session_visibility(_ctx(cfg))
    assert f.status != WARN
    assert f.status != FAIL


def test_b39_visibility_tree_does_not_warn():
    cfg = {"tools": {"sessions": {"visibility": "tree"}}}
    f = check_session_visibility(_ctx(cfg))
    assert f.status != WARN
    assert f.status != FAIL


# --- PASS: safe scope + safe visibility ---

def test_b39_per_peer_scope_passes():
    cfg = {
        "session": {"dmScope": "per-peer"},
        "tools": {"sessions": {"visibility": "self"}},
    }
    f = check_session_visibility(_ctx(cfg))
    assert f.status == PASS


def test_b39_per_channel_peer_scope_passes():
    cfg = {
        "session": {"dmScope": "per-channel-peer"},
        "tools": {"sessions": {"visibility": "tree"}},
    }
    f = check_session_visibility(_ctx(cfg))
    assert f.status == PASS


def test_b39_per_account_channel_peer_scope_passes():
    # tools.sessions.visibility set explicitly so this isolates the dmScope dimension
    # from the visibility-default dimension (see B-796 note above).
    cfg = {
        "session": {"dmScope": "per-account-channel-peer"},
        "tools": {"sessions": {"visibility": "self"}},
    }
    f = check_session_visibility(_ctx(cfg))
    assert f.status == PASS


# B-796: this used to assert PASS -- "dmScope set, visibility never mentioned" was
# exactly the lying-PASS shape the fix closes. tools.sessions.visibility absent
# resolves to OpenClaw's own "all" default (resolveSessionToolsVisibility,
# session-visibility-*.mjs), which is a real cross-session exposure this check must
# not stay silent about just because the operator only touched the OTHER field.
def test_b39_session_cfg_only_no_vis_warns_on_visibility_default():
    cfg = {"session": {"dmScope": "per-peer"}}
    f = check_session_visibility(_ctx(cfg))
    assert f.status == WARN
    assert "defaults this to" in f.detail


# ============================================================
# B-796/B-797 — absent-case defaults (2026.9.3 dist, verified by direct read of the
# canonical runtime resolvers, not inferred from a schema description):
#   resolveSessionToolsVisibility (session-visibility-*.mjs) defaults ANY missing or
#   unrecognized tools.sessions.visibility to "all".
#   base-session-key-*.mjs's session-key builder resolves an absent session.dmScope to
#   "main" (cfg.session?.dmScope ?? "main").
# Both fields are declared as strict zod enums, so a present-but-invalid value is a
# config OpenClaw's own loader would reject outright -- UNKNOWN, never guessed into
# the resolved-default path meant for genuine absence.
# ============================================================

def test_b39_absent_dmscope_fails_like_explicit_main():
    """B-797: no session.dmScope at all, but an open channel -- must FAIL exactly as
    an explicit dmScope="main" would, not silently pass because the key was never
    set. tools.sessions.visibility pinned safe to isolate this from B-796's own WARN."""
    cfg = {
        "channels": {"discord": {"dmPolicy": "open"}},
        "tools": {"sessions": {"visibility": "self"}},
    }
    f = check_session_visibility(_ctx(cfg))
    assert f.status == FAIL
    assert "defaults this to" in f.detail


def test_b39_absent_visibility_alone_warns():
    """B-796: a config that touches NEITHER field at all -- both resolved defaults are
    unsafe, but the FAIL branch needs a channel to fire on; with none configured, the
    WARN (visibility only) is what should surface. Uses a non-empty config so
    Context's config_found=False default doesn't route this into the "no openclaw.json
    found at all" branch instead (see test_b39_no_session_config_unknown for that
    case)."""
    f = check_session_visibility(_ctx({"agents": {"defaults": {}}}))
    assert f.status == WARN
    assert "defaults this to" in f.detail


def test_b39_both_absent_fails_when_channel_open():
    """FAIL takes priority over WARN even when BOTH fields are resolved defaults, not
    explicit values -- the same priority the pre-existing
    test_b39_fail_takes_priority_over_warn pins for explicit values."""
    cfg = {"channels": {"telegram": {"dmPolicy": "allowlist"}}}
    f = check_session_visibility(_ctx(cfg))
    assert f.status == FAIL


def test_b39_invalid_dmscope_value_is_unknown():
    """session.dmScope is a strict zod enum -- a config carrying a value outside its
    four literals is one OpenClaw's own loader rejects at parse time, so this check
    must say UNKNOWN, never guess the runtime default applies to a config that
    wouldn't actually load."""
    cfg = {"session": {"dmScope": "everyone"}}
    f = check_session_visibility(_ctx(cfg))
    assert f.status == UNKNOWN


def test_b39_invalid_visibility_value_is_unknown():
    cfg = {"tools": {"sessions": {"visibility": "everyone"}}}
    f = check_session_visibility(_ctx(cfg))
    assert f.status == UNKNOWN


def test_b39_non_dict_session_is_unknown():
    f = check_session_visibility(_ctx({"session": "not-a-dict"}))
    assert f.status == UNKNOWN


def test_b39_non_dict_tools_is_unknown():
    f = check_session_visibility(_ctx({"tools": "not-a-dict"}))
    assert f.status == UNKNOWN


def test_b39_non_dict_tools_sessions_is_unknown():
    f = check_session_visibility(_ctx({"tools": {"sessions": "not-a-dict"}}))
    assert f.status == UNKNOWN


def test_b39_genuinely_no_config_stays_unknown_even_with_exposure_shaped_input():
    """Golden Rule #4: a home with no openclaw.json at all must never be scored as if
    it were a real, exposed install -- config_found=False takes priority over any
    resolved-default reasoning, matching B175's own precedent for the same shape."""
    c = Context(home=Path("/nonexistent"), config_found=False, config_parse_error=False)
    c.config = {}
    f = check_session_visibility(c)
    assert f.status == UNKNOWN


# --- Evidence populated on FAIL ---

def test_b39_fail_evidence_populated():
    cfg = {
        "session": {"dmScope": "main"},
        "channels": {"slack": {"dmPolicy": "allowlist"}},
    }
    f = check_session_visibility(_ctx(cfg))
    assert f.status == FAIL
    assert f.evidence


# ============================================================
# Reliability: fixture-based end-to-end
# ============================================================

from clawseccheck import audit  # noqa: E402

RELIABILITY = Path(__file__).resolve().parent.parent / "fixtures" / "reliability"


def test_b38_bad_fixture_fails():
    _, findings, _ = audit(RELIABILITY / "bad_b38_private_network")
    by_id = {f.id: f for f in findings}
    assert by_id["B38"].status == FAIL


def test_b38_bad_fixture_legacy_alias_fails():
    # C-135, 2026-09-16: legacy browser.ssrfPolicy.allowPrivateNetwork alone, no
    # dangerouslyAllowPrivateNetwork -- end-to-end through the real audit() entry point.
    _, findings, _ = audit(RELIABILITY / "bad_b38_private_network_legacy_alias")
    by_id = {f.id: f for f in findings}
    assert by_id["B38"].status == FAIL


def test_b39_bad_fixture_fails():
    _, findings, _ = audit(RELIABILITY / "bad_b39_main_scope")
    by_id = {f.id: f for f in findings}
    assert by_id["B39"].status == FAIL
