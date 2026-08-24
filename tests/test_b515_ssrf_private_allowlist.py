"""B-515 follow-up — B38 (check_browser_ssrf) must judge allowlist entries that are
THEMSELVES loopback/private/link-local/CGNAT/IPv6-ULA/cloud-metadata addresses, not
only wildcard/user-content/proxy shapes.

Reproduced defect: an operator with dangerouslyAllowPrivateNetwork=false and
allowedHostnames=["169.254.169.254"] (the AWS/Azure/GCP instance-metadata IP) got a
PASS asserting "private-network access blocked" in the same breath as an allowlist
entry naming exactly that host. Fixed to WARN — matching this module's own severity
for the sibling wildcard/user-content/proxy weak-entry class, since a fixed internal
host MAY be a deliberate choice on an internal deployment and this is a static,
network-free check.

MECHANISM (verified against the real installed OpenClaw engine offline, a stub
resolver, no live DNS — a first C-135 round claimed "an allowlisted host bypasses
dangerouslyAllowPrivateNetwork=false for itself" for EVERY private shape; that is
FALSE for link-local/cloud-metadata, which a second review round caught):

    allowedHostnames  169.254.169.254  -> BLOCKED  (link-local / cloud-metadata)
    allowedHostnames  100.100.100.200  -> BLOCKED  (Alibaba cloud-metadata carve-out)
    hostnameAllowlist 169.254.169.254  -> BLOCKED  (legacy key grants no exemption)
    allowedHostnames  10.0.0.5         -> REACHABLE
    allowedHostnames  127.0.0.1        -> REACHABLE
    allowedHostnames  fd00::1          -> REACHABLE
    allowedHostnames  100.64.0.7       -> REACHABLE

So `allowedHostnames` genuinely exempts loopback/RFC1918/CGNAT/IPv6-ULA/0.0.0.0/::
("BYPASS") from the private-network gate, but link-local and the well-known
cloud-metadata literals stay blocked by a second, unconditional gate regardless of the
allowlist ("LATENT" — still a WARN, on config-hygiene/intent grounds: it becomes live
the moment dangerouslyAllowPrivateNetwork is separately set to true). The legacy
`hostnameAllowlist` key never grants the real exemption at all, so every
otherwise-BYPASS-shaped entry placed there is judged LATENT too — this module's tests
below therefore assert WARN + evidence membership only, never a "this is reachable"
claim tied to the legacy key.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, WARN
from clawseccheck.checks import check_browser_ssrf
from clawseccheck.collector import Context


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def _cfg(hosts):
    return {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "allowedHostnames": hosts,
        },
    }}


# --- the reproduced defect: cloud-metadata IP must not PASS ---

def test_metadata_ip_warns_not_pass():
    f = check_browser_ssrf(_ctx(_cfg(["169.254.169.254"])))
    assert f.status == WARN
    assert "169.254.169.254" in " ".join(f.evidence)


def test_metadata_ip_detail_does_not_claim_private_network_blocked():
    f = check_browser_ssrf(_ctx(_cfg(["169.254.169.254"])))
    assert f.status == WARN
    # The false claim this task exists to remove: WARN detail must not assert the
    # private network is blocked while the allowlist grants a metadata-IP exception.
    assert "private-network access blocked" not in f.detail


def test_metadata_ip_detail_does_not_claim_it_bypasses_the_guard():
    # Second-round fix: the metadata IP is NOT actually reachable today (a separate,
    # unconditional gate blocks it regardless of the allowlist) -- the sentence naming
    # it must use LATENT framing ("still blocks today"), not BYPASS framing
    # ("reach TODAY").
    f = check_browser_ssrf(_ctx(_cfg(["169.254.169.254"])))
    sentence = next(s for s in f.detail.split(". ") if "169.254.169.254" in s)
    assert "still blocks today" in sentence
    assert "reach TODAY" not in sentence


# --- BYPASS shapes: genuinely reachable today per the real-engine probe ---

def test_loopback_ip_warns_as_bypass():
    f = check_browser_ssrf(_ctx(_cfg(["127.0.0.1"])))
    assert f.status == WARN
    assert "127.0.0.1" in " ".join(f.evidence)
    sentence = next(s for s in f.detail.split(". ") if "127.0.0.1" in s)
    assert "reach TODAY" in sentence


def test_localhost_literal_warns():
    f = check_browser_ssrf(_ctx(_cfg(["localhost"])))
    assert f.status == WARN
    assert "localhost" in " ".join(f.evidence)


def test_rfc1918_10_8_warns_as_bypass():
    f = check_browser_ssrf(_ctx(_cfg(["10.0.0.5"])))
    assert f.status == WARN
    sentence = next(s for s in f.detail.split(". ") if "10.0.0.5" in s)
    assert "reach TODAY" in sentence


def test_rfc1918_192_168_warns():
    f = check_browser_ssrf(_ctx(_cfg(["192.168.1.1"])))
    assert f.status == WARN


def test_cgnat_ordinary_address_warns_as_bypass():
    f = check_browser_ssrf(_ctx(_cfg(["100.64.0.7"])))
    assert f.status == WARN
    sentence = next(s for s in f.detail.split(". ") if "100.64.0.7" in s)
    assert "reach TODAY" in sentence


def test_ipv6_ula_warns_as_bypass():
    f = check_browser_ssrf(_ctx(_cfg(["fd00::1"])))
    assert f.status == WARN
    sentence = next(s for s in f.detail.split(". ") if "fd00::1" in s)
    assert "reach TODAY" in sentence


def test_ipv6_loopback_warns():
    f = check_browser_ssrf(_ctx(_cfg(["::1"])))
    assert f.status == WARN


def test_zero_route_ipv4_warns_as_bypass():
    # "0.0.0.0 day" (2024): browsers on several OSes route 0.0.0.0 to localhost,
    # bypassing private-network protections -- REACHABLE per the real-engine probe.
    f = check_browser_ssrf(_ctx(_cfg(["0.0.0.0"])))
    assert f.status == WARN
    assert "0.0.0.0" in " ".join(f.evidence)


def test_zero_route_ipv6_warns_as_bypass():
    f = check_browser_ssrf(_ctx(_cfg(["::"])))
    assert f.status == WARN
    assert "::" in f.evidence


# --- previously-missed false negatives (bracketed / IPv4-mapped forms) ---

def test_bracketed_ipv6_ula_warns():
    f = check_browser_ssrf(_ctx(_cfg(["[fd00::1]"])))
    assert f.status == WARN
    assert "[fd00::1]" in f.evidence


def test_ipv4_mapped_private_address_warns():
    f = check_browser_ssrf(_ctx(_cfg(["::ffff:10.0.0.5"])))
    assert f.status == WARN
    assert "::ffff:10.0.0.5" in f.evidence


# --- LATENT shapes: still blocked today, WARN on intent grounds only ---

def test_alibaba_metadata_carveout_warns():
    # Inside the ordinary 100.64.0.0/10 CGNAT range yet BLOCKED by the real engine
    # (unlike an ordinary CGNAT address, see test_cgnat_ordinary_address_warns_as_bypass) --
    # verified with an explicit carve-out rather than range math alone.
    f = check_browser_ssrf(_ctx(_cfg(["100.100.100.200"])))
    assert f.status == WARN
    sentence = next(s for s in f.detail.split(". ") if "100.100.100.200" in s)
    assert "still blocks today" in sentence


def test_ipv6_link_local_warns():
    f = check_browser_ssrf(_ctx(_cfg(["fe80::1"])))
    assert f.status == WARN


def test_gcp_metadata_hostname_warns():
    f = check_browser_ssrf(_ctx(_cfg(["metadata.google.internal"])))
    assert f.status == WARN
    assert "metadata.google.internal" in " ".join(f.evidence)


def test_gcp_metadata_hostname_case_and_trailing_dot_warns():
    f = check_browser_ssrf(_ctx(_cfg(["Metadata.Google.Internal."])))
    assert f.status == WARN


# --- legacy hostnameAllowlist key: grants no exemption, ever ---

def test_private_entry_via_legacy_hostname_allowlist_warns():
    # hostnameAllowlist never feeds skipPrivateNetworkChecks (verified against the
    # real engine) -- this asserts WARN + evidence only, never "reachable".
    cfg = {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": ["169.254.169.254"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == WARN
    assert "169.254.169.254" in " ".join(f.evidence)


def test_bypass_shaped_entry_via_legacy_key_is_not_claimed_reachable():
    # 10.0.0.5 would be a genuine BYPASS via allowedHostnames (see
    # test_rfc1918_10_8_warns_as_bypass) but grants nothing via the legacy key --
    # its sentence here must use the LATENT/"still blocks today" framing, not "reach
    # TODAY".
    cfg = {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": False,
            "hostnameAllowlist": ["10.0.0.5"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == WARN
    sentence = next(s for s in f.detail.split(". ") if "10.0.0.5" in s)
    assert "reach TODAY" not in sentence


# --- negative controls: shapes deliberately NOT judged / must stay clean ---

def test_ordinary_public_allowlist_stays_clean():
    f = check_browser_ssrf(_ctx(_cfg(["api.example.com", "trusted.example.com"])))
    assert f.status == PASS


def test_test_net_documentation_range_not_judged_stays_clean():
    # 192.0.2.0/24 (TEST-NET-1) is public/documentation space, not private -- this
    # project deliberately does not treat every non-RFC1918 IP literal as suspicious.
    f = check_browser_ssrf(_ctx(_cfg(["192.0.2.1"])))
    assert f.status == PASS


def test_decimal_encoded_ipv4_not_judged_stays_clean():
    # 2130706433 == 127.0.0.1 in decimal form -- deliberately not parsed by THIS
    # check: Python's ipaddress module rejects it as non-canonical, and OpenClaw's own
    # engine independently recognizes and blocks this exact shape
    # (looksLikeUnsupportedIpv4Literal, ssrf-BayeDjCv.js:145-150) -- hand-rolling a
    # second parser here would not close a real gap, only duplicate an existing one.
    f = check_browser_ssrf(_ctx(_cfg(["2130706433"])))
    assert f.status == PASS


def test_bare_cidr_entry_not_judged_stays_clean():
    # A bare CIDR is not a hostname shape the runtime's allowlist matcher documents;
    # ipaddress.ip_address() raises on it, so this is left unjudged rather than guessed.
    f = check_browser_ssrf(_ctx(_cfg(["10.0.0.0/8"])))
    assert f.status == PASS


def test_wildcard_over_private_looking_string_not_double_judged():
    # A wildcard entry is already reported by the weak-entry leg; it is never also fed
    # through the IP/loopback parse (it isn't a parseable literal anyway).
    f = check_browser_ssrf(_ctx(_cfg(["*.internal"])))
    assert f.status == WARN
    assert f.evidence == ["*.internal"]


# --- mixed allowlist: all legs fire in ONE Finding, no double-report ---

def test_weak_and_latent_entries_both_named_once_each():
    f = check_browser_ssrf(_ctx(_cfg(["169.254.169.254", "*.evil.example"])))
    assert f.status == WARN
    assert f.evidence.count("169.254.169.254") == 1
    assert f.evidence.count("*.evil.example") == 1
    assert len(f.evidence) == 2


def test_weak_entry_alone_still_fires_unchanged():
    # Regression pin: the pre-existing weak-entry leg must still fire on its own.
    f = check_browser_ssrf(_ctx(_cfg(["*.evil.example"])))
    assert f.status == WARN
    assert f.evidence == ["*.evil.example"]


def test_bypass_and_latent_and_weak_all_named_once_each():
    f = check_browser_ssrf(
        _ctx(_cfg(["10.0.0.5", "169.254.169.254", "*.evil.example"]))
    )
    assert f.status == WARN
    assert sorted(f.evidence) == sorted(["10.0.0.5", "169.254.169.254", "*.evil.example"])


# --- FAIL branch (dangerouslyAllowPrivateNetwork=true) is untouched by this change ---

def test_dangerously_allow_private_network_still_fails_regardless_of_allowlist():
    cfg = {"browser": {
        "ssrfPolicy": {
            "dangerouslyAllowPrivateNetwork": True,
            "allowedHostnames": ["api.example.com"],
        },
    }}
    f = check_browser_ssrf(_ctx(cfg))
    assert f.status == FAIL
