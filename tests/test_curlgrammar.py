"""CLAWSECCHECK-B-986: soundness guards on clawseccheck/curlgrammar.py.

Two mechanical guards, not just spot checks:
  (a) completeness — OPTION_ROLE is TOTAL over OPTION_ARITY's keys, and every
      role used is a member of the closed ROLES set. No option can silently
      fall through with no role at all.
  (b) category cross-check — every VALUE-taking option in curl's own
      proxy/dns/connection --help categories that this module does NOT mark
      HOP must be an explicitly justified member of
      `_PROXY_DNS_CONN_SAFE_JUSTIFIED` (the comment above it in
      curlgrammar.py is the human-readable justification; this test is what
      makes skipping that step impossible for a future edit).

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from clawseccheck import curlgrammar as g


def test_option_role_is_total_over_option_arity():
    missing = sorted(set(g.OPTION_ARITY) - set(g.OPTION_ROLE))
    assert not missing, f"options with an arity but no role: {missing}"


def test_option_arity_is_total_over_option_role():
    # The reverse direction too -- a role entry for an option with no arity
    # would be dead/unreachable data, and could indicate a typo'd key.
    missing = sorted(set(g.OPTION_ROLE) - set(g.OPTION_ARITY))
    assert not missing, f"options with a role but no arity: {missing}"


def test_every_role_value_is_in_the_closed_set():
    bad = sorted({r for r in g.OPTION_ROLE.values() if r not in g.ROLES})
    assert not bad, f"role(s) outside the closed ROLES set: {bad}"


def test_every_arity_value_is_bool_or_value():
    bad = sorted({a for a in g.OPTION_ARITY.values() if a not in ("bool", "value")})
    assert not bad, f"arity value(s) outside {{bool, value}}: {bad}"


def test_no_option_name_contains_equals():
    # curlargv.py never splits on '=' (curl itself does not support
    # --option=value glued long-option syntax -- see curlgrammar.py's module
    # docstring). If a future regeneration ever produced a key containing
    # '=', that assumption would silently be wrong.
    bad = [n for n in g.OPTION_ARITY if "=" in n]
    assert not bad, f"option name(s) containing '=': {bad}"


def test_category_cross_check_proxy_dns_connection():
    categories = g._CATEGORY_PROXY | g._CATEGORY_DNS | g._CATEGORY_CONNECTION
    value_taking = {n for n in categories if g.OPTION_ARITY[n] == "value"}
    not_hop = {n for n in value_taking if g.OPTION_ROLE[n] != "HOP"}
    assert not_hop == g._PROXY_DNS_CONN_SAFE_JUSTIFIED, (
        "a value-taking proxy/dns/connection-category option changed HOP "
        "status without updating _PROXY_DNS_CONN_SAFE_JUSTIFIED and its "
        f"justification comment. In categories, not HOP, unjustified: "
        f"{sorted(not_hop - g._PROXY_DNS_CONN_SAFE_JUSTIFIED)}; justified "
        f"but no longer in categories/not-HOP: "
        f"{sorted(g._PROXY_DNS_CONN_SAFE_JUSTIFIED - not_hop)}"
    )


def test_short_to_long_targets_are_real_options():
    bad = sorted(v for v in g.SHORT_TO_LONG.values() if v not in g.OPTION_ARITY)
    assert not bad, f"SHORT_TO_LONG points at unknown long option(s): {bad}"


def test_decision_1_proxy_hop_flags_are_all_hop():
    # Dave's decision 1 (CLAWSECCHECK-B-986): exactly these seven flags
    # unconditionally refuse the B-415 exemption.
    for long_name in (
        "--proxy",
        "--preproxy",
        "--socks4",
        "--socks4a",
        "--socks5",
        "--socks5-hostname",
    ):
        assert g.OPTION_ROLE[long_name] == "HOP", long_name
    assert g.SHORT_TO_LONG["x"] == "--proxy"


def test_auth_header_role_is_exactly_dash_h():
    assert {n for n, r in g.OPTION_ROLE.items() if r == "AUTH_HEADER"} == {"--header"}
    assert g.SHORT_TO_LONG["H"] == "--header"


def test_config_role_is_exactly_dash_capital_k():
    assert {n for n, r in g.OPTION_ROLE.items() if r == "CONFIG"} == {"--config"}
    assert g.SHORT_TO_LONG["K"] == "--config"


def test_dest_role_is_exactly_url():
    assert {n for n, r in g.OPTION_ROLE.items() if r == "DEST"} == {"--url"}


def test_next_role_is_exactly_next_and_is_bool_arity():
    assert {n for n, r in g.OPTION_ROLE.items() if r == "NEXT"} == {"--next"}
    assert g.OPTION_ARITY["--next"] == "bool"
    assert g.SHORT_TO_LONG[":"] == "--next"


def test_terminal_role_is_help_version_manual():
    assert {n for n, r in g.OPTION_ROLE.items() if r == "TERMINAL"} == {
        "--help",
        "--version",
        "--manual",
    }


def test_tls_material_includes_proxy_star_variants():
    tls = {n for n, r in g.OPTION_ROLE.items() if r == "TLS_MATERIAL"}
    assert "--cacert" in tls and "--cert" in tls and "--key" in tls
    proxy_variants = {n for n in tls if n.startswith("--proxy-")}
    assert proxy_variants, "TLS_MATERIAL must include at least one --proxy-* variant"


def test_mirror_role_matches_spec_literally():
    assert {n for n, r in g.OPTION_ROLE.items() if r == "MIRROR"} == {
        "--verbose",
        "--trace",
        "--trace-ascii",
        "--trace-time",
        "--trace-ids",
        "--trace-config",
        "--libcurl",
        "--stderr",
    }


def test_write_out_and_haproxy_clientip_arity_corrections_are_value():
    # Verified directly against real curl 8.5.0 (both error "requires
    # parameter" with no further argument) -- the raw --help-derived row
    # under-reported these as boolean. See curlgrammar.py's OPTION_ARITY
    # docstring.
    assert g.OPTION_ARITY["--write-out"] == "value"
    assert g.OPTION_ARITY["--haproxy-clientip"] == "value"


def test_option_role_and_arity_accessors():
    assert g.option_role("--proxy") == "HOP"
    assert g.option_arity("--proxy") == "value"
