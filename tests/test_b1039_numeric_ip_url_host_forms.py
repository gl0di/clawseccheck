"""B-1039 -- a URL host spelled as a non-dotted-quad number (`0x8.8.8.8`, `0x08080808`,
`2130706433`, `8.8`, `1.2.3`, `010.8.8.8`) used to miss the IPv4-shape regexes in front of
`_ipv4_class`, so B103's raw-IP FAIL and B13's IP-URL WARN never fired for it (the classifier
already calls every such form "ambiguous", i.e. off-host).

Only the URL HOST may match: version strings, ports, dates and DNS labels that merely start with
digits must stay quiet, and a plain LAN dotted quad stays local.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks import _install_entry_findings, _ipv4_class, vet_skill
from clawseccheck.checks._content import (
    _INSTALL_IPV4_HOST_RE,
    _install_host_is_local,
    _install_host_is_public_ip,
    _install_url_target,
)
from clawseccheck.checks._vet import _IOC_IPURL_RE, _IPV4_LITERAL_RE, _url_host_is_local

# Spellings that stay "ambiguous" (hex / leading-zero / out-of-range): off-host, never local.
AMBIGUOUS_FORMS = ("0x8.8.8.8", "0x08080808", "010.8.8.8", "0X7F.0.0.1", "0x7f000001", "0x7f.1",
                   "127.0x1", "4294967296", "999.1.1.1", "1.2.3.300", "0x1ffffffff")
# Pure-decimal short forms decode like inet_aton (curl / getaddrinfo / WHATWG): one meaning.
DECODED_OFF_HOST = {"8.8": "public", "1.2.3": "public", "134744072": "public",
                    "4294967295": "special"}
DECODED_LOOPBACK = ("127.1", "127", "2130706433", "127.0.1", "0")
# Every spelling that must raise B103 / B13.
FORMS = AMBIGUOUS_FORMS + tuple(DECODED_OFF_HOST)


def _vet(md: str) -> tuple:
    with tempfile.TemporaryDirectory() as td:
        d = Path(td) / "s"
        d.mkdir()
        (d / "SKILL.md").write_text("---\nname: s\ndescription: helper\n---\n" + md,
                                    encoding="utf-8")
        f = vet_skill(str(d))
        return f.status, f.detail + "\n" + "\n".join(f.evidence)


@pytest.mark.parametrize("host", FORMS)
def test_every_form_matches_both_host_regexes_and_is_off_host(host):
    assert _ipv4_class(host) == DECODED_OFF_HOST.get(host, "ambiguous")
    assert _INSTALL_IPV4_HOST_RE.match(host)
    assert _IPV4_LITERAL_RE.match(host)


@pytest.mark.parametrize("host", DECODED_LOOPBACK)
def test_decoded_loopback_short_forms_are_local(host):
    assert _ipv4_class(host) == "local"
    assert _INSTALL_IPV4_HOST_RE.match(host)
    assert _url_host_is_local(f"http://{host}/x")
    assert not _install_host_is_public_ip(host)
    assert _install_host_is_local(host)
    assert not _install_entry_findings(
        "s", [{"id": "a", "kind": "download", "url": f"https://{host}/p.tar.gz"}])
    assert _IOC_IPURL_RE.search(f"http://{host}:9222/x").group(1) == host
    status, text = _vet(f"# helper\nCDP at http://{host}:9222/json and http://{host}/\n")
    assert status == PASS, text


@pytest.mark.parametrize("host,cls", (("127.1", "local"), ("127", "local"),
                                      ("2130706433", "local"), ("134744072", "public"),
                                      ("8.8", "public"), ("1.2.3", "public"),
                                      ("0x7f.1", "ambiguous"), ("127.0x1", "ambiguous"),
                                      ("4294967296", "ambiguous"), ("1.16777216", "ambiguous"),
                                      ("1.2.65536", "ambiguous"), ("256.1", "ambiguous"),
                                      ("0127.1", "ambiguous")))
def test_short_form_decoding_matches_inet_aton(host, cls):
    assert _ipv4_class(host) == cls


@pytest.mark.parametrize("host", ("4294967296", "0x7f.1", "127.0x1", "0127.1"))
def test_what_does_not_decode_can_never_clear_a_finding(host):
    assert not _url_host_is_local(f"http://{host}/x")
    assert _install_host_is_public_ip(host)
    assert not _install_host_is_local(host)


@pytest.mark.parametrize("host", FORMS)
def test_b103_install_fetch_fails_on_every_form(host):
    entry = {"id": "a", "kind": "download", "url": f"https://{host}/p.tar.gz"}
    fails = _install_entry_findings("s", [entry])
    assert fails and "raw public-IP host" in fails[0], (host, fails)
    assert _install_host_is_public_ip(host)
    assert not _install_host_is_local(host)


@pytest.mark.parametrize("host", FORMS)
def test_b103_goes_through_urlparse_unchanged(host):
    """The host reaches the classifier after `urlparse` (lowercased, port stripped)."""
    scheme, parsed = _install_url_target(f"https://{host}:8443/x")
    assert scheme == "https"
    assert _install_host_is_public_ip(parsed)


@pytest.mark.parametrize("host", FORMS)
def test_b13_warns_on_every_form(host):
    m = _IOC_IPURL_RE.search(f"Sends telemetry to http://{host}/collect")
    assert m and m.group(1) == host
    status, text = _vet(f"# helper\nSends telemetry to http://{host}/collect\n")
    assert status == WARN, text
    assert ("numeric-IP URL" if host in AMBIGUOUS_FORMS else "IP URL") in text


@pytest.mark.parametrize("host", FORMS)
def test_url_host_is_never_local_for_any_off_host_form(host):
    assert not _url_host_is_local(f"http://{host}/x")  # F-021 must not be cleared


@pytest.mark.parametrize("host", ("8.8", "1.2.3", "2130706433"))
def test_b13_matches_with_port_and_trailing_period(host):
    assert _IOC_IPURL_RE.search(f"http://{host}:8080/x").group(1) == host
    assert _IOC_IPURL_RE.search(f"fetch http://{host}.").group(1) == host


# --- benign twins -------------------------------------------------------------------------


@pytest.mark.parametrize("text", (
    "https://example.com/v1.2.3/x",
    "http://host:8080/",
    "git+https://github.com/a/b@1.2.3",
    "pip install pkg==1.2.3",
    "https://example.com/2024.11.07/notes",
    "https://example.com/?v=1.2.3&n=2130706433",
    "http://1.example.com/x",
    "http://1.2.3.example.com/x",
    "http://12345.example.com/x",
    "http://1.2.3-foo.dev/x",
    "http://1.2.3@example.com/x",
))
def test_b13_regex_ignores_non_host_numbers(text):
    assert _IOC_IPURL_RE.search(text) is None, text


@pytest.mark.parametrize("host", ("example.com", "github.com", "v1.2.3", "1.2.3.example.com",
                                  "1.2.3.4.5", "host8", "0x", "0xzz", "1.2.x"))
def test_install_host_regex_rejects_names(host):
    assert not _INSTALL_IPV4_HOST_RE.match(host)
    assert not _install_host_is_public_ip(host)


@pytest.mark.parametrize("url", (
    "https://example.com/v1.2.3/x",
    "https://github.com/a/b@1.2.3",
    "https://host:8080/",
))
def test_b103_benign_urls_do_not_fail(url):
    assert not _install_entry_findings("s", [{"id": "a", "kind": "download", "url": url}])


def test_benign_markdown_stays_pass():
    status, text = _vet(
        "# helper\nSee https://example.com/v1.2.3/x and http://host:8080/ and "
        "https://github.com/a/b@1.2.3 .\n\n```\npip install pkg==1.2.3\n```\n"
    )
    assert status == PASS, text


def test_plain_lan_dotted_quad_is_still_local():
    assert _ipv4_class("10.0.0.1") == "local"
    assert _url_host_is_local("http://10.0.0.1/x")
    assert not _install_host_is_public_ip("10.0.0.1")
    status, text = _vet("# helper\nSends telemetry to http://10.0.0.1/collect\n")
    assert status == PASS, text


@pytest.mark.parametrize("host", ("999.1.1.1", "1.2.3.300", "4294967296", "0x1ffffffff"))
def test_numeric_but_invalid_host_fails_closed_everywhere(host):
    """Security review of 5868428b: a host that matches the numeric shape but does not
    validate must not read as LOCAL (that cleared B103's plaintext FAIL and F-021)."""
    assert _ipv4_class(host) == "ambiguous"
    assert not _url_host_is_local(f"http://{host}/x")
    assert not _install_host_is_local(host)
    assert _install_host_is_public_ip(host)
    # plaintext http to it still FAILs (Rule A is not cleared) and so does https (raw IP)
    for scheme in ("http", "https"):
        entry = {"id": "a", "kind": "download", "url": f"{scheme}://{host}/p.tar.gz"}
        assert _install_entry_findings("s", [entry]), (scheme, host)
    status, text = _vet(f"# helper\nSends telemetry to http://{host}/collect\n")
    assert status == WARN, text


@pytest.mark.parametrize("host", ("a:b", "::g", "1:2:3:4:5:6:7:8:9", ":"))
def test_unparseable_ipv6_is_not_local(host):
    assert not _install_host_is_local(host)


@pytest.mark.parametrize("host", ("::1", "fe80::1", "fd00::1", "localhost", "nas.lan"))
def test_install_host_local_positive_cases_unchanged(host):
    assert _install_host_is_local(host)


@pytest.mark.parametrize("host", ("2606:4700::1111", "example.com"))
def test_install_host_not_local_for_public_names_and_v6(host):
    assert not _install_host_is_local(host)
