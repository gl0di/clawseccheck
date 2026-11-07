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

FORMS = ("0x8.8.8.8", "0x08080808", "2130706433", "8.8", "1.2.3", "010.8.8.8", "0X7F.0.0.1",
         "0x7f000001", "4294967295")


def _vet(md: str) -> tuple:
    with tempfile.TemporaryDirectory() as td:
        d = Path(td) / "s"
        d.mkdir()
        (d / "SKILL.md").write_text("---\nname: s\ndescription: helper\n---\n" + md,
                                    encoding="utf-8")
        f = vet_skill(str(d))
        return f.status, f.detail + "\n" + "\n".join(f.evidence)


@pytest.mark.parametrize("host", FORMS)
def test_every_form_is_ambiguous_and_matches_both_host_regexes(host):
    assert _ipv4_class(host) == "ambiguous"
    assert _INSTALL_IPV4_HOST_RE.match(host)
    assert _IPV4_LITERAL_RE.match(host)


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
    assert "numeric-IP URL" in text


@pytest.mark.parametrize("host", FORMS)
def test_url_host_is_never_local_for_any_form(host):
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
