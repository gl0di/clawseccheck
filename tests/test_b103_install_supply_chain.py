"""B103 (task B-099) — supply-chain provenance of metadata.openclaw.install[] directives.

A skill's SKILL.md frontmatter can declare install[] directives OpenClaw runs to bootstrap
a runtime dependency (brew/apt/go/node/npm/uv/download). The `download` kind fetches +
extracts an arbitrary archive from a url. This had zero vetting — a plaintext-HTTP or
raw-IP/.onion fetch read SAFE/A/100.

B103 FAILs only on unambiguous provenance failures (plaintext http/ftp scheme, or a raw-IP
or .onion host) and never on a package coordinate. Zero-FP is verified against the full real
fleet (see test_fleet_wide_zero_fail). Offline, read-only, stdlib only.
"""
from __future__ import annotations

import glob
import os
from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, UNKNOWN
from clawseccheck.checks import (
    _fm_metadata_obj_multiline,
    _install_entry_findings,
    _skill_frontmatter_block,
    check_install_directive_supply_chain,
    dig,
)
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
_FLEET = os.path.expanduser("~/.npm-global/lib/node_modules/openclaw/skills/*/SKILL.md")


# ── integration: fixtures through the real check ──────────────────────────────

@pytest.mark.parametrize("name", [
    "bad_b103_http_download", "bad_b103_ftp", "bad_b103_ip_host", "bad_b103_onion",
])
def test_bad_fixtures_fail(name):
    f = check_install_directive_supply_chain(collect(FIXTURES / name))
    assert f.status == FAIL, f"{name}: expected FAIL, got {f.status}: {f.detail}"


@pytest.mark.parametrize("name", [
    "clean_b103_brew", "clean_b103_go", "clean_b103_download_https", "clean_b103_multi",
    # B-115: install directives that fetch from a loopback / private-LAN / IPv6-loopback
    # mirror (air-gapped / homelab) are the operator's own network, not an anonymous
    # supply-chain source — they must PASS, not FAIL as raw-IP hosts.
    "clean_b103_private_ip",
])
def test_clean_fixtures_pass(name):
    f = check_install_directive_supply_chain(collect(FIXTURES / name))
    assert f.status == PASS, f"{name}: expected PASS, got {f.status}: {f.detail}"


def test_b103_public_ip_host_still_fails():
    # B-115 discriminator: a raw PUBLIC (routable) IP install host is still an unverified,
    # swappable supply-chain source and must FAIL.
    f = check_install_directive_supply_chain(collect(FIXTURES / "bad_b103_ip_host"))
    assert f.status == FAIL
    assert "public-IP" in f.detail


def test_b103_private_and_ipv6_hosts_not_flagged():
    from clawseccheck.checks import _install_host_is_public_ip
    for host in ("185.199.108.153", "8.8.8.8", "2606:4700:4700::1111"):
        assert _install_host_is_public_ip(host), host
    for host in ("127.0.0.1", "192.168.1.50", "10.0.0.1", "172.16.0.1",
                 "198.51.100.7", "::1", "fc00::1", "fe80::1"):
        assert not _install_host_is_public_ip(host), host


# ── unit: the per-entry rules + the misparse guard ────────────────────────────

def test_plaintext_and_anonymous_hosts_fail():
    for entry in (
        {"id": "a", "kind": "download", "url": "http://x.example/p.tar.gz"},
        {"id": "b", "kind": "download", "url": "ftp://x.example/p.tar.gz"},
        {"id": "c", "kind": "download", "url": "https://185.199.108.153/p.tar.gz"},
        {"id": "d", "kind": "download",
         "url": "https://abcdefghijklmnop234567.onion/p.tar.gz"},
    ):
        assert _install_entry_findings("s", [entry]), entry


def test_package_coordinates_are_never_url_parsed():
    # go module / brew formula / node package all CONTAIN dotted text or github.com but are
    # coordinates, not URLs — they must never be host/IP/onion tested (pre-mortem #1).
    clean = [
        {"id": "go", "kind": "go", "module": "github.com/steipete/sonoscli/cmd/sonos@latest"},
        {"id": "brew", "kind": "brew", "formula": "steipete/tap/imsg"},
        {"id": "node", "kind": "node", "package": "@steipete/oracle"},
        {"id": "https", "kind": "download",
         "url": "https://github.com/k2-fsa/sherpa/releases/download/v1.13.2/x.tar.bz2"},
    ]
    assert _install_entry_findings("s", clean) == []


def test_multiline_metadata_parser_recovers_install():
    # the real fleet writes multi-line, trailing-comma JSON that the single-line parser misses.
    fm = ('name: x\nmetadata: {\n  "openclaw": {\n    "install": [\n'
          '      { "id": "brew", "kind": "brew", "formula": "gh", "bins": ["gh"] },\n'
          '    ],\n  },\n}\n')
    meta = _fm_metadata_obj_multiline(fm)
    install = dig(meta, "openclaw.install")
    assert isinstance(install, list) and install and install[0]["formula"] == "gh"


def test_unparseable_metadata_is_unknown_not_fail():
    # a broken metadata block must be treated as nothing-to-inspect, never a finding.
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.bootstrap = {}
    c.installed_skills = {"s": "---\nname: x\nmetadata: { not valid json {{{ \n---\n\nbody\n"}
    assert check_install_directive_supply_chain(c).status == UNKNOWN


def test_no_install_block_is_unknown():
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.bootstrap = {}
    c.installed_skills = {"s": "---\nname: x\ndescription: y\n---\n\nbody\n"}
    assert check_install_directive_supply_chain(c).status == UNKNOWN


def test_no_skills_is_unknown():
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.bootstrap = {}
    c.installed_skills = {}
    assert check_install_directive_supply_chain(c).status == UNKNOWN


# ── C-135 / §5: zero FAIL across the entire real bundled fleet ────────────────

@pytest.mark.skipif(not glob.glob(_FLEET), reason="OpenClaw bundled skills not present (CI)")
def test_fleet_wide_zero_fail():
    fails = []
    for sk in sorted(glob.glob(_FLEET)):
        fm = _skill_frontmatter_block(Path(sk).read_text(encoding="utf-8"))
        if not fm:
            continue
        install = dig(_fm_metadata_obj_multiline(fm), "openclaw.install")
        if install:
            fails.extend(_install_entry_findings(os.path.basename(os.path.dirname(sk)), install))
    assert not fails, f"B103 false-positive FAIL on real bundled skills: {fails}"
