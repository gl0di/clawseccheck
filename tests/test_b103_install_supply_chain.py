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
])
def test_clean_fixtures_pass(name):
    f = check_install_directive_supply_chain(collect(FIXTURES / name))
    assert f.status == PASS, f"{name}: expected PASS, got {f.status}: {f.detail}"


# ── unit: the per-entry rules + the misparse guard ────────────────────────────

def test_plaintext_and_anonymous_hosts_fail():
    for entry in (
        {"id": "a", "kind": "download", "url": "http://x.example/p.tar.gz"},
        {"id": "b", "kind": "download", "url": "ftp://x.example/p.tar.gz"},
        {"id": "c", "kind": "download", "url": "https://198.51.100.7/p.tar.gz"},
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
