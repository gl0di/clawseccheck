"""F-073 (E-020, = E-019/F-064): vet_source() — the pre-download reputation gate.

Judges a source's IDENTITY (slug / URL / package spec) with zero network and zero
fetch: exact known-bad IOC match → FAIL (do not fetch); typosquat / source
heuristics → WARN (quarantine only); nothing known → UNKNOWN (proceed via
quarantine + --vet the fetched copy). Never PASS — identity cannot prove unseen
code safe. The shipped known-bad catalog is seeded ONLY from real, primary-source-
verified advisories (§2.4, C-145 — ClawHavoc / Unit 42), each entry citing its source;
FAIL-path tests still inject synthetic catalogs so they never depend on the live snapshot.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import FAIL, UNKNOWN, WARN
from clawseccheck.checks import _SOURCE_KNOWN_BAD, _parse_source_target, vet_source
from clawseccheck.cli import main

_BAD = {"npm": frozenset({"evil-agent-tool"}), "clawhub": frozenset({"badskill"}),
        "pypi": frozenset(), "git": frozenset(), "url": frozenset(), "any": frozenset()}


# --------------------------------------------------------------------------- #
# Target parsing (shapes mirror `openclaw plugins install` sources, recon §11.4)#
# --------------------------------------------------------------------------- #
def test_parse_shapes():
    npm = _parse_source_target("npm:@openclaw/brave-plugin@2026.6.11")
    assert npm["ecosystem"] == "npm" and npm["name"] == "@openclaw/brave-plugin"
    assert npm["version"] == "2026.6.11" and npm["kind"] == "plugin"
    pypi = _parse_source_target("pypi:some-mcp-server==1.0")
    assert pypi["ecosystem"] == "pypi" and pypi["version"] == "1.0" and pypi["kind"] == "mcp"
    claw = _parse_source_target("clawhub:clawseccheck")
    assert claw["ecosystem"] == "clawhub" and claw["kind"] == "skill"
    git = _parse_source_target("git:github.com/owner/repo@v1.2")
    assert git["ecosystem"] == "git" and git["host"] == "github.com" and git["ref"] == "v1.2"
    url = _parse_source_target("https://github.com/owner/repo")
    assert url["ecosystem"] == "url" and url["host"] == "github.com" and url["name"] == "repo"
    bare = _parse_source_target("someskill")
    assert bare["ecosystem"] == "registry"


# --------------------------------------------------------------------------- #
# Verdict bands.                                                               #
# --------------------------------------------------------------------------- #
def test_known_bad_exact_match_fails():
    f = vet_source("npm:evil-agent-tool", known_bad=_BAD)
    assert f.status == FAIL
    assert "known-compromised" in f.detail
    assert "Do NOT fetch" in f.fix


def test_known_bad_is_ecosystem_scoped():
    # 'badskill' is bad on clawhub, not on pypi — ecosystem scoping must hold.
    assert vet_source("clawhub:badskill", known_bad=_BAD).status == FAIL
    assert vet_source("pypi:badskill", known_bad=_BAD).status == UNKNOWN


def test_bare_name_checked_against_every_catalog():
    f = vet_source("evil-agent-tool", known_bad=_BAD)
    assert f.status == FAIL


def test_typosquat_of_brand_name_warns():
    f = vet_source("npm:reqeusts")                     # 'requests', distance 2
    assert f.status == WARN
    assert "typosquat" in f.detail
    assert "quarantine" in f.fix


def test_typosquat_of_real_plugin_id_warns():
    f = vet_source("clawhub:telegramm")                # real plugin id 'telegram'
    assert f.status == WARN
    assert "telegram" in "\n".join(f.evidence)


def test_exact_known_good_name_is_not_a_squat():
    f = vet_source("clawhub:telegram")                 # the real thing, not a squat
    assert f.status == UNKNOWN


def test_clean_unknown_name_is_unknown_never_pass():
    f = vet_source("clawhub:my-totally-new-skill")
    assert f.status == UNKNOWN
    assert "cannot prove unseen code safe" in f.detail
    assert "quarantine" in f.fix


# --------------------------------------------------------------------------- #
# Source heuristics.                                                           #
# --------------------------------------------------------------------------- #
def test_paste_host_and_plain_http_warn():
    f = vet_source("https://pastebin.com/raw/abc123")
    assert f.status == WARN and "paste" in "\n".join(f.evidence)
    f2 = vet_source("http://example.com/skill.zip")
    assert f2.status == WARN and "plaintext http" in "\n".join(f2.evidence)


def test_bare_ip_host_warns():
    f = vet_source("https://203.0.113.7/payload")
    assert f.status == WARN and "bare-IP" in "\n".join(f.evidence)


def test_git_unpinned_ref_warns_pinned_does_not():
    assert vet_source("git:github.com/owner/repo").status == WARN
    assert vet_source("git:github.com/owner/repo@abc123").status == UNKNOWN


def test_plain_github_https_url_is_unknown():
    # A normal repo URL carries no bad signal by itself — zero-FP on the common case.
    f = vet_source("https://github.com/openclaw/openclaw")
    assert f.status == UNKNOWN


# --------------------------------------------------------------------------- #
# CLI: rc semantics, human render, JSON purity.                                #
# --------------------------------------------------------------------------- #
def test_cli_vet_source_unknown_rc0(capsys):
    rc = main(["--vet-source", "clawhub:my-totally-new-skill"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "RISK DOSSIER" in captured.out and "UNKNOWN" in captured.out


def test_cli_vet_source_suspicious_rc1(capsys):
    rc = main(["--vet-source", "npm:reqeusts"])
    captured = capsys.readouterr()
    assert rc == 1
    assert "SUSPICIOUS" in captured.out


def test_cli_vet_source_json_purity(capsys):
    rc = main(["--vet-source", "git:github.com/owner/repo", "--json"])
    captured = capsys.readouterr()
    assert rc == 1
    payload = json.loads(captured.out)
    assert payload["mode"] == "vet-source"
    assert payload["verdict"] == "SUSPICIOUS"


# --------------------------------------------------------------------------- #
# C-145: the shipped known-bad catalog (real, primary-source-verified IOCs).   #
# These use the DEFAULT catalog (no known_bad= injection) — they assert the    #
# real snapshot fires. Verified against the primary advisories on 2026-07-03.  #
# --------------------------------------------------------------------------- #
def test_shipped_clawhub_ioc_fails():
    # Unit 42 (2026-06-23) skill slug — shipped in the real catalog.
    f = vet_source("clawhub:omnicogg")
    assert f.status == FAIL
    assert "known-compromised" in f.detail


def test_shipped_bare_name_ioc_fails():
    # A bare registry name is checked against every ecosystem pool.
    assert vet_source("money-radar").status == FAIL


def test_shipped_malicious_host_fails():
    # Infrastructure IOC matched against the URL host (not just the path segment).
    f = vet_source("https://laosji.net/setup.sh")
    assert f.status == FAIL
    assert "known-compromised infrastructure" in f.detail


def test_shipped_malicious_host_subdomain_fails():
    assert vet_source("https://cdn.laosji.net/x").status == FAIL


def test_shipped_c2_ip_host_is_fail_not_just_bare_ip_warn():
    # 91.92.242.30 is a known C2 -> FAIL (upgraded from the generic bare-IP WARN).
    f = vet_source("https://91.92.242.30/payload")
    assert f.status == FAIL
    assert "known-compromised infrastructure" in f.detail


def test_clean_host_not_in_catalog_is_not_fail():
    # Zero-FP: an unrelated host is never FAILed by the host check.
    assert vet_source("https://github.com/openclaw/openclaw").status == UNKNOWN


def test_near_miss_of_ioc_still_routes_through_typosquat_only():
    # A near-miss of a shipped IOC is NOT an exact known-bad match; it is only ever a
    # (typosquat) WARN or UNKNOWN — never a spurious FAIL from the known-bad pool.
    assert vet_source("clawhub:omnicoggg").status in (WARN, UNKNOWN)


def test_catalog_is_populated_and_source_cited():
    # The shipped catalog is no longer empty, and its source block cites the advisories.
    assert _SOURCE_KNOWN_BAD["clawhub"] and _SOURCE_KNOWN_BAD["url"]
    pkg = Path(__file__).resolve().parent.parent / "clawseccheck" / "checks"
    text = "".join(f.read_text(encoding="utf-8") for f in sorted(pkg.glob("*.py")))
    block = text.split("_SOURCE_KNOWN_BAD: dict = {", 1)[1].split("_SOURCE_KNOWN_GOOD", 1)[0]
    assert "Unit 42" in block
    assert "ClawHavoc" in block or "Koi" in block
