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

import datetime
import json
from pathlib import Path

from clawseccheck import iocdb
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
    assert git["owner"] == "owner"
    url = _parse_source_target("https://github.com/owner/repo")
    assert url["ecosystem"] == "url" and url["host"] == "github.com" and url["name"] == "repo"
    assert url["owner"] == "owner"
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


# --------------------------------------------------------------------------- #
# B-200: typosquat on the SOURCE's owner/org segment (git:host/OWNER/repo, or a
# URL host/OWNER/repo path) -- previously parsed and silently discarded, so a
# source impersonating a trusted org while naming the repo itself anything went
# undetected. Reuses the same _squat_hits machinery/pool as the slug check above.
# --------------------------------------------------------------------------- #
def test_git_owner_typosquat_of_brand_warns():
    f = vet_source("git:github.com/githubb/some-tool")  # owner squats 'github'
    assert f.status == WARN
    assert "githubb" in "\n".join(f.evidence)
    assert "github" in "\n".join(f.evidence)


def test_url_owner_typosquat_of_brand_warns():
    f = vet_source("https://github.com/anthropicc/repo/archive/main.zip")
    assert f.status == WARN
    assert "anthropicc" in "\n".join(f.evidence)


def test_exact_known_owner_is_not_a_squat():
    # 'gitlab' is itself a known brand -- the real org, not a squat of itself.
    f = vet_source("git:github.com/gitlab/some-tool")
    assert "typosquat" not in f.detail
    assert not any("resembles" in e for e in f.evidence)


def test_owner_squat_fires_even_when_repo_name_is_an_exact_known_good_match():
    # The repo/slug basename ('clawseccheck') is an exact known-good match, which
    # previously suppressed the ENTIRE squat check (including the owner) -- the
    # owner squat must still fire independently.
    f = vet_source("git:github.com/githubb/clawseccheck")
    assert f.status == WARN
    assert "githubb" in "\n".join(f.evidence)


def test_unrelated_legit_owner_and_repo_stays_clean():
    f = vet_source("git:github.com/gl0di/clawseccheck")
    assert not any("resembles" in e for e in f.evidence)


def test_single_segment_git_path_has_no_owner():
    # No "owner/repo" split possible -- owner extraction must not crash or
    # fabricate a false candidate.
    info = _parse_source_target("git:github.com/justarepo")
    assert info["owner"] is None


# ---------------------------------------------------------------------------
# C-135 (on B-200): real GitHub orgs one un-separated short suffix away from a
# brand (framework/language-suffix or pluralization naming, not a squat) false-
# fired -- e.g. github.com/anthropics is Anthropic's own real org.
# ---------------------------------------------------------------------------

def test_real_org_brand_suffix_variants_are_not_squats():
    for owner in ("anthropics", "expressjs", "discordjs", "huggingfaceh4", "postgresml"):
        f = vet_source(f"git:github.com/{owner}/mytool")
        assert not any("resembles" in e for e in f.evidence), owner


def test_real_squat_owners_still_fire_after_legit_neighbor_exemption():
    # Positive control: the exemption above must be specific to the verified real
    # orgs, not a blanket "brand + short suffix" rule -- an actual squat (extra
    # doubled letter, not a real naming convention) must still WARN.
    for owner in ("githubb", "anthropicc"):
        f = vet_source(f"git:github.com/{owner}/mytool")
        assert any("resembles" in e for e in f.evidence), owner


def test_b218_hyphen_omitted_known_plugin_id_is_not_a_squat():
    """CLAWSECCHECK-B-218: writing a hyphenated known plugin-id without its hyphen
    (a common, arguably more natural spelling) must not false-fire as a typosquat --
    the known side is now normalized the same way the candidate side already is."""
    for slug in ("githubcopilot", "copilotproxy", "documentextract", "filetransfer", "azurespeech"):
        f = vet_source(f"git:github.com/{slug}/mytool")
        assert not any("resembles" in e for e in f.evidence), slug


def test_b218_genuine_near_miss_of_hyphenated_known_still_warns():
    # Positive control: the hyphen-stripped exemption above must be an EXACT match
    # only -- a genuine near-miss (hyphen omitted AND a real typo) must still WARN.
    f = vet_source("git:github.com/githubcopilott/mytool")
    assert any("resembles" in e for e in f.evidence)


def test_official_anthropics_claude_code_source_does_not_double_warn_on_owner():
    f = vet_source("git:github.com/anthropics/claude-code")
    owner_hits = [e for e in f.evidence if "anthropic" in e and "resembles" in e]
    assert owner_hits == []


# ---------------------------------------------------------------------------
# C-135 (on B-200): a leading/doubled slash in a git: source zeroed the owner
# segment (an unfiltered split kept the empty string as path_parts[0]), silently
# skipping the owner-squat check entirely -- a real, zero-cost evasion.
# ---------------------------------------------------------------------------

def test_doubled_slash_does_not_silently_drop_owner_extraction():
    info = _parse_source_target("git:github.com//githubb/mytool")
    assert info["owner"] == "githubb"


def test_doubled_slash_owner_squat_still_warns():
    f = vet_source("git:github.com//githubb/mytool@main")
    assert any("resembles" in e for e in f.evidence)


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


# --------------------------------------------------------------------------- #
# CLAWSECCHECK-F-157: the shipped catalog is now iocdb.py — a dated,           #
# provenance-bound dataset, not an inline frozenset literal.                   #
# --------------------------------------------------------------------------- #
def test_shipped_catalog_round_trips_through_iocdb():
    # Every value formerly hardcoded in _SOURCE_KNOWN_BAD is still matched after the
    # move to iocdb.py — no silent coverage loss.
    assert vet_source("clawhub:omnicogg").status == FAIL
    assert vet_source("clawhub:money-radar").status == FAIL
    assert vet_source("clawhub:letssendit").status == FAIL
    assert vet_source("clawhub:ai-tradingview-assistant-for-macos").status == FAIL
    assert vet_source("clawhub:tradingview-ai-indicator-assistant").status == FAIL
    assert vet_source("https://91.92.242.30/x").status == FAIL
    assert vet_source("https://laosji.net/x").status == FAIL
    assert vet_source("https://letssendit.fun/x").status == FAIL


def test_c135_bare_name_colliding_with_host_ioc_is_not_a_false_fail():
    # CLAWSECCHECK-F-157 C-135 regression: a pypi/npm/git/clawhub package whose bare
    # NAME happens to equal one of the 3 HOSTS literals must NOT fail as a
    # known-bad SOURCE -- it has nothing to do with the actual IOC host, only a
    # name collision. Pre-fix, iocdb.known_bad_sources() leaked HOSTS values into
    # the "any" pool, so vet_source's step-1 exact-name match (eco_keys =
    # [eco, "any"]) wrongly FAILed every one of these. Correct verdict: UNKNOWN
    # (no known-bad SOURCE record for that ecosystem+name).
    for target in (
        "pypi:laosji.net",
        "npm:letssendit.fun",
        "git:github.com/someuser/91.92.242.30@main",  # ref pinned: isolate from the
        # separate unpinned-ref WARN so only the known-bad-name path is under test
    ):
        f = vet_source(target)
        assert f.status == UNKNOWN, f"{target} -> {f.status}: {f.detail}"
        assert "known-compromised" not in f.detail


def test_c135_real_host_ioc_still_fails_after_the_any_pool_fix():
    # The companion assertion to the fix above: restricting HOSTS to the "url" pool
    # must NOT silently disable real host-IOC detection. A genuine URL/host source
    # actually served off the known-bad infrastructure still FAILs via the step-1b
    # host check (catalog: url) -- this is the true positive the fix must preserve.
    for target in (
        "https://laosji.net/payload.sh",
        "https://letssendit.fun/x",
        "https://91.92.242.30/x",
    ):
        f = vet_source(target)
        assert f.status == FAIL, f"{target} -> {f.status}: {f.detail}"
        assert "known-compromised infrastructure" in f.detail
        assert "catalog: url" in f.detail


def test_vet_source_stays_silent_when_iocdb_is_fresh():
    # Real dataset, real (current) clock -- freshness_notice() contributes nothing.
    f = vet_source("clawhub:my-totally-new-skill")
    assert not any("days old" in e for e in f.evidence)


def test_vet_source_evidence_never_carries_iocdb_staleness_notice(monkeypatch):
    # B-385: date.today()-derived text must NEVER reach Finding.evidence, staleness or
    # not -- it was moved to a renderer-only channel (cli.py's --vet-source branch).
    # Even with the dataset forced stale, evidence stays untouched.
    monkeypatch.setattr(iocdb, "REVISION", "2020-01-01")
    f = vet_source("clawhub:my-totally-new-skill")
    assert not any("days old" in e for e in f.evidence)


def test_vet_source_evidence_byte_identical_across_dates(monkeypatch):
    # B-385 regression test (the ticket's own required test): freeze the dataset as
    # maximally stale and confirm Finding.evidence for the SAME target is byte-identical
    # regardless of "which day" the stale-ness would have been computed on -- i.e.
    # evidence no longer depends on the clock at all. This must have failed before the
    # fix (the old code embedded a live-clock-derived "N days old" line whenever stale).
    monkeypatch.setattr(iocdb, "REVISION", "2020-01-01")
    f1 = vet_source("clawhub:my-totally-new-skill")
    f2 = vet_source("clawhub:my-totally-new-skill")
    assert f1.evidence == f2.evidence
    assert not any("days old" in e for e in f1.evidence)


def test_vet_source_synthetic_catalog_never_gets_real_staleness_notice(monkeypatch):
    # A test-injected known_bad= catalog has no revision of its own -- the real
    # dataset's (possibly stale) freshness notice must never leak onto it (still true
    # now that the notice never enters evidence for ANY catalog).
    monkeypatch.setattr(iocdb, "REVISION", "2020-01-01")
    f = vet_source("npm:evil-agent-tool", known_bad=_BAD)
    assert not any("days old" in e for e in f.evidence)


def test_vet_source_cli_still_surfaces_staleness_notice_on_stderr(monkeypatch, capsys):
    # The staleness warning must still reach the user SOMEWHERE (not silently dropped) --
    # just never inside the Finding/dossier/--json result payload. Printed to stderr by
    # the --vet-source CLI branch, sourced directly from iocdb.freshness_notice().
    monkeypatch.setattr(iocdb, "REVISION", "2020-01-01")
    rc = main(["--vet-source", "clawhub:my-totally-new-skill", "--json"])
    assert rc in (0, 1)
    captured = capsys.readouterr()
    assert "IOC dataset is" in captured.err and "days old" in captured.err
    # And it must not have leaked into the --json result payload's evidence either.
    assert "days old" not in captured.out


def test_vet_source_cli_respects_no_freshness_notice_flag(monkeypatch, capsys):
    monkeypatch.setattr(iocdb, "REVISION", "2020-01-01")
    main(["--vet-source", "clawhub:my-totally-new-skill", "--json", "--no-freshness-notice"])
    err = capsys.readouterr().err
    assert "days old" not in err


# --------------------------------------------------------------------------- #
# iocdb.py itself: freshness_notice() unit coverage (dated, provenance-bound).  #
# --------------------------------------------------------------------------- #
def test_iocdb_freshness_notice_silent_when_current():
    assert iocdb.freshness_notice(today=iocdb.revision_date()) == []


def test_iocdb_freshness_notice_silent_just_under_threshold():
    just_under = iocdb.revision_date() + datetime.timedelta(days=iocdb.STALE_AFTER_DAYS - 1)
    assert iocdb.freshness_notice(today=just_under) == []


def test_iocdb_freshness_notice_fires_at_threshold():
    at_threshold = iocdb.revision_date() + datetime.timedelta(days=iocdb.STALE_AFTER_DAYS)
    notice = iocdb.freshness_notice(today=at_threshold)
    assert notice and "days old" in notice[0]


def test_iocdb_freshness_notice_fires_well_past_threshold():
    old = iocdb.revision_date() + datetime.timedelta(days=iocdb.STALE_AFTER_DAYS + 400)
    notice = iocdb.freshness_notice(today=old)
    assert notice and f"{iocdb.STALE_AFTER_DAYS + 400} days old" in notice[0]


def test_catalog_is_populated_and_source_cited():
    # The shipped catalog is no longer empty, and its source block cites the advisories.
    # CLAWSECCHECK-F-157: the catalog (and its per-entry provenance) now lives in
    # clawseccheck/iocdb.py, not an inline literal in checks/_vet.py.
    assert _SOURCE_KNOWN_BAD["clawhub"] and _SOURCE_KNOWN_BAD["url"]
    iocdb_path = Path(__file__).resolve().parent.parent / "clawseccheck" / "iocdb.py"
    text = iocdb_path.read_text(encoding="utf-8")
    assert "Unit 42" in text
    assert "ClawHavoc" in text or "Koi" in text
