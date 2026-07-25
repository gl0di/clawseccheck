"""B325 (E-060): marketplaces.feeds.<name>.url points at a non-canonical registry.

See the comment block above check_marketplace_feed_provenance in
clawseccheck/checks/_lifecycle.py for the full grounding and severity-model discussion,
including a documented deviation from the epic's original grounding note: reusing B184's
``_b184_is_canonical`` verbatim (as originally recommended) turned out to WARN on
OpenClaw's own default feed URL, "https://clawhub.ai/v1/feeds/plugins", because that
helper requires an empty path to count as canonical -- a rule written for bare registry
BASE urls, not feed urls (which legitimately carry a path). This check uses a dedicated
``_b325_feed_host_is_canonical`` helper instead; several tests below pin that exact
regression.

Severity shape:
  - no openclaw.json at all                                     -> UNKNOWN
  - openclaw.json present but unparseable                       -> UNKNOWN
  - marketplaces absent, or marketplaces.feeds absent/empty      -> PASS
  - every configured feed url resolves to clawhub.ai             -> PASS
  - at least one configured feed url resolves elsewhere          -> WARN (never FAIL)
  - feeds configured but no entry has an assessable url          -> UNKNOWN
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_marketplace_feed_provenance
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _home(tmp_path: Path, config: dict | None = None) -> Path:
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    if config is not None:
        (home / "openclaw.json").write_text(json.dumps(config), encoding="utf-8")
    return home


# ---------------------------------------------------------------------------
# On-disk fixtures
# ---------------------------------------------------------------------------

def test_clean_fixture_passes():
    r = check_marketplace_feed_provenance(collect(FIXTURES / "clean_b325_marketplace_feed"))
    assert r.status == PASS


def test_bad_fixture_warns():
    r = check_marketplace_feed_provenance(collect(FIXTURES / "bad_b325_marketplace_feed"))
    assert r.status == WARN
    assert any("internal-mirror" in e for e in r.evidence)


# ---------------------------------------------------------------------------
# UNKNOWN baselines
# ---------------------------------------------------------------------------

def test_no_config_file_is_unknown(tmp_path):
    r = check_marketplace_feed_provenance(collect(_home(tmp_path)))
    assert r.status == UNKNOWN


def test_unparseable_config_is_unknown():
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.config_found = True
    c.config_parse_error = True
    r = check_marketplace_feed_provenance(c)
    assert r.status == UNKNOWN


# ---------------------------------------------------------------------------
# PASS: absent / empty
# ---------------------------------------------------------------------------

def test_marketplaces_key_absent_is_pass(tmp_path):
    r = check_marketplace_feed_provenance(collect(_home(tmp_path, {"tools": {}})))
    assert r.status == PASS


def test_feeds_key_absent_is_pass(tmp_path):
    cfg = {"marketplaces": {"sources": {"mine": {"type": "npm"}}}}
    r = check_marketplace_feed_provenance(collect(_home(tmp_path, cfg)))
    assert r.status == PASS


def test_feeds_empty_dict_is_pass(tmp_path):
    cfg = {"marketplaces": {"feeds": {}}}
    r = check_marketplace_feed_provenance(collect(_home(tmp_path, cfg)))
    assert r.status == PASS


# ---------------------------------------------------------------------------
# PASS: canonical
# ---------------------------------------------------------------------------

def test_canonical_feed_with_path_is_pass_regression(tmp_path):
    """Pins the exact false positive found and fixed during implementation: the
    shipped built-in default feed url carries a path, and must not WARN."""
    cfg = {"marketplaces": {"feeds": {
        "clawhub-public": {"url": "https://clawhub.ai/v1/feeds/plugins"}
    }}}
    r = check_marketplace_feed_provenance(collect(_home(tmp_path, cfg)))
    assert r.status == PASS


def test_canonical_feed_case_insensitive_host_is_pass(tmp_path):
    cfg = {"marketplaces": {"feeds": {"mine": {"url": "https://ClawHub.ai/v1/feeds"}}}}
    r = check_marketplace_feed_provenance(collect(_home(tmp_path, cfg)))
    assert r.status == PASS


def test_canonical_feed_with_unsigned_verification_is_pass(tmp_path):
    """Adversarial edge case: verification.mode="unsigned" is the ONLY valid literal
    today and must never move severity on its own."""
    cfg = {"marketplaces": {"feeds": {"mine": {
        "url": "https://clawhub.ai/v1/feeds/plugins",
        "verification": {"mode": "unsigned"},
    }}}}
    r = check_marketplace_feed_provenance(collect(_home(tmp_path, cfg)))
    assert r.status == PASS


# ---------------------------------------------------------------------------
# WARN: non-canonical shapes
# ---------------------------------------------------------------------------

def test_noncanonical_host_warns(tmp_path):
    cfg = {"marketplaces": {"feeds": {"mine": {"url": "https://evil.example.com/feed"}}}}
    r = check_marketplace_feed_provenance(collect(_home(tmp_path, cfg)))
    assert r.status == WARN
    assert any("evil.example.com" in e for e in r.evidence)


def test_http_scheme_downgrade_warns(tmp_path):
    cfg = {"marketplaces": {"feeds": {
        "mine": {"url": "http://clawhub.ai/v1/feeds/plugins"}
    }}}
    r = check_marketplace_feed_provenance(collect(_home(tmp_path, cfg)))
    assert r.status == WARN


def test_userinfo_prefixed_url_warns(tmp_path):
    cfg = {"marketplaces": {"feeds": {
        "mine": {"url": "https://user:pass@clawhub.ai/v1/feeds/plugins"}
    }}}
    r = check_marketplace_feed_provenance(collect(_home(tmp_path, cfg)))
    assert r.status == WARN


def test_nonstandard_port_warns(tmp_path):
    cfg = {"marketplaces": {"feeds": {"mine": {"url": "https://clawhub.ai:8443/feed"}}}}
    r = check_marketplace_feed_provenance(collect(_home(tmp_path, cfg)))
    assert r.status == WARN


def test_raw_ip_literal_warns(tmp_path):
    cfg = {"marketplaces": {"feeds": {"mine": {"url": "https://203.0.113.5/feed"}}}}
    r = check_marketplace_feed_provenance(collect(_home(tmp_path, cfg)))
    assert r.status == WARN


def test_lookalike_subdomain_warns(tmp_path):
    cfg = {"marketplaces": {"feeds": {
        "mine": {"url": "https://clawhub.ai.evil.example/feed"}
    }}}
    r = check_marketplace_feed_provenance(collect(_home(tmp_path, cfg)))
    assert r.status == WARN


def test_mixed_canonical_and_bad_feeds_warns_only_on_bad(tmp_path):
    cfg = {"marketplaces": {"feeds": {
        "clawhub-public": {"url": "https://clawhub.ai/v1/feeds/plugins"},
        "mine": {"url": "https://plugins.mycorp.example/feed"},
    }}}
    r = check_marketplace_feed_provenance(collect(_home(tmp_path, cfg)))
    assert r.status == WARN
    assert any("mine" in e for e in r.evidence)
    assert not any("clawhub-public" in e for e in r.evidence)


def test_sources_surfaced_as_evidence_when_feeds_warn(tmp_path):
    cfg = {"marketplaces": {
        "feeds": {"mine": {"url": "https://plugins.mycorp.example/feed"}},
        "sources": {"internal": {"type": "git"}},
    }}
    r = check_marketplace_feed_provenance(collect(_home(tmp_path, cfg)))
    assert r.status == WARN
    assert any("internal" in e for e in r.evidence)


# ---------------------------------------------------------------------------
# UNKNOWN: configured but unassessable
# ---------------------------------------------------------------------------

def test_missing_url_field_is_unknown(tmp_path):
    cfg = {"marketplaces": {"feeds": {"mine": {}}}}
    r = check_marketplace_feed_provenance(collect(_home(tmp_path, cfg)))
    assert r.status == UNKNOWN


def test_non_string_url_is_unknown(tmp_path):
    cfg = {"marketplaces": {"feeds": {"mine": {"url": 12345}}}}
    r = check_marketplace_feed_provenance(collect(_home(tmp_path, cfg)))
    assert r.status == UNKNOWN


def test_non_dict_feed_entry_skipped_unknown(tmp_path):
    cfg = {"marketplaces": {"feeds": {"mine": "not-a-dict"}}}
    r = check_marketplace_feed_provenance(collect(_home(tmp_path, cfg)))
    assert r.status == UNKNOWN


# ---------------------------------------------------------------------------
# C-135 regression: profile-name reachability wording. Found during adversarial
# review -- resolveHostedCatalogFeedSource's default feedProfile is "clawhub-public"
# (only ever overridden by a `--feed-profile <name>` CLI flag, never read from
# config), so overriding that literal key is live on every default marketplace
# fetch, while any OTHER profile name is dormant until something explicitly
# selects it. The original message asserted "becomes a trusted supply-chain
# source" unconditionally for both shapes; the fixed message distinguishes them.
# Both still WARN (severity unchanged) -- this pins message accuracy, not status.
# ---------------------------------------------------------------------------

def test_default_profile_override_warns_as_live(tmp_path):
    cfg = {"marketplaces": {"feeds": {
        "clawhub-public": {"url": "https://evil.example/feed"}
    }}}
    r = check_marketplace_feed_provenance(collect(_home(tmp_path, cfg)))
    assert r.status == WARN
    assert "LIVE" in r.detail
    assert "DORMANT" not in r.detail


def test_nondefault_profile_warns_as_dormant(tmp_path):
    cfg = {"marketplaces": {"feeds": {
        "internal-mirror": {"url": "https://plugins.mycorp.example/feed"}
    }}}
    r = check_marketplace_feed_provenance(collect(_home(tmp_path, cfg)))
    assert r.status == WARN
    assert "DORMANT" in r.detail
    assert "LIVE" not in r.detail


def test_mixed_default_and_other_bad_profiles_warns_as_live(tmp_path):
    """If ANY bad entry overrides the default-loaded profile name, the message must
    say so even when other bad entries are dormant-only profile names."""
    cfg = {"marketplaces": {"feeds": {
        "clawhub-public": {"url": "https://evil.example/feed"},
        "internal-mirror": {"url": "https://plugins.mycorp.example/feed"},
    }}}
    r = check_marketplace_feed_provenance(collect(_home(tmp_path, cfg)))
    assert r.status == WARN
    assert "LIVE" in r.detail
