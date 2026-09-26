"""B25 — Update / pinning hygiene tests.

Conservative philosophy: WARN only on positive evidence (auto-update true,
or a floating ref/branch); PASS when pinned entries are present; UNKNOWN when
nothing determinable.
"""
from pathlib import Path

from clawseccheck.checks import check_update_pinning
from clawseccheck.collector import Context


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def _plugins_entries(entries: dict) -> dict:
    return {"plugins": {"entries": entries}}


def _skills_entries(entries: dict) -> dict:
    return {"skills": {"entries": entries}}


# ---- UNKNOWN: nothing determinable ----

def test_b25_empty_config_unknown():
    assert check_update_pinning(_ctx({})).status == "UNKNOWN"


def test_b25_plugins_entries_no_source_no_version_unknown():
    # Real agents: entries have only {enabled: true} — no source/version.
    cfg = _plugins_entries({"telegram": {"enabled": True}, "memory-core": {"enabled": True}})
    assert check_update_pinning(_ctx(cfg)).status == "UNKNOWN"


def test_b25_skills_entries_no_source_unknown():
    cfg = _skills_entries({"my-skill": {"enabled": True}})
    assert check_update_pinning(_ctx(cfg)).status == "UNKNOWN"


# ---- Regression: update.auto.enabled is OpenClaw's own core auto-update, not a
# ---- skills/plugin signal (removed 2026-09-26) ----
#
# `update.auto.enabled` drives OpenClaw's OWN `openclaw update` for its core package
# installs (dist: schema-*.mjs "Enable background auto-update for stable and beta
# package installs"; update-startup*.mjs gates `runAutoUpdateCommand`) -- it is not a
# skill/plugin auto-update mechanism, so it must not, by itself, produce a WARN here.
# `update.auto` (bare boolean), top-level `autoUpdate`, and `auto_update` were never
# real OpenClaw schema paths either -- they must never resurrect this signal.

def test_b25_core_auto_update_enabled_alone_does_not_warn():
    # No plugin/skill entries and no pre-release channel -> nothing else to flag ->
    # UNKNOWN, not WARN. This is the regression case: enabling OpenClaw's own
    # background auto-update for itself must not read as a supply-chain risk.
    cfg = {"update": {"auto": {"enabled": True}}}
    f = check_update_pinning(_ctx(cfg))
    assert f.status == "UNKNOWN"
    assert "auto-update" not in f.detail.lower()


def test_b25_phantom_auto_update_shapes_do_not_warn():
    """update.auto (bare), autoUpdate, auto_update are not real schema paths; even if
    present they must never trigger a WARN by themselves."""
    for cfg in (
        {"update": {"auto": True}},
        {"autoUpdate": True},
        {"autoUpdate": "true"},
        {"auto_update": True},
    ):
        f = check_update_pinning(_ctx(cfg))
        assert f.status == "UNKNOWN"


def test_b25_core_auto_update_disabled_does_not_warn():
    # explicitly disabled — no entries to check -> UNKNOWN (not WARN)
    cfg = {"update": {"auto": {"enabled": False}}}
    assert check_update_pinning(_ctx(cfg)).status == "UNKNOWN"


def test_b25_core_auto_update_plus_beta_channel_still_warns_via_channel_only():
    """update.auto.enabled=true alongside update.channel=beta must still WARN (via
    the channel signal) but must not mention auto-update in the detail/evidence --
    the removed signal must not resurface piggybacked on a different WARN."""
    cfg = {"update": {"auto": {"enabled": True}, "channel": "beta"}}
    f = check_update_pinning(_ctx(cfg))
    assert f.status == "WARN"
    assert "update.channel" in f.detail
    assert "auto-update" not in f.detail.lower()
    assert all("auto-update" not in ev.lower() for ev in f.evidence)


# ---- WARN: floating ref in version/ref field ----

def test_b25_version_latest_warns():
    cfg = _plugins_entries({"myplugin": {"source": "https://example.com/myplugin", "version": "latest"}})
    f = check_update_pinning(_ctx(cfg))
    assert f.status == "WARN"
    assert "floating" in f.detail.lower() or "latest" in f.detail


def test_b25_version_main_warns():
    cfg = _plugins_entries({"myplugin": {"source": "https://example.com/myplugin", "version": "main"}})
    assert check_update_pinning(_ctx(cfg)).status == "WARN"


def test_b25_version_master_warns():
    cfg = _plugins_entries({"myplugin": {"source": "git@github.com:x/y.git", "version": "master"}})
    assert check_update_pinning(_ctx(cfg)).status == "WARN"


def test_b25_ref_head_warns():
    cfg = _plugins_entries({"myplugin": {"source": "https://example.com/x", "ref": "HEAD"}})
    assert check_update_pinning(_ctx(cfg)).status == "WARN"


def test_b25_ref_dev_warns():
    cfg = _skills_entries({"myskill": {"source": "https://example.com/x", "ref": "dev"}})
    assert check_update_pinning(_ctx(cfg)).status == "WARN"


def test_b25_source_url_with_floating_branch_warns():
    cfg = _plugins_entries({"myplugin": {
        "source": "https://github.com/owner/repo/archive/main.tar.gz"
    }})
    assert check_update_pinning(_ctx(cfg)).status == "WARN"


def test_b25_source_url_tree_master_warns():
    cfg = _plugins_entries({"myplugin": {
        "source": "https://github.com/owner/repo/tree/master"
    }})
    assert check_update_pinning(_ctx(cfg)).status == "WARN"


# ---- PASS: pinned tag or commit SHA ----

def test_b25_semver_tag_passes():
    cfg = _plugins_entries({"myplugin": {"source": "https://example.com/x", "version": "v1.2.3"}})
    assert check_update_pinning(_ctx(cfg)).status == "PASS"


def test_b25_semver_without_v_passes():
    cfg = _plugins_entries({"myplugin": {"source": "https://example.com/x", "version": "2.0.1"}})
    assert check_update_pinning(_ctx(cfg)).status == "PASS"


def test_b25_commit_sha_long_passes():
    sha = "a" * 40
    cfg = _plugins_entries({"myplugin": {"source": "https://example.com/x", "ref": sha}})
    assert check_update_pinning(_ctx(cfg)).status == "PASS"


def test_b25_commit_sha_short_passes():
    cfg = _plugins_entries({"myplugin": {"source": "https://example.com/x", "commit": "abc1234"}})
    assert check_update_pinning(_ctx(cfg)).status == "PASS"


def test_b25_integrity_hash_passes():
    cfg = _plugins_entries({"myplugin": {
        "source": "https://example.com/x",
        "integrity": "sha256-abcdef1234567890",
    }})
    assert check_update_pinning(_ctx(cfg)).status == "PASS"


def test_b25_sha256_field_passes():
    cfg = _plugins_entries({"myplugin": {
        "source": "https://example.com/x",
        "sha256": "deadbeef1234",
    }})
    assert check_update_pinning(_ctx(cfg)).status == "PASS"


def test_b25_checksum_field_passes():
    cfg = _plugins_entries({"myplugin": {
        "source": "https://example.com/x",
        "checksum": "sha256:abc123",
    }})
    assert check_update_pinning(_ctx(cfg)).status == "PASS"


# ---- Mixed: floating wins over pinned ----

def test_b25_mixed_pinned_and_floating_warns():
    cfg = _plugins_entries({
        "good": {"source": "https://example.com/x", "version": "v1.2.3"},
        "bad": {"source": "https://example.com/y", "version": "main"},
    })
    assert check_update_pinning(_ctx(cfg)).status == "WARN"


# ---- Evidence populated on WARN ----

def test_b25_warn_populates_evidence():
    cfg = _plugins_entries({"myplugin": {"source": "https://example.com/x", "version": "latest"}})
    f = check_update_pinning(_ctx(cfg))
    assert f.status == "WARN"
    assert len(f.evidence) >= 1


# ---- Skills namespace also checked ----

def test_b25_skills_floating_ref_warns():
    cfg = _skills_entries({"myskill": {"source": "https://example.com/x", "version": "nightly"}})
    assert check_update_pinning(_ctx(cfg)).status == "WARN"


def test_b25_skills_pinned_passes():
    cfg = _skills_entries({"myskill": {"source": "https://example.com/x", "version": "v3.1.0"}})
    assert check_update_pinning(_ctx(cfg)).status == "PASS"


# ---- Legacy flat shape: <ns>.<name> directly, no `entries` wrapper (B-060) ----
# Previously dropped entirely -> a legacy unpinned plugin silently went UNKNOWN. _plugins
# already tolerates this shape; _iter_entries now does too (structural keys skipped).

def test_b25_legacy_flat_floating_ref_warns():
    cfg = {"plugins": {"my-plugin": {"source": "https://example.com/x", "version": "main"}}}
    f = check_update_pinning(_ctx(cfg))
    assert f.status == "WARN"
    assert len(f.evidence) >= 1


def test_b25_legacy_flat_skills_floating_warns():
    cfg = {"skills": {"my-skill": {"source": "https://example.com/x", "ref": "latest"}}}
    assert check_update_pinning(_ctx(cfg)).status == "WARN"


def test_b25_legacy_flat_pinned_passes():
    cfg = {"plugins": {"my-plugin": {"source": "https://example.com/x", "version": "v1.2.3"}}}
    assert check_update_pinning(_ctx(cfg)).status == "PASS"


def test_b25_legacy_flat_no_source_unknown():
    # legacy entry with no ref info -> still nothing determinable -> UNKNOWN
    cfg = {"plugins": {"my-plugin": {"enabled": True}}}
    assert check_update_pinning(_ctx(cfg)).status == "UNKNOWN"


def test_b25_legacy_structural_keys_not_treated_as_entries():
    # plugins.mcp / plugins.allow are structural config, not installable plugins ->
    # they must NOT be mistaken for unpinned entries (no false WARN).
    cfg = {"plugins": {
        "mcp": {"server": {"url": "https://example.com/mcp"}},
        "allow": ["some-plugin"],
    }}
    assert check_update_pinning(_ctx(cfg)).status == "UNKNOWN"


# ---- C-413: update.channel signal ----
# Grounded (openclaw@2026.9.3): update.channel is
# union(["stable","extended-stable","beta","dev"]).optional() — four literals, not the
# originating task stub's assumed two ("dev"/"beta"). "extended-stable" must NOT be
# swept in as a pre-release tier.

def test_b25_channel_dev_warns_alone():
    cfg = {"update": {"channel": "dev"}}
    f = check_update_pinning(_ctx(cfg))
    assert f.status == "WARN"
    assert "update.channel" in f.detail


def test_b25_channel_beta_warns_alone():
    cfg = {"update": {"channel": "beta"}}
    f = check_update_pinning(_ctx(cfg))
    assert f.status == "WARN"
    assert "update.channel" in f.detail


def test_b25_channel_stable_does_not_warn():
    cfg = {"update": {"channel": "stable"}}
    assert check_update_pinning(_ctx(cfg)).status == "UNKNOWN"  # no entries, no pinning signal either


def test_b25_channel_extended_stable_not_swept_in_as_prerelease():
    cfg = {"update": {"channel": "extended-stable"}}
    assert check_update_pinning(_ctx(cfg)).status == "UNKNOWN"  # not WARN — extended-stable is a safe tier


def test_b25_channel_dev_and_pinned_entries_still_warns():
    cfg = {"update": {"channel": "dev"}}
    cfg.update(_plugins_entries({"myplugin": {"source": "https://example.com/x", "version": "v1.2.3"}}))
    f = check_update_pinning(_ctx(cfg))
    assert f.status == "WARN"
    assert "update.channel" in f.detail
