"""B25 — Update / pinning hygiene tests.

Conservative philosophy: WARN only on positive evidence (auto-update true,
or a floating ref/branch); PASS when pinned entries are present; UNKNOWN when
nothing determinable.
"""
from pathlib import Path

from clawcheck.checks import check_update_pinning
from clawcheck.collector import Context


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


# ---- WARN: auto-update enabled ----

def test_b25_auto_update_enabled_true_warns():
    cfg = {"update": {"auto": {"enabled": True}}}
    f = check_update_pinning(_ctx(cfg))
    assert f.status == "WARN"
    assert "auto-update" in f.detail.lower()


def test_b25_update_auto_true_warns():
    cfg = {"update": {"auto": True}}
    f = check_update_pinning(_ctx(cfg))
    assert f.status == "WARN"
    assert "auto-update" in f.detail.lower()


def test_b25_autoupdate_key_warns():
    cfg = {"autoUpdate": True}
    f = check_update_pinning(_ctx(cfg))
    assert f.status == "WARN"


def test_b25_auto_update_string_true_warns():
    cfg = {"autoUpdate": "true"}
    assert check_update_pinning(_ctx(cfg)).status == "WARN"


def test_b25_auto_update_false_does_not_warn():
    # explicitly disabled — no entries to check -> UNKNOWN (not WARN)
    cfg = {"update": {"auto": {"enabled": False}}}
    assert check_update_pinning(_ctx(cfg)).status == "UNKNOWN"


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
