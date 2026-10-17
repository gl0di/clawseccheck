"""C-742: B158 must not call a present standalone plugin FILE "not present on disk".

OpenClaw documents ``plugins.load.paths`` as "files or directories", and from 2026.10.4 an
enabled manifestless plugin file listed there starts with the Gateway (vendor commit 0f9aceef3).
B158 used to test every entry with ``is_dir`` alone, so an existing file produced the false
sentence "declared but not present on disk". A directory still counts, a missing path of either
kind still warns with the SAME text (the ``detail`` is fingerprinted), and ``skills.load.extraDirs``
names skill roots, so a file there is still not a root.
"""

from __future__ import annotations

import json
import os
import stat

import pytest

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks import check_declared_skill_reconciliation
from clawseccheck.collector import Context, collect


def _ctx(home, cfg):
    c = Context(home=home)
    c.config = cfg
    c.config_found = True
    c.bootstrap = {}
    c.limit_hits = []
    return c


def _paths(*entries):
    return {"plugins": {"load": {"paths": list(entries)}}}


def _missing_line(label, shown):
    return f"{label}: '{shown}' declared but not present on disk"


# ----------------------------------------------------------------- the defect itself
def test_a_present_standalone_plugin_file_is_present(tmp_path):
    policies = tmp_path / "policies"
    policies.mkdir()
    (policies / "maintenance-access.js").write_text(
        "module.exports = { id: 'maintenance-access', register() {} };\n", encoding="utf-8")
    f = check_declared_skill_reconciliation(
        _ctx(tmp_path, _paths("policies/maintenance-access.js")))
    assert f.status == PASS, (f.status, f.detail, f.evidence)
    assert not any("not present on disk" in e for e in (f.evidence or []))


def test_the_pass_wording_names_a_file_only_when_one_was_accepted(tmp_path):
    (tmp_path / "plugins" / "real").mkdir(parents=True)
    (tmp_path / "p.js").write_text("module.exports = {};\n", encoding="utf-8")
    dirs_only = check_declared_skill_reconciliation(_ctx(tmp_path, _paths("plugins/real")))
    with_file = check_declared_skill_reconciliation(_ctx(tmp_path, _paths("plugins/real", "p.js")))
    # configs without a file keep the exact historical sentence (fingerprint rule)
    assert dirs_only.detail == (
        "Every declared skill/plugin load source resolves to a present directory on disk.")
    assert with_file.detail == (
        "Every declared skill/plugin load source resolves to a present directory or file on disk.")


def test_an_absolute_file_entry_is_present_too(tmp_path):
    plugin = tmp_path / "elsewhere" / "tool.ts"
    plugin.parent.mkdir()
    plugin.write_text("export default {};\n", encoding="utf-8")
    f = check_declared_skill_reconciliation(_ctx(tmp_path, _paths(str(plugin))))
    assert f.status == PASS, (f.status, f.detail, f.evidence)


def test_a_missing_file_entry_still_warns_with_the_unchanged_text(tmp_path):
    f = check_declared_skill_reconciliation(
        _ctx(tmp_path, _paths("policies/maintenance-access.js")))
    assert f.status == WARN
    assert _missing_line("plugins.load.paths", "policies/maintenance-access.js") in f.evidence


# ------------------------------------------------- what must not move (fingerprint / scope)
def test_a_directory_entry_is_unchanged(tmp_path):
    (tmp_path / "plugins" / "real").mkdir(parents=True)
    ok = check_declared_skill_reconciliation(_ctx(tmp_path, _paths("plugins/real")))
    gone = check_declared_skill_reconciliation(_ctx(tmp_path, _paths("plugins/ghost")))
    assert ok.status == PASS
    assert gone.status == WARN
    assert _missing_line("plugins.load.paths", "plugins/ghost") in gone.evidence


def test_the_detail_of_a_missing_directory_is_byte_identical_to_a_missing_file(tmp_path):
    """The fingerprint hashes ``detail``; the wording for a missing source must not depend
    on whether the author meant a file or a directory."""
    a = check_declared_skill_reconciliation(_ctx(tmp_path, _paths("plugins/ghost")))
    b = check_declared_skill_reconciliation(_ctx(tmp_path, _paths("plugins/ghost.js")))
    assert a.detail.replace("ghost", "X") == b.detail.replace("ghost.js", "X")


def test_a_file_named_as_an_extra_skill_dir_is_still_not_a_root(tmp_path):
    (tmp_path / "just-a-file").write_text("x", encoding="utf-8")
    f = check_declared_skill_reconciliation(
        _ctx(tmp_path, {"skills": {"load": {"extraDirs": ["just-a-file"]}}}))
    assert f.status == WARN
    assert _missing_line("skills.load.extraDirs", "just-a-file") in f.evidence


def test_one_present_file_does_not_hide_a_missing_neighbour(tmp_path):
    (tmp_path / "a.js").write_text("module.exports = {};\n", encoding="utf-8")
    f = check_declared_skill_reconciliation(_ctx(tmp_path, _paths("a.js", "b.js")))
    assert f.status == WARN
    assert _missing_line("plugins.load.paths", "b.js") in f.evidence
    assert not any("'a.js'" in e for e in f.evidence)


# --------------------------------------------------------------------------- odd shapes
def test_a_symlink_to_a_file_is_present_and_a_dangling_one_is_not(tmp_path):
    target = tmp_path / "real.js"
    target.write_text("module.exports = {};\n", encoding="utf-8")
    (tmp_path / "link.js").symlink_to(target)
    (tmp_path / "dangling.js").symlink_to(tmp_path / "nowhere.js")
    ok = check_declared_skill_reconciliation(_ctx(tmp_path, _paths("link.js")))
    gone = check_declared_skill_reconciliation(_ctx(tmp_path, _paths("dangling.js")))
    assert ok.status == PASS
    assert gone.status == WARN
    assert _missing_line("plugins.load.paths", "dangling.js") in gone.evidence


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs mkfifo")
def test_a_fifo_entry_does_not_hang_or_crash(tmp_path):
    os.mkfifo(tmp_path / "pipe.js")
    assert stat.S_ISFIFO(os.lstat(tmp_path / "pipe.js").st_mode)
    f = check_declared_skill_reconciliation(_ctx(tmp_path, _paths("pipe.js")))
    # not a regular file or a directory: reported with the existing wording, never opened
    assert f.status == WARN
    assert _missing_line("plugins.load.paths", "pipe.js") in f.evidence


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory modes")
def test_an_unreadable_parent_degrades_to_the_existing_warn_not_a_crash(tmp_path):
    sealed = tmp_path / "sealed"
    sealed.mkdir()
    (sealed / "p.js").write_text("module.exports = {};\n", encoding="utf-8")
    sealed.chmod(0)
    try:
        f = check_declared_skill_reconciliation(_ctx(tmp_path, _paths("sealed/p.js")))
    finally:
        sealed.chmod(0o700)
    assert f.status == WARN
    assert _missing_line("plugins.load.paths", "sealed/p.js") in f.evidence


# --------------------------------------------------------------------------------- wiring
def test_through_the_real_collector_on_a_home_with_a_standalone_plugin(tmp_path):
    """Wiring, not the helper: the check is fed by ``collect()`` from an openclaw.json on disk."""
    home = tmp_path / ".openclaw"
    (home / "policies").mkdir(parents=True)
    plugin = home / "policies" / "maintenance-access.js"
    plugin.write_text("module.exports = { id: 'maintenance-access', register() {} };\n",
                      encoding="utf-8")
    cfg = home / "openclaw.json"
    cfg.write_text(json.dumps({
        "plugins": {"load": {"paths": [str(plugin)]},
                    "entries": {"maintenance-access": {"enabled": True}}}}), encoding="utf-8")
    cfg.chmod(0o600)
    f = check_declared_skill_reconciliation(collect(home))
    assert f.status == PASS, (f.status, f.detail, f.evidence)
