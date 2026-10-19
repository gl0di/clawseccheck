"""C-742: B158 must not call a present standalone plugin FILE "not present on disk" - and must
not go quiet about it either.

OpenClaw documents ``plugins.load.paths`` as "files or directories", and from 2026.10.4 an
enabled manifestless plugin file listed there starts with the Gateway (vendor commit 0f9aceef3).
B158 used to test every entry with ``is_dir`` alone, so an existing file produced the false
sentence "declared but not present on disk".

The first version of this fix turned that WARN into a PASS. A security review of the commit
pointed out what that did: this audit reads NO plugin code, so B158's WARN was the only signal
that an unscanned source loads, and a PASS removed it (fail-open coverage regression). The rule
now: a present file is not MISSING, but it is not AUDITED either, so it keeps a WARN with a true
sentence. A missing path of either kind keeps its old text (the ``detail`` is fingerprinted), and
``skills.load.extraDirs``, which names skill roots, still needs a directory.
"""

from __future__ import annotations

import json
import os
import stat

import pytest

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks import check_declared_skill_reconciliation
from clawseccheck.collector import Context, collect

UNREAD = "does not read plugin code"
MISSING = "not present on disk"


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


def _unread_line(shown):
    return (f"plugins.load.paths: '{shown}' is a plugin file - present on disk, "
            "but this audit does not read plugin code")


def _write(path, text="module.exports = { id: 'x', register() {} };\n"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# ----------------------------------------------------------------- the defect itself
def test_a_present_plugin_file_is_not_called_missing_and_is_not_called_audited(tmp_path):
    _write(tmp_path / "policies" / "maintenance-access.js")
    f = check_declared_skill_reconciliation(
        _ctx(tmp_path, _paths("policies/maintenance-access.js")))
    assert f.status == WARN, (f.status, f.detail)           # NOT a PASS: nothing reads this code
    assert MISSING not in f.detail and MISSING not in " ".join(f.evidence or [])
    assert UNREAD in f.detail
    assert _unread_line("policies/maintenance-access.js") in f.evidence
    assert "unaudited" in f.detail


def test_an_absolute_file_entry_gets_the_same_honest_row(tmp_path):
    plugin = tmp_path / "elsewhere" / "tool.ts"
    _write(plugin, "export default {};\n")
    f = check_declared_skill_reconciliation(_ctx(tmp_path, _paths(str(plugin))))
    assert f.status == WARN
    assert UNREAD in f.detail and MISSING not in f.detail


def test_a_missing_file_entry_still_warns_with_the_unchanged_text(tmp_path):
    f = check_declared_skill_reconciliation(
        _ctx(tmp_path, _paths("policies/maintenance-access.js")))
    assert f.status == WARN
    assert _missing_line("plugins.load.paths", "policies/maintenance-access.js") in f.evidence
    assert UNREAD not in f.detail


# ------------------------------------------------- what must not move (fingerprint / scope)
def test_a_directory_entry_is_unchanged(tmp_path):
    (tmp_path / "plugins" / "real").mkdir(parents=True)
    ok = check_declared_skill_reconciliation(_ctx(tmp_path, _paths("plugins/real")))
    gone = check_declared_skill_reconciliation(_ctx(tmp_path, _paths("plugins/ghost")))
    assert ok.status == PASS
    assert ok.detail == (
        "Every declared skill/plugin load source resolves to a present directory on disk.")
    assert gone.status == WARN
    assert _missing_line("plugins.load.paths", "plugins/ghost") in gone.evidence


def test_the_detail_with_a_missing_path_is_byte_identical_whether_or_not_a_file_is_listed(tmp_path):
    """The fingerprint hashes ``detail``. Adding a present file next to a missing path must not
    change it; the file's row travels in ``evidence`` only."""
    _write(tmp_path / "a.js")
    only_missing = check_declared_skill_reconciliation(_ctx(tmp_path, _paths("b.js")))
    both = check_declared_skill_reconciliation(_ctx(tmp_path, _paths("a.js", "b.js")))
    assert both.status == WARN and only_missing.status == WARN
    assert both.detail == only_missing.detail
    assert _missing_line("plugins.load.paths", "b.js") in both.evidence
    assert _unread_line("a.js") in both.evidence


def test_a_file_named_as_an_extra_skill_dir_is_still_a_miss_not_an_unread_file(tmp_path):
    (tmp_path / "just-a-file").write_text("x", encoding="utf-8")
    f = check_declared_skill_reconciliation(
        _ctx(tmp_path, {"skills": {"load": {"extraDirs": ["just-a-file"]}}}))
    assert f.status == WARN
    assert _missing_line("skills.load.extraDirs", "just-a-file") in f.evidence
    assert UNREAD not in f.detail


def test_a_directory_next_to_a_file_keeps_the_file_row(tmp_path):
    (tmp_path / "plugins" / "real").mkdir(parents=True)
    _write(tmp_path / "p.js")
    f = check_declared_skill_reconciliation(_ctx(tmp_path, _paths("plugins/real", "p.js")))
    assert f.status == WARN                                   # never a PASS while a file loads
    assert _unread_line("p.js") in f.evidence
    assert not any("plugins/real" in e for e in f.evidence)


# --------------------------------------------------------------------------- odd shapes
def test_a_symlink_to_a_file_is_an_unread_file_and_a_dangling_one_is_missing(tmp_path):
    target = tmp_path / "real.js"
    _write(target)
    (tmp_path / "link.js").symlink_to(target)
    (tmp_path / "dangling.js").symlink_to(tmp_path / "nowhere.js")
    linked = check_declared_skill_reconciliation(_ctx(tmp_path, _paths("link.js")))
    dangling = check_declared_skill_reconciliation(_ctx(tmp_path, _paths("dangling.js")))
    assert linked.status == WARN and UNREAD in linked.detail and MISSING not in linked.detail
    assert dangling.status == WARN
    assert _missing_line("plugins.load.paths", "dangling.js") in dangling.evidence


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
    _write(sealed / "p.js")
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
    plugin = home / "policies" / "maintenance-access.js"
    _write(plugin, "module.exports = { id: 'maintenance-access', register() {} };\n")
    cfg = home / "openclaw.json"
    cfg.write_text(json.dumps({
        "plugins": {"load": {"paths": [str(plugin)]},
                    "entries": {"maintenance-access": {"enabled": True}}}}), encoding="utf-8")
    cfg.chmod(0o600)
    f = check_declared_skill_reconciliation(collect(home))
    assert f.status == WARN, (f.status, f.detail, f.evidence)
    assert UNREAD in f.detail and MISSING not in f.detail
