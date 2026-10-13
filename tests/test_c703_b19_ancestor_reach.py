"""C-703: B19 must not warn on a loose-mode directory/file that no other user can reach.

A group-writable ``workspace/memory`` (775) sealed under a 0700 OpenClaw home and a 0700
workspace is unreachable: nobody but the owner can traverse to it, so its own mode is not an
exposure (the same path-aware rule B19's transcript leg and C5 already apply). The walk
judges every directory from the OpenClaw home DOWN to the leaf and stops at the home. Only
a directory with NEITHER the group nor the other execute bit blocks the leaf; an ancestor
that cannot be stat'ed, or any symlink on the path, keeps today's WARN (never a new PASS
from an unknown).
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_data_atrest
from clawseccheck.collector import Context

# The existing WARN wording for one loose workspace/memory directory, byte for byte.
_WARN_PREFIX = (
    "Conversation data/PII at rest is group/world-readable (memory/logs, session "
    "transcripts, or install backups): "
)


def _ctx(home: Path) -> Context:
    return Context(home=home, config={})


def _mk(path: Path, mode: int) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)
    return path


def _tree(tmp_path: Path, *, leaf: int, anc: int, name: str = "memory") -> tuple[Path, Path]:
    """<home>/workspace/<name>: *anc* is the mode of BOTH the home and the workspace."""
    home = tmp_path / "oc"
    ws = home / "workspace"
    leaf_dir = ws / name
    _mk(leaf_dir, leaf)
    _mk(ws, anc)
    _mk(home, anc)
    return home, leaf_dir


# ---- the matrix: leaf mode x (home and workspace) mode -------------------------------
@pytest.mark.parametrize("leaf", [0o775, 0o755])
def test_sealed_by_0700_ancestors_passes(tmp_path, leaf):
    home, _ = _tree(tmp_path, leaf=leaf, anc=0o700)
    f = check_data_atrest(_ctx(home))
    assert f.status == PASS, f.detail
    assert "no other user can traverse" in f.detail
    assert "workspace/memory" in f.detail  # says which directory is loose but sealed
    assert f"(mode {oct(leaf)[-3:]})" in f.detail


@pytest.mark.parametrize("leaf", [0o775, 0o755])
@pytest.mark.parametrize("anc", [0o750, 0o755, 0o711])
def test_traversable_ancestors_keep_the_warn(tmp_path, leaf, anc):
    home, _ = _tree(tmp_path, leaf=leaf, anc=anc)
    f = check_data_atrest(_ctx(home))
    assert f.status == WARN, f.detail
    assert f.detail == _WARN_PREFIX + f"workspace/memory (mode {oct(leaf)[-3:]})"
    assert f.evidence == [f"workspace/memory (mode {oct(leaf)[-3:]})"]


@pytest.mark.parametrize("anc", [0o700, 0o750, 0o755, 0o711])
def test_tight_leaf_passes_whatever_the_ancestors(tmp_path, anc):
    home, _ = _tree(tmp_path, leaf=0o700, anc=anc)
    f = check_data_atrest(_ctx(home))
    assert f.status == PASS, f.detail
    assert "no other user can traverse" not in f.detail  # the ordinary PASS text is untouched


@pytest.mark.parametrize(("home_mode", "ws_mode"), [(0o755, 0o700), (0o700, 0o755)])
def test_one_sealing_ancestor_is_enough(tmp_path, home_mode, ws_mode):
    home = tmp_path / "oc"
    _mk(home / "workspace" / "memory", 0o775)
    _mk(home / "workspace", ws_mode)
    _mk(home, home_mode)
    assert check_data_atrest(_ctx(home)).status == PASS


def test_group_traverse_bit_alone_counts_as_reachable(tmp_path):
    # No group-membership engine: a g+x ancestor is conservatively reachable by that group.
    home = tmp_path / "oc"
    _mk(home / "workspace" / "memory", 0o775)
    _mk(home / "workspace", 0o710)
    _mk(home, 0o710)
    assert check_data_atrest(_ctx(home)).status == WARN


# ---- degraded paths: never a new PASS from an unknown ---------------------------------
def test_unstatable_ancestor_keeps_the_warn(tmp_path, monkeypatch):
    home, _ = _tree(tmp_path, leaf=0o775, anc=0o700)
    ws = str(home / "workspace")
    real = os.lstat

    def fake(p, *a, **k):
        if os.fspath(p) == ws:
            raise PermissionError(13, "denied")
        return real(p, *a, **k)

    monkeypatch.setattr(os, "lstat", fake)
    f = check_data_atrest(_ctx(home))
    assert f.status == WARN, f.detail
    assert f.detail == _WARN_PREFIX + "workspace/memory (mode 775)"


def test_unstatable_home_keeps_the_warn(tmp_path, monkeypatch):
    home, _ = _tree(tmp_path, leaf=0o775, anc=0o700)
    real = os.lstat

    def fake(p, *a, **k):
        if os.fspath(p) == str(home):
            raise PermissionError(13, "denied")
        return real(p, *a, **k)

    monkeypatch.setattr(os, "lstat", fake)
    assert check_data_atrest(_ctx(home)).status == WARN


def test_symlinked_workspace_keeps_the_warn(tmp_path):
    # workspace -> a real directory outside the home: the real memory/ is reachable by its own
    # path, so the 0700 home above the symlink proves nothing about it.
    home = tmp_path / "oc"
    real_ws = tmp_path / "elsewhere"
    _mk(real_ws / "memory", 0o775)
    _mk(real_ws, 0o755)
    _mk(home, 0o700)
    (home / "workspace").symlink_to(real_ws)
    f = check_data_atrest(_ctx(home))
    assert f.status == WARN, f.detail
    assert f.detail == _WARN_PREFIX + "workspace/memory (mode 775)"


def test_symlink_below_the_sealing_ancestor_still_counts(tmp_path):
    # The blocker is the HOME; the symlink sits further down. The walk must still see it.
    home = tmp_path / "oc"
    real_ws = tmp_path / "elsewhere"
    _mk(real_ws / "memory", 0o775)
    _mk(home, 0o700)
    (home / "workspace").symlink_to(real_ws)
    assert check_data_atrest(_ctx(home)).status == WARN


def test_symlinked_leaf_keeps_the_warn(tmp_path):
    home = tmp_path / "oc"
    real_mem = tmp_path / "data" / "mem"
    _mk(real_mem, 0o775)
    _mk(home / "workspace", 0o700)
    _mk(home, 0o700)
    (home / "workspace" / "memory").symlink_to(real_mem)
    assert check_data_atrest(_ctx(home)).status == WARN


def test_symlinked_home_keeps_the_warn(tmp_path):
    real_home = tmp_path / "real-oc"
    _mk(real_home / "workspace" / "memory", 0o775)
    _mk(real_home / "workspace", 0o700)
    _mk(real_home, 0o700)
    link = tmp_path / "oc"
    link.symlink_to(real_home)
    assert check_data_atrest(_ctx(link)).status == WARN


def test_no_stores_is_still_unknown(tmp_path):
    home = _mk(tmp_path / "oc", 0o700)
    assert check_data_atrest(_ctx(home)).status == UNKNOWN


# ---- the other loose-mode loci share the rule -----------------------------------------
def test_logs_dir_and_log_file_under_a_0700_home_pass(tmp_path):
    home = _mk(tmp_path / "oc", 0o755)
    _mk(home / "logs", 0o777)
    (home / "gateway.log").write_text("x")
    (home / "gateway.log").chmod(0o644)
    home.chmod(0o755)
    assert check_data_atrest(_ctx(home)).status == WARN  # reachable: today's behaviour
    home.chmod(0o700)
    f = check_data_atrest(_ctx(home))
    assert f.status == PASS, f.detail
    assert "logs (mode 777)" in f.detail and "gateway.log (mode 644)" in f.detail


def test_mixed_home_keeps_the_baseline_detail_and_explains_in_fix(tmp_path):
    # The detail of a WARN that still fires is byte-identical to the pre-C-703 text, sealed
    # entries included (the fingerprint hashes it); the explanation lives in `fix`.
    home = _mk(tmp_path / "oc", 0o755)
    _mk(home / "workspace" / "memory", 0o775)
    _mk(home / "workspace", 0o700)  # memory/ sealed by its own parent
    _mk(home / "logs", 0o777)  # logs/ hangs straight off the traversable home
    home.chmod(0o755)
    f = check_data_atrest(_ctx(home))
    assert f.status == WARN, f.detail
    assert f.detail == _WARN_PREFIX + "workspace/memory (mode 775); logs (mode 777)"
    assert f.evidence == ["workspace/memory (mode 775)", "logs (mode 777)"]
    assert "workspace/memory (mode 775)" in f.fix and "not reachable by other users" in f.fix
    assert "logs (mode 777)" in f.fix  # names what IS exposed


def test_all_reachable_fix_has_no_sealed_note(tmp_path):
    home, _ = _tree(tmp_path, leaf=0o775, anc=0o755)
    f = check_data_atrest(_ctx(home))
    assert f.status == WARN
    assert "not reachable by other users" not in f.fix


def test_only_a_loose_log_file_under_a_0700_home_is_a_sealed_pass_not_unknown(tmp_path):
    # The sole store is a loose *.log directly under a sealed home (no logs/ dir, no
    # workspace): stores exist and none is reachable -> PASS, never "no stores found".
    home = _mk(tmp_path / "oc", 0o700)
    (home / "gateway.log").write_text("x")
    (home / "gateway.log").chmod(0o644)
    f = check_data_atrest(_ctx(home))
    assert f.status == PASS, f.detail
    assert "gateway.log (mode 644)" in f.detail
    assert "no other user can traverse" in f.detail
    assert "No memory/log/transcript stores" not in f.detail
    home.chmod(0o755)
    assert check_data_atrest(_ctx(home)).status == WARN  # same file, open home


def test_hard_linked_log_file_is_not_sealed(tmp_path):
    # A second name for the same inode sits in an open directory: the sealed home proves
    # nothing about it, so the WARN stays.
    open_dir = _mk(tmp_path / "open", 0o755)
    home = _mk(tmp_path / "oc", 0o700)
    _mk(home / "logs", 0o700)
    (open_dir / "gateway.log").write_text("x")
    (open_dir / "gateway.log").chmod(0o644)
    os.link(open_dir / "gateway.log", home / "gateway.log")
    f = check_data_atrest(_ctx(home))
    assert f.status == WARN, f.detail
    assert f.detail == _WARN_PREFIX + "gateway.log (mode 644)"


def test_single_link_log_file_under_a_0700_home_is_still_sealed(tmp_path):
    # Positive control for the hard-link rule: nlink == 1 does not disable the seal.
    home = _mk(tmp_path / "oc", 0o700)
    _mk(home / "logs", 0o700)
    (home / "gateway.log").write_text("x")
    (home / "gateway.log").chmod(0o644)
    assert check_data_atrest(_ctx(home)).status == PASS


def test_sealed_pass_names_what_was_judged_and_the_exact_rule(tmp_path):
    home, _ = _tree(tmp_path, leaf=0o775, anc=0o700)
    f = check_data_atrest(_ctx(home))
    assert f.status == PASS
    assert "workspace/memory (mode 775): " in f.detail
    assert "no other user can traverse to them" in f.detail
    assert "a directory at or above them" in f.detail
    assert "between the OpenClaw home" not in f.detail
    assert "not reachable by other users" not in f.detail  # no blanket claim about transcripts
    assert "no group/other execute bit on a directory at or above them" in f.fix
    assert "stays at 0700" not in f.fix


# ---- mutant killers --------------------------------------------------------------------
def test_other_execute_bit_alone_on_an_ancestor_is_not_sealed(tmp_path):
    home = tmp_path / "oc"
    _mk(home / "workspace" / "memory", 0o775)
    _mk(home / "workspace", 0o701)
    _mk(home, 0o701)
    assert check_data_atrest(_ctx(home)).status == WARN


@pytest.mark.parametrize("leaf", [0o740, 0o640, 0o644])
def test_leaf_mode_alone_never_seals(tmp_path, leaf):
    # A directory leaf with no execute bit for others/group under an OPEN chain is exposed
    # by its parents; the leaf's own missing x must not count as a sealing ancestor.
    home, _ = _tree(tmp_path, leaf=leaf, anc=0o755)
    f = check_data_atrest(_ctx(home))
    assert f.status == WARN, f.detail
    assert f.detail == _WARN_PREFIX + f"workspace/memory (mode {oct(leaf)[-3:]})"


def test_loose_log_file_under_an_open_home_warns(tmp_path):
    # A regular file never has its own x bit; counting the leaf would seal every file.
    home = _mk(tmp_path / "oc", 0o755)
    (home / "gateway.log").write_text("x")
    (home / "gateway.log").chmod(0o644)
    f = check_data_atrest(_ctx(home))
    assert f.status == WARN, f.detail
    assert f.detail == _WARN_PREFIX + "gateway.log (mode 644)"


def test_transcript_leg_is_unchanged(tmp_path):
    # A world-readable transcript in a traversable chain still WARNs; the C-703 walk does not
    # touch the transcript / install-backup judgement (_other_can_reach_read owns it).
    home = _mk(tmp_path / "oc", 0o755)
    t = home / "agents" / "main" / "sessions" / "s1.jsonl"
    _mk(t.parent, 0o755)
    _mk(home / "agents", 0o755)
    t.write_text("{}")
    t.chmod(0o644)
    f = check_data_atrest(_ctx(home))
    assert f.status == WARN, f.detail
    assert "s1.jsonl" in " ".join(f.evidence or [])
