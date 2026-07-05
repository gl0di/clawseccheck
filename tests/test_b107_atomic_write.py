"""B-107 — secure_write_text must be atomic (temp + fsync + os.replace).

The old writer opened the destination O_TRUNC and wrote in place: a crash / power loss /
ENOSPC mid-write left a truncated, corrupt file. For the monitor's state.json a corrupt
read is swallowed as "no state", silently resetting the baseline to first-run and hiding
real config drift — a security monitor reporting "all clear" after losing its own state.

These tests pin the atomic behaviour: a reader never sees a partial file, no stray temp is
left behind, a planted symlink at the destination is replaced (never written through), and
the original file survives a failed replace. Offline, read-only of the tmp_path sandbox,
stdlib only.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from clawseccheck.safeio import secure_write_text


def _siblings(p: Path) -> list[str]:
    return sorted(c.name for c in p.parent.iterdir())


def test_writes_content_and_leaves_no_temp(tmp_path):
    dest = tmp_path / "state.json"
    secure_write_text(dest, '{"a": 1}')
    assert dest.read_text() == '{"a": 1}'
    assert _siblings(dest) == ["state.json"], f"stray files: {_siblings(dest)}"


def test_overwrite_is_clean(tmp_path):
    dest = tmp_path / "state.json"
    secure_write_text(dest, "first")
    secure_write_text(dest, "second-longer-content")
    assert dest.read_text() == "second-longer-content"
    assert _siblings(dest) == ["state.json"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_mode_is_owner_only(tmp_path):
    dest = tmp_path / "state.json"
    secure_write_text(dest, "x")
    assert (dest.stat().st_mode & 0o777) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="symlink semantics")
def test_symlink_at_dest_is_refused_and_victim_untouched(tmp_path):
    # An attacker plants a symlink at our destination pointing at a file outside the store.
    # The B-007 contract: refuse (raise) and never clobber the victim. The atomicity work
    # keeps that refusal; os.replace is also a backstop that never writes through a symlink.
    outside = tmp_path / "outside.txt"
    outside.write_text("SECRET-UNTOUCHED")
    dest = tmp_path / "state.json"
    dest.symlink_to(outside)

    with pytest.raises(OSError):
        secure_write_text(dest, "our-new-state")

    assert outside.read_text() == "SECRET-UNTOUCHED"  # victim untouched
    assert _siblings(dest) == ["outside.txt", "state.json"], f"stray files: {_siblings(dest)}"


def test_failed_replace_keeps_original_and_no_temp(tmp_path, monkeypatch):
    dest = tmp_path / "state.json"
    secure_write_text(dest, "original")

    def _boom(src, dst):
        raise OSError("simulated crash during replace")

    monkeypatch.setattr(os, "replace", _boom)
    with pytest.raises(OSError):
        secure_write_text(dest, "new-content-that-fails")

    # Original file intact (never truncated), and the temp was cleaned up.
    assert dest.read_text() == "original"
    assert _siblings(dest) == ["state.json"], f"stray files: {_siblings(dest)}"


def test_partial_write_never_visible_at_dest(tmp_path, monkeypatch):
    # Simulate a crash *during* the byte write: os.write raises. The destination must not
    # exist yet / must keep its previous content — the temp path absorbed the partial write.
    dest = tmp_path / "state.json"
    secure_write_text(dest, "good-baseline")

    real_write = os.write

    def _partial(fd, data):
        real_write(fd, data[: len(data) // 2])  # write half …
        raise OSError("simulated crash mid-write")  # … then die

    monkeypatch.setattr(os, "write", _partial)
    with pytest.raises(OSError):
        secure_write_text(dest, "this-should-never-be-half-written")

    monkeypatch.undo()
    # The old baseline is still the only complete file readers can see.
    assert dest.read_text() == "good-baseline"
    assert _siblings(dest) == ["state.json"], f"stray files: {_siblings(dest)}"


def test_monitor_state_roundtrip(tmp_path):
    # Integration: the monitor's own save/load cycle still works over the atomic writer.
    from clawseccheck import monitor

    state_path = tmp_path / "state.json"
    snap = {"schema": 2, "skills": {"a": {"hash": "deadbeef", "caps": [], "version": "1"}}}
    monitor.save_state(state_path, snap)
    assert monitor.load_state(state_path) == snap
