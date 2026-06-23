"""Symlink / TOCTOU safety for ClawSecCheck's own ~/.clawseccheck writes (B-007).

A local attacker (or a lost first-run race) could pre-plant a symlink at one of
the state/history paths and turn the next default/--monitor/--trend write into an
arbitrary-file overwrite as the invoking user.  These tests prove the writes now
refuse to follow a symlinked target and never clobber the victim.

All offline; writes confined to pytest tmp_path.
"""
from __future__ import annotations

import os

import pytest

from clawseccheck.history import record
from clawseccheck.monitor import record_events, save_state

posix_only = pytest.mark.skipif(os.name != "posix", reason="O_NOFOLLOW/symlink is POSIX-only")


class _Score:
    score = 80
    grade = "B"


@posix_only
def test_history_record_refuses_symlinked_target(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("precious", encoding="utf-8")
    store = tmp_path / "store"
    store.mkdir()
    target = store / "history.jsonl"
    os.symlink(victim, target)

    # record() degrades quietly (best-effort, runs on every audit) — must not raise.
    record(_Score(), path=str(target), when="2026-06-23")

    # The victim file must be untouched: the write was refused, not redirected.
    assert victim.read_text(encoding="utf-8") == "precious"


@posix_only
def test_save_state_refuses_symlinked_target(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("precious", encoding="utf-8")
    store = tmp_path / "store"
    store.mkdir()
    target = store / "state.json"
    os.symlink(victim, target)

    with pytest.raises(OSError):
        save_state(target, {"hello": "world"})

    assert victim.read_text(encoding="utf-8") == "precious"


@posix_only
def test_record_events_refuses_symlinked_target(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("precious", encoding="utf-8")
    store = tmp_path / "store"
    store.mkdir()
    target = store / "events.jsonl"
    os.symlink(victim, target)

    # record_events swallows OSError internally — must not raise, must not clobber.
    record_events([("WARN", "drift detected")], path=target, when="2026-06-23T00:00:00")

    assert victim.read_text(encoding="utf-8") == "precious"


@posix_only
def test_history_dir_created_owner_only(tmp_path):
    """The state dir is created 0700 at creation (no world-readable umask window)."""
    target = tmp_path / "fresh" / "history.jsonl"
    record(_Score(), path=str(target), when="2026-06-23")
    mode = target.parent.stat().st_mode & 0o777
    assert mode == 0o700
    assert target.stat().st_mode & 0o777 == 0o600
