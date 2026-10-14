"""C-734: ``--watch`` went deaf below the first level of a directory tree that appeared
after start-up.

``mkdir -p workspace/skills/new/scripts`` (or a ``cp -r`` / ``mv`` of a whole skill)
delivers ONE inotify event, for the top directory that is new. The watcher added a watch for
that directory only, so every directory already below it - ``skills``, ``new``, ``scripts`` -
never got one and later changes there were never seen. Found by the monitor/watch tester: a
first change was detected, a second batch of installs five seconds later was not.

The watcher now walks the new tree (bounded by the start-up cap, never following a symlink)
and also handles a directory MOVED into the tree.

Offline, read-only outside tmp_path, stdlib only. inotify is Linux-only, as in test_watch.py.
"""
from __future__ import annotations

import os
import sys

import pytest

from clawseccheck import watch

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"),
                                reason="inotify is Linux-only")


def _watcher(root, **kw):
    w = watch.InotifyWatcher(root, **kw)
    assert w.poll_for_change(0.1) is False        # nothing has happened yet
    return w


def _watched(w, root):
    return sorted(str(p.relative_to(root.resolve())) or "." for p in w._wd_to_path.values())


def test_a_nested_tree_created_at_once_is_watched_all_the_way_down(tmp_path):
    w = _watcher(tmp_path)
    try:
        scripts = tmp_path / "workspace" / "skills" / "new" / "scripts"
        scripts.mkdir(parents=True)
        (scripts / "run.sh").write_text("echo hi\n", encoding="utf-8")
        assert w.poll_for_change(3.0) is True                         # the creation itself
        assert _watched(w, tmp_path) == [
            ".", "workspace", "workspace/skills", "workspace/skills/new",
            "workspace/skills/new/scripts"]
        (scripts / "run.sh").write_text("echo changed\n", encoding="utf-8")
        assert w.poll_for_change(3.0) is True                         # a file at depth 4
        (tmp_path / "workspace" / "skills" / "second").mkdir()
        assert w.poll_for_change(3.0) is True                         # a sibling, one level up
    finally:
        w.close()


def test_a_tree_moved_into_the_watched_home_is_watched_too(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    staging = tmp_path / "staging" / "skill" / "references"
    staging.mkdir(parents=True)
    w = _watcher(home)
    try:
        os.rename(tmp_path / "staging" / "skill", home / "skill")
        assert w.poll_for_change(3.0) is True                         # IN_MOVED_TO | IN_ISDIR
        assert _watched(w, home) == [".", "skill", "skill/references"]
        (home / "skill" / "references" / "note.md").write_text("x\n", encoding="utf-8")
        assert w.poll_for_change(3.0) is True
    finally:
        w.close()


def test_a_symlinked_directory_is_never_followed(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    outside = tmp_path / "outside" / "deep"
    outside.mkdir(parents=True)
    w = _watcher(home)
    try:
        (home / "link").symlink_to(tmp_path / "outside", target_is_directory=True)
        w.poll_for_change(1.0)
        assert _watched(w, home) == ["."]
        (outside / "x.txt").write_text("x\n", encoding="utf-8")
        assert w.poll_for_change(0.5) is False
    finally:
        w.close()


def test_a_new_tree_past_the_cap_is_disclosed_not_silently_partial(tmp_path):
    w = _watcher(tmp_path, max_dirs=3)
    try:
        assert w.capped is False
        (tmp_path / "a" / "b" / "c" / "d").mkdir(parents=True)
        assert w.poll_for_change(3.0) is True
        assert w.capped is True                  # the heartbeat's watch_dirs_capped
        assert len(w._wd_to_path) <= 3
    finally:
        w.close()


def test_a_directory_deleted_after_its_event_does_not_break_the_walk(tmp_path):
    w = _watcher(tmp_path)
    try:
        gone = tmp_path / "gone" / "inner"
        gone.mkdir(parents=True)
        (tmp_path / "gone").rename(tmp_path / "gone2")       # the path in the event no longer exists
        assert w.poll_for_change(3.0) is True
        (tmp_path / "later").mkdir()
        assert w.poll_for_change(3.0) is True
    finally:
        w.close()
