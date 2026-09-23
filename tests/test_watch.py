"""C-517 — continuous ``--watch`` mode (``clawseccheck/watch.py``).

Bounded and fast by construction, per this project's testing discipline for a
long-running loop: every test either calls the loop function directly with a small
``max_cycles``/short debounce, or spawns the real CLI as a subprocess and stops it with
a signal — nothing here sleeps for real wall-clock minutes.

Detection itself is never re-tested here: ``run_watch`` shells out to the SAME
``--monitor`` command ``tests/test_monitor.py`` and ``scripts/monitor_detection_gate.py``
already cover, so the end-to-end test below only has to prove that a real file-system
change reaches that command, once, in the same rendered format.
"""
from __future__ import annotations

import io
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from clawseccheck import watch
from clawseccheck.cli import main

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "fixtures"
HOME_SAFE = FIXTURES / "home_safe"

_ON_LINUX = sys.platform == "linux"


# --------------------------------------------------------------------- inotify probe

def test_probe_inotify_real_on_this_linux_box():
    """Not a platform-name guess: a real syscall attempt. On the CI/dev Linux box this
    must succeed — a permanent False here means the whole test module is only ever
    exercising the poll fallback, which is worth knowing loudly rather than silently."""
    if not _ON_LINUX:
        pytest.skip("inotify is Linux-only")
    assert watch.probe_inotify() is True


def test_probe_inotify_false_when_libc_binding_fails(monkeypatch):
    def _boom():
        raise watch.InotifyUnavailable("simulated")
    monkeypatch.setattr(watch, "_inotify_init", _boom)
    assert watch.probe_inotify() is False


# ------------------------------------------------------------------- bounded dir walk

def test_bounded_watch_dirs_finds_every_real_subdirectory(tmp_path):
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "c").mkdir()
    dirs, capped = watch._bounded_watch_dirs(tmp_path, max_dirs=100)
    assert not capped
    names = {d.relative_to(tmp_path).as_posix() for d in dirs}
    assert names == {".", "a", "a/b", "c"}


def test_bounded_watch_dirs_never_follows_a_symlinked_directory(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real, target_is_directory=True)
    dirs, _capped = watch._bounded_watch_dirs(tmp_path, max_dirs=100)
    assert real in dirs
    assert (tmp_path / "link") not in dirs


def test_bounded_watch_dirs_discloses_a_cap_rather_than_silently_truncating(tmp_path):
    for i in range(10):
        (tmp_path / f"d{i}").mkdir()
    dirs, capped = watch._bounded_watch_dirs(tmp_path, max_dirs=3)
    assert capped is True
    assert len(dirs) == 3


# ------------------------------------------------------------------------ watchers

@pytest.mark.skipif(not _ON_LINUX, reason="inotify is Linux-only")
def test_inotify_watcher_detects_a_file_change(tmp_path):
    w = watch.InotifyWatcher(tmp_path)
    try:
        assert w.mode == "inotify"
        assert w.poll_for_change(0.2) is False  # nothing happened yet
        (tmp_path / "x.txt").write_text("hello\n", encoding="utf-8")
        assert w.poll_for_change(3.0) is True
    finally:
        w.close()


@pytest.mark.skipif(not _ON_LINUX, reason="inotify is Linux-only")
def test_inotify_watcher_notices_a_directory_created_after_start(tmp_path):
    """A subdirectory created after start-up must not be a permanent blind spot —
    it is watched the moment its own IN_CREATE|IN_ISDIR event is drained."""
    w = watch.InotifyWatcher(tmp_path)
    try:
        newdir = tmp_path / "newdir"
        newdir.mkdir()
        assert w.poll_for_change(3.0) is True  # the mkdir itself
        (newdir / "y.txt").write_text("hi\n", encoding="utf-8")
        assert w.poll_for_change(3.0) is True  # a file inside the NEW directory
    finally:
        w.close()


def test_poll_watcher_detects_a_file_change(tmp_path):
    w = watch.PollWatcher(tmp_path, poll_interval_s=0.05)
    assert w.mode == "poll"
    (tmp_path / "x.txt").write_text("hello\n", encoding="utf-8")
    assert w.poll_for_change(0.2) is True
    # A second poll with nothing new must not report a change again.
    assert w.poll_for_change(0.2) is False


def test_make_watcher_prefers_inotify_when_it_works(tmp_path):
    if not _ON_LINUX:
        pytest.skip("inotify is Linux-only")
    w = watch.make_watcher(tmp_path)
    try:
        assert w.mode == "inotify"
    finally:
        w.close()


def test_make_watcher_falls_back_to_poll_when_inotify_construction_fails(tmp_path, monkeypatch):
    def _boom(*_a, **_kw):
        raise OSError("simulated sandbox refusal")
    monkeypatch.setattr(watch, "InotifyWatcher", _boom)
    w = watch.make_watcher(tmp_path, poll_interval_s=0.05)
    try:
        assert w.mode == "poll"
    finally:
        w.close()


# ------------------------------------------------------------------------ heartbeat

def test_read_heartbeat_returns_none_when_absent(tmp_path):
    assert watch.read_heartbeat(tmp_path / "nope.json") is None


def test_write_then_read_heartbeat_round_trips(tmp_path):
    p = tmp_path / "store" / "watch_heartbeat.json"
    watch._write_heartbeat(p, pid=123, status="running", mode="inotify")
    hb = watch.read_heartbeat(p)
    assert hb == {"pid": 123, "status": "running", "mode": "inotify"}
    assert oct(p.stat().st_mode & 0o777) == oct(0o600)


class TestDescribeLiveness:
    def test_none_is_not_running(self):
        word, _sentence = watch.describe_liveness(None)
        assert word == "NOT RUNNING"

    def test_recorded_clean_stop_is_stopped(self):
        word, _s = watch.describe_liveness({
            "status": "stopped", "pid": os.getpid(),
            "updated_at": watch._now_iso(), "heartbeat_interval_s": 30,
        })
        assert word == "STOPPED"

    def test_a_gone_pid_is_stopped_even_without_a_clean_shutdown_record(self):
        # A definitely-dead pid: spawn and wait for a trivial child.
        p = subprocess.Popen([sys.executable, "-c", "pass"])
        dead_pid = p.pid
        p.wait(timeout=10)
        word, _s = watch.describe_liveness({
            "status": "running", "pid": dead_pid,
            "updated_at": watch._now_iso(), "heartbeat_interval_s": 30,
        })
        assert word == "STOPPED"

    def test_an_old_heartbeat_is_stale(self):
        from datetime import datetime, timedelta
        # Naive local time, matching watch._now_iso() (monitorstore._now_iso) exactly —
        # a UTC-aware string here would not reproduce the real code path at all.
        old = (datetime.now() - timedelta(seconds=120)).isoformat(timespec="seconds")
        word, _s = watch.describe_liveness({
            "status": "running", "pid": os.getpid(),
            "updated_at": old, "heartbeat_interval_s": 1,
        })
        assert word == "STALE"

    def test_a_fresh_heartbeat_from_a_live_pid_is_alive(self):
        word, sentence = watch.describe_liveness({
            "status": "running", "pid": os.getpid(), "mode": "inotify", "cycles": 2,
            "updated_at": watch._now_iso(), "heartbeat_interval_s": 30,
        })
        assert word == "ALIVE"
        assert "inotify" in sentence


# --------------------------------------------------------------- run_watch end to end

def _copy_home(tmp_path) -> Path:
    home = tmp_path / "home"
    shutil.copytree(HOME_SAFE, home)  # copy2 preserves the conftest-pinned 0600 modes
    return home


def _seed_baseline(home: Path, store: Path) -> None:
    rc = main(["--monitor", "--home", str(home), "--data-dir", str(store)])
    assert rc == 0, "the baseline run must succeed or nothing below means anything"


def test_run_watch_detects_a_planted_change_within_one_debounce_window(tmp_path, capsys):
    """The end-to-end contract: a real file change reaches a `--monitor --verbose`-
    shaped alert, through whichever mechanism `make_watcher` picked on this machine."""
    home = _copy_home(tmp_path)
    store = tmp_path / "store"
    _seed_baseline(home, store)
    capsys.readouterr()  # discard the baseline run's own output

    buf = io.StringIO()
    result: dict = {}

    def _runner():
        result["rc"] = watch.run_watch(
            home,
            state_path=store / "state.json",
            events_path=store / "events.jsonl",
            history_path=store / "history.jsonl",
            heartbeat_path=store / "watch_heartbeat.json",
            debounce_s=0.3, select_timeout_s=0.1, poll_interval_s=0.1,
            max_cycles=1, install_signal_handlers=False, stream=buf,
        )

    t = threading.Thread(target=_runner, daemon=True)
    t.start()
    time.sleep(0.5)  # let the watcher finish setting up its watches

    cfg_path = home / "openclaw.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    cfg["tools"]["exec"] = {"mode": "auto"}
    cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")  # same inode: mode unchanged

    t.join(timeout=15)
    assert not t.is_alive(), "run_watch did not stop after max_cycles=1"
    assert result.get("rc") == 0

    output = buf.getvalue()
    # The exact alert `--monitor --verbose` renders for this change (see
    # tests/test_monitor.py / monitordims/_execpolicy.py) — proof this is the SAME
    # rendered text, not a re-implementation.
    assert "tools.exec" in output
    assert "auto" in output

    hb = watch.read_heartbeat(store / "watch_heartbeat.json")
    assert hb is not None
    assert hb["cycles"] == 1
    assert hb["status"] == "stopped"
    assert hb["last_scan_rc"] == 0
    # Whether the REAL inotify path (not the poll fallback) was exercised is exactly
    # what this asserts on a Linux CI/dev box — see docs/design/watch-mechanism.md.
    if _ON_LINUX:
        assert hb["mode"] == "inotify"


def test_run_watch_collapses_a_burst_of_writes_into_one_rescan(tmp_path):
    home = _copy_home(tmp_path)
    store = tmp_path / "store"
    _seed_baseline(home, store)

    buf = io.StringIO()
    result: dict = {}

    def _runner():
        result["rc"] = watch.run_watch(
            home,
            state_path=store / "state.json",
            events_path=store / "events.jsonl",
            history_path=store / "history.jsonl",
            heartbeat_path=store / "watch_heartbeat.json",
            debounce_s=0.6, select_timeout_s=0.1, poll_interval_s=0.1,
            max_cycles=1, install_signal_handlers=False, stream=buf,
        )

    t = threading.Thread(target=_runner, daemon=True)
    t.start()
    time.sleep(0.5)

    cfg_path = home / "openclaw.json"
    for i in range(3):
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        cfg["tools"]["exec"] = {"mode": "auto"}
        cfg["_burst"] = i
        cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        time.sleep(0.15)  # well inside the 0.6s debounce window

    t.join(timeout=15)
    assert not t.is_alive()
    hb = watch.read_heartbeat(store / "watch_heartbeat.json")
    assert hb["cycles"] == 1, "a burst inside one debounce window must be ONE re-scan"


def test_run_watch_missing_home_directory_via_cli_returns_1(tmp_path, capsys):
    rc = main(["--watch", "--home", str(tmp_path / "does-not-exist"),
              "--data-dir", str(tmp_path / "store")])
    assert rc == 1
    err = capsys.readouterr().err
    assert "is not a directory" in err


# ------------------------------------------------------- real subprocess: signals

def _wait_for_heartbeat(path: Path, timeout: float = 10.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        hb = watch.read_heartbeat(path)
        if hb is not None:
            return hb
        time.sleep(0.05)
    raise AssertionError(f"no heartbeat appeared at {path} within {timeout}s")


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
def test_watch_subprocess_exits_cleanly_on_signal(tmp_path, sig):
    """The CLI, as a real separate process: proves signal installation actually works
    (not just the in-process stop_event path the other tests use), and that stopping
    it leaves no stale lock behind for the next --monitor run to trip over."""
    home = _copy_home(tmp_path)
    store = tmp_path / "store"
    _seed_baseline(home, store)

    proc = subprocess.Popen(
        [sys.executable, "-m", "clawseccheck", "--watch", "--home", str(home),
         "--data-dir", str(store), "--watch-debounce", "0.3", "--no-deptree", "--no-host"],
        cwd=str(REPO_ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        hb_path = store / "watch_heartbeat.json"
        _wait_for_heartbeat(hb_path)
        proc.send_signal(sig)
        rc = proc.wait(timeout=15)
        assert rc == 0, proc.stdout.read()
    finally:
        if proc.poll() is None:  # pragma: no cover - safety net if an assert fired above
            proc.kill()
            proc.wait(timeout=5)

    hb = watch.read_heartbeat(hb_path)
    assert hb["status"] == "stopped"

    # No leftover lock: a further --monitor run against the same store must succeed.
    rc2 = main(["--monitor", "--home", str(home), "--data-dir", str(store)])
    assert rc2 == 0


# ---------------------------------------------------------------------- --watch-status

def test_watch_status_cli_not_running(tmp_path, capsys):
    rc = main(["--watch-status", "--home", str(HOME_SAFE), "--data-dir", str(tmp_path / "store")])
    assert rc == 1
    assert "NOT RUNNING" in capsys.readouterr().out


def test_watch_status_cli_alive_then_stopped(tmp_path, capsys):
    home = _copy_home(tmp_path)
    store = tmp_path / "store"
    _seed_baseline(home, store)
    capsys.readouterr()

    proc = subprocess.Popen(
        [sys.executable, "-m", "clawseccheck", "--watch", "--home", str(home),
         "--data-dir", str(store), "--watch-debounce", "0.3", "--no-deptree", "--no-host"],
        cwd=str(REPO_ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        hb_path = store / "watch_heartbeat.json"
        _wait_for_heartbeat(hb_path)
        rc = main(["--watch-status", "--home", str(home), "--data-dir", str(store)])
        out = capsys.readouterr().out
        assert rc == 0
        assert "ALIVE" in out
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=15)

    rc2 = main(["--watch-status", "--home", str(home), "--data-dir", str(store)])
    out2 = capsys.readouterr().out
    assert rc2 == 1
    assert "STOPPED" in out2
