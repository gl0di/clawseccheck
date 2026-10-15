"""C-725 - ``--watch`` must be able to re-scan however it was started, must announce a
failed re-scan, must not let a second watcher corrupt the first one's status, and must
report a heartbeat it cannot trust as exactly that.

Everything that starts a process stops it in ``finally`` (terminate, then a bounded wait,
then kill) and every wait has a hard timeout. Homes and stores live under ``tmp_path``.
"""
from __future__ import annotations

import fcntl
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
HOME_SAFE = REPO_ROOT / "fixtures" / "home_safe"
AUDIT_PY = REPO_ROOT / "audit.py"

# Keep every nested --monitor fast and hermetic (no npm walk, no host scan).
_OPT_OUT = ["--no-native", "--no-host", "--no-sockets", "--no-deptree", "--no-dist"]


def _copy_home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    shutil.copytree(HOME_SAFE, home)  # copy2 keeps the conftest-pinned 0600 modes
    return home


def _seed_baseline(home: Path, store: Path) -> None:
    rc = main(["--monitor", "--home", str(home), "--data-dir", str(store), *_OPT_OUT])
    assert rc == 0, "the baseline run must succeed or nothing below means anything"


def _plant_change(home: Path) -> None:
    cfg_path = home / "openclaw.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    cfg["tools"]["exec"] = {"mode": "auto"}
    cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def _wait_for(predicate, timeout: float, what: str):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.1)
    raise AssertionError(f"timed out after {timeout}s waiting for {what}")


def _stop(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:  # pragma: no cover - safety net
            proc.kill()
            proc.wait(timeout=5)


def _event_lines(store: Path) -> int:
    p = store / "events.jsonl"
    return len(p.read_text(encoding="utf-8").splitlines()) if p.is_file() else 0


def _drive_watch(tmp_path: Path, head: list, *, cwd: Path, env: "dict | None") -> str:
    """Start ``--watch`` with *head* from *cwd*, plant one change, return the watcher's
    own output once it has re-scanned. Fails if the re-scan did not work."""
    home = _copy_home(tmp_path)
    store = tmp_path / "store"
    _seed_baseline(home, store)
    before = _event_lines(store)
    cwd.mkdir(parents=True, exist_ok=True)
    out_path = tmp_path / "watch.out"
    with open(out_path, "w", encoding="utf-8") as out_f:
        proc = subprocess.Popen(
            [sys.executable, *head, "--watch", "--home", str(home), "--data-dir", str(store),
             # _OPT_OUT spelled out: the hermeticity guards read literals, not names
             "--watch-debounce", "0.3", "--no-native", "--no-host", "--no-sockets",
             "--no-deptree", "--no-dist"],
            cwd=str(cwd), env=env, stdout=out_f, stderr=subprocess.STDOUT, text=True,
        )
        try:
            _wait_for(lambda: watch.read_heartbeat(store / "watch_heartbeat.json"), 15,
                      "the watcher heartbeat")
            _plant_change(home)
            _wait_for(lambda: "change detected" in out_path.read_text(encoding="utf-8"), 40,
                      "the watcher to report a re-scan")
        finally:
            _stop(proc)
    text = out_path.read_text(encoding="utf-8")
    assert "No module named" not in text, text
    assert "RE-SCAN FAILED" not in text, text
    assert "(rc=0)" in text or "(rc=3)" in text, text
    assert "tools.exec" in text, text
    assert _event_lines(store) > before, "the re-scan wrote nothing to the events journal"
    return text


# ------------------------------------------------------------ item 1: the child's import


def test_rescan_works_when_started_through_audit_py_from_another_directory(tmp_path):
    """The documented skill entry point, started from a directory that does NOT hold the
    package. Before the fix the nested `python -m clawseccheck` could not import it."""
    _drive_watch(tmp_path, [str(AUDIT_PY)], cwd=tmp_path / "elsewhere", env=None)


def test_rescan_works_when_started_with_dash_m_and_the_package_on_pythonpath(tmp_path):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT) + (os.pathsep + env["PYTHONPATH"]
                                           if env.get("PYTHONPATH") else "")
    _drive_watch(tmp_path, ["-m", "clawseccheck"], cwd=tmp_path / "elsewhere", env=env)


def test_the_child_launch_ignores_a_decoy_package_in_the_working_directory(tmp_path):
    """The child must import THIS package, never one that merely sits in its cwd."""
    decoy_cwd = tmp_path / "decoy_cwd"
    (decoy_cwd / "clawseccheck").mkdir(parents=True)
    marker = tmp_path / "decoy_was_imported"
    (decoy_cwd / "clawseccheck" / "__init__.py").write_text(
        f"open({str(marker)!r}, 'w').close()\nraise SystemExit(97)\n", encoding="utf-8")
    entry, env = watch._child_launch()
    r = subprocess.run([sys.executable, *entry, "--version"], cwd=str(decoy_cwd), env=env,
                       capture_output=True, text=True, timeout=60)
    assert not marker.exists(), "the child imported the package sitting in its cwd"
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)


def test_the_child_launch_follows_how_the_parent_was_started(monkeypatch):
    """Started as the bundled shim -> the child is the shim (its stray-file refusal then
    protects the child too); any other start -> `-m clawseccheck` with this package's
    own parent directory first on PYTHONPATH and the cwd kept off sys.path."""
    monkeypatch.setattr(sys, "argv", [str(AUDIT_PY), "--watch"])
    entry, env = watch._child_launch()
    assert entry == [str(AUDIT_PY)]
    monkeypatch.setattr(sys, "argv", ["pytest", "-q"])
    entry, env = watch._child_launch()
    assert entry == ["-m", "clawseccheck"]
    assert env["PYTHONPATH"].split(os.pathsep)[0] == str(REPO_ROOT)
    assert env["PYTHONSAFEPATH"] == "1"


# ------------------------------------------------- item 1: a failed re-scan is announced


def _run_watch_in_thread(home, store, *, stream, max_cycles, **kw):
    result: dict = {}

    def _runner():
        result["rc"] = watch.run_watch(
            home, state_path=store / "state.json", events_path=store / "events.jsonl",
            history_path=store / "history.jsonl",
            heartbeat_path=store / "watch_heartbeat.json",
            debounce_s=0.3, select_timeout_s=0.1, poll_interval_s=0.1,
            max_cycles=max_cycles, install_signal_handlers=False, stream=stream, **kw)

    t = threading.Thread(target=_runner, daemon=True)
    t.start()
    time.sleep(0.5)
    return t, result


def test_a_rescan_that_cannot_run_is_announced_loudly_with_its_reason(tmp_path):
    home = _copy_home(tmp_path)
    store = tmp_path / "store"
    _seed_baseline(home, store)
    buf = io.StringIO()
    t, result = _run_watch_in_thread(
        home, store, stream=buf, max_cycles=1,
        extra_monitor_args=("--definitely-not-a-flag",))
    _plant_change(home)
    t.join(timeout=60)
    assert not t.is_alive()
    text = buf.getvalue()
    assert text.count("RE-SCAN FAILED") == 1, text
    assert "definitely-not-a-flag" in text, "the child's own reason must be shown"
    assert "did not complete" in text and "still watching" in text, text
    assert "NOT been checked" not in text, "the block must not claim nothing was checked"
    assert "no change" not in text.lower(), text
    hb = watch.read_heartbeat(store / "watch_heartbeat.json")
    assert hb["last_scan_rc"] not in (0, 3, None)


def test_the_watch_keeps_watching_after_a_failed_rescan(tmp_path, monkeypatch):
    home = _copy_home(tmp_path)
    store = tmp_path / "store"
    results = iter([(1, "boom: store is read-only\n"), (3, "ALERT tools.exec\n")])
    monkeypatch.setattr(watch, "_run_monitor_once", lambda *a, **k: next(results))
    buf = io.StringIO()
    t, result = _run_watch_in_thread(home, store, stream=buf, max_cycles=2)
    for _ in range(2):
        (home / "poke.txt").write_text(str(time.monotonic()), encoding="utf-8")
        time.sleep(1.2)
    t.join(timeout=20)
    assert not t.is_alive()
    text = buf.getvalue()
    assert text.count("RE-SCAN FAILED") == 1, text
    assert "boom: store is read-only" in text
    assert "ALERT tools.exec" in text and "(rc=3)" in text
    assert watch.read_heartbeat(store / "watch_heartbeat.json")["cycles"] == 2


def test_a_missing_interpreter_is_a_failed_rescan_not_a_crash(monkeypatch, tmp_path):
    def _boom(*a, **k):
        raise FileNotFoundError(2, "No such file or directory", "python-gone")
    monkeypatch.setattr(subprocess, "run", _boom)
    rc, text = watch._run_monitor_once(tmp_path, "s", "e", "h")
    assert rc != 0 and "could not run the re-scan" in text


# --------------------------------------------------------- item 2: a second watcher


def _start_cli_watch(tmp_path: Path, home: Path, store: Path, name: str):
    out_path = tmp_path / f"{name}.out"
    out_f = open(out_path, "w", encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-m", "clawseccheck", "--watch", "--home", str(home),
         "--data-dir", str(store), "--watch-debounce", "0.3", *_OPT_OUT],
        cwd=str(REPO_ROOT), stdout=out_f, stderr=subprocess.STDOUT, text=True)
    return proc, out_path, out_f


def test_a_second_watch_on_a_live_store_is_refused_and_the_first_stays_truthful(tmp_path):
    home = _copy_home(tmp_path)
    store = tmp_path / "store"
    _seed_baseline(home, store)
    hb_path = store / "watch_heartbeat.json"
    first, _o1, f1 = _start_cli_watch(tmp_path, home, store, "w1")
    second = None
    try:
        hb1 = _wait_for(lambda: watch.read_heartbeat(hb_path), 15, "the first heartbeat")
        second, o2, f2 = _start_cli_watch(tmp_path, home, store, "w2")
        try:
            rc2 = second.wait(timeout=30)
        finally:
            f2.close()
        text2 = o2.read_text(encoding="utf-8")
        assert rc2 != 0, text2
        assert "holds this store's lock" in text2, text2
        assert watch.read_heartbeat(hb_path)["pid"] == first.pid == hb1["pid"]
        assert first.poll() is None, "the refused start must not touch the first watcher"
        status = subprocess.run(
            [sys.executable, "-m", "clawseccheck", "--watch-status", "--home", str(home),
             "--data-dir", str(store), "--no-deptree", "--no-host"], cwd=str(REPO_ROOT),
            capture_output=True, text=True, timeout=60)
        assert status.stdout.startswith("ALIVE"), status.stdout
    finally:
        if second is not None:
            _stop(second)
        _stop(first)
        f1.close()


def test_a_stale_record_is_replaced_and_the_start_says_so(tmp_path):
    dead = subprocess.Popen([sys.executable, "-c", "pass"])
    dead.wait(timeout=10)
    store = tmp_path / "store"
    hb_path = store / "watch_heartbeat.json"
    watch._write_heartbeat(hb_path, pid=dead.pid, status="running", mode="inotify",
                           updated_at=watch._now_iso())
    buf = io.StringIO()
    rc = watch.run_watch(_copy_home(tmp_path), state_path=store / "s.json",
                         events_path=store / "e.jsonl", history_path=store / "h.jsonl",
                         heartbeat_path=hb_path, max_cycles=0, install_signal_handlers=False,
                         stream=buf)
    assert rc == 0
    assert "stale" in buf.getvalue().lower() and str(dead.pid) in buf.getvalue()
    assert watch.read_heartbeat(hb_path)["pid"] == os.getpid()


def test_a_live_pid_that_is_not_a_watcher_does_not_block_a_start(tmp_path, monkeypatch):
    store = tmp_path / "store"
    hb_path = store / "watch_heartbeat.json"
    watch._write_heartbeat(hb_path, pid=os.getpid(), status="running", mode="inotify",
                           updated_at=watch._now_iso())
    monkeypatch.setattr(watch, "_pid_is_watcher", lambda pid: False)
    rc = watch.run_watch(_copy_home(tmp_path), state_path=store / "s.json",
                         events_path=store / "e.jsonl", history_path=store / "h.jsonl",
                         heartbeat_path=hb_path, max_cycles=0, install_signal_handlers=False,
                         stream=io.StringIO())
    assert rc == 0


# ------------------------------------------------------ item 3: --watch-status honesty


@pytest.mark.parametrize("bad_pid", [0, -1, 1])
def test_a_pid_that_cannot_be_a_watcher_is_a_stale_record_not_alive(bad_pid):
    hb = {"status": "running", "pid": bad_pid, "mode": "inotify",
          "updated_at": watch._now_iso(), "heartbeat_interval_s": 30}
    word, sentence = watch.describe_liveness(hb, None, "free")
    assert word == "STALE RECORD", (word, sentence)
    word, sentence = watch.describe_liveness(hb, None, "held")
    assert word == "LOCK HELD", "a held lock whose heartbeat names a non-process is no bare ALIVE"


@pytest.mark.parametrize("bad_pid", [True, "12", None, 10 ** 30, 1.5])
def test_a_pid_of_the_wrong_type_or_range_is_a_corrupt_record(bad_pid):
    word, sentence = watch.describe_liveness({
        "status": "running", "pid": bad_pid, "mode": "inotify",
        "updated_at": watch._now_iso(), "heartbeat_interval_s": 30}, None, "free")
    assert word == "UNREADABLE" and "corrupt" in sentence, (word, sentence)


@pytest.mark.parametrize("argv,expected", [
    (["/usr/bin/python3", "-m", "clawseccheck", "--watch", "--home", "/h"], True),
    (["python3", "/x/skills/clawseccheck/audit.py", "--watch"], True),
    (["python3", "/x/other-dir/audit.py", "--watch", "--home", "/h"], True),
    (["/home/u/.local/bin/clawseccheck", "--watch"], True),
    (["python3", "-m", "clawseccheck", "--watch-status"], False),
    (["python3", "-m", "clawseccheck", "--monitor"], False),
    (["vim", "--watch", "notes.txt"], False),
    (["python3", "-m", "pytest", "-q"], False),
    ([], False),
])
def test_the_cmdline_identity_rule(argv, expected):
    assert watch._cmdline_is_watcher(argv) is expected


def test_pid_is_watcher_reads_proc_on_linux_and_is_false_for_this_test_process():
    if not (sys.platform == "linux" and Path("/proc/self/cmdline").is_file()):
        assert watch._pid_is_watcher(os.getpid()) is None
        return
    assert watch._pid_is_watcher(os.getpid()) is False  # pytest, not a --watch process
    assert watch._pid_is_watcher(2 ** 22 + 12345) is False  # no such process


def test_a_corrupt_heartbeat_is_reported_as_unreadable_not_as_never_run(tmp_path, capsys):
    store = tmp_path / "store"
    store.mkdir()
    (store / "watch_heartbeat.json").write_text("{not json", encoding="utf-8")
    rc = main(["--watch-status", "--home", str(HOME_SAFE), "--data-dir", str(store)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "has not run yet" not in out
    assert "UNREADABLE" in out and "corrupt" in out.lower()


def test_an_absent_heartbeat_still_reads_as_never_run(tmp_path, capsys):
    rc = main(["--watch-status", "--home", str(HOME_SAFE), "--data-dir", str(tmp_path / "s")])
    out = capsys.readouterr().out
    assert rc == 1 and "NOT RUNNING" in out and "has not run yet" in out


def test_a_failed_last_rescan_is_visible_in_the_status_sentence():
    word, sentence = watch.describe_liveness({
        "status": "running", "pid": os.getpid(), "mode": "inotify", "cycles": 1,
        "last_scan_rc": 2, "updated_at": watch._now_iso(), "heartbeat_interval_s": 30},
        None, "held")
    assert word == "ALIVE" and "FAILED" in sentence


# ============================================================ follow-up: lock, hostile input, output

def _hold_lock(store: Path) -> int:
    store.mkdir(parents=True, exist_ok=True)
    fd = os.open(store / "watch.lock", os.O_WRONLY | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fd


def _lock_is_free(store: Path) -> bool:
    fd = os.open(store / "watch.lock", os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        return False
    finally:
        os.close(fd)


def _plant(store: Path, **fields) -> Path:
    hb = {"status": "running", "pid": os.getpid(), "mode": "inotify", "cycles": 1,
          "updated_at": watch._now_iso(), "heartbeat_interval_s": 30}
    hb.update(fields)
    store.mkdir(parents=True, exist_ok=True)
    path = store / "watch_heartbeat.json"
    path.write_text(json.dumps(hb), encoding="utf-8")
    return path


def _status(store: Path, capsys) -> "tuple[int, str]":
    capsys.readouterr()
    rc = main(["--watch-status", "--home", str(HOME_SAFE), "--data-dir", str(store)])
    return rc, capsys.readouterr().out


def test_status_lock_held_with_a_fresh_agreeing_heartbeat_is_alive(tmp_path, capsys):
    store = tmp_path / "store"
    fd = _hold_lock(store)
    try:
        _plant(store)  # pid = this process, which is also the lock holder
        rc, out = _status(store, capsys)
        assert rc == 0 and out.startswith("ALIVE"), out
    finally:
        os.close(fd)
    assert _lock_is_free(store), "the status probe must not leave the lock held"


def test_status_lock_held_but_heartbeat_stopped_is_not_a_bare_alive(tmp_path, capsys):
    store = tmp_path / "store"
    fd = _hold_lock(store)
    try:
        _plant(store, status="stopped", pid=1)
        rc, out = _status(store, capsys)
    finally:
        os.close(fd)
    assert rc == 1 and out.startswith("LOCK HELD"), out
    assert "does not back it" in out and "stopped" in out, out


def test_status_lock_held_and_heartbeat_stale_names_both_facts(tmp_path, capsys):
    from datetime import datetime, timedelta
    store = tmp_path / "store"
    fd = _hold_lock(store)
    try:
        old = (datetime.now() - timedelta(seconds=600)).isoformat(timespec="seconds")
        _plant(store, updated_at=old)
        rc, out = _status(store, capsys)
    finally:
        os.close(fd)
    assert rc == 1 and out.startswith("STALE"), out
    assert "holds this store's lock" in out and "may be hung" in out, out
    assert "another process holds the lock" in out, out


def test_status_lock_held_and_heartbeat_names_a_dead_pid_is_not_alive(tmp_path, capsys):
    dead = subprocess.Popen([sys.executable, "-c", "pass"])
    dead.wait(timeout=10)
    store = tmp_path / "store"
    fd = _hold_lock(store)
    try:
        _plant(store, pid=dead.pid)
        rc, out = _status(store, capsys)
    finally:
        os.close(fd)
    assert rc == 1 and out.startswith("LOCK HELD"), out
    assert "not running" in out, out


def test_status_names_the_lock_holder_and_notices_a_different_heartbeat_pid(tmp_path, capsys):
    if sys.platform != "linux":  # /proc/locks is Linux-only; elsewhere the holder is unknown
        assert watch.lock_holder_pid(tmp_path / "x.lock") is None
        return
    store = tmp_path / "store"
    other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    fd = _hold_lock(store)
    try:
        assert watch.lock_holder_pid(store / "watch.lock") == os.getpid()
        _plant(store, pid=other.pid)  # alive, but it is not what holds the lock
        rc, out = _status(store, capsys)
    finally:
        os.close(fd)
        other.kill()
        other.wait(timeout=10)
    assert rc == 1 and out.startswith("LOCK HELD"), out
    assert f"lock held by pid {os.getpid()}" in out and "not the lock holder" in out, out


def test_lock_holder_pid_tolerates_a_missing_file(tmp_path):
    assert watch.lock_holder_pid(tmp_path / "nope.lock") is None


def test_status_lock_held_and_heartbeat_missing_or_corrupt_is_not_a_bare_alive(tmp_path, capsys):
    store = tmp_path / "store"
    fd = _hold_lock(store)
    try:
        rc, out = _status(store, capsys)
        assert rc == 1 and out.startswith("LOCK HELD") and "no heartbeat file" in out, out
        (store / "watch_heartbeat.json").write_text("{nope", encoding="utf-8")
        rc, out = _status(store, capsys)
        assert rc == 1 and out.startswith("LOCK HELD") and "corrupt" in out, out
    finally:
        os.close(fd)


def test_status_lock_free_and_heartbeat_running_is_a_stale_record(tmp_path, capsys):
    store = tmp_path / "store"
    # A live, watcher-looking pid does not matter: only the lock says a watcher runs.
    decoy = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)",
                              "--watch", "audit.py"])
    try:
        _plant(store, pid=decoy.pid)
        rc, out = _status(store, capsys)
    finally:
        decoy.kill()
        decoy.wait(timeout=10)
    assert rc == 1 and out.startswith("STALE RECORD"), out
    assert "no watcher is running" in out, out


def test_status_lock_free_and_heartbeat_stopped_is_stopped(tmp_path, capsys):
    store = tmp_path / "store"
    _plant(store, status="stopped")
    rc, out = _status(store, capsys)
    assert rc == 1 and out.startswith("STOPPED"), out


def test_status_lock_free_and_heartbeat_corrupt_is_unreadable(tmp_path, capsys):
    store = tmp_path / "store"
    store.mkdir()
    (store / "watch_heartbeat.json").write_text("{nope", encoding="utf-8")
    rc, out = _status(store, capsys)
    assert rc == 1 and out.startswith("UNREADABLE") and "corrupt" in out, out


def test_a_second_start_cannot_take_a_held_lock_and_leaves_the_record_alone(tmp_path):
    store = tmp_path / "store"
    fd = _hold_lock(store)
    try:
        hb_path = _plant(store, pid=4242)
        before = hb_path.read_text(encoding="utf-8")
        rc = watch.run_watch(_copy_home(tmp_path), state_path=store / "s.json",
                             events_path=store / "e.jsonl", history_path=store / "h.jsonl",
                             heartbeat_path=hb_path, max_cycles=0,
                             install_signal_handlers=False, stream=io.StringIO())
        assert rc != 0
        assert hb_path.read_text(encoding="utf-8") == before
    finally:
        os.close(fd)


def test_the_lock_is_released_when_run_watch_returns(tmp_path):
    store = tmp_path / "store"
    rc = watch.run_watch(_copy_home(tmp_path), state_path=store / "s.json",
                         events_path=store / "e.jsonl", history_path=store / "h.jsonl",
                         heartbeat_path=store / "watch_heartbeat.json", max_cycles=0,
                         install_signal_handlers=False, stream=io.StringIO())
    assert rc == 0 and _lock_is_free(store)


def test_a_planted_heartbeat_naming_this_tests_live_pid_does_not_suppress_a_start(tmp_path):
    store = tmp_path / "store"
    hb_path = _plant(store, pid=os.getpid())
    buf = io.StringIO()
    rc = watch.run_watch(_copy_home(tmp_path), state_path=store / "s.json",
                         events_path=store / "e.jsonl", history_path=store / "h.jsonl",
                         heartbeat_path=hb_path, max_cycles=0,
                         install_signal_handlers=False, stream=buf)
    assert rc == 0
    assert "stale" in buf.getvalue().lower(), buf.getvalue()
    assert watch.read_heartbeat(hb_path)["status"] == "stopped"


def test_a_live_decoy_process_named_in_the_heartbeat_does_not_suppress_a_real_watcher(tmp_path):
    """The attack: plant a heartbeat naming a live process whose argv looks like a watch."""
    home = _copy_home(tmp_path)
    store = tmp_path / "store"
    _seed_baseline(home, store)
    decoy = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)",
                              "--watch", "audit.py"])
    real = f = None
    try:
        hb_path = _plant(store, pid=decoy.pid)
        real, out_path, f = _start_cli_watch(tmp_path, home, store, "w1")
        _wait_for(lambda: (watch.read_heartbeat(hb_path) or {}).get("pid") == real.pid, 20,
                  "the real watcher to take over the heartbeat")
        assert real.poll() is None
        assert "stale" in out_path.read_text(encoding="utf-8").lower()
    finally:
        decoy.kill()
        decoy.wait(timeout=10)
        if real is not None:
            _stop(real)
        if f is not None:
            f.close()


def test_a_watcher_killed_with_sigkill_frees_the_lock_for_the_next_start(tmp_path, capsys):
    home = _copy_home(tmp_path)
    store = tmp_path / "store"
    _seed_baseline(home, store)
    hb_path = store / "watch_heartbeat.json"
    first, _o1, f1 = _start_cli_watch(tmp_path, home, store, "w1")
    second = f2 = None
    try:
        _wait_for(lambda: (watch.read_heartbeat(hb_path) or {}).get("pid") == first.pid, 20,
                  "the first heartbeat")
        first.kill()
        first.wait(timeout=10)
        rc, out = _status(store, capsys)
        assert rc == 1 and out.startswith("STALE RECORD"), out
        second, o2, f2 = _start_cli_watch(tmp_path, home, store, "w2")
        _wait_for(lambda: (watch.read_heartbeat(hb_path) or {}).get("pid") == second.pid, 20,
                  "the second watcher to take over")
        assert second.poll() is None
        assert "stale" in o2.read_text(encoding="utf-8").lower()
    finally:
        if first.poll() is None:
            first.kill()
            first.wait(timeout=10)
        f1.close()
        if second is not None:
            _stop(second)
        if f2 is not None:
            f2.close()


def test_without_fcntl_a_confirmed_live_watcher_still_blocks_a_second_start(tmp_path, monkeypatch):
    monkeypatch.setattr(watch, "fcntl", None)
    monkeypatch.setattr(watch, "_HAS_FCNTL", False)
    monkeypatch.setattr(watch, "_pid_is_watcher", lambda pid: True)
    store = tmp_path / "store"
    hb_path = _plant(store, pid=os.getpid())
    rc = watch.run_watch(_copy_home(tmp_path), state_path=store / "s.json",
                         events_path=store / "e.jsonl", history_path=store / "h.jsonl",
                         heartbeat_path=hb_path, max_cycles=0,
                         install_signal_handlers=False, stream=io.StringIO())
    assert rc != 0


def test_without_fcntl_an_unconfirmed_identity_warns_and_starts(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(watch, "fcntl", None)
    monkeypatch.setattr(watch, "_HAS_FCNTL", False)
    monkeypatch.setattr(watch, "_pid_is_watcher", lambda pid: None)
    store = tmp_path / "store"
    hb_path = _plant(store, pid=os.getpid())
    capsys.readouterr()
    rc = watch.run_watch(_copy_home(tmp_path), state_path=store / "s.json",
                         events_path=store / "e.jsonl", history_path=store / "h.jsonl",
                         heartbeat_path=hb_path, max_cycles=0,
                         install_signal_handlers=False, stream=io.StringIO())
    assert rc == 0
    assert "could not be confirmed" in capsys.readouterr().err


def test_a_symlinked_lock_file_is_never_followed_and_does_not_suppress_a_start(tmp_path, capsys):
    store = tmp_path / "store"
    store.mkdir()
    target = tmp_path / "elsewhere"
    target.write_text("keep", encoding="utf-8")
    os.symlink(target, store / "watch.lock")
    capsys.readouterr()
    rc = watch.run_watch(_copy_home(tmp_path), state_path=store / "s.json",
                         events_path=store / "e.jsonl", history_path=store / "h.jsonl",
                         heartbeat_path=store / "watch_heartbeat.json", max_cycles=0,
                         install_signal_handlers=False, stream=io.StringIO())
    assert rc == 0
    assert target.read_text(encoding="utf-8") == "keep"
    assert "lock" in capsys.readouterr().err.lower()


# ------------------------------------------------- hostile heartbeat: never an exception

_HOSTILE = {
    "huge_int": 10 ** 30, "negative_int": -7, "float": 1.5, "nan": float("nan"),
    "bool": True, "string": "abc", "list": [1, 2], "dict": {"a": 1}, "null": None,
    "megabyte_string": "A" * 1_000_000,
}
_FIELDS = ("status", "pid", "updated_at", "heartbeat_interval_s", "mode", "cycles",
           "last_scan_rc", "last_scan_at")
_STATUS_WORDS = ("ALIVE", "STALE RECORD", "STALE", "STOPPED", "UNREADABLE", "NOT RUNNING",
                 "UNKNOWN", "LOCK HELD")


@pytest.mark.parametrize("label", sorted(_HOSTILE))
@pytest.mark.parametrize("field", _FIELDS)
def test_a_hostile_heartbeat_value_never_raises_in_status_or_start(
        tmp_path, capsys, field, label):
    store = tmp_path / "store"
    path = _plant(store, **{field: _HOSTILE[label]})
    # on disk (the megabyte case exceeds the reader's size bound: corrupt, not a crash)
    rc, out = _status(store, capsys)
    assert out.split(":", 1)[0] in _STATUS_WORDS, out[:200]
    assert "Traceback" not in out and len(out) < 3000, out[:200]
    # the same dict handed straight to the describer, under every lock state
    hb = {"status": "running", "pid": os.getpid(), "mode": "inotify", "cycles": 1,
          "updated_at": watch._now_iso(), "heartbeat_interval_s": 30,
          "last_scan_rc": 0, "last_scan_at": watch._now_iso()}
    hb[field] = _HOSTILE[label]
    for lock in (None, "free", "held"):
        word, sentence = watch.describe_liveness(hb, None, lock, "not_regular", 4242)
        assert word in _STATUS_WORDS and len(sentence) < 3000, (lock, word, sentence[:200])
    # the start path replaces the record without raising
    rc = watch.run_watch(_copy_home(tmp_path), state_path=store / "s.json",
                         events_path=store / "e.jsonl", history_path=store / "h.jsonl",
                         heartbeat_path=path, max_cycles=0, install_signal_handlers=False,
                         stream=io.StringIO())
    assert rc == 0
    assert watch.read_heartbeat(path)["pid"] == os.getpid()


# --------------------------------------------- a failed re-scan keeps the child's whole output

def test_a_failed_rescan_prints_every_line_of_the_childs_output(tmp_path, monkeypatch):
    script = ("import sys\n"
              "for i in range(60):\n"
              "    print('ALERT new skill mal-%d' % i if i == 12 else 'line %d' % i)\n"
              "sys.exit(1)\n")
    monkeypatch.setattr(watch, "_child_launch", lambda: (["-c", script], dict(os.environ)))
    home = _copy_home(tmp_path)
    store = tmp_path / "store"
    buf = io.StringIO()
    t, _result = _run_watch_in_thread(home, store, stream=buf, max_cycles=1)
    (home / "poke.txt").write_text("x", encoding="utf-8")
    t.join(timeout=30)
    assert not t.is_alive()
    text = buf.getvalue()
    assert "RE-SCAN FAILED" in text and "did not complete" in text, text
    for i in range(60):
        assert ("ALERT new skill mal-12" if i == 12 else f"line {i}\n") in text, i
    assert "NOT been checked" not in text


# ===================================================== round 3: special files, unknown, limits

def _plant_special(path: Path, kind: str, tmp_path: Path) -> None:
    if kind == "fifo":
        os.mkfifo(path)
    elif kind == "directory":
        path.mkdir()
    else:
        os.symlink(tmp_path / "nowhere", path)  # dangling


_KINDS = ("fifo", "directory", "dangling_symlink")
_TARGETS = ("watch.lock", "watch_heartbeat.json")


def _status_in_a_process(store: Path) -> str:
    """`--watch-status` as a real process under a hard timeout: the timeout IS the
    assertion that a planted special file cannot make it hang."""
    r = subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--watch-status", "--home", str(HOME_SAFE),
         "--data-dir", str(store), "--no-deptree", "--no-host"], cwd=str(REPO_ROOT),
        capture_output=True, text=True, timeout=30)
    assert "Traceback" not in r.stderr, r.stderr
    return r.stdout


@pytest.mark.parametrize("target", _TARGETS)
@pytest.mark.parametrize("kind", _KINDS)
def test_a_special_file_in_the_store_hangs_neither_status_nor_start(
        tmp_path, capsys, kind, target):
    store = tmp_path / "store"
    store.mkdir()
    _plant_special(store / target, kind, tmp_path)

    out = _status_in_a_process(store)
    if target == "watch.lock":
        assert out.startswith("UNKNOWN"), out
        assert "cannot be determined" in out and "never creates" in out or "symbolic link" in out
        assert "unverified" in out, out
    else:
        assert out.startswith("UNREADABLE"), out

    result: dict = {}
    buf = io.StringIO()

    def _start():
        result["rc"] = watch.run_watch(
            _copy_home(tmp_path), state_path=store / "s.json", events_path=store / "e.jsonl",
            history_path=store / "h.jsonl", heartbeat_path=store / "watch_heartbeat.json",
            max_cycles=0, install_signal_handlers=False, stream=buf)

    capsys.readouterr()
    t = threading.Thread(target=_start, daemon=True)
    t.start()
    t.join(timeout=30)
    assert not t.is_alive(), "run_watch hung on a planted special file"
    assert result["rc"] == 0
    err = capsys.readouterr().err
    if target == "watch.lock":
        assert "WITHOUT single-watcher protection" in err, err
        assert ("not a regular file" in err) or ("symbolic link" in err), err


def test_a_real_watch_starts_and_says_so_when_its_lock_file_is_a_fifo(tmp_path):
    home = _copy_home(tmp_path)
    store = tmp_path / "store"
    _seed_baseline(home, store)
    os.mkfifo(store / "watch.lock")
    proc, out_path, f = _start_cli_watch(tmp_path, home, store, "w1")
    try:
        hb = _wait_for(lambda: watch.read_heartbeat(store / "watch_heartbeat.json"), 20,
                       "a watcher with an unusable lock file to start")
        assert hb["pid"] == proc.pid
        text = out_path.read_text(encoding="utf-8")
        assert "not a regular file" in text and "WITHOUT single-watcher protection" in text, text
        status = _status_in_a_process(store)
        assert status.startswith("UNKNOWN"), status
        assert "ALIVE" not in status
    finally:
        _stop(proc)
        f.close()


def test_a_real_watch_replaces_a_fifo_planted_at_the_heartbeat_path(tmp_path):
    home = _copy_home(tmp_path)
    store = tmp_path / "store"
    _seed_baseline(home, store)
    os.mkfifo(store / "watch_heartbeat.json")
    proc, out_path, f = _start_cli_watch(tmp_path, home, store, "w1")
    try:
        hb = _wait_for(lambda: watch.read_heartbeat(store / "watch_heartbeat.json"), 20,
                       "the watcher to replace the planted pipe with a heartbeat")
        assert hb["pid"] == proc.pid
        assert "not a regular file" in out_path.read_text(encoding="utf-8")
    finally:
        _stop(proc)
        f.close()


def test_the_unknown_answer_never_trusts_a_fresh_heartbeat_naming_a_live_pid(tmp_path):
    """The pre-round-3 fallback printed ALIVE here on the strength of a planted file."""
    store = tmp_path / "store"
    store.mkdir()
    os.mkfifo(store / "watch.lock")
    _plant(store, pid=os.getpid())
    out = _status_in_a_process(store)
    assert out.startswith("UNKNOWN") and "ALIVE" not in out.split(":", 1)[0], out
    assert "status 'running'" in out, "the heartbeat must be shown as a claim"


def test_a_symlinked_lock_file_reads_unknown_not_alive(tmp_path, capsys):
    store = tmp_path / "store"
    store.mkdir()
    target = tmp_path / "real.lock"
    target.write_text("", encoding="utf-8")
    os.symlink(target, store / "watch.lock")
    _plant(store, pid=os.getpid())
    rc, out = _status(store, capsys)
    assert rc == 1 and out.startswith("UNKNOWN") and "symbolic link" in out, out


def test_without_fcntl_status_says_it_cannot_tell_and_never_prints_alive(tmp_path, capsys,
                                                                       monkeypatch):
    monkeypatch.setattr(watch, "fcntl", None)
    monkeypatch.setattr(watch, "_HAS_FCNTL", False)
    store = tmp_path / "store"
    _plant(store, pid=os.getpid())
    rc, out = _status(store, capsys)
    assert rc == 1 and out.startswith("UNKNOWN"), out
    assert "no file locks" in out and "unverified" in out, out


def test_the_trust_limit_is_stated_in_the_usage_doc():
    text = (REPO_ROOT / "docs" / "USAGE.md").read_text(encoding="utf-8")
    assert "convenience, not proof" in text
    assert "imitate its files" in text
