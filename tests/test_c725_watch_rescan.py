"""C-725 - ``--watch`` must be able to re-scan however it was started, must announce a
failed re-scan, must not let a second watcher corrupt the first one's status, and must
report a heartbeat it cannot trust as exactly that.

Everything that starts a process stops it in ``finally`` (terminate, then a bounded wait,
then kill) and every wait has a hard timeout. Homes and stores live under ``tmp_path``.
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
             "--watch-debounce", "0.3", *_OPT_OUT],
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
    assert "NOT been checked" in text and "still watching" in text, text
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
        assert str(first.pid) in text2 and "already" in text2.lower(), text2
        assert watch.read_heartbeat(hb_path)["pid"] == first.pid == hb1["pid"]
        assert first.poll() is None, "the refused start must not touch the first watcher"
        status = subprocess.run(
            [sys.executable, "-m", "clawseccheck", "--watch-status", "--home", str(home),
             "--data-dir", str(store)], cwd=str(REPO_ROOT), capture_output=True, text=True,
            timeout=60)
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


def test_run_watch_refuses_when_the_recorded_pid_is_a_live_watcher(tmp_path, monkeypatch):
    store = tmp_path / "store"
    hb_path = store / "watch_heartbeat.json"
    watch._write_heartbeat(hb_path, pid=os.getpid(), status="running", mode="inotify",
                           updated_at=watch._now_iso())
    monkeypatch.setattr(watch, "_pid_is_watcher", lambda pid: True)
    buf = io.StringIO()
    rc = watch.run_watch(_copy_home(tmp_path), state_path=store / "s.json",
                         events_path=store / "e.jsonl", history_path=store / "h.jsonl",
                         heartbeat_path=hb_path, max_cycles=0, install_signal_handlers=False,
                         stream=buf)
    assert rc != 0
    assert watch.read_heartbeat(hb_path)["status"] == "running", "the record must be untouched"


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


@pytest.mark.parametrize("bad_pid", [0, -1, 1, True, "12", None])
def test_a_pid_that_cannot_be_a_watcher_is_a_stale_record_not_alive(bad_pid):
    word, sentence = watch.describe_liveness({
        "status": "running", "pid": bad_pid, "mode": "inotify",
        "updated_at": watch._now_iso(), "heartbeat_interval_s": 30})
    assert word == "STALE RECORD", (word, sentence)


def test_a_live_pid_that_is_not_a_watcher_is_a_stale_record(monkeypatch):
    monkeypatch.setattr(watch, "_pid_is_watcher", lambda pid: False)
    word, sentence = watch.describe_liveness({
        "status": "running", "pid": os.getpid(), "mode": "inotify",
        "updated_at": watch._now_iso(), "heartbeat_interval_s": 30})
    assert word == "STALE RECORD"
    assert "not a clawseccheck" in sentence


def test_an_unconfirmable_identity_is_alive_but_says_so(monkeypatch):
    monkeypatch.setattr(watch, "_pid_is_watcher", lambda pid: None)
    word, sentence = watch.describe_liveness({
        "status": "running", "pid": os.getpid(), "mode": "inotify", "cycles": 1,
        "updated_at": watch._now_iso(), "heartbeat_interval_s": 30})
    assert word == "ALIVE"
    assert "could not be confirmed" in sentence


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


def test_a_failed_last_rescan_is_visible_in_the_status_sentence(monkeypatch):
    monkeypatch.setattr(watch, "_pid_is_watcher", lambda pid: True)
    word, sentence = watch.describe_liveness({
        "status": "running", "pid": os.getpid(), "mode": "inotify", "cycles": 1,
        "last_scan_rc": 2, "updated_at": watch._now_iso(), "heartbeat_interval_s": 30})
    assert word == "ALIVE" and "FAILED" in sentence
