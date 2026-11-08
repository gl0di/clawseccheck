"""B-1055: ``--watch`` on a store with no baseline must take one at START, so the first
edit it sees is compared against the pre-edit state and alerts.

Before: the watcher did nothing until a relevant file changed; that first change spawned a
``--monitor`` that found no baseline, saved the ALREADY-CHANGED state as the baseline
("Baseline saved. Future runs will alert on what changes since now.") and raised nothing.
Measured on dev @1bc28cda: exposing the gateway (``gateway.bind`` -> ``0.0.0.0:8080``)
as the first edit produced no alert at all; only a second edit did.
"""
from __future__ import annotations

import io
import os
import shutil
import threading
import time
from pathlib import Path

from clawseccheck import watch

REPO = Path(__file__).resolve().parents[1]
CLEAN = REPO / "fixtures" / "reliability" / "clean_loopback_minimal"
OPT_OUT = ("--no-native", "--no-host", "--no-sockets", "--no-deptree", "--no-dist")


def _wait_for(pred, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.2)
    return False


def test_the_first_edit_after_start_alerts_against_a_start_baseline(tmp_path):
    home = tmp_path / "home"
    shutil.copytree(CLEAN, home)
    os.chmod(home / "openclaw.json", 0o600)
    store = tmp_path / "store"
    store.mkdir()
    buf = io.StringIO()
    result = {}
    stop = threading.Event()

    def _runner():
        result["rc"] = watch.run_watch(
            home, state_path=store / "state.json", events_path=store / "events.jsonl",
            history_path=store / "history.jsonl",
            heartbeat_path=store / "watch_heartbeat.json",
            debounce_s=0.5, select_timeout_s=0.1, poll_interval_s=0.1,
            extra_monitor_args=OPT_OUT, max_cycles=1,
            install_signal_handlers=False, stop_event=stop, stream=buf)

    t = threading.Thread(target=_runner, daemon=True)
    t.start()
    try:
        # The baseline is taken at start, before any change.
        # state.json appears while the monitor subprocess is still running; the watcher only
        # writes its header to the stream and records last_scan_at AFTER that subprocess
        # returns, so wait for those (not for the state file) before asserting on them.
        assert _wait_for(lambda: (store / "state.json").is_file(), 120), buf.getvalue()
        assert _wait_for(
            lambda: "no baseline in this store yet" in buf.getvalue()
            and (watch.read_heartbeat(store / "watch_heartbeat.json") or {}).get("last_scan_at"),
            120), buf.getvalue()
        hb = watch.read_heartbeat(store / "watch_heartbeat.json")
        assert hb["last_scan_at"] and hb["cycles"] == 0

        cfg = home / "openclaw.json"
        time.sleep(1.0)
        cfg.write_text(cfg.read_text(encoding="utf-8").replace(
            '"127.0.0.1:8080"', '"0.0.0.0:8080"'), encoding="utf-8")
        t.join(timeout=180)
        assert not t.is_alive()
        text = buf.getvalue()
        rescan = text.split("change detected, re-scanned", 1)
        assert len(rescan) == 2, text
        assert "Baseline saved" not in rescan[1], "the first edit must not become the baseline"
        assert "change(s) detected" in rescan[1], rescan[1]
    finally:
        # A watcher thread left running past a failed assertion would keep consuming
        # process-directed signals and break unrelated tests (a SIGALRM-owing test in
        # test_scanbudget_reentrancy measured exactly that), so always stop and join it.
        stop.set()
        t.join(timeout=60)


def test_an_existing_baseline_is_not_retaken_at_start(tmp_path, monkeypatch):
    store = tmp_path / "store"
    store.mkdir()
    (store / "state.json").write_text("{}", encoding="utf-8")
    calls = []
    monkeypatch.setattr(watch, "_run_monitor_once", lambda *a, **k: calls.append(a) or (0, ""))
    stop = threading.Event()
    stop.set()
    rc = watch.run_watch(
        tmp_path, state_path=store / "state.json", events_path=store / "events.jsonl",
        history_path=store / "history.jsonl", heartbeat_path=store / "watch_heartbeat.json",
        install_signal_handlers=False, stop_event=stop, stream=io.StringIO())
    assert rc == 0
    assert calls == []
