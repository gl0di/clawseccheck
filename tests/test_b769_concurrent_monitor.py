"""B-769 item 3: two concurrent `--monitor` runs against the same store must not
duplicate the same real event in the journal.

`journal_lock` (B-108) already serializes the read-last-hash -> append critical
section, which stops two racing writers from corrupting the HASH CHAIN. It does
NOT, by itself, stop them from duplicating its CONTENT: both processes read the
same stale on-disk baseline, run their own (real, several-second) audit, compute
the identical diff against it, and each individually-valid append still leaves
the same real drift event recorded twice.

The fix (record_events' new baseline_prev/state_path parameters) re-checks, inside
the SAME lock, whether the baseline moved since THIS run's alerts were computed.
This is exercised end to end with two REAL OS processes -- a simulated lock (two
threads in one interpreter, or two sequential calls) cannot reproduce the actual
race: the whole point is that the diff happens in each process's own memory,
before either one has any way to see the other's write.

Offline, read-only with respect to the user's real OpenClaw config; writes only
inside pytest's tmp_path.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from clawseccheck.monitorstore import verify_chain

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
REPO = Path(__file__).resolve().parent.parent


def _cfg(home: Path) -> dict:
    return json.loads((home / "openclaw.json").read_text(encoding="utf-8"))


def _write_cfg(home: Path, cfg: dict) -> None:
    (home / "openclaw.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def _run(home: Path, store: Path, *extra: str) -> "tuple[int, str]":
    cmd = [sys.executable, "-m", "clawseccheck", "--monitor", "--home", str(home),
           "--data-dir", str(store), "--no-deptree", "--no-host", *extra]
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO))
    return r.returncode, r.stdout + r.stderr


def test_two_real_processes_racing_on_a_stale_baseline_do_not_duplicate_the_alert(tmp_path):
    home = tmp_path / "home"
    store = tmp_path / "store"
    import shutil
    shutil.copytree(FIXTURES / "home_safe", home)
    for p in home.rglob("*"):
        if p.is_file():
            p.chmod(0o600)

    # Establish the CLEAN baseline first -- both racing runs below must diff
    # against this SAME stale snapshot, never against each other's output.
    rc0, out0 = _run(home, store)
    assert rc0 == 0, f"baseline run must succeed first: {out0[-800:]}"

    # One real, unambiguous drift: gateway auth switched off. Matches the same
    # mutation scripts/monitor_detection_gate.py uses for this exact check.
    cfg = _cfg(home)
    cfg.setdefault("gateway", {})["auth"] = {"mode": "none"}
    _write_cfg(home, cfg)
    for p in home.rglob("*"):
        if p.is_file():
            p.chmod(0o600)

    # Two REAL OS processes, launched back to back with no synchronization --
    # each takes several seconds for its own real audit (measured ~3s on this
    # machine) before either ever reaches the point of writing anything, which
    # is the actual race window this test exercises. `Popen`, not `run`: both
    # must be in flight at once, not sequential.
    procs = [
        subprocess.Popen(
            [sys.executable, "-m", "clawseccheck", "--monitor",
             "--home", str(home), "--data-dir", str(store), "--no-deptree", "--no-host"],
            cwd=str(REPO), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        for _ in range(2)
    ]
    outs = [p.communicate() for p in procs]
    for i, p in enumerate(procs):
        assert p.returncode in (0, 1, 3), (
            f"process {i} exited unexpectedly: {outs[i][0][-500:]} {outs[i][1][-500:]}"
        )

    events_path = store / "events.jsonl"
    assert events_path.is_file(), "at least one of the two runs must have journaled the drift"
    lines = [json.loads(ln) for ln in events_path.read_text(encoding="utf-8").splitlines() if ln]
    gateway_lines = [e for e in lines
                     if "control-plane mutation reachability via gateway" in e["message"].lower()]
    assert gateway_lines, "the real drift (gateway auth switched off) must be recorded at all"
    assert len(gateway_lines) == 1, (
        f"the SAME drift was journaled {len(gateway_lines)} times by two racing "
        f"processes reading the same stale baseline: {gateway_lines}"
    )

    # The lock (B-108) must still be doing its own job: no spurious BROKEN chain
    # from the two processes' appends interleaving.
    ok, msg = verify_chain(events_path)
    assert ok is True, f"chain must verify clean after two concurrent writers: {msg}"


def test_sequential_state_write_failure_still_re_journals_next_run(tmp_path, monkeypatch):
    """The B-769 fix must not defeat B-278's own accepted recovery path: when the
    FIRST run's journal write lands but its state write then fails, the baseline
    never advances, so a SECOND (later, non-racing) run seeing the same real
    drift must still journal it -- not be silently deduped as if it were a race.
    This is the scenario the content/time heuristic (tried first, reverted) broke.

    In-process (main(), not subprocess): monkeypatching cli.save_state only
    reaches a call in THIS interpreter, not a child process spawned by _run().
    """
    import clawseccheck.cli as cli

    home = tmp_path / "home"
    store = tmp_path / "store"
    state, events = store / "state.json", store / "events.jsonl"
    import shutil
    shutil.copytree(FIXTURES / "home_safe", home)
    for p in home.rglob("*"):
        if p.is_file():
            p.chmod(0o600)

    def _run_inproc(*extra):
        return cli.main(["--home", str(home), "--no-native", "--monitor",
                         "--state", str(state), "--events", str(events),
                         "--history", str(store / "history.jsonl"), *extra])

    rc0 = _run_inproc()
    assert rc0 == 0, "baseline run must succeed first"

    cfg = _cfg(home)
    cfg.setdefault("gateway", {})["auth"] = {"mode": "none"}
    _write_cfg(home, cfg)
    for p in home.rglob("*"):
        if p.is_file():
            p.chmod(0o600)

    monkeypatch.setattr(cli, "save_state",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("boom")))
    rc1 = _run_inproc()
    assert rc1 != 0

    monkeypatch.undo()
    _run_inproc()

    lines = [json.loads(ln) for ln in events.read_text(encoding="utf-8").splitlines() if ln]
    gateway_lines = [e for e in lines
                     if "control-plane mutation reachability via gateway" in e["message"].lower()]
    assert len(gateway_lines) == 2, (
        "a legitimate later re-detection (state write failed, baseline never "
        f"advanced) must still be journaled, not deduped: got {len(gateway_lines)}"
    )
