"""B-870: `journal_lock` built its sidecar path from the raw *target* string
without ever calling ``.expanduser()``. Every OTHER caller (history.py,
ledger.py, runstore.py, sbom_runs.py, incidentstore.py, monitorstore.py) already
expands its own path before calling in, so the bug was invisible there. The one
caller that doesn't is `cli.py`'s `--monitor` mode: with no `--state`/`--events`/
`--data-dir` given, `args.state` stays the literal default string
``"~/.clawseccheck/state.json"`` (`monitorstore.DEFAULT_STATE`), and that literal
tilde reached `journal_lock` unexpanded.

Two real consequences, both exercised here end to end (real subprocesses, not a
monkeypatched lock -- the whole point is the actual path the lock sidecar
resolves to):

  1. A bare `--monitor` litters the CURRENT WORKING DIRECTORY with a literal
     `./~/.clawseccheck/state.json.lock` instead of putting the lock next to the
     real state file in `$HOME/.clawseccheck/`.
  2. Because that bogus lock path depends on the CWD, two concurrent `--monitor`
     runs launched from two DIFFERENT directories each take out a lock on a
     DIFFERENT (bogus) file -- they never actually contend on the one resource
     B-769's fix depends on serializing, so the same real drift can be journaled
     twice.

Offline, read-only with respect to the user's real OpenClaw config/home; writes
only inside pytest's tmp_path (a fake $HOME is exported for the subprocess, so
this never touches the real machine's ~/.clawseccheck/).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
REPO = Path(__file__).resolve().parent.parent


def _seed_home(dest: Path) -> None:
    shutil.copytree(FIXTURES / "home_safe", dest)
    for p in dest.rglob("*"):
        if p.is_file():
            p.chmod(0o600)


def _cfg(home: Path) -> dict:
    return json.loads((home / "openclaw.json").read_text(encoding="utf-8"))


def _write_cfg(home: Path, cfg: dict) -> None:
    (home / "openclaw.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    for p in home.rglob("*"):
        if p.is_file():
            p.chmod(0o600)


def _env(fake_home: Path) -> dict:
    # cwd is deliberately NOT the repo root for these tests (that is the whole
    # point -- the bug/fix is about what happens in an ARBITRARY launch
    # directory), so `-m clawseccheck` needs the repo on PYTHONPATH to resolve.
    env = {**os.environ, "HOME": str(fake_home)}
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(REPO) + (os.pathsep + existing if existing else "")
    return env


def _run(openclaw_home: Path, cwd: Path, env: dict) -> "tuple[int, str]":
    cmd = [sys.executable, "-m", "clawseccheck", "--home", str(openclaw_home),
           "--monitor", "--no-native"]
    r = subprocess.run(cmd, cwd=str(cwd), env=env, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


# ---------------------------------------------------------------------------
# consequence 1: no litter in the launch directory
# ---------------------------------------------------------------------------

def test_bare_monitor_from_arbitrary_cwd_writes_nothing_into_that_cwd(tmp_path):
    fake_home = tmp_path / "fakehome"
    openclaw_home = fake_home / ".openclaw"
    launch_dir = tmp_path / "launch"
    launch_dir.mkdir(parents=True)
    _seed_home(openclaw_home)

    env = _env(fake_home)
    rc, out = _run(openclaw_home, launch_dir, env)
    assert rc in (0, 1, 3), f"unexpected exit: {out[-800:]}"

    # Nothing landed in the arbitrary launch directory -- in particular no
    # literal "~" entry (the exact artefact B-870 documents).
    assert list(launch_dir.iterdir()) == [], (
        f"bare --monitor littered the launch directory: {list(launch_dir.iterdir())}"
    )

    # The real state file (and its lock sidecar) landed where it belongs: next
    # to each other, under the fake $HOME, never under a literal "~" dir.
    real_store = fake_home / ".clawseccheck"
    assert (real_store / "state.json").is_file(), (
        f"state.json did not land under $HOME/.clawseccheck: {out[-800:]}"
    )
    assert (real_store / "state.json.lock").exists(), (
        "the lock sidecar must sit next to the real state file, not under a "
        "literal '~' directory"
    )


# ---------------------------------------------------------------------------
# consequence 2: the lock must be the actual shared resource across cwds
# ---------------------------------------------------------------------------

def test_concurrent_bare_monitor_from_different_cwds_still_serializes(tmp_path):
    """Same race `test_b769_concurrent_monitor.py` proves is closed for
    `--data-dir` (which already expanded), reproduced here for the bare default
    path with the two racing processes launched from two DIFFERENT working
    directories -- the exact case a per-cwd lock target cannot serialize.
    """
    fake_home = tmp_path / "fakehome"
    openclaw_home = fake_home / ".openclaw"
    cwd_a = tmp_path / "cwd_a"
    cwd_b = tmp_path / "cwd_b"
    cwd_a.mkdir(parents=True)
    cwd_b.mkdir(parents=True)
    _seed_home(openclaw_home)

    env = _env(fake_home)

    # Establish the baseline first, from a third directory -- both racing runs
    # below must diff against this SAME stale snapshot.
    rc0, out0 = _run(openclaw_home, tmp_path, env)
    assert rc0 == 0, f"baseline run must succeed first: {out0[-800:]}"

    # One real, unambiguous drift, same mutation the B-769 test and
    # scripts/monitor_detection_gate.py both use.
    cfg = _cfg(openclaw_home)
    cfg.setdefault("gateway", {})["auth"] = {"mode": "none"}
    _write_cfg(openclaw_home, cfg)

    cmd = [sys.executable, "-m", "clawseccheck", "--home", str(openclaw_home),
           "--monitor", "--no-native"]
    procs = [
        subprocess.Popen(cmd, cwd=str(cwd), env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for cwd in (cwd_a, cwd_b)
    ]
    outs = [p.communicate() for p in procs]
    for i, p in enumerate(procs):
        assert p.returncode in (0, 1, 3), (
            f"process {i} exited unexpectedly: {outs[i][0][-500:]} {outs[i][1][-500:]}"
        )

    events_path = fake_home / ".clawseccheck" / "events.jsonl"
    assert events_path.is_file(), (
        "at least one of the two runs must have journaled the drift into the "
        "real $HOME store, not a per-cwd '~' directory"
    )
    lines = [json.loads(ln) for ln in events_path.read_text(encoding="utf-8").splitlines() if ln]
    gateway_lines = [e for e in lines
                     if "control-plane mutation reachability via gateway" in e["message"].lower()]
    assert gateway_lines, "the real drift (gateway auth switched off) must be recorded at all"
    assert len(gateway_lines) == 1, (
        f"the SAME drift was journaled {len(gateway_lines)} times by two racing "
        f"processes launched from different cwds -- the lock did not actually "
        f"serialize them: {gateway_lines}"
    )

    # And no litter: neither launch directory should have grown a "~" tree.
    assert list(cwd_a.iterdir()) == [], f"cwd_a littered: {list(cwd_a.iterdir())}"
    assert list(cwd_b.iterdir()) == [], f"cwd_b littered: {list(cwd_b.iterdir())}"
