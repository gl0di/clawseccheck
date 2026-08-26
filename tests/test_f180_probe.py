"""F-180 — `--monitor --probe`: ask whether anything changed without answering it.

Every `--monitor` run advanced the baseline, which made the epic's real-time goal
unreachable rather than merely slow. A `trigger.script` polling by running `--monitor`
**consumes the drift on the first poll**: the run records the new state, so the expensive
`agentTurn` it wakes compares against the already-advanced baseline and finds nothing.

`--probe` computes the snapshot and the diff, renders, and sets the exit code, while
writing none of the three local files.

**The exit-code arm is the subtle part, and it is the reverse of the obvious reading.**
`cli.py` gates `return 3` on `persisted`, so a non-persisting run returns **0 even with
drift**. For the F-155 seed gate that is correct — nothing was recorded, so an exit code
claiming drift was journaled would be false. For a probe it is exactly backwards: a poll
that cannot report drift is not a poll. Hence `persisted or _probe`, and
`test_a_probe_reports_drift_in_the_exit_code` is what keeps it.

**The three-file footgun bit this feature during its own implementation.** The first
version gated `record_events` and `save_state` and left `history.jsonl` growing on every
poll — `--history` defaults independently of `--state`/`--events`, which is the documented
trap, reappearing inside the feature written to avoid consuming state.
`test_a_probe_touches_none_of_the_three_files` compares BYTES of all three.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path

import pytest

from clawseccheck.cli import main

_FILES = ("state.json", "events.jsonl", "history.jsonl")


def _run(home: Path, store: Path, *extra) -> "tuple[int, str]":
    """Returns stdout AND stderr combined.

    Not a convenience: the "MONITORING NOT ESTABLISHED" line goes to stderr, and asserting
    it against stdout alone made the rc=1 positive control fail while the mechanism was
    working perfectly. A control that cannot see the signal it is controlling for is worse
    than no control.
    """
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(["--monitor", "--home", str(home), "--data-dir", str(store), *extra])
    return rc, out.getvalue() + err.getvalue()


def _digests(store: Path) -> dict:
    out = {}
    for name in _FILES:
        f = store / name
        out[name] = hashlib.sha256(f.read_bytes()).hexdigest() if f.is_file() else "ABSENT"
    return out


def _write_cfg(home: Path, bind: str) -> None:
    cfg = home / "openclaw.json"
    cfg.write_text(json.dumps({
        "gateway": {"bind": bind,
                    "auth": {"mode": "token", "token": "a-very-long-token-of-32-chars!!"}},
    }), encoding="utf-8")
    os.chmod(cfg, 0o600)


@pytest.fixture()
def bed(tmp_path):
    home, store = tmp_path / "home", tmp_path / "store"
    home.mkdir()
    store.mkdir()
    _write_cfg(home, "127.0.0.1:8080")
    _run(home, store)
    return home, store


def test_a_probe_touches_none_of_the_three_files(bed):
    """All three, by content. `--history` defaults independently of `--state`/`--events`,
    which is how the first implementation of this very feature kept writing one of them."""
    home, store = bed
    before = _digests(store)
    _write_cfg(home, "0.0.0.0:8080")
    _run(home, store, "--probe")
    assert _digests(store) == before


def test_a_probe_reports_drift_in_the_exit_code(bed):
    """The reversed trap. `return 3` is gated on `persisted`, so without the probe arm a
    probe would return 0 with drift sitting right there on the screen — and a poll that
    cannot signal is not a poll."""
    home, store = bed
    _write_cfg(home, "0.0.0.0:8080")
    rc, out = _run(home, store, "--probe", "--exit-code", "--fail-on", "medium")
    assert "Gateway bind changed" in out, out
    assert rc == 3, out


def test_the_drift_survives_the_probe(bed):
    """The assertion the whole feature exists for: an ordinary run after a probe still
    reports the same change, because the probe did not consume it."""
    home, store = bed
    _write_cfg(home, "0.0.0.0:8080")
    _run(home, store, "--probe")
    rc, out = _run(home, store, "--exit-code", "--fail-on", "medium")
    assert "Gateway bind changed" in out, out
    assert rc == 3, out


def test_an_ordinary_run_still_consumes_it(bed):
    """The narrowness control. If the probe had broken ordinary consumption, the test above
    would pass forever and the watch would report the same drift for the rest of time."""
    home, store = bed
    _write_cfg(home, "0.0.0.0:8080")
    _run(home, store, "--probe")
    _run(home, store)
    rc, out = _run(home, store, "--exit-code", "--fail-on", "medium")
    assert "Gateway bind changed" not in out, out
    assert rc == 0, out


def test_a_probe_says_it_did_not_record(bed):
    """Without this the user reads the alert as filed, then sees it again on the next
    ordinary run with no explanation — which reads as the tool double-reporting."""
    home, store = bed
    _write_cfg(home, "0.0.0.0:8080")
    _rc, out = _run(home, store, "--probe")
    assert "This was a probe" in out, out
    assert "report it again" in out, out


def test_a_probe_on_a_first_ever_run_creates_no_baseline(tmp_path):
    """A probe must not quietly establish monitoring. Someone polling before ever running
    the check would otherwise get a baseline they never asked for — and, worse, one taken
    at a moment they had not vetted."""
    home, store = tmp_path / "home", tmp_path / "store"
    home.mkdir()
    store.mkdir()
    _write_cfg(home, "127.0.0.1:8080")
    _run(home, store, "--probe")
    assert not (store / "state.json").exists(), sorted(p.name for p in store.iterdir())


def test_an_unwritable_store_still_fails_loudly_without_the_probe(tmp_path):
    """The positive control for the reservation of rc=1.

    Every assertion above is about NOT writing, so all of them would still pass if the
    probe work had simply deleted the "monitoring is not established" path. This proves it
    is intact: a run that MEANT to write and could not must still say so.
    """
    home, store = tmp_path / "home", tmp_path / "store"
    home.mkdir()
    store.mkdir()
    _write_cfg(home, "127.0.0.1:8080")
    _run(home, store)
    _write_cfg(home, "0.0.0.0:8080")
    # The FILE, not the directory. `safeio.secure_dir` re-applies 0700 to the data dir on
    # every run, so a directory chmod is undone before the write is attempted — the first
    # version of this control did that and passed vacuously with rc=3. A read-only
    # `events.jsonl` is also the exact scenario B-278's comment describes.
    journal = store / "events.jsonl"
    journal.touch()
    os.chmod(journal, 0o444)
    try:
        rc, out = _run(home, store, "--exit-code", "--fail-on", "medium")
    finally:
        os.chmod(journal, 0o600)
    assert rc == 1, (rc, out)
    assert "MONITORING NOT ESTABLISHED" in out, out


def test_a_probe_on_an_unwritable_store_is_not_an_emergency(tmp_path):
    """rc=1 is documented in the shipped cron recipe as MORE urgent than drift. A probe was
    never going to write, so an unwritable store is not its emergency — reporting one would
    turn every poll on a read-only store into a false alarm."""
    home, store = tmp_path / "home", tmp_path / "store"
    home.mkdir()
    store.mkdir()
    _write_cfg(home, "127.0.0.1:8080")
    _run(home, store)
    _write_cfg(home, "0.0.0.0:8080")
    journal = store / "events.jsonl"
    journal.touch()
    os.chmod(journal, 0o444)
    try:
        rc, out = _run(home, store, "--probe", "--exit-code", "--fail-on", "medium")
    finally:
        os.chmod(journal, 0o600)
    assert rc == 3, (rc, out)
    assert "MONITORING NOT ESTABLISHED" not in out, out


def test_probe_without_monitor_is_not_silently_honoured(tmp_path):
    """`--probe` is a monitor-only modifier. A flag that silently does nothing on another
    path is how `--monitor --json` was dropped for a whole release (F-176)."""
    home = tmp_path / "home"
    home.mkdir()
    _write_cfg(home, "127.0.0.1:8080")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        main(["--home", str(home), "--probe", "--fast"])
    combined = buf.getvalue()
    assert "probe" in combined.lower(), combined
