"""B-781: a --monitor run against a DIFFERENT --home must not compare against, or
overwrite, a baseline recorded for a different OpenClaw home.

Before this fix, the monitor's snapshot/journal/baseline were keyed by --data-dir
alone -- --home was never part of that identity. A run pointed at a different home
therefore flooded the journal with alerts about a machine that did not change, and
silently REBASED the real baseline to the other home's values, so a later genuine
regression on the real machine could read as "no change" (measured: a fixture run
against an isolated --data-dir left gateway_bind = "0.0.0.0" in state.json, where
nothing about the real machine had changed).

The fix: `snapshot()` now records `home_digest` (a sha256 of the RESOLVED, absolute
home path) unconditionally, and `monitor.home_mismatch(prev, home)` tells cli.py's
`--monitor` handling whether the two are verifiably different BEFORE any of the
per-run scanning, the diff, or the journal/state writes happen.

Every test writes only under tmp_path; no test touches the real ~/.clawseccheck store.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from clawseccheck.cli import main
from clawseccheck.monitor import _home_identity, home_mismatch

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE = str(FIXTURES / "home_safe")
VULN = str(FIXTURES / "home_vuln")


def _run(tmp_path: Path, *extra: str, home: str, state=None, events=None):
    state = state if state is not None else tmp_path / "state.json"
    events = events if events is not None else tmp_path / "events.jsonl"
    return main(["--home", home, "--no-native", "--monitor", "--ascii",
                 "--state", str(state), "--events", str(events),
                 "--history", str(tmp_path / "history.jsonl"), *extra])


# --------------------------------------------------------------------------- unit level

def test_same_home_absolute_vs_relative_spelling_is_one_identity(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    abs_digest, _ = _home_identity(home)
    rel_digest, _ = _home_identity(Path(str(home)))
    assert abs_digest == rel_digest


def test_same_home_with_a_trailing_slash_is_one_identity(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    a, _ = _home_identity(str(home))
    b, _ = _home_identity(str(home) + "/")
    assert a == b


def test_same_home_reached_through_a_symlink_is_one_identity(tmp_path):
    real = tmp_path / "real_home"
    real.mkdir()
    link = tmp_path / "link_home"
    link.symlink_to(real)
    real_digest, _ = _home_identity(real)
    link_digest, _ = _home_identity(link)
    assert real_digest == link_digest


def test_two_different_homes_have_different_identity(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    da, _ = _home_identity(a)
    db, _ = _home_identity(b)
    assert da != db


def test_home_mismatch_is_false_with_no_prior_baseline():
    assert home_mismatch(None, "/tmp/whatever") is False
    assert home_mismatch({}, "/tmp/whatever") is False


def test_home_mismatch_is_false_when_the_prior_baseline_predates_home_tracking(tmp_path):
    """A legacy baseline (no `home_digest` key at all) must be treated as UNVERIFIED,
    not silently trusted as a match -- but also not hard-blocked, or every baseline
    saved before this fix would read as a mismatch the moment it upgrades. Disclosure
    of the gap is WATCHED_DIMENSIONS' own job (see the CLI-level test below)."""
    legacy = {"version": 9, "checks": {}}
    assert home_mismatch(legacy, tmp_path / "home") is False


def test_home_mismatch_is_false_for_the_same_home_reached_differently(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    digest, display = _home_identity(home)
    prev = {"home_digest": digest, "home_display": display}
    assert home_mismatch(prev, str(home) + "/") is False


def test_home_mismatch_is_true_for_a_genuinely_different_home(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    digest, display = _home_identity(a)
    prev = {"home_digest": digest, "home_display": display}
    assert home_mismatch(prev, b) is True


# ----------------------------------------------------------------------- CLI end to end

def test_a_monitor_run_against_a_different_home_refuses_to_rebase(tmp_path, capsys):
    state = tmp_path / "state.json"
    events = tmp_path / "events.jsonl"

    rc0 = _run(tmp_path, home=SAFE, state=state, events=events)
    assert rc0 == 0
    before = state.read_text(encoding="utf-8")
    capsys.readouterr()

    rc1 = _run(tmp_path, home=VULN, state=state, events=events)
    err = capsys.readouterr().err

    assert rc1 == 1
    assert "MONITORING NOT ESTABLISHED" in err
    assert "different OpenClaw home" in err
    # Names both homes, not just one.
    assert "home_safe" in err
    assert "home_vuln" in err
    # The baseline was NOT rebased.
    assert state.read_text(encoding="utf-8") == before
    assert json.loads(before)["gateway_bind"] != "0.0.0.0:8080"


def test_a_monitor_run_against_a_different_home_does_not_flood_the_journal(tmp_path, capsys):
    """The dangerous half of the bug: a home switch must not manufacture dozens of
    'no longer determinable' alerts and write them into the tamper-evident journal."""
    state = tmp_path / "state.json"
    events = tmp_path / "events.jsonl"

    _run(tmp_path, home=SAFE, state=state, events=events)
    capsys.readouterr()
    _run(tmp_path, home=VULN, state=state, events=events)
    capsys.readouterr()

    assert not events.exists() or events.read_text(encoding="utf-8").strip() == ""


def test_a_monitor_run_against_a_different_home_prints_no_alert_flood(tmp_path, capsys):
    state = tmp_path / "state.json"
    events = tmp_path / "events.jsonl"
    _run(tmp_path, home=SAFE, state=state, events=events)
    capsys.readouterr()
    _run(tmp_path, home=VULN, state=state, events=events)
    out = capsys.readouterr().out
    assert "change(s) detected" not in out


def test_a_legacy_baseline_with_no_recorded_home_is_not_blocked(tmp_path, capsys):
    """The existing-baseline case B-781's own DoD calls out: a state file written before
    per-home tracking existed must be treated as unverified, not silently trusted AND
    not hard-blocked -- a hard block here would read every pre-existing baseline on
    upgrade as a false mismatch."""
    state = tmp_path / "state.json"
    events = tmp_path / "events.jsonl"
    _run(tmp_path, home=SAFE, state=state, events=events)

    snap = json.loads(state.read_text(encoding="utf-8"))
    del snap["home_digest"]
    del snap["home_display"]
    state.write_text(json.dumps(snap), encoding="utf-8")
    capsys.readouterr()

    rc = _run(tmp_path, "--verbose", home=SAFE, state=state, events=events)
    out = capsys.readouterr().out
    assert rc == 0
    assert "MONITORING NOT ESTABLISHED" not in out


def test_the_same_home_reached_by_a_different_spelling_compares_normally(tmp_path, capsys):
    """The legitimate case: a symlink, a trailing slash, `~` vs absolute -- must NOT be
    treated as a different machine."""
    real = tmp_path / "real_home"
    shutil.copytree(FIXTURES / "home_safe", real)
    for p in real.rglob("*"):
        if p.is_file():
            p.chmod(0o600)
    link = tmp_path / "link_home"
    link.symlink_to(real)

    state = tmp_path / "state.json"
    events = tmp_path / "events.jsonl"
    rc0 = _run(tmp_path, home=str(real), state=state, events=events)
    assert rc0 == 0
    capsys.readouterr()

    rc1 = _run(tmp_path, home=str(link), state=state, events=events)
    err = capsys.readouterr().err
    assert rc1 == 0
    assert "MONITORING NOT ESTABLISHED" not in err


def test_snapshot_carries_home_digest_unconditionally():
    from clawseccheck import audit
    from clawseccheck.monitor import snapshot

    ctx, findings, score = audit(FIXTURES / "home_safe")
    snap = snapshot(ctx, findings, score)
    assert "home_digest" in snap
    assert len(snap["home_digest"]) == 64
    assert "home_digest" in snap["watched"]
