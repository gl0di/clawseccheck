"""F-182 — a behaviour the agent provably started doing can now page.

`--monitor` alerts when a behavioural detector fires that did not fire last time, and it
did so at INFO with a stated reason: the trajectory replay is capped, so "fired now, not
last time" can mean nothing more than the window sliding over older activity. Paging on
window movement would be a false alarm, so INFO was right — *when the window was capped*.

The run already records whether it was. `behavioral_capped` goes into the snapshot on both
sides; only `curr`'s copy was ever read, and only to raise a note. When NEITHER run hit the
cap, both replays were complete and the ambiguity the INFO exists for is simply absent —
"newly fired" means newly **done**.

At INFO that sat below the shipped cron recipe's `--fail-on medium`, which made this the
one signal in the whole watch about what the agent *actually did*, rather than how it is
configured, that could never reach a human.

**`is False`, not falsy.** An absent flag — an older baseline, or a run that recorded none
— must read as capped. `test_an_absent_cap_flag_reads_as_capped` is what keeps that, and it
is the assertion most likely to be broken by a "simplification" to `not prev.get(...)`.

**This branch has fixture evidence only, and that is structural.** The real machine is
capped (its "more saved agent activity than can be replayed" note fires on every run), so
no run on this fleet can exercise MEDIUM. That is why MEDIUM is the ceiling here.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path

import pytest

from clawseccheck import monitor
from clawseccheck.monitor import diff_with_notes

_MARK = "behaviour pattern(s)"


def _cli(home=None, store=None, extra=()) -> "tuple[int, str]":
    """The real entry point, so these assertions cover the wiring and not just the arm."""
    from clawseccheck.cli import main
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(["--monitor", "--home", str(home), "--data-dir", str(store), *extra])
    return rc, buf.getvalue()


def _snap(fired: list, capped, **kw) -> dict:
    """A snapshot carrying the behavioural layer's result.

    `capped` is passed through verbatim rather than coerced, so a test can supply the
    absent case by handing in `None` and having the key omitted.
    """
    base = {
        "version": monitor.SNAPSHOT_VERSION,
        "checks": {}, "graded": True, "score": 50, "raw_score": 50, "grade": "F",
        "scope": ["host"], "watched": list(monitor.WATCHED_DIMENSIONS),
        "config_ever_seen": True,
        "config_file_sha256": "a" * 64,
        "behavioral_fired": sorted(fired),
        "behavioral_undetermined": [],
    }
    if capped is not None:
        base["behavioral_capped"] = capped
    base.update(kw)
    return base


def _alerts(prev: dict, curr: dict) -> list:
    alerts, _notes = diff_with_notes(prev, curr)
    return [(lvl, m) for lvl, m in alerts if _MARK in m]


# ------------------------------------------------------------------ the new branch

def test_a_complete_replay_on_both_sides_pages():
    """The defect this task exists for. Both runs read the whole trajectory, so a detector
    that fired now and not before is something the agent newly DID."""
    hits = _alerts(_snap([], False), _snap(["T1"], False))
    assert hits, "a newly-fired detector must still be reported"
    assert all(lvl == "MEDIUM" for lvl, _m in hits), hits
    assert "actually did" in hits[0][1], hits


def test_the_paging_branch_says_why_it_is_confident():
    """A MEDIUM that does not explain itself invites the reader to assume a false alarm and
    start ignoring the class. The sentence has to carry the reason it is not one."""
    _lvl, message = _alerts(_snap([], False), _snap(["T1"], False))[0]
    assert "replayed its activity in full" in message, message
    assert "newly visible" in message, message


# ------------------------------------------------------------------ the narrowness

@pytest.mark.parametrize("prev_cap,curr_cap", [(True, False), (False, True), (True, True)])
def test_a_capped_replay_on_either_side_stays_advisory(prev_cap, curr_cap):
    """Both directions, because ignoring ONE of the two flags is the likely defect and a
    test that only capped `curr` would pass with `prev` unread — which is exactly the state
    this task found the code in."""
    hits = _alerts(_snap([], prev_cap), _snap(["T1"], curr_cap))
    assert hits, "a capped replay must still REPORT the pattern, just not page"
    assert all(lvl == "INFO" for lvl, _m in hits), (prev_cap, curr_cap, hits)
    assert "newly seen rather than newly done" in hits[0][1], hits


@pytest.mark.parametrize("prev_cap,curr_cap", [(None, False), (False, None), (None, None)])
def test_an_absent_cap_flag_reads_as_capped(prev_cap, curr_cap):
    """Absence is not evidence that the replay was complete.

    An older baseline predating the flag, or a run that recorded none, must not be read as
    "the whole trajectory was seen". Rewriting the guard as `not prev.get(...)` would pass
    every other test in this file and break exactly this one.
    """
    hits = _alerts(_snap([], prev_cap), _snap(["T1"], curr_cap))
    assert hits
    assert all(lvl == "INFO" for lvl, _m in hits), (prev_cap, curr_cap, hits)


def test_a_truthy_non_bool_does_not_count_as_complete():
    """`is False` is strict on purpose. A snapshot carrying something odd in that slot is a
    damaged record, and a damaged record must not be read as proof of a complete replay."""
    hits = _alerts(_snap([], "no"), _snap(["T1"], "no"))
    assert all(lvl == "INFO" for lvl, _m in hits), hits


# ------------------------------------------------------------------ the floor

def test_nothing_newly_fired_is_silent_even_when_complete():
    """The false-positive floor. Without it, every assertion above is satisfied by an arm
    that fires on every run."""
    assert not _alerts(_snap(["T1"], False), _snap(["T1"], False))


def test_a_detector_that_stopped_firing_is_not_this_arm():
    """Scope control. This task changes the newly-fired direction only; a pattern that
    disappeared must not start paging as a side effect."""
    assert not [m for lvl, m in _alerts(_snap(["T1"], False), _snap([], False))
                if lvl == "MEDIUM"]


def test_the_layer_not_running_is_still_a_note_not_an_alert():
    """The arm sits inside the "did the behavioural layer run at all" guard. Splitting the
    severity must not have moved it outside."""
    prev = _snap([], False)
    curr = _snap([], False)
    del curr["behavioral_fired"]
    alerts, notes = diff_with_notes(prev, curr)
    assert not [m for _lvl, m in alerts if _MARK in m], alerts
    assert [s for _c, s in notes if "was not examined this run" in s], notes


# ------------------------------------------------------------------ the exit code

def _rc(prev: dict, curr: dict, threshold: str) -> bool:
    """Whether the recipe's own threshold would page on this diff.

    Ranked with `cli._SEVERITY_RANK`, the real table the exit-code arm uses, rather than a
    local copy — a private import, which this suite does by design (no `__all__` on the
    package's modules). Worth noting what that table contains: CRITICAL/HIGH/MEDIUM/LOW and
    **not INFO**, so `.get("INFO", -1)` is below every threshold. That is the mechanism by
    which the old wording could never page, and it is why moving this arm to MEDIUM is the
    whole fix rather than a cosmetic relabel.
    """
    from clawseccheck.cli import _SEVERITY_RANK
    alerts, _notes = diff_with_notes(prev, curr)
    rank = _SEVERITY_RANK[threshold.upper()]
    return any(_SEVERITY_RANK.get(lvl, -1) >= rank for lvl, _ in alerts)


def test_a_complete_replay_reaches_the_shipped_threshold():
    """The whole point, asserted where it actually matters. `--fail-on medium` is what the
    emitted cron job uses, so this is the difference between a human hearing about it and
    not."""
    assert _rc(_snap([], False), _snap(["T1"], False), "medium")


def test_a_capped_replay_does_not_reach_it():
    assert not _rc(_snap([], True), _snap(["T1"], False), "medium")


# ------------------------------------------------------------------ end to end, for real

def test_the_paging_branch_is_reachable_through_the_real_cli(tmp_path):
    """**This test exists because the claim it replaces was wrong.**

    F-182 shipped saying the MEDIUM branch "has fixture evidence only, and structurally
    cannot have more — the real machine is always capped, so no run on this fleet can
    exercise it." The first half is true of *this machine's* OpenClaw home. The second half
    was an overstatement: `files_capped` is a property of how much recorded activity a home
    holds, not of the fleet, and a home with little of it replays in full.

    Measured through the real `audit()` + `behavioral.analyze()` path:

        ~/.openclaw                 files_capped=True
        fixtures/home_safe          files_capped=False
        fixtures/traj_outcome_anomaly  files_capped=False, fired=['T2']

    So the branch that decides whether a human is woken about what their agent actually DID
    is reachable end to end, and asserting it only against hand-built snapshot dicts was
    leaving the strongest available evidence on the table.

    The two runs use one home, with the trajectory appearing between them — which is what
    "a detector newly fired" means in the field, rather than two different homes compared.
    """
    home, store = tmp_path / "home", tmp_path / "store"
    sessions = home / "agents" / "main" / "sessions"
    sessions.mkdir(parents=True)
    store.mkdir()
    cfg = home / "openclaw.json"
    cfg.write_text(json.dumps({
        "gateway": {"bind": "127.0.0.1:8080",
                    "auth": {"mode": "token", "token": "a-very-long-token-of-32-chars!!"}},
    }), encoding="utf-8")
    os.chmod(cfg, 0o600)

    rc0, out0 = _cli(home, store)
    assert rc0 == 0, out0

    src = Path("fixtures/traj_outcome_anomaly/agents/main/sessions/s1.trajectory.jsonl")
    (sessions / "s1.trajectory.jsonl").write_text(src.read_text(encoding="utf-8"),
                                                 encoding="utf-8")

    rc, out = _cli(store=store, home=home, extra=("--exit-code", "--fail-on", "medium"))
    assert _MARK in out, out
    assert "actually did" in out, (
        "the paging wording is expected here: both replays were complete\n" + out)
    assert rc == 3, (
        "an uncapped replay that newly fired a detector must reach the shipped "
        f"cron recipe's threshold\n{out}")


def test_the_same_case_stays_advisory_when_the_replay_was_capped(tmp_path):
    """The positive control's mirror, also end to end. Same home, same newly-fired
    detector, only the recorded cap flag differs — so a failure here means the severity is
    keyed on something other than the flag."""
    home, store = tmp_path / "home", tmp_path / "store"
    sessions = home / "agents" / "main" / "sessions"
    sessions.mkdir(parents=True)
    store.mkdir()
    cfg = home / "openclaw.json"
    cfg.write_text(json.dumps({
        "gateway": {"bind": "127.0.0.1:8080",
                    "auth": {"mode": "token", "token": "a-very-long-token-of-32-chars!!"}},
    }), encoding="utf-8")
    os.chmod(cfg, 0o600)
    _cli(home, store)

    # Rewrite the stored baseline as a capped one. The alternative — generating enough
    # activity to really hit the cap — would make this test slow and its premise fragile.
    state = json.loads((store / "state.json").read_text(encoding="utf-8"))
    state["behavioral_capped"] = True
    (store / "state.json").write_text(json.dumps(state), encoding="utf-8")

    src = Path("fixtures/traj_outcome_anomaly/agents/main/sessions/s1.trajectory.jsonl")
    (sessions / "s1.trajectory.jsonl").write_text(src.read_text(encoding="utf-8"),
                                                  encoding="utf-8")
    rc, out = _cli(store=store, home=home, extra=("--exit-code", "--fail-on", "medium"))
    assert _MARK in out, "the pattern must still be reported, just not at paging severity"
    assert "newly seen rather than newly done" in out, out
    assert rc == 0, out
