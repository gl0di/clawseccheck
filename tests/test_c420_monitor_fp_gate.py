"""C-420 — guards for the monitor false-positive gate (``scripts/monitor_fp_gate.py``).

The gate answers one question: two snapshots of an unchanged home must diff to nothing.
Its own correctness cannot be checked against the real home in CI — there isn't one — so
everything here runs on synthetic homes under ``tmp_path``, which is also what makes the
"one known change produces exactly one alert" direction testable at all.

**Why the gate needed to exist.** `scripts/fleet_fp_gate.py` guards check FAILs. Nothing
guarded monitor ALERTS, so every dimension the watch epic added landed with only a
per-task C-135 pass behind it — a human act that does not re-run on the next commit. Two
false-positive classes had already been found by hand during design (`meta.lastTouched*`
firing on every upgrade; B191 divergence under a rotated trajectory cap firing forever),
and both are the kind a mechanical gate catches for free.

**The assertion is on alerts, never notes.** A note (C-418) records a comparison the run
declined to make. On a healthy machine there are several, and counting them as false
positives would make the gate red on a correct setup — so a test pins that too, or the
distinction survives only as a comment.

Offline, writes nothing outside ``tmp_path``, stdlib only.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = REPO_ROOT / "scripts" / "monitor_fp_gate.py"


def _load_gate():
    spec = importlib.util.spec_from_file_location("_monitor_fp_gate", GATE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


def _home(tmp_path: Path, **config) -> Path:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    cfg = home / "openclaw.json"
    cfg.write_text(json.dumps(config or {"gateway": {"bind": "127.0.0.1"}}),
                   encoding="utf-8")
    os.chmod(cfg, 0o600)
    return home


# ---------------------------------------------------------------- the core question

def test_an_unchanged_home_produces_no_alert(tmp_path):
    result = gate.check(str(_home(tmp_path)))
    assert result["alerts"] == [], result["alerts"]
    assert result["comparable"] is True


def test_notes_are_expected_and_do_not_count_as_false_positives(tmp_path):
    """The distinction the whole gate rests on. A run with notes and no alerts is a
    PASS — if notes counted, the gate would be red on every healthy machine."""
    result = gate.check(str(_home(tmp_path)))
    text, code = gate.render(result)
    assert code == 0, text
    assert "OK:" in text
    assert "note" in text, "the note count must be reported, not silently dropped"


def test_a_real_change_produces_exactly_one_alert(tmp_path):
    """The other direction: a gate that cannot fire is decoration. Builds the two
    snapshots by hand so the change lands between them."""
    home = _home(tmp_path, gateway={"bind": "127.0.0.1", "authToken": "t" * 24})
    first, _ = gate.build_one(str(home))

    cfg = home / "openclaw.json"
    cfg.write_text(json.dumps({"gateway": {"bind": "0.0.0.0"}}), encoding="utf-8")
    os.chmod(cfg, 0o600)
    second, _ = gate.build_one(str(home), prev=first)

    from clawseccheck.monitor import diff_with_notes
    alerts, _notes = diff_with_notes(first, second)
    assert alerts, "binding the gateway to 0.0.0.0 must raise something"
    assert any("0.0.0.0" in m or "bind" in m.lower() for _lvl, m in alerts), alerts


# ---------------------------------------------------------------- the harness contract

def test_the_second_snapshot_is_built_against_the_first(tmp_path):
    """B-269: `snapshot()` takes the previous state to repair a blind run, so a pair
    built independently would be answering an easier question than the watch does."""
    home = _home(tmp_path)
    first, _ = gate.build_one(str(home))
    second, _ = gate.build_one(str(home), prev=first)
    assert first.get("watched") == second.get("watched")
    assert second.get("ts") is not None


def test_the_gate_writes_nothing_anywhere(tmp_path, monkeypatch):
    """The task asked for state/events/history to be redirected away from
    ~/.clawseccheck/. Going through the library means there is nothing to redirect —
    pinned, because a later refactor routing this back through the CLI would silently
    start writing to the user's real drift state."""
    home = _home(tmp_path)
    sentinel = tmp_path / "must-stay-empty"
    sentinel.mkdir()
    monkeypatch.setenv("HOME", str(sentinel))
    before = sorted(p.name for p in tmp_path.iterdir())
    gate.check(str(home))
    assert sorted(p.name for p in tmp_path.iterdir()) == before
    assert list(sentinel.iterdir()) == [], "the gate wrote into HOME"


def test_a_degraded_run_is_refused_rather_than_judged(tmp_path):
    """Reuses fleet_fp_gate's rule: a degraded run can lose a signal, so neither an
    alert nor its absence means anything. Refusal is exit 2, distinct from a failure."""
    result = dict(gate.check(str(_home(tmp_path))))
    result["degraded_checks"] = ["ERR:B1"]
    result["comparable"] = False
    text, code = gate.render(result)
    assert code == 2
    assert "REFUSED" in text and "ERR:B1" in text


def test_alerts_exit_one_and_name_every_one(tmp_path):
    result = {"version": "9.9.9", "comparable": True, "note_count": 0,
              "degraded_checks": [],
              "alerts": [{"level": "HIGH", "message": "something moved"},
                         {"level": "MEDIUM", "message": "something else moved"}]}
    text, code = gate.render(result)
    assert code == 1
    assert "FALSE POSITIVES: 2" in text
    assert "something moved" in text and "something else moved" in text


def test_the_degraded_helper_is_the_fleet_gates_own(tmp_path):
    """The task said reuse rather than reimplement — a second copy of "what counts as
    degraded" is a second thing to keep in step."""
    import importlib.util as _u
    spec = _u.spec_from_file_location("_fleet_fp_gate_probe",
                                      REPO_ROOT / "scripts" / "fleet_fp_gate.py")
    fleet = _u.module_from_spec(spec)
    spec.loader.exec_module(fleet)
    assert gate.degraded_checks is fleet.degraded_checks or (
        gate.degraded_checks.__name__ == fleet.degraded_checks.__name__
        and gate.degraded_checks.__module__.endswith("fleet_fp_gate")
    )


# ---------------------------------------------------------------- dimension coverage

def test_the_gate_exercises_every_dimension_the_cli_snapshots(tmp_path):
    """A gate blind to the dimensions the epic keeps adding is the one failure mode it
    cannot afford. Asserted structurally against the snapshot's own manifest rather than
    a hand-kept list, so a new dimension is covered the day it is declared."""
    from clawseccheck.monitor import WATCHED_DIMENSIONS
    snap, _ = gate.build_one(str(_home(tmp_path)))
    assert snap.get("watched") == list(WATCHED_DIMENSIONS)
    source = GATE_PATH.read_text(encoding="utf-8")
    for kwarg in ("behavioral=", "install=", "provenance=", "prev="):
        assert kwarg in source, f"the gate does not pass {kwarg} to snapshot()"
