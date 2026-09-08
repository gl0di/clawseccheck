"""F-176 — `--monitor` gets a machine channel: `--json` now emits a payload, and a
boolean says whether every comparison this build knows how to make was actually made.

Two gaps, one task. C-419 already gave `--monitor` an opt-in exit-code channel
(`--exit-code`/`--fail-on`, rc=3 for drift, rc=1 reserved for "monitoring not
established"); this task does not touch it. C-418 already scoped the human report's
all-clear to what was actually compared (`diff_with_notes`'s *notes*); this task puts
that same fact on the machine channel too.

**Completeness definition**, restated here because it is the one testable claim this
file exists to pin: ``fully_compared = base_status == BASELINE_OK and not notes``.
Neither half alone is sufficient — see `clawseccheck/cli.py`'s own comment at the
computation for why "notes empty" alone or "baseline OK" alone each under-count what
"nothing was skipped" actually requires. `test_baseline_absent_notes_empty_is_still_not_
fully_compared` below pins exactly the case a notes-only definition would get wrong.

**Exit-code decision**, also pinned here: completeness carries NO exit-code weight.
`--exit-code`/`--fail-on` remain a pure function of `alerts`/`persisted`, unaffected by
`fully_compared` or `baseline_status` — a fifth "partial" exit code was rejected (it
would need its own opt-in flag, which the task forbids, or it would silently change what
plain `--monitor --exit-code` already returns for an ordinary partial run, breaking the
published cron recipe). `test_exit_code_is_independent_of_completeness` is the direct
regression gate for that decision.

Real `--monitor` runs against a real fixture home are used where they can decide the
question (JSON validity, notes/alerts disjointness, the event journal). The four
completeness x alert combinations and the two boundary "notes-only would be wrong" cases
are driven by monkeypatching `clawseccheck.cli.diff_with_notes`/`read_baseline` (the same
names cli.py imports and calls directly) — a plain, unchanged `--monitor` run is never
"fully compared" today (E-077/C-426 withhold a grade outside `--full`'s deep phases,
which `--monitor` never runs, so the score-comparison note fires on every run with a
prior baseline), so the "complete" side of the boolean can only be exercised this way
without waiting on an unrelated grading change.

Note wording is intentionally NOT asserted verbatim anywhere in this file (a sibling
task is actively rewording the coverage note); assertions match on NOTE category or a
short, stable substring only.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from clawseccheck import cli
from clawseccheck.cli import main
from clawseccheck.monitor import (
    BASELINE_ABSENT,
    BASELINE_OK,
    NOTE_UNDETERMINED,
    diff_with_notes,
    load_events,
)

_SAFE = '{"gateway": {"bind": "127.0.0.1"}}'
_EXPOSED = '{"gateway": {"bind": "0.0.0.0"}}'

_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def _home(tmp_path: Path, body: str = _SAFE, name: str = "home") -> Path:
    home = tmp_path / name
    home.mkdir(exist_ok=True)
    cfg = home / "openclaw.json"
    cfg.write_text(body, encoding="utf-8")
    os.chmod(cfg, 0o600)
    return home


def _store_args(store: Path) -> list:
    return ["--data-dir", str(store)]


def _run_json(home: Path, store: Path, *extra) -> "tuple[int, dict]":
    rc = main(["--monitor", "--json", "--home", str(home), *_store_args(store),
              "--no-native", "--no-update-notice", "--no-freshness-notice", *extra])
    return rc


def _run_text(home: Path, store: Path, *extra) -> int:
    return main(["--monitor", "--home", str(home), *_store_args(store),
                "--no-native", "--no-update-notice", "--no-freshness-notice", *extra])


def _mock(monkeypatch, *, alerts, notes, baseline_status=BASELINE_OK):
    """Force `diff_with_notes`/`read_baseline`/the re-vet loop to a known shape.

    A plain (real) `--monitor` run cannot exercise `fully_compared is True` — see the
    module docstring — so the "complete" side of every test below goes through here.
    Patches the names `clawseccheck/cli.py` actually calls (it imports them by name from
    `.monitor`), not `clawseccheck.monitor`'s own attributes.
    """
    monkeypatch.setattr(cli, "diff_with_notes", lambda prev, curr: (list(alerts), list(notes)))
    monkeypatch.setattr(cli, "read_baseline",
                        lambda path: (baseline_status, {"x": 1} if baseline_status == BASELINE_OK
                                     else None))
    monkeypatch.setattr(cli, "_changed_skills", lambda prev, curr: [])


# ---------------------------------------------------------------- valid JSON + shape

def test_monitor_json_produces_a_valid_payload_with_the_required_keys(tmp_path, capsys):
    home, store = _home(tmp_path), tmp_path / "store"
    _run_json(home, store)
    out = capsys.readouterr().out
    payload = json.loads(out)  # raises if not valid JSON
    for key in ("alerts", "notes", "baseline_status", "persisted", "fully_compared"):
        assert key in payload
    assert payload["baseline_status"] == BASELINE_ABSENT  # first run
    assert payload["persisted"] is True
    assert isinstance(payload["alerts"], list) and isinstance(payload["notes"], list)


def test_json_was_previously_dropped_silently_and_now_is_not(tmp_path, capsys):
    """The exact regression this task fixes: `--monitor --json` used to print the human
    report and a "no effect" note, never JSON."""
    home, store = _home(tmp_path), tmp_path / "store"
    _run_json(home, store)
    out = capsys.readouterr().out
    json.loads(out)  # must parse; the old behaviour printed prose here


# ---------------------------------------------------------------- notes == diff_with_notes

def test_notes_match_diff_with_notes_exactly_on_a_real_run(tmp_path, capsys):
    home, store = _home(tmp_path), tmp_path / "store"
    _run_json(home, store)
    capsys.readouterr()
    snap_a = json.loads((store / "state.json").read_text())
    rc = _run_json(home, store)
    out = capsys.readouterr().out
    payload = json.loads(out)
    snap_b = json.loads((store / "state.json").read_text())
    expected_alerts, expected_notes = diff_with_notes(snap_a, snap_b)
    assert payload["notes"] == [{"category": c, "message": m} for c, m in expected_notes]
    # The real regression corpus for "zero new alerts": this run's alerts must be exactly
    # what `diff_with_notes` computed over the same two snapshots (the CLI's re-vet loop
    # adds nothing here — no skill changed).
    assert payload["alerts"] == [{"severity": s, "message": m} for s, m in expected_alerts]
    assert rc in (0, 3)


# ---------------------------------------------------------------- completeness definition

def test_a_fully_comparable_pair_is_reported_complete_with_empty_notes(tmp_path, capsys,
                                                                        monkeypatch):
    home, store = _home(tmp_path), tmp_path / "store"
    _mock(monkeypatch, alerts=[], notes=[], baseline_status=BASELINE_OK)
    _run_json(home, store)
    payload = json.loads(capsys.readouterr().out)
    assert payload["fully_compared"] is True
    assert payload["notes"] == []


def test_a_skipped_comparison_is_reported_incomplete(tmp_path, capsys, monkeypatch):
    home, store = _home(tmp_path), tmp_path / "store"
    _mock(monkeypatch, alerts=[], notes=[(NOTE_UNDETERMINED, "something was skipped")],
         baseline_status=BASELINE_OK)
    _run_json(home, store)
    payload = json.loads(capsys.readouterr().out)
    assert payload["fully_compared"] is False
    assert len(payload["notes"]) == 1
    assert payload["notes"][0]["category"] == NOTE_UNDETERMINED


def test_baseline_absent_with_empty_notes_is_still_not_fully_compared(tmp_path, capsys,
                                                                       monkeypatch):
    """The boundary case a notes-only definition gets wrong: `diff_with_notes` returns
    NO notes on a first run (by its own design — see its docstring), so `not notes`
    alone would call an empty first run "fully compared". It is not: nothing was
    compared against at all."""
    home, store = _home(tmp_path), tmp_path / "store"
    _mock(monkeypatch, alerts=[], notes=[], baseline_status=BASELINE_ABSENT)
    _run_json(home, store)
    payload = json.loads(capsys.readouterr().out)
    assert payload["notes"] == []
    assert payload["fully_compared"] is False, (
        "a notes-only definition would wrongly report True here")


# ---------------------------------------------------------------- text/JSON agreement

def test_text_and_json_agree_when_fully_compared(tmp_path, capsys, monkeypatch):
    home, store = _home(tmp_path), tmp_path / "store"
    _mock(monkeypatch, alerts=[], notes=[], baseline_status=BASELINE_OK)
    _run_json(home, store)
    payload = json.loads(capsys.readouterr().out)
    _mock(monkeypatch, alerts=[], notes=[], baseline_status=BASELINE_OK)
    _run_text(home, store)
    text = capsys.readouterr().out
    assert payload["fully_compared"] is True
    assert "could not be compared this run" not in text
    assert "No new threats since last check." in text


def test_text_and_json_agree_when_partial(tmp_path, capsys, monkeypatch):
    home, store = _home(tmp_path), tmp_path / "store"
    _mock(monkeypatch, alerts=[], notes=[(NOTE_UNDETERMINED, "x")], baseline_status=BASELINE_OK)
    _run_json(home, store)
    payload = json.loads(capsys.readouterr().out)
    _mock(monkeypatch, alerts=[], notes=[(NOTE_UNDETERMINED, "x")], baseline_status=BASELINE_OK)
    _run_text(home, store)
    text = capsys.readouterr().out
    assert payload["fully_compared"] is False
    assert "could not be compared this run" in text
    assert "No new threats since last check." not in text


# ---------------------------------------------------------------- exit code independence

def test_exit_code_is_independent_of_completeness(tmp_path, capsys, monkeypatch):
    """Pins all four alert x completeness combinations, and the F-176 decision itself:
    completeness carries zero exit-code weight. Only `alerts`/`persisted` do — exactly
    as C-419 left it."""
    home, store = _home(tmp_path), tmp_path / "store"
    cases = [
        (False, False, False),  # no alerts, complete
        (False, False, True),   # no alerts, partial
        (True, True, False),    # alerts,    complete
        (True, True, True),     # alerts,    partial
    ]
    for has_alert, _expect_alert, partial in cases:
        alerts = [("CRITICAL", "boom")] if has_alert else []
        notes = [(NOTE_UNDETERMINED, "x")] if partial else []
        _mock(monkeypatch, alerts=alerts, notes=notes, baseline_status=BASELINE_OK)
        rc_bare = _run_json(home, store)
        capsys.readouterr()
        _mock(monkeypatch, alerts=alerts, notes=notes, baseline_status=BASELINE_OK)
        rc_gated = _run_json(home, store, "--exit-code")
        capsys.readouterr()
        assert rc_bare == 0, (has_alert, partial)
        assert rc_gated == (3 if has_alert else 0), (has_alert, partial)


# ---------------------------------------------------------------- notes disjoint from alerts

def test_no_note_appears_in_the_alerts_array(tmp_path, capsys):
    home, store = _home(tmp_path), tmp_path / "store"
    _run_json(home, store)
    capsys.readouterr()
    _run_json(home, store)  # second run: real notes fire (score/host/behavioral coverage)
    payload = json.loads(capsys.readouterr().out)
    assert payload["notes"], "precondition: this run must actually carry notes"
    note_messages = {n["message"] for n in payload["notes"]}
    alert_messages = {a["message"] for a in payload["alerts"]}
    assert note_messages.isdisjoint(alert_messages)
    assert all(n["category"] not in _SEVERITIES for n in payload["notes"])


def test_no_note_reaches_the_event_journal(tmp_path, capsys):
    home, store = _home(tmp_path), tmp_path / "store"
    _run_json(home, store)
    capsys.readouterr()
    _home(tmp_path, _EXPOSED)  # real drift: a CRITICAL alert this run
    _run_json(home, store)
    payload = json.loads(capsys.readouterr().out)
    assert payload["alerts"], "precondition: this run must carry a real alert"
    assert payload["notes"], "precondition: this run must also carry a note"
    events = load_events(store / "events.jsonl")
    event_messages = {e.get("message") for e in events}
    note_messages = {n["message"] for n in payload["notes"]}
    assert event_messages.isdisjoint(note_messages)
    assert all(e.get("level") in _SEVERITIES for e in events)
