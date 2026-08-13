"""B-511 — the watch must not republish a grade the run refused to give.

E-077's headline is "a grade only for a complete check". On the DEFAULT `--monitor` path
it was false, and this is the sequence that showed it — two ordinary runs against the
same home, one auth token removed between them:

```
No grade yet - 3 of 5 layers did not run
[!] Security score dropped: A 97 -> A 96.
```

Both lines in one output. `snapshot()` persisted `score` and `grade` with no record of
whether they were earned, and `diff()` read them straight back out. The same sentence was
chain-hashed into `events.jsonl`, so a withheld number reached the tamper-evident journal
too. `history.jsonl` was the only writer that already declined — its shape is the one
copied here.

**Why the numbers are still persisted.** Nulling them is worse than the bug: `monitor._num()`
defaults an absent score to `0`, so a null baseline would make the next run report a
catastrophic drop on a config where nothing moved — the B-269 fabrication shape. So
`snapshot()` keeps recording them and adds `graded`; `diff()` declines the comparison.

**Why an absent flag reads as ungraded.** A snapshot written between C-426 and this fix is
ungraded and has no `graded` key. Defaulting it to True would let exactly those baselines —
the ones the defect produced — republish their numbers. The cost is one run's score
comparison after upgrading, and then it self-heals; that is the same trade the `raw_score`
backstop already makes for the same reason.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.cli import main
from clawseccheck.monitor import diff_with_notes, load_state

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE = str(FIXTURES / "home_safe")


# ------------------------------------------------------------------ the unit

def _snap(score, grade, **over):
    snap = {"score": score, "grade": grade, "skills": {}, "bootstrap": {},
            "checks": {"B2": "PASS"}}
    snap.update(over)
    return snap


def _levels(prev, curr):
    alerts, _notes = diff_with_notes(prev, curr)
    return [lvl for lvl, _m in alerts]


def _messages(prev, curr):
    alerts, _notes = diff_with_notes(prev, curr)
    return " ".join(m for _lvl, m in alerts)


def test_two_graded_runs_still_report_a_drop():
    """The guard must not become a blanket silence — this is the alert's whole job."""
    prev = _snap(97, "A", graded=True)
    curr = _snap(80, "B", graded=True)
    assert "dropped" in _messages(prev, curr)


def test_an_ungraded_current_run_reports_no_drop():
    prev = _snap(97, "A", graded=True)
    curr = _snap(80, "B", graded=False)
    assert "dropped" not in _messages(prev, curr)


def test_an_ungraded_baseline_reports_no_drop():
    """The direction that actually shipped: every baseline written since C-426."""
    prev = _snap(97, "A", graded=False)
    curr = _snap(80, "B", graded=True)
    assert "dropped" not in _messages(prev, curr)


def test_a_baseline_predating_the_flag_reports_no_drop():
    """No `graded` key at all. Read as ungraded, not assumed graded — those baselines
    are precisely the ones the defect produced."""
    prev = _snap(97, "A")
    curr = _snap(80, "B", graded=True)
    assert "dropped" not in _messages(prev, curr)


def test_the_withheld_numbers_never_appear_in_any_alert():
    """Not merely "no drop alert" — the values must not surface through some other arm."""
    prev = _snap(97, "A", graded=False)
    curr = _snap(80, "B", graded=False)
    text = _messages(prev, curr)
    for token in ("97", "80", "A 97", "B 80"):
        assert token not in text, f"{token!r} leaked into {text!r}"


def test_standing_down_is_a_note_not_an_alert():
    """C-418: a note describes no change, so it must not raise a severity level."""
    prev = _snap(97, "A", graded=False)
    curr = _snap(80, "B", graded=True)
    alerts, notes = diff_with_notes(prev, curr)
    assert not [lvl for lvl, _m in alerts if lvl in ("HIGH", "MEDIUM")]
    assert any("did not earn a grade" in str(n) for n in notes), notes


# ------------------------------------------------------------------ end to end

def test_a_default_monitor_run_records_that_it_earned_nothing(tmp_path, capsys):
    state = tmp_path / "state.json"
    rc = main(["--home", SAFE, "--monitor", "--no-native", "--ascii",
               "--state", str(state), "--events", str(tmp_path / "e.jsonl"),
               "--history", str(tmp_path / "h.jsonl")])
    assert rc in (0, 3)
    capsys.readouterr()
    baseline = load_state(str(state))
    assert baseline["graded"] is False, "the default run does not earn a grade (C-426)"
    assert baseline["score"] is not None, (
        "the number stays recorded on purpose — nulling it makes _num() read 0 and "
        "fabricate a drop on the next run"
    )


def test_the_reported_sequence_no_longer_contradicts_itself(tmp_path, capsys):
    """The measured repro. Two default runs with the config changed between them: the
    output said 'No grade yet' and announced a score drop in the same breath."""
    home = tmp_path / "home"
    home.mkdir()
    cfg = home / "openclaw.json"
    cfg.write_text(json.dumps({"gateway": {"bind": "127.0.0.1", "authToken": "x" * 24}}),
                   encoding="utf-8")
    cfg.chmod(0o600)
    argv = ["--home", str(home), "--monitor", "--no-native", "--ascii",
            "--state", str(tmp_path / "s.json"), "--events", str(tmp_path / "e.jsonl"),
            "--history", str(tmp_path / "h.jsonl")]

    main(argv)
    capsys.readouterr()
    cfg.write_text(json.dumps({"gateway": {"bind": "127.0.0.1"}}), encoding="utf-8")
    cfg.chmod(0o600)
    main(argv)
    out = capsys.readouterr().out

    assert "No grade yet" in out, "precondition: this is an ungraded run"
    assert "Security score dropped" not in out, out
    assert "Grade:" not in out, out


def test_the_journal_does_not_chain_hash_a_withheld_number(tmp_path, capsys):
    """The alert reached events.jsonl, so the withheld value was written into the
    tamper-evident record — the one file whose whole value is that it is trustworthy."""
    home = tmp_path / "home"
    home.mkdir()
    cfg = home / "openclaw.json"
    cfg.write_text(json.dumps({"gateway": {"bind": "127.0.0.1", "authToken": "y" * 24}}),
                   encoding="utf-8")
    cfg.chmod(0o600)
    events = tmp_path / "e.jsonl"
    argv = ["--home", str(home), "--monitor", "--no-native", "--ascii",
            "--state", str(tmp_path / "s.json"), "--events", str(events),
            "--history", str(tmp_path / "h.jsonl")]

    main(argv)
    cfg.write_text(json.dumps({"gateway": {"bind": "127.0.0.1"}}), encoding="utf-8")
    cfg.chmod(0o600)
    main(argv)
    capsys.readouterr()

    if events.exists():
        assert "Security score dropped" not in events.read_text(encoding="utf-8")
