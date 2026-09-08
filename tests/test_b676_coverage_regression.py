"""CLAWSECCHECK-B-676 — the watch getting quieter is itself drift.

`--monitor` computed `fully_compared` and a list of `notes` naming every comparison it
declined to make, and neither reached the exit code the published cron recipe branches on.
The two fixes the task proposed both rested on `fully_compared` carrying information, and
it does not: measured over five consecutive runs of an unchanged `fixtures/home_safe` and
five more over a real machine, it is False on every run, because three of the standing
notes are permanent structural conditions (an unreadable crontab spool, five of seven host
classes `unknown`, a rotating behavioural window). An always-false flag is not a signal.

What carries information is the DELTA: the note set is byte-stable run to run, so a
comparison the watch made last time and cannot make now is a real event. This file pins
that, both halves — silence in the steady state and an alert on a genuine loss.

Offline, read-only, stdlib only. Nothing here writes outside pytest's tmp_path.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from clawseccheck.monitor import (
    WATCHED_DIMENSIONS,
    _COVERAGE_ALREADY_ANNOUNCED,
    _COVERAGE_MAX_ENTRIES,
    _COVERAGE_NAME_CAP,
    _coverage_key,
    _coverage_signature,
    _diff_coverage,
)
from clawseccheck.monitordims._shared import (
    NOTE_CONFIG_BLIND,
    NOTE_INSPECTION_CAPPED,
    NOTE_UNDETERMINED,
)
from clawseccheck.monitorstore import _REFERENCE_VOLATILE_KEYS

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "fixtures"


# ---------------------------------------------------------------- the signature


def test_a_count_inside_a_sentence_is_not_a_coverage_change():
    """"5 security tool(s) could not be confirmed" becoming 6 is the SAME comparison being
    skipped for the same reason. Without this the arm would fire every time a machine
    gained or lost a security tool, which is not a coverage event at all."""
    five = [(NOTE_UNDETERMINED, "5 security tool(s) could not be confirmed as running.")]
    six = [(NOTE_UNDETERMINED, "6 security tool(s) could not be confirmed as running.")]
    assert _coverage_signature(five) == _coverage_signature(six)


def test_a_different_reason_is_a_different_entry():
    """Anti-vacuity for the test above: normalization must not collapse everything."""
    a = [(NOTE_UNDETERMINED, "5 security tool(s) could not be confirmed.")]
    b = [(NOTE_UNDETERMINED, "5 startup location(s) could not be read.")]
    assert _coverage_signature(a) != _coverage_signature(b)


def test_the_category_is_part_of_the_identity():
    """The same sentence under two categories is two different skipped comparisons."""
    assert _coverage_key(NOTE_UNDETERMINED, "x") != _coverage_key(NOTE_INSPECTION_CAPPED, "x")


def test_an_already_announced_category_is_excluded_from_the_signature():
    """A blind run raises its own HIGH naming exactly what was not evaluated, and the
    config_blind notes are that sentence broken up. Measured before this exclusion: the
    identical fact was reported five times in one run."""
    assert NOTE_CONFIG_BLIND in _COVERAGE_ALREADY_ANNOUNCED
    blind = [(NOTE_CONFIG_BLIND, "Your connections were not compared.")]
    assert _coverage_signature(blind) == []


def test_the_signature_is_sorted_and_capped():
    notes = [(NOTE_UNDETERMINED, f"reason {chr(97 + i)}") for i in range(_COVERAGE_MAX_ENTRIES + 10)]
    sig = _coverage_signature(notes)
    assert sig == sorted(sig)
    assert len(sig) == _COVERAGE_MAX_ENTRIES


def test_malformed_note_entries_are_skipped_not_raised():
    """`notes` is built by seventeen dimension modules; one malformed pair must not take a
    monitor run down — the same discipline `record_events` applies."""
    assert _coverage_signature([None, (), ("only-one",), (NOTE_UNDETERMINED, "ok")]) == [
        _coverage_key(NOTE_UNDETERMINED, "ok")
    ]


# ---------------------------------------------------------------- the arm


def _arm(prev, curr, notes):
    alerts, emitted = [], []
    _diff_coverage(prev, curr, notes, alerts, lambda c, m: emitted.append((c, m)))
    return alerts, emitted


def _snap(not_compared=None, watched=("a", "b")):
    out = {"watched": list(watched)}
    if not_compared is not None:
        out["not_compared"] = not_compared
    return out


def test_an_identical_note_set_produces_nothing():
    notes = [(NOTE_UNDETERMINED, "3 things could not be determined.")]
    prev = _snap(_coverage_signature(notes))
    assert _arm(prev, _snap(), notes) == ([], [])


def test_a_lost_comparison_alerts_at_medium():
    was = [(NOTE_UNDETERMINED, "old reason")]
    now = was + [(NOTE_INSPECTION_CAPPED, "a cap started biting")]
    alerts, _ = _arm(_snap(_coverage_signature(was)), _snap(), now)
    assert len(alerts) == 1
    severity, message = alerts[0]
    assert severity == "MEDIUM"
    assert "a cap started biting" in message


def test_a_regained_comparison_is_silent():
    """Coverage IMPROVING is not an event to page anyone about, and reporting it would
    double the noise for nothing."""
    was = [(NOTE_UNDETERMINED, "a"), (NOTE_UNDETERMINED, "b")]
    now = [(NOTE_UNDETERMINED, "a")]
    assert _arm(_snap(_coverage_signature(was)), _snap(), now) == ([], [])


def test_no_prior_record_is_silent():
    """A baseline predating this key, or written by a run that compared nothing. Reporting
    here is the 0 -> 4 step measured between the first and second run of an unchanged
    home, and that step is not drift."""
    notes = [(NOTE_UNDETERMINED, "anything")]
    assert _arm(_snap(None), _snap(), notes) == ([], [])
    assert _arm(_snap("not-a-list"), _snap(), notes) == ([], [])


def test_a_changed_watched_manifest_stands_down_with_a_note():
    """A build that adds a note kind changes the note set without the machine moving."""
    was = [(NOTE_UNDETERMINED, "a")]
    now = was + [(NOTE_UNDETERMINED, "a brand new kind of note")]
    alerts, emitted = _arm(
        _snap(_coverage_signature(was), watched=("a", "b")),
        _snap(watched=("a", "b", "c")),
        now,
    )
    assert alerts == []
    assert len(emitted) == 1 and "updated" in emitted[0][1]


def test_many_losses_are_capped_and_the_remainder_counted():
    """A burst of twenty alerts about the watch getting quieter would bury the drift alerts
    they sit beside — so the cap is stated in the output rather than applied silently."""
    # Letters, not digits: `f"reason {i}"` collapses to ONE entry, because the signature
    # normalizes numbers out on purpose. That is the arm working, and it cost this test a
    # red run to notice — worth keeping the reason next to the data.
    now = [(NOTE_UNDETERMINED, f"lost reason {chr(97 + i)}")
           for i in range(_COVERAGE_NAME_CAP + 4)]
    alerts, _ = _arm(_snap([]), _snap(), now)
    assert len(alerts) == _COVERAGE_NAME_CAP + 1
    assert f"{4} further comparison(s)" in alerts[-1][1]


def test_a_non_dict_baseline_never_raises():
    for bad in (None, [], "x", 42):
        assert _arm(bad, _snap(), [(NOTE_UNDETERMINED, "a")]) == ([], [])


# ---------------------------------------------------------------- wiring


def test_the_key_is_declared_and_excluded_from_the_baseline_reference():
    """Both halves of the plumbing, pinned together.

    Declared, or the C-417 manifest guard would report it as read-but-not-declared. And
    excluded from `snapshot_reference`, because the key is absent on the first run of a new
    baseline and present on the second — leaving it in moved the reference on an untouched
    machine and journaled a witness event for it, breaking three F-173 invariants."""
    assert "not_compared" in WATCHED_DIMENSIONS
    assert "not_compared" in _REFERENCE_VOLATILE_KEYS


def test_the_arm_is_called_from_the_shell_not_from_diff_with_notes():
    """The CALL SITE, not the helper. Three of the note appends happen in `cli.py` after
    `diff_with_notes` returns — the re-vet overflow, the history-write failure and the
    re-vet cap — so an arm one level down would compare against an incomplete note set and
    report those three as newly lost on the following run. A test that only exercised
    `_diff_coverage` would stay green with the call deleted."""
    cli = (REPO / "clawseccheck" / "cli.py").read_text(encoding="utf-8")
    monitor = (REPO / "clawseccheck" / "monitor.py").read_text(encoding="utf-8")
    assert "_diff_coverage(prev, snap, monitor_notes, alerts" in cli
    assert '_coverage_now = _coverage_signature(monitor_notes)' in cli
    assert "_diff_coverage(" not in monitor.split("def diff_with_notes")[-1]


def test_the_signature_is_taken_before_the_arm_runs():
    """Otherwise a note the arm itself emits (the post-upgrade stand-down, the cap
    disclosure) is recorded as a comparison this run skipped — it would read as newly lost
    on the next run and vanish the run after."""
    cli = (REPO / "clawseccheck" / "cli.py").read_text(encoding="utf-8")
    before = cli.index("_coverage_now = _coverage_signature(monitor_notes)")
    call = cli.index("_diff_coverage(prev, snap, monitor_notes, alerts")
    assert before < call


# ---------------------------------------------------------------- end to end


def _run(home, store, *extra):
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck.cli", "--monitor", "--json",
         "--home", str(home), "--data-dir", str(store), *extra],
        cwd=REPO, capture_output=True, text=True,
    )


def _payload(res):
    return json.loads(res.stdout)


@pytest.fixture()
def home(tmp_path):
    h = tmp_path / "home"
    shutil.copytree(FIXTURES / "home_safe", h)
    os.chmod(h / "openclaw.json", 0o600)
    return h


def test_five_runs_over_an_unchanged_home_raise_nothing(home, tmp_path):
    """The negative control, through the real CLI. This is the property the whole design
    rests on: on an unchanged machine the same comparisons are skipped for the same
    reasons, so a difference is a real event."""
    store = tmp_path / "store"
    for _ in range(5):
        payload = _payload(_run(home, store))
        assert payload["alerts"] == [], payload["alerts"]


def test_the_key_appears_only_once_there_is_a_usable_baseline(home, tmp_path):
    store = tmp_path / "store"
    _run(home, store)
    first = json.loads((store / "state.json").read_text(encoding="utf-8"))
    assert "not_compared" not in first, "a run that compared nothing must record nothing"
    _run(home, store)
    second = json.loads((store / "state.json").read_text(encoding="utf-8"))
    assert isinstance(second.get("not_compared"), list) and second["not_compared"]


def test_a_real_coverage_loss_reaches_the_exit_code(home, tmp_path):
    """End to end, through the real CLI, including `--fail-on medium` and the exit code a
    cron job reads — which is the whole point of the task.

    The loss is genuine and is not otherwise announced: a second skill that declares no
    version means the watch can no longer compare version numbers for it. The alert lands
    on the run AFTER the skill first appears, because the version note only fires for
    skills present on both sides."""
    store = tmp_path / "store"
    skills = home / "workspace" / "skills"
    (skills / "base").mkdir(parents=True)
    (skills / "base" / "SKILL.md").write_text(
        "---\nname: base\nversion: 1.0.0\ndescription: baseline helper\n---\n\nHelper.\n",
        encoding="utf-8")
    _run(home, store)
    _run(home, store)
    assert _payload(_run(home, store))["alerts"] == [], "not steady before the change"

    (skills / "noversion").mkdir()
    (skills / "noversion" / "SKILL.md").write_text(
        "---\nname: noversion\ndescription: declares no version\n---\n\nHelper.\n",
        encoding="utf-8")
    _run(home, store)  # the skill appears; the version note cannot fire yet

    res = subprocess.run(
        [sys.executable, "-m", "clawseccheck.cli", "--monitor", "--json",
         "--home", str(home), "--data-dir", str(store),
         "--exit-code", "--fail-on", "medium"],
        cwd=REPO, capture_output=True, text=True)
    payload = json.loads(res.stdout)
    lost = [a for a in payload["alerts"]
            if "could not make a comparison it made at the last check" in a["message"]]
    assert len(lost) == 1, payload["alerts"]
    assert lost[0]["severity"] == "MEDIUM"
    assert res.returncode == 3, "the coverage regression must reach the exit code"


def test_a_blind_run_reports_the_fact_once(home, tmp_path):
    """The duplication this arm was measured into avoiding: before `config_blind` was
    excluded, an unreadable config produced the HIGH plus four MEDIUMs restating it."""
    store = tmp_path / "store"
    _run(home, store)
    _run(home, store)
    (home / "openclaw.json").write_text("{ this is not json", encoding="utf-8")
    os.chmod(home / "openclaw.json", 0o600)
    alerts = _payload(_run(home, store))["alerts"]
    assert len(alerts) == 1, alerts
    assert "Could not read openclaw.json" in alerts[0]["message"]
