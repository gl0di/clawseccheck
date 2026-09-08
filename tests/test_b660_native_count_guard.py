"""B-660 — the native-audit counter must not report the tool's absence as a rising count.

`native_count` is `len(native.findings) if native else 0`, and `_num` defaults a missing key
to `0`. The arm that compared the two therefore could not tell "the native audit did not run
last time" from "the native audit found fewer problems last time" — it was the one arm in
`diff()` gated on neither `_same_scope_flags` nor the `watched` manifest.

Two fabricating inputs, both on a machine where nothing moved:

* `--monitor --no-native` and then an ordinary `--monitor`;
* a baseline written before the key existed — `watched` recorded that absence correctly and
  this arm never consulted it.

This is the `_num()`-zero-default shape E-076's architect comment predicted. B-511 closed it
for `score` via `_both_graded`; `native_count` was not given the same treatment, and survived
because the fleet it was measured on reports zero native findings, so `0 > 0` is False.

Why the FP gate could not catch it: `scripts/monitor_fp_gate.py` diffs two snapshots of an
UNCHANGED home taken the SAME way. This defect needs the two runs to differ in *how they were
taken*, which is outside that gate by construction.

`test_a_genuine_rise_is_still_reported` is the positive control. Without it the whole file is
satisfied by deleting the arm, which would trade a false alert for a silent one — the
direction this project treats as worse.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from clawseccheck import monitor

_FULL_SCOPE = ["deptree", "host", "native", "sockets"]
_NO_NATIVE = ["deptree", "host", "sockets"]


def _snap(**kw) -> dict:
    """A minimal snapshot pair that exercises only the native arm.

    `graded` on both sides and equal scores, so the score-drop arm stays silent and any
    alert this file sees is the one it is about.
    """
    base = {
        "version": monitor.SNAPSHOT_VERSION,
        "checks": {},
        "graded": True,
        "score": 50,
        "raw_score": 50,
        "grade": "F",
        "scope": list(_FULL_SCOPE),
        "watched": list(monitor.WATCHED_DIMENSIONS),
    }
    base.update(kw)
    return base


def _native_alerts(prev: dict, curr: dict) -> list[str]:
    return [msg for _lvl, msg in monitor.diff(prev, curr)
            if "openclaw security audit reports" in msg]


def _note_sentences(prev: dict, curr: dict) -> list[str]:
    _alerts, notes = monitor.diff_with_notes(prev, curr)
    return [sentence for _cat, sentence in notes]


# ---------------------------------------------------------------- the fabrications

def test_a_run_taken_with_no_native_does_not_make_the_next_run_report_a_rise():
    """The filed repro: `--no-native` once, then an ordinary run, nothing on the machine
    moved. `prev` holds 0 because the tool did not run, not because it found nothing."""
    prev = _snap(native_count=0, scope=list(_NO_NATIVE))
    curr = _snap(native_count=7, scope=list(_FULL_SCOPE))
    assert _native_alerts(prev, curr) == [], (
        "a scope change alone reported the native audit as finding more issues")


def test_a_baseline_predating_the_key_does_not_report_a_rise():
    """An upgrade migration. The `watched` manifest records the absence correctly; the arm
    has to consult it (or presence) rather than reading `_num`'s default as a measurement."""
    prev = _snap(scope=list(_FULL_SCOPE))          # no native_count: the key did not exist
    prev["watched"] = [d for d in monitor.WATCHED_DIMENSIONS if d != "native_count"]
    assert "native_count" not in prev              # the premise, not an assumption
    curr = _snap(native_count=7)
    assert _native_alerts(prev, curr) == [], (
        "a baseline that predates the key reported the whole current count as a rise")


def test_a_corrupted_count_is_skipped_rather_than_coerced():
    """A hand-edited or truncated state file must not become a finding. `True` is excluded
    explicitly: it is an `int` to `isinstance` and `True < 2` compares as 1."""
    for bad in ("7", None, True, [7]):
        prev = _snap(native_count=bad)
        curr = _snap(native_count=7)
        assert _native_alerts(prev, curr) == [], f"a {bad!r} count produced an alert"


# ---------------------------------------------------------------- the positive control

def test_a_genuine_rise_is_still_reported():
    """Same scope on both sides, count really moved. Without this the file would be
    satisfied by deleting the arm, i.e. by trading a false alert for a lost one."""
    prev = _snap(native_count=3)
    curr = _snap(native_count=7)
    assert _native_alerts(prev, curr) == [
        "openclaw security audit reports 4 more issue(s) than last time."]


def test_a_falling_count_is_not_reported_as_a_rise():
    """Direction is part of the claim: fewer issues than last time is not news."""
    assert _native_alerts(_snap(native_count=7), _snap(native_count=3)) == []


def test_an_unchanged_count_says_nothing():
    assert _native_alerts(_snap(native_count=7), _snap(native_count=7)) == []


# ---------------------------------------------------------------- the disclosure

def test_not_comparing_it_is_disclosed_rather_than_silent():
    """C-418's contract: a comparison this run did not make is counted, and named under
    --verbose. Standing the arm down without saying so would swap a false alert for an
    undisclosed blind spot, which is the trade this whole epic exists to refuse."""
    prev = _snap(scope=list(_FULL_SCOPE))          # no native_count on the prev side
    curr = _snap(native_count=7)
    assert any("openclaw security audit" in s for s in _note_sentences(prev, curr)), (
        "the native count was skipped with no note")


def test_a_scope_difference_is_disclosed_too():
    prev = _snap(native_count=0, scope=list(_NO_NATIVE))
    curr = _snap(native_count=7, scope=list(_FULL_SCOPE))
    sentences = _note_sentences(prev, curr)
    assert any("openclaw security audit" in s and "different options" in s
               for s in sentences), sentences


def test_a_comparable_pair_adds_no_note():
    """The disclosure must be scoped to the case that earned it. A note on every run would
    inflate the 'N things could not be compared' count and teach the user to ignore it."""
    sentences = _note_sentences(_snap(native_count=3), _snap(native_count=7))
    assert not any("openclaw security audit" in s for s in sentences), sentences
