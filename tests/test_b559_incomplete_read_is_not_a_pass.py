"""B-559: T1/T2 answer UNKNOWN, not PASS, when the trajectory log was not read in full.

Both detectors gated only on the sidecar EXISTING, so they returned PASS over an empty or
capped event set — "no thread shows an ingress -> sensitive -> egress sequence" is
trivially true when there are no threads. Golden Rule #4 is explicit that a check which
cannot determine state reports UNKNOWN rather than a fake PASS; T3 and B191 already did
exactly that on the same input, so this is the module's own precedent, not a new rule.

The disclosure was already there — the renderer prints "Results are INCOMPLETE (treat as
UNKNOWN, not authoritative)" directly above the tick (B-245). This moves that fact into
the verdict, where a reader who skims the ticks still meets it.

## The asymmetry this file exists to pin

Only the CLEAN branch is gated. A firing detector stays WARN however much went unread: the
sequence was observed, and demoting an observation because the rest of the history was
capped would turn a real finding into silence. That is the false negative a fix in this
direction introduces if it is written carelessly, and
`test_a_firing_detector_survives_an_incomplete_read` is the guard.

## Measured before landing — four host shapes, both trees

    host shape   tree     T1        T2        T3        B191      cap signal
    clean        before   PASS      PASS      UNKNOWN   UNKNOWN   []
    clean        after    PASS      PASS      UNKNOWN   UNKNOWN   []
    empty        before   PASS      PASS      UNKNOWN   UNKNOWN   []
    empty        after    UNKNOWN   UNKNOWN   UNKNOWN   UNKNOWN   []
    capped       before   PASS      PASS      UNKNOWN   UNKNOWN   []
    capped       after    UNKNOWN   UNKNOWN   UNKNOWN   UNKNOWN   []
    nosidecar    before   -         -         -         UNKNOWN   []
    nosidecar    after    -         -         -         UNKNOWN   []

`clean` is the row that matters as much as the changed ones: "looked and found nothing"
must keep reading as PASS, or the fix has traded one wrong answer for another.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from clawseccheck import behavioral as B
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
TRAJ_HOME = FIXTURES / "traj_present_not_acted"
FIRING_HOME = FIXTURES / "traj_behavioral_trifecta"

# `read_events` caps at 60 files; 70 copies puts any home past it.
_PAST_THE_FILE_CAP = 70


def _statuses(home: Path) -> dict:
    return {f.id: f.status for f in B.analyze(collect(home))["findings"]}


def _copy(tmp_path: Path, src: Path, name: str = "home") -> Path:
    home = tmp_path / name
    shutil.copytree(src, home)
    return home


def _make_capped(home: Path) -> Path:
    """Duplicate the home's sidecar past the per-file cap, preserving its content — so
    the only thing that changes is whether every session could be read."""
    sidecars = sorted(home.rglob("*.trajectory.jsonl"))
    body = sidecars[0].read_text(encoding="utf-8")
    for i in range(_PAST_THE_FILE_CAP):
        (sidecars[0].parent / f"pad{i}.trajectory.jsonl").write_text(body, encoding="utf-8")
    return home


def _make_unparseable(home: Path) -> Path:
    for sidecar in home.rglob("*.trajectory.jsonl"):
        sidecar.write_text('{"schemaVersion": 99}\n', encoding="utf-8")
    return home


# ------------------------------------------------------- the predicate, on its own


def test_a_complete_read_reports_no_incompleteness():
    assert B.analysis_incompleteness(B.analyze(collect(TRAJ_HOME))) is None


def test_every_flag_analyze_reports_produces_a_reason():
    """Each alone must be enough. Named individually so a signal that stops being read
    fails here rather than silently letting a partial read claim a verdict."""
    base = {"present": True, "event_count": 5, "truncated": False,
            "files_capped": False, "unknown_version": False,
            "files_scanned": 78, "files_total": 78}
    assert B.analysis_incompleteness(base) is None
    for flag in ("truncated", "files_capped", "unknown_version"):
        assert B.analysis_incompleteness({**base, flag: True}), flag
    for absent in ("present", "event_count"):
        assert B.analysis_incompleteness({**base, absent: 0}), absent
    # A file the reader could not OPEN raises no flag at all — it is only visible as a
    # gap between the two counts. Found by the C-135 pass, which hid a real trifecta in
    # a mode-000 sidecar and got PASS.
    assert B.analysis_incompleteness({**base, "files_scanned": 77}), "unreadable file"


def test_a_file_that_could_not_be_opened_is_not_a_pass(tmp_path):
    """End to end, with a real trifecta in the file that cannot be read: the run must
    not answer PASS for a session it never opened."""
    home = _copy(tmp_path, TRAJ_HOME)
    sessions = sorted(home.rglob("*.trajectory.jsonl"))[0].parent
    shutil.copy(FIRING_HOME / "agents/main/sessions/s1.trajectory.jsonl",
                sessions / "hidden.trajectory.jsonl")
    (sessions / "hidden.trajectory.jsonl").chmod(0o000)
    try:
        result = B.analyze(collect(home))
        assert result["files_scanned"] != result["files_total"], result
        statuses = {f.id: f.status for f in result["findings"]}
        assert statuses["T1"] == "UNKNOWN", statuses
        assert statuses["T2"] == "UNKNOWN", statuses
    finally:
        # Restore the mode so pytest's tmp_path teardown can remove it.
        (sessions / "hidden.trajectory.jsonl").chmod(0o600)


def test_the_capped_reason_names_the_counts_a_reader_can_check():
    reason = B.analysis_incompleteness(
        {"present": True, "event_count": 5, "files_capped": True,
         "files_scanned": 60, "files_total": 78})
    assert "60" in reason and "78" in reason, reason


# ----------------------------------------------------------------- the no-regression row


def test_a_complete_read_that_finds_nothing_still_passes(tmp_path):
    """"Looked and found nothing" is a verdict and must keep reading as one. If this
    turns UNKNOWN the fix has traded a fake PASS for a useless one."""
    statuses = _statuses(_copy(tmp_path, TRAJ_HOME))
    assert statuses["T1"] == "PASS", statuses
    assert statuses["T2"] == "PASS", statuses


# ------------------------------------------------------------------ the fake PASS, closed


def test_an_empty_event_set_is_not_a_pass(tmp_path):
    statuses = _statuses(_make_unparseable(_copy(tmp_path, TRAJ_HOME)))
    assert statuses["T1"] == "UNKNOWN", statuses
    assert statuses["T2"] == "UNKNOWN", statuses


def test_a_capped_read_is_not_a_pass(tmp_path):
    """The common real shape: a long-lived install with more sessions than the file cap.
    Before this, such a host got a tick under a line saying the results were INCOMPLETE."""
    home = _make_capped(_copy(tmp_path, TRAJ_HOME))
    assert B.analyze(collect(home))["files_capped"] is True
    statuses = _statuses(home)
    assert statuses["T1"] == "UNKNOWN", statuses
    assert statuses["T2"] == "UNKNOWN", statuses


def test_the_unknown_finding_says_why_and_does_not_claim_a_clean_log(tmp_path):
    home = _make_capped(_copy(tmp_path, TRAJ_HOME))
    t1 = next(f for f in B.analyze(collect(home))["findings"] if f.id == "T1")
    assert t1.status == "UNKNOWN"
    assert "what was read" in t1.detail, t1.detail
    assert "not a clean result" in t1.detail, t1.detail


# ----------------------------------------------- the false negative this could introduce


def test_a_firing_detector_survives_an_incomplete_read(tmp_path):
    """**The guard.** A trifecta observed in the sessions that WERE read is a finding, and
    an incomplete read is not grounds to withdraw it. Demoting it would let an attacker
    silence a real detection by making the log long enough to hit the file cap."""
    home = _make_capped(_copy(tmp_path, FIRING_HOME))
    result = B.analyze(collect(home))
    assert result["files_capped"] is True, "fixture no longer exercises the capped path"
    statuses = {f.id: f.status for f in result["findings"]}
    assert statuses["T1"] == "WARN", statuses


def test_the_grade_cap_signal_survives_an_incomplete_read(tmp_path):
    """The cap is the only route these detectors have to the score (F-154). If an
    incomplete read dropped it, capping the log would buy back a grade."""
    home = _make_capped(_copy(tmp_path, FIRING_HOME))
    assert "T1" in B.grade_cap_signal(B.analyze(collect(home)))


def test_a_clean_run_signals_no_cap_before_or_after(tmp_path):
    assert B.grade_cap_signal(B.analyze(collect(_copy(tmp_path, TRAJ_HOME)))) == frozenset()


# ------------------------------------------------------------------ the caller contract


def test_the_detectors_default_to_the_pre_b559_contract():
    """`incomplete` defaults to None, so every existing caller — and the detectors' own
    unit tests — keep the old behaviour without being told about this parameter."""
    assert B.check_behavioral_trifecta({}).status == "PASS"
    assert B.check_outcome_anomaly({}).status == "PASS"
    assert B.check_behavioral_trifecta({}, incomplete="reason").status == "UNKNOWN"
    assert B.check_outcome_anomaly({}, incomplete="reason").status == "UNKNOWN"
