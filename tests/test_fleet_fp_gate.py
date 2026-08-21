"""Guards for the real-fleet false-positive gate (``scripts/fleet_fp_gate.py``).

Two layers, deliberately, and for the same reason ``test_schema_grounding.py`` has two:
the thing being protected lives partly outside the repo.

  1. ALWAYS-ON (CI-enforced). Unit tests over the gate's own logic on synthetic findings
     -- no real fleet, no network, no writes outside ``tmp_path``. These keep the
     mechanism honest everywhere: that it compares FAIL SETS and not scores, that a new
     FAIL blocks, that a missing baseline fails CLOSED, and that a snapshot carries no
     absolute path. If the gate itself rots, CI says so.

  2. LOCAL-ONLY (skips where there is no recorded baseline -- CI, a fresh clone, another
     contributor's machine). Asserts the recorded real-fleet baseline was re-recorded
     for the CURRENT release. This is the enforcement point that makes the gate
     un-forgettable at the moment it matters: the release gate already requires a green
     full-suite run before tagging, so a version bump without a fresh real-fleet
     baseline turns the suite red on the maintainer's machine.

The skip in layer 2 is deliberate and documented (the recon-doc precedent): CI genuinely
has no real fleet, and a machine-specific baseline must never be committed to the repo --
it would be wrong for every other checkout and would publish the machine's installed-skill
inventory.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

import clawseccheck
from clawseccheck.catalog import CRITICAL, FAIL, HIGH, PASS, UNKNOWN, WARN, Finding
from _realhome import REAL_HOME, real_path

REPO_ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = REPO_ROOT / "scripts" / "fleet_fp_gate.py"


def _load_gate():
    spec = importlib.util.spec_from_file_location("_fleet_fp_gate", GATE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


def _f(fid, status, severity=HIGH, *, suppressed=False):
    return Finding(fid, f"title {fid}", severity, status, "detail", "fix", "framework",
                   suppressed=suppressed)


def _snapshot(fails, *, version="9.9.9", targets=("alpha",), degraded=(), score=50):
    return {
        "schema": gate.SCHEMA,
        "tool_version": version,
        "generated": "2026-01-01",
        "home_label": "0123456789ab",
        "targets": list(targets),
        "degraded_checks": list(degraded),
        "context": {"score": score, "grade": "F", "suppressed_fail_count": 0},
        "fails": list(fails),
    }


def _row(fid, scope="audit", target="", severity=HIGH):
    return {"scope": scope, "target": target, "id": fid, "severity": severity}


# --------------------------------------------------------------------- layer 1: FAIL set

def test_fail_rows_keeps_only_unsuppressed_fails():
    findings = [
        _f("B1", FAIL), _f("B2", WARN), _f("B3", PASS), _f("B4", UNKNOWN),
        _f("B5", FAIL, suppressed=True),
    ]
    assert [r["id"] for r in gate.fail_rows(findings, scope="audit")] == ["B1"]


def test_fail_rows_records_target_and_is_sorted():
    findings = [_f("B9", FAIL), _f("B2", FAIL), _f("A1", FAIL, CRITICAL)]
    rows = gate.fail_rows(findings, scope="vet", target="beta")
    assert [r["id"] for r in rows] == ["A1", "B2", "B9"]
    assert {r["target"] for r in rows} == {"beta"}
    assert {r["scope"] for r in rows} == {"vet"}


def test_fail_rows_carries_no_detail_or_evidence():
    """A gate artifact must be comparable across commits and safe to read. Detail can
    embed live counts (unstable) and evidence can quote skill prose (unsafe)."""
    finding = Finding("B7", "t", HIGH, FAIL, "detail text", "fix", "fw",
                      evidence=["alpha: something quoted from a skill (a/b.py:3)"])
    row = gate.fail_rows([finding], scope="vet", target="alpha")[0]
    assert set(row) == {"scope", "target", "id", "severity"}
    assert "quoted" not in json.dumps(row)


# --------------------------------------------------------------------- layer 1: compare

def test_compare_flags_a_new_fail_as_a_blocker():
    baseline = _snapshot([_row("A1")])
    snapshot = _snapshot([_row("A1"), _row("B13", scope="vet", target="alpha")])
    result = gate.compare(snapshot, baseline)
    assert result["blocked"] is True
    assert [(r["scope"], r["target"], r["id"]) for r in result["new_fails"]] == [
        ("vet", "alpha", "B13")
    ]


def test_compare_does_not_block_on_a_resolved_fail():
    """A FAIL that disappeared is reported, never blocking: this gate catches new false
    positives, it does not freeze coverage."""
    baseline = _snapshot([_row("A1"), _row("B13")])
    result = gate.compare(_snapshot([_row("A1")]), baseline)
    assert result["blocked"] is False
    assert [r["id"] for r in result["resolved_fails"]] == ["B13"]


def test_compare_blocks_on_a_fail_from_a_newly_seen_target():
    """A newly installed skill gets no free pass -- an overfitted rule shows up there
    first."""
    baseline = _snapshot([], targets=("alpha",))
    snapshot = _snapshot([_row("B65", scope="vet", target="gamma")],
                         targets=("alpha", "gamma"))
    result = gate.compare(snapshot, baseline)
    assert result["blocked"] is True
    assert result["new_targets"] == ["gamma"]


def test_a_score_change_alone_is_never_a_blocker():
    """Baselines expire with their commit: adding a passing check moves the score
    without changing correctness, so only FAIL SETS are compared."""
    baseline = _snapshot([_row("A1")], score=20)
    result = gate.compare(_snapshot([_row("A1")], score=95), baseline)
    assert result["blocked"] is False
    assert result["new_fails"] == []


def test_a_severity_regrade_alone_is_not_a_new_fail():
    baseline = _snapshot([_row("A1", severity=HIGH)])
    result = gate.compare(_snapshot([_row("A1", severity=CRITICAL)]), baseline)
    assert result["blocked"] is False


def test_compare_reports_a_version_and_fleet_mismatch():
    baseline = _snapshot([], version="1.0.0")
    snapshot = _snapshot([], version="2.0.0")
    snapshot["home_label"] = "ffffffffffff"
    result = gate.compare(snapshot, baseline)
    rendered = gate.render_compare(result)
    assert result["baseline_version"] == "1.0.0"
    assert "different fleet root" in rendered


# --------------------------------------------------------------- layer 1: degraded runs

def test_degraded_checks_detects_a_crashed_or_timed_out_check():
    findings = [_f("B1", FAIL), _f("ERR:check_something", UNKNOWN)]
    assert gate.degraded_checks(findings) == ["ERR:check_something"]


def test_a_degraded_snapshot_is_not_comparable():
    """A run where a check produced no verdict hides FAILs, so neither its pass nor its
    block means anything -- and a degraded BASELINE would later report the recovered
    FAIL as new."""
    baseline = _snapshot([_row("A1")])
    snapshot = _snapshot([_row("A1")], degraded=["ERR:check_installed_skills"])
    result = gate.compare(snapshot, baseline)
    assert result["comparable"] is False
    assert "CANNOT COMPARE" in gate.render_compare(result)

    degraded_baseline = _snapshot([_row("A1")], degraded=["ERR:check_x"])
    assert gate.compare(_snapshot([_row("A1")]), degraded_baseline)["comparable"] is False


def test_a_clean_snapshot_is_comparable():
    baseline = _snapshot([_row("A1")])
    assert gate.compare(_snapshot([_row("A1")]), baseline)["comparable"] is True


# ------------------------------------------------------------ layer 1: fail-closed I/O

def test_missing_baseline_fails_closed(tmp_path):
    """A missing baseline must never read as "no new FAILs" -- that would silently turn
    every real FAIL into an expected one."""
    with pytest.raises(SystemExit) as exc:
        gate._load_baseline(tmp_path / "nope.json")
    assert exc.value.code == gate.EXIT_CANNOT_RUN


def test_malformed_baseline_fails_closed(tmp_path):
    bad = tmp_path / "b.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        gate._load_baseline(bad)
    assert exc.value.code == gate.EXIT_CANNOT_RUN

    wrong_shape = tmp_path / "c.json"
    wrong_shape.write_text(json.dumps({"tool_version": "1.0.0"}), encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        gate._load_baseline(wrong_shape)
    assert exc.value.code == gate.EXIT_CANNOT_RUN


def test_compare_exit_codes_are_distinct():
    """"new FAIL found" and "could not run" must be distinguishable by a caller."""
    assert len({gate.EXIT_OK, gate.EXIT_NEW_FAIL, gate.EXIT_CANNOT_RUN}) == 3
    assert gate.EXIT_OK == 0


def test_home_label_is_a_hash_not_a_path(tmp_path):
    label = gate._home_label(tmp_path)
    assert str(tmp_path) not in label
    assert len(label) == 12 and all(c in "0123456789abcdef" for c in label)


def test_written_snapshot_is_owner_only_and_round_trips(tmp_path):
    snap = _snapshot([_row("A1"), _row("B13", scope="vet", target="alpha")])
    out = tmp_path / "state" / "snap.json"
    gate._write_json(out, snap)
    assert out.stat().st_mode & 0o077 == 0  # local state, never group/world readable
    assert json.loads(out.read_text(encoding="utf-8"))["fails"] == snap["fails"]


def test_a_snapshot_never_embeds_the_fleet_path(tmp_path):
    """The fleet root reaches the artifact only as a hash. A snapshot has to be readable
    and diffable without disclosing where (or on which machine) it was taken."""
    fleet_root = tmp_path / "some" / "private" / "openclaw"
    fleet_root.mkdir(parents=True)
    snap = _snapshot([_row("A1")])
    snap["home_label"] = gate._home_label(fleet_root)
    out = tmp_path / "snap.json"
    gate._write_json(out, snap)
    assert str(fleet_root) not in out.read_text(encoding="utf-8")


# ------------------------------------------------------ layer 1: the diagnosed state

def _dx(fid, scope="audit", target="", note="because reasons"):
    return {"scope": scope, "target": target, "id": fid, "note": note,
            "recorded": "2026-08-21", "tool_version": "9.9.9"}


def test_an_undiagnosed_new_fail_still_blocks():
    """The regression pin for the whole feature. Everything below makes it POSSIBLE for a
    live FAIL not to block; this asserts the default did not move. If only one test in
    this section survives a refactor, it should be this one."""
    baseline = _snapshot([_row("A1")])
    baseline["diagnosed"] = [_dx("B13", scope="vet", target="alpha")]
    snapshot = _snapshot([_row("A1"), _row("B99", scope="vet", target="alpha")])
    result = gate.compare(snapshot, baseline)
    assert result["blocked"] is True
    assert [r["id"] for r in result["new_fails"]] == ["B99"]


def test_a_diagnosed_fail_does_not_block_and_is_printed_with_its_reason():
    """The feature. B181 on this project's own machine is a TRUE positive caused by the
    dev-sync, so it must neither block nor be silenced -- it must keep explaining itself."""
    baseline = _snapshot([_row("A1")])
    baseline["diagnosed"] = [_dx("B181", note="dev-sync overwrites the installed copy")]
    result = gate.compare(_snapshot([_row("A1"), _row("B181")]), baseline)
    assert result["blocked"] is False
    assert result["new_fails"] == []
    assert [r["id"] for r in result["known_fails"]] == ["B181"]
    rendered = gate.render_compare(result)
    assert "KNOWN" in rendered
    assert "dev-sync overwrites the installed copy" in rendered


def test_a_diagnosis_is_scoped_to_one_target_not_to_the_check_id():
    """The naive implementation this must never become: an allowlist of check ids.
    Acknowledging B181 for our own dev-synced skill would then also acknowledge it for a
    skill someone really did tamper with -- the gate silencing the exact finding it
    exists to surface."""
    baseline = _snapshot([])
    baseline["diagnosed"] = [_dx("B181", scope="vet", target="clawseccheck")]
    snapshot = _snapshot([_row("B181", scope="vet", target="clawseccheck"),
                          _row("B181", scope="vet", target="canvas")])
    result = gate.compare(snapshot, baseline)
    assert result["blocked"] is True
    assert [(r["target"], r["id"]) for r in result["new_fails"]] == [("canvas", "B181")]
    assert [(r["target"], r["id"]) for r in result["known_fails"]] == [
        ("clawseccheck", "B181")
    ]


def test_a_diagnosis_is_scoped_to_one_scope_too():
    """The audit pool and a vet pool can report the same id about different things."""
    baseline = _snapshot([])
    baseline["diagnosed"] = [_dx("B61", scope="audit", target="")]
    result = gate.compare(
        _snapshot([_row("B61"), _row("B61", scope="vet", target="alpha")]), baseline)
    assert [r["scope"] for r in result["new_fails"]] == ["vet"]
    assert [r["scope"] for r in result["known_fails"]] == ["audit"]


def test_a_diagnosed_fail_keeps_printing_even_when_the_baseline_carries_it():
    """The one behavioural difference from `record`, and the reason this exists at all.
    A baselined FAIL is silent forever; a diagnosed one restates its reason on every run,
    so a justification that has stopped being true stays in front of a reader."""
    baseline = _snapshot([_row("B181")])
    baseline["diagnosed"] = [_dx("B181", note="known dev-sync artifact")]
    result = gate.compare(_snapshot([_row("B181")]), baseline)
    assert result["blocked"] is False
    assert [r["id"] for r in result["known_fails"]] == ["B181"]
    assert "known dev-sync artifact" in gate.render_compare(result)


def test_the_pass_line_discloses_what_it_let_through():
    """A bare "OK" after a diagnosed FAIL would be the silent-cap failure this project
    refuses elsewhere: the reader has to be told the pass was conditional."""
    baseline = _snapshot([])
    baseline["diagnosed"] = [_dx("B181")]
    rendered = gate.render_compare(gate.compare(_snapshot([_row("B181")]), baseline))
    assert "OK: no new real-fleet FAIL" in rendered
    assert "carry a recorded diagnosis" in rendered
    # ...and stays bare when there is nothing to disclose.
    plain = gate.render_compare(gate.compare(_snapshot([]), _snapshot([])))
    assert "carry a recorded diagnosis" not in plain


def test_a_stale_diagnosis_is_reported_and_never_blocks():
    """A diagnosis whose FAIL is gone has lost its subject. Silence would let it sit
    there pre-approving that FAIL if it ever returns."""
    baseline = _snapshot([])
    baseline["diagnosed"] = [_dx("B181")]
    result = gate.compare(_snapshot([]), baseline)
    assert result["blocked"] is False
    assert [e["id"] for e in result["stale_diagnoses"]] == ["B181"]
    assert "stale dx" in gate.render_compare(result)


def test_a_baseline_with_no_diagnosed_key_behaves_exactly_as_before():
    """Forward compatibility: every baseline recorded before this feature must load and
    diff identically. The absent key is an empty index, never an error."""
    baseline = _snapshot([_row("A1")])
    assert "diagnosed" not in baseline
    result = gate.compare(_snapshot([_row("A1"), _row("B13")]), baseline)
    assert result["blocked"] is True
    assert result["known_fails"] == []
    assert result["stale_diagnoses"] == []
    assert gate.diagnosis_index(baseline) == {}


# ------------------------------------------------ layer 1: acknowledging is constrained

def test_add_diagnosis_refuses_a_fail_that_is_not_live():
    """The load-bearing refusal. Without it this is a pre-approval list, and a FAIL could
    be cleared by predicting it rather than by looking at it."""
    baseline = _snapshot([])
    with pytest.raises(ValueError) as exc:
        gate.add_diagnosis(baseline, _snapshot([_row("A1")]), scope="audit", target="",
                           check_id="B181", note="a guess about the future")
    assert "not a live FAIL" in str(exc.value)


def test_add_diagnosis_refuses_a_blank_note():
    """The note IS the feature; an entry without one is a silencer with extra steps, and
    an empty string is the shape a script produces by accident."""
    snapshot = _snapshot([_row("B181")])
    for note in ("", "   ", "\n"):
        with pytest.raises(ValueError) as exc:
            gate.add_diagnosis(_snapshot([]), snapshot, scope="audit", target="",
                               check_id="B181", note=note)
        assert "silencer" in str(exc.value)


def test_add_diagnosis_replaces_rather_than_duplicating():
    """Two answers to one question is a state the index must not be able to hold."""
    snapshot = _snapshot([_row("B181")])
    first = gate.add_diagnosis(_snapshot([]), snapshot, scope="audit", target="",
                               check_id="B181", note="first reading")
    second = gate.add_diagnosis(first, snapshot, scope="audit", target="",
                                check_id="B181", note="corrected reading")
    assert len(second["diagnosed"]) == 1
    assert second["diagnosed"][0]["note"] == "corrected reading"


def test_add_diagnosis_stamps_when_and_against_what():
    """A diagnosis with no date is unauditable -- the reader cannot tell a reason checked
    yesterday from one nobody has revisited in a year."""
    entry = gate.add_diagnosis(_snapshot([]), _snapshot([_row("B181")]), scope="audit",
                               target="", check_id="B181", note="dev-sync",
                               today="2026-08-21")["diagnosed"][0]
    assert entry["recorded"] == "2026-08-21"
    assert entry["tool_version"] == "9.9.9"
    assert entry["note"] == "dev-sync"


def test_add_diagnosis_does_not_mutate_the_baseline_it_was_given():
    baseline = _snapshot([])
    gate.add_diagnosis(baseline, _snapshot([_row("B181")]), scope="audit", target="",
                       check_id="B181", note="dev-sync")
    assert "diagnosed" not in baseline


# ------------------------------------------- layer 1: a hand-edited baseline fails closed

def test_a_malformed_diagnosed_array_fails_closed(tmp_path):
    """`diagnosed` is the one part of the baseline a human edits, so a typo must be
    reported rather than absorbed. Reading it as empty would be safe in the blocking
    direction but silent -- and silence about a rejected diagnosis is how someone
    concludes the acknowledgement "did not take" without ever being told why."""
    cases = [
        "oops",                                             # not an array
        [{"scope": "audit", "target": "", "id": "B181"}],   # no note
        [{"scope": "audit", "target": "", "id": "B181", "note": "  "}],  # blank note
        [{"scope": "audit", "target": "", "id": 181, "note": "x"}],      # id not a string
        ["just a string"],                                  # not an object
    ]
    for i, diagnosed in enumerate(cases):
        path = tmp_path / f"b{i}.json"
        payload = _snapshot([_row("A1")])
        payload["diagnosed"] = diagnosed
        path.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(SystemExit) as exc:
            gate._load_baseline(path)
        assert exc.value.code == gate.EXIT_CANNOT_RUN, diagnosed


def test_a_well_formed_diagnosed_array_loads(tmp_path):
    path = tmp_path / "ok.json"
    payload = _snapshot([_row("A1")])
    payload["diagnosed"] = [_dx("B181")]
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert gate._load_baseline(path)["diagnosed"][0]["id"] == "B181"


# --------------------------------------------------- layer 1: re-recording keeps the why

def test_record_carries_a_live_diagnosis_and_drops_a_stale_one():
    """A version bump forces a re-record (see layer 2). Losing the diagnoses there would
    turn every explained FAIL back into a silent baselined one -- the exact state
    `acknowledge` exists to get out of. Dropping a stale one silently would be the same
    defect mirrored, so both halves are returned to be printed."""
    previous = _snapshot([])
    previous["diagnosed"] = [_dx("B181"), _dx("B13", scope="vet", target="alpha")]
    fresh = _snapshot([_row("B181")])
    kept, dropped = gate.carry_diagnoses(previous, fresh)
    assert [e["id"] for e in kept] == ["B181"]
    assert [e["id"] for e in dropped] == ["B13"]


def test_carry_diagnoses_handles_a_first_ever_record():
    kept, dropped = gate.carry_diagnoses(None, _snapshot([_row("A1")]))
    assert kept == [] and dropped == []


# ------------------------------------------------------- layer 2: local, real baseline

def _recorded_baseline():
    # B-519: the suite runs with $HOME redirected to a tmp dir, so this must resolve
    # against the REAL home -- otherwise layer 2 skips everywhere and the release gate
    # that makes a stale baseline un-forgettable becomes a no-op.
    path = real_path(gate.DEFAULT_BASELINE)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def test_recorded_baseline_matches_this_release():
    """The real-fleet FAIL set must be re-recorded for the release being shipped.

    Skips wherever no baseline has been recorded (CI, a fresh clone) -- the real fleet
    is one machine's installed software and its baseline is local state, never committed.
    Where a baseline DOES exist, a version bump that forgets to refresh it turns this
    red, which is the point: the release gate requires a green suite before tagging.
    """
    baseline = _recorded_baseline()
    if baseline is None:
        pytest.skip("no recorded real-fleet baseline on this machine (expected in CI)")
    assert baseline.get("tool_version") == clawseccheck.__version__, (
        f"the recorded real-fleet baseline is for v{baseline.get('tool_version')} but this "
        f"tree is v{clawseccheck.__version__}. Re-record it before shipping:\n"
        "    python3 scripts/fleet_fp_gate.py compare   # diagnose any new FAIL first\n"
        "    python3 scripts/fleet_fp_gate.py record\n"
        "A benchmark-motivated detection change must go through that comparison."
    )


def test_recorded_baseline_is_well_formed():
    baseline = _recorded_baseline()
    if baseline is None:
        pytest.skip("no recorded real-fleet baseline on this machine (expected in CI)")
    assert baseline.get("schema") == gate.SCHEMA
    assert isinstance(baseline.get("fails"), list)
    # The REAL artifact, not a synthetic one: it must name no local path. Home is read
    # dynamically so this file never carries a machine path of its own.
    assert str(REAL_HOME) not in json.dumps(baseline)
    assert not baseline.get("degraded_checks"), (
        "the recorded baseline was captured on a machine where a check produced no "
        "verdict, so it under-reports FAILs — re-record it on a quiet machine."
    )
    for row in baseline["fails"]:
        assert set(row) == {"scope", "target", "id", "severity"}
    # `diagnosed` is a sibling of `fails`, never a field inside a row: `fails` is what
    # the scan observed and `record` regenerates it wholesale, so a human note living
    # inside a row would be silently discarded on the next re-record.
    for entry in baseline.get("diagnosed") or []:
        assert gate._diagnosis_problem(entry) is None, entry
        assert str(REAL_HOME) not in entry["note"], (
            "a diagnosis is read by whoever runs the gate next -- it must not carry a "
            "machine path"
        )


def test_carry_diagnoses_survives_a_hand_corrupted_entry():
    """`record` reads the old baseline with `_read_json_or_none`, which does not validate
    (its job is "is there one at all"). A hand-corrupted `diagnosed` array must therefore
    not turn a re-record into a traceback -- the malformed entry is dropped and named."""
    previous = _snapshot([])
    previous["diagnosed"] = [
        _dx("B181"),                                   # fine, and live below
        {"scope": "audit", "id": "B13"},               # no target, no note
        "not even an object",
    ]
    kept, dropped = gate.carry_diagnoses(previous, _snapshot([_row("B181")]))
    assert [e["id"] for e in kept] == ["B181"]
    assert len(dropped) == 2
