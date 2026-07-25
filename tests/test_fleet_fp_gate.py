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


# ------------------------------------------------------- layer 2: local, real baseline

def _recorded_baseline():
    path = Path(gate.DEFAULT_BASELINE).expanduser()
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
    assert str(Path.home()) not in json.dumps(baseline)
    assert not baseline.get("degraded_checks"), (
        "the recorded baseline was captured on a machine where a check produced no "
        "verdict, so it under-reports FAILs — re-record it on a quiet machine."
    )
    for row in baseline["fails"]:
        assert set(row) == {"scope", "target", "id", "severity"}
